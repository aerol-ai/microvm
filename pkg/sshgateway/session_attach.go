package sshgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// Frame protocol bytes — matches sessions_handler.go in toolboxd.
const (
	streamFramePrefixStdout byte = 0x01
	streamFramePrefixStderr byte = 0x02
)

// sessionEndpoint locates a toolboxd /sessions API surface plus the auth header
// to reach it. It exists so the same attach/bridge logic serves two callers:
//
//   - local (single-node / self-owned): the in-container toolboxd, reached
//     directly at ws://<ContainerIP>:<toolboxPort>/sessions with the per-sandbox
//     toolbox token.
//   - remote (cluster, sandbox owned by another node): this node's own v1 API
//     at /v1/sandboxes/<id>/sessions, which clusterForwardWrap transparently
//     reverse-proxies (WebSocket upgrade included) to the owner over the
//     cert-pinned mTLS channel. The PAT authenticates the loopback hop; the
//     owner injects the real toolbox token on its side.
//
// baseURL is the http(s) /sessions root (no trailing slash); wsURL is the
// matching ws(s) root; auth is the full Authorization header value or "".
// forwardID, when set, is echoed as a correlation header on every call so a
// cross-node SSH session can be traced from the edge to the owner.
type sessionEndpoint struct {
	baseURL   string
	wsURL     string
	auth      string
	forwardID string
}

// forwardIDHeader is the correlation header carried on cross-node SSH calls.
// The edge logs the same ID, so an operator can join the edge and owner sides
// of one forwarded session.
const forwardIDHeader = "X-Aerol-Ssh-Forward-Id"

func (ep sessionEndpoint) applyHeaders(h http.Header) {
	if ep.auth != "" {
		h.Set("Authorization", ep.auth)
	}
	if ep.forwardID != "" {
		h.Set(forwardIDHeader, ep.forwardID)
	}
}

// localSessionEndpoint targets the in-container toolboxd directly. This is the
// single-node / self-owned path and must stay byte-for-byte identical to the
// pre-cluster behaviour.
func localSessionEndpoint(containerIP string, toolboxPort int, toolboxToken string) sessionEndpoint {
	root := fmt.Sprintf("%s:%d/sessions", containerIP, toolboxPort)
	return sessionEndpoint{
		baseURL: "http://" + root,
		wsURL:   "ws://" + root,
		auth:    bearer(toolboxToken),
	}
}

func bearer(token string) string {
	if token == "" {
		return ""
	}
	return "Bearer " + token
}

// attachToSession opens a WebSocket to a toolboxd session API (local container
// or owner-forwarded v1), creating the named session if necessary, and pumps
// bytes between the SSH channel and the WS. Returns the session's exit code (or
// 1 if the transport itself failed).
//
// resize, when non-nil, delivers terminal size changes (cols, rows) that arrive
// mid-session; they are pushed to the toolbox as resize control messages. Pass
// nil when the caller does not forward window-change events. The caller owns the
// channel and must close it when the session is done.
func (g *Gateway) attachToSession(ctx context.Context, channel ssh.Channel, ep sessionEndpoint, sessionName string, state *sessionState, resize <-chan [2]uint32) int {
	if sessionName == "" {
		sessionName = "default"
	}
	// Step 1: ensure the session exists. Idempotent — toolboxd's
	// GetOrCreate is "name keyed". We POST /sessions and ignore the
	// returned ID for new ones; for existing ones we ask /sessions and pick
	// the matching name. Cleaner: POST always with idempotency via a
	// "lookup-or-create" flag. We don't have that yet, so list first.
	sessionID, err := g.findOrCreateSession(ctx, ep, sessionName, state)
	if err != nil {
		g.writeStderr(channel, fmt.Sprintf("attach failed: %v\r\n", err))
		return 1
	}

	wsURL := fmt.Sprintf("%s/%s/attach", ep.wsURL, url.PathEscape(sessionID))
	header := http.Header{}
	ep.applyHeaders(header)
	dialer := *websocket.DefaultDialer
	// The remote path dials this node's own v1 API over loopback (ws://), so
	// TLS is normally unused. Tolerate wss:// for completeness.
	if strings.HasPrefix(ep.wsURL, "wss://") {
		dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	dialer.HandshakeTimeout = 10 * time.Second
	conn, _, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		g.writeStderr(channel, fmt.Sprintf("attach dial failed: %v\r\n", err))
		return 1
	}
	defer conn.Close()

	// If the SSH client requested a PTY size, push it through.
	if state.wantPTY && state.ptyCols > 0 && state.ptyRows > 0 {
		_ = conn.WriteJSON(map[string]any{
			"type": "resize",
			"cols": int(state.ptyCols),
			"rows": int(state.ptyRows),
		})
	}

	exitCh := make(chan int, 1)
	var writeMu sync.Mutex

	// Forward mid-session terminal resizes (UC-9 on the cross-node path). The
	// goroutine exits when the caller closes the resize channel.
	if resize != nil {
		go func() {
			for d := range resize {
				if d[0] == 0 || d[1] == 0 {
					continue
				}
				writeMu.Lock()
				_ = conn.WriteJSON(map[string]any{"type": "resize", "cols": int(d[0]), "rows": int(d[1])})
				writeMu.Unlock()
			}
		}()
	}

	// channel → toolbox session (stdin and resize from window-change events
	// arrive on the request channel — those are handled in handleSession's
	// loop and we forward via a side channel into the WS; here we only ferry
	// bytes).
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := channel.Read(buf)
			if n > 0 {
				writeMu.Lock()
				werr := conn.WriteMessage(websocket.BinaryMessage, append([]byte(nil), buf[:n]...))
				writeMu.Unlock()
				if werr != nil {
					return
				}
			}
			if err != nil {
				writeMu.Lock()
				_ = conn.WriteJSON(map[string]any{"type": "close"})
				writeMu.Unlock()
				return
			}
		}
	}()

	// toolbox → channel.
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			exitCh <- 1
			break
		}
		switch mt {
		case websocket.BinaryMessage:
			if len(data) == 0 {
				continue
			}
			payload := data[1:]
			if data[0] == streamFramePrefixStderr {
				_, _ = channel.Stderr().Write(payload)
			} else {
				_, _ = channel.Write(payload)
			}
		case websocket.TextMessage:
			var ctrl struct {
				Type string `json:"type"`
				Code int    `json:"code"`
			}
			if err := json.Unmarshal(data, &ctrl); err != nil {
				continue
			}
			if ctrl.Type == "exit" {
				exitCh <- ctrl.Code
				return ctrl.Code
			}
		}
	}

	select {
	case code := <-exitCh:
		return code
	default:
		return 1
	}
}

// findOrCreateSession looks up the named session via toolboxd's HTTP API and
// returns its ID, creating it if absent. Synchronous; uses small timeouts.
func (g *Gateway) findOrCreateSession(ctx context.Context, ep sessionEndpoint, name string, state *sessionState) (string, error) {
	httpClient := &http.Client{Timeout: 5 * time.Second}

	create := models.CreateSessionRequest{
		Name: name,
		PTY:  true,
		Cols: int(state.ptyCols),
		Rows: int(state.ptyRows),
	}
	// One-shot exec: run the command as the session's process via `sh -c` so
	// the session exits with the command's exact status (reported back over the
	// attach WS as an "exit" frame). The session is unique-named and never
	// reused, so we skip the find step entirely.
	if state.execCommand != "" {
		create.Command = state.execCommand
		create.PTY = state.wantPTY
	} else {
		// Interactive shell: reuse a running session with the same name if one
		// exists (idempotent attach).
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.baseURL, nil)
		if err != nil {
			return "", err
		}
		ep.applyHeaders(req.Header)
		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("list sessions: %w", err)
		}
		var listed models.SessionList
		if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
			_ = resp.Body.Close()
			return "", fmt.Errorf("decode sessions: %w", err)
		}
		_ = resp.Body.Close()
		for _, sess := range listed.Sessions {
			if sess.Name == name && sess.Status == models.SessionStatusRunning {
				return sess.ID, nil
			}
		}
	}

	createBody, _ := json.Marshal(create)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.baseURL, bytes.NewReader(createBody))
	if err != nil {
		return "", err
	}
	createReq.Header.Set("Content-Type", "application/json")
	ep.applyHeaders(createReq.Header)
	createResp, err := httpClient.Do(createReq)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode >= 400 {
		return "", fmt.Errorf("create session: status %d", createResp.StatusCode)
	}
	var sess models.Session
	if err := json.NewDecoder(createResp.Body).Decode(&sess); err != nil {
		return "", fmt.Errorf("decode created session: %w", err)
	}
	return sess.ID, nil
}
