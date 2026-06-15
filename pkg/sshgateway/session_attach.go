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
type sessionEndpoint struct {
	baseURL string
	wsURL   string
	auth    string
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
func (g *Gateway) attachToSession(ctx context.Context, channel ssh.Channel, ep sessionEndpoint, sessionName string, state *sessionState) int {
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
	if ep.auth != "" {
		header.Set("Authorization", ep.auth)
	}
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

	// Cross-node one-shot exec: there is no local container to docker-exec
	// into, so the command is injected as the session's first stdin line and
	// the shell is asked to exit afterwards so the exit status propagates.
	if state.execCommand != "" {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte(state.execCommand+"\nexit\n"))
	}

	exitCh := make(chan int, 1)
	var writeMu sync.Mutex

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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.baseURL, nil)
	if err != nil {
		return "", err
	}
	if ep.auth != "" {
		req.Header.Set("Authorization", ep.auth)
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
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

	// Create with PTY=true (SSH callers always want a TTY-backed shell).
	createBody, _ := json.Marshal(models.CreateSessionRequest{
		Name: name,
		PTY:  true,
		Cols: int(state.ptyCols),
		Rows: int(state.ptyRows),
	})
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.baseURL, bytes.NewReader(createBody))
	if err != nil {
		return "", err
	}
	createReq.Header.Set("Content-Type", "application/json")
	if ep.auth != "" {
		createReq.Header.Set("Authorization", ep.auth)
	}
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
