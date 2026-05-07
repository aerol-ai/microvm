package sshgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// attachToSession opens a WebSocket to the in-container toolboxd session
// API, creating the named session if necessary, and pumps bytes between
// the SSH channel and the WS. Returns the session's exit code (or 1 if the
// transport itself failed).
func (g *Gateway) attachToSession(ctx context.Context, channel ssh.Channel, sandbox *models.Sandbox, sessionName string, state *sessionState) int {
	if sessionName == "" {
		sessionName = "default"
	}
	// Step 1: ensure the session exists. Idempotent — toolboxd's
	// GetOrCreate is "name keyed". We POST /sessions and ignore the
	// returned ID for new ones; for existing ones we ask /sessions and pick
	// the matching name. Cleaner: POST always with idempotency via a
	// "lookup-or-create" flag. We don't have that yet, so list first.
	sessionID, err := g.findOrCreateSession(ctx, sandbox, sessionName, state)
	if err != nil {
		g.writeStderr(channel, fmt.Sprintf("attach failed: %v\r\n", err))
		return 1
	}

	wsURL := fmt.Sprintf("ws://%s:%d/sessions/%s/attach", sandbox.ContainerIP, g.toolboxPort, url.PathEscape(sessionID))
	header := http.Header{}
	if sandbox.ToolboxToken != "" {
		header.Set("Authorization", "Bearer "+sandbox.ToolboxToken)
	}
	dialer := *websocket.DefaultDialer
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
func (g *Gateway) findOrCreateSession(ctx context.Context, sandbox *models.Sandbox, name string, state *sessionState) (string, error) {
	listURL := fmt.Sprintf("http://%s:%d/sessions", sandbox.ContainerIP, g.toolboxPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return "", err
	}
	if sandbox.ToolboxToken != "" {
		req.Header.Set("Authorization", "Bearer "+sandbox.ToolboxToken)
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
	createURL := fmt.Sprintf("http://%s:%d/sessions", sandbox.ContainerIP, g.toolboxPort)
	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(createBody))
	if err != nil {
		return "", err
	}
	createReq.Header.Set("Content-Type", "application/json")
	if sandbox.ToolboxToken != "" {
		createReq.Header.Set("Authorization", "Bearer "+sandbox.ToolboxToken)
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
