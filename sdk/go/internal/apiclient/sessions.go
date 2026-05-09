package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
)

type CreateSessionRequest = models.CreateSessionRequest
type Session = models.Session
type SessionList = models.SessionList
type SessionStatus = models.SessionStatus
type SessionSignalRequest = models.SessionSignalRequest
type SessionResizeRequest = models.SessionResizeRequest

// Frame stream prefixes match the toolboxd session protocol (sessions_handler.go).
// Reused via the existing streamPrefixStdout/streamPrefixStderr in exec_stream.go.

func (c *Client) CreateSession(ctx context.Context, sandboxID string, req CreateSessionRequest) (Session, error) {
	var response Session
	err := c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/sessions", req, &response)
	return response, err
}

func (c *Client) ListSessions(ctx context.Context, sandboxID string) ([]Session, error) {
	var response SessionList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/sandboxes/"+sandboxID+"/sessions", nil, &response); err != nil {
		return nil, err
	}
	return response.Sessions, nil
}

func (c *Client) GetSession(ctx context.Context, sandboxID, sessionID string) (Session, error) {
	var response Session
	err := c.doJSON(ctx, http.MethodGet, "/v1/sandboxes/"+sandboxID+"/sessions/"+sessionID, nil, &response)
	return response, err
}

func (c *Client) DeleteSession(ctx context.Context, sandboxID, sessionID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/sandboxes/"+sandboxID+"/sessions/"+sessionID, nil, nil)
}

func (c *Client) SignalSession(ctx context.Context, sandboxID, sessionID, signal string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/sessions/"+sessionID+"/signal", SessionSignalRequest{Signal: signal}, nil)
}

func (c *Client) ResizeSession(ctx context.Context, sandboxID, sessionID string, cols, rows int) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/sessions/"+sessionID+"/resize", SessionResizeRequest{Cols: cols, Rows: rows}, nil)
}

// SessionLog returns the cached replay buffer as a flat byte stream. Useful
// for "give me everything that's happened so far" without subscribing.
func (c *Client) SessionLog(ctx context.Context, sandboxID, sessionID string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/sandboxes/"+sandboxID+"/sessions/"+sessionID+"/log", nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return nil, decodeError(response)
	}
	return io.ReadAll(response.Body)
}

// SessionRecording returns the raw asciinema v2 cast file bytes. Caller can
// pipe this to `asciinema play -` or save it for later replay.
func (c *Client) SessionRecording(ctx context.Context, sandboxID, sessionID string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/sandboxes/"+sandboxID+"/sessions/"+sessionID+"/recording", nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return nil, decodeError(response)
	}
	return io.ReadAll(response.Body)
}

// SessionAttachOptions configures a live WebSocket attach to a session. The
// callbacks fire from the read pump goroutine; keep them quick.
type SessionAttachOptions struct {
	OnStdout func([]byte)
	OnStderr func([]byte)
	OnExit   func(code int, signal string)
	OnError  func(message string)
	// Cols/Rows, if non-zero, are sent as an initial resize after connect.
	Cols int
	Rows int
}

type SessionAttachHandle struct {
	conn       *websocket.Conn
	sendMu     sync.Mutex
	finishOnce sync.Once
	done       chan struct{}
	resultMu   sync.RWMutex
	result     sessionAttachResult
}

type sessionAttachResult struct {
	code   int
	signal string
	err    error
}

type sessionControlMessage struct {
	Type   string `json:"type"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Signal string `json:"signal,omitempty"`
}

type sessionServerMessage struct {
	Type    string `json:"type"`
	Code    int    `json:"code,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Message string `json:"message,omitempty"`
}

// AttachSession opens a WebSocket to the session's attach endpoint. Returns a
// handle for sending stdin / resize / signal / close, and for awaiting exit.
// The session keeps running if the handle is closed without sending a kill
// signal — use Signal("KILL") + Close() if you actually want it gone.
func (c *Client) AttachSession(ctx context.Context, sandboxID, sessionID string, options SessionAttachOptions) (*SessionAttachHandle, error) {
	if sandboxID == "" || sessionID == "" {
		return nil, errors.New("sandbox id and session id are required")
	}
	wsURL, err := websocketURL(c.baseURL, "/v1/sandboxes/"+url.PathEscape(sandboxID)+"/sessions/"+url.PathEscape(sessionID)+"/attach")
	if err != nil {
		return nil, err
	}
	requestHeader := http.Header{}
	if c.patToken != "" {
		requestHeader.Set("Authorization", "Bearer "+c.patToken)
	}
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, wsURL, requestHeader)
	if err != nil {
		return nil, decorateHandshakeError("session attach", wsURL, resp, err)
	}

	handle := &SessionAttachHandle{
		conn: conn,
		done: make(chan struct{}),
	}

	if options.Cols > 0 && options.Rows > 0 {
		_ = handle.writeJSON(sessionControlMessage{Type: "resize", Cols: options.Cols, Rows: options.Rows})
	}

	go handle.readLoop(options)
	go func() {
		select {
		case <-ctx.Done():
			handle.finish(0, "", ctx.Err())
			_ = conn.Close()
		case <-handle.done:
		}
	}()

	return handle, nil
}

func (h *SessionAttachHandle) Write(data []byte) error {
	return h.writeMessage(websocket.BinaryMessage, data)
}

func (h *SessionAttachHandle) WriteString(data string) error {
	return h.Write([]byte(data))
}

func (h *SessionAttachHandle) Resize(cols, rows int) error {
	return h.writeJSON(sessionControlMessage{Type: "resize", Cols: cols, Rows: rows})
}

func (h *SessionAttachHandle) Signal(name string) error {
	return h.writeJSON(sessionControlMessage{Type: "signal", Signal: name})
}

// Close politely tells the server we're detaching. The session keeps running.
func (h *SessionAttachHandle) Close() error {
	err := h.writeJSON(sessionControlMessage{Type: "close"})
	_ = h.conn.Close()
	return err
}

// Wait blocks until the session exits or the connection drops. Returns the
// exit code, signal name (if any), and any transport error.
func (h *SessionAttachHandle) Wait() (int, string, error) {
	<-h.done
	h.resultMu.RLock()
	defer h.resultMu.RUnlock()
	return h.result.code, h.result.signal, h.result.err
}

func (h *SessionAttachHandle) readLoop(options SessionAttachOptions) {
	for {
		messageType, payload, err := h.conn.ReadMessage()
		if err != nil {
			h.finish(0, "", fmt.Errorf("session stream closed: %w", describeReadErr(err)))
			return
		}
		switch messageType {
		case websocket.TextMessage:
			var message sessionServerMessage
			if err := json.Unmarshal(payload, &message); err != nil {
				continue
			}
			switch message.Type {
			case "exit":
				if options.OnExit != nil {
					options.OnExit(message.Code, message.Signal)
				}
				h.finish(message.Code, message.Signal, nil)
				_ = h.conn.Close()
				return
			case "error":
				if options.OnError != nil {
					options.OnError(message.Message)
				}
				if message.Message == "" {
					message.Message = "session error"
				}
				h.finish(0, "", errors.New(message.Message))
				_ = h.conn.Close()
				return
			}
		case websocket.BinaryMessage:
			if len(payload) == 0 {
				continue
			}
			chunk := append([]byte(nil), payload[1:]...)
			switch payload[0] {
			case streamPrefixStdout:
				if options.OnStdout != nil {
					options.OnStdout(chunk)
				}
			case streamPrefixStderr:
				if options.OnStderr != nil {
					options.OnStderr(chunk)
				}
			}
		}
	}
}

func (h *SessionAttachHandle) writeJSON(payload any) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	return h.conn.WriteJSON(payload)
}

func (h *SessionAttachHandle) writeMessage(messageType int, payload []byte) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	return h.conn.WriteMessage(messageType, payload)
}

func (h *SessionAttachHandle) finish(code int, signal string, err error) {
	h.finishOnce.Do(func() {
		h.resultMu.Lock()
		h.result = sessionAttachResult{code: code, signal: signal, err: err}
		h.resultMu.Unlock()
		close(h.done)
	})
}
