package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const (
	streamPrefixStdout = 0x01
	streamPrefixStderr = 0x02
)

type ExecStreamOptions = sdktypes.ExecStreamOptions
type ExecExitInfo = sdktypes.ExecExitInfo

type ExecStreamHandle struct {
	conn       *websocket.Conn
	sendMu     sync.Mutex
	finishOnce sync.Once
	done       chan struct{}
	resultMu   sync.RWMutex
	result     execStreamResult
}

type execStreamResult struct {
	info ExecExitInfo
	err  error
}

type execStreamControlMessage struct {
	Type   string `json:"type"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Signal string `json:"signal,omitempty"`
}

type execStreamServerMessage struct {
	Type    string `json:"type"`
	Code    int    `json:"code,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Message string `json:"message,omitempty"`
}

func (c *Client) ExecStream(ctx context.Context, id string, options ExecStreamOptions) (*ExecStreamHandle, error) {
	if strings.TrimSpace(options.Command) == "" {
		return nil, errors.New("command is required")
	}

	wsURL, err := websocketURL(c.baseURL, c.versionPrefix+"/sandboxes/"+url.PathEscape(id)+"/toolbox/process/exec/stream")
	if err != nil {
		return nil, err
	}

	requestHeader := http.Header{}
	if c.patToken != "" {
		requestHeader.Set("Authorization", "Bearer "+c.patToken)
	}

	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, wsURL, requestHeader)
	if err != nil {
		return nil, decorateHandshakeError("exec stream", wsURL, resp, err)
	}

	handle := &ExecStreamHandle{
		conn: conn,
		done: make(chan struct{}),
	}

	start := struct {
		Command string            `json:"command"`
		Workdir string            `json:"workdir,omitempty"`
		Env     map[string]string `json:"env,omitempty"`
		TTY     bool              `json:"tty,omitempty"`
		Cols    int               `json:"cols,omitempty"`
		Rows    int               `json:"rows,omitempty"`
	}{
		Command: options.Command,
		Workdir: options.Workdir,
		Env:     options.Env,
		TTY:     options.TTY,
		Cols:    options.Cols,
		Rows:    options.Rows,
	}
	if err := conn.WriteJSON(start); err != nil {
		_ = conn.Close()
		return nil, err
	}

	go handle.readLoop(options)
	go func() {
		select {
		case <-ctx.Done():
			handle.finish(ExecExitInfo{}, ctx.Err())
			_ = conn.Close()
		case <-handle.done:
		}
	}()

	return handle, nil
}

func (h *ExecStreamHandle) Write(data []byte) error {
	return h.writeMessage(websocket.BinaryMessage, data)
}

func (h *ExecStreamHandle) WriteString(data string) error {
	return h.Write([]byte(data))
}

func (h *ExecStreamHandle) Resize(cols, rows int) error {
	return h.writeJSON(execStreamControlMessage{Type: "resize", Cols: cols, Rows: rows})
}

func (h *ExecStreamHandle) Signal(name string) error {
	return h.writeJSON(execStreamControlMessage{Type: "signal", Signal: name})
}

func (h *ExecStreamHandle) Close() error {
	return h.writeJSON(execStreamControlMessage{Type: "close"})
}

func (h *ExecStreamHandle) Wait() (ExecExitInfo, error) {
	<-h.done
	h.resultMu.RLock()
	defer h.resultMu.RUnlock()
	return h.result.info, h.result.err
}

func (h *ExecStreamHandle) readLoop(options ExecStreamOptions) {
	for {
		messageType, payload, err := h.conn.ReadMessage()
		if err != nil {
			h.finish(ExecExitInfo{}, fmt.Errorf("stream closed before exit: %w", describeReadErr(err)))
			return
		}

		switch messageType {
		case websocket.TextMessage:
			var message execStreamServerMessage
			if err := json.Unmarshal(payload, &message); err != nil {
				continue
			}
			switch message.Type {
			case "exit":
				h.finish(ExecExitInfo{Code: message.Code, Signal: message.Signal}, nil)
				_ = h.conn.Close()
				return
			case "error":
				if options.OnError != nil {
					options.OnError(message.Message)
				}
				if message.Message == "" {
					message.Message = "stream error"
				}
				h.finish(ExecExitInfo{}, errors.New(message.Message))
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

func (h *ExecStreamHandle) writeJSON(payload any) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	return h.conn.WriteJSON(payload)
}

func (h *ExecStreamHandle) writeMessage(messageType int, payload []byte) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	return h.conn.WriteMessage(messageType, payload)
}

func (h *ExecStreamHandle) finish(info ExecExitInfo, err error) {
	h.finishOnce.Do(func() {
		h.resultMu.Lock()
		h.result = execStreamResult{info: info, err: err}
		h.resultMu.Unlock()
		close(h.done)
	})
}

// describeReadErr annotates a gorilla/websocket read error with the close
// code/text when the peer sent one. Plain `err.Error()` says only "websocket:
// close 1006 (abnormal closure)"; with this we surface the toolboxd-supplied
// text frame too when present.
func describeReadErr(err error) error {
	if err == nil {
		return nil
	}
	if ce, ok := err.(*websocket.CloseError); ok {
		if ce.Text == "" {
			return fmt.Errorf("close code=%d", ce.Code)
		}
		return fmt.Errorf("close code=%d text=%q", ce.Code, ce.Text)
	}
	return err
}

// decorateHandshakeError annotates a gorilla/websocket Dial error with the
// HTTP status and body the server returned. On a non-101 response the dialer
// surfaces only "websocket: bad handshake", which is useless for diagnosing
// 401s ("auth dropped"), 404s ("route mismatch"), 502s ("toolbox unavailable"),
// or 5xx from upstream. Caller passes the *http.Response the dialer also
// returned (may be nil on transport-level errors).
func decorateHandshakeError(label, wsURL string, resp *http.Response, err error) error {
	if err == nil {
		return nil
	}
	if resp == nil {
		return fmt.Errorf("%s websocket dial %s: %w", label, wsURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return fmt.Errorf("%s websocket dial %s: %w (status=%d)", label, wsURL, err, resp.StatusCode)
	}
	return fmt.Errorf("%s websocket dial %s: %w (status=%d, body=%q)", label, wsURL, err, resp.StatusCode, trimmed)
}

func websocketURL(baseURL, path string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported base URL scheme %q", parsed.Scheme)
	}
	return parsed.String(), nil
}
