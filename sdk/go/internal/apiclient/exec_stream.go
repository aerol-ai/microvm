package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	wsURL, err := websocketURL(c.baseURL, "/v1/sandboxes/"+url.PathEscape(id)+"/toolbox/process/exec/stream")
	if err != nil {
		return nil, err
	}

	requestHeader := http.Header{}
	if c.patToken != "" {
		requestHeader.Set("Authorization", "Bearer "+c.patToken)
	}

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, requestHeader)
	if err != nil {
		return nil, err
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
			h.finish(ExecExitInfo{}, fmt.Errorf("stream closed before exit: %w", err))
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
