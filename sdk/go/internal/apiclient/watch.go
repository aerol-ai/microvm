package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// FeatureFilesWatch names file watching in an UnsupportedFeatureError.
const FeatureFilesWatch = "files.watch"

// routeMissingHeader is toolboxd's mark on a 404 that means "no such
// route", as opposed to a missing file.
const routeMissingHeader = "X-Toolbox-Route"

type WatchOptions = sdktypes.WatchOptions
type FileEvent = sdktypes.FileEvent

// WatchHandle is a running file watch.
type WatchHandle struct {
	conn       *websocket.Conn
	onEvent    func(FileEvent)
	stopped    chan struct{}
	stopOnce   sync.Once
	finishOnce sync.Once
	done       chan struct{}
	err        error
}

type watchFrame struct {
	Type   string      `json:"type"`
	Events []FileEvent `json:"events"`
	Reason string      `json:"reason"`
}

// WatchFiles opens a watch on path through the toolbox pass-through. It
// returns once the agent has armed the watch, so a change made after it
// returns is reported. The handshake is sent once: a watch is a stream.
// watchStartTimeout bounds the wait for the agent's "start" frame. A
// variable for tests.
var watchStartTimeout = 60 * time.Second

func (c *Client) WatchFiles(ctx context.Context, id, path string, options WatchOptions) (*WatchHandle, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("path is required")
	}
	query := url.Values{"path": {path}}
	if options.Recursive {
		query.Set("recursive", "true")
	}
	wsURL, err := websocketURL(c.baseURL, c.versionPrefix+"/sandboxes/"+url.PathEscape(id)+"/toolbox/files/watch?"+query.Encode())
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	c.setAuthHeaders(header)
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return nil, watchHandshakeError(id, wsURL, resp, err)
	}

	// Wait for "start": the agent sends it once the kernel watch is armed.
	// The wait is bounded even when ctx has no deadline: a proxy that
	// accepts the upgrade and then goes quiet would otherwise block the
	// caller forever. Later reads are not bounded, since a quiet folder
	// sends nothing for as long as it stays quiet.
	var first watchFrame
	readErr := make(chan error, 1)
	go func() { readErr <- conn.ReadJSON(&first) }()
	startTimer := time.NewTimer(watchStartTimeout)
	defer startTimer.Stop()
	select {
	case err = <-readErr:
	case <-ctx.Done():
		_ = conn.Close()
		<-readErr
		return nil, ctx.Err()
	case <-startTimer.C:
		_ = conn.Close()
		<-readErr
		return nil, fmt.Errorf("file watch did not start within %s", watchStartTimeout)
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("file watch closed before it started: %w", describeReadErr(err))
	}
	if first.Type != "start" {
		_ = conn.Close()
		return nil, fmt.Errorf("file watch: unexpected first message %q", first.Type)
	}

	h := &WatchHandle{conn: conn, onEvent: options.OnEvent, stopped: make(chan struct{}), done: make(chan struct{})}
	go h.readLoop()
	go func() {
		select {
		case <-ctx.Done():
			h.finish(ctx.Err())
			_ = conn.Close()
		case <-h.done:
		}
	}()
	return h, nil
}

// watchHandshakeError turns a refused upgrade into the error callers can act
// on. A 404 from toolboxd's route table means the sandbox runs an agent
// built before file watching, which needs a restart (or a re-created
// Firecracker template), not a bug report.
func watchHandshakeError(id, wsURL string, resp *http.Response, err error) error {
	if resp == nil {
		return fmt.Errorf("file watch websocket dial %s: %w", wsURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	if resp.StatusCode == http.StatusNotFound {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &payload)
		// Agents older than the route-missing header answer a bare "not
		// found"; sandboxd says "sandbox not found" and a missing folder
		// "path not found: ...".
		if resp.Header.Get(routeMissingHeader) == "none" || payload.Error == "not found" {
			return &UnsupportedFeatureError{SandboxID: id, Features: []string{FeatureFilesWatch}}
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return decodeError(resp)
}

func (h *WatchHandle) readLoop() {
	for {
		var frame watchFrame
		if err := h.conn.ReadJSON(&frame); err != nil {
			select {
			case <-h.stopped:
				h.finish(nil)
			default:
				h.finish(fmt.Errorf("file watch dropped: %w", describeReadErr(err)))
			}
			return
		}
		switch frame.Type {
		case "events":
			if h.onEvent == nil {
				continue
			}
			for _, ev := range frame.Events {
				h.onEvent(ev)
			}
		case "end":
			reason := frame.Reason
			if reason == "" {
				reason = "file watch ended"
			}
			h.finish(&StreamError{Message: reason})
			_ = h.conn.Close()
			return
		}
	}
}

// Stop ends the watch. Wait then returns nil. Calling it again does nothing.
func (h *WatchHandle) Stop() error {
	h.stopOnce.Do(func() {
		close(h.stopped)
		_ = h.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadlineSoon())
		_ = h.conn.Close()
	})
	return nil
}

// Wait blocks until the watch ends. It returns nil after Stop, a
// *StreamError with the agent's reason when the agent ended the watch (the
// folder was removed or moved), or the error that dropped the connection.
func (h *WatchHandle) Wait() error {
	<-h.done
	return h.err
}

// Done is closed when the watch has ended.
func (h *WatchHandle) Done() <-chan struct{} { return h.done }

func (h *WatchHandle) finish(err error) {
	h.finishOnce.Do(func() {
		h.err = err
		close(h.done)
	})
}

// deadlineSoon bounds the close frame Stop sends: a dead peer must not hold
// Stop up.
func deadlineSoon() time.Time { return time.Now().Add(time.Second) }
