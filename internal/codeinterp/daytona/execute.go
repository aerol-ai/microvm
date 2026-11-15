package daytona

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// outputFrame is every Daytona frame. Daytona's clients expect all five
// fields on each one, empty or not.
type outputFrame struct {
	Type      string `json:"type"`
	Text      string `json:"text"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Traceback string `json:"traceback"`
}

// countFrame is the AerolVM execution_count frame (richOutput only).
type countFrame struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// resultFields maps MIME types to E2B's result field names, which the
// AerolVM SDKs share. Any other type goes under "extra".
var resultFields = map[string]string{
	"text/plain":             "text",
	"text/html":              "html",
	"text/markdown":          "markdown",
	"image/svg+xml":          "svg",
	"image/png":              "png",
	"image/jpeg":             "jpeg",
	"application/pdf":        "pdf",
	"text/latex":             "latex",
	"application/json":       "json",
	"application/javascript": "javascript",
	"e2b/data":               "data",
}

func resultFrame(ev codeinterp.Event) map[string]any {
	out := map[string]any{"type": "result", "is_main_result": ev.Main}
	extra := map[string]any{}
	for mime, value := range ev.Bundle {
		if field, ok := resultFields[mime]; ok {
			out[field] = value
		} else {
			extra[mime] = value
		}
	}
	if len(extra) > 0 {
		out["extra"] = extra
	}
	return out
}

func control(text string) outputFrame { return outputFrame{Type: "control", Text: text} }

// session is one execute WebSocket after its first message.
type session struct {
	h    *handler
	conn *websocket.Conn

	out        chan any
	writerDone chan struct{}
	readerDone chan struct{}
	gone       chan struct{}
	goneOnce   sync.Once
	stopPing   chan struct{}
}

func (s *session) markGone() { s.goneOnce.Do(func() { close(s.gone) }) }

// send queues a frame. It never blocks on a client that is gone: Daytona
// keeps the run going and drops its output.
func (s *session) send(frame any) {
	select {
	case s.out <- frame:
	case <-s.gone:
	}
}

// writer is the connection's only data writer (gorilla allows one).
func (s *session) writer() {
	defer close(s.writerDone)
	for frame := range s.out {
		select {
		case <-s.gone:
			continue
		default:
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.h.live.writeWait))
		if err := s.conn.WriteJSON(frame); err != nil {
			s.markGone()
		}
	}
}

// reader reads after the first message: it answers pings (gorilla does that
// inside reads), extends the deadline, and takes interrupts.
func (s *session) reader(contextID string) {
	defer close(s.readerDone)
	defer s.markGone()
	extend := func() { _ = s.conn.SetReadDeadline(time.Now().Add(s.h.live.pongWait)) }
	extend()
	s.conn.SetPongHandler(func(string) error {
		extend()
		return nil
	})
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			return
		}
		extend()
		var msg ClientMessage
		if json.Unmarshal(data, &msg) == nil && msg.Type == "interrupt" {
			if err := s.h.m.Interrupt(contextID); err != nil {
				s.h.logger.Debug("code interpreter interrupt failed", "context", contextID, "error", err)
			}
		}
	}
}

// pinger keeps proxies that cut idle connections from cutting a quiet run,
// and finds a client that vanished.
func (s *session) pinger() {
	t := time.NewTicker(s.h.live.interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopPing:
			return
		case <-s.gone:
			return
		case <-t.C:
			// WriteControl may run alongside the writer.
			if err := s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(s.h.live.writeWait)); err != nil {
				s.markGone()
				return
			}
		}
	}
}

// finish sends the queued frames, then the close frame, and waits a little
// for the client's answer so it reads the close code.
func (s *session) finish(code int, reason string) {
	close(s.out)
	<-s.writerDone
	close(s.stopPing)
	select {
	case <-s.gone:
		return
	default:
	}
	msg := websocket.FormatCloseMessage(code, closeReason(reason))
	if err := s.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(s.h.live.writeWait)); err != nil {
		return
	}
	select {
	case <-s.readerDone:
	case <-time.After(s.h.closeWait):
	}
}

// closeEarly ends a connection whose run never started.
func (h *handler) closeEarly(conn *websocket.Conn, code int, reason string) {
	msg := websocket.FormatCloseMessage(code, closeReason(reason))
	_ = conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(h.live.writeWait))
	// Read until the client answers so it sees the code, bounded.
	_ = conn.SetReadDeadline(time.Now().Add(h.closeWait))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (h *handler) execute(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("code interpreter upgrade failed", "error", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxMessage)

	_ = conn.SetReadDeadline(time.Now().Add(h.firstWait))
	_, data, err := conn.ReadMessage()
	if err != nil {
		h.closeEarly(conn, websocket.CloseProtocolError, "expected an execute request")
		return
	}
	var req ExecuteRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.closeEarly(conn, websocket.CloseProtocolError, "invalid execute request: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		h.closeEarly(conn, websocket.ClosePolicyViolation, "code is required")
		return
	}
	timeout := DefaultTimeout
	if req.Timeout != nil {
		switch t := *req.Timeout; {
		case t < 0 || math.IsNaN(t):
			h.closeEarly(conn, websocket.ClosePolicyViolation, "timeout must be 0 (none) or a number of seconds")
			return
		case t*float64(time.Second) >= math.MaxInt64:
			timeout = 0 // longer than any run can last
		default:
			timeout = time.Duration(t * float64(time.Second))
		}
	}

	var info codeinterp.ContextInfo
	if req.ContextID != "" {
		info, err = h.lookup(req.ContextID)
	} else {
		info, err = h.m.Default(req.Language)
	}
	if err != nil {
		code, reason := closeFor(err, req.ContextID)
		h.closeEarly(conn, code, reason)
		return
	}

	s := &session{
		h:          h,
		conn:       conn,
		out:        make(chan any, 64),
		writerDone: make(chan struct{}),
		readerDone: make(chan struct{}),
		gone:       make(chan struct{}),
		stopPing:   make(chan struct{}),
	}
	go s.writer()
	go s.reader(info.ID)
	go s.pinger()

	sink := func(ev codeinterp.Event) {
		switch ev.Kind {
		case codeinterp.EventStdout:
			s.send(outputFrame{Type: "stdout", Text: ev.Text})
		case codeinterp.EventStderr:
			s.send(outputFrame{Type: "stderr", Text: ev.Text})
		case codeinterp.EventError:
			s.send(outputFrame{Type: "error", Name: ev.ErrName, Value: ev.ErrValue, Traceback: ev.ErrTraceback})
		case codeinterp.EventResult:
			if req.RichOutput {
				s.send(resultFrame(ev))
			}
		case codeinterp.EventCount:
			if req.RichOutput {
				s.send(countFrame{Type: "execution_count", Count: ev.Count})
			}
		}
	}
	res, err := h.m.Run(runContext(r), info.ID, codeinterp.Request{Code: req.Code, Env: req.Envs}, sink,
		codeinterp.RunPolicy{Timeout: timeout, Grace: interruptGrace})
	switch {
	case err != nil:
		code, reason := closeFor(err, info.ID)
		s.finish(code, reason)
	case res.TimedOut:
		s.send(control("interrupted"))
		s.finish(CloseTimeout, "execution timed out")
	case res.Restarted:
		s.finish(websocket.CloseGoingAway, "context shutdown")
	case res.Interrupted():
		// Before Died: a WASM kernel has no signals, so its interrupt kills
		// the interpreter (the run is both). The client asked for the stop
		// and gets the usual answer; the context reports active:false.
		s.send(control("interrupted"))
		s.finish(websocket.CloseNormalClosure, "")
	case res.Died:
		s.finish(websocket.CloseGoingAway, "worker process ended")
	default:
		s.send(control("completed"))
		s.finish(websocket.CloseNormalClosure, "")
	}
}

// closeFor maps a Manager error to a close code: the client's fault is
// 1008, a failed interpreter start 1011.
func closeFor(err error, id string) (int, string) {
	switch {
	case errors.Is(err, codeinterp.ErrNotFound):
		return websocket.ClosePolicyViolation, "context not found: " + id
	case errors.Is(err, codeinterp.ErrQueueFull), errors.Is(err, codeinterp.ErrLimit),
		errors.Is(err, codeinterp.ErrUnsupportedLanguage):
		return websocket.ClosePolicyViolation, err.Error()
	case errors.Is(err, codeinterp.ErrClosed):
		return websocket.CloseGoingAway, err.Error()
	}
	return websocket.CloseInternalServerErr, err.Error()
}
