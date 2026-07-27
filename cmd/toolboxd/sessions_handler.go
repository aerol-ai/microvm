package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

// Path scheme:
//   POST   /sessions                  → create
//   GET    /sessions                  → list
//   GET    /sessions/{id}             → metadata
//   DELETE /sessions/{id}             → kill + drop
//   POST   /sessions/{id}/signal      → send signal
//   POST   /sessions/{id}/resize      → resize PTY
//   GET    /sessions/{id}/log         → snapshot of replay buffer (text/plain)
//   GET    /sessions/{id}/recording   → cast file
//   GET    /sessions/{id}/attach      → WebSocket attach (replay + live)
//
// Frame protocol on the attach WS:
//   server → client : binary frames; first byte 0x01=stdout 0x02=stderr,
//                     remainder is the chunk. Plus JSON text frames for
//                     control: {"type":"exit","code":N,"signal":"…"}.
//   client → server : binary frames are stdin. JSON text frames carry
//                     control: {"type":"resize","cols":N,"rows":N},
//                     {"type":"signal","signal":"TERM"}.

const (
	streamFramePrefixStdoutSession byte = 0x01
	streamFramePrefixStderrSession byte = 0x02
)

var sessionAttachUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
	Subprotocols:    []string{"sandbox.bearer"},
}

type sessionAttachControlIn struct {
	Type   string `json:"type"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Signal string `json:"signal,omitempty"`
}

type sessionAttachControlOut struct {
	Type    string `json:"type"`
	Code    int    `json:"code,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Message string `json:"message,omitempty"`
}

func (s *server) handleSessionsCreate(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions disabled")
		return
	}
	var req models.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sess, err := s.sessions.Create(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sess.Snapshot())
}

func (s *server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, models.SessionList{Sessions: []models.Session{}})
		return
	}
	writeJSON(w, http.StatusOK, models.SessionList{Sessions: s.sessions.List()})
}

func (s *server) handleSessionGet(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := s.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sess.Snapshot())
}

func (s *server) handleSessionDelete(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.sessions.Delete(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleSessionSignal(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := s.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var body models.SessionSignalRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := sess.Signal(body.Signal); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleSessionResize(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := s.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var body models.SessionResizeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := sess.Resize(body.Cols, body.Rows); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleSessionLog(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := s.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sess.Replay())
}

func (s *server) handleSessionRecording(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := s.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	path := sess.RecordingPath()
	if path == "" {
		writeError(w, http.StatusNotFound, "no recording")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-asciicast+json-seq")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".cast"))
	w.WriteHeader(http.StatusOK)
	_, _ = copyToResponse(w, f)
}

// copyToResponse is io.Copy with a small buffer so large recordings don't
// allocate a massive intermediate.
func copyToResponse(w http.ResponseWriter, f *os.File) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func (s *server) handleSessionAttach(w http.ResponseWriter, r *http.Request, id string) {
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := s.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	conn, err := sessionAttachUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Warn("session attach upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	pumpSession(s, conn, sess)
}

func pumpSession(s *server, conn *websocket.Conn, sess *sessions.Session) {
	frames, cancel := sess.Subscribe()
	defer cancel()

	doneCh := make(chan struct{})
	// Client → session: stdin and control.
	go func() {
		defer close(doneCh)
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch msgType {
			case websocket.BinaryMessage:
				if _, err := sess.Write(data); err != nil {
					return
				}
			case websocket.TextMessage:
				var ctrl sessionAttachControlIn
				if err := json.Unmarshal(data, &ctrl); err != nil {
					continue
				}
				switch ctrl.Type {
				case "resize":
					_ = sess.Resize(ctrl.Cols, ctrl.Rows)
				case "signal":
					_ = sess.Signal(ctrl.Signal)
				case "close":
					return
				}
			}
		}
	}()

	// Session → client.
	for {
		select {
		case <-doneCh:
			return
		case <-sess.Done():
			// Drain remaining frames, then send exit.
			drain(conn, frames)
			code, sig := sess.ExitInfo()
			_ = conn.WriteJSON(sessionAttachControlOut{Type: "exit", Code: code, Signal: sig})
			return
		case frame, ok := <-frames:
			if !ok {
				code, sig := sess.ExitInfo()
				_ = conn.WriteJSON(sessionAttachControlOut{Type: "exit", Code: code, Signal: sig})
				return
			}
			prefix := streamFramePrefixStdoutSession
			if frame.Stream == sessions.StreamStderr {
				prefix = streamFramePrefixStderrSession
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{prefix}, frame.Data...)); err != nil {
				return
			}
		}
	}
}

func drain(conn *websocket.Conn, frames <-chan sessions.Frame) {
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		select {
		case frame, ok := <-frames:
			if !ok {
				return
			}
			prefix := streamFramePrefixStdoutSession
			if frame.Stream == sessions.StreamStderr {
				prefix = streamFramePrefixStderrSession
			}
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{prefix}, frame.Data...))
		default:
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// sessionPath dispatches /sessions* paths after the prefix has been stripped
// by the main router. Returns true if the request was handled here.
func (s *server) handleSessionsRoute(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path == "/sessions" {
		switch r.Method {
		case http.MethodPost:
			s.handleSessionsCreate(w, r)
		case http.MethodGet:
			s.handleSessionsList(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return true
	}
	const prefix = "/sessions/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	id, action, _ := strings.Cut(rest, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "session id required")
		return true
	}
	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			s.handleSessionGet(w, r, id)
		case http.MethodDelete:
			s.handleSessionDelete(w, r, id)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "signal":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		s.handleSessionSignal(w, r, id)
	case "resize":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		s.handleSessionResize(w, r, id)
	case "log":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		s.handleSessionLog(w, r, id)
	case "recording":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		s.handleSessionRecording(w, r, id)
	case "attach":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		s.handleSessionAttach(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
	return true
}
