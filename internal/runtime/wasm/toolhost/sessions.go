package toolhost

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

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

func (h *Host) handleSessionsRoute(w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/sessions")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		switch r.Method {
		case http.MethodPost:
			h.handleSessionsCreate(w, r)
			return true
		case http.MethodGet:
			h.handleSessionsList(w, r)
			return true
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return true
	}
	id, action, _ := strings.Cut(path, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "session id required")
		return true
	}
	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			h.handleSessionGet(w, r, id)
		case http.MethodDelete:
			h.handleSessionDelete(w, r, id)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "signal":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		h.handleSessionSignal(w, r, id)
	case "resize":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		h.handleSessionResize(w, r, id)
	case "log":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		h.handleSessionLog(w, r, id)
	case "recording":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		h.handleSessionRecording(w, r, id)
	case "attach":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		h.handleSessionAttach(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
	return true
}

func (h *Host) handleSessionsCreate(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		writeError(w, http.StatusServiceUnavailable, "sessions disabled")
		return
	}
	var req models.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.WorkDir) == "" {
		req.WorkDir = h.workDir
	}
	sess, err := h.sessions.Create(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sess.Snapshot())
}

func (h *Host) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		writeJSON(w, http.StatusOK, models.SessionList{Sessions: []models.Session{}})
		return
	}
	writeJSON(w, http.StatusOK, models.SessionList{Sessions: h.sessions.List()})
}

func (h *Host) handleSessionGet(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := h.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sess.Snapshot())
}

func (h *Host) handleSessionDelete(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.sessions.Delete(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Host) handleSessionSignal(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := h.sessions.Get(id)
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

func (h *Host) handleSessionResize(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := h.sessions.Get(id)
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

func (h *Host) handleSessionLog(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := h.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sess.Replay())
}

func (h *Host) handleSessionRecording(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := h.sessions.Get(id)
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
	_, _ = io.Copy(w, f)
}

func (h *Host) handleSessionAttach(w http.ResponseWriter, r *http.Request, id string) {
	if h.sessions == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sess, err := h.sessions.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	conn, err := sessionAttachUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Default().Warn("wasm session attach upgrade failed", "error", err)
		return
	}
	defer conn.Close()
	pumpWasmSession(conn, sess)
}

func pumpWasmSession(conn *websocket.Conn, sess *sessions.Session) {
	frames, cancel := sess.Subscribe()
	defer cancel()

	doneCh := make(chan struct{})
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

	for {
		select {
		case <-doneCh:
			return
		case <-sess.Done():
			drainSessionFrames(conn, frames)
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

func drainSessionFrames(conn *websocket.Conn, frames <-chan sessions.Frame) {
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
