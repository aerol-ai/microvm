// Package daytona serves Daytona's codeInterpreter protocol on top of a
// codeinterp.Manager (plans/code-interpreter.md, section 4.1). The AerolVM
// SDKs speak the same protocol with two opt-in extensions: "richOutput" in
// the first message turns on result and execution_count frames, and the
// client may send {"type":"interrupt"}. A Daytona client never sends either,
// so it sees Daytona's exact protocol.
//
// Paths are relative to /process/interpreter:
//
//	POST   /context               create a context
//	GET    /context               list contexts (the default one is left out)
//	GET    /context/{id}          one context (AerolVM)
//	DELETE /context/{id}          delete a context
//	POST   /context/{id}/restart  new interpreter, same id (AerolVM)
//	GET    /execute               WebSocket: one run per connection
//
// Written from the protocol only; no Daytona server code is used.
package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// DefaultContextID is the python context a run without a contextId uses.
// Daytona has it from the start, leaves it out of the list and refuses to
// delete it.
const DefaultContextID = "default"

// ManagerOptions returns the Manager options for Daytona's semantics. When
// the launcher can say which languages it has drivers for (a Languages
// method), other languages are refused up front with HTTP 400 instead of
// failing at launch.
func ManagerOptions(l codeinterp.Launcher, lim *codeinterp.Limit, defaultCwd string) codeinterp.Options {
	opts := codeinterp.Options{
		Launcher:   l,
		Limit:      lim,
		DefaultCwd: defaultCwd,
		DefaultID: func(language string) string {
			if language == codeinterp.LangPython {
				return DefaultContextID
			}
			return ""
		},
		ProtectDefaults: true,
	}
	if ls, ok := l.(interface{ Languages() []string }); ok {
		opts.Languages = ls.Languages()
	}
	return opts
}

// CreateContextRequest is the body of POST /context.
type CreateContextRequest struct {
	Cwd string `json:"cwd,omitempty"`
	// Language is python unless set; Daytona's SDKs never set it.
	Language string `json:"language,omitempty"`
}

// ExecuteRequest is the first message on the execute WebSocket.
type ExecuteRequest struct {
	Code string `json:"code"`
	// ContextID empty means a default context: Language's (AerolVM), or
	// python's "default".
	ContextID string            `json:"contextId,omitempty"`
	Language  string            `json:"language,omitempty"`
	Envs      map[string]string `json:"envs,omitempty"`
	// Timeout is in seconds: absent means DefaultTimeout, 0 means none.
	Timeout *float64 `json:"timeout,omitempty"`
	// RichOutput adds result and execution_count frames (AerolVM).
	RichOutput bool `json:"richOutput,omitempty"`
}

// ClientMessage is a message the client sends after the first one.
type ClientMessage struct {
	// Type "interrupt" interrupts the run (AerolVM). Others are ignored.
	Type string `json:"type"`
}

// DefaultTimeout is a run's timeout when the request names none, as on
// Daytona.
const DefaultTimeout = 600 * time.Second

const (
	// maxBody bounds a context request body.
	maxBody = 1 << 20
	// maxMessage bounds a client WebSocket message; the first one carries
	// the code.
	maxMessage = codeinterp.MaxFramePayload
	// firstMessageWait bounds how long a client may take to send its run.
	firstMessageWait = 10 * time.Second
	// interruptGrace is how long an interrupted (timed out) run has to stop
	// before its interpreter is killed.
	interruptGrace = 2 * time.Second
	// closeWait bounds the wait for the client's answer to our close frame.
	closeWait = 2 * time.Second
	// maxCloseReason is the room for a close frame's reason (125 - 2).
	maxCloseReason = 123
)

// Close codes beyond the standard ones.
const (
	// CloseTimeout ends a run that hit its timeout (Daytona's 4008).
	CloseTimeout = 4008
)

// liveness is the keepalive: a ping every interval, a client that answers
// nothing for pongWait is gone, and one frame write may take writeWait.
type liveness struct {
	interval  time.Duration
	pongWait  time.Duration
	writeWait time.Duration
}

var defaultLiveness = liveness{interval: 30 * time.Second, pongWait: 90 * time.Second, writeWait: 30 * time.Second}

type handler struct {
	m         *codeinterp.Manager
	logger    *slog.Logger
	live      liveness
	firstWait time.Duration
	closeWait time.Duration
	upgrader  websocket.Upgrader
}

// NewHandler serves the protocol for m. Mount it with the /process/interpreter
// prefix stripped.
func NewHandler(m *codeinterp.Manager, logger *slog.Logger) http.Handler {
	return newHandler(m, logger)
}

func newHandler(m *codeinterp.Manager, logger *slog.Logger) *handler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &handler{
		m:         m,
		logger:    logger,
		live:      defaultLiveness,
		firstWait: firstMessageWait,
		closeWait: closeWait,
		upgrader: websocket.Upgrader{
			// The caller authenticated before the upgrade (toolboxd's bearer
			// check), and SDK clients send no Origin.
			CheckOrigin:     func(*http.Request) bool { return true },
			ReadBufferSize:  64 << 10,
			WriteBufferSize: 64 << 10,
			// Browsers pass the token as this subprotocol; echo it.
			Subprotocols: []string{"sandbox.bearer"},
			Error: func(w http.ResponseWriter, _ *http.Request, status int, reason error) {
				writeError(w, status, reason.Error())
			},
		},
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/context":
		switch r.Method {
		case http.MethodPost:
			h.create(w, r)
		case http.MethodGet:
			h.list(w)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case strings.HasPrefix(path, "/context/"):
		rest := strings.TrimPrefix(path, "/context/")
		if id, ok := strings.CutSuffix(rest, "/restart"); ok && validID(id) {
			if r.Method != http.MethodPost {
				methodNotAllowed(w, "POST")
				return
			}
			h.restart(w, r, id)
			return
		}
		if !validID(rest) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.get(w, rest)
		case http.MethodDelete:
			h.delete(w, rest)
		default:
			methodNotAllowed(w, "GET, DELETE")
		}
	case path == "/execute":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		h.execute(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func validID(id string) bool { return id != "" && !strings.Contains(id, "/") }

// contextJSON is Daytona's InterpreterContext: its client requires all five
// fields.
type contextJSON struct {
	ID        string `json:"id"`
	Cwd       string `json:"cwd"`
	CreatedAt string `json:"createdAt"`
	Active    bool   `json:"active"`
	Language  string `json:"language"`
}

func toJSON(info codeinterp.ContextInfo) contextJSON {
	return contextJSON{
		ID:        info.ID,
		Cwd:       info.Cwd,
		CreatedAt: info.CreatedAt.UTC().Format(time.RFC3339Nano),
		Active:    info.Active,
		Language:  info.Language,
	}
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var req CreateContextRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(string(body)) != "" {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}
	info, err := h.m.Create(r.Context(), req.Language, req.Cwd)
	if err != nil {
		h.writeManagerError(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, toJSON(info))
}

func (h *handler) list(w http.ResponseWriter) {
	infos := h.m.List()
	out := make([]contextJSON, 0, len(infos))
	for _, info := range infos {
		out = append(out, toJSON(info))
	}
	writeJSON(w, http.StatusOK, map[string]any{"contexts": out})
}

// lookup finds a context. "default" always exists, as on Daytona, though
// the Manager registers it only on first use.
func (h *handler) lookup(id string) (codeinterp.ContextInfo, error) {
	if id == DefaultContextID {
		return h.m.Default(codeinterp.LangPython)
	}
	return h.m.Get(id)
}

func (h *handler) get(w http.ResponseWriter, id string) {
	info, err := h.lookup(id)
	if err != nil {
		h.writeManagerError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, toJSON(info))
}

func (h *handler) delete(w http.ResponseWriter, id string) {
	err := codeinterp.ErrDefaultContext
	if id != DefaultContextID {
		err = h.m.Delete(id)
	}
	if err != nil {
		h.writeManagerError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Context deleted successfully"})
}

func (h *handler) restart(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := h.lookup(id); err != nil {
		h.writeManagerError(w, err, id)
		return
	}
	info, err := h.m.Restart(r.Context(), id)
	if err != nil {
		h.writeManagerError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, toJSON(info))
}

func (h *handler) writeManagerError(w http.ResponseWriter, err error, id string) {
	var missing *codeinterp.MissingInterpreterError
	switch {
	case errors.Is(err, codeinterp.ErrNotFound):
		writeError(w, http.StatusNotFound, "context not found: "+id)
	case errors.Is(err, codeinterp.ErrUnsupportedLanguage), errors.Is(err, codeinterp.ErrDefaultContext):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, codeinterp.ErrLimit), errors.Is(err, codeinterp.ErrQueueFull):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, codeinterp.ErrClosed):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.As(err, &missing):
		// It says which programs to install in the image.
		writeError(w, http.StatusInternalServerError, missing.Error())
	default:
		// A bad cwd or a driver that failed. The message may name host
		// paths (closeFor), so only the log has it.
		h.logger.Warn("code interpreter context failed", "context", id, "error", err)
		writeError(w, http.StatusInternalServerError, internalErrorText)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError answers with both "error" and "message": Daytona's clients
// read the one, toolboxd's other routes use the other.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "message": msg})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// closeReason fits msg into a close frame without cutting a character.
func closeReason(msg string) string {
	if len(msg) <= maxCloseReason {
		return msg
	}
	cut := maxCloseReason
	for cut > 0 && !utf8RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// runContext is the context a run waits and starts its interpreter under:
// Daytona keeps running a run whose client went away, so it is not the
// request's.
func runContext(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}
