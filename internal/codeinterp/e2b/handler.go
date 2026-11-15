// Package e2b serves E2B's Code Interpreter protocol, the HTTP server E2B
// runs on sandbox port 49999, on top of a codeinterp.Manager, so E2B's own
// code-interpreter SDKs work unchanged (plans/code-interpreter.md §4.2).
// toolboxd mounts it under /interpreter/e2b, and the E2B facade sends
// requests that carry E2b-Sandbox-Port: 49999 there.
//
// E2B's server is a behaviour reference only; nothing here is taken from it.
package e2b

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// maxBodyBytes bounds a request body. Code is sent inline, so the bound is
// the driver frame cap the code has to fit in anyway.
const maxBodyBytes = codeinterp.MaxFramePayload

type handler struct {
	m         *codeinterp.Manager
	logger    *slog.Logger
	keepalive time.Duration
	maxBody   int64
	now       func() time.Time
	mux       *http.ServeMux
	defaults  sync.Once
}

// NewHandler serves E2B's Code Interpreter routes from m, which should be
// built with ManagerOptions. Paths are relative to the mount point; query
// strings are ignored.
func NewHandler(m *codeinterp.Manager, logger *slog.Logger) http.Handler {
	return newHandler(m, logger, KeepaliveInterval)
}

func newHandler(m *codeinterp.Manager, logger *slog.Logger, keepalive time.Duration) *handler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	h := &handler{m: m, logger: logger, keepalive: keepalive, maxBody: maxBodyBytes, now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /execute", h.execute)
	mux.HandleFunc("POST /contexts", h.createContext)
	mux.HandleFunc("GET /contexts", h.listContexts)
	mux.HandleFunc("DELETE /contexts/{id}", h.deleteContext)
	mux.HandleFunc("POST /contexts/{id}/restart", h.restartContext)
	mux.HandleFunc("GET /health", h.health)
	h.mux = mux
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// E2B's server makes its python and javascript contexts at start, so
	// they head GET /contexts. Registering them costs nothing (a default's
	// kernel starts on its first run), so it happens on the first request
	// rather than at agent start, which keeps boot untouched.
	h.defaults.Do(h.registerDefaults)
	h.mux.ServeHTTP(w, r)
}

func (h *handler) registerDefaults() {
	for _, lang := range []string{codeinterp.LangPython, codeinterp.LangJavaScript} {
		if _, err := h.m.Default(lang); err != nil {
			// /execute registers it again on demand, so this is not fatal.
			h.logger.Warn("e2b interpreter: default context not registered", "language", lang, "error", err)
		}
	}
}

type executeRequest struct {
	Code      *string           `json:"code"`
	ContextID *string           `json:"context_id"`
	Language  *string           `json:"language"`
	EnvVars   map[string]string `json:"env_vars"`
}

type createContextRequest struct {
	Language *string `json:"language"`
	Cwd      *string `json:"cwd"`
}

type contextResponse struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Cwd      string `json:"cwd"`
}

func toContextResponse(info codeinterp.ContextInfo) contextResponse {
	return contextResponse{ID: info.ID, Language: info.Language, Cwd: info.Cwd}
}

func (h *handler) execute(w http.ResponseWriter, r *http.Request) {
	var req executeRequest
	if !h.decodeBody(w, r, &req, false) {
		return
	}
	if req.Code == nil {
		writeValidation(w, validationIssue{Type: "missing", Loc: []any{"body", "code"}, Msg: "Field required"})
		return
	}
	contextID, language := deref(req.ContextID), deref(req.Language)
	if contextID != "" && language != "" {
		writeText(w, http.StatusBadRequest, "Only one of context_id or language can be provided")
		return
	}

	var info codeinterp.ContextInfo
	var err error
	switch {
	case language != "":
		info, err = h.m.Default(language)
	case contextID != "":
		info, err = h.m.Get(contextID)
	default:
		info, err = h.m.Default(codeinterp.LangPython)
	}
	if err != nil {
		h.writeLookupError(w, contextID, err)
		return
	}

	// Headers go out before the run waits in the context's queue: the SDKs
	// bound the wait for headers far more tightly (60 s in JavaScript) than
	// the run itself, and a run behind a long one may wait for minutes.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()

	out := newStream(w, h.keepalive)
	sink := func(ev codeinterp.Event) { out.send(eventLine(ev, h.now())) }
	res, err := h.m.Run(r.Context(), info.ID, codeinterp.Request{Code: *req.Code, Env: req.EnvVars}, sink,
		// No server timeout, as on E2B: the SDK's own timeout closes the
		// connection, and a client that goes away interrupts the run while
		// the context keeps its state.
		codeinterp.RunPolicy{InterruptOnCancel: true})
	switch {
	case err != nil:
		out.send(newErrorLine(runErrorName(err), err.Error(), ""))
	case res.Restarted:
		out.send(newErrorLine(errNameRestarting, errTextRestarting, ""))
	case res.Died:
		out.send(newErrorLine(errNameUnexpected, errTextUnexpected, ""))
	}
	// The SDKs treat the end line as the only proof the run finished.
	out.send(endLine)
	out.close()
}

// runErrorName names an error that ended a run before its code ran, for
// the error line that replaces the run's output.
func runErrorName(err error) string {
	var missing *codeinterp.MissingInterpreterError
	switch {
	case errors.As(err, &missing):
		return "InterpreterNotFound"
	case errors.Is(err, codeinterp.ErrQueueFull):
		return "ContextBusy"
	case codeinterp.IsNotFound(err):
		return "ContextNotFound"
	}
	return "InterpreterError"
}

// writeLookupError answers a context lookup that failed before the stream
// started, with E2B's plain-text bodies.
func (h *handler) writeLookupError(w http.ResponseWriter, contextID string, err error) {
	switch {
	case codeinterp.IsNotFound(err):
		writeText(w, http.StatusNotFound, fmt.Sprintf("Context %s not found", contextID))
	case errors.Is(err, codeinterp.ErrUnsupportedLanguage):
		writeText(w, http.StatusBadRequest, err.Error())
	default:
		h.writeCreateError(w, err)
	}
}

// writeCreateError answers a failed context create. A full sandbox is 429
// (plans/code-interpreter.md D11); the SDKs show the status and body
// whatever it is.
func (h *handler) writeCreateError(w http.ResponseWriter, err error) {
	msg := "Failed to create context: " + err.Error()
	switch {
	case errors.Is(err, codeinterp.ErrUnsupportedLanguage):
		writeText(w, http.StatusBadRequest, msg)
	case errors.Is(err, codeinterp.ErrLimit):
		writeText(w, http.StatusTooManyRequests, msg)
	case errors.Is(err, codeinterp.ErrClosed):
		writeText(w, http.StatusServiceUnavailable, msg)
	default:
		h.logger.Warn("e2b interpreter: context create failed", "error", err)
		writeText(w, http.StatusInternalServerError, msg)
	}
}

func (h *handler) createContext(w http.ResponseWriter, r *http.Request) {
	var req createContextRequest
	// The JavaScript SDK sends {} and E2B fills the defaults; an empty body
	// means the same here.
	if !h.decodeBody(w, r, &req, true) {
		return
	}
	info, err := h.m.Create(r.Context(), deref(req.Language), deref(req.Cwd))
	if err != nil {
		h.writeCreateError(w, err)
		return
	}
	writeJSON(w, toContextResponse(info))
}

func (h *handler) listContexts(w http.ResponseWriter, _ *http.Request) {
	list := h.m.List()
	out := make([]contextResponse, 0, len(list))
	for _, info := range list {
		out = append(out, toContextResponse(info))
	}
	writeJSON(w, out)
}

func (h *handler) deleteContext(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.m.Delete(id); err != nil {
		h.writeContextError(w, id, "remove", err)
		return
	}
	writeJSON(w, nil)
}

func (h *handler) restartContext(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.m.Restart(r.Context(), id); err != nil {
		h.writeContextError(w, id, "restart", err)
		return
	}
	writeJSON(w, nil)
}

func (h *handler) writeContextError(w http.ResponseWriter, id, verb string, err error) {
	if codeinterp.IsNotFound(err) {
		writeText(w, http.StatusNotFound, fmt.Sprintf("Context %s not found", id))
		return
	}
	status := http.StatusInternalServerError
	if errors.Is(err, codeinterp.ErrClosed) {
		status = http.StatusServiceUnavailable
	} else {
		h.logger.Warn("e2b interpreter: context "+verb+" failed", "context_id", id, "error", err)
	}
	writeText(w, status, fmt.Sprintf("Failed to %s context %s: %v", verb, id, err))
}

func (h *handler) health(w http.ResponseWriter, _ *http.Request) {
	// E2B's server returns the JSON string "OK".
	writeJSON(w, "OK")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// validationIssue is one entry of a 422 body, shaped like the FastAPI
// validation errors E2B's server returns.
type validationIssue struct {
	Type string `json:"type"`
	Loc  []any  `json:"loc"`
	Msg  string `json:"msg"`
}

func writeValidation(w http.ResponseWriter, issues ...validationIssue) {
	body, _ := json.Marshal(map[string]any{"detail": issues})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_, _ = w.Write(body)
}

// decodeBody reads a JSON object into dst. It answers 422 (E2B's status for
// a body that does not fit the model) and returns false when it cannot.
func (h *handler) decodeBody(w http.ResponseWriter, r *http.Request, dst any, allowEmpty bool) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeText(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body is larger than %d bytes", h.maxBody))
			return false
		}
		writeText(w, http.StatusBadRequest, "failed to read the request body")
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if allowEmpty {
			return true
		}
		writeValidation(w, validationIssue{Type: "missing", Loc: []any{"body"}, Msg: "Field required"})
		return false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			loc := []any{"body"}
			if typeErr.Field != "" {
				for _, part := range strings.Split(typeErr.Field, ".") {
					loc = append(loc, part)
				}
			}
			writeValidation(w, validationIssue{Type: "type_error", Loc: loc, Msg: "Input should be a valid " + jsonKind(typeErr.Type)})
			return false
		}
		writeValidation(w, validationIssue{Type: "json_invalid", Loc: []any{"body"}, Msg: "JSON decode error: " + err.Error()})
		return false
	}
	return true
}

func writeText(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

// jsonKind names the JSON type a Go type expects, for a 422 message.
func jsonKind(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Map, reflect.Struct:
		return "object"
	}
	return t.Kind().String()
}

// writeJSON writes v with status 200 and no trailing newline, as E2B's
// server does (DELETE and restart answer the body null). Callers pass only
// strings, nil and context records, which always marshal.
func writeJSON(w http.ResponseWriter, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
