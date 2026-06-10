package toolhost_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/pkg/models"
)

func newSessionsManager(t *testing.T) *sessions.Manager {
	t.Helper()
	recDir := t.TempDir()
	mgr, err := sessions.New(slog.Default(), sessions.Config{
		SandboxID:    "sb-test",
		RecordingDir: recDir,
		BufferBytes:  64 * 1024,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

func newHostWithSessions(t *testing.T) (*toolhost.Host, *sessions.Manager) {
	t.Helper()
	mgr := newSessionsManager(t)
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb-test",
		WorkDir:   t.TempDir(),
		Sessions:  mgr,
		Exec:      &stubExec{},
		StateKV:   newMemStateKV(),
	})
	return h, mgr
}

// ─── Sessions create / list / get / delete with real manager ─────────────────

func TestSessionsCreateAndList(t *testing.T) {
	h, _ := newHostWithSessions(t)

	// create a session
	req := models.CreateSessionRequest{Command: "echo hello", PTY: false}
	payload, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	var created models.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create json: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected session ID")
	}

	// list sessions
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/sessions", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var list models.SessionList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list json: %v", err)
	}
	if len(list.Sessions) == 0 {
		t.Fatal("expected at least one session in list")
	}
}

func TestSessionsGetByID(t *testing.T) {
	h, mgr := newHostWithSessions(t)

	// create session through manager directly
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "sleep 1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// get by ID
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID(), nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsGetNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/sessions/nonexistent-id", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsDeleteByID(t *testing.T) {
	h, mgr := newHostWithSessions(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "sleep 60"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/sessions/"+sess.ID(), nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsDeleteNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/sessions/nonexistent", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsSignalNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(models.SessionSignalRequest{Signal: "TERM"})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sessions/nonexistent/signal", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("signal unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsSignalBadJSON(t *testing.T) {
	h, mgr := newHostWithSessions(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "sleep 60"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(sess.ID()) })

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID()+"/signal", bytes.NewReader([]byte("notjson")))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json signal status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsResizeNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	payload, _ := json.Marshal(models.SessionResizeRequest{Cols: 80, Rows: 24})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sessions/nonexistent/resize", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("resize unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsResizeBadJSON(t *testing.T) {
	h, mgr := newHostWithSessions(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "sleep 60"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(sess.ID()) })

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID()+"/resize", bytes.NewReader([]byte("notjson")))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json resize status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsLogNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/sessions/nonexistent/log", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("log unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsLogFound(t *testing.T) {
	h, mgr := newHostWithSessions(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{Command: "echo hello"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// give it time to run
	time.Sleep(100 * time.Millisecond)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/log", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("log status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsRecordingNotFound(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/sessions/nonexistent/recording", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("recording unknown status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsCreateBadJSON(t *testing.T) {
	h, _ := newHostWithSessions(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte("notjson")))
	r.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json create status = %d body=%s", rec.Code, rec.Body.String())
	}
}
