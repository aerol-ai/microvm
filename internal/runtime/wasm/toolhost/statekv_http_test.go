package toolhost_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/statekv"
	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
)

// ─── State KV with rate-limited store ────────────────────────────────────────

func TestHostStateKVRateLimited(t *testing.T) {
	inner := newMemStateKV()
	rl := statekv.NewRateLimitedStore(inner, 1 /*per sec*/, 1 /*burst*/)

	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   rl,
	})
	handler := h.Handler()

	// First write should succeed
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/state/kv/mykey", bytes.NewReader([]byte("value")))
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("first put status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Second write (immediately) should be rate-limited → 429
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/state/kv/mykey", bytes.NewReader([]byte("value2")))
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited put status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVDeleteRateLimited(t *testing.T) {
	inner := newMemStateKV()
	// Pre-load a key so delete is meaningful
	_ = inner.Set(context.Background(), "sb", "delkey", []byte("v"))
	rl := statekv.NewRateLimitedStore(inner, 1 /*per sec*/, 1 /*burst*/)

	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   rl,
	})
	handler := h.Handler()

	// First delete should succeed
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/state/kv/delkey", nil)
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first delete status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Second delete (immediately) should be rate-limited → 429
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/state/kv/delkey", nil)
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited delete status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVGetNotFound(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/state/kv/missing", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get not found status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVSetError(t *testing.T) {
	kv := &errStateKV{}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/state/kv/key", bytes.NewReader([]byte("val")))
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("set error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVDeleteError(t *testing.T) {
	kv := &errStateKV{}
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/state/kv/key", nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVInvalidKeyGet(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	// A key longer than 512 bytes → 400
	oversizedKey := string(make([]byte, 513))
	for i := range []byte(oversizedKey) {
		oversizedKey = oversizedKey[:i] + "a" + oversizedKey[i+1:]
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/state/kv/"+oversizedKey, nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key GET status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVInvalidKeyPut(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	// A key longer than 512 bytes → 400
	oversizedKey := string(make([]byte, 513))
	for i := 0; i < len(oversizedKey); i++ {
		oversizedKey = oversizedKey[:i] + "x" + oversizedKey[i+1:]
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/state/kv/"+oversizedKey, bytes.NewReader([]byte("val")))
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key PUT status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostStateKVInvalidKeyDelete(t *testing.T) {
	h := toolhost.New(toolhost.Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})
	// A key longer than 512 bytes → 400
	oversizedKey := string(make([]byte, 513))
	for i := 0; i < len(oversizedKey); i++ {
		oversizedKey = oversizedKey[:i] + "k" + oversizedKey[i+1:]
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/state/kv/"+oversizedKey, nil)
	h.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key DELETE status = %d body=%s", rec.Code, rec.Body.String())
	}
}
