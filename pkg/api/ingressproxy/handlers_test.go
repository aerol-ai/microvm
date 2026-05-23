package ingressproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
)

type fakeResolver struct {
	target  string
	err     error
	callCnt int
	lastID  string
	lastPrt int
}

func (f *fakeResolver) WakeAwarePortTarget(_ context.Context, id string, port int) (service.PortEndpoint, error) {
	f.callCnt++
	f.lastID = id
	f.lastPrt = port
	if f.err != nil {
		return service.PortEndpoint{}, f.err
	}
	return service.PortEndpoint{URL: f.target}, nil
}

func newHandler(resolver PortResolver, max int64) http.Handler {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Resolver: resolver, MaxBufferBytes: max})
	return mux
}

func TestHTTPWakeProxiesToUpstream(t *testing.T) {
	// Upstream simulates the now-awake container on its exposed port.
	var gotPath, gotBody, gotMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Upstream", "hit")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	resolver := &fakeResolver{target: upstream.URL}
	h := newHandler(resolver, 1024)

	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/abc123/3000/api/echo?q=1",
		strings.NewReader("payload"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Upstream") != "hit" {
		t.Fatalf("missing upstream header — proxy didn't reach it: %+v", rec.Header())
	}
	if resolver.lastID != "abc123" || resolver.lastPrt != 3000 {
		t.Fatalf("resolver got id=%q port=%d", resolver.lastID, resolver.lastPrt)
	}
	if gotPath != "/api/echo" {
		t.Fatalf("upstream path = %q, want /api/echo", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("upstream method = %q", gotMethod)
	}
	if gotBody != "payload" {
		t.Fatalf("upstream body = %q", gotBody)
	}
}

func TestHTTPWakeNoTrailingPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("upstream path = %q, want /", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newHandler(&fakeResolver{target: upstream.URL}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/8080", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHTTPWakeRejectsInvalidPort(t *testing.T) {
	h := newHandler(&fakeResolver{target: "http://unused"}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/not-a-number/path", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHTTPWakeRejectsOversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("upstream should not be reached for oversize body")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newHandler(&fakeResolver{target: upstream.URL}, 8)
	req := httptest.NewRequest(http.MethodPost,
		"/__ingress/http/abc/3000/api",
		strings.NewReader(strings.Repeat("x", 100)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPWakeManualStopReturns409(t *testing.T) {
	h := newHandler(&fakeResolver{err: service.ErrSandboxManuallyStopped}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPWakeCircuitOpenReturns503WithRetryAfter(t *testing.T) {
	h := newHandler(&fakeResolver{err: service.ErrWakeCircuitOpen}, 1024)
	req := httptest.NewRequest(http.MethodGet, "/__ingress/http/abc/3000/api", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", rec.Header().Get("Retry-After"))
	}
}
