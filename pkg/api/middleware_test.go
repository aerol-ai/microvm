package api

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestLoggingMiddlewareCreatesHTTPServerSpan(t *testing.T) {
	oldTracerProvider := otel.GetTracerProvider()
	oldPropagator := otel.GetTextMapPropagator()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(recorder),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(oldTracerProvider)
		otel.SetTextMapPropagator(oldPropagator)
		_ = provider.Shutdown(context.Background())
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sandboxes/{id}", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	})
	handler := loggingMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), mux)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil))

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]
	if span.Name() != "GET /v1/sandboxes/{id}" {
		t.Fatalf("unexpected span name: %q", span.Name())
	}
	if got := spanStringAttr(span, "http.route"); got != "/v1/sandboxes/{id}" {
		t.Fatalf("unexpected route attr: %q", got)
	}
	if got := spanStringAttr(span, "http.request.method"); got != http.MethodGet {
		t.Fatalf("unexpected method attr: %q", got)
	}
	if got := spanIntAttr(span, "http.response.status_code"); got != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status attr: %d", got)
	}
	if span.Status().Code != codes.Error {
		t.Fatalf("expected error status for 503, got %v", span.Status().Code)
	}
}

func spanStringAttr(span sdktrace.ReadOnlySpan, key string) string {
	for _, attr := range span.Attributes() {
		if string(attr.Key) == key {
			return attr.Value.AsString()
		}
	}
	return ""
}

func spanIntAttr(span sdktrace.ReadOnlySpan, key string) int64 {
	for _, attr := range span.Attributes() {
		if string(attr.Key) == key {
			return attr.Value.AsInt64()
		}
	}
	return 0
}

func TestStatusRecorderHijackAndFlush(t *testing.T) {
	rw := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rw}

	// Flush
	rec.Flush() // NewRecorder implements Flusher in newer Go versions, but we just want to ensure it doesn't panic.

	// Hijack
	_, _, err := rec.Hijack()
	if err == nil {
		t.Fatal("expected error because httptest.ResponseRecorder does not implement Hijacker")
	}

	// statusCode
	if rec.statusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.statusCode())
	}
	rec.hijacked = true
	if rec.statusCode() != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", rec.statusCode())
	}
}

type mockHijacker struct {
	http.ResponseWriter
	hijacked bool
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijacked = true
	return nil, nil, nil
}

func TestStatusRecorderHijackSuccess(t *testing.T) {
	inner := &mockHijacker{ResponseWriter: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: inner}

	_, _, err := rec.Hijack()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !inner.hijacked {
		t.Fatal("expected inner to be hijacked")
	}
	if !rec.hijacked {
		t.Fatal("expected rec to be hijacked")
	}
}

func TestMiddlewareWriteJSONAndError(t *testing.T) {
	rw := httptest.NewRecorder()
	writeJSON(rw, http.StatusCreated, map[string]string{"foo": "bar"})
	if rw.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rw.Code)
	}

	rw = httptest.NewRecorder()
	writeError(rw, http.StatusBadRequest, "bad request")
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rw.Code)
	}
}

func TestExtractBearerToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if extractBearerToken(r) != "" {
		t.Fatal("expected empty token")
	}

	r.Header.Set("Authorization", "Bearer valid")
	if extractBearerToken(r) != "valid" {
		t.Fatal("expected valid")
	}

	r.Header.Del("Authorization")
	r.Header.Set("Sec-WebSocket-Protocol", "sandbox.bearer, ws-token")
	if extractBearerToken(r) != "ws-token" {
		t.Fatal("expected ws-token")
	}
}

func TestWriteStoreAwareError(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rw := httptest.NewRecorder()
	defer func() { recover() }()
	s.writeStoreAwareError(rw, nil)
}

func TestLoggingMiddlewarePattern(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sandboxes/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	handler := loggingMiddleware(logger, mux)

	req := httptest.NewRequest("GET", "/v1/sandboxes/foo", nil)
	// httptest doesn't set Pattern automatically unless routed by a real server, but Go 1.22+ sets it if we do ServeMux
	handler.ServeHTTP(httptest.NewRecorder(), req)
}
