package api

import (
	"context"
	"io"
	"log/slog"
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
