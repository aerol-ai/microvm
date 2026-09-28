package api

import (
	"context"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestHandleHealthStoreFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	_ = st.Close()

	server := NewServer(logger, svc, nil, nil, config.Config{}, "pat-token", nil)
	rec := httptest.NewRecorder()
	server.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestNewServerFallsBackToDockerBuilder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dc := &docker.Client{}
	server := NewServer(logger, nil, dc, nil, config.Config{}, "pat", nil)
	if server.builder != dc {
		t.Fatal("expected docker client to be used as builder fallback")
	}
}

func TestRequireE2BAuthAcceptsUserToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	validator := stubValidator{
		accept:   "user-token",
		identity: controlplane.Identity{OwnerRef: "tenant-1"},
	}
	server := NewServer(logger, nil, nil, nil, config.Config{}, "pat-token", validator)

	called := false
	handler := server.requireE2BAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		access, ok := controlplane.AccessFromContext(r.Context())
		if !ok || access.Operator || access.Identity.OwnerRef != "tenant-1" {
			t.Fatalf("unexpected access: %+v ok=%v", access, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil)
	req.Header.Set("X-API-KEY", "user-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if !called {
		t.Fatal("handler not reached")
	}
}

func TestLoggingMiddlewareHijackedAndUpgrade(t *testing.T) {
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

	inner := &mockHijacker{ResponseWriter: httptest.NewRecorder()}
	handler := loggingMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _, _ = w.(http.Hijacker).Hijack()
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	handler.ServeHTTP(&statusRecorder{ResponseWriter: inner}, req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]
	if got := spanIntAttr(span, "http.response.status_code"); got != http.StatusSwitchingProtocols {
		t.Fatalf("status attr = %d, want 101", got)
	}
	foundHijack := false
	for _, attr := range span.Attributes() {
		if string(attr.Key) == "aerolvm.http.hijacked" && attr.Value.AsBool() {
			foundHijack = true
		}
	}
	if !foundHijack {
		t.Fatal("expected hijacked span attribute")
	}
}

func TestPrometheusCollectNestedMapAndInt(t *testing.T) {
	root := ensureExpvarMap("aerolvm_nested_test")
	child := new(expvar.Map).Init()
	child.Add("inner", 3)
	root.Set("child", child)
	root.Add("scalar", 9)

	var buf strings.Builder
	if err := writePrometheusExpvars(&buf); err != nil {
		t.Fatalf("writePrometheusExpvars: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "aerolvm_nested_test") {
		t.Fatalf("missing nested metric:\n%s", body)
	}

	probe := ensureExpvarInt("aerolvm_int_probe")
	probe.Set(0)
	if val, ok := prometheusValue(probe); !ok || val != "0" {
		t.Fatalf("prometheusValue int: ok=%v val=%q", ok, val)
	}

	for _, suffix := range []string{"_bucket", "_count", "_sum"} {
		name := "aerolvm_hist" + suffix
		if prometheusMetricType(name) != "counter" {
			t.Fatalf("%s should be counter", name)
		}
	}

	if prometheusMetricName("9bad:name") != "_bad:name" {
		t.Fatalf("unexpected sanitized name: %s", prometheusMetricName("9bad:name"))
	}
	if prometheusLabelsString(nil) != "" {
		t.Fatal("expected empty label string")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWritePrometheusExpvarsWriteError(t *testing.T) {
	ensureExpvarInt("aerolvm_write_err_probe").Set(1)
	if err := writePrometheusExpvars(errWriter{}); err == nil {
		t.Fatal("expected write error")
	}
}
