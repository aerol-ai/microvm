package observability

import (
	"context"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOTELDisabledAndHelpers(t *testing.T) {
	metricsShutdown, err := StartOTELMetrics(context.Background(), nil, OTELMetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("StartOTELMetrics disabled error = %v", err)
	}
	if metricsShutdown != nil {
		t.Fatalf("expected nil metrics shutdown when disabled")
	}

	tracesShutdown, err := StartOTELTraces(context.Background(), nil, OTELTracesConfig{Enabled: false})
	if err != nil {
		t.Fatalf("StartOTELTraces disabled error = %v", err)
	}
	if tracesShutdown != nil {
		t.Fatalf("expected nil traces shutdown when disabled")
	}

	res := otelResource("", "node-1", "leader")
	if res == nil {
		t.Fatalf("expected non-nil resource")
	}

	attrs := expvarAttributes(ExpvarSample{
		Name: "metric.name",
		Labels: []ExpvarLabel{
			{Name: "sandbox", Value: "sb1"},
			{Name: "", Value: "ignored"},
		},
	})
	if len(attrs) != 2 {
		t.Fatalf("attrs len = %d, want 2", len(attrs))
	}
	if string(attrs[0].Key) != "metric" || attrs[0].Value.AsString() != "metric.name" {
		t.Fatalf("unexpected first attr: %+v", attrs[0])
	}
}

func TestStartOTELEnabledPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	expvarName := "aerolvm_otel_test_metric"
	expvar.NewInt(expvarName).Set(3)

	metricsShutdown, err := StartOTELMetrics(context.Background(), logger, OTELMetricsConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		Interval:    10 * time.Millisecond,
		ServiceName: "sdk-tests",
		NodeID:      "node-a",
		NodeRole:    "worker",
	})
	if err != nil {
		t.Fatalf("StartOTELMetrics enabled error = %v", err)
	}
	if metricsShutdown == nil {
		t.Fatal("expected non-nil metrics shutdown")
	}
	time.Sleep(30 * time.Millisecond)
	if err := metricsShutdown(context.Background()); err != nil {
		t.Fatalf("metrics shutdown error = %v", err)
	}

	tracesShutdown, err := StartOTELTraces(context.Background(), logger, OTELTracesConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		SampleRatio: -1,
		ServiceName: "sdk-tests",
		NodeID:      "node-a",
		NodeRole:    "worker",
	})
	if err != nil {
		t.Fatalf("StartOTELTraces enabled error = %v", err)
	}
	if tracesShutdown == nil {
		t.Fatal("expected non-nil traces shutdown")
	}
	if err := tracesShutdown(context.Background()); err != nil {
		t.Fatalf("traces shutdown error = %v", err)
	}
}

func TestStartOTELExporterErrors(t *testing.T) {
	shutdown, err := StartOTELMetrics(context.Background(), nil, OTELMetricsConfig{
		Enabled:  true,
		Endpoint: "://bad-endpoint",
	})
	if err != nil {
		t.Fatalf("unexpected StartOTELMetrics error = %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected StartOTELMetrics shutdown on permissive endpoint parse")
	}

	tracesShutdown, err := StartOTELTraces(context.Background(), nil, OTELTracesConfig{
		Enabled:  true,
		Endpoint: "://bad-endpoint",
	})
	if err != nil {
		t.Fatalf("unexpected StartOTELTraces error = %v", err)
	}
	if tracesShutdown == nil {
		t.Fatal("expected StartOTELTraces shutdown on permissive endpoint parse")
	}
}
