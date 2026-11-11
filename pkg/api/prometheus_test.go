package api

import (
	"context"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/usagemetrics"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func ensureExpvarInt(name string) *expvar.Int {
	if v := expvar.Get(name); v != nil {
		return v.(*expvar.Int)
	}
	return expvar.NewInt(name)
}

func ensureExpvarFloat(name string) *expvar.Float {
	if v := expvar.Get(name); v != nil {
		return v.(*expvar.Float)
	}
	return expvar.NewFloat(name)
}

func ensureExpvarMap(name string) *expvar.Map {
	if v := expvar.Get(name); v != nil {
		return v.(*expvar.Map)
	}
	return expvar.NewMap(name)
}

func TestServePrometheusMetrics(t *testing.T) {
	ensureExpvarInt("aerolvm_test_counter_total").Add(1)
	ensureExpvarFloat("aerolvm_test_gauge").Add(2.5)

	m := ensureExpvarMap("aerolvm_test_map")
	m.Add("foo", 10)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)

	var s Server
	s.servePrometheusMetrics(rw, req)

	if rw.Code != 200 {
		t.Fatalf("expected 200, got %d", rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "aerolvm_test_counter_total") {
		t.Errorf("missing test_counter in output")
	}
	if !strings.Contains(body, "aerolvm_test_gauge") {
		t.Errorf("missing test_gauge in output")
	}
	if !strings.Contains(body, "aerolvm_test_map") {
		t.Errorf("missing test_map in output")
	}
	// Registered by internal/observability, which this package imports: the
	// soak run (UC-482) reads it from /v1/metrics on every node.
	if !strings.Contains(body, "\naerolvm_go_goroutines ") {
		t.Errorf("missing aerolvm_go_goroutines in output")
	}
}

type badString struct{}

func (b badString) String() string { return "NaN" }

func TestPrometheusValueEdgeCases(t *testing.T) {
	if !isFinite(0.0) {
		t.Fatal("0.0 should be finite")
	}
	if isFinite(math.NaN()) {
		t.Fatal("NaN should not be finite")
	}
	if isFinite(math.Inf(1)) {
		t.Fatal("Inf should not be finite")
	}

	f := new(expvar.Float)
	f.Set(math.NaN())
	if _, ok := prometheusValue(f); ok {
		t.Fatal("expected false for NaN Float")
	}

	if _, ok := prometheusValue(badString{}); ok {
		t.Fatal("expected false for NaN string")
	}

	if prometheusMetricType("aerolvm_test_total") != "counter" {
		t.Fatal("expected counter")
	}
	if prometheusMetricType("aerolvm_test") != "gauge" {
		t.Fatal("expected gauge")
	}

	if prometheusMetricName("1invalid-name") != "_invalid_name" {
		t.Fatalf("expected _invalid_name, got %s", prometheusMetricName("1invalid-name"))
	}

	l := []prometheusLabel{{name: "foo", value: "bar\n\"\\"}}
	if !strings.Contains(prometheusLabelsString(l), "\\n\\\"\\\\") {
		t.Fatal("expected escaped labels")
	}
}

type badResponseWriter struct {
	http.ResponseWriter
}

func (b badResponseWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("bad write")
}

func TestServePrometheusMetrics_Error(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rw := badResponseWriter{ResponseWriter: httptest.NewRecorder()}
	// ensure we have at least one aerolvm_ expvar to trigger a write
	ensureExpvarInt("aerolvm_error_trigger").Add(1)
	s.servePrometheusMetrics(rw, nil)
}

// With the usage exporter on, /v1/metrics carries each owner's counters
// under real owner and incarnation labels (C20); with it off, none of them.
func TestServePrometheusUsageMetrics(t *testing.T) {
	owner := controlplane.TeamOwnerRef("payments")
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{name: "on", enabled: true},
		{name: "off", enabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := storeWith(t, "usage", ownedSandbox("sb-usage", "payments"))
			svc := service.New(config.Config{UsageMetricsEnabled: tc.enabled}, discardLogger(), st, nil, nil, nil, nil, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc.StartUsageMetrics(ctx)
			srv := &Server{logger: discardLogger(), service: svc}
			want := []string{
				"# TYPE aerolvm_usage_reserved_cpu_seconds_total counter\n",
				`aerolvm_usage_reserved_cpu_seconds_total{owner="` + owner + `",incarnation="`,
				`aerolvm_usage_reserved_memory_mib_seconds_total{owner="` + owner + `",incarnation="`,
				"# TYPE aerolvm_usage_last_sample_timestamp_seconds gauge\n",
				`aerolvm_usage_consumed_read_failures_total{incarnation="`,
			}
			// The exporter's first sample runs on its own goroutine.
			deadline := time.Now().Add(5 * time.Second)
			for {
				rw := httptest.NewRecorder()
				srv.servePrometheusMetrics(rw, httptest.NewRequest("GET", "/v1/metrics", nil))
				body := rw.Body.String()
				if !tc.enabled {
					if strings.Contains(body, "aerolvm_usage_") {
						t.Fatalf("usage series with the exporter off:\n%s", body)
					}
					return
				}
				missing := ""
				for _, w := range want {
					if !strings.Contains(body, w) {
						missing = w
					}
				}
				if missing == "" {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("/v1/metrics lacks %q:\n%s", missing, body)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// failAfter is a writer that takes ok writes, then fails every one after.
type failAfter struct{ ok int }

func (f *failAfter) Write(p []byte) (int, error) {
	if f.ok == 0 {
		return 0, errors.New("bad write")
	}
	f.ok--
	return len(p), nil
}

func TestWriteUsageMetricsWriteErrors(t *testing.T) {
	m := usagemetrics.NewMeter("inc", time.Unix(0, 0))
	m.Observe(time.Unix(30, 0), []usagemetrics.Sandbox{{ID: "a", Owner: "acme", CPU: 1, Running: true}}, 0)
	for _, tc := range []struct {
		name string
		ok   int
	}{
		{name: "the family header fails", ok: 0},
		{name: "a series line fails", ok: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := writeUsageMetrics(&failAfter{ok: tc.ok}, m); err == nil {
				t.Fatal("writeUsageMetrics() error = nil, want the write error")
			}
		})
	}
	if err := writeUsageMetrics(&failAfter{}, nil); err != nil {
		t.Fatalf("writeUsageMetrics(nil meter) error = %v, want nil: nothing to write", err)
	}
}

// A family with no series (no owner has run a sandbox here yet) prints no
// HELP or TYPE line either.
func TestWriteUsageMetricsSkipsEmptyFamilies(t *testing.T) {
	var b strings.Builder
	if err := writeUsageMetrics(&b, usagemetrics.NewMeter("inc", time.Unix(0, 0))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "aerolvm_usage_reserved") {
		t.Fatalf("an empty owner family was printed:\n%s", b.String())
	}
	if !strings.Contains(b.String(), `aerolvm_usage_consumed_read_failures_total{incarnation="inc"} 0`) {
		t.Fatalf("the process series is missing:\n%s", b.String())
	}
}
