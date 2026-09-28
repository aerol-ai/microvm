package api

import (
	"errors"
	"expvar"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
