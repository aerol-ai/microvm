package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTraceparent(t *testing.T) {
	const tid, pid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"00-" + tid + "-" + pid + "-01", true},
		{" 00-" + tid + "-" + pid + "-00 ", true},
		{"01-" + tid + "-" + pid + "-01", false},
		{"00-" + strings.ToUpper(tid) + "-" + pid + "-01", false},
		{"00-" + strings.Repeat("0", 32) + "-" + pid + "-01", false},
		{"00-" + tid + "-" + strings.Repeat("0", 16) + "-01", false},
		{"00-" + tid[:31] + "-" + pid + "-01", false},
		{"00-" + tid + "-" + pid + "-1", false},
		{"00-" + tid + "-" + pid + "-zz", false},
		{"00-" + tid + "-" + pid, false},
		{"", false},
	} {
		gotT, gotP, ok := parseTraceparent(tc.in)
		if ok != tc.ok || (ok && (gotT != tid || gotP != pid)) {
			t.Fatalf("parseTraceparent(%q) = %q %q %v, want ok=%v", tc.in, gotT, gotP, ok, tc.ok)
		}
	}
}

// A3: a request with trace context logs one line naming its trace id and
// path, never its query; one without logs nothing; the handler runs either
// way, with the writer unwrapped.
func TestWithTraceLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var sawWriter http.ResponseWriter
	rr := httptest.NewRecorder()
	h := withTraceLog(logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sawWriter = w
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/process/execute?secret=hunter2", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(rr, req)
	line := buf.String()
	for _, want := range []string{"toolbox request", "trace_id=4bf92f3577b34da6a3ce929d0e0e4736", "parent_span_id=00f067aa0ba902b7", "path=/process/execute", "method=POST"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, "hunter2") {
		t.Fatalf("the log holds the query: %q", line)
	}
	if rr.Code != http.StatusNoContent || sawWriter != http.ResponseWriter(rr) {
		t.Fatal("the handler did not run with the original writer")
	}

	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	bad := httptest.NewRequest(http.MethodGet, "/health", nil)
	bad.Header.Set("traceparent", "garbage")
	h.ServeHTTP(httptest.NewRecorder(), bad)
	if buf.Len() != 0 {
		t.Fatalf("a request without valid trace context logged: %q", buf.String())
	}
	// A nil logger never panics.
	withTraceLog(nil, http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), req)
}
