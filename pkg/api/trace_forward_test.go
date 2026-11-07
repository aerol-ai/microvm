package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const (
	callerTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	callerSpanID  = "00f067aa0ba902b7"
	callerParent  = "00-" + callerTraceID + "-" + callerSpanID + "-01"
)

// traceServer is a single-node server whose sandbox's toolbox is a fake
// toolboxd that records the traceparent of every request it gets.
func traceServer(t *testing.T) (http.Handler, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+r.Header.Get("traceparent"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st := storeWith(t, "trace")
	svc := service.New(config.Config{ToolboxPort: port}, discardLogger(), st, nil, nil, nil, cipher, nil, nil)
	sb := ownedSandbox("sb-trace", "payments")
	sb.ContainerIP = host
	sb.ToolboxToken = "toolbox-secret"
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{}, "pat-token", nil)
	return srv.Handler(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// A3 with tracing on: the v1 pass-through and the Daytona facade both
// forward a traceparent in the caller's trace whose parent is sandboxd's
// own API span, never the caller's header copied through.
func TestToolboxCallsCarrySandboxdSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	oldTP, oldProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() {
		otel.SetTracerProvider(oldTP)
		otel.SetTextMapPropagator(oldProp)
		_ = provider.Shutdown(context.Background())
	})
	h, seen := traceServer(t)
	for _, path := range []string{
		"/v1/sandboxes/sb-trace/toolbox/files?path=/tmp",
		"/daytona/toolbox/sb-trace/files?path=/tmp",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer pat-token")
		req.Header.Set("traceparent", callerParent)
		req.Header.Set("baggage", "user=alice")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code >= 400 {
			t.Fatalf("%s = %d %s", path, rr.Code, rr.Body.String())
		}
	}
	got := seen()
	if len(got) < 2 {
		t.Fatalf("toolbox saw %v", got)
	}
	spanIDs := map[string]bool{}
	for _, s := range recorder.Ended() {
		spanIDs[s.SpanContext().SpanID().String()] = true
	}
	for _, line := range got {
		_, tp, _ := strings.Cut(line, " ")
		parts := strings.Split(tp, "-")
		if len(parts) != 4 || parts[1] != callerTraceID || parts[2] == callerSpanID || !spanIDs[parts[2]] {
			t.Fatalf("toolbox request %q: want the caller's trace with a sandboxd span as parent (spans %v)", line, spanIDs)
		}
	}
}

// A3 with tracing off (the default): the caller's own trace context still
// reaches toolboxd on both paths, and a malformed one does not.
func TestToolboxCallsCarryCallerTraceWithTracingOff(t *testing.T) {
	h, seen := traceServer(t)
	for _, tc := range []struct{ path, header, want string }{
		{"/v1/sandboxes/sb-trace/toolbox/files?path=/a", callerParent, callerParent},
		{"/daytona/toolbox/sb-trace/files?path=/a", callerParent, callerParent},
		{"/v1/sandboxes/sb-trace/toolbox/files?path=/b", "garbage", ""},
	} {
		before := len(seen())
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Authorization", "Bearer pat-token")
		req.Header.Set("traceparent", tc.header)
		h.ServeHTTP(httptest.NewRecorder(), req)
		got := seen()
		if len(got) <= before {
			t.Fatalf("%s: no toolbox request", tc.path)
		}
		for _, line := range got[before:] {
			if _, tp, _ := strings.Cut(line, " "); tp != tc.want {
				t.Fatalf("%s with %q: toolbox got %q, want %q", tc.path, tc.header, tp, tc.want)
			}
		}
	}
}
