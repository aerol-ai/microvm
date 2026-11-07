package e2b

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// A3: E2B's runtime proxy (its own reverse proxy, not the service's) sets
// the W3C trace context of the API span on the envd request, replacing
// whatever the caller sent.
func TestRuntimeProxyCarriesTraceContext(t *testing.T) {
	forwarded := make(chan http.Header, 1)
	toolbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- r.Header.Clone()
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))
	defer toolbox.Close()
	u, _ := neturl.Parse(toolbox.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	runtime := newFakeE2BRuntime()
	runtime.containerIP = host
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: port})

	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","secure":true}`)))
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	// The span the API edge would have started: what toolboxd must see.
	traceID, _ := oteltrace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := oteltrace.SpanIDFromHex("00f067aa0ba902b7")
	sc := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{TraceID: traceID, SpanID: spanID, TraceFlags: oteltrace.FlagsSampled})
	req := httptest.NewRequest(http.MethodGet, "/e2b/runtime/health", nil)
	req.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	req.Header.Set("X-Access-Token", created.EnvdAccessToken)
	req.Header.Set("traceparent", "00-ffffffffffffffffffffffffffffffff-ffffffffffffffff-01")
	req = req.WithContext(oteltrace.ContextWithRemoteSpanContext(req.Context(), sc))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("runtime status = %d %s", resp.Code, resp.Body.String())
	}
	select {
	case h := <-forwarded:
		if got := h.Get("traceparent"); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
			t.Fatalf("envd got traceparent %q, want the API span's", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no request reached envd")
	}
}
