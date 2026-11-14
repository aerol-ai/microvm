package runloop

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/observability"
)

// A3: a Runloop toolbox call carries the API request's W3C trace context
// into toolboxd (RoundTripToolbox sets it on the request it builds).
func TestRunloopToolboxCallsCarryTraceContext(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var mu sync.Mutex
	var seen []string
	env.toolbox.mu.Lock()
	env.toolbox.beforeServe = func(r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("traceparent"))
		mu.Unlock()
	}
	env.toolbox.mu.Unlock()
	// The API edge's extraction, which the server's middleware runs first.
	inner := env.handler
	env.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r.WithContext(observability.ExtractTraceContext(r.Context(), r.Header)))
	})
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute_sync", `{"command":"echo sync"}`, nil,
		"traceparent", "00-"+traceID+"-00f067aa0ba902b7-01"), http.StatusOK)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no toolbox request was made")
	}
	for _, tp := range seen {
		if !strings.Contains(tp, traceID) {
			t.Fatalf("toolbox requests carried traceparent %q, want trace %s", seen, traceID)
		}
	}
}
