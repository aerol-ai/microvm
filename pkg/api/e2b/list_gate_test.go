package e2b

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// listGateCluster is a real cluster client (not the single-node Noop type),
// so the list fans out and must take a slot.
type listGateCluster struct{ *cluster.Noop }

// With every one of the node's list slots taken, the facade's cluster-wide
// list is shed at once with 503 + Retry-After in its own envelope, before it
// reads the store or asks any owner.
func TestListIsShedWhenTheNodesListSlotsAreFull(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&listGateCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	gate := apihttp.NewGate(1, 0, 0, apihttp.GateMetrics{})
	hold, err := gate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	h := newHandlers(Deps{Service: svc, Logger: logger, ListGate: gate})
	for _, tc := range []struct {
		name string
		fn   http.HandlerFunc
	}{{"GET /e2b/sandboxes", h.listSandboxes}} {
		rr := httptest.NewRecorder()
		tc.fn(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s with every list slot taken = %d, want 503: %s", tc.name, rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Retry-After"); got != strconv.Itoa(apihttp.OverloadedRetryAfterSeconds) {
			t.Fatalf("%s: Retry-After = %q", tc.name, got)
		}
	}
}

// A tenant (here the operator) whose lists already hold its share of the
// node's slots is told 429 + Retry-After in this facade's own envelope,
// while the node still has room for other tenants.
func TestListIsRateLimitedWhenTheTenantHoldsItsShare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&listGateCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	gate := apihttp.NewGate(2, 1, 0, apihttp.GateMetrics{})
	hold, err := gate.AcquireFlow(context.Background(), apihttp.OperatorFlow)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	h := newHandlers(Deps{Service: svc, Logger: logger, ListGate: gate})
	for _, tc := range []struct {
		name string
		fn   http.HandlerFunc
	}{{"GET /e2b/sandboxes", h.listSandboxes}} {
		rr := httptest.NewRecorder()
		tc.fn(rr, httptest.NewRequest(http.MethodGet, "/", nil))
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("%s with the tenant's share taken = %d, want 429: %s", tc.name, rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Retry-After"); got != strconv.Itoa(apihttp.RateLimitedRetryAfterSeconds) {
			t.Fatalf("%s: Retry-After = %q", tc.name, got)
		}
		if !strings.Contains(rr.Body.String(), `"code":429`) {
			t.Fatalf("%s: body %s is not the E2B envelope with code 429", tc.name, rr.Body.String())
		}
	}
}
