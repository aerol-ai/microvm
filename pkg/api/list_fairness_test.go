package api

import (
	"context"
	"encoding/json"
	"expvar"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fairListServer is a cluster-mode server with real team tokens and a list
// gate of 2 slots, 1 per tenant, no queue wait.
func fairListServer(t *testing.T, set *switchableTokens) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "fair.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Config{EnableCluster: true, IdentityEnabled: true, APIListMaxInflight: 2, APIListMaxInflightPerTenant: 1}
	svc := service.New(cfg, discardLogger(), st, nil, nil, caddy.New(config.Config{HTTPClientTimeout: time.Second}), nil, nil, nil)
	svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	return NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, identity.NewTokenAuthenticator(set, discardLogger())))
}

// fairList is one cluster-wide list on one surface, presenting bearer the
// way that surface's SDK does.
type fairList struct {
	surface, path string
	e2bKey        bool
}

var fairLists = []fairList{
	{surface: "v1", path: "/v1/sandboxes"},
	{surface: "daytona", path: "/daytona/sandbox"},
	{surface: "daytona", path: "/daytona/sandbox/paginated"},
	{surface: "e2b", path: "/e2b/sandboxes", e2bKey: true},
	{surface: "e2b", path: "/e2b/v2/sandboxes", e2bKey: true},
	{surface: "runloop", path: "/runloop/v1/devboxes"},
}

func (l fairList) serve(t *testing.T, s *Server, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	header := map[string]string{}
	if l.e2bKey {
		header["X-API-KEY"] = bearer
	}
	return serve(s.Handler(), http.MethodGet, l.path, bearer, header)
}

// checkRefusal asserts status, Retry-After and the surface's own error
// envelope: v1 and Daytona carry the stable code, E2B its {code, message},
// Runloop its {message} without x-should-retry: false (both are retryable).
func (l fairList) checkRefusal(t *testing.T, rec *httptest.ResponseRecorder, status, retryAfter int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("GET %s = %d, want %d: %s", l.path, rec.Code, status, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(retryAfter) {
		t.Fatalf("GET %s: Retry-After = %q, want %d", l.path, got, retryAfter)
	}
	switch l.surface {
	case "v1", "daytona":
		var body models.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != code || body.Error == "" {
			t.Fatalf("GET %s: body %s, want code %q", l.path, rec.Body.String(), code)
		}
	case "e2b":
		var body struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != status || body.Message == "" {
			t.Fatalf("GET %s: body %s, want the E2B envelope with code %d", l.path, rec.Body.String(), status)
		}
	case "runloop":
		var body struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Message == "" {
			t.Fatalf("GET %s: body %s, want the Runloop envelope", l.path, rec.Body.String())
		}
		if rec.Header().Get("x-should-retry") == "false" {
			t.Fatalf("GET %s: a refusal told the Runloop SDK not to retry", l.path)
		}
	}
}

// One node, two slots, one per tenant. A tenant whose list already holds
// its slot is told 429 rate_limited on every surface, in that surface's
// envelope; a tenant within its share on a full node is told 503
// overloaded; and a second token of the same team is the same tenant.
func TestListGateTellsATenantOverItsShare429AndOthers503(t *testing.T) {
	set := &switchableTokens{}
	payments := mintToken(t, set, "ci", "payments", controlplane.RoleRunner, time.Now().Add(time.Hour))
	payments2 := mintToken(t, set, "ci-2", "payments", controlplane.RoleRunner, time.Now().Add(time.Hour))
	ops := mintToken(t, set, "ops", "ops", controlplane.RoleRunner, time.Now().Add(time.Hour))
	s := fairListServer(t, set)
	if s.listGate.Limit() != 2 || s.listGate.PerFlowLimit() != 1 {
		t.Fatalf("gate %d slots, %d per tenant; want 2 and 1", s.listGate.Limit(), s.listGate.PerFlowLimit())
	}
	if listGateLimitMetric.Value() != 2 || listGatePerTenantMetric.Value() != 1 {
		t.Fatalf("size metrics %d/%d, want 2/1", listGateLimitMetric.Value(), listGatePerTenantMetric.Value())
	}
	// Free gate: every surface lists for a team token.
	for _, l := range fairLists {
		if rec := l.serve(t, s, payments); rec.Code != http.StatusOK {
			t.Fatalf("GET %s as a team token with a free gate = %d: %s", l.path, rec.Code, rec.Body.String())
		}
	}

	// Team payments holds its one slot: payments is over its share, on every
	// surface and with either of its tokens; ops and the operator are not.
	hold, err := s.listGate.AcquireFlow(context.Background(), "owner:team:payments")
	if err != nil {
		t.Fatal(err)
	}
	rateLimited := listGateMetrics.RateLimited.Value()
	for _, l := range fairLists {
		for _, bearer := range []string{payments, payments2} {
			l.checkRefusal(t, l.serve(t, s, bearer), http.StatusTooManyRequests, apihttp.RateLimitedRetryAfterSeconds, models.ErrorCodeRateLimited)
		}
		if rec := l.serve(t, s, ops); rec.Code != http.StatusOK {
			t.Fatalf("GET %s as another team beside a tenant at its share = %d: %s", l.path, rec.Code, rec.Body.String())
		}
	}
	if got := listGateMetrics.RateLimited.Value() - rateLimited; got != int64(2*len(fairLists)) {
		t.Fatalf("aerolvm_api_list_rate_limited_total rose by %d, want %d", got, 2*len(fairLists))
	}

	// Team risk takes the second slot: the node is full. ops and the
	// operator, within their shares, are told 503; payments still 429.
	hold2, err := s.listGate.AcquireFlow(context.Background(), "owner:team:risk")
	if err != nil {
		t.Fatal(err)
	}
	shed := listGateMetrics.Shed.Value()
	for _, l := range fairLists {
		l.checkRefusal(t, l.serve(t, s, ops), http.StatusServiceUnavailable, apihttp.OverloadedRetryAfterSeconds, models.ErrorCodeOverloaded)
		l.checkRefusal(t, l.serve(t, s, "pat-token"), http.StatusServiceUnavailable, apihttp.OverloadedRetryAfterSeconds, models.ErrorCodeOverloaded)
		l.checkRefusal(t, l.serve(t, s, payments), http.StatusTooManyRequests, apihttp.RateLimitedRetryAfterSeconds, models.ErrorCodeRateLimited)
	}
	if got := listGateMetrics.Shed.Value() - shed; got != int64(2*len(fairLists)) {
		t.Fatalf("aerolvm_api_list_shed_total rose by %d, want %d", got, 2*len(fairLists))
	}

	// /debug/vars names the tenants holding the gate; /v1/metrics never does.
	debug := serve(s.Handler(), http.MethodGet, "/debug/vars", "pat-token", nil)
	if debug.Code != http.StatusOK || !strings.Contains(debug.Body.String(), `"api_list_gate"`) || !strings.Contains(debug.Body.String(), "owner:team:payments") {
		t.Fatalf("/debug/vars = %d, want api_list_gate naming owner:team:payments", debug.Code)
	}
	metrics := serve(s.Handler(), http.MethodGet, "/v1/metrics", "pat-token", nil)
	if metrics.Code != http.StatusOK || strings.Contains(metrics.Body.String(), "team:") {
		t.Fatalf("/v1/metrics = %d and names a tenant: a tenant must never be a metric label", metrics.Code)
	}
	for _, name := range []string{"aerolvm_api_list_rate_limited_total", "aerolvm_api_list_tenants 2", "aerolvm_api_list_queued 0", "aerolvm_api_list_max_inflight_per_tenant 1"} {
		if !strings.Contains(metrics.Body.String(), name) {
			t.Fatalf("/v1/metrics lacks %q", name)
		}
	}

	hold()
	hold2()
	for _, l := range fairLists {
		if rec := l.serve(t, s, payments); rec.Code != http.StatusOK {
			t.Fatalf("GET %s after the slots freed = %d", l.path, rec.Code)
		}
	}
}

// A non-admin cannot read the debug view that names tenants.
func TestListGateDebugViewIsFleetAdminOnly(t *testing.T) {
	set := &switchableTokens{}
	viewer := mintToken(t, set, "ro", "payments", controlplane.RoleViewer, time.Now().Add(time.Hour))
	s := fairListServer(t, set)
	if rec := serve(s.Handler(), http.MethodGet, "/debug/vars", viewer, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("/debug/vars as a team viewer = %d, want 403", rec.Code)
	}
	// The published view follows the newest server's gate, and survives a
	// server with no gate at all.
	if v := expvar.Get("api_list_gate"); v == nil || !strings.Contains(v.String(), `"per_tenant_limit":1`) {
		t.Fatalf("api_list_gate = %v", v)
	}
	NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", nil)
	if v := expvar.Get("api_list_gate").String(); !strings.Contains(v, `"limit":0`) {
		t.Fatalf("api_list_gate with no gate = %s", v)
	}
}
