package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The bank-flagship overload, in miniature: owners answer slowly, and lists
// keep arriving. Before, every list queued behind the slow fan-out (p99 37 s
// at 1024 clients) until the node fell over. Now a node runs at most its
// gate's lists; the rest are refused at once with 503 + Retry-After, while
// the admitted ones finish normally.
func TestClusterListWrap_ShedsAStormInsteadOfQueueingIt(t *testing.T) {
	arrived := make(chan struct{}, 16)
	release := make(chan struct{})
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{{ID: "sb-remote", Image: "alpine"}})
	}))
	t.Cleanup(peer.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	stub := &membersStubCluster{
		Noop:           cluster.NewNoop("node-a", "http://node-a", ""),
		internalClient: peer.Client(),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: peer.URL, InternalURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, stub)
	const slots, storm = 2, 10
	h.deps.ListGate = apihttp.NewGate(slots, 0, 0, apihttp.GateMetrics{})

	type result struct {
		code       int
		retryAfter string
	}
	results := make(chan result, storm)
	for range storm {
		go func() {
			rr := httptest.NewRecorder()
			h.clusterListWrap(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil))
			results <- result{code: rr.Code, retryAfter: rr.Header().Get("Retry-After")}
		}()
	}
	for range slots {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("the admitted lists never reached the owner")
		}
	}
	// With the owner still stuck, every other list must already be answered.
	for i := range storm - slots {
		select {
		case got := <-results:
			if got.code != http.StatusServiceUnavailable || got.retryAfter != strconv.Itoa(apihttp.OverloadedRetryAfterSeconds) {
				t.Fatalf("shed list %d = %d (Retry-After %q), want 503 + Retry-After", i, got.code, got.retryAfter)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("list %d queued behind the slow owner instead of being shed", i)
		}
	}
	close(release)
	for range slots {
		if got := <-results; got.code != http.StatusOK {
			t.Fatalf("an admitted list = %d, want 200", got.code)
		}
	}
	select {
	case <-arrived:
		t.Fatal("a shed list still reached the owner")
	default:
	}
}

// The same storm from one tenant beside a quiet one, with each tenant
// limited to half the node's slots. Before, the noisy tenant's lists took
// every slot and the quiet tenant's were shed with it. Now the noisy tenant
// holds its share and the rest of its lists are told 429 (its own share is
// the cause), while the quiet tenant's lists reach the owner at once.
func TestClusterListWrap_ANoisyTenantCannotCrowdOutAQuietOne(t *testing.T) {
	arrived := make(chan struct{}, 16)
	release := make(chan struct{})
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{})
	}))
	t.Cleanup(peer.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	stub := &membersStubCluster{
		Noop:           cluster.NewNoop("node-a", "http://node-a", ""),
		internalClient: peer.Client(),
		members: []cluster.Member{
			{NodeID: "node-b", APIURL: peer.URL, InternalURL: peer.URL, Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, stub)
	const slots, share, storm, quiet = 4, 2, 10, 2
	h.deps.ListGate = apihttp.NewGate(slots, share, 200*time.Millisecond, apihttp.GateMetrics{})
	asTeam := func(team string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
		return r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.TokenAccess("tok_"+team, team, controlplane.RoleRunner, team, time.Time{})))
	}
	type result struct {
		code       int
		retryAfter string
		body       string
	}
	list := func(team string, out chan<- result) {
		rr := httptest.NewRecorder()
		h.clusterListWrap(rr, asTeam(team))
		out <- result{code: rr.Code, retryAfter: rr.Header().Get("Retry-After"), body: rr.Body.String()}
	}
	noisy := make(chan result, storm)
	for range storm {
		go list("noisy", noisy)
	}
	for range share {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("the noisy tenant's admitted lists never reached the owner")
		}
	}
	// The noisy tenant holds its share; the quiet tenant still gets in.
	quietOut := make(chan result, quiet)
	for range quiet {
		go list("quiet", quietOut)
	}
	for i := range quiet {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatalf("quiet list %d never reached the owner while the noisy tenant stormed", i)
		}
	}
	// With the owner still stuck, every noisy list past the share is told
	// 429 once the queue wait runs out.
	for i := range storm - share {
		select {
		case got := <-noisy:
			if got.code != http.StatusTooManyRequests || got.retryAfter != strconv.Itoa(apihttp.RateLimitedRetryAfterSeconds) || !strings.Contains(got.body, models.ErrorCodeRateLimited) {
				t.Fatalf("noisy list %d = %d (Retry-After %q) %s, want 429 rate_limited + Retry-After", i, got.code, got.retryAfter, got.body)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("noisy list %d queued behind the slow owner instead of being refused", i)
		}
	}
	close(release)
	for range share {
		if got := <-noisy; got.code != http.StatusOK {
			t.Fatalf("an admitted noisy list = %d, want 200", got.code)
		}
	}
	for range quiet {
		if got := <-quietOut; got.code != http.StatusOK {
			t.Fatalf("a quiet list = %d, want 200: %s", got.code, got.body)
		}
	}
}
