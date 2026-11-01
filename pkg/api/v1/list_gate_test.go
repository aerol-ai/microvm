package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
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
	h.deps.ListGate = apihttp.NewGate(slots, 0, apihttp.GateMetrics{})

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
