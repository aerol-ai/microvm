package clusterroute

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// TestWrapRefusesAFencedSandbox: a worker that could not confirm it still owns
// a failover.policy=recreate sandbox has paused it, and the leader may be
// starting a copy elsewhere. Every route through the shared owner wrapper
// answers 503 + Retry-After for it, whether the (possibly stale) lookup names
// this node or knows nothing, instead of serving the paused copy. Other
// sandboxes on the node are served as before.
func TestWrapRefusesAFencedSandbox(t *testing.T) {
	for _, tc := range []struct {
		name string
		stub *stubCluster
	}{
		{name: "lookup says this node", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{IsSelf: true}}},
		{name: "lookup knows nothing", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := svcWithStore(t, tc.stub, "sb-ha", "sb-plain")
			svc.FenceOwnershipForTest("sb-ha")

			lh, ran := local()
			rr := httptest.NewRecorder()
			Wrap(svc, Options{WriteError: writeErr}, lh).ServeHTTP(rr, req("sb-ha"))
			if *ran {
				t.Fatal("the local handler served a fenced sandbox")
			}
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (body %q)", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("Retry-After"); got != strconv.Itoa(cluster.LeaderChangeRetryAfterSeconds) {
				t.Fatalf("Retry-After = %q, want %d", got, cluster.LeaderChangeRetryAfterSeconds)
			}
			if !strings.Contains(rr.Body.String(), "paused") {
				t.Fatalf("body = %q, want it to say the sandbox is paused", rr.Body.String())
			}

			lh, ran = local()
			rr = httptest.NewRecorder()
			Wrap(svc, Options{WriteError: writeErr}, lh).ServeHTTP(rr, req("sb-plain"))
			if !*ran {
				t.Fatalf("an unfenced sandbox was not served locally: status %d", rr.Code)
			}
		})
	}
}
