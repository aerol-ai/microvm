package clusterroute

import (
	"errors"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

func expvarInt(t testing.TB, name string) int64 {
	t.Helper()
	v := expvar.Get(name)
	if v == nil {
		return 0
	}
	n, err := strconv.ParseInt(v.String(), 10, 64)
	if err != nil {
		t.Fatalf("expvar %s = %q: %v", name, v.String(), err)
	}
	return n
}

func routeLookups(t testing.TB) int64 {
	t.Helper()
	m, _ := expvar.Get("aerolvm_cluster_route_lookups_total").(*expvar.Map)
	if m == nil {
		return 0
	}
	var n int64
	m.Do(func(kv expvar.KeyValue) {
		v, _ := strconv.ParseInt(kv.Value.String(), 10, 64)
		n += v
	})
	return n
}

// The measurement plan E3a asks for: control-plane lookups per routed call,
// over an in-process edge and owner, with the cache off and on. An operator
// call costs OwnerOf on each hop; a tenant-scoped call adds PlacementOf on
// each hop. With the cache on only the first call pays the edge's lookups.
func TestOwnerCacheLookupsPerRoutedRequest(t *testing.T) {
	const calls = 20
	tests := []struct {
		name        string
		cache       bool
		tenant      string
		wantLookups int64
	}{
		{name: "cache off, operator", wantLookups: 2 * calls},
		{name: "cache off, tenant", tenant: "acct-a", wantLookups: 4 * calls},
		{name: "cache on, operator", cache: true, wantLookups: 2 + (calls - 1)},
		{name: "cache on, tenant", cache: true, tenant: "acct-a", wantLookups: 4 + 2*(calls-1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFleet(t, tc.cache, "ingress-1", "worker-a")
			f.placeOn("sb-1", "worker-a", "acct-a")
			reqs0, lookups0 := expvarInt(t, "aerolvm_cluster_route_requests_total"), routeLookups(t)
			before := f.snapshot()
			for i := 0; i < calls; i++ {
				if rr := f.call("ingress-1", http.MethodGet, "sb-1", "", tc.tenant); rr.Code != http.StatusOK || rr.Header().Get("X-Served-By") != "worker-a" {
					t.Fatalf("call %d: status %d served by %q", i, rr.Code, rr.Header().Get("X-Served-By"))
				}
			}
			d := f.snapshot().since(before)
			if d.lookups != tc.wantLookups {
				t.Fatalf("lookups = %d over %d calls, want %d", d.lookups, calls, tc.wantLookups)
			}
			// The expvar counters see the same numbers.
			if got := expvarInt(t, "aerolvm_cluster_route_requests_total") - reqs0; got != calls {
				t.Fatalf("route_requests delta = %d, want %d", got, calls)
			}
			if got := routeLookups(t) - lookups0; got != tc.wantLookups {
				t.Fatalf("route_lookups delta = %d, want %d", got, tc.wantLookups)
			}
			t.Logf("%s: %.2f control-plane lookups per routed call (%d over %d)", tc.name, float64(d.lookups)/calls, d.lookups, calls)
		})
	}
}

// BenchmarkRoutedRequestLookups reports lookups/call at steady state.
//
//	go test -run '^$' -bench RoutedRequestLookups ./pkg/api/clusterroute/
func BenchmarkRoutedRequestLookups(b *testing.B) {
	for _, cache := range []bool{false, true} {
		for _, tenant := range []string{"", "acct-a"} {
			name := fmt.Sprintf("cache=%v/tenant=%v", cache, tenant != "")
			b.Run(name, func(b *testing.B) {
				f := newFleet(b, cache, "ingress-1", "worker-a")
				f.placeOn("sb-1", "worker-a", "acct-a")
				f.call("ingress-1", http.MethodGet, "sb-1", "", tenant) // fill the cache
				start := f.lookups.Load()
				n := 0
				for b.Loop() {
					f.call("ingress-1", http.MethodGet, "sb-1", "", tenant)
					n++
				}
				b.ReportMetric(float64(f.lookups.Load()-start)/float64(n), "lookups/call")
			})
		}
	}
}

// After the sandbox moves, the old owner answers "not here" (421 + its
// token), the edge drops the entry and routes once more from a fresh lookup,
// and the call reaches the new owner with its body intact. Exactly one retry;
// the next call goes straight to the new owner.
func TestOwnerCacheMovedSandboxRetriesOnce(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a", "worker-b")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "") // fill the cache
	f.move("sb-1", "worker-b")                          // worker-a keeps its stale row

	hits0, retries0, notOwner0 := expvarInt(t, "aerolvm_cluster_owner_cache_hits_total"), expvarInt(t, "aerolvm_cluster_owner_cache_retries_total"), expvarInt(t, "aerolvm_cluster_owner_cache_not_owner_total")
	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodPost, "sb-1", `{"cmd":"echo hi"}`, "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Served-By") != "worker-b" || rr.Body.String() != `{"cmd":"echo hi"}` {
		t.Fatalf("got %d from %q body %q, want 200 from worker-b with the body", rr.Code, rr.Header().Get("X-Served-By"), rr.Body.String())
	}
	if d.served["worker-a"] != 0 {
		t.Fatal("the old owner served a call its own lookup says it does not own")
	}
	if d.notHere["worker-a"] != 1 || d.forwards["ingress-1"] != 2 || d.hinted["ingress-1"] != 1 {
		t.Fatalf("not-here=%d forwards=%d hinted=%d, want 1, 2 (one retry), 1", d.notHere["worker-a"], d.forwards["ingress-1"], d.hinted["ingress-1"])
	}
	if rr.Header().Get(cluster.HeaderNotOwner) != "" {
		t.Fatal("the caller saw the cluster-private not-owner header")
	}
	if got := expvarInt(t, "aerolvm_cluster_owner_cache_hits_total") - hits0; got != 1 {
		t.Fatalf("hits delta = %d, want 1", got)
	}
	if got := expvarInt(t, "aerolvm_cluster_owner_cache_retries_total") - retries0; got != 1 {
		t.Fatalf("retries delta = %d, want 1", got)
	}
	if got := expvarInt(t, "aerolvm_cluster_owner_cache_not_owner_total") - notOwner0; got != 1 {
		t.Fatalf("not_owner delta = %d, want 1", got)
	}

	before = f.snapshot()
	rr = f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d = f.snapshot().since(before)
	if rr.Header().Get("X-Served-By") != "worker-b" || d.forwards["ingress-1"] != 1 || d.notHere["worker-a"] != 0 || d.lookups != 1 {
		t.Fatalf("next call: served by %q, forwards=%d, not-here=%d, lookups=%d; want worker-b, 1, 0, 1 (owner's only)",
			rr.Header().Get("X-Served-By"), d.forwards["ingress-1"], d.notHere["worker-a"], d.lookups)
	}
}

// The retry is the plain lookup path, so it can never loop: when the second
// target's view disagrees too, the call stops with the usual loop 421 after
// exactly two sends, as it would with the cache off.
func TestOwnerCacheRetryCannotLoop(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a", "worker-b")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	f.move("sb-1", "worker-b")
	// worker-b lags: it still thinks worker-a owns it.
	f.nodes["worker-b"].view = map[string]fleetPlacement{"sb-1": {node: "worker-a"}}

	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusMisdirectedRequest || rr.Header().Get(cluster.HeaderNotOwner) != "" {
		t.Fatalf("status %d not-owner=%q, want the plain loop 421", rr.Code, rr.Header().Get(cluster.HeaderNotOwner))
	}
	if d.forwards["ingress-1"] != 2 || d.forwards["worker-b"] != 0 {
		t.Fatalf("edge forwards = %d, worker-b forwards = %d; want 2 and 0", d.forwards["ingress-1"], d.forwards["worker-b"])
	}
	if d.served["worker-a"]+d.served["worker-b"] != 0 {
		t.Fatal("a node served the call")
	}
}

// A cache entry never becomes an answer. Whatever happened to the sandbox,
// the caller gets what a fresh lookup at the edge gives (the cache-off
// answer), and the old owner, which still holds a stale row, serves nothing.
func TestOwnerCacheEntryNeverBecomesTheAnswer(t *testing.T) {
	tests := []struct {
		name       string
		change     func(f *fleet)
		wantStatus int
		wantBy     string
	}{
		{name: "deleted: 404 from the edge", change: func(f *fleet) { f.remove("sb-1") }, wantStatus: http.StatusNotFound},
		{name: "orphaned: 410 from the edge", change: func(f *fleet) { f.orphan("sb-1") }, wantStatus: http.StatusGone},
		{name: "moved to the edge itself: served there", change: func(f *fleet) { f.move("sb-1", "ingress-1") }, wantStatus: http.StatusOK, wantBy: "ingress-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFleet(t, true, "ingress-1", "worker-a")
			f.placeOn("sb-1", "worker-a", "")
			f.call("ingress-1", http.MethodGet, "sb-1", "", "")
			tc.change(f)

			before := f.snapshot()
			rr := f.call("ingress-1", http.MethodDelete, "sb-1", "", "")
			d := f.snapshot().since(before)
			if rr.Code != tc.wantStatus || rr.Header().Get("X-Served-By") != tc.wantBy {
				t.Fatalf("got %d from %q, want %d from %q", rr.Code, rr.Header().Get("X-Served-By"), tc.wantStatus, tc.wantBy)
			}
			if d.served["worker-a"] != 0 || d.notHere["worker-a"] != 1 {
				t.Fatalf("old owner served=%d not-here=%d, want 0 and 1", d.served["worker-a"], d.notHere["worker-a"])
			}
			// The entry is gone: the next call does not visit worker-a.
			before = f.snapshot()
			f.call("ingress-1", http.MethodGet, "sb-1", "", "")
			if d := f.snapshot().since(before); d.notHere["worker-a"] != 0 || d.hinted["ingress-1"] != 0 {
				t.Fatalf("stale entry used again: not-here=%d hinted=%d", d.notHere["worker-a"], d.hinted["ingress-1"])
			}
		})
	}
}

// Same answers with the cache off, and no route hint ever leaves a node: the
// flag off is the router as it was.
func TestOwnerCacheOffSendsNoHint(t *testing.T) {
	f := newFleet(t, false, "ingress-1", "worker-a", "worker-b")
	f.placeOn("sb-1", "worker-a", "")
	before := f.snapshot()
	if rr := f.call("ingress-1", http.MethodGet, "sb-1", "", ""); rr.Header().Get("X-Served-By") != "worker-a" {
		t.Fatalf("served by %q", rr.Header().Get("X-Served-By"))
	}
	f.move("sb-1", "worker-b")
	if rr := f.call("ingress-1", http.MethodGet, "sb-1", "", ""); rr.Header().Get("X-Served-By") != "worker-b" {
		t.Fatalf("after move served by %q", rr.Header().Get("X-Served-By"))
	}
	f.remove("sb-1")
	if rr := f.call("ingress-1", http.MethodGet, "sb-1", "", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("after delete status %d", rr.Code)
	}
	d := f.snapshot().since(before)
	if d.hinted["ingress-1"] != 0 || d.notHere["worker-a"]+d.notHere["worker-b"] != 0 || d.lookups != 5 {
		t.Fatalf("hinted=%d not-here=%d lookups=%d; want 0, 0, 5", d.hinted["ingress-1"], d.notHere["worker-a"]+d.notHere["worker-b"], d.lookups)
	}
}

// A tenant-scoped call uses an entry only when the entry knows the tenant
// and it is the caller's. Another tenant's call goes down the lookup path and
// gets the plain 404, without visiting the owner.
func TestOwnerCacheChecksTheTenant(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "acct-a")

	// An operator call fills the entry without a tenant: a tenant call must
	// not use it, and then refills it with the tenant.
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	before := f.snapshot()
	f.call("ingress-1", http.MethodGet, "sb-1", "", "acct-a")
	if d := f.snapshot().since(before); d.hinted["ingress-1"] != 0 || d.lookups != 4 {
		t.Fatalf("tenant call on a tenant-less entry: hinted=%d lookups=%d, want 0 and 4", d.hinted["ingress-1"], d.lookups)
	}
	// Now the entry knows the tenant: the caller's next call uses it.
	before = f.snapshot()
	f.call("ingress-1", http.MethodGet, "sb-1", "", "acct-a")
	if d := f.snapshot().since(before); d.hinted["ingress-1"] != 1 || d.lookups != 2 {
		t.Fatalf("tenant call on a tenant entry: hinted=%d lookups=%d, want 1 and 2", d.hinted["ingress-1"], d.lookups)
	}

	before = f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "acct-b")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusNotFound || d.forwards["ingress-1"] != 0 {
		t.Fatalf("foreign tenant: status %d forwards %d, want 404 and 0", rr.Code, d.forwards["ingress-1"])
	}
}

// Only a 421 that carries the edge's own token is "not here". The sandbox's
// own server (behind a toolbox route) can answer 421 and set the header to
// anything; the edge passes that answer on, sends nothing twice, and hides
// the cluster-private header from the caller.
func TestOwnerCacheTrustsOnlyItsOwnToken(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.nodes["worker-a"].localAnswer = func(w http.ResponseWriter, r *http.Request) {
		// The best a sandbox can do: it never sees the token (Wrap drops the
		// hint header before any handler runs).
		w.Header().Set(cluster.HeaderNotOwner, r.Header.Get(cluster.HeaderRouteHint)+"guess")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = io.WriteString(w, "from the sandbox")
	}
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodPost, "sb-1", `{"cmd":"rm -rf /tmp/x"}`, "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusMisdirectedRequest || rr.Body.String() != "from the sandbox" {
		t.Fatalf("got %d %q, want the sandbox's own 421", rr.Code, rr.Body.String())
	}
	if d.served["worker-a"] != 1 || d.forwards["ingress-1"] != 1 {
		t.Fatalf("served=%d forwards=%d; the call must run once and be sent once", d.served["worker-a"], d.forwards["ingress-1"])
	}
	if got := rr.Header().Get(cluster.HeaderNotOwner); got != "" {
		t.Fatalf("caller saw %s=%q", cluster.HeaderNotOwner, got)
	}
}

// A node gossip reports dead gets no cache-routed traffic: the call takes the
// lookup path (and the cache-off answer).
func TestOwnerCacheSkipsDeadNodes(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	f.markDead("worker-a")
	before := f.snapshot()
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	if d := f.snapshot().since(before); d.hinted["ingress-1"] != 0 || d.lookups != 2 {
		t.Fatalf("dead owner: hinted=%d lookups=%d, want 0 and 2", d.hinted["ingress-1"], d.lookups)
	}
}

// A 502, 503 or 504 through an entry is passed on (the call may have run, so
// no retry) and drops the entry, so the next call looks the sandbox up.
func TestOwnerCacheDropsEntryOnGatewayErrors(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFleet(t, true, "ingress-1", "worker-a")
			f.placeOn("sb-1", "worker-a", "")
			f.call("ingress-1", http.MethodGet, "sb-1", "", "")
			f.nodes["worker-a"].localAnswer = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }
			before := f.snapshot()
			if rr := f.call("ingress-1", http.MethodGet, "sb-1", "", ""); rr.Code != status {
				t.Fatalf("status %d, want %d", rr.Code, status)
			}
			if d := f.snapshot().since(before); d.forwards["ingress-1"] != 1 {
				t.Fatalf("forwards = %d, want 1 (no retry)", d.forwards["ingress-1"])
			}
			before = f.snapshot()
			f.call("ingress-1", http.MethodGet, "sb-1", "", "")
			if d := f.snapshot().since(before); d.hinted["ingress-1"] != 0 {
				t.Fatal("entry still used after a gateway error")
			}
		})
	}
}

// Bodies the edge cannot hold for a second send skip the cache and stream
// down the lookup path as before.
func TestOwnerCacheSkipsBodiesItCannotReplay(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")

	big := strings.Repeat("x", maxReplayBody+1)
	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodPut, "sb-1", big, "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusOK || rr.Body.Len() != len(big) || d.hinted["ingress-1"] != 0 {
		t.Fatalf("big body: status %d len %d hinted %d", rr.Code, rr.Body.Len(), d.hinted["ingress-1"])
	}

	// Unsized (chunked) body.
	r := httptest.NewRequest(http.MethodPut, "/x/sb-1", io.NopCloser(strings.NewReader("chunk")))
	r.ContentLength = -1
	before = f.snapshot()
	rr = httptest.NewRecorder()
	f.nodes["ingress-1"].h.ServeHTTP(rr, r)
	if d := f.snapshot().since(before); rr.Code != http.StatusOK || rr.Body.String() != "chunk" || d.hinted["ingress-1"] != 0 {
		t.Fatalf("chunked body: status %d body %q hinted %d", rr.Code, rr.Body.String(), d.hinted["ingress-1"])
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("client went away") }
func (failingBody) Close() error             { return nil }

// A body that cannot be read is answered 400 at the edge; nothing is sent.
func TestOwnerCacheBodyReadError(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	r := httptest.NewRequest(http.MethodPost, "/x/sb-1", nil)
	r.Body, r.ContentLength = failingBody{}, 10
	before := f.snapshot()
	rr := httptest.NewRecorder()
	f.nodes["ingress-1"].h.ServeHTTP(rr, r)
	if d := f.snapshot().since(before); rr.Code != http.StatusBadRequest || d.forwards["ingress-1"] != 0 {
		t.Fatalf("status %d forwards %d, want 400 and 0", rr.Code, d.forwards["ingress-1"])
	}
}

// Exactly one node writes the audit record of a call. The node that turns a
// cache-routed forward down writes none, and the edge takes its "a peer
// records it" mark back: here the retry ends at the edge (404), so the edge
// records it.
func TestOwnerCacheAuditRecordStaysWithTheAnsweringNode(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	f.remove("sb-1")

	r := httptest.NewRequest(http.MethodGet, "/x/sb-1", nil)
	ctx, edgeState := auditlog.ContextWithCallState(r.Context())
	rr := httptest.NewRecorder()
	f.nodes["ingress-1"].h.ServeHTTP(rr, r.WithContext(ctx))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rr.Code)
	}
	if edgeState.Forwarded() {
		t.Fatal("edge still marked forwarded after the not-here: no node would record the call")
	}
	if st := f.nodes["worker-a"].lastState; st == nil || !st.Forwarded() {
		t.Fatal("the node that answered not-here would record a call it did not run")
	}
}

// One node: no cache, no route counters, local serve as always.
func TestOwnerCacheSingleNodeUnaffected(t *testing.T) {
	svc := svcWith(t, nil) // service.New attaches the single-node Noop
	if cluster.OwnerCacheOf(svc.Cluster()) != nil {
		t.Fatal("single node has an owner cache")
	}
	lh, ran := local()
	h := Wrap(svc, Options{WriteError: writeErr}, lh)
	reqs0, lookups0 := expvarInt(t, "aerolvm_cluster_route_requests_total"), routeLookups(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req("sb-1"))
	if !*ran {
		t.Fatalf("single node did not serve locally; status %d", rr.Code)
	}
	if expvarInt(t, "aerolvm_cluster_route_requests_total") != reqs0 || routeLookups(t) != lookups0 {
		t.Fatal("single node counted route lookups")
	}
}
