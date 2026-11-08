package clusterroute

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func (f *fleet) epochOf(id string) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.place[id].epoch
}

func (n *fleetNode) sent() []string {
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	return slices.Clone(n.sentEpochs)
}

// A forward carries the epoch the edge's lookup read, and the owner drops
// the header before its handler runs, so nothing behind it (a toolbox proxy
// into the sandbox) sees it.
func TestForwardCarriesTheOwnerEpoch(t *testing.T) {
	f := newFleet(t, false, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	if rr.Code != http.StatusOK || rr.Header().Get("X-Served-By") != "worker-a" {
		t.Fatalf("got %d from %q, want 200 from worker-a", rr.Code, rr.Header().Get("X-Served-By"))
	}
	want := strconv.FormatUint(f.epochOf("sb-1"), 10)
	if got := f.nodes["ingress-1"].sent(); !slices.Equal(got, []string{want}) {
		t.Fatalf("forwards carried epochs %q, want [%s]", got, want)
	}
	if got := f.nodes["worker-a"].localEpoch; got != "" {
		t.Fatalf("the local handler saw epoch header %q", got)
	}
}

// The sandbox moved away and came back after the edge cached it. The owner
// owns it again, but the cached entry's epoch is older than the owner's own
// reading, so the owner turns it down once; the edge routes again from a
// fresh lookup, and its new entry carries the current epoch.
func TestCachedForwardWithAnOlderEpochIsRoutedAgain(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a", "worker-b")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "") // fill the cache
	stale := strconv.FormatUint(f.epochOf("sb-1"), 10)
	f.move("sb-1", "worker-b")
	f.move("sb-1", "worker-a")
	current := strconv.FormatUint(f.epochOf("sb-1"), 10)

	sentBefore := len(f.nodes["ingress-1"].sent())
	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Served-By") != "worker-a" {
		t.Fatalf("got %d from %q, want 200 from worker-a", rr.Code, rr.Header().Get("X-Served-By"))
	}
	if d.notHere["worker-a"] != 1 || d.forwards["ingress-1"] != 2 || d.served["worker-a"] != 1 {
		t.Fatalf("not-here=%d forwards=%d served=%d, want 1, 2, 1", d.notHere["worker-a"], d.forwards["ingress-1"], d.served["worker-a"])
	}
	if got := f.nodes["ingress-1"].sent()[sentBefore:]; !slices.Equal(got, []string{stale, current}) {
		t.Fatalf("epochs sent %q, want [%s %s]", got, stale, current)
	}

	// The refreshed entry is current: one forward, no "not here".
	before = f.snapshot()
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d = f.snapshot().since(before)
	if d.forwards["ingress-1"] != 1 || d.notHere["worker-a"] != 0 {
		t.Fatalf("next call: forwards=%d not-here=%d, want 1 and 0", d.forwards["ingress-1"], d.notHere["worker-a"])
	}
}

// A cached forward whose epoch matches is served as before, and one from an
// edge on an older build (no epoch) is served as before too.
func TestCachedForwardWithTheCurrentOrNoEpochIsServed(t *testing.T) {
	f := newFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	before := f.snapshot()
	f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	if d := f.snapshot().since(before); d.notHere["worker-a"] != 0 || d.served["worker-a"] != 1 {
		t.Fatalf("current epoch: not-here=%d served=%d, want 0 and 1", d.notHere["worker-a"], d.served["worker-a"])
	}

	rr := httptest.NewRecorder()
	f.nodes["worker-a"].h.ServeHTTP(rr, ownerHopRequest(t, "sb-1", "token-1", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("no epoch: got %d, want 200", rr.Code)
	}
}

func ownerHopRequest(t *testing.T, id, hint, epoch string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x/"+id, nil)
	req.Header.Set(cluster.HeaderForwarded, "1")
	if hint != "" {
		req.Header.Set(cluster.HeaderRouteHint, hint)
	}
	if epoch != "" {
		req.Header.Set(cluster.HeaderOwnerEpoch, epoch)
	}
	return req
}

func TestForwardedOwnerEpoch(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint64
	}{{"", 0}, {"12", 12}, {" 12 ", 12}, {"-1", 0}, {"x", 0}, {"18446744073709551616", 0}} {
		h := http.Header{}
		if tc.value != "" {
			h.Set(cluster.HeaderOwnerEpoch, tc.value)
		}
		if got := cluster.ForwardedOwnerEpoch(h); got != tc.want {
			t.Errorf("%q: got %d, want %d", tc.value, got, tc.want)
		}
	}
}
