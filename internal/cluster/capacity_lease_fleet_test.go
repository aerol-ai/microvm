package cluster

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// Fleet-scale capacity tests.
//
// These assert SCHEDULING properties — every healthy lease is renewed inside
// its TTL — so they drive the sweep through a scripted in-process transport:
// each peer answers after an exact latency and honours cancellation, with no
// sockets and no TLS. Everything above the socket is production code: peer
// dial, fetchCapacitySnapshot, both passes, pool sizing, the fairness clock,
// the backoff.
//
// They used to run real TLS against one httptest server. Measured under -race,
// that added only ~1ms per completed request, but the fixtures ran close to the
// sweep's batch ceiling on a single host, so machine load (a combined -race
// run, parallel packages) decided whether they passed. That tests the machine,
// not the scheduler. Real-socket throughput at fleet scale is an environment
// property and belongs in a representative-environment run; the single-peer
// tests in capacity_lease_additional_test.go still exercise the real TLS path.

// scriptedPeerTransport answers /v1/capacity for every peer. Latency is chosen
// per peer by host prefix: "fast-" answers at once, "slow-" after slow,
// "hole-" never answers.
type scriptedPeerTransport struct {
	slow    time.Duration
	calls   atomic.Int64
	answers atomic.Int64
}

func (t *scriptedPeerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	var wait time.Duration
	switch host := req.URL.Hostname(); {
	case strings.HasPrefix(host, "fast-"):
	case strings.HasPrefix(host, "hole-"):
		<-req.Context().Done()
		return nil, req.Context().Err()
	default:
		wait = t.slow
	}
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	t.answers.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"host_cpu_cores":4,"host_memory_total_mb":8192}`)),
		Request:    req,
	}, nil
}

type scriptedFleet struct {
	c         *Cluster
	transport *scriptedPeerTransport
	ids       []string
}

func newScriptedFleet(slow time.Duration) *scriptedFleet {
	tr := &scriptedPeerTransport{slow: slow}
	client := &http.Client{Transport: tr}
	return &scriptedFleet{
		transport: tr,
		c: &Cluster{
			nodeID:         "self",
			internalClient: client,
			logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
			gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
		},
	}
}

// add registers n peers named prefix-NNNN. leased seeds a fresh lease (a
// renewal); classifiedSlow records the peer as already measured slower than
// the probe, as a node that has been running is.
func (f *scriptedFleet) add(prefix string, n int, leased, classifiedSlow bool) []string {
	client := &http.Client{Transport: f.transport}
	ids := make([]string, 0, n)
	now := time.Now()
	for i := range n {
		id := fmt.Sprintf("%s-%04d", prefix, i)
		url := "https://" + id + ".peer.test"
		f.c.gossip.memberIndex.upsert(Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: url, InternalURL: url})
		f.c.peerClients.m.Store(id, client)
		if leased {
			f.c.capacityLeases.set(id, capacity.Snapshot{HostCPUCores: 4}, now)
		}
		if classifiedSlow {
			f.c.capacityLeases.recordResponsiveness(id, false)
		}
		ids = append(ids, id)
	}
	f.ids = append(f.ids, ids...)
	return ids
}

// leaseAges returns, for ids, how many have no lease and the oldest lease age.
func (f *scriptedFleet) leaseAges(ids []string) (missing int, oldest time.Duration) {
	now := time.Now()
	f.c.capacityLeases.mu.RLock()
	defer f.c.capacityLeases.mu.RUnlock()
	for _, id := range ids {
		lease, ok := f.c.capacityLeases.leases[id]
		if !ok {
			missing++
			continue
		}
		if age := now.Sub(lease.updated); age > oldest {
			oldest = age
		}
	}
	return missing, oldest
}

func (f *scriptedFleet) refreshedSince(ids []string, since time.Time) (stale int) {
	f.c.capacityLeases.mu.RLock()
	defer f.c.capacityLeases.mu.RUnlock()
	for _, id := range ids {
		if lease, ok := f.c.capacityLeases.leases[id]; !ok || lease.updated.Before(since) {
			stale++
		}
	}
	return stale
}

// runWindows runs TTL windows of sweeps at the real cadence and fails if any
// healthy lease expires at any sample point between sweeps, or is not
// refreshed within a window.
func (f *scriptedFleet) runWindows(t *testing.T, healthy []string, windows int) {
	t.Helper()
	ttl := f.c.capacityLeases.ttl
	sweepsPerWindow := int(ttl / f.c.capacityLeaseSweepBudget())
	for w := 1; w <= windows; w++ {
		windowStart := time.Now()
		for s := 1; s <= sweepsPerWindow; s++ {
			f.c.refreshCapacityLeases(context.Background())
			if missing, oldest := f.leaseAges(healthy); missing > 0 || oldest > ttl {
				t.Fatalf("window %d sweep %d: %d healthy peers have no lease and the oldest lease is %s old (TTL %s): placement treats them as CapacityStale",
					w, s, missing, oldest.Round(time.Millisecond), ttl)
			}
		}
		if stale := f.refreshedSince(healthy, windowStart); stale > 0 {
			t.Fatalf("window %d: %d of %d healthy leases were not refreshed within the TTL window", w, stale, len(healthy))
		}
	}
}

// The supported target: 2,000 healthy peers that all need the full request
// path — 1.9s, inside the 2s per-request timeout — keep every lease alive over
// multiple TTL windows at the real cadence. This is the reviewer's shape.
func TestCapacityKeepsTheSupportedFleetFreshAcrossTTLWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two TTL windows at the real cadence")
	}
	f := newScriptedFleet(1900 * time.Millisecond)
	healthy := f.add("slow", 2000, true, true)
	f.runWindows(t, healthy, 2)
}

// The same fleet with ONE newcomer that never answers. First contact must not
// take time from renewals: a slow peer needs one slot for two seconds, not two
// seconds of the whole pool.
func TestCapacityKeepsTheFleetFreshWithANewcomerPending(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two TTL windows at the real cadence")
	}
	f := newScriptedFleet(1900 * time.Millisecond)
	healthy := f.add("slow", 1999, true, true)
	f.add("hole", 1, false, false)
	f.runWindows(t, healthy, 2)
	// And the newcomer really was tried, and is now paced rather than
	// holding a slot every sweep.
	if f.c.capacityLeases.due("hole-0000", time.Now()) {
		t.Fatal("a newcomer that never answers was not backed off after repeated failures")
	}
}

// Peers that answer at once must be renewed however many others are slow:
// 1,296 slow and 704 instant, all renewals, before anything is classified.
func TestCapacityRenewsInstantRespondersBehindASlowFleet(t *testing.T) {
	f := newScriptedFleet(1200 * time.Millisecond)
	f.add("slow", 1296, true, false)
	fast := f.add("fast", 704, true, false)
	start := time.Now()
	f.c.refreshCapacityLeases(context.Background())
	if stale := f.refreshedSince(fast, start); stale > 0 {
		t.Fatalf("%d of %d instant responders were not renewed in a sweep spent on slow peers", stale, len(fast))
	}
	// The slow class is classified and routed straight to the full request,
	// and is not starved to achieve the above.
	start = time.Now()
	f.c.refreshCapacityLeases(context.Background())
	var slowRefreshed int
	for _, id := range f.ids {
		if strings.HasPrefix(id, "slow-") && f.refreshedSince([]string{id}, start) == 0 {
			slowRefreshed++
		}
	}
	if slowRefreshed == 0 {
		t.Fatal("no slow-but-healthy peer was refreshed once classified")
	}
	if stale := f.refreshedSince(fast, start); stale > 0 {
		t.Fatalf("%d instant responders missed the second sweep", stale)
	}
}

// A fleet that is uniformly slow-but-healthy must be DISCOVERED: first contact
// reserves time for the pass that can answer, and a peer measured slower than
// the probe skips it from then on.
func TestCapacityDiscoversASlowButHealthyFleet(t *testing.T) {
	f := newScriptedFleet(400 * time.Millisecond)
	peers := f.add("slow", 2000, false, false)
	for range 2 {
		f.c.refreshCapacityLeases(context.Background())
	}
	if missing, _ := f.leaseAges(peers); missing > 0 {
		t.Fatalf("%d of %d slow-but-healthy peers were never discovered in two sweeps", missing, len(peers))
	}
	// And once discovered they stay renewed.
	start := time.Now()
	f.c.refreshCapacityLeases(context.Background())
	if stale := f.refreshedSince(peers, start); stale > 0 {
		t.Fatalf("%d discovered peers were not renewed on the next sweep", stale)
	}
}
