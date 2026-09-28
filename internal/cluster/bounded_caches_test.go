package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// Every Agent RPC picks a server. Snapshotting the whole membership first and
// filtering allocates the entire fleet — about 1.16 MB per discovery at 2,000
// nodes — to choose among a handful of candidates.
func TestControlPlaneMembersReadsMaintainedServerIndex(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	for i := range 2000 {
		index.upsert(Member{NodeID: fmt.Sprintf("wrk-%04d", i), Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://w"})
	}
	for i := range 5 {
		index.upsert(Member{NodeID: fmt.Sprintf("srv-%d", i), Alive: true, Role: config.NodeRoleServer, InternalURL: "https://s"})
	}
	index.upsert(Member{NodeID: "srv-dead", Alive: false, Role: config.NodeRoleServer, InternalURL: "https://d"})
	index.upsert(Member{NodeID: "srv-no-endpoint", Alive: true, Role: config.NodeRoleServer})

	a := &Agent{nodeID: "worker-self", gossip: &gossipNode{memberIndex: index}}
	got := a.controlPlaneMembers()
	if len(got) != 5 {
		t.Fatalf("control-plane candidates = %d, want 5 (alive server-role with an endpoint)", len(got))
	}
	for _, m := range got {
		if m.Role != config.NodeRoleServer || !m.Alive || m.InternalURL == "" {
			t.Fatalf("candidate %+v is not an addressable live server", m)
		}
	}

	// The maintained index must itself stay small: it is the fleet snapshot
	// this change exists to avoid.
	if snap := index.controlPlaneSnapshot(); len(snap) != 5 {
		t.Fatalf("server index holds %d entries for a 2,007-member fleet, want 5", len(snap))
	}

	// A server going away must leave the index.
	index.upsert(Member{NodeID: "srv-0", Alive: false, Role: config.NodeRoleServer, InternalURL: "https://s"})
	if snap := index.controlPlaneSnapshot(); len(snap) != 4 {
		t.Fatalf("server index = %d after a server died, want 4", len(snap))
	}
}

// A dead or slow peer must not hold a pool slot a healthy peer needs before
// its lease expires. 256 timing-out endpoints at a 2s dial timeout is ~16s of
// work across 32 workers, longer than the 15s minimum TTL.
func TestCapacityLeaseBacksOffFailingPeersIndependently(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := newCapacityLeaseCache("self", nil, 5*time.Second, logger)
	now := time.Now()

	if !c.due("peer-a", now) {
		t.Fatal("an unseen peer must be due immediately")
	}
	// One failure is noise: the backoff base is the whole lease TTL, so pacing
	// on the first miss would cost a transiently slow peer its lease. It is
	// retried on the next sweep.
	c.recordFetchResult("peer-a", now, fmt.Errorf("dial timeout"))
	if !c.due("peer-a", now.Add(time.Second)) {
		t.Fatal("a peer that failed once was backed off; one transient miss must not cost it its lease")
	}
	// Two in a row is a signal: from here the peer is paced.
	c.recordFetchResult("peer-a", now, fmt.Errorf("dial timeout"))
	if c.due("peer-a", now.Add(time.Second)) {
		t.Fatal("a peer failing repeatedly was re-attempted on the very next tick")
	}
	if !c.due("peer-a", now.Add(capacityLeaseBackoffMax+time.Second)) {
		t.Fatal("a failing peer is never retried")
	}
	// Backoff grows, capped.
	for range 20 {
		c.recordFetchResult("peer-a", now, fmt.Errorf("dial timeout"))
	}
	c.mu.RLock()
	next := c.nextAttempt["peer-a"]
	c.mu.RUnlock()
	if wait := next.Sub(now); wait > capacityLeaseBackoffMax {
		t.Fatalf("backoff grew to %s, cap is %s", wait, capacityLeaseBackoffMax)
	}

	// A healthy peer is unaffected by the other's failures, and success
	// clears the backoff.
	if !c.due("peer-b", now) {
		t.Fatal("a healthy peer was postponed by another peer's failures")
	}
	c.recordFetchResult("peer-a", now, nil)
	if !c.due("peer-a", now) {
		t.Fatal("a recovered peer stayed in backoff")
	}
}

// The most-stale peer is refreshed first, so a long tail cannot push a peer
// past its own TTL.
func TestCapacityLeaseStalenessOrdersTheQueue(t *testing.T) {
	c := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	now := time.Now()
	c.set("fresh", capacity.Snapshot{}, now)
	c.set("stale", capacity.Snapshot{}, now.Add(-30*time.Second))

	if c.staleness("stale", now) <= c.staleness("fresh", now) {
		t.Fatal("staleness ordering does not prefer the peer closest to expiry")
	}
	if c.staleness("never-seen", now) <= c.staleness("stale", now) {
		t.Fatal("a peer with no lease at all must be the most urgent")
	}
}

// Node metadata caches need a retirement policy: without one they keep an
// entry per node the process has ever gossiped with.
func TestCapacityLeaseRetiresDepartedNodes(t *testing.T) {
	c := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	now := time.Now()
	for i := range 100 {
		id := fmt.Sprintf("gone-%03d", i)
		c.set(id, capacity.Snapshot{}, now)
		c.recordFetchResult(id, now, fmt.Errorf("dead"))
	}
	c.set("still-here", capacity.Snapshot{}, now)
	c.set("self", capacity.Snapshot{}, now)

	dropped := c.retain(map[string]struct{}{"still-here": {}, "self": {}})
	if dropped != 100 {
		t.Fatalf("retired %d departed nodes, want 100", dropped)
	}
	c.mu.RLock()
	leases, next, fails := len(c.leases), len(c.nextAttempt), len(c.failures)
	c.mu.RUnlock()
	if leases != 2 || next != 0 || fails != 0 {
		t.Fatalf("after retirement: leases=%d nextAttempt=%d failures=%d, want 2/0/0", leases, next, fails)
	}
}

// The reverse-proxy cache is keyed by (node, URL) and had no eviction at all,
// so a retired peer — or a peer whose advertised URL changed — left an entry
// behind forever.
func TestProxyCacheRetiresDepartedPeers(t *testing.T) {
	pc := newProxyCache()
	rt := http.DefaultTransport
	for i := range 50 {
		id := fmt.Sprintf("peer-%02d", i)
		if _, err := pc.getForPeer(id, "https://"+id+".internal:9443", rt); err != nil {
			t.Fatalf("getForPeer(%s): %v", id, err)
		}
	}
	// Same peer, new advertised URL: a second entry, which retirement must
	// also reclaim.
	if _, err := pc.getForPeer("peer-00", "https://peer-00-moved.internal:9443", rt); err != nil {
		t.Fatalf("getForPeer moved: %v", err)
	}
	pc.mu.RLock()
	before := len(pc.proxies)
	pc.mu.RUnlock()
	if before != 51 {
		t.Fatalf("proxy cache = %d entries, want 51", before)
	}

	pc.invalidate("peer-00")
	pc.mu.RLock()
	after := len(pc.proxies)
	var leftover *httputil.ReverseProxy
	for key, p := range pc.proxies {
		if len(key) >= 7 && key[:7] == "peer-00" {
			leftover = p
		}
	}
	pc.mu.RUnlock()
	if after != 49 {
		t.Fatalf("proxy cache = %d entries after retiring one peer, want 49", after)
	}
	if leftover != nil {
		t.Fatal("a retired peer kept a pinned reverse proxy")
	}
	pc.invalidate("")
	pc.invalidate("absent")
}
