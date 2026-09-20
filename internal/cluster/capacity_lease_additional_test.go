package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestCapacityLeaseCacheRefreshLocal(t *testing.T) {
	admitter := capacity.New(capacity.HostInfo{CPUCores: 4}, capacity.Limits{}, nil)
	cache := newCapacityLeaseCache("self", admitter, time.Second, nil)
	cache.SetLocalTemplateIDsProvider(func() ([]string, bool) {
		return []string{"tpl-1"}, true
	})

	cache.refreshLocal(time.Now())

	cache.mu.RLock()
	lease := cache.leases["self"]
	cache.mu.RUnlock()

	if !lease.snapshot.LocalTemplateInventoryKnown {
		t.Errorf("expected template inventory known")
	}
}

func TestFetchCapacitySnapshot(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	_, err := fetchCapacitySnapshot(context.Background(), ts.Client(), ts.URL, "")
	if err == nil {
		t.Errorf("expected error on 404")
	}
	var stErr statusError
	if !errors.As(err, &stErr) || stErr.status != http.StatusNotFound {
		t.Errorf("expected statusError 404, got %v", err)
	}

	// Test bad json
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer ts2.Close()

	_, err = fetchCapacitySnapshot(context.Background(), ts2.Client(), ts2.URL, "")
	if err == nil {
		t.Errorf("expected error on bad json")
	}
}

func TestFetchMemberCapacityNoUrl(t *testing.T) {
	c := &Cluster{}
	_, err := c.fetchMemberCapacity(context.Background(), Member{NodeID: "m1", APIURL: ""}, capacityLeaseFetchTimeout)
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Errorf("expected missing url error, got %v", err)
	}
}

func TestFetchMemberCapacityFailClosedOnInternal503(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("try public"))
	}))
	defer internal.Close()

	publicHits := 0
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits++
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384})
	}))
	defer public.Close()

	c := &Cluster{
		internalClient: internal.Client(),
	}
	_, err := c.fetchMemberCapacity(context.Background(), Member{
		NodeID:      "m1",
		APIURL:      public.URL,
		InternalURL: internal.URL,
	}, capacityLeaseFetchTimeout)
	if err == nil {
		t.Fatal("expected internal 503 to fail closed (no public downgrade)")
	}
	if publicHits != 0 {
		t.Fatalf("public hits = %d, want 0", publicHits)
	}
}

func TestRefreshCapacityLeasesHandlesErrorsAndFallbacks(t *testing.T) {
	internalError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer internalError.Close()

	internalUnavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer internalUnavailable.Close()

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 6, HostMemoryTotalMB: 12288})
	}))
	defer public.Close()

	c := &Cluster{
		nodeID:         "self",
		internalClient: &http.Client{}, // shared dialer; PeerDial selects each peer's InternalURL
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "skip-empty", Alive: true, Role: config.NodeRoleWorker})
	c.gossip.memberIndex.upsert(Member{NodeID: "dead-node", Alive: false, Role: config.NodeRoleWorker, APIURL: public.URL})
	c.gossip.memberIndex.upsert(Member{NodeID: "error-node", Alive: true, Role: config.NodeRoleWorker, APIURL: public.URL, InternalURL: internalError.URL})
	c.gossip.memberIndex.upsert(Member{NodeID: "no-public-downgrade", Alive: true, Role: config.NodeRoleWorker, APIURL: public.URL, InternalURL: internalUnavailable.URL})

	c.refreshCapacityLeases(context.Background())

	// With TLS loaded, a 503 on the internal channel must not silently
	// downgrade to the public capacity endpoint.
	if _, ok := c.capacityLeases.leases["no-public-downgrade"]; ok {
		t.Fatal("refreshCapacityLeases() downgraded 503 internal to public capacity")
	}
	if _, ok := c.capacityLeases.leases["skip-empty"]; ok {
		t.Fatal("refreshCapacityLeases() created a lease for skip-empty member")
	}
}

// A fleet where most peers are SLOW BUT ALIVE is the shape the renewal
// reservation does not survive on its own. 1,296 peers that answer in ~1.2s
// miss the 300ms quick probe, and because a quick-probe miss is deliberately
// not a failure, they never enter backoff — so every sweep re-probes all of
// them at full cost. They and the 704 peers that answer instantly are all
// renewals, so they compete for the same reserved slice, and at 32 slots the
// slow ones occupy it for the whole sweep. The healthy peers are never
// dialled and their leases expire while they are answering in microseconds.
func TestCapacitySweepKeepsRenewingResponsivePeersUnderASlowFleet(t *testing.T) {
	var slowHits, fastHits atomic.Int64
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowHits.Add(1)
		select {
		case <-time.After(1200 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 8192})
	}))
	defer slow.Close()
	fast := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastHits.Add(1)
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384})
	}))
	defer fast.Close()

	// One shared peer transport, as production has: every peer is dialled
	// through the same pool, which is why one class of peers can occupy it.
	peerTransport := newInternalTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only
	peerClient := &http.Client{Transport: peerTransport}
	c := &Cluster{
		nodeID:         "self",
		internalClient: &http.Client{Transport: peerTransport},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
	}

	const (
		slowPeers = 1296
		fastPeers = 704
	)
	// Every peer already holds a lease, so all 2,000 are renewals. The slow
	// ones are the stalest, which is how they reach the front of the queue.
	// Seed the per-peer client cache so the dial skips node-SAN binding
	// (httptest certs carry no node: SAN); everything else — the shared
	// transport, the worker pool, the sweep — is the production path.
	seedPeer := func(id string) { c.peerClients.m.Store(id, peerClient) }
	stale := time.Now().Add(-12 * time.Second)
	fresh := time.Now().Add(-9 * time.Second)
	healthy := make([]string, 0, fastPeers)
	for i := range slowPeers {
		id := fmt.Sprintf("slow-%04d", i)
		c.gossip.memberIndex.upsert(Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: slow.URL, InternalURL: slow.URL})
		seedPeer(id)
		c.capacityLeases.set(id, capacity.Snapshot{HostCPUCores: 4}, stale)
	}
	for i := range fastPeers {
		id := fmt.Sprintf("fast-%04d", i)
		healthy = append(healthy, id)
		c.gossip.memberIndex.upsert(Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: fast.URL, InternalURL: fast.URL})
		seedPeer(id)
		c.capacityLeases.set(id, capacity.Snapshot{HostCPUCores: 8}, fresh)
	}

	sweepStart := time.Now()
	c.refreshCapacityLeases(context.Background())

	// Every responsive peer must have been refreshed IN THIS SWEEP: renewing
	// a lease that costs microseconds cannot be contingent on how many other
	// peers are slow.
	var missed int
	for _, id := range healthy {
		c.capacityLeases.mu.RLock()
		lease, ok := c.capacityLeases.leases[id]
		c.capacityLeases.mu.RUnlock()
		if !ok || lease.updated.Before(sweepStart) {
			missed++
		}
	}
	if missed > 0 {
		t.Fatalf("%d of %d responsive peers were not renewed in a sweep spent on slow ones; their leases expire while they answer instantly", missed, fastPeers)
	}
	if fastHits.Load() < fastPeers {
		t.Fatalf("responsive peers were dialled %d times, want at least %d", fastHits.Load(), fastPeers)
	}

	// The slow peers that were probed must now be PACED, which only shows in
	// the next sweep: without it every sweep pays full price for all 1,296
	// again, because missing a quick probe never enters the failure backoff.
	slowAfterFirst := slowHits.Load()
	fastAfterFirst := fastHits.Load()
	secondSweep := time.Now()
	c.refreshCapacityLeases(context.Background())

	if probes := slowHits.Load() - slowAfterFirst; probes >= slowAfterFirst {
		t.Fatalf("the second sweep re-probed %d slow peers after %d in the first; a slow peer that is alive is never backed off, so nothing paces it", probes, slowAfterFirst)
	}
	if renewed := fastHits.Load() - fastAfterFirst; renewed < fastPeers {
		t.Fatalf("the second sweep renewed %d responsive peers, want all %d", renewed, fastPeers)
	}
	for _, id := range healthy {
		c.capacityLeases.mu.RLock()
		lease := c.capacityLeases.leases[id]
		c.capacityLeases.mu.RUnlock()
		if lease.updated.Before(secondSweep) {
			t.Fatalf("responsive peer %s was not renewed by the second sweep", id)
		}
	}
}
