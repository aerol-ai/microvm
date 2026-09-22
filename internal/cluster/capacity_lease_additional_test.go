package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// The supported fleet has to be refreshable inside the lease TTL, for peers
// that need the FULL request path — the ones the quick probe can never
// discover. This is capacity planning, not timing: how many peers one sweep
// can finish is (pool x budget / per-peer cost), and every peer has to be
// reached at least once per TTL or placement starts rejecting healthy nodes
// as CapacityStale.
func TestCapacitySweepCoversTheSupportedFleetWithinTheLeaseTTL(t *testing.T) {
	const fleet = 2000
	cache := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	c := &Cluster{capacityLeases: cache}

	ttl := cache.ttl
	budget := c.capacityLeaseSweepBudget()
	// Renewals must be able to use the whole sweep when there is no
	// first-contact work competing for it.
	pool := passConcurrency(fleet, budget, capacityLeaseFetchTimeout, capacityLeaseFullPassMaxConcurrency)
	// Requests complete in whole BATCHES: one dispatched too late to finish
	// inside the sweep yields nothing. A continuous pool*budget/timeout
	// overstates throughput by up to a batch, which is how a fleet running
	// near the timeout slipped past an earlier version of this check.
	perSweep := pool * int(budget/capacityLeaseFetchTimeout)
	sweepsPerTTL := int(ttl / budget)
	if sweepsPerTTL < 1 {
		sweepsPerTTL = 1
	}
	if covered := perSweep * sweepsPerTTL; covered < fleet {
		t.Fatalf("a %s TTL allows %d sweeps of %d peers = %d, short of the %d-node fleet: healthy workers go CapacityStale and placement stops using them (pool=%d budget=%s)",
			ttl, sweepsPerTTL, perSweep, covered, fleet, pool, budget)
	}
}

// A request the SWEEP cut short is not the peer's failure. The full pass
// gives each attempt its own timeout, but a request dispatched near the end
// of the phase only gets the phase's remaining time; charging that to the
// peer puts a healthy node into a 15s backoff whose next eligible attempt is
// already past its lease expiry.
func TestCapacityPhaseDeadlineIsNotChargedToThePeer(t *testing.T) {
	answered := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(400 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4})
	}))
	defer answered.Close()

	peerTransport := newInternalTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only
	peerClient := &http.Client{Transport: peerTransport}
	c := &Cluster{
		nodeID:         "self",
		internalClient: &http.Client{Transport: peerTransport},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
	}
	healthy := Member{NodeID: "healthy", Alive: true, Role: config.NodeRoleWorker, APIURL: answered.URL, InternalURL: answered.URL}
	c.gossip.memberIndex.upsert(healthy)
	c.peerClients.m.Store(healthy.NodeID, peerClient)

	// The phase runs out well before the peer's own 2s allowance.
	c.runCapacityFetchPhase(context.Background(), []Member{healthy}, 100*time.Millisecond, capacityFetchPass{
		attemptTimeout: capacityLeaseFetchTimeout,
		recordFailures: true,
	})
	if !c.capacityLeases.due(healthy.NodeID, time.Now()) {
		t.Fatal("a peer whose request the sweep itself cut short was put into failure backoff; it is skipped until long after its lease expires, although it never failed")
	}

	// A peer that fails on its OWN account must still be charged: once is
	// retried (one miss is noise), twice in a row is paced.
	dead := Member{NodeID: "dead", Alive: true, Role: config.NodeRoleWorker, APIURL: "https://127.0.0.1:1", InternalURL: "https://127.0.0.1:1"}
	c.gossip.memberIndex.upsert(dead)
	c.peerClients.m.Store(dead.NodeID, peerClient)
	for range 2 {
		c.runCapacityFetchPhase(context.Background(), []Member{dead}, 5*time.Second, capacityFetchPass{
			attemptTimeout: capacityLeaseFetchTimeout,
			recordFailures: true,
		})
	}
	if c.capacityLeases.due(dead.NodeID, time.Now()) {
		t.Fatal("a peer that refused the connection twice was not backed off; real failures must still be paced")
	}
	// ...whereas the curtailed peer above never accrued a failure at all.
	c.capacityLeases.mu.RLock()
	curtailedFails := c.capacityLeases.failures[healthy.NodeID]
	c.capacityLeases.mu.RUnlock()
	if curtailedFails != 0 {
		t.Fatalf("the curtailed peer accrued %d failures", curtailedFails)
	}
}

// A request the sweep cut short must not cost the peer its PLACE either. The
// fairness clock orders the next sweep by when each peer was last attempted;
// advancing it at dispatch meant a curtailed peer sorted LAST next time, was
// dispatched at the tail again and curtailed again — every sweep. No backoff
// was involved, yet those leases never renewed.
func TestCapacityCurtailedAttemptKeepsItsFairnessPosition(t *testing.T) {
	answered := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(400 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4})
	}))
	defer answered.Close()

	peerTransport := newInternalTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only
	c := &Cluster{
		nodeID:         "self",
		internalClient: &http.Client{Transport: peerTransport},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
	}
	peer := Member{NodeID: "tail", Alive: true, Role: config.NodeRoleWorker, APIURL: answered.URL, InternalURL: answered.URL}
	c.gossip.memberIndex.upsert(peer)
	c.peerClients.m.Store(peer.NodeID, &http.Client{Transport: peerTransport})

	before := c.capacityLeases.attemptedAt(peer.NodeID)
	c.runCapacityFetchPhase(context.Background(), []Member{peer}, 100*time.Millisecond, capacityFetchPass{
		attemptTimeout: capacityLeaseFetchTimeout,
		recordFailures: true,
	})
	if after := c.capacityLeases.attemptedAt(peer.NodeID); !after.Equal(before) {
		t.Fatalf("a curtailed attempt moved the peer's fairness clock from %v to %v: it now sorts behind everyone that completed and is curtailed again next sweep", before, after)
	}

	// A completed attempt DOES move it, or the rotation would never advance.
	c.runCapacityFetchPhase(context.Background(), []Member{peer}, 5*time.Second, capacityFetchPass{
		attemptTimeout: capacityLeaseFetchTimeout,
		recordFailures: true,
	})
	if after := c.capacityLeases.attemptedAt(peer.NodeID); !after.After(before) {
		t.Fatal("a completed attempt did not advance the fairness clock")
	}
}
