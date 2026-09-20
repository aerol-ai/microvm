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

	// Sized to the smallest fleet that still reproduces the original
	// starvation with the old 32-slot probe pool (400*300ms/32 = 3.75s,
	// past a 3s renewal budget), because the fixture has to distinguish
	// "answers instantly" from "answers slowly" by WALL CLOCK: at several
	// thousand concurrent TLS dials under -race nothing is instant, and the
	// test would be measuring the race detector. The full 2,000-peer shape is
	// covered by TestCapacityFirstContactAcquiresLeasesFromSlowButHealthyPeers.
	const (
		slowPeers = 400
		fastPeers = 200
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

	// The property is that a responsive peer's renewal does not depend on how
	// many peers are slow — not that one particular sweep is long enough for
	// 2,000 real TLS dials. The first sweep is where the slow peers are
	// MEASURED; from then on they are excluded from the probe and paced, so
	// the responsive class must converge to "renewed every sweep" and the
	// slow class's cost per sweep must fall.
	const sweeps = 3
	perSweepSlowDials := make([]int64, 0, sweeps)
	firstSweep := time.Now()
	var lastSweepStart time.Time
	for range sweeps {
		lastSweepStart = time.Now()
		before := slowHits.Load()
		c.refreshCapacityLeases(context.Background())
		perSweepSlowDials = append(perSweepSlowDials, slowHits.Load()-before)
	}

	var missed int
	for _, id := range healthy {
		c.capacityLeases.mu.RLock()
		lease, ok := c.capacityLeases.leases[id]
		c.capacityLeases.mu.RUnlock()
		if !ok || lease.updated.Before(lastSweepStart) {
			missed++
		}
	}
	if missed > 0 {
		t.Fatalf("%d of %d responsive peers were still not renewed by sweep %d (slow dials per sweep: %v); a lease that costs microseconds to renew cannot be contingent on how many other peers are slow",
			missed, fastPeers, sweeps, perSweepSlowDials)
	}

	// And the slow class must not be starved to achieve that: it is slow, not
	// broken, and its leases have the same TTL as everyone else's.
	var slowRefreshed int
	c.capacityLeases.mu.RLock()
	for i := range slowPeers {
		if lease, ok := c.capacityLeases.leases[fmt.Sprintf("slow-%04d", i)]; ok && !lease.updated.Before(firstSweep) {
			slowRefreshed++
		}
	}
	c.capacityLeases.mu.RUnlock()
	if slowRefreshed == 0 {
		t.Fatalf("no slow-but-healthy peer was refreshed across %d sweeps (dials per sweep: %v); protecting the responsive class must not starve the rest", sweeps, perSweepSlowDials)
	}
}

// A fleet that is uniformly SLOW BUT HEALTHY — every peer answers well inside
// the 2s full timeout, just not inside the 300ms probe — must still become
// schedulable. The quick pass is sized to cover the class within the budget,
// so on a fleet like this it consumes the whole budget and the full pass,
// which is the only one that can actually get an answer, never runs. First
// contact is the worst case: those peers never acquire a lease, so they are
// never reclassified and every sweep repeats the same futile probe.
func TestCapacityFirstContactAcquiresLeasesFromSlowButHealthyPeers(t *testing.T) {
	var attempts, answers atomic.Int64
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		select {
		case <-time.After(400 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		answers.Add(1)
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 8192})
	}))
	defer slow.Close()

	peerTransport := newInternalTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only
	peerClient := &http.Client{Transport: peerTransport}
	c := &Cluster{
		nodeID:         "self",
		internalClient: &http.Client{Transport: peerTransport},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
	}

	const peers = 2000
	for i := range peers {
		id := fmt.Sprintf("slow-%04d", i)
		c.gossip.memberIndex.upsert(Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: slow.URL, InternalURL: slow.URL})
		c.peerClients.m.Store(id, peerClient)
	}

	// Three sweeps, as the reproduction ran them.
	for range 3 {
		c.refreshCapacityLeases(context.Background())
	}

	c.capacityLeases.mu.RLock()
	leases := len(c.capacityLeases.leases)
	c.capacityLeases.mu.RUnlock()
	if leases == 0 {
		t.Fatalf("%d attempts produced %d completed responses and ZERO leases: the sweep never reserves time for the pass that can answer, so a healthy fleet stays unschedulable",
			attempts.Load(), answers.Load())
	}
	// Bounded progress is the bar, not full coverage: a class that cannot be
	// covered in one sweep must still converge instead of restarting.
	if leases < peers/10 {
		t.Fatalf("only %d of %d peers acquired a lease over three sweeps; progress is not bounded below", leases, peers)
	}

	// Sustained RENEWAL of the same class matters as much as acquisition: a
	// peer that answers in 400ms must keep its lease, not acquire one and
	// then lose it because renewals only ever get the probe.
	acquired := make([]string, 0, leases)
	c.capacityLeases.mu.RLock()
	for id := range c.capacityLeases.leases {
		if id != "self" {
			acquired = append(acquired, id)
		}
	}
	c.capacityLeases.mu.RUnlock()

	renewFrom := time.Now()
	for range 2 {
		c.refreshCapacityLeases(context.Background())
	}
	var renewed int
	c.capacityLeases.mu.RLock()
	for _, id := range acquired {
		if lease, ok := c.capacityLeases.leases[id]; ok && !lease.updated.Before(renewFrom) {
			renewed++
		}
	}
	c.capacityLeases.mu.RUnlock()
	if renewed == 0 {
		t.Fatalf("none of the %d established slow-but-healthy leases was renewed in two further sweeps", len(acquired))
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
	perSweep := int(float64(pool) * (float64(budget) / float64(capacityLeaseFetchTimeout)))
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

	// A peer that fails on its OWN account must still back off.
	dead := Member{NodeID: "dead", Alive: true, Role: config.NodeRoleWorker, APIURL: "https://127.0.0.1:1", InternalURL: "https://127.0.0.1:1"}
	c.gossip.memberIndex.upsert(dead)
	c.peerClients.m.Store(dead.NodeID, peerClient)
	c.runCapacityFetchPhase(context.Background(), []Member{dead}, 5*time.Second, capacityFetchPass{
		attemptTimeout: capacityLeaseFetchTimeout,
		recordFailures: true,
	})
	if c.capacityLeases.due(dead.NodeID, time.Now()) {
		t.Fatal("a peer that refused the connection was not backed off; real failures must still be paced")
	}
}

// End-to-end form of the same property: a fleet of peers that all need the
// full request path must have EVERY lease refreshed within one TTL window,
// not merely "some progress". A peer whose lease goes stale is dropped by
// placement, so partial coverage means healthy capacity disappears.
func TestCapacityRenewsEveryLeaseWithinOneTTLWindow(t *testing.T) {
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(1200 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 8192})
	}))
	defer slow.Close()

	peerTransport := newInternalTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only
	peerClient := &http.Client{Transport: peerTransport}
	c := &Cluster{
		nodeID:         "self",
		internalClient: &http.Client{Transport: peerTransport},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
	}

	// Sized past what the old 128-slot / three-fifths-of-the-sweep renewal
	// path could cover in a TTL window (3 x 128 x 3s/1.2s = 960), so the test
	// measures throughput rather than wall-clock luck.
	const fleet = 1200
	seeded := time.Now()
	for i := range fleet {
		id := fmt.Sprintf("slow-%04d", i)
		c.gossip.memberIndex.upsert(Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: slow.URL, InternalURL: slow.URL})
		c.peerClients.m.Store(id, peerClient)
		// Every peer already holds a lease: these are RENEWALS, so there is
		// no first-contact work competing for the sweep.
		c.capacityLeases.set(id, capacity.Snapshot{HostCPUCores: 4}, seeded)
	}

	// One TTL window is three sweeps at the default cadence.
	start := time.Now()
	for range 3 {
		c.refreshCapacityLeases(context.Background())
	}

	var stale []string
	c.capacityLeases.mu.RLock()
	for i := range fleet {
		id := fmt.Sprintf("slow-%04d", i)
		if lease, ok := c.capacityLeases.leases[id]; !ok || lease.updated.Before(start) {
			stale = append(stale, id)
		}
	}
	c.capacityLeases.mu.RUnlock()
	if len(stale) > 0 {
		t.Fatalf("%d of %d healthy peers were not refreshed in a full TTL window; placement drops a CapacityStale worker, so that capacity is gone despite every endpoint answering inside its timeout",
			len(stale), fleet)
	}
}
