package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// capacityPeer is a worker's /v1/capacity endpoint that counts its requests.
// gate, when not nil, holds every request until it is closed; fail makes it
// answer 500.
type capacityPeer struct {
	srv  *httptest.Server
	hits atomic.Int32
	fail atomic.Bool
	gate chan struct{}
}

func newCapacityPeer(t *testing.T, worker Member, gate chan struct{}) *capacityPeer {
	t.Helper()
	p := &capacityPeer{gate: gate}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		if p.gate != nil {
			<-p.gate
		}
		if p.fail.Load() || r.URL.Path != "/v1/capacity" {
			http.Error(w, "not now", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(worker.Capacity)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// client is an HTTP client that trusts the peer's test certificate. It is
// not an *http.Transport, so ClientForPeer leaves it alone: the test
// certificate carries no node id, and the node-id pin has its own tests.
func (p *capacityPeer) client() *http.Client {
	return &http.Client{Transport: roundTripperFunc(p.srv.Client().Transport.RoundTrip)}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// onDemandLeader is a leader with a lease cache that has no lease for its
// worker, the way a server that has just started sees it; the worker's
// /v1/capacity is served by peer.
func onDemandLeader(t *testing.T, worker Member, gate chan struct{}) (*Cluster, *capacityPeer) {
	t.Helper()
	peer := newCapacityPeer(t, worker, gate)
	worker.InternalURL = peer.srv.URL
	c := slotCluster(worker)
	c.capacityLeases = newCapacityLeaseCache(c.nodeID, nil, 5*time.Second, nil)
	c.internalClient = peer.client()
	return c, peer
}

func onDemandReserve(sandboxID, owner string) command {
	return ledgerReserve(sandboxID, owner, "inc-"+sandboxID, 1)
}

// A server elected right after it started has no lease for a worker the
// router picked from its own fresh view. Admission used to refuse that create
// with a retryable 503 ("has no fresh capacity heartbeat") until the sweep
// reached the worker, about 20 s in the cluster-chaos runs (UC-477, UC-481).
// Now the leader fetches the lease itself first, and the create is admitted.
func TestReserveOnLeaderWithoutLeaseFetchesItFromTheOwner(t *testing.T) {
	bc := newReserveTestCluster(t, 0, 4)
	worker := slotWorker(bc.target.NodeID, 4, containerAndFC)
	peer := newCapacityPeer(t, worker, nil)
	worker.InternalURL = peer.srv.URL
	bc.leader.gossip.currentMemberIndex().replace([]Member{worker})
	bc.leader.capacityLeases = newCapacityLeaseCache(bc.leader.nodeID, nil, 5*time.Second, nil)
	bc.leader.internalClient = peer.client()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}
	before := capacityLeaseOnDemandFetches.Value()

	// The worker cannot answer: the refusal is today's retryable one, and the
	// leader asked the worker once.
	peer.fail.Store(true)
	err := bc.leader.ReserveOnTarget(context.Background(), "sb-od-1", bc.target, spec, PlacementSecrets{}, time.Minute)
	if !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("worker failing its capacity fetch: reserve = %v, want ErrNoPlacementTarget", err)
	}
	if got := peer.hits.Load(); got != 1 {
		t.Fatalf("worker asked %d times, want 1", got)
	}

	// The worker answers: admitted, and the lease is kept for the next one.
	peer.fail.Store(false)
	bc.leader.capacityLeases.mu.Lock()
	delete(bc.leader.capacityLeases.onDemandFailed, worker.NodeID)
	bc.leader.capacityLeases.mu.Unlock()
	if err := bc.leader.ReserveOnTarget(context.Background(), "sb-od-1", bc.target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("reserve with no lease on the leader = %v, want admitted after an on-demand fetch", err)
	}
	if err := bc.leader.ReserveOnTarget(context.Background(), "sb-od-2", bc.target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("second reserve = %v, want admitted", err)
	}
	if got := peer.hits.Load(); got != 2 {
		t.Fatalf("worker asked %d times, want 2 (the second create reads the fetched lease)", got)
	}
	if got := capacityLeaseOnDemandFetches.Value() - before; got != 1 {
		t.Fatalf("on-demand fetch counter moved by %d, want 1", got)
	}
}

func TestEnsureOwnerLeasesFetchesOnlyWhatAdmissionWouldRefuse(t *testing.T) {
	cases := []struct {
		name string
		// edit changes the worker before the leader is built.
		edit     func(*Member)
		prepare  func(*Cluster, Member)
		owner    func(*Cluster, Member) string
		wantHits int32
	}{
		{name: "no lease", wantHits: 1},
		{
			name: "lease past its ttl",
			prepare: func(c *Cluster, w Member) {
				c.capacityLeases.setReported(w.NodeID, w.Capacity, time.Now().Add(-time.Minute), 0)
			},
			wantHits: 1,
		},
		{
			name: "fresh lease",
			prepare: func(c *Cluster, w Member) {
				c.capacityLeases.setReported(w.NodeID, w.Capacity, time.Now(), 0)
			},
		},
		{name: "owner gossip lists as dead", edit: func(m *Member) { m.Alive = false }},
		{name: "owner that cannot hold sandboxes", edit: func(m *Member) { m.Role = config.NodeRoleIngress }},
		{name: "owner gossip does not know", owner: func(*Cluster, Member) string { return "worker-unknown" }},
		{name: "this server is the owner", owner: func(c *Cluster, _ Member) string { return c.nodeID }},
		{
			name: "failed less than a gap ago",
			prepare: func(c *Cluster, w Member) {
				c.capacityLeases.onDemandFailed = map[string]time.Time{w.NodeID: time.Now()}
			},
		},
		{
			name: "failed more than a gap ago",
			prepare: func(c *Cluster, w Member) {
				c.capacityLeases.onDemandFailed = map[string]time.Time{w.NodeID: time.Now().Add(-2 * capacityLeaseOnDemandGap)}
			},
			wantHits: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			worker := slotWorker("worker-1", 4, containerAndFC)
			if tc.edit != nil {
				tc.edit(&worker)
			}
			c, peer := onDemandLeader(t, worker, nil)
			if tc.prepare != nil {
				tc.prepare(c, worker)
			}
			owner := worker.NodeID
			if tc.owner != nil {
				owner = tc.owner(c, worker)
			}
			c.ensureOwnerLeases(context.Background(), onDemandReserve("sb-1", owner))
			if got := peer.hits.Load(); got != tc.wantHits {
				t.Fatalf("worker asked %d times, want %d", got, tc.wantHits)
			}
			if tc.wantHits > 0 && !c.capacityLeases.freshLease(worker.NodeID, time.Now()) {
				t.Fatal("no fresh lease after a successful on-demand fetch")
			}
		})
	}

	t.Run("a batch asks each owner once", func(t *testing.T) {
		worker := slotWorker("worker-1", 4, containerAndFC)
		c, peer := onDemandLeader(t, worker, nil)
		batch := command{Op: opReserveBatch, Reservations: []reservationCommand{
			reservationFromCommand(onDemandReserve("sb-1", worker.NodeID)),
			reservationFromCommand(onDemandReserve("sb-2", worker.NodeID)),
		}}
		c.ensureOwnerLeases(context.Background(), batch)
		if got := peer.hits.Load(); got != 1 {
			t.Fatalf("worker asked %d times, want 1", got)
		}
	})
}

// Concurrent creates onto one worker share one fetch, and a caller that goes
// away neither waits for it nor cancels it for the others.
func TestEnsureOwnerLeasesSharesOneFetch(t *testing.T) {
	worker := slotWorker("worker-1", 4, containerAndFC)
	gate := make(chan struct{})
	c, peer := onDemandLeader(t, worker, gate)

	gone, cancel := context.WithCancel(context.Background())
	goneDone := make(chan struct{})
	go func() {
		defer close(goneDone)
		c.ensureOwnerLeases(gone, onDemandReserve("sb-gone", worker.NodeID))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for peer.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	const waiters = 16
	var wg sync.WaitGroup
	for i := range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.ensureOwnerLeases(context.Background(), onDemandReserve("sb-wait-"+string(rune('a'+i)), worker.NodeID))
		}()
	}
	cancel()
	select {
	case <-goneDone:
	case <-time.After(5 * time.Second):
		t.Fatal("a caller whose ctx ended kept waiting for the fetch")
	}
	close(gate)
	wg.Wait()
	if got := peer.hits.Load(); got != 1 {
		t.Fatalf("worker asked %d times for %d concurrent creates, want 1", got, waiters+1)
	}
	if !c.capacityLeases.freshLease(worker.NodeID, time.Now()) {
		t.Fatal("the shared fetch stored no lease after its first caller went away")
	}
}

// A failed fetch leaves the sweep's backoff alone; a successful one clears
// it, as a sweep's success does.
func TestEnsureOwnerLeasesAndTheSweepBackoff(t *testing.T) {
	worker := slotWorker("worker-1", 4, containerAndFC)
	c, peer := onDemandLeader(t, worker, nil)
	now := time.Now()
	c.capacityLeases.recordFetchResult(worker.NodeID, now, errors.New("first"))
	c.capacityLeases.recordFetchResult(worker.NodeID, now, errors.New("second"))
	if c.capacityLeases.due(worker.NodeID, now) {
		t.Fatal("two failures did not back the worker off")
	}

	peer.fail.Store(true)
	c.ensureOwnerLeases(context.Background(), onDemandReserve("sb-1", worker.NodeID))
	c.capacityLeases.mu.RLock()
	fails := c.capacityLeases.failures[worker.NodeID]
	c.capacityLeases.mu.RUnlock()
	if fails != 2 {
		t.Fatalf("sweep failures after a failed on-demand fetch = %d, want 2 (untouched)", fails)
	}

	peer.fail.Store(false)
	c.capacityLeases.mu.Lock()
	delete(c.capacityLeases.onDemandFailed, worker.NodeID)
	c.capacityLeases.mu.Unlock()
	c.ensureOwnerLeases(context.Background(), onDemandReserve("sb-1", worker.NodeID))
	if !c.capacityLeases.due(worker.NodeID, now) {
		t.Fatal("a successful on-demand fetch left the worker in the sweep's backoff")
	}
}

// Single-node and non-cluster callers have no lease cache or gossip.
func TestEnsureOwnerLeasesWithoutLeasesIsANoop(t *testing.T) {
	(&Cluster{}).ensureOwnerLeases(context.Background(), onDemandReserve("sb-1", "worker-1"))
	var nilCluster *Cluster
	nilCluster.ensureOwnerLeases(context.Background(), onDemandReserve("sb-1", "worker-1"))
	var nilCache *capacityLeaseCache
	if nilCache.freshLease("worker-1", time.Now()) {
		t.Fatal("a nil cache reported a fresh lease")
	}
}
