package service

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type bindingCluster struct {
	*cluster.Noop
	mu        sync.Mutex
	placement cluster.Placement
	present   bool
	reads     int
	block     chan struct{}
}

func newBindingCluster(self string) *bindingCluster {
	return &bindingCluster{Noop: cluster.NewNoop(self, "http://"+self, "")}
}

func (c *bindingCluster) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	c.reads++
	p, present := c.placement, c.present
	block := c.block
	c.mu.Unlock()
	if block != nil {
		<-block
	}
	if !present || p.SandboxID != id {
		return cluster.Placement{}, false
	}
	return p, true
}

func (c *bindingCluster) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// The binding check is the last per-event control-plane read on the HTTP
// ingest path. At one event per second for each of 100k sandboxes that is
// ~100k placement reads/s fleet-wide, ahead of the sink's rate limiter.
func TestEgressAuditBindingIsLeasedNotPerEvent(t *testing.T) {
	const sandboxID = "sb-busy"
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-1"}
	cl.present = true
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	for i := range 500 {
		if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1"); err != nil {
			t.Fatalf("event %d rejected: %v", i, err)
		}
	}
	if got := cl.readCount(); got != 1 {
		t.Fatalf("placement reads = %d for 500 events; the check must cost O(lifecycle), not O(events)", got)
	}
}

// Stale-owner rejection is the whole point of the check and must survive the
// lease. A local lifecycle boundary pre-empts the TTL entirely.
func TestEgressAuditBindingRejectsStaleOwnerAndIncarnation(t *testing.T) {
	const sandboxID = "sb-fenced"
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-1"}
	cl.present = true
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1"); err != nil {
		t.Fatalf("live binding rejected: %v", err)
	}
	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-other"); err == nil {
		t.Fatal("a capability for a different incarnation was accepted from the lease")
	}

	// Raft reassigns the sandbox away from this node.
	cl.mu.Lock()
	cl.placement.OwnerNodeID = "node-b"
	cl.mu.Unlock()
	svc.invalidateAuditOwnershipLease(sandboxID)
	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1"); err == nil {
		t.Fatal("a fenced owner kept appending after the local lifecycle boundary dropped its lease")
	}

	// An orphan has no legitimate worker.
	cl.mu.Lock()
	cl.present = false
	cl.mu.Unlock()
	svc.invalidateAuditOwnershipLease(sandboxID)
	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1"); err == nil {
		t.Fatal("an orphaned placement was accepted")
	}
}

// A lease expires; the next event re-reads rather than trusting it forever.
func TestEgressAuditBindingLeaseExpires(t *testing.T) {
	const sandboxID = "sb-expiring"
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-1"}
	cl.present = true
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1"); err != nil {
		t.Fatalf("first event rejected: %v", err)
	}
	leases := svc.ownershipLeases()
	leases.mu.Lock()
	entry := leases.entries[sandboxID]
	entry.expiresAt = time.Now().Add(-time.Second)
	leases.entries[sandboxID] = entry
	leases.mu.Unlock()

	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1"); err != nil {
		t.Fatalf("event after expiry rejected: %v", err)
	}
	if got := cl.readCount(); got != 2 {
		t.Fatalf("placement reads = %d, want 2 (one per lease generation)", got)
	}
}

// An unreachable authority must fail CLOSED, exactly as the per-event read
// did, and must not be cached as a lease.
func TestEgressAuditBindingFailsClosedWithoutAuthority(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}}
	if err := svc.validateEgressAuditBinding(context.Background(), "sb-x", "inc-1"); err == nil {
		t.Fatal("binding accepted with no cluster client")
	}
	leases := svc.ownershipLeases()
	leases.mu.Lock()
	entries := len(leases.entries)
	leases.mu.Unlock()
	if entries != 0 {
		t.Fatalf("an unavailable authority left %d leases behind", entries)
	}
}

// A flood of records with an expired lease must not become a flood of reads.
// This is the overload admission: it bounds the expensive remote validation
// structurally, ahead of the work.
func TestEgressAuditBindingRefreshIsSingleFlighted(t *testing.T) {
	const sandboxID = "sb-thundering"
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-1"}
	cl.present = true
	cl.block = make(chan struct{})
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	const concurrent = 64
	var wg sync.WaitGroup
	errs := make([]error, concurrent)
	for i := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-1")
		}()
	}
	// Give the goroutines time to pile onto the single flight, then release.
	time.Sleep(50 * time.Millisecond)
	close(cl.block)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent event %d rejected: %v", i, err)
		}
	}
	if got := cl.readCount(); got != 1 {
		t.Fatalf("placement reads = %d for %d concurrent events, want 1 in-flight read", got, concurrent)
	}
}

// Standalone keeps its local-row semantics and also stops re-reading SQLite
// for every record.
func TestEgressAuditBindingStandaloneUsesLocalRow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-local", Image: "wasm", Status: models.SandboxStatusStarted, AuditIncarnationID: "inc-1",
	}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{DBPath: dbPath}, store: st}

	if err := svc.validateEgressAuditBinding(ctx, "sb-local", "inc-1"); err != nil {
		t.Fatalf("live standalone binding rejected: %v", err)
	}
	if err := svc.validateEgressAuditBinding(ctx, "sb-local", "inc-old"); err == nil {
		t.Fatal("a previous lifetime's incarnation was accepted")
	}
	if err := svc.validateEgressAuditBinding(ctx, "sb-absent", "inc-1"); err == nil {
		t.Fatal("a capability for a sandbox with no row was accepted")
	}
}

// End to end through the HTTP handler. The pre-fix handler accepted 100
// events and made 101 placement reads; the count must now be a small constant
// per lifecycle (the binding lease plus the audit-identity memo) and must not
// grow with traffic.
func TestAuditIngestHandlerDoesNotReadPerEvent(t *testing.T) {
	const sandboxID = "sb-http"
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Create(t.Context(), &models.Sandbox{
		ID: sandboxID, Image: "wasm", Status: models.SandboxStatusStarted, AuditIncarnationID: "inc-1",
	}); err != nil {
		t.Fatal(err)
	}
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-1", OwnerRef: "acct-1"}
	cl.present = true

	svc := &Service{cfg: config.Config{DBPath: dbPath, EnableCluster: true}, store: st, cluster: cl}
	t.Cleanup(svc.CloseSecretAuditSink)
	ing := &auditIngestServer{svc: svc, token: "master-key"}
	capability := scopedAuditCapability(t, "master-key", sandboxID, "inc-1")

	post := func(i int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, auditIngestPath, bytes.NewReader([]byte(`{"destination":"example.com:443","network":"tcp"}`)))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(auditIngestHeaderCap, capability)
		rr := httptest.NewRecorder()
		ing.handleEgress(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("event %d status = %d body=%s", i, rr.Code, rr.Body.String())
		}
	}
	for i := range 100 {
		post(i)
	}
	afterFirst := cl.readCount()
	if afterFirst > 2 {
		t.Fatalf("handler made %d placement reads for 100 events; want at most 2 per lifecycle (binding lease + identity memo)", afterFirst)
	}
	for i := range 100 {
		post(100 + i)
	}
	if got := cl.readCount(); got != afterFirst {
		t.Fatalf("placement reads grew from %d to %d over another 100 events; the cost must not scale with traffic", afterFirst, got)
	}
}

// The lease map is bounded even for ids whose lifecycle boundary this process
// never observed.
func TestAuditOwnershipLeaseMapIsBounded(t *testing.T) {
	l := &auditOwnershipLeases{entries: make(map[string]auditOwnershipLease)}
	now := time.Now()
	for i := range auditOwnershipLeaseMaxEntries {
		l.put(fmt.Sprintf("sb-%06d", i), auditOwnershipLease{expiresAt: now.Add(-time.Second)}, now)
	}
	l.put("sb-fresh", auditOwnershipLease{ownedBySelf: true, expiresAt: now.Add(time.Minute)}, now)
	l.mu.Lock()
	entries := len(l.entries)
	_, fresh := l.entries["sb-fresh"]
	l.mu.Unlock()
	if entries > auditOwnershipLeaseMaxEntries {
		t.Fatalf("lease map holds %d entries, cap is %d", entries, auditOwnershipLeaseMaxEntries)
	}
	if !fresh {
		t.Fatal("the sweep dropped the entry it was making room for")
	}
}

// waitForBindingRead blocks until the fake control plane has actually been
// asked, so a test can act inside the in-flight window rather than guessing
// at it with a sleep.
func waitForBindingRead(t *testing.T, cl *bindingCluster) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cl.readCount() > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the placement read never started")
}

// Invalidation has to fence, not just delete. A placement read that started
// before the boundary finishes after it, and an unfenced refill reinstalls
// the answer it read — so a capability the local lifecycle just destroyed
// keeps being accepted for a further TTL, contradicting the "rejected on the
// next event" guarantee this file documents.
func TestEgressAuditBindingRejectsRefillFromReadStartedBeforeInvalidation(t *testing.T) {
	const sandboxID = "sb-refill"
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-old"}
	cl.present = true
	cl.block = make(chan struct{})
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	inFlight := make(chan error, 1)
	go func() { inFlight <- svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-old") }()

	// Wait until the placement read is actually in flight, then destroy the
	// sandbox locally: the placement is gone and the lease is invalidated
	// while the old answer is still on its way back.
	waitForBindingRead(t, cl)
	cl.mu.Lock()
	cl.present = false
	cl.mu.Unlock()
	svc.invalidateAuditOwnershipLease(sandboxID)
	close(cl.block)
	<-inFlight

	if err := svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-old"); err == nil {
		t.Fatal("a capability for a destroyed lifetime was accepted after the boundary; the in-flight read reinstalled its pre-boundary answer")
	}
}

// A caller that arrives after the boundary must not be answered from a flight
// that started before it, even though singleflight will happily share it.
func TestEgressAuditBindingSingleFlightDoesNotShareAcrossBoundary(t *testing.T) {
	const sandboxID = "sb-shared-flight"
	cl := newBindingCluster("node-a")
	cl.placement = cluster.Placement{SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-old"}
	cl.present = true
	cl.block = make(chan struct{})
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	first := make(chan error, 1)
	go func() { first <- svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-old") }()
	waitForBindingRead(t, cl)

	// The boundary lands, then a second caller joins the still-open flight.
	svc.invalidateAuditOwnershipLease(sandboxID)
	joined := make(chan error, 1)
	go func() { joined <- svc.validateEgressAuditBinding(context.Background(), sandboxID, "inc-old") }()
	time.Sleep(20 * time.Millisecond)
	close(cl.block)
	<-first

	if err := <-joined; err == nil {
		t.Fatal("a caller that arrived after the lifecycle boundary was accepted from a flight that started before it")
	}
}

// Only destruction paths invalidated the lease. A create is a lifecycle
// boundary too: anything that resolved the binding before the row existed
// leaves a negative lease, and that lease then rejects the new lifetime's own
// valid capability.
func TestEgressAuditBindingAcceptsLifetimePersistedAfterNegativeLease(t *testing.T) {
	st := openSealTestStore(t)
	svc := &Service{store: st}
	ctx := context.Background()

	if err := svc.validateEgressAuditBinding(ctx, "sb-reused", "inc-new"); err == nil {
		t.Fatal("a sandbox that does not exist yet must be rejected")
	}

	sb := &models.Sandbox{
		ID:                 "sb-reused",
		Image:              "wasm",
		Runtime:            models.RuntimeWasm,
		AuditIncarnationID: "inc-new",
		OwnerRef:           "tenant-a",
		Status:             models.SandboxStatusStarted,
	}
	if err := svc.persistSandboxCreate(ctx, sb); err != nil {
		t.Fatalf("persistSandboxCreate: %v", err)
	}

	if err := svc.validateEgressAuditBinding(ctx, "sb-reused", "inc-new"); err != nil {
		t.Fatalf("the durably persisted lifetime's own capability was rejected by a lease taken before it existed: %v", err)
	}
}

// Fences are the only lease entries no sandbox boundary will evict, so they
// get a retirement policy rather than accumulating one row per id.
func TestAuditOwnershipLeaseFencesArePruned(t *testing.T) {
	svc := &Service{}
	svc.invalidateAuditOwnershipLease("sb-fenced")
	l := svc.ownershipLeases()

	if pruned := svc.pruneAuditOwnershipLeaseFences(time.Now()); pruned != 0 {
		t.Fatalf("pruned %d fresh fences; an in-flight resolve could still need them", pruned)
	}
	l.mu.Lock()
	entry := l.entries["sb-fenced"]
	epoch := entry.epoch
	l.mu.Unlock()
	if epoch == 0 {
		t.Fatal("invalidation did not bump the lifecycle epoch, so nothing fences an in-flight resolve")
	}

	if pruned := svc.pruneAuditOwnershipLeaseFences(time.Now().Add(auditOwnershipLeaseFenceTTL + time.Minute)); pruned != 1 {
		t.Fatalf("pruned %d expired fences, want 1", pruned)
	}
	// A live lease must survive the sweep.
	l.put("sb-live", auditOwnershipLease{ownedBySelf: true, incarnationID: "inc", expiresAt: time.Now().Add(time.Minute)}, time.Now())
	if pruned := svc.pruneAuditOwnershipLeaseFences(time.Now().Add(time.Hour)); pruned != 0 {
		t.Fatalf("the fence sweep dropped %d live leases", pruned)
	}
}
