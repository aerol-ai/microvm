package service

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// delayedPlacementCluster lets a test hold one PlacementOf open so a lookup
// started before a lifecycle boundary can be released after it.
type delayedPlacementCluster struct {
	*cluster.Noop
	mu        sync.Mutex
	placement cluster.Placement
	reads     int

	gate    chan struct{} // closed by the cluster once the delayed read entered
	release chan struct{} // closed by the test to let it return
	delay   bool
}

func newDelayedPlacementCluster(self string) *delayedPlacementCluster {
	return &delayedPlacementCluster{
		Noop:    cluster.NewNoop(self, "http://"+self, ""),
		gate:    make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (c *delayedPlacementCluster) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	c.reads++
	p := c.placement
	delay := c.delay
	c.delay = false
	c.mu.Unlock()
	if delay {
		close(c.gate)
		<-c.release
	}
	if p.SandboxID != id {
		return cluster.Placement{}, false
	}
	return p, true
}

func (c *delayedPlacementCluster) setPlacement(p cluster.Placement) {
	c.mu.Lock()
	c.placement = p
	c.mu.Unlock()
}

// A lookup that started before a lifecycle boundary must not reinstall the old
// incarnation and tenant owner after the new lifetime has been cached.
// Invalidation used to only delete the map entry, so the losing resolve simply
// wrote its stale answer back — permanently, because both fields are treated
// as immutable for the lifetime.
func TestAuditIdentityStaleResolveCannotOverwriteNewLifetime(t *testing.T) {
	const sandboxID = "sb-reused-id"
	cl := newDelayedPlacementCluster("node-a")
	cl.setPlacement(cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a",
		IncarnationID: "old", OwnerRef: "acct-old",
	})
	cl.mu.Lock()
	cl.delay = true
	cl.mu.Unlock()

	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	stale := make(chan struct{})
	go func() {
		defer close(stale)
		svc.auditIdentityFor(sandboxID) // resolves "old", blocked inside PlacementOf
	}()
	<-cl.gate

	// The old lifetime ends and a new one under the same deterministic id is
	// cached while that resolve is still in flight.
	svc.invalidateAuditIdentity(sandboxID)
	cl.setPlacement(cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a",
		IncarnationID: "new", OwnerRef: "acct-new",
	})
	if inc, owner := svc.auditIdentityFor(sandboxID); inc != "new" || owner != "acct-new" {
		t.Fatalf("new lifetime cached as (%q,%q), want (new,acct-new)", inc, owner)
	}

	close(cl.release)
	<-stale

	inc, owner := svc.auditIdentityFor(sandboxID)
	if inc != "new" || owner != "acct-new" {
		t.Fatalf("after the delayed resolve landed, reads returned (%q,%q); a pre-boundary lookup restored a dead lifetime's identity", inc, owner)
	}
}

// Fences must not accumulate: they exist only to outlive in-flight resolves.
func TestAuditIdentityFencesArePruned(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	svc.invalidateAuditIdentity("sb-gone")
	svc.auditIncarnationMu.Lock()
	svc.auditIdentityCache["sb-live"] = auditIdentity{incarnationID: "inc", complete: true, epoch: 3}
	svc.auditIncarnationMu.Unlock()

	if pruned := svc.pruneAuditIdentityFences(time.Now()); pruned != 0 {
		t.Fatalf("pruned %d fresh fences, want 0", pruned)
	}
	if pruned := svc.pruneAuditIdentityFences(time.Now().Add(auditIdentityFenceTTL + time.Second)); pruned != 1 {
		t.Fatalf("pruned %d expired fences, want 1", pruned)
	}
	svc.auditIncarnationMu.RLock()
	defer svc.auditIncarnationMu.RUnlock()
	if _, ok := svc.auditIdentityCache["sb-gone"]; ok {
		t.Fatal("expired fence retained")
	}
	if entry, ok := svc.auditIdentityCache["sb-live"]; !ok || entry.incarnationID != "inc" {
		t.Fatal("prune evicted a live identity; only pure fences have a TTL")
	}
}

// Standalone WASM prepares an incarnation BEFORE the sandbox row exists, so
// its capability issuer resolves (incarnation, "") — an identity with no
// tenant owner yet. Caching that as complete left every later egress and
// credential-open event for the lifetime with blank attribution, because the
// WASM create supplies AuditIncarnationID itself and persistSandboxCreate
// therefore never re-declared the boundary.
func TestStandaloneWasmAuditOwnerCompletesAfterPersist(t *testing.T) {
	const sandboxID = "sb-wasm-standalone"
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{cfg: config.Config{DBPath: dbPath}, store: st}

	ctx := context.Background()
	incarnationID, err := svc.prepareAuditIncarnation(ctx, sandboxID, "toolbox-token")
	if err != nil {
		t.Fatalf("prepareAuditIncarnation: %v", err)
	}
	if incarnationID == "" {
		t.Fatal("prepareAuditIncarnation returned an empty incarnation")
	}

	// The capability issuer resolves the pending incarnation while no row
	// exists. This must not be memoized as a finished identity.
	if inc, owner := svc.auditIdentityFor(sandboxID); inc != incarnationID || owner != "" {
		t.Fatalf("pre-persist identity = (%q,%q), want (%q,\"\")", inc, owner, incarnationID)
	}
	svc.auditIncarnationMu.RLock()
	cached := svc.auditIdentityCache[sandboxID]
	svc.auditIncarnationMu.RUnlock()
	if cached.complete {
		t.Fatalf("provisional pre-persist identity cached as complete (%+v); it can never learn the tenant owner", cached)
	}

	sandbox := &models.Sandbox{
		ID:                 sandboxID,
		Image:              "wasm",
		Status:             models.SandboxStatusStarted,
		AuditIncarnationID: incarnationID,
		OwnerRef:           "acct-real",
	}
	if err := svc.persistSandboxCreate(ctx, sandbox); err != nil {
		t.Fatalf("persistSandboxCreate: %v", err)
	}

	inc, owner := svc.auditIdentityFor(sandboxID)
	if inc != incarnationID {
		t.Fatalf("post-persist incarnation = %q, want %q", inc, incarnationID)
	}
	if owner != "acct-real" {
		t.Fatalf("post-persist audit owner = %q, want acct-real; the lifetime's evidence would carry blank tenant attribution", owner)
	}
}
