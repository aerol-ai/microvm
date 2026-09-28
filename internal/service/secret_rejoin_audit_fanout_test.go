package service

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type rejoinAuditCluster struct {
	*cluster.Noop
	mu              sync.Mutex
	placement       cluster.Placement
	authBatchCalls  int
	pointReadCalls  int
	authBatchGotIDs []string
}

func newRejoinAuditCluster(self string) *rejoinAuditCluster {
	return &rejoinAuditCluster{Noop: cluster.NewNoop(self, "http://"+self, "")}
}

func (c *rejoinAuditCluster) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pointReadCalls++
	if c.placement.SandboxID != id || id == "" {
		return cluster.Placement{}, false
	}
	return c.placement, true
}

func (c *rejoinAuditCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authBatchCalls++
	c.authBatchGotIDs = append(c.authBatchGotIDs, ids...)
	out := map[string]cluster.Placement{}
	for _, id := range ids {
		if id == c.placement.SandboxID && id != "" {
			out[id] = c.placement
		}
	}
	return out, nil
}

func (c *rejoinAuditCluster) counts() (auth, point int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authBatchCalls, c.pointReadCalls
}

func seedClusterSecretRow(t *testing.T, st *storepkg.Store, sandboxID string, recipients []string) {
	t.Helper()
	ref := secrets.FormatRef(sandboxID, "inc-"+sandboxID, secrets.RefVersion)
	if _, err := st.PutClusterSecret(context.Background(), storepkg.ClusterSecretRecord{
		Ref:            ref,
		SandboxID:      sandboxID,
		Version:        secrets.RefVersion,
		Recipients:     recipients,
		SealedPayload:  []byte("sealed"),
		SealGeneration: 1,
	}); err != nil {
		t.Fatalf("seed cluster secret %s: %v", sandboxID, err)
	}
}

// A rejoining member asks every other node to re-verify the secrets it owes
// that member. Recipient membership is already on the local row, so a node
// owing the rejoiner nothing must not ask the Raft leader anything: otherwise
// one member restart is a fleet-wide leader burst to repair nothing.
func TestReFanoutForNodesSkipsPlacementReadWhenNothingIsOwed(t *testing.T) {
	st := openSealTestStore(t)
	cl := newRejoinAuditCluster("node-a")
	svc := &Service{
		cfg:     config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store:   st,
		cluster: cl,
	}

	// 25 local secrets, none of them owed to the rejoining node.
	for i := 0; i < 25; i++ {
		seedClusterSecretRow(t, st, fmt.Sprintf("sb-%03d", i), []string{"node-a", "node-b"})
	}

	if err := svc.ReFanoutClusterSecretsForNodes(context.Background(), map[string]struct{}{"node-rejoin": {}}); err != nil {
		t.Fatalf("refanout: %v", err)
	}

	auth, _ := cl.counts()
	if auth != 0 {
		t.Fatalf("authoritative placement batches = %d for zero owed secrets; the filter must run before the read", auth)
	}
}

// The filter must not become a way to skip work that IS owed.
func TestReFanoutForNodesStillReadsPlacementsForOwedSecrets(t *testing.T) {
	st := openSealTestStore(t)
	const owned = "sb-owed"
	cl := newRejoinAuditCluster("node-a")
	cl.placement = cluster.Placement{
		SandboxID: owned, OwnerNodeID: "node-a",
		IncarnationID: "inc-" + owned, SecretSealGeneration: 1,
	}
	svc := &Service{
		cfg:     config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store:   st,
		cluster: cl,
	}

	seedClusterSecretRow(t, st, "sb-other", []string{"node-a", "node-b"})
	seedClusterSecretRow(t, st, owned, []string{"node-a", "node-rejoin"})

	_ = svc.ReFanoutClusterSecretsForNodes(context.Background(), map[string]struct{}{"node-rejoin": {}})

	auth, _ := cl.counts()
	if auth == 0 {
		t.Fatal("no placement read for a secret that IS owed to the rejoining node")
	}
	cl.mu.Lock()
	got := append([]string(nil), cl.authBatchGotIDs...)
	cl.mu.Unlock()
	for _, id := range got {
		if id != owned {
			t.Fatalf("placement batch asked for %q; only owed rows belong in the read (got %v)", id, got)
		}
	}
}

// Egress audit stamps every event with (incarnation, owner_ref). Both are
// immutable for a lifecycle, so resolving them must not be a control-plane
// read per event — that ran ahead of the sink's rate limiter, so the limiter
// could not protect the control plane.
func TestAuditIdentityResolvesOncePerLifecycle(t *testing.T) {
	const sandboxID = "sb-audit-cache"
	cl := newRejoinAuditCluster("node-a")
	cl.placement = cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a",
		IncarnationID: "inc-1", OwnerRef: "acct_1",
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	for i := 0; i < 500; i++ {
		inc, owner := svc.auditIdentityFor(sandboxID)
		if inc != "inc-1" || owner != "acct_1" {
			t.Fatalf("event %d stamped (%q,%q), want (inc-1,acct_1)", i, inc, owner)
		}
	}

	if _, point := cl.counts(); point != 1 {
		t.Fatalf("placement reads = %d for 500 events; want 1 (the incarnation is immutable for a lifecycle)", point)
	}
}

// The cache is keyed by sandbox ID, and deterministic IDs (e2b) get reused.
// A new lifetime must never be stamped with the previous one's incarnation —
// that is the capability-inheritance bug the uncached read existed to prevent.
func TestAuditIdentityEvictedWhenLifecycleRestarts(t *testing.T) {
	const sandboxID = "sb-determin"
	cl := newRejoinAuditCluster("node-a")
	cl.placement = cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a",
		IncarnationID: "inc-1", OwnerRef: "acct_1",
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	if inc, _ := svc.auditIdentityFor(sandboxID); inc != "inc-1" {
		t.Fatalf("first lifetime = %q, want inc-1", inc)
	}

	// Same ID, new lifetime.
	cl.mu.Lock()
	cl.placement.IncarnationID = "inc-2"
	cl.placement.OwnerRef = "acct_2"
	cl.mu.Unlock()

	// Stale until something declares the boundary.
	if inc, _ := svc.auditIdentityFor(sandboxID); inc != "inc-1" {
		t.Fatalf("cache should still hold the old lifetime before eviction, got %q", inc)
	}

	svc.invalidateAuditIdentity(sandboxID)

	inc, owner := svc.auditIdentityFor(sandboxID)
	if inc != "inc-2" || owner != "acct_2" {
		t.Fatalf("after eviction = (%q,%q), want (inc-2,acct_2) — a reused sandbox ID inherited the previous lifetime", inc, owner)
	}
}

// An unresolved identity must not be memoized: caching "" would pin a sandbox
// whose placement had not landed yet into a blank stamp for the rest of its
// life.
func TestAuditIdentityDoesNotCacheUnresolved(t *testing.T) {
	cl := newRejoinAuditCluster("node-a") // no placement configured
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}

	if inc, _ := svc.auditIdentityFor("sb-missing"); inc != "" {
		t.Fatalf("unresolved identity = %q, want empty", inc)
	}
	cl.mu.Lock()
	cl.placement = cluster.Placement{
		SandboxID: "sb-missing", OwnerNodeID: "node-a",
		IncarnationID: "inc-late", OwnerRef: "acct_late",
	}
	cl.mu.Unlock()

	inc, owner := svc.auditIdentityFor("sb-missing")
	if inc != "inc-late" || owner != "acct_late" {
		t.Fatalf("late-landing placement = (%q,%q), want (inc-late,acct_late)", inc, owner)
	}
}
