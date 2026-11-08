package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// deletedLifecycleCluster stands in for the cluster a node returns to after
// an outage. placements is the authoritative placement map; deleted holds the
// post-delete records (sandbox id -> incarnation). Its AssertOwnership writes
// a placement for every row it is handed, as Cluster.AssertOwnership did for a
// missing row before C2, so a row that reaches it counts as re-placed.
type deletedLifecycleCluster struct {
	*cluster.Noop
	placements map[string]cluster.Placement
	deleted    map[string]string
	asserted   []cluster.LocalSandboxState
}

func newDeletedLifecycleCluster(deleted map[string]string) *deletedLifecycleCluster {
	return &deletedLifecycleCluster{
		Noop:       cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{},
		deleted:    deleted,
	}
}

func (c *deletedLifecycleCluster) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.placements[id]
	return p, ok
}

func (c *deletedLifecycleCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *deletedLifecycleCluster) AuditACLForSandbox(_ context.Context, id, incarnationID string) (cluster.AuditACL, bool, error) {
	if inc, ok := c.deleted[id]; ok && incarnationID != "" && inc == incarnationID {
		return cluster.AuditACL{SandboxID: id, IncarnationID: inc}, true, nil
	}
	return cluster.AuditACL{}, false, nil
}

func (c *deletedLifecycleCluster) AssertOwnership(_ context.Context, local []cluster.LocalSandboxState) error {
	for _, st := range local {
		c.asserted = append(c.asserted, st)
		c.placements[st.ID] = cluster.Placement{
			SandboxID: st.ID, OwnerNodeID: c.SelfNodeID(), IncarnationID: st.Secrets.IncarnationID,
			State: cluster.PlacementStatePlaced,
		}
	}
	return nil
}

// AuditCallerWritesAllowed lets the replay's system record be written.
func (c *deletedLifecycleCluster) AuditCallerWritesAllowed() bool { return true }

func (c *deletedLifecycleCluster) assertedIDs() []string {
	out := make([]string, 0, len(c.asserted))
	for _, st := range c.asserted {
		out = append(out, st.ID)
	}
	return out
}

func seedReplayRow(t *testing.T, st *store.Store, id, incarnationID string, createdAt time.Time) {
	t.Helper()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: id, Image: "alpine", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-" + id, AuditIncarnationID: incarnationID,
		CreatedAt: createdAt, UpdatedAt: createdAt, LastActiveAt: createdAt,
	}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// TestReplayClusterOwnershipDestroysDeletedLifecycle is C2's service half: a
// local row whose lifecycle the cluster deleted while this node was away is
// destroyed by the ownership replay, not handed back to the cluster to be
// placed again. A row with no placement and no delete record is still
// replayed as before.
func TestReplayClusterOwnershipDestroysDeletedLifecycle(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	c := newDeletedLifecycleCluster(map[string]string{"sb-deleted": "inc-deleted"})
	svc.AttachCluster(c)

	sink := &memSecretAuditSink{}
	svc.secretAudit = sink
	svc.secretAuditOnce.Do(func() {})

	now := time.Now().UTC()
	seedReplayRow(t, st, "sb-deleted", "inc-deleted", now)
	seedReplayRow(t, st, "sb-unplaced", "inc-unplaced", now)

	if _, err := svc.ReplayClusterOwnership(ctx); err != nil {
		t.Fatalf("ReplayClusterOwnership: %v", err)
	}
	if ids := c.assertedIDs(); slices.Contains(ids, "sb-deleted") {
		t.Fatalf("replay handed a deleted lifecycle back to the cluster: asserted %v", ids)
	}
	if _, ok := c.placements["sb-deleted"]; ok {
		t.Fatal("deleted lifecycle was placed again")
	}
	if _, err := st.Get(ctx, "sb-deleted"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("local copy of the deleted lifecycle was kept: err=%v", err)
	}
	if !slices.Contains(rt.destroyIDs, "sb-deleted") {
		t.Fatalf("runtime of the deleted lifecycle was not destroyed: destroys=%v", rt.destroyIDs)
	}

	if ids := c.assertedIDs(); !slices.Contains(ids, "sb-unplaced") {
		t.Fatalf("a row with no delete record must still be replayed: asserted %v", ids)
	}
	if _, err := st.Get(ctx, "sb-unplaced"); err != nil {
		t.Fatalf("a row with no delete record was removed: %v", err)
	}
	if slices.Contains(rt.destroyIDs, "sb-unplaced") {
		t.Fatalf("a row with no delete record was destroyed: destroys=%v", rt.destroyIDs)
	}

	// "Who deleted this sandbox?" has an answer in its audit log.
	recorded := false
	for _, ev := range sink.Events() {
		if ev.Ref == "SYSTEM cluster.deleted_while_away" && ev.SandboxID == "sb-deleted" {
			recorded = ev.Caller.ID == "system:boot-restore"
		}
	}
	if !recorded {
		t.Fatalf("the destroy wrote no system:boot-restore audit record: %+v", sink.Events())
	}
}
