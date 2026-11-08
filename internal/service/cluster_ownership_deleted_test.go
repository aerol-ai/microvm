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
//
// authoritative, when set, is what an authoritative read returns instead of
// placements: a worker's PlacementOf reports "no placement" when its lookup
// fails, so the authoritative answer can differ. authErr fails that read.
// sole says whether this node is the only Raft server.
type deletedLifecycleCluster struct {
	*cluster.Noop
	placements    map[string]cluster.Placement
	deleted       map[string]string
	asserted      []cluster.LocalSandboxState
	authoritative map[string]cluster.Placement
	authErr       error
	sole          bool
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
	if c.authErr != nil {
		return nil, c.authErr
	}
	source := c.placements
	if c.authoritative != nil {
		source = c.authoritative
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := source[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *deletedLifecycleCluster) SoleRaftServer() bool { return c.sole }

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
	svc.cfg.AuditDeletedGrace = time.Hour
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

// TestReplayClusterOwnershipUnplacedRowOutcomes is the rule for a local row
// the cluster has no placement for, after the user's decision on C2:
// destroy it unless it is provably not a deleted sandbox. Provably live means
// this node is the only Raft server, or the row is younger than
// SB_AUDIT_DELETED_GRACE (a delete would still have its record). Every
// destroy re-checks that the cluster really has no placement, and nothing is
// destroyed when post-delete records are switched off (grace 0) or the row
// has no incarnation to match.
func TestReplayClusterOwnershipUnplacedRowOutcomes(t *testing.T) {
	const (
		placed    = "placed"
		destroyed = "destroyed"
		kept      = "kept"
	)
	old := time.Now().UTC().Add(-2 * time.Hour)
	young := time.Now().UTC()
	cases := []struct {
		name          string
		grace         time.Duration
		createdAt     time.Time
		incarnation   string
		deleted       bool
		sole          bool
		authoritative map[string]cluster.Placement
		authErr       error
		want          string
		wantRecord    string
		wantErr       bool
	}{
		{name: "post-delete record: destroyed", grace: time.Hour, createdAt: young, incarnation: "inc-row", deleted: true,
			want: destroyed, wantRecord: "SYSTEM cluster.deleted_while_away"},
		{name: "older than the grace, no record, not the sole server: destroyed as unproven", grace: time.Hour, createdAt: old, incarnation: "inc-row",
			want: destroyed, wantRecord: "SYSTEM cluster.unproven_while_away"},
		{name: "older than the grace on the sole Raft server: placed", grace: time.Hour, createdAt: old, incarnation: "inc-row", sole: true,
			want: placed},
		{name: "younger than the grace: placed", grace: time.Hour, createdAt: young, incarnation: "inc-row",
			want: placed},
		{name: "grace 0 keeps no record, so nothing is destroyed", grace: 0, createdAt: old, incarnation: "inc-row",
			want: kept},
		{name: "grace 0 on the sole Raft server: placed", grace: 0, createdAt: old, incarnation: "inc-row", sole: true,
			want: placed},
		{name: "the cluster still has a placement the local view missed: kept", grace: time.Hour, createdAt: old, incarnation: "inc-row",
			authoritative: map[string]cluster.Placement{"sb-row": {SandboxID: "sb-row", OwnerNodeID: "self", IncarnationID: "inc-row", State: cluster.PlacementStatePlaced}},
			want:          kept},
		{name: "the authoritative read fails: kept and reported", grace: time.Hour, createdAt: old, incarnation: "inc-row",
			authErr: errors.New("leader unreachable"), want: kept, wantErr: true},
		{name: "no incarnation to match: kept", grace: time.Hour, createdAt: old, incarnation: "",
			want: kept},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &recordingRuntime{}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.cfg.EnableCluster = true
			svc.cfg.AuditDeletedGrace = tc.grace
			deleted := map[string]string{}
			if tc.deleted {
				deleted["sb-row"] = tc.incarnation
			}
			c := newDeletedLifecycleCluster(deleted)
			c.sole, c.authoritative, c.authErr = tc.sole, tc.authoritative, tc.authErr
			svc.AttachCluster(c)
			sink := &memSecretAuditSink{}
			svc.secretAudit = sink
			svc.secretAuditOnce.Do(func() {})
			seedReplayRow(t, st, "sb-row", tc.incarnation, tc.createdAt)

			_, err := svc.ReplayClusterOwnership(ctx)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ReplayClusterOwnership error = %v, want error %v", err, tc.wantErr)
			}
			asserted := slices.Contains(c.assertedIDs(), "sb-row")
			_, getErr := st.Get(ctx, "sb-row")
			rowGone := errors.Is(getErr, store.ErrNotFound)
			runtimeGone := slices.Contains(rt.destroyIDs, "sb-row")
			got := kept
			switch {
			case asserted && !rowGone && !runtimeGone:
				got = placed
			case rowGone && runtimeGone && !asserted:
				got = destroyed
			case asserted || rowGone || runtimeGone:
				t.Fatalf("mixed outcome: asserted=%v rowGone=%v runtimeDestroyed=%v", asserted, rowGone, runtimeGone)
			}
			if got != tc.want {
				t.Fatalf("outcome = %s, want %s (asserted=%v rowGone=%v runtimeDestroyed=%v)", got, tc.want, asserted, rowGone, runtimeGone)
			}
			if tc.wantRecord == "" {
				return
			}
			found := false
			for _, ev := range sink.Events() {
				if ev.Ref == tc.wantRecord && ev.SandboxID == "sb-row" && ev.Caller.ID == "system:boot-restore" {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %q audit record by system:boot-restore: %+v", tc.wantRecord, sink.Events())
			}
		})
	}
}
