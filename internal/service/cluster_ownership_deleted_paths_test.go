package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
)

// lookupCountingCluster records post-delete record lookups and can fail them
// or report a replica that has not caught up after a restart.
type lookupCountingCluster struct {
	*deletedLifecycleCluster
	lookupErr   error
	lookups     []string
	notCaughtUp bool
}

func (c *lookupCountingCluster) AuditACLForSandbox(ctx context.Context, id, incarnationID string) (cluster.AuditACL, bool, error) {
	c.lookups = append(c.lookups, id+"/"+incarnationID)
	if c.lookupErr != nil {
		return cluster.AuditACL{}, false, c.lookupErr
	}
	return c.deletedLifecycleCluster.AuditACLForSandbox(ctx, id, incarnationID)
}

func (c *lookupCountingCluster) PlacementViewCaughtUp() bool { return !c.notCaughtUp }

// TestReplayClusterOwnershipUnplacedRowWithoutProof covers the replay steps
// that must neither place nor destroy a row with no placement: a failed
// record lookup and a replica that has not caught up. Both are reported so
// the boot replay retries. A row with a placement is replayed regardless, and
// a row with no incarnation is never looked up by id alone.
func TestReplayClusterOwnershipUnplacedRowWithoutProof(t *testing.T) {
	cases := []struct {
		name        string
		lookupErr   error
		notCaughtUp bool
		wantErr     error
		wantLookups int
	}{
		{name: "record lookup fails", lookupErr: errors.New("control plane unreachable"), wantLookups: 1},
		{name: "replica still catching up", notCaughtUp: true, wantErr: cluster.ErrNotCaughtUp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &recordingRuntime{}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.cfg.EnableCluster = true
			// An old row and a live grace: without the lookup, this row
			// would be destroyed as unproven.
			svc.cfg.AuditDeletedGrace = time.Hour
			c := &lookupCountingCluster{
				deletedLifecycleCluster: newDeletedLifecycleCluster(map[string]string{"sb-unplaced": "inc-unplaced"}),
				lookupErr:               tc.lookupErr,
				notCaughtUp:             tc.notCaughtUp,
			}
			c.placements["sb-reserved"] = cluster.Placement{
				SandboxID: "sb-reserved", OwnerNodeID: "self", IncarnationID: "inc-reserved", State: cluster.PlacementStateReserved,
			}
			svc.AttachCluster(c)
			now := time.Now().UTC()
			seedReplayRow(t, st, "sb-unplaced", "inc-unplaced", now.Add(-2*time.Hour))
			seedReplayRow(t, st, "sb-reserved", "inc-reserved", now)

			_, err := svc.ReplayClusterOwnership(ctx)
			if err == nil {
				t.Fatal("a row the replay could not decide must be reported, so the boot replay retries")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReplayClusterOwnership = %v, want %v", err, tc.wantErr)
			}
			if tc.lookupErr != nil && !errors.Is(err, tc.lookupErr) {
				t.Fatalf("ReplayClusterOwnership = %v, want the lookup error", err)
			}
			if len(c.lookups) != tc.wantLookups {
				t.Fatalf("record lookups = %v, want %d", c.lookups, tc.wantLookups)
			}
			ids := c.assertedIDs()
			if slices.Contains(ids, "sb-unplaced") {
				t.Fatalf("an undecided row was handed to the cluster: asserted %v", ids)
			}
			if !slices.Contains(ids, "sb-reserved") {
				t.Fatalf("a row with a placement must still be replayed: asserted %v", ids)
			}
			if len(rt.destroyIDs) != 0 {
				t.Fatalf("an undecided row was destroyed: %v", rt.destroyIDs)
			}
			if _, err := st.Get(ctx, "sb-unplaced"); err != nil {
				t.Fatalf("an undecided row was removed: %v", err)
			}
		})
	}
}

func TestReplayClusterOwnershipNeverLooksUpWithoutIncarnation(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	svc.cfg.AuditDeletedGrace = time.Hour
	c := &lookupCountingCluster{deletedLifecycleCluster: newDeletedLifecycleCluster(nil)}
	svc.AttachCluster(c)
	seedReplayRow(t, st, "sb-no-incarnation", "", time.Now().UTC())

	if _, err := svc.ReplayClusterOwnership(ctx); err != nil {
		t.Fatalf("ReplayClusterOwnership: %v", err)
	}
	if len(c.lookups) != 0 {
		t.Fatalf("looked up a record by id alone, which could match another lifetime: %v", c.lookups)
	}
	if !slices.Contains(c.assertedIDs(), "sb-no-incarnation") {
		t.Fatalf("row with no incarnation must go on to the cluster's rule: asserted %v", c.assertedIDs())
	}
}

// TestDestroyUnplacedLocalSandboxRechecksRow: the destroy reads the row
// again under the lifecycle lock and leaves it alone when it is gone or is
// another lifetime by then; a runtime failure keeps the row for the retry.
func TestDestroyUnplacedLocalSandboxRechecksRow(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	svc.AttachCluster(newDeletedLifecycleCluster(nil))
	seedReplayRow(t, st, "sb-reused", "inc-new", time.Now().UTC())

	if err := svc.destroyUnplacedLocalSandbox(ctx, "sb-missing", "inc-missing", unplacedDestroyedDeleted); err != nil {
		t.Fatalf("missing row: %v", err)
	}
	if err := svc.destroyUnplacedLocalSandbox(ctx, "sb-reused", "inc-old", unplacedDestroyedDeleted); err != nil {
		t.Fatalf("reused row: %v", err)
	}
	if _, err := st.Get(ctx, "sb-reused"); err != nil {
		t.Fatalf("a newer lifetime of the same id was destroyed: %v", err)
	}
	if len(rt.destroyIDs) != 0 {
		t.Fatalf("runtime destroyed for a row that changed: %v", rt.destroyIDs)
	}

	rt.destroyErr = errors.New("runtime busy")
	if err := svc.destroyUnplacedLocalSandbox(ctx, "sb-reused", "inc-new", unplacedDestroyedUnproven); !errors.Is(err, rt.destroyErr) {
		t.Fatalf("destroy = %v, want the runtime error", err)
	}
	if _, err := st.Get(ctx, "sb-reused"); err != nil {
		t.Fatalf("a failed destroy must keep the row as the retry anchor: %v", err)
	}
	rt.destroyErr = nil
	if err := svc.destroyUnplacedLocalSandbox(ctx, "sb-reused", "inc-new", unplacedDestroyedUnproven); err != nil {
		t.Fatalf("retried destroy: %v", err)
	}
	if _, err := st.Get(ctx, "sb-reused"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retried destroy left the row: %v", err)
	}
}

// TestReplayClusterOwnershipDestroyFailureIsReported: when the destroy of a
// deleted lifecycle fails, the replay reports it (the boot replay retries)
// and still does not hand the row to the cluster.
func TestReplayClusterOwnershipDestroyFailureIsReported(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{destroyErr: errors.New("runtime busy")}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	c := newDeletedLifecycleCluster(map[string]string{"sb-deleted": "inc-deleted"})
	svc.AttachCluster(c)
	seedReplayRow(t, st, "sb-deleted", "inc-deleted", time.Now().UTC())

	if _, err := svc.ReplayClusterOwnership(ctx); !errors.Is(err, rt.destroyErr) {
		t.Fatalf("ReplayClusterOwnership = %v, want the destroy error", err)
	}
	if slices.Contains(c.assertedIDs(), "sb-deleted") {
		t.Fatalf("a deleted lifecycle was handed to the cluster after a failed destroy: %v", c.assertedIDs())
	}
}

// TestUnplacedRowPlaceable is the proof that lets a row with no placement and
// no post-delete record be placed instead of destroyed.
func TestUnplacedRowPlaceable(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		createdAt  time.Time
		grace      time.Duration
		soleServer bool
		want       bool
	}{
		{"sole server places an old row (a single node turned into a cluster)", now.Add(-48 * time.Hour), time.Hour, true, true},
		{"sole server places even with grace 0", now.Add(-48 * time.Hour), 0, true, true},
		{"young row: a delete would still have its record", now.Add(-10 * time.Minute), time.Hour, false, true},
		{"row just inside grace less clock skew", now.Add(-58*time.Minute + time.Second), time.Hour, false, true},
		{"row at grace less clock skew: no longer provable", now.Add(-59 * time.Minute), time.Hour, false, false},
		{"old row: its record may have expired", now.Add(-2 * time.Hour), time.Hour, false, false},
		{"grace 0 keeps no record, so nothing is provable", now.Add(-time.Second), 0, false, false},
		{"grace shorter than the clock skew allowance", now.Add(-time.Second), 30 * time.Second, false, false},
		{"unknown creation time counts as old", time.Time{}, time.Hour, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unplacedRowPlaceable(tc.createdAt, now, tc.grace, tc.soleServer); got != tc.want {
				t.Fatalf("unplacedRowPlaceable(age=%s, grace=%s, sole=%v) = %v, want %v",
					now.Sub(tc.createdAt), tc.grace, tc.soleServer, got, tc.want)
			}
		})
	}
}

// TestDestroyUnplacedLocalSandboxNeedsCluster: without a placement client the
// destroy cannot confirm there is no placement, so it refuses.
func TestDestroyUnplacedLocalSandboxNeedsCluster(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	if err := svc.destroyUnplacedLocalSandbox(context.Background(), "sb-x", "inc-x", unplacedDestroyedUnproven); !errors.Is(err, ErrClusterFinalizationUnavailable) {
		t.Fatalf("destroy without a cluster = %v, want ErrClusterFinalizationUnavailable", err)
	}
}
