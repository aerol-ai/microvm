package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	retireRef = "aocr.test/cluster/c/snapshots/app:latest"
	retireOld = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	retireNew = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func dueRetirements(t *testing.T, st *Store) []SnapshotRegistryRetirement {
	t.Helper()
	due, err := st.ListDueSnapshotRegistryRetirements(context.Background(), time.Now().UTC().Add(time.Hour), 100)
	if err != nil {
		t.Fatalf("ListDueSnapshotRegistryRetirements: %v", err)
	}
	return due
}

// The obligation is written in the delete's own transaction, from the row
// as it is at that moment, and only for the copy the caller's pusher made.
func TestDeleteSnapshotRetiringRegistryCopy(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		row       models.SandboxSnapshot
		pushedRef string
		want      bool
	}{
		{name: "pushed copy", row: models.SandboxSnapshot{Image: "aerolvm-snapshot/x:latest", ImageRegistryRef: retireRef, ImageDigest: retireOld}, pushedRef: retireRef, want: true},
		{name: "no registry configured", row: models.SandboxSnapshot{Image: "aerolvm-snapshot/x:latest", ImageRegistryRef: retireRef, ImageDigest: retireOld}},
		{name: "a ref the pusher would not have written", row: models.SandboxSnapshot{Image: "aerolvm-snapshot/x:latest", ImageRegistryRef: "aocr.test/elsewhere:latest", ImageDigest: retireOld}, pushedRef: retireRef},
		{name: "registered with the registry image itself", row: models.SandboxSnapshot{Image: retireRef, ImageRegistryRef: retireRef, ImageDigest: retireOld}, pushedRef: retireRef},
		{name: "no digest", row: models.SandboxSnapshot{Image: "aerolvm-snapshot/x:latest", ImageRegistryRef: retireRef}, pushedRef: retireRef},
		{name: "never pushed", row: models.SandboxSnapshot{Image: "aerolvm-snapshot/x:latest"}, pushedRef: retireRef},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			row := tc.row
			row.Name, row.OwnerRef, row.SourceSandboxID, row.CreatedAt = "app", "acme", "sb", time.Now().UTC()
			if err := st.CreateSnapshot(ctx, &row); err != nil {
				t.Fatal(err)
			}
			if err := st.DeleteSnapshotRetiringRegistryCopy(ctx, "acme", "app", tc.pushedRef); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if _, err := st.GetSnapshot(ctx, "acme", "app"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("row still there: %v", err)
			}
			due := dueRetirements(t, st)
			if got := len(due) == 1; got != tc.want {
				t.Fatalf("obligation recorded = %v (%+v), want %v", got, due, tc.want)
			}
			if tc.want && (due[0].RegistryRef != retireRef || due[0].Digest != retireOld || due[0].OwnerRef != "acme" || due[0].Name != "app") {
				t.Fatalf("obligation = %+v", due[0])
			}
		})
	}

	st := newTestStore(t)
	if err := st.DeleteSnapshotRetiringRegistryCopy(ctx, "acme", "missing", retireRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row = %v", err)
	}
	if err := st.DeleteSnapshot(ctx, "acme", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row through DeleteSnapshot = %v", err)
	}
}

// A failed obligation write rolls the row delete back: the two go together
// or not at all.
func TestDeleteSnapshotRetirementIsAtomicWithTheDelete(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "app", Image: "aerolvm-snapshot/x:latest", SourceSandboxID: "sb", CreatedAt: time.Now().UTC(),
		ImageRegistryRef: retireRef, ImageDigest: retireOld,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER fail_retire BEFORE INSERT ON snapshot_registry_retirements BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSnapshotRetiringRegistryCopy(ctx, "", "app", retireRef); err == nil {
		t.Fatal("delete succeeded without its obligation")
	}
	if _, err := st.GetSnapshot(ctx, "", "app"); err != nil {
		t.Fatalf("the row went without its obligation: %v", err)
	}
}

func TestSnapshotRegistryRetirementLedger(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Idempotent, and a copy without a digest is never scheduled.
	ob := SnapshotRegistryRetirement{RegistryRef: retireRef, Digest: retireOld, OwnerRef: "acme", Name: "app"}
	for range 2 {
		if err := st.ScheduleSnapshotRegistryRetirement(ctx, ob); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ScheduleSnapshotRegistryRetirement(ctx, SnapshotRegistryRetirement{RegistryRef: retireRef}); err != nil {
		t.Fatal(err)
	}
	if err := st.ScheduleSnapshotRegistryRetirement(ctx, SnapshotRegistryRetirement{RegistryRef: retireRef, Digest: retireNew, Name: "app"}); err != nil {
		t.Fatal(err)
	}
	due := dueRetirements(t, st)
	if len(due) != 2 || due[0].Digest != retireOld {
		t.Fatalf("due = %+v", due)
	}
	if none, _ := st.ListDueSnapshotRegistryRetirements(ctx, time.Now().UTC().Add(-time.Hour), 10); len(none) != 0 {
		t.Fatalf("not-yet-due obligations listed: %+v", none)
	}
	if one, _ := st.ListDueSnapshotRegistryRetirements(ctx, time.Now().UTC().Add(time.Hour), 1); len(one) != 1 {
		t.Fatalf("limit ignored: %d", len(one))
	}
	if _, err := st.ListDueSnapshotRegistryRetirements(ctx, time.Now(), 0); err == nil {
		t.Fatal("a zero limit was accepted")
	}

	// A deferral moves the obligation to the back; a failure also counts.
	if err := st.DeferSnapshotRegistryRetirement(ctx, retireRef, retireOld, ""); err != nil {
		t.Fatal(err)
	}
	due = dueRetirements(t, st)
	if due[len(due)-1].Digest != retireOld || due[len(due)-1].Attempts != 0 {
		t.Fatalf("deferred obligation not at the back: %+v", due)
	}
	if err := st.DeferSnapshotRegistryRetirement(ctx, retireRef, retireOld, "registry 503"); err != nil {
		t.Fatal(err)
	}
	for _, r := range dueRetirements(t, st) {
		if r.Digest == retireOld && (r.Attempts != 1 || r.LastError != "registry 503") {
			t.Fatalf("failed obligation = %+v", r)
		}
	}

	if err := st.DeleteSnapshotRegistryRetirement(ctx, retireRef, retireOld); err != nil {
		t.Fatal(err)
	}
	if due := dueRetirements(t, st); len(due) != 1 || due[0].Digest != retireNew {
		t.Fatalf("after drop = %+v", due)
	}
}

func TestSnapshotRegistryCopyInUse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	check := func(wantInUse, wantPending bool) {
		t.Helper()
		inUse, pending, err := st.SnapshotRegistryCopyInUse(ctx, retireRef, retireOld, "acme", "app")
		if err != nil || inUse != wantInUse || pending != wantPending {
			t.Fatalf("in use = %v pending = %v (%v), want %v %v", inUse, pending, err, wantInUse, wantPending)
		}
	}
	check(false, false)
	// The same name re-created, push to come.
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "app", OwnerRef: "acme", Image: "aerolvm-snapshot/x:latest", SourceSandboxID: "sb",
		CreatedAt: time.Now().UTC(), PushState: models.SnapshotPushStatePending,
	}); err != nil {
		t.Fatal(err)
	}
	check(false, true)
	// It pushed a new digest under the same tag: the old one is free.
	_, stamp, _, _ := st.ClaimSnapshotPush(ctx, "acme", "app")
	if _, err := st.CompleteSnapshotPush(ctx, "acme", "app", stamp, models.ImageDistributionAOCR, retireRef, retireNew); err != nil {
		t.Fatal(err)
	}
	check(false, false)
	// Some row names the old manifest itself.
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "alias", OwnerRef: "acme", Image: retireRef, SourceSandboxID: "", CreatedAt: time.Now().UTC(),
		ImageRegistryRef: retireRef, ImageDigest: retireOld,
	}); err != nil {
		t.Fatal(err)
	}
	check(true, false)

	_ = st.Close()
	if _, _, err := st.SnapshotRegistryCopyInUse(ctx, retireRef, retireOld, "acme", "app"); err == nil {
		t.Fatal("closed store")
	}
}

func TestSnapshotRetirementClosedStore(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	_ = st.Close()
	if err := st.DeleteSnapshotRetiringRegistryCopy(ctx, "", "x", retireRef); err == nil {
		t.Error("delete on a closed store")
	}
	if err := st.ScheduleSnapshotRegistryRetirement(ctx, SnapshotRegistryRetirement{RegistryRef: retireRef, Digest: retireOld}); err == nil {
		t.Error("schedule on a closed store")
	}
	if _, err := st.ListDueSnapshotRegistryRetirements(ctx, time.Now(), 1); err == nil {
		t.Error("list on a closed store")
	}
	if err := st.DeferSnapshotRegistryRetirement(ctx, retireRef, retireOld, ""); err == nil {
		t.Error("defer on a closed store")
	}
	if err := st.DeleteSnapshotRegistryRetirement(ctx, retireRef, retireOld); err == nil {
		t.Error("drop on a closed store")
	}
}

func TestSnapshotRetirementStoreFaults(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "app", Image: "i", SourceSandboxID: "sb", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER keep_snap BEFORE DELETE ON sandbox_snapshots BEGIN SELECT RAISE(ABORT, 'locked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSnapshot(ctx, "", "app"); err == nil {
		t.Fatal("a refused delete succeeded")
	}

	if err := st.ScheduleSnapshotRegistryRetirement(ctx, SnapshotRegistryRetirement{RegistryRef: retireRef, Digest: retireOld}); err != nil {
		t.Fatal(err)
	}
	// A row that is due but does not scan.
	if _, err := st.db.Exec(`UPDATE snapshot_registry_retirements SET attempts = 'many'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListDueSnapshotRegistryRetirements(ctx, time.Now(), 10); err == nil {
		t.Fatal("a corrupt row scanned")
	}
}

// The upgrade repair reports what it cannot do.
func TestEnsureSnapshotPushQueueShapeFaults(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1) // one connection, one :memory: database
	if err := ensureSnapshotPushQueueShape(db); err == nil {
		t.Fatal("no sandbox_snapshots table, yet no error")
	}
	// A table missing a column an index needs.
	if _, err := db.Exec(`CREATE TABLE sandbox_snapshots (name TEXT, owner_ref TEXT, created_at DATETIME, push_state TEXT, source_sandbox_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := ensureSnapshotPushQueueShape(db); err == nil {
		t.Fatal("an index on a missing column was reported built")
	}
}
