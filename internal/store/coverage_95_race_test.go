package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	_ "github.com/mattn/go-sqlite3"
)

func TestGetOrCreateVolumeUniqueConstraintRecovery(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Plant the winner on the same DEFERRED tx so INSERT hits UNIQUE without
	// SQLITE_BUSY_SNAPSHOT from a cross-connection writer.
	afterVolumeMissSelect = func(tx *sql.Tx) {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO volumes (id, tenant, name, backend, source, created_at)
			VALUES ('vol-winner', 't-race', 'shared', 's3', 'src', CURRENT_TIMESTAMP)`)
		if err != nil {
			t.Errorf("plant winner: %v", err)
		}
	}
	t.Cleanup(func() { afterVolumeMissSelect = nil })

	vol, created, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "vol-loser", Tenant: "t-race", Name: "shared", Backend: "s3", Source: "src",
	}, 0)
	if err != nil {
		t.Fatalf("GetOrCreateVolume: %v", err)
	}
	if created || vol == nil || vol.ID != "vol-winner" {
		t.Fatalf("recovery = %+v created=%v, want vol-winner", vol, created)
	}
}

func TestTransferFirecrackerTapSlotN0Recovery(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/tap-race.db"
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	db2, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db2.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db2.Close() })

	now := time.Now().UTC()
	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AllocateFirecrackerTapSlot(ctx, "from", now); err != nil {
		t.Fatal(err)
	}

	afterTransferTapReads = func() {
		_, err := db2.ExecContext(ctx, `
			UPDATE firecracker_tap_pool SET sandbox_id = 'to', allocated_at = ?
			WHERE sandbox_id = 'from'`, now)
		if err != nil {
			t.Errorf("concurrent transfer: %v", err)
		}
	}
	t.Cleanup(func() { afterTransferTapReads = nil })

	slot, err := st.TransferFirecrackerTapSlot(ctx, "from", "to", now)
	if err != nil {
		t.Fatalf("TransferFirecrackerTapSlot: %v", err)
	}
	if slot == nil || slot.SandboxID != "to" {
		t.Fatalf("slot = %+v, want to", slot)
	}
}

func TestTransferFirecrackerTapSlotSourceNilReread(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/tap-nil.db"
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	db2, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	now := time.Now().UTC()
	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
	}, now); err != nil {
		t.Fatal(err)
	}

	// Both initial reads miss; plant toID before the source-nil re-read.
	afterTransferSourceNil = func() {
		_, err := db2.ExecContext(ctx, `
			UPDATE firecracker_tap_pool SET sandbox_id = 'to', allocated_at = ?`, now)
		if err != nil {
			t.Errorf("plant toID: %v", err)
		}
	}
	t.Cleanup(func() { afterTransferSourceNil = nil })
	slot, err := st.TransferFirecrackerTapSlot(ctx, "from-missing", "to", now)
	if err != nil || slot == nil || slot.SandboxID != "to" {
		t.Fatalf("source-nil re-read = %+v err=%v", slot, err)
	}

	// n==0 and toID still empty → ErrNotFound.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE firecracker_tap_pool SET sandbox_id = 'ghost', allocated_at = ?`, now); err != nil {
		t.Fatal(err)
	}
	afterTransferTapReads = func() {
		_, _ = db2.ExecContext(ctx, `
			UPDATE firecracker_tap_pool SET sandbox_id = NULL, allocated_at = NULL
			WHERE sandbox_id = 'ghost'`)
	}
	t.Cleanup(func() { afterTransferTapReads = nil })
	if _, err := st.TransferFirecrackerTapSlot(ctx, "ghost", "missing-to", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("n==0 with empty toID = %v, want ErrNotFound", err)
	}
}

func TestNetnsUpdateAbortTriggers(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-upd", now)

	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER netns_reject_realize
		BEFORE UPDATE ON container_netns_slots
		WHEN NEW.state = 'realized'
		BEGIN
			SELECT RAISE(ABORT, 'forced realize abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "sb-upd", "/n", "10.0.0.1", now); err == nil {
		t.Fatal("expected realize abort")
	}

	_, _ = st.db.ExecContext(ctx, `DROP TRIGGER netns_reject_realize`)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "sb-upd", "/n", "10.0.0.1", now)
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER netns_reject_adopt
		BEFORE UPDATE ON container_netns_slots
		WHEN NEW.state = 'adopted'
		BEGIN
			SELECT RAISE(ABORT, 'forced adopt abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AdoptContainerNetnsSlot(ctx, "sb-upd", now); err == nil {
		t.Fatal("expected adopt abort")
	}
}

func TestListSnapshotAliasesAllFacadesAndNilTemplate(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	_ = st.Create(ctx, sampleSandbox("sb-al3"))
	_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-al3", SourceSandboxID: "sb-al3", Image: "img"})
	_ = st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "a1", SnapshotName: "snap-al3", Facade: "e2b"})
	all, err := st.ListSnapshotAliases(ctx, "")
	if err != nil || len(all) != 1 {
		t.Fatalf("ListSnapshotAliases(\"\") = %v err=%v", all, err)
	}
	if err := st.CreateTemplate(ctx, nil); err == nil {
		t.Fatal("CreateTemplate nil")
	}
}

func TestFinishPrewarmAbortTrigger(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER netns_reject_finish
		BEFORE UPDATE ON container_netns_slots
		WHEN NEW.state = 'pooled'
		BEGIN
			SELECT RAISE(ABORT, 'forced finish abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/n", "10.0.0.1", now); err == nil {
		t.Fatal("expected finish abort")
	}
}
