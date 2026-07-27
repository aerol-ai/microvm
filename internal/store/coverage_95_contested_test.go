package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	_ "github.com/mattn/go-sqlite3"
)

func TestAllocateFirecrackerTapSlotContested(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/tap-c.db"
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

	afterTapAllocateSelect = func(tapName string) {
		_, _ = db2.ExecContext(ctx, `
			UPDATE firecracker_tap_pool SET sandbox_id = 'thief', allocated_at = ?
			WHERE tap_name = ? AND sandbox_id IS NULL`, now, tapName)
	}
	afterTapAllocateMiss = func() {
		_, _ = db2.ExecContext(ctx, `
			UPDATE firecracker_tap_pool SET sandbox_id = NULL, allocated_at = NULL
			WHERE sandbox_id = 'thief'`)
	}
	t.Cleanup(func() {
		afterTapAllocateSelect = nil
		afterTapAllocateMiss = nil
	})

	_, err = st.AllocateFirecrackerTapSlot(ctx, "sb-victim", now)
	if err == nil || !strings.Contains(err.Error(), "pool contested") {
		t.Fatalf("want contested error, got %v", err)
	}
}

func TestNetnsBeginClaimReserveContested(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/netns-c.db"
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
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)

	arm := func(stealState, freeState string) {
		afterNetnsFreeSelect = func(slotID string) {
			_, _ = db2.ExecContext(ctx, `
				UPDATE container_netns_slots
				SET sandbox_id = 'thief', state = ?, updated_at = ?
				WHERE slot_id = ?`, stealState, now, slotID)
		}
		afterNetnsFreeMiss = func() {
			_, _ = db2.ExecContext(ctx, `
				UPDATE container_netns_slots
				SET sandbox_id = NULL, state = ?, updated_at = ?
				WHERE sandbox_id = 'thief'`, freeState, now)
		}
	}

	arm(NetnsSlotStateReserved, NetnsSlotStateFree)
	t.Cleanup(func() {
		afterNetnsFreeSelect = nil
		afterNetnsFreeMiss = nil
	})
	if _, err := st.BeginPrewarmContainerNetnsSlot(ctx, now); err == nil || !strings.Contains(err.Error(), "contested") {
		t.Fatalf("begin contested = %v", err)
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-r", now); err == nil || !strings.Contains(err.Error(), "contested") {
		t.Fatalf("reserve contested = %v", err)
	}

	afterNetnsFreeSelect = nil
	afterNetnsFreeMiss = nil
	slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/n", "10.0.0.1", now)

	arm(NetnsSlotStateAdopted, NetnsSlotStatePooled)
	if _, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-c", now); err == nil || !strings.Contains(err.Error(), "contested") {
		t.Fatalf("claim contested = %v", err)
	}
}

func TestGetOrCreateVolumeUniqueScanError(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	afterVolumeMissSelect = func(tx *sql.Tx) {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO volumes (id, tenant, name, backend, source, created_at)
			VALUES ('vol-winner', 't-bad', 'shared', 's3', 'src', ?)`, []byte{1, 2, 3})
		if err != nil {
			t.Errorf("plant corrupt winner: %v", err)
		}
	}
	t.Cleanup(func() { afterVolumeMissSelect = nil })
	_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "vol-loser", Tenant: "t-bad", Name: "shared", Backend: "s3", Source: "src",
	}, 0)
	if err == nil {
		t.Fatal("expected scan error recovering raced volume")
	}
}

func TestTransferTapUpdateAbortAndGetPortError(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
	}, now)
	_, _ = st.AllocateFirecrackerTapSlot(ctx, "from", now)
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER tap_reject_transfer
		BEFORE UPDATE ON firecracker_tap_pool
		BEGIN
			SELECT RAISE(ABORT, 'forced transfer abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TransferFirecrackerTapSlot(ctx, "from", "to", now); err == nil {
		t.Fatal("expected transfer abort")
	}

	_ = st.Create(ctx, sampleSandbox("sb-gp"))
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-gp", Port: 7, Protocol: "http", PublicURL: "https://x", CreatedAt: now,
	})
	if _, err := st.db.ExecContext(ctx, `UPDATE exposed_ports SET created_at = ? WHERE sandbox_id = ?`, []byte{9}, "sb-gp"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.getPort(ctx, "sb-gp", 7); err == nil {
		t.Fatal("getPort corrupt created_at")
	}
	if _, err := st.getPort(ctx, "sb-gp", 999); err != nil {
		t.Fatalf("getPort missing = %v", err)
	}
}

func TestReassignNetnsAbortAndVolumeInUse(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "from", now)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "from", "/n", "10.0.0.1", now)
	_, _ = st.AdoptContainerNetnsSlot(ctx, "from", now)
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER netns_reject_reassign
		BEFORE UPDATE ON container_netns_slots
		BEGIN
			SELECT RAISE(ABORT, 'forced reassign abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st.ReassignContainerNetnsSandbox(ctx, "from", "to", now); err == nil {
		t.Fatal("expected reassign abort")
	}

	_ = st.CreateVolume(ctx, &models.Volume{ID: "v-inuse", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
	_ = st.Create(ctx, sampleSandbox("sb-vol"))
	_ = st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "v-inuse", SandboxID: "sb-vol", Target: "/data", Source: "s",
	}})
	if err := st.DeleteVolumeIfUnattached(ctx, "t", "v-inuse", "s"); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("in use = %v", err)
	}
}

func TestAllocateTapSelectErrorAndVMMContestedShape(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := st.db.ExecContext(ctx, `DROP TABLE firecracker_tap_pool`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AllocateFirecrackerTapSlot(ctx, "sb", now); err == nil {
		t.Fatal("allocate after drop")
	}
}
