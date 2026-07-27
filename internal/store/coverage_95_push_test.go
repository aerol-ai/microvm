package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVolumeInsertAbortAndDeleteIgnored(t *testing.T) {
	ctx := context.Background()

	t.Run("insert_non_unique_error", func(t *testing.T) {
		st := newTestStore(t)
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER volumes_abort_insert
			BEFORE INSERT ON volumes
			BEGIN
				SELECT RAISE(ABORT, 'forced disk full');
			END;
		`); err != nil {
			t.Fatal(err)
		}
		_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
			ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s",
		}, 0)
		if err == nil {
			t.Fatal("expected insert abort")
		}
	})

	t.Run("delete_ignored_not_found", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.CreateVolume(ctx, &models.Volume{
			ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER volumes_ignore_delete
			BEFORE DELETE ON volumes
			BEGIN
				SELECT RAISE(IGNORE);
			END;
		`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteVolumeIfUnattached(ctx, "t", "v1", "s"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ignore-delete = %v, want ErrNotFound", err)
		}
	})
}

func TestBeginClaimAllocateUpdateAborts(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("begin_prewarm_update", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER netns_abort_update
			BEFORE UPDATE ON container_netns_slots
			BEGIN SELECT RAISE(ABORT, 'x'); END;
		`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.BeginPrewarmContainerNetnsSlot(ctx, now); err == nil {
			t.Fatal("begin update abort")
		}
	})

	t.Run("claim_pooled_update", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
		slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		_ = st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/n", "10.0.0.1", now)
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER netns_abort_claim
			BEFORE UPDATE ON container_netns_slots
			BEGIN SELECT RAISE(ABORT, 'x'); END;
		`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb", now); err == nil {
			t.Fatal("claim update abort")
		}
	})

	t.Run("allocate_tap_update", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
			TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
		}, now)
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER tap_abort_update
			BEFORE UPDATE ON firecracker_tap_pool
			BEGIN SELECT RAISE(ABORT, 'x'); END;
		`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AllocateFirecrackerTapSlot(ctx, "sb", now); err == nil {
			t.Fatal("allocate update abort")
		}
	})
}

func TestTransferGetErrorsByDroppedTable(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
	}, now)
	_, _ = st.AllocateFirecrackerTapSlot(ctx, "from", now)
	if _, err := st.db.ExecContext(ctx, `DROP TABLE firecracker_tap_pool`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TransferFirecrackerTapSlot(ctx, "from", "to", now); err == nil {
		t.Fatal("transfer after drop")
	}
}

func TestSourceNilTransferGetError(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
	}, now)
	afterTransferSourceNil = func() {
		_, _ = st.db.ExecContext(ctx, `DROP TABLE firecracker_tap_pool`)
	}
	t.Cleanup(func() { afterTransferSourceNil = nil })
	if _, err := st.TransferFirecrackerTapSlot(ctx, "missing-from", "missing-to", now); err == nil {
		t.Fatal("expected error on source-nil re-read after drop")
	}
}

func TestGetOrCreateVolumeCountAbort(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	afterVolumeBeforeCount = func(tx *sql.Tx) {
		_, _ = tx.ExecContext(ctx, `ALTER TABLE volumes RENAME TO volumes_hidden`)
	}
	t.Cleanup(func() { afterVolumeBeforeCount = nil })
	_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s",
	}, 5)
	if err == nil {
		t.Fatal("expected count error after rename")
	}
}
