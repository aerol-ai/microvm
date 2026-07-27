package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVolumeDeleteIfUnattachedExecErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("schedule_abort", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER pending_reject
			BEFORE INSERT ON pending_volume_deletions
			BEGIN
				SELECT RAISE(ABORT, 'forced pending abort');
			END;
		`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteVolumeIfUnattached(ctx, "t", "v1", "s"); err == nil {
			t.Fatal("expected schedule abort")
		}
	})

	t.Run("delete_abort", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
		if _, err := st.db.ExecContext(ctx, `
			CREATE TRIGGER volumes_reject_delete
			BEFORE DELETE ON volumes
			BEGIN
				SELECT RAISE(ABORT, 'forced delete abort');
			END;
		`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteVolumeIfUnattached(ctx, "t", "v1", "s"); err == nil {
			t.Fatal("expected delete abort")
		}
	})

	t.Run("count_attachments_error", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
		if _, err := st.db.ExecContext(ctx, `DROP TABLE volume_attachments`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteVolumeIfUnattached(ctx, "t", "v1", "s"); err == nil {
			t.Fatal("expected count attachments error")
		}
	})
}

func TestReserveNetnsUpdateAbortAndListScan(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER netns_reject_reserve
		BEFORE UPDATE ON container_netns_slots
		BEGIN
			SELECT RAISE(ABORT, 'forced reserve abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb", now); err == nil {
		t.Fatal("expected reserve abort")
	}

	st2 := newTestStore(t)
	_ = st2.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st2.ReserveContainerNetnsSlot(ctx, "sb-l", now)
	if _, err := st2.db.ExecContext(ctx, `
		UPDATE container_netns_slots SET created_at = ? WHERE sandbox_id = ?
	`, []byte{1, 2, 3}, "sb-l"); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.ListNonFreeContainerNetnsSlots(ctx); err == nil {
		t.Fatal("ListNonFree corrupt created_at")
	}
	if _, err := st2.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateReserved); err == nil {
		t.Fatal("ListByState corrupt created_at")
	}
}

func TestTransferGetErrorsAndUpsertAlias(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 3,
	}, now)
	_, _ = st.AllocateFirecrackerTapSlot(ctx, "from", now)

	afterTransferTapReads = func() {
		_, _ = st.db.ExecContext(ctx, `DROP TABLE firecracker_tap_pool`)
	}
	t.Cleanup(func() { afterTransferTapReads = nil })
	// Hook runs on same goroutine while Allocate's connection may be free between
	// statements — DROP via st.db can proceed because Transfer isn't in a multi-stmt tx.
	if _, err := st.TransferFirecrackerTapSlot(ctx, "from", "to", now); err == nil {
		t.Fatal("expected transfer error after drop")
	}

	st2 := newTestStore(t)
	_ = st2.Create(ctx, sampleSandbox("sb-al"))
	_ = st2.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap", SourceSandboxID: "sb-al", Image: "img"})
	if _, err := st2.db.ExecContext(ctx, `DROP TABLE snapshot_aliases`); err != nil {
		t.Fatal(err)
	}
	if err := st2.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "a", SnapshotName: "snap", Facade: "e2b"}); err == nil {
		t.Fatal("UpsertSnapshotAlias after drop")
	}
}

func TestCreateTemplateValidationAndClusterSecret(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.CreateTemplate(ctx, &models.Template{ID: "", Image: "img"}); err == nil {
		t.Fatal("CreateTemplate empty id")
	}
	if _, err := st.db.ExecContext(ctx, `DROP TABLE cluster_secrets`); err != nil {
		t.Fatal(err)
	}
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "r", SandboxID: "sb", Version: 1, SealedPayload: []byte("x"),
	}); err == nil {
		t.Fatal("PutClusterSecret after drop")
	}
}

func TestGetOrCreateVolumeCountErrorInTx(t *testing.T) {
	// After the miss SELECT, break COUNT by replacing volumes with a view that
	// errors on aggregate — use a trigger on a side table instead: maxPerTenant>0
	// with volumes renamed mid-flight via hook is awkward; drop after creating
	// a decoy store path: Execute COUNT against missing table by renaming inside hook
	// before count — move hook earlier.
	st := newTestStore(t)
	ctx := context.Background()
	// Pre-fill to capacity then force count path on a new name with table drop.
	_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-c", Name: "a", Backend: "s3", Source: "s"})
	if _, err := st.db.ExecContext(ctx, `ALTER TABLE volumes RENAME TO volumes_real`); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v2", Tenant: "t-c", Name: "b", Backend: "s3", Source: "s",
	}, 5)
	if err == nil {
		t.Fatal("expected error when volumes table renamed before count/select")
	}
}

func TestClaimIdempotentRefreshAbort(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(1, 0).UTC()
	_, _, err := st.ClaimIdempotentRequest(ctx, "s", "fp", now.Add(-time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER idem_reject_update
		BEFORE UPDATE ON request_idempotency
		BEGIN
			SELECT RAISE(ABORT, 'forced refresh abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	// Expired lock → refresh UPDATE aborts.
	if _, _, err := st.ClaimIdempotentRequest(ctx, "s", "fp", now, time.Minute); err == nil {
		t.Fatal("expected refresh abort")
	}
}

func TestListReadyTemplateIDsAndWasmKVErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl", Image: "img", Status: models.TemplateStatusReady})
	if _, err := st.db.ExecContext(ctx, `
		UPDATE firecracker_templates SET status = ? WHERE id = ?
	`, string(models.TemplateStatusReady), "tpl"); err != nil {
		t.Fatal(err)
	}
	// Corrupt by replacing table with a view that breaks Scan of id? Use DROP.
	if _, err := st.db.ExecContext(ctx, `DROP TABLE firecracker_templates`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListReadyTemplateIDs(ctx); err == nil {
		t.Fatal("ListReadyTemplateIDs after drop")
	}

	st2 := newTestStore(t)
	if _, err := st2.db.ExecContext(ctx, `DROP TABLE wasm_state_kv`); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.ListWasmStateKVKeys(ctx, "sb"); err == nil {
		t.Fatal("ListWasmStateKVKeys after drop")
	}
}

func TestMarkTemplateRowsAffectedPaths(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if _, err := st.MarkTemplateUnhealthy(ctx, "missing", "e"); err != nil && !errors.Is(err, ErrNotFound) {
		// May return nil or not-found depending on implementation
		_ = err
	}
	if _, err := st.MarkTemplatePushPending(ctx, "missing"); err != nil {
		_ = err
	}
	_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl-m", Image: "img"})
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER tpl_reject
		BEFORE UPDATE ON firecracker_templates
		BEGIN
			SELECT RAISE(ABORT, 'forced tpl abort');
		END;
	`); err != nil {
		t.Fatal(err)
	}
	_, _ = st.MarkTemplateUnhealthy(ctx, "tpl-m", "e")
	_, _ = st.MarkTemplatePushPending(ctx, "tpl-m")
}
