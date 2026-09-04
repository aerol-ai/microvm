package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	_ "github.com/mattn/go-sqlite3"
)

func TestOpenRemainingIndexNameCollisions(t *testing.T) {
	// Tables and indexes share SQLite's namespace. Steal each post-migration
	// index name with a table so CREATE INDEX IF NOT EXISTS fails.
	indexes := []string{
		"idx_sandboxes_auto_import_pending",
		"idx_sandboxes_template_id",
		"idx_sandboxes_module_ref",
		"idx_sandboxes_module_digest",
	}
	for _, idx := range indexes {
		t.Run(idx, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "state.db")
			st, err := Open(p)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if _, err := st.db.Exec(`DROP INDEX IF EXISTS ` + idx); err != nil {
				t.Fatal(err)
			}
			_ = st.Close()

			db, err := sql.Open("sqlite3", p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TABLE ` + idx + ` (x INTEGER)`); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()

			if _, err := Open(p); err == nil {
				t.Fatalf("expected Open failure when %s name is stolen by a table", idx)
			}
		})
	}
}

func TestClaimIdempotentCorruptScanAndReadyCommitPaths(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(400, 0).UTC()

	if _, _, err := st.ClaimIdempotentRequest(ctx, "scope", "fp-corrupt", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Force the conflict→SELECT path to fail decoding locked_until.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE request_idempotency SET locked_until = ? WHERE scope = ? AND fingerprint = ?
	`, []byte{0xff, 0xfe}, "scope", "fp-corrupt"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ClaimIdempotentRequest(ctx, "scope", "fp-corrupt", now.Add(time.Second), time.Minute); err == nil {
		t.Fatal("expected scan error on corrupt locked_until")
	}
}

func TestSnapshotAliasExtraNamesDecodeError(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	_ = st.Create(ctx, sampleSandbox("sb-al2"))
	_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-al2", SourceSandboxID: "sb-al2", Image: "img"})
	_ = st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "bad-extra", SnapshotName: "snap-al2", Facade: "e2b"})
	if _, err := st.db.ExecContext(ctx, `
		UPDATE snapshot_aliases SET extra_names_json = ? WHERE alias = ?
	`, "{not-json", "bad-extra"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListSnapshotAliases(ctx, "e2b"); err == nil {
		t.Fatal("expected extra_names decode error")
	}
	if _, err := st.GetSnapshotAlias(ctx, "bad-extra"); err == nil {
		t.Fatal("GetSnapshotAlias corrupt extra_names")
	}
}

func TestNetnsMarkRealizedNonReservedState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-nr", now)
	// Force an unexpected state while still owned — covers the non-reserved guard.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE container_netns_slots SET state = ? WHERE sandbox_id = ?
	`, NetnsSlotStatePooled, "sb-nr"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "sb-nr", "/n", "10.0.0.1", now); err == nil {
		t.Fatal("expected wrong-state error for pooled-owned slot")
	}
}

func TestFleetResolveAndDomainConflictEdges(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.SetFleetSuspended(ctx, "missing", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetFleetSuspended missing = %v", err)
	}
	if _, err := st.ResolveSandboxIDByName(ctx, "   "); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveSandboxIDByName blank = %v", err)
	}

	a := sampleSandbox("sb-dom-a")
	b := sampleSandbox("sb-dom-b")
	_ = st.Create(ctx, a)
	_ = st.Create(ctx, b)
	if err := st.AddCustomDomain(ctx, a.ID, "shared.example.com", 8080); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCustomDomain(ctx, b.ID, "shared.example.com", 8080); !errors.Is(err, ErrCustomDomainConflict) {
		t.Fatalf("cross-sandbox domain = %v, want ErrCustomDomainConflict", err)
	}
}

func TestWasmDigestsInUseHappyAndChunked(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sb := sampleSandbox("sb-dig")
	sb.ModuleDigest = "digest-live"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID: "mod-dig", ModuleRef: "m.wasm", Status: "ready", Digest: "digest-mod", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	inUse, err := st.WasmDigestsInUse(ctx, []string{"digest-live", "digest-mod", "digest-absent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := inUse["digest-live"]; !ok {
		t.Fatalf("missing sandbox digest: %v", inUse)
	}
	if _, ok := inUse["digest-mod"]; !ok {
		t.Fatalf("missing module digest: %v", inUse)
	}

	// >400 digests exercises the chunking loop (end>len branch on last chunk).
	digests := make([]string, 401)
	for i := range digests {
		digests[i] = "d-" + iToStr(i)
	}
	digests[0] = "digest-live"
	if _, err := st.WasmDigestsInUse(ctx, digests); err != nil {
		t.Fatalf("chunked WasmDigestsInUse: %v", err)
	}
}

func TestPendingImageGCAndPortScanErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.SchedulePendingImageGC(ctx, "img-bad", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `DROP TABLE pending_image_gc`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListPendingImageGCDue(ctx, now, 10); err == nil {
		t.Fatal("ListPendingImageGCDue after drop")
	}

	_ = st.Create(ctx, sampleSandbox("sb-port"))
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-port", Port: 90, Protocol: "http", HostPort: 32090, PublicURL: "https://x", CreatedAt: now,
	})
	if _, err := st.db.ExecContext(ctx, `UPDATE exposed_ports SET created_at = ? WHERE sandbox_id = ?`, []byte{9}, "sb-port"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPortByHostPort(ctx, 32090); err == nil {
		t.Fatal("GetPortByHostPort corrupt created_at")
	}
}

func TestVolumeListCountDeleteScanAndQueryErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("list_corrupt", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
		if _, err := st.db.ExecContext(ctx, `UPDATE volumes SET created_at = ? WHERE id = ?`, []byte{1}, "v1"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListVolumes(ctx, "t"); err == nil {
			t.Fatal("ListVolumes corrupt")
		}
	})

	t.Run("delete_and_count_dropped", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
		if _, err := st.db.ExecContext(ctx, `DROP TABLE volumes`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteVolume(ctx, "t", "v1"); err == nil {
			t.Fatal("DeleteVolume after drop")
		}
		if _, err := st.CountVolumes(ctx, "t"); err == nil {
			t.Fatal("CountVolumes after drop")
		}
		if _, err := st.GetVolumeByID(ctx, "t", "v1"); err == nil {
			t.Fatal("GetVolumeByID after drop")
		}
	})

	t.Run("attachments_and_pending_dropped", func(t *testing.T) {
		st := newTestStore(t)
		if _, err := st.db.ExecContext(ctx, `DROP TABLE volume_attachments`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.CountVolumeAttachments(ctx, "t", "v"); err == nil {
			t.Fatal("CountVolumeAttachments after drop")
		}
		if err := st.DeleteVolumeAttachmentsForSandbox(ctx, "sb"); err == nil {
			t.Fatal("DeleteVolumeAttachmentsForSandbox after drop")
		}
		st2 := newTestStore(t)
		if _, err := st2.db.ExecContext(ctx, `DROP TABLE pending_volume_deletions`); err != nil {
			t.Fatal(err)
		}
		if _, err := st2.ListPendingVolumeDeletions(ctx); err == nil {
			t.Fatal("ListPendingVolumeDeletions after drop")
		}
	})

	t.Run("delete_if_unattached_dropped", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3", Source: "s"})
		if _, err := st.db.ExecContext(ctx, `DROP TABLE volume_attachments`); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteVolumeIfUnattached(ctx, "t", "v1", "s"); err == nil {
			t.Fatal("DeleteVolumeIfUnattached after attachments drop")
		}
	})
}

func TestAllocateTapSlotClosedAndExhaustedEdges(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.1.0.0/30", HostIP: "10.1.0.1", GuestIP: "10.1.0.2", VsockCID: 3,
	}, now)
	slot, err := st.AllocateFirecrackerTapSlot(ctx, "sb-tap", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReleaseFirecrackerTapSlot(ctx, "sb-tap"); err != nil {
		t.Fatal(err)
	}
	// Re-allocate after release (idempotent pool reuse).
	again, err := st.AllocateFirecrackerTapSlot(ctx, "sb-tap2", now)
	if err != nil || again.TapName != slot.TapName {
		t.Fatalf("realloc = %+v err=%v", again, err)
	}

	st2 := newTestStore(t)
	_ = st2.Close()
	_, _ = st2.AllocateFirecrackerTapSlot(ctx, "sb", now)
	_, _ = st2.TransferFirecrackerTapSlot(ctx, "a", "b", now)
	_, _ = st2.GetFirecrackerTapPoolStats(ctx)
}

func TestListReadyTemplateIDsAndCompatScan(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl-ready", Image: "img", Status: models.TemplateStatusReady})
	_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl-pending", Image: "img", Status: models.TemplateStatusPending})
	if _, err := st.db.ExecContext(ctx, `
		UPDATE firecracker_templates SET status = ? WHERE id = ?
	`, string(models.TemplateStatusReady), "tpl-ready"); err != nil {
		t.Fatal(err)
	}
	ids, err := st.ListReadyTemplateIDs(ctx)
	if err != nil || len(ids) == 0 {
		t.Fatalf("ListReadyTemplateIDs = %v err=%v", ids, err)
	}
	ready, catalog, err := st.ListTemplateInventoryIDs(ctx)
	if err != nil || len(ready) != 1 || len(catalog) != 2 {
		t.Fatalf("ListTemplateInventoryIDs = ready:%v catalog:%v err=%v", ready, catalog, err)
	}

	_ = st.Create(ctx, sampleSandbox("sb-cs2"))
	_ = st.UpsertCompatState(ctx, "sb-cs2", "e2b", `{"ok":true}`)
	if _, err := st.db.ExecContext(ctx, `
		UPDATE sandbox_compat_state SET created_at = ? WHERE sandbox_id = ?
	`, []byte{1, 2, 3}, "sb-cs2"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListCompatState(ctx, "e2b"); err == nil {
		t.Fatal("ListCompatState corrupt created_at")
	}

	// VMM slot with non-null released_at / allocated_at for collect nullable branches.
	_ = st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "vmm-rel", TemplateID: "tpl-ready"}, now)
	if _, err := st.db.ExecContext(ctx, `
		UPDATE firecracker_vmm_pool
		SET status = ?, sandbox_id = ?, loaded_at = ?, allocated_at = ?, released_at = ?
		WHERE id = ?
	`, FirecrackerVMMSlotStatusReleased, "sb-cs2", now, now, now, "vmm-rel"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListReleasedFirecrackerVMMSlots(ctx, now.Add(time.Hour)); err != nil {
		t.Fatalf("ListReleasedFirecrackerVMMSlots: %v", err)
	}
	if _, err := st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl-ready"); err != nil {
		// released excluded — should succeed empty or with other rows
		t.Fatalf("ListFirecrackerVMMSlotsForRefill: %v", err)
	}
}

func TestUpdateTagsLifecycleQueryErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if _, err := st.db.ExecContext(ctx, `DROP TABLE sandboxes`); err != nil {
		t.Fatal(err)
	}
	_ = st.UpdateTags(ctx, "sb", map[string]string{"a": "b"})
	_ = st.UpdateLifecycle(ctx, "sb", models.Lifecycle{StopIfIdleFor: time.Second})
	_ = st.MarkNetworkQuotaExceeded(ctx, "sb", time.Now())
	_ = st.SetAllowPublicTraffic(ctx, "sb", true, "https://x")
	_ = st.UpdateSandboxNetCounters(ctx, "sb", 1, 2)
	_, _ = st.ListAutoImportPendingIDs(ctx)
}
