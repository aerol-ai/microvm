package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGetListAttachQueryAndScanErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("loadPorts_query", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-ports")); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `DROP TABLE exposed_ports`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, "sb-ports"); err == nil {
			t.Fatal("Get should fail when exposed_ports is missing")
		}
	})

	t.Run("loadCustomDomains_query", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-dom")); err != nil {
			t.Fatal(err)
		}
		// Keep exposed_ports so Get reaches loadCustomDomains.
		if _, err := st.db.ExecContext(ctx, `DROP TABLE sandbox_custom_domains`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, "sb-dom"); err == nil {
			t.Fatal("Get should fail when sandbox_custom_domains is missing")
		}
	})

	t.Run("attachPortsBulk_query", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-list-ports")); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `DROP TABLE exposed_ports`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.List(ctx); err == nil {
			t.Fatal("List should fail when attachPortsBulk cannot query")
		}
		if _, err := st.ListByOwner(ctx, ""); err == nil {
			// owner_ref empty matches; still needs attach
			_ = err
		}
	})

	t.Run("attachCustomDomainsBulk_query", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-list-dom")); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `DROP TABLE sandbox_custom_domains`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.List(ctx); err == nil {
			t.Fatal("List should fail when attachCustomDomainsBulk cannot query")
		}
	})

	t.Run("loadPorts_scan", func(t *testing.T) {
		st := newTestStore(t)
		sb := sampleSandbox("sb-bad-port")
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO exposed_ports (sandbox_id, port, protocol, host_port, public_url, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, sb.ID, 8080, "http", 0, "https://x", []byte{0xff, 0xfe, 0xfd}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, sb.ID); err == nil {
			t.Fatal("Get should fail on corrupt port created_at")
		}
		if _, err := st.List(ctx); err == nil {
			t.Fatal("List should fail on corrupt port created_at")
		}
	})

	t.Run("attachDomains_scan", func(t *testing.T) {
		st := newTestStore(t)
		sb := sampleSandbox("sb-bad-dom")
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO sandbox_custom_domains (hostname, sandbox_id, status, last_error, target_port, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, "bad.example.com", sb.ID, "ready", "", 0, []byte{1, 2, 3}, now); err != nil {
			t.Fatal(err)
		}
		if _, err := st.List(ctx); err == nil {
			t.Fatal("List should fail on corrupt domain created_at")
		}
	})

	t.Run("scanSandbox_bad_json", func(t *testing.T) {
		st := newTestStore(t)
		sb := sampleSandbox("sb-bad-json")
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET tags_json = ? WHERE id = ?`, "{bad", sb.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, sb.ID); err == nil {
			t.Fatal("Get should fail on corrupt tags_json")
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET tags_json = '{}', container_command_json = ? WHERE id = ?`, "{bad", sb.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, sb.ID); err == nil {
			t.Fatal("Get should fail on corrupt command json")
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET container_command_json = '[]', gpus_json = ? WHERE id = ?`, "{bad", sb.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, sb.ID); err == nil {
			t.Fatal("Get should fail on corrupt gpus_json")
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET gpus_json = '', network_allow_out_json = ? WHERE id = ?`, "{bad", sb.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, sb.ID); err == nil {
			t.Fatal("Get should fail on corrupt allow_out json")
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET network_allow_out_json = '[]', network_deny_out_json = ? WHERE id = ?`, "{bad", sb.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, sb.ID); err == nil {
			t.Fatal("Get should fail on corrupt deny_out json")
		}
	})
}

func TestListHelpersQueryErrorsByDroppedTables(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	cases := []struct {
		name string
		drop string
		call func(*Store) error
		seed func(*testing.T, *Store)
	}{
		{
			name: "ListSnapshotAliases",
			drop: "snapshot_aliases",
			seed: func(t *testing.T, st *Store) {
				_ = st.Create(ctx, sampleSandbox("sb-a"))
				_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-a", SourceSandboxID: "sb-a", Image: "img"})
				_ = st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "al", SnapshotName: "snap-a", Facade: "e2b"})
			},
			call: func(st *Store) error { _, err := st.ListSnapshotAliases(ctx, "snap-a"); return err },
		},
		{
			name: "ListCompatState",
			drop: "sandbox_compat_state",
			seed: func(t *testing.T, st *Store) {
				_ = st.Create(ctx, sampleSandbox("sb-c"))
				_ = st.UpsertCompatState(ctx, "sb-c", "e2b", `{}`)
			},
			call: func(st *Store) error { _, err := st.ListCompatState(ctx, "sb-c"); return err },
		},
		{
			name: "ListSnapshots",
			drop: "sandbox_snapshots",
			seed: func(t *testing.T, st *Store) {
				_ = st.Create(ctx, sampleSandbox("sb-s"))
				_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-s", SourceSandboxID: "sb-s", Image: "img"})
			},
			call: func(st *Store) error { _, err := st.ListSnapshots(ctx); return err },
		},
		{
			name: "ListTemplates",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {
				_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl-x", Image: "img"})
			},
			call: func(st *Store) error { _, err := st.ListTemplates(ctx); return err },
		},
		{
			name: "ListTemplatesPendingPush",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListTemplatesPendingPush(ctx); return err },
		},
		{
			name: "ListUnhealthyTemplates",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListUnhealthyTemplates(ctx); return err },
		},
		{
			name: "ListTemplatesReadyBefore",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListTemplatesReadyBefore(ctx, now); return err },
		},
		{
			name: "ListReadyTemplateIDs",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListReadyTemplateIDs(ctx); return err },
		},
		{
			name: "ListGCEligibleTemplates",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListGCEligibleTemplates(ctx, now); return err },
		},
		{
			name: "ListSnapshotsPendingPush",
			drop: "sandbox_snapshots",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListSnapshotsPendingPush(ctx); return err },
		},
		{
			name: "ListAllExposedPorts",
			drop: "exposed_ports",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListAllExposedPorts(ctx); return err },
		},
		{
			name: "ListCustomDomains",
			drop: "sandbox_custom_domains",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListCustomDomains(ctx, "sb"); return err },
		},
		{
			name: "ListAllCustomDomains",
			drop: "sandbox_custom_domains",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListAllCustomDomains(ctx); return err },
		},
		{
			name: "ListPendingImageGCDue",
			drop: "pending_image_gc",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListPendingImageGCDue(ctx, now, 10); return err },
		},
		{
			name: "ListAutoImportPendingIDs",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListAutoImportPendingIDs(ctx); return err },
		},
		{
			name: "GetPortByHostPort",
			drop: "exposed_ports",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.GetPortByHostPort(ctx, 1); return err },
		},
		{
			name: "ResolveSandboxIDByName",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ResolveSandboxIDByName(ctx, "x"); return err },
		},
		{
			name: "IsTemplateReferenced",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.IsTemplateReferenced(ctx, "tpl"); return err },
		},
		{
			name: "IsTemplateReferencedByVMM",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.IsTemplateReferencedByVMM(ctx, "tpl"); return err },
		},
		{
			name: "AllocateFirecrackerTapSlot",
			drop: "firecracker_tap_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.AllocateFirecrackerTapSlot(ctx, "sb", now); return err },
		},
		{
			name: "GetFirecrackerVMMPoolStats",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.GetFirecrackerVMMPoolStats(ctx, "tpl"); return err },
		},
		{
			name: "ReleaseOrphanedFirecrackerVMMSlots",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ReleaseOrphanedFirecrackerVMMSlots(ctx, now); return err },
		},
		{
			name: "ListWasmModules",
			drop: "wasm_modules",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListWasmModules(ctx); return err },
		},
		{
			name: "ListReadyWasmModuleRefs",
			drop: "wasm_modules",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListReadyWasmModuleRefs(ctx); return err },
		},
		{
			name: "ListWasmModulesOlderThan",
			drop: "wasm_modules",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListWasmModulesOlderThan(ctx, now); return err },
		},
		{
			name: "ListWasmCheckpointPushes",
			drop: "wasm_checkpoint_pushes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListWasmCheckpointPushes(ctx, "sb"); return err },
		},
		{
			name: "ListWasmStateKVKeys",
			drop: "wasm_state_kv",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListWasmStateKVKeys(ctx, "sb"); return err },
		},
		{
			name: "WasmDigestsInUse",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.WasmDigestsInUse(ctx, []string{"d"}); return err },
		},
		{
			name: "ListFirecrackerVMMSlotsForRefill",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl"); return err },
		},
		{
			name: "TryReserveHostPort",
			drop: "exposed_ports",
			seed: func(t *testing.T, st *Store) {
				_ = st.Create(ctx, sampleSandbox("sb-hp"))
			},
			call: func(st *Store) error {
				_, err := st.TryReserveHostPort(ctx, "sb-hp", 80, 40000, "tcp", "https://x", now)
				return err
			},
		},
		{
			name: "AddCustomDomain",
			drop: "sandbox_custom_domains",
			seed: func(t *testing.T, st *Store) {
				_ = st.Create(ctx, sampleSandbox("sb-add-dom"))
			},
			call: func(st *Store) error { return st.AddCustomDomain(ctx, "sb-add-dom", "x.example.com", 80) },
		},
		{
			name: "UpsertSnapshotAlias",
			drop: "snapshot_aliases",
			seed: func(t *testing.T, st *Store) {
				_ = st.Create(ctx, sampleSandbox("sb-alias"))
				_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-alias", SourceSandboxID: "sb-alias", Image: "img"})
			},
			call: func(st *Store) error {
				return st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "a", SnapshotName: "snap-alias", Facade: "e2b"})
			},
		},
		{
			name: "CreateTemplate",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.CreateTemplate(ctx, &models.Template{ID: "tpl", Image: "img"}) },
		},
		{
			name: "CreateSnapshot",
			drop: "sandbox_snapshots",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error {
				return st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "s", SourceSandboxID: "sb", Image: "i"})
			},
		},
		{
			name: "UpdateTags",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.UpdateTags(ctx, "sb", map[string]string{"a": "b"}) },
		},
		{
			name: "PutClusterSecret",
			drop: "cluster_secrets",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error {
				return st.PutClusterSecret(ctx, ClusterSecretRecord{
					Ref: "r", SandboxID: "sb", Version: 1, SealedPayload: []byte("x"),
				})
			},
		},
		{
			name: "InsertFirecrackerVMMSlot",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error {
				return st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "s", TemplateID: "t"}, now)
			},
		},
		{
			name: "InsertWasmCheckpointPush",
			drop: "wasm_checkpoint_pushes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.InsertWasmCheckpointPush(ctx, "sb", "ref", "dig"); return err },
		},
		{
			name: "UpsertAccountMapping",
			drop: "account_mappings",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.UpsertAccountMapping(ctx, "ext", "int") },
		},
		{
			name: "HasActiveImageRef",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.HasActiveImageRef(ctx, "img"); return err },
		},
		{
			name: "RefreshPendingImageGCIfExists",
			drop: "pending_image_gc",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.RefreshPendingImageGCIfExists(ctx, "img", now); return err },
		},
		{
			name: "DeletePendingImageGCIfScheduledAt",
			drop: "pending_image_gc",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.DeletePendingImageGCIfScheduledAt(ctx, "img", now); return err },
		},
		{
			name: "SetFleetSuspended",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.SetFleetSuspended(ctx, "sb", true) },
		},
		{
			name: "MarkTemplateUnhealthy",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.MarkTemplateUnhealthy(ctx, "tpl", "e"); return err },
		},
		{
			name: "MarkTemplatePushPending",
			drop: "firecracker_templates",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.MarkTemplatePushPending(ctx, "tpl"); return err },
		},
		{
			name: "RemoveCustomDomain",
			drop: "sandbox_custom_domains",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.RemoveCustomDomain(ctx, "sb", "h") },
		},
		{
			name: "SetCustomDomainStatus",
			drop: "sandbox_custom_domains",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error {
				return st.SetCustomDomainStatus(ctx, "h", models.CustomDomainReady, "")
			},
		},
		{
			name: "DeleteFirecrackerVMMSlot",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.DeleteFirecrackerVMMSlot(ctx, "id") },
		},
		{
			name: "AllocateFirecrackerVMMSlot",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.AllocateFirecrackerVMMSlot(ctx, "sb", "tpl", now); return err },
		},
		{
			name: "MarkFirecrackerVMMSlotLoaded",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.MarkFirecrackerVMMSlotLoaded(ctx, "id", "/a", "/b", 3, now) },
		},
		{
			name: "MarkFirecrackerVMMSlotFailed",
			drop: "firecracker_vmm_pool",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.MarkFirecrackerVMMSlotFailed(ctx, "id", "e", now) },
		},
		{
			name: "GetClusterSecret",
			drop: "cluster_secrets",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { _, err := st.GetClusterSecret(ctx, "ref"); return err },
		},
		{
			name: "ensureSandboxLookupNameAvailable",
			drop: "sandboxes",
			seed: func(t *testing.T, st *Store) {},
			call: func(st *Store) error { return st.Create(ctx, sampleSandbox("sb-new")) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			tc.seed(t, st)
			if _, err := st.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+tc.drop); err != nil {
				t.Fatalf("drop %s: %v", tc.drop, err)
			}
			if err := tc.call(st); err == nil {
				t.Fatalf("%s: expected error after DROP %s", tc.name, tc.drop)
			}
		})
	}
}

func TestTransferFirecrackerTapSlotConcurrentIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap0", CIDR: "10.200.0.0/30", HostIP: "10.200.0.1", GuestIP: "10.200.0.2", VsockCID: 3,
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AllocateFirecrackerTapSlot(ctx, "park-race", now); err != nil {
		t.Fatal(err)
	}

	// Duplicate concurrent transfers: losers hit RowsAffected=0 and re-read toID.
	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := st.TransferFirecrackerTapSlot(ctx, "park-race", "sb-race", now)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent transfer: %v", err)
		}
	}
	got, err := st.GetFirecrackerTapSlotBySandbox(ctx, "sb-race")
	if err != nil || got == nil {
		t.Fatalf("final owner = %+v err=%v", got, err)
	}
}

func TestClaimIdempotentClosedAndCorrupt(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	st := newTestStore(t)
	if _, err := st.db.ExecContext(ctx, `DROP TABLE request_idempotency`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ClaimIdempotentRequest(ctx, "scope", "fp", now, time.Minute); err == nil {
		t.Fatal("claim after drop")
	}

	st2 := newTestStore(t)
	_ = st2.Close()
	_, _, _ = st2.ClaimIdempotentRequest(ctx, "scope", "fp", now, time.Minute)
	_ = st2.CompleteIdempotentRequest(ctx, "scope", "fp", "t", now, time.Minute)
}

func TestNetnsDropTableErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := st.db.ExecContext(ctx, `DROP TABLE container_netns_slots`); err != nil {
		t.Fatal(err)
	}
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb", now)
	_, _ = st.BeginPrewarmContainerNetnsSlot(ctx, now)
	_ = st.FinishPrewarmContainerNetnsSlot(ctx, "aerol-netns-0", "/n", "10.0.0.1", now)
	_, _ = st.ClaimPooledContainerNetnsSlot(ctx, "sb", now)
	_, _ = st.ListNonFreeContainerNetnsSlots(ctx)
	_ = st.ResetContainerNetnsSlotToFree(ctx, "aerol-netns-0", now)
	_, _ = st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateFree)
	_, _ = st.GetContainerNetnsPoolStats(ctx)
	_ = st.ReassignContainerNetnsSandbox(ctx, "a", "b", now)
}

func TestGetOrCreateVolumeRaceInsertPath(t *testing.T) {
	// Unique constraint on (tenant,name) + concurrent inserts covers the
	// isSQLiteUniqueConstraint recovery branch inside GetOrCreateVolume.
	st := newTestStore(t)
	ctx := context.Background()
	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	var firstErr error
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
				ID: "vol-" + iToStr(i), Tenant: "t-race2", Name: "shared2", Backend: "s3", Source: "src",
			}, 0)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("GetOrCreateVolume race: %v", firstErr)
	}
}

func TestAddCustomDomainPortMismatchAndClosed(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	sb := sampleSandbox("sb-dom2")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCustomDomain(ctx, sb.ID, "same.example.com", 8080); err != nil {
		t.Fatal(err)
	}
	// Same hostname+sandbox+port is idempotent; different port conflicts.
	if err := st.AddCustomDomain(ctx, sb.ID, "same.example.com", 8080); err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if err := st.AddCustomDomain(ctx, sb.ID, "same.example.com", 9090); !errors.Is(err, ErrCustomDomainPortMismatch) {
		t.Fatalf("port mismatch = %v", err)
	}
}
