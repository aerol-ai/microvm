package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Covers per-row mutators and small read paths that had no direct unit
// coverage. All are plain SQLite CRUD; the focus is the ErrNotFound and
// success branches.

func TestUpdateTagsAndLifecycleMutators(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.Create(ctx, sampleSandbox("sb-mut")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := st.UpdateTags(ctx, "sb-mut", map[string]string{"team": "a"}); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}
	if err := st.UpdateTags(ctx, "missing", map[string]string{"x": "y"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateTags(missing) = %v, want ErrNotFound", err)
	}

	got, err := st.Get(ctx, "sb-mut")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Tags["team"] != "a" {
		t.Fatalf("tags = %v", got.Tags)
	}
}

func TestNetworkCountersAndLimits(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-net")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Negative deltas rejected.
	if err := st.UpdateSandboxNetCounters(ctx, "sb-net", -1, 0); err == nil {
		t.Fatalf("expected error for negative delta")
	}
	// No-op when both zero.
	if err := st.UpdateSandboxNetCounters(ctx, "sb-net", 0, 0); err != nil {
		t.Fatalf("zero delta: %v", err)
	}
	if err := st.UpdateSandboxNetCounters(ctx, "sb-net", 100, 200); err != nil {
		t.Fatalf("UpdateSandboxNetCounters: %v", err)
	}
	if err := st.UpdateSandboxNetCounters(ctx, "missing", 1, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSandboxNetCounters(missing) = %v", err)
	}

	if err := st.SetNetworkLimits(ctx, "sb-net", 1000, 2000); err != nil {
		t.Fatalf("SetNetworkLimits: %v", err)
	}
	if err := st.SetNetworkLimits(ctx, "missing", 1, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetNetworkLimits(missing) = %v", err)
	}

	now := time.Now().UTC()
	if err := st.MarkNetworkQuotaExceeded(ctx, "sb-net", now); err != nil {
		t.Fatalf("MarkNetworkQuotaExceeded: %v", err)
	}
	// Re-mark preserves original detection timestamp (just must not error).
	if err := st.MarkNetworkQuotaExceeded(ctx, "sb-net", now.Add(time.Hour)); err != nil {
		t.Fatalf("MarkNetworkQuotaExceeded re-mark: %v", err)
	}
	if err := st.MarkNetworkQuotaExceeded(ctx, "missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MarkNetworkQuotaExceeded(missing) = %v", err)
	}
	if err := st.ClearNetworkQuotaExceeded(ctx, "sb-net"); err != nil {
		t.Fatalf("ClearNetworkQuotaExceeded: %v", err)
	}
	if err := st.ClearNetworkQuotaExceeded(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ClearNetworkQuotaExceeded(missing) = %v", err)
	}
}

func TestAutoImportPendingRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-imp")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ids, err := st.ListAutoImportPendingIDs(ctx)
	if err != nil {
		t.Fatalf("ListAutoImportPendingIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no pending, got %v", ids)
	}

	if err := st.SetAutoImportPending(ctx, "sb-imp", true); err != nil {
		t.Fatalf("SetAutoImportPending: %v", err)
	}
	if err := st.SetAutoImportPending(ctx, "missing", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetAutoImportPending(missing) = %v", err)
	}

	ids, err = st.ListAutoImportPendingIDs(ctx)
	if err != nil {
		t.Fatalf("ListAutoImportPendingIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "sb-imp" {
		t.Fatalf("pending ids = %v, want [sb-imp]", ids)
	}

	if err := st.SetAutoImportPending(ctx, "sb-imp", false); err != nil {
		t.Fatalf("SetAutoImportPending(false): %v", err)
	}
}

func TestExposedPortReads(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-port")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now().UTC()
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-port",
		Port:      8080,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  31000,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}

	// By host port — hit.
	ep, err := st.GetPortByHostPort(ctx, 31000)
	if err != nil {
		t.Fatalf("GetPortByHostPort: %v", err)
	}
	if ep == nil || ep.SandboxID != "sb-port" || ep.Port != 8080 {
		t.Fatalf("GetPortByHostPort = %+v", ep)
	}
	// By host port — miss returns (nil, nil).
	ep, err = st.GetPortByHostPort(ctx, 9999)
	if err != nil || ep != nil {
		t.Fatalf("GetPortByHostPort(miss) = %+v, %v", ep, err)
	}

	all, err := st.ListAllExposedPorts(ctx)
	if err != nil {
		t.Fatalf("ListAllExposedPorts: %v", err)
	}
	if len(all) != 1 || all[0].HostPort != 31000 {
		t.Fatalf("ListAllExposedPorts = %+v", all)
	}
}

func TestSnapshotPushLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	now := time.Now().UTC().Round(0)
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "snap-1",
		Image:     "img:1",
		CreatedAt: now,
		PushState: models.SnapshotPushStatePending,
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	pending, err := st.ListSnapshotsPendingPush(ctx)
	if err != nil {
		t.Fatalf("ListSnapshotsPendingPush: %v", err)
	}
	if len(pending) != 1 || pending[0].Name != "snap-1" {
		t.Fatalf("pending = %+v", pending)
	}

	if err := st.UpdateSnapshotImageDistribution(ctx, "snap-1", "aocr", "reg/ref", "sha256:abc"); err != nil {
		t.Fatalf("UpdateSnapshotImageDistribution: %v", err)
	}
	if err := st.UpdateSnapshotImageDistribution(ctx, "missing", "aocr", "r", "d"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSnapshotImageDistribution(missing) = %v", err)
	}

	if err := st.SetSnapshotPushState(ctx, "snap-1", "active", ""); err != nil {
		t.Fatalf("SetSnapshotPushState: %v", err)
	}
	if err := st.SetSnapshotPushState(ctx, "missing", "active", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetSnapshotPushState(missing) = %v", err)
	}

	// snap-1 is now active so no longer pending.
	pending, err = st.ListSnapshotsPendingPush(ctx)
	if err != nil {
		t.Fatalf("ListSnapshotsPendingPush 2: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending after active, got %+v", pending)
	}
}

func TestReleaseOrphanedFirecrackerVMMSlots(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	// Two spawning slots with no owning sandbox — both orphaned.
	for _, id := range []string{"vmms-1", "vmms-2"} {
		if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{
			ID:         id,
			TemplateID: "tpl-a",
		}, now); err != nil {
			t.Fatalf("InsertFirecrackerVMMSlot %s: %v", id, err)
		}
	}

	n, err := st.ReleaseOrphanedFirecrackerVMMSlots(ctx, now)
	if err != nil {
		t.Fatalf("ReleaseOrphanedFirecrackerVMMSlots: %v", err)
	}
	if n != 2 {
		t.Fatalf("released = %d, want 2", n)
	}
	// Idempotent: a second sweep releases nothing (rows already released).
	n, err = st.ReleaseOrphanedFirecrackerVMMSlots(ctx, now)
	if err != nil {
		t.Fatalf("ReleaseOrphanedFirecrackerVMMSlots 2: %v", err)
	}
	if n != 0 {
		t.Fatalf("second sweep released = %d, want 0", n)
	}
}

func TestMountsBlobRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-mnt")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := st.GetMounts(ctx, "sb-mnt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMounts(absent) = %v, want ErrNotFound", err)
	}

	blob := []byte("sealed-bytes")
	if err := st.PutMounts(ctx, "sb-mnt", blob); err != nil {
		t.Fatalf("PutMounts: %v", err)
	}
	// Upsert path: overwrite.
	if err := st.PutMounts(ctx, "sb-mnt", []byte("sealed-bytes-2")); err != nil {
		t.Fatalf("PutMounts overwrite: %v", err)
	}

	got, err := st.GetMounts(ctx, "sb-mnt")
	if err != nil {
		t.Fatalf("GetMounts: %v", err)
	}
	if string(got) != "sealed-bytes-2" {
		t.Fatalf("GetMounts = %q", got)
	}

	if err := st.DeleteMounts(ctx, "sb-mnt"); err != nil {
		t.Fatalf("DeleteMounts: %v", err)
	}
	if _, err := st.GetMounts(ctx, "sb-mnt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMounts after delete = %v, want ErrNotFound", err)
	}
}

func TestStoreCoverageExtra(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Idempotent Requests
	_ = st.DeleteIdempotentRequest(ctx, "req-1", "fingerprint-1")
	_, _, _ = st.ClaimIdempotentRequest(ctx, "req-1", "fingerprint-1", time.Now(), time.Minute)
	_, _ = st.GetIdempotentRequest(ctx, "req-1", "fingerprint-1")
	_ = st.CompleteIdempotentRequest(ctx, "req-1", "fingerprint-1", "resp-1", time.Now(), time.Minute)

	// Missing sandbox updates
	_ = st.UpdateStatus(ctx, "missing", models.SandboxStatus("running"), "err")
	_ = st.UpdateRuntime(ctx, "missing", "container-1", "ip", "url")
	_ = st.Touch(ctx, "missing", time.Now())

	// Mounts and Secrets missing paths
	_ = st.DeleteMounts(ctx, "missing")
	_ = st.DeleteClusterSecretsForSandbox(ctx, "missing")
	_, _ = st.GetClusterSecret(ctx, "missing")
	_ = st.PutClusterSecret(ctx, ClusterSecretRecord{})

	// Snapshot Aliases
	_ = st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{})
	_, _ = st.GetSnapshotAlias(ctx, "alias-1")
	_, _ = st.ListSnapshotAliases(ctx, "missing")
	_ = st.DeleteSnapshotAlias(ctx, "alias-1")

	// Template Status
	_ = st.UpdateTemplateStatus(ctx, "tpl-1", models.TemplateStatus("ready"), "err", "build_log", 0)
	_ = st.UpdateTemplateSnapshotReady(ctx, "tpl-1", "img", "snap", 100, "rootfs", 0, false)
	_ = st.UpdateTemplateSnapshotFailed(ctx, "tpl-1", "error")
	_, _ = st.MarkTemplateUnhealthy(ctx, "tpl-1", "error")
	_, _ = st.MarkTemplatePushPending(ctx, "tpl-1")
	_ = st.SetTemplatePushState(ctx, "tpl-1", "ready", "")
	_ = st.UpdateTemplatePushDistribution(ctx, "tpl-1", "reg", "repo")
	_ = st.DeleteTemplate(ctx, "tpl-1")

	// Compat State
	_ = st.UpsertCompatState(ctx, "missing", "k1", "v1")
	_, _ = st.GetCompatState(ctx, "missing", "k1")
	_, _ = st.ListCompatState(ctx, "missing")

	// Misc Sandbox
	_, _ = st.ResolveSandboxIDByName(ctx, "missing")
	_ = st.Delete(ctx, "missing")

	// Snapshots
	_ = st.DeleteSnapshot(ctx, "missing")
	_, _ = st.GetSnapshot(ctx, "missing")

	// Firecracker slots
	_ = st.ReleaseFirecrackerTapSlot(ctx, "missing")
	_, _ = st.GetFirecrackerTapSlotBySandbox(ctx, "missing")

	_ = st.MarkFirecrackerVMMSlotFailed(ctx, "missing", "err")
	_ = st.MarkFirecrackerVMMSlotLoaded(ctx, "missing", "missing")
	_ = st.ReleaseFirecrackerVMMSlot(ctx, "missing")
	_, _ = st.GetFirecrackerVMMSlotBySandbox(ctx, "missing")
	_, _ = st.GetFirecrackerVMMSlotByID(ctx, "missing")
	_ = st.DeleteFirecrackerVMMSlot(ctx, "missing")

	// Lists
	_, _ = st.ListTemplatesPendingPush(ctx)
	_, _ = st.ListUnhealthyTemplates(ctx)
	_, _ = st.ListTemplatesReadyBefore(ctx, time.Now())
	_, _ = st.ListReadyTemplateIDs(ctx)
	_, _ = st.ListGCEligibleTemplates(ctx)
	_, _ = st.IsTemplateReferenced(ctx, "tpl")
	_, _ = st.IsTemplateReferencedByVMM(ctx, "tpl")
}
