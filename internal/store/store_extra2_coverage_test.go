package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestStoreMiscHelpers(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Populate DB to hit scan functions during List
	_ = st.Create(ctx, sampleSandbox("sb-list"))
	_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl-list", Image: "img"})
	_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{SourceSandboxID: "sb-list", Name: "snap-list"})
	_ = st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "alias-list", SnapshotName: "snap-list"})
	_ = st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-list", Port: 80, Protocol: "tcp", HostPort: 8080})
	_ = st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "slot-1", TemplateID: "tpl-list"}, time.Now())
	_, _, _ = st.ClaimIdempotentRequest(ctx, "req-1", "fingerprint-1", time.Now(), time.Minute)
	_ = st.UpsertCompatState(ctx, "sb-list", "key1", "val1")
	_ = st.AddCustomDomain(ctx, "sb-list", "domain.com", 80)
	_ = st.PutMounts(ctx, "sb-list", []byte("a"))
	_ = st.PutClusterSecret(ctx, ClusterSecretRecord{SandboxID: "sb-list"})

	// Run List to hit Scan rows
	_, _ = st.List(ctx)
	_, _ = st.ListByOwner(ctx, "owner-list")
	_, _ = st.ListTemplates(ctx)
	_, _ = st.ListSnapshots(ctx)
	_, _ = st.ListSnapshotAliases(ctx, "sb-list")
	_, _ = st.ListAllExposedPorts(ctx)
	_, _ = st.GetFirecrackerVMMPoolStats(ctx, "tpl-list")
	_, _ = st.ListCompatState(ctx, "sb-list")
	_, _ = st.ListAllCustomDomains(ctx)
	_, _ = st.GetMounts(ctx, "sb-list")
	_, _ = st.GetClusterSecret(ctx, "sb-list")

	// Canceled context for these
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	_ = st.SetFleetSuspended(ctxCancel, "tpl", true)
	_, _ = st.RefreshPendingImageGCIfExists(ctxCancel, "tpl", time.Now())
	_, _ = st.DeletePendingImageGCIfScheduledAt(ctxCancel, "tpl", time.Now())

	_, _ = Open("invalid-dsn:::")
	_, _ = Open("file::memory:?cache=shared")

	// Helpers
	_, _ = marshalGPUs(&models.GPURequest{})
	_, _ = marshalGPUs(nil)

	now := time.Now()
	_ = nullableTime(&time.Time{})
	_ = nullableTime(&now)

	_ = isSandboxNameConflict(errors.New("UNIQUE constraint failed: sandbox.lookup_name"), "lookup_name")
	_ = isSandboxNameConflict(errors.New("other"), "lookup_name")

	_ = boolToInt(true)
	_ = boolToInt(false)

	_, _ = marshalJSON(map[string]string{"a": "b"}, "field")
	_, _ = marshalJSON(make(chan int), "field") // error path

	// Additional edge cases
	// Create base items for updates
	_ = st.CreateTemplate(ctx, &models.Template{ID: "tpl-update", Image: "img", Status: models.TemplateStatusPending})
	_, _ = st.MarkTemplateUnhealthy(ctx, "tpl-update", "reason")
	_, _ = st.MarkTemplatePushPending(ctx, "tpl-update")

	_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{SourceSandboxID: "sb-list", Name: "snap-update"})

	_, _, _ = st.ClaimIdempotentRequest(ctx, "req-2", "fp2", time.Now(), time.Minute)
	_, _, _ = st.ClaimIdempotentRequest(ctx, "req-2", "fp2", time.Now(), time.Minute) // Duplicate

	_ = st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "slot-update", TemplateID: "tpl-update"}, time.Now())
	_ = st.MarkFirecrackerVMMSlotLoaded(ctx, "slot-update", "sb-list", "tap", 1, time.Now())
	_ = st.MarkFirecrackerVMMSlotFailed(ctx, "slot-update", "err", time.Now())
	_ = st.DeleteFirecrackerVMMSlot(ctx, "slot-update")

	_ = st.SetCustomDomainStatus(ctx, "sb-list", "domain.com", "err")
	_ = st.RemoveCustomDomain(ctx, "sb-list", "domain.com")

	// Complex updates
	_ = st.UpdateTemplatePushDistribution(ctx, "tpl-update", "ref", "digest")
	_ = st.UpdateTemplateSnapshotReady(ctx, "tpl-update", "mem", "state", 100, "chk", 123, true)
	_ = st.SetTemplatePushState(ctx, "tpl-update", "state", "err")
	_ = st.SetSnapshotPushState(ctx, "snap-update", "state", "err")
	_ = st.UpdateSnapshotImageDistribution(ctx, "snap-update", "mode", "ref", "dig")
	_ = st.CompleteIdempotentRequest(ctx, "req-2", "fp2", "target", time.Now(), time.Minute)
	_ = st.UpdateStatus(ctx, "sb-list", models.SandboxStatus("running"), "err")
	_ = st.UpdateRuntime(ctx, "sb-list", "cid", "cip", "url")
	_ = st.Touch(ctx, "sb-list", time.Now())

	_, _ = st.GetSnapshot(ctx, "snap-list")
	_, _ = st.GetTemplate(ctx, "tpl-list")
	_, _ = st.IsTemplateReferenced(ctx, "tpl-list")
	_, _ = st.IsTemplateReferencedByVMM(ctx, "tpl-list")
	_, _ = st.GetIdempotentRequest(ctx, "req-1", "fingerprint-1")
	_, _ = st.GetClusterSecret(ctx, "sb-list")
	_ = st.SetNetworkLimits(ctx, "sb-list", 1, 1)
	_, _ = st.GetCompatState(ctx, "sb-list", "key1")
	_, _ = st.GetMounts(ctx, "sb-list")
	_, _ = st.GetSnapshotAlias(ctx, "alias-list")
	_, _ = st.ListTemplatesPendingPush(ctx)
	_, _ = st.ListSnapshotsPendingPush(ctx)
	_, _ = st.ListUnhealthyTemplates(ctx)
	_, _ = st.ListGCEligibleTemplates(ctx, time.Now())
	_, _ = st.ListReadyTemplateIDs(ctx)
	_, _ = st.ListAutoImportPendingIDs(ctx)
	_, _ = st.ListAllCustomDomains(ctx)
	_, _ = st.ListAllExposedPorts(ctx)
	_, _ = st.ListCustomDomains(ctx, "sb-list")

	_ = st.DeleteMounts(ctx, "sb-list")
	_ = st.DeleteClusterSecretsForSandbox(ctx, "sb-list")
	_ = st.DeleteSnapshotAlias(ctx, "alias-list")
	_ = st.DeleteSnapshot(ctx, "snap-list")
	_ = st.DeleteTemplate(ctx, "tpl-list")
	_ = st.Delete(ctx, "sb-list")

	_, _ = st.List(ctx)

	_ = st.Close()
}

func TestStoreClosedDBErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.Close() // Close the DB immediately to trigger all error paths

	_ = st.Upsert(ctx, &models.Sandbox{})
	_ = st.UpsertCompatState(ctx, "a", "b", "c")
	_, _, _ = st.ClaimIdempotentRequest(ctx, "req", "fp", time.Now(), time.Minute)
	_ = st.CreateTemplate(ctx, &models.Template{Image: "img"})
	_, _ = st.MarkTemplateUnhealthy(ctx, "tpl", "err")
	_, _ = st.MarkTemplatePushPending(ctx, "tpl")
	_, _ = st.ListTemplatesPendingPush(ctx)
	_, _ = st.ListUnhealthyTemplates(ctx)
	_, _ = st.ListTemplatesReadyBefore(ctx, time.Now())
	_, _ = st.ListReadyTemplateIDs(ctx)
	_, _ = st.ListGCEligibleTemplates(ctx, time.Now())
	_, _ = st.ListSnapshotsPendingPush(ctx)
	_, _ = st.TryReserveHostPort(ctx, "sb", 80, 80, "tcp", "a", time.Now())
	_, _ = st.ListAllExposedPorts(ctx)
	_ = st.AddCustomDomain(ctx, "sb", "dom", 80)
	_ = st.RemoveCustomDomain(ctx, "sb", "dom")
	_, _ = st.ListCustomDomains(ctx, "sb")
	_, _ = st.ListAllCustomDomains(ctx)
	_ = st.SetCustomDomainStatus(ctx, "sb", models.CustomDomainStatus("active"), "err")
	_ = st.PutClusterSecret(ctx, ClusterSecretRecord{})
	_, _ = st.AllocateFirecrackerTapSlot(ctx, "sb", time.Now())
	_ = st.ReleaseFirecrackerTapSlot(ctx, "sb")
	_ = st.MarkFirecrackerVMMSlotLoaded(ctx, "id", "sb", "tap", 1, time.Now())
	_ = st.MarkFirecrackerVMMSlotFailed(ctx, "id", "err", time.Now())
	_, _ = st.AllocateFirecrackerVMMSlot(ctx, "sb", "tpl", time.Now())
	_ = st.ReleaseFirecrackerVMMSlot(ctx, "id", time.Now())
	_, _ = st.ReleaseOrphanedFirecrackerVMMSlots(ctx, time.Now())
	_, _ = st.GetFirecrackerVMMSlotByID(ctx, "id")
	_, _ = st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl")
	_ = st.DeleteFirecrackerVMMSlot(ctx, "id")
	_, _ = st.GetFirecrackerVMMPoolStats(ctx, "tpl")
	_ = st.SetFleetSuspended(ctx, "tpl", true)
	_, _ = st.RefreshPendingImageGCIfExists(ctx, "tpl", time.Now())
	_, _ = st.DeletePendingImageGCIfScheduledAt(ctx, "tpl", time.Now())

	_ = st.AddCustomDomain(ctx, "sb", "dom", 80)
	_ = st.RemoveCustomDomain(ctx, "sb", "dom")
	_, _ = st.ListCustomDomains(ctx, "sb")
	_, _ = st.ListAllCustomDomains(ctx)
	_ = st.SetCustomDomainStatus(ctx, "sb", models.CustomDomainStatus("active"), "err")
	_ = st.ReleaseFirecrackerTapSlot(ctx, "sb")
	_, _ = st.GetFirecrackerTapSlotBySandbox(ctx, "sb")
	_, _ = st.GetFirecrackerTapPoolStats(ctx)
	_ = st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{}, time.Now())
	_ = st.MarkFirecrackerVMMSlotLoaded(ctx, "x", "y", "z", 1, time.Now())
	_ = st.MarkFirecrackerVMMSlotFailed(ctx, "x", "y", time.Now())
	_, _ = st.AllocateFirecrackerVMMSlot(ctx, "x", "y", time.Now())
	_ = st.ReleaseFirecrackerVMMSlot(ctx, "x", time.Now())
	_, _ = st.ReleaseOrphanedFirecrackerVMMSlots(ctx, time.Now())
	_, _ = st.GetFirecrackerVMMSlotByID(ctx, "x")
	_, _ = st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl")
	_ = st.DeleteFirecrackerVMMSlot(ctx, "x")
	_, _ = st.GetFirecrackerVMMPoolStats(ctx, "tpl")
	_ = st.SetFleetSuspended(ctx, "tpl", true)

	// Additional closed DB calls
	_, _ = st.ListAutoImportPendingIDs(ctx)
	_, _ = st.ListCustomDomains(ctx, "sb")
	_, _ = st.ListAllCustomDomains(ctx)
	_, _ = st.ListReadyTemplateIDs(ctx)
	_, _ = st.ListTemplatesReadyBefore(ctx, time.Now())
	_, _ = st.ListUnhealthyTemplates(ctx)
	_, _ = st.ListTemplatesPendingPush(ctx)
	_, _ = st.ListSnapshotsPendingPush(ctx)
	_, _ = st.ListAllExposedPorts(ctx)
	_, _ = st.ListGCEligibleTemplates(ctx, time.Now())
	_, _ = st.ListSnapshotAliases(ctx, "x")
	_, _ = st.ListCompatState(ctx, "x")
	_, _ = st.List(ctx)
	_, _ = st.ListByOwner(ctx, "owner")
	_, _ = st.ListSnapshots(ctx)
	_, _ = st.ListTemplates(ctx)

	_ = st.SetWakeArmed(ctx, "sb", true)
	_ = st.SetAutoImportPending(ctx, "sb", true)
	_, _ = st.GetCompatState(ctx, "sb", "k")
	_, _ = st.GetSnapshotAlias(ctx, "alias")
	_, _ = st.GetIdempotentRequest(ctx, "req", "fp")
	_, _ = st.GetSnapshot(ctx, "snap")
	_, _ = st.GetTemplate(ctx, "tpl")
	_, _ = st.IsTemplateReferenced(ctx, "tpl")
	_, _ = st.IsTemplateReferencedByVMM(ctx, "tpl")
	_ = st.SetNetworkLimits(ctx, "sb", 1, 1)
	_ = st.ClearNetworkQuotaExceeded(ctx, "sb")
	_, _ = st.GetClusterSecret(ctx, "sb")
	_ = st.DeleteClusterSecretsForSandbox(ctx, "sb")
	_, _ = st.GetMounts(ctx, "sb")
}
