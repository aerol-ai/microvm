package store

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVolumeCRUD(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	v := &models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3"}
	if err := st.CreateVolume(ctx, v); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if v.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not stamped")
	}

	got, err := st.GetVolume(ctx, "t-a", "data")
	if err != nil {
		t.Fatalf("GetVolume: %v", err)
	}
	if got.ID != "vol-1" || got.Backend != "s3" {
		t.Fatalf("GetVolume = %+v", got)
	}

	byID, err := st.GetVolumeByID(ctx, "t-a", "vol-1")
	if err != nil {
		t.Fatalf("GetVolumeByID: %v", err)
	}
	if byID.Name != "data" {
		t.Fatalf("GetVolumeByID = %+v", byID)
	}
}

// REGRESSION: the unique(tenant,name) index is the idempotency + isolation
// boundary. A duplicate within a tenant must fail loudly; the same name under a
// different tenant must succeed (cross-tenant isolation).
func TestVolumeUniqueTenantName(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Duplicate (tenant, name) → ErrVolumeExists, no second row.
	err := st.CreateVolume(ctx, &models.Volume{ID: "v2", Tenant: "t-a", Name: "data", Backend: "s3"})
	if !errors.Is(err, ErrVolumeExists) {
		t.Fatalf("dup create err = %v, want ErrVolumeExists", err)
	}
	// Same name, different tenant → allowed.
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v3", Tenant: "t-b", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("cross-tenant same name should succeed: %v", err)
	}

	n, err := st.CountVolumes(ctx, "t-a")
	if err != nil {
		t.Fatalf("CountVolumes: %v", err)
	}
	if n != 1 {
		t.Fatalf("tenant t-a count = %d, want 1 (dup not inserted)", n)
	}
}

func TestGetOrCreateVolumeQuotaAndIdempotency(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	created, didCreate, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3",
	}, 1)
	if err != nil {
		t.Fatalf("GetOrCreateVolume create: %v", err)
	}
	if !didCreate || created.ID != "v1" {
		t.Fatalf("create = %+v, created=%v", created, didCreate)
	}

	existing, didCreate, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v2", Tenant: "t-a", Name: "data", Backend: "s3",
	}, 1)
	if err != nil {
		t.Fatalf("GetOrCreateVolume existing: %v", err)
	}
	if didCreate || existing.ID != "v1" {
		t.Fatalf("existing = %+v, created=%v, want original id", existing, didCreate)
	}

	_, _, err = st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v3", Tenant: "t-a", Name: "logs", Backend: "s3",
	}, 1)
	if !errors.Is(err, ErrVolumeQuotaExceeded) {
		t.Fatalf("new volume at cap err = %v, want ErrVolumeQuotaExceeded", err)
	}
}

func TestVolumeNotFoundAndScoping(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := st.GetVolume(ctx, "t-a", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetVolume missing err = %v, want ErrNotFound", err)
	}
	// Tenant b cannot resolve tenant a's volume id.
	if _, err := st.GetVolumeByID(ctx, "t-b", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant GetVolumeByID err = %v, want ErrNotFound", err)
	}
}

func TestVolumeListAndDelete(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	// Empty list is a non-nil zero-length slice.
	empty, err := st.ListVolumes(ctx, "t-a")
	if err != nil {
		t.Fatalf("ListVolumes empty: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %v, want non-nil len 0", empty)
	}

	for _, id := range []string{"v1", "v2", "v3"} {
		if err := st.CreateVolume(ctx, &models.Volume{ID: id, Tenant: "t-a", Name: id, Backend: "s3"}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	// A volume under another tenant must not leak into t-a's list.
	if err := st.CreateVolume(ctx, &models.Volume{ID: "x", Tenant: "t-b", Name: "x", Backend: "nfs"}); err != nil {
		t.Fatalf("create other-tenant: %v", err)
	}

	list, err := st.ListVolumes(ctx, "t-a")
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("list len = %d, want 3", len(list))
	}

	// Delete is tenant-scoped: t-b cannot delete t-a's volume.
	if err := st.DeleteVolume(ctx, "t-b", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete err = %v, want ErrNotFound", err)
	}
	if err := st.DeleteVolume(ctx, "t-a", "v1"); err != nil {
		t.Fatalf("DeleteVolume: %v", err)
	}
	if err := st.DeleteVolume(ctx, "t-a", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-delete err = %v, want ErrNotFound", err)
	}
	if n, _ := st.CountVolumes(ctx, "t-a"); n != 2 {
		t.Fatalf("count after delete = %d, want 2", n)
	}
}

func TestVolumeAttachmentsBlockDeleteAndPendingLedger(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	vol := &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3"}
	if err := st.CreateVolume(ctx, vol); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-attach")); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	attachment := models.VolumeAttachment{
		Tenant:    "t-a",
		VolumeID:  "v1",
		SandboxID: "sb-attach",
		Target:    "/data",
		Source:    "bucket/prefix/t-a/data",
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{attachment}); err != nil {
		t.Fatalf("PutVolumeAttachments: %v", err)
	}
	count, err := st.CountVolumeAttachments(ctx, "t-a", "v1")
	if err != nil {
		t.Fatalf("CountVolumeAttachments: %v", err)
	}
	if count != 1 {
		t.Fatalf("attachment count = %d, want 1", count)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v1", attachment.Source); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("DeleteVolumeIfUnattached attached err = %v, want ErrVolumeInUse", err)
	}

	if err := st.Delete(ctx, "sb-attach"); err != nil {
		t.Fatalf("Delete sandbox: %v", err)
	}
	count, err = st.CountVolumeAttachments(ctx, "t-a", "v1")
	if err != nil {
		t.Fatalf("CountVolumeAttachments after sandbox delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("attachment count after cascade = %d, want 0", count)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v1", attachment.Source); err != nil {
		t.Fatalf("DeleteVolumeIfUnattached released: %v", err)
	}
	if _, err := st.GetVolumeByID(ctx, "t-a", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetVolumeByID deleted err = %v, want ErrNotFound", err)
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatalf("ListPendingVolumeDeletions: %v", err)
	}
	if len(pending) != 1 || pending[0].VolumeID != "v1" || pending[0].Source != attachment.Source {
		t.Fatalf("pending deletions = %+v, want v1 coordinates", pending)
	}
}

// Recreating a deleted name must NOT silently drop the prior generation's
// pending-deletion ledger row. Dropping it would both cancel reclaim of the old
// backend bytes forever and resurrect not-yet-reclaimed data. The reclaim worker
// owns the live-source check that decides whether the bytes survive.
func TestGetOrCreateVolumePreservesPendingDeletionOnRecreate(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v-old", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/prefix/t-a/data"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v-old", ""); err != nil {
		t.Fatalf("DeleteVolumeIfUnattached: %v", err)
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatalf("ListPendingVolumeDeletions before recreate: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending before recreate = %+v, want one row", pending)
	}

	recreated, created, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v-new", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/prefix/t-a/data",
	}, 0)
	if err != nil {
		t.Fatalf("GetOrCreateVolume recreate: %v", err)
	}
	if !created || recreated.ID != "v-new" {
		t.Fatalf("recreated = %+v, created=%v", recreated, created)
	}
	pending, err = st.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatalf("ListPendingVolumeDeletions after recreate: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending after recreate = %+v, want preserved for the reclaim worker", pending)
	}
}

// A row created before the source column existed (Source == "") still deletes,
// falling back to the caller-supplied source for the ledger coordinate.
func TestDeleteVolumeIfUnattachedFallbackSource(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v-legacy", Tenant: "t-a", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v-legacy", "bucket/prefix/t-a/data"); err != nil {
		t.Fatalf("DeleteVolumeIfUnattached: %v", err)
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatalf("ListPendingVolumeDeletions: %v", err)
	}
	if len(pending) != 1 || pending[0].Source != "bucket/prefix/t-a/data" {
		t.Fatalf("pending = %+v, want fallback source recorded", pending)
	}
}

func TestDeletePendingVolumeDeletionIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v1", ""); err != nil {
		t.Fatalf("DeleteVolumeIfUnattached: %v", err)
	}
	if err := st.DeletePendingVolumeDeletion(ctx, "v1"); err != nil {
		t.Fatalf("DeletePendingVolumeDeletion: %v", err)
	}
	// Second delete of an already-gone row is a no-op success.
	if err := st.DeletePendingVolumeDeletion(ctx, "v1"); err != nil {
		t.Fatalf("DeletePendingVolumeDeletion idempotent: %v", err)
	}
	pending, _ := st.ListPendingVolumeDeletions(ctx)
	if len(pending) != 0 {
		t.Fatalf("ledger not empty: %+v", pending)
	}
}

func TestSchedulePendingVolumeDeletion(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	v := models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	if err := st.SchedulePendingVolumeDeletion(ctx, v, v.Source); err != nil {
		t.Fatalf("SchedulePendingVolumeDeletion: %v", err)
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil || len(pending) != 1 || pending[0].Backend != "s3" || pending[0].Name != "data" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	// Refresh the same row (idempotent upsert).
	if err := st.SchedulePendingVolumeDeletion(ctx, v, "override-source"); err != nil {
		t.Fatalf("SchedulePendingVolumeDeletion refresh: %v", err)
	}
	pending, _ = st.ListPendingVolumeDeletions(ctx)
	if len(pending) != 1 || pending[0].Source != "override-source" {
		t.Fatalf("refresh pending = %+v", pending)
	}
}

func TestDeleteVolumeAttachmentsForSandbox(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-1")); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "v1", SandboxID: "sb-1", Target: "/data", Source: "bucket/t-a/data",
	}}); err != nil {
		t.Fatalf("PutVolumeAttachments: %v", err)
	}
	if err := st.DeleteVolumeAttachmentsForSandbox(ctx, "sb-1"); err != nil {
		t.Fatalf("DeleteVolumeAttachmentsForSandbox: %v", err)
	}
	count, err := st.CountVolumeAttachments(ctx, "t-a", "v1")
	if err != nil || count != 0 {
		t.Fatalf("CountVolumeAttachments after explicit delete = %d, %v", count, err)
	}
	if err := st.DeleteVolumeAttachmentsForSandbox(ctx, "sb-1"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestLiveVolumeExistsForSource(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if ok, err := st.LiveVolumeExistsForSource(ctx, "bucket/t-a/data"); err != nil || ok {
		t.Fatalf("expected no live volume, got ok=%v err=%v", ok, err)
	}
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if ok, err := st.LiveVolumeExistsForSource(ctx, "bucket/t-a/data"); err != nil || !ok {
		t.Fatalf("expected live volume, got ok=%v err=%v", ok, err)
	}
}

func TestCreateVolumeValidation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	bad := []*models.Volume{
		nil,
		{ID: "", Tenant: "t", Name: "n", Backend: "s3"},
		{ID: "i", Tenant: "", Name: "n", Backend: "s3"},
		{ID: "i", Tenant: "t", Name: "", Backend: "s3"},
		{ID: "i", Tenant: "t", Name: "n", Backend: ""},
	}
	for i, v := range bad {
		if err := st.CreateVolume(ctx, v); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}
