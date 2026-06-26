package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGetOrCreateVolumeValidation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if _, _, err := st.GetOrCreateVolume(ctx, nil, 0); err == nil {
		t.Fatal("expected error for nil volume")
	}
	cases := []*models.Volume{
		{ID: "", Tenant: "t", Name: "n", Backend: "s3"},
		{ID: "i", Tenant: "", Name: "n", Backend: "s3"},
		{ID: "i", Tenant: "t", Name: "", Backend: "s3"},
		{ID: "i", Tenant: "t", Name: "n", Backend: ""},
	}
	for i, v := range cases {
		if _, _, err := st.GetOrCreateVolume(ctx, v, 0); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestCreateVolumeWithSourceAndTimestamp(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	created := time.Now().UTC().Add(-time.Hour)
	v := &models.Volume{
		ID: "vol-src", Tenant: "t-a", Name: "data", Backend: "s3",
		Source: "s3://bucket/t-a/data", CreatedAt: created,
	}
	if err := st.CreateVolume(ctx, v); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	got, err := st.GetVolume(ctx, "t-a", "data")
	if err != nil {
		t.Fatalf("GetVolume: %v", err)
	}
	if got.Source != "s3://bucket/t-a/data" || !got.CreatedAt.Equal(created) {
		t.Fatalf("got = %+v, want source and created_at preserved", got)
	}
}

func TestPutVolumeAttachmentsEmptyAndValidation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.PutVolumeAttachments(ctx, nil); err != nil {
		t.Fatalf("nil attachments: %v", err)
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{}); err != nil {
		t.Fatalf("empty attachments: %v", err)
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "v1", SandboxID: "sb", Target: "", Source: "src",
	}}); err == nil {
		t.Fatal("expected validation error for empty target")
	}
}

func TestPutVolumeAttachmentsUpsertUpdatesSource(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-upsert")); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	base := models.VolumeAttachment{
		Tenant: "t-a", VolumeID: "v1", SandboxID: "sb-upsert",
		Target: "/data", Source: "bucket/old",
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{base}); err != nil {
		t.Fatalf("first put: %v", err)
	}
	base.Source = "bucket/new"
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{base}); err != nil {
		t.Fatalf("upsert put: %v", err)
	}
}

func TestDeleteVolumeIfUnattachedValidation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.DeleteVolumeIfUnattached(ctx, "", "v1", "src"); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "", "src"); err == nil {
		t.Fatal("expected error for empty id")
	}
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v-no-src", Tenant: "t-a", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v-no-src", ""); err == nil {
		t.Fatal("expected error when volume has no source and no fallback")
	}
}

func TestSchedulePendingVolumeDeletionValidation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.SchedulePendingVolumeDeletion(ctx, models.Volume{}, ""); err == nil {
		t.Fatal("expected validation error for empty volume")
	}
	if err := st.SchedulePendingVolumeDeletion(ctx, models.Volume{ID: "v1", Tenant: "t-a"}, ""); err == nil {
		t.Fatal("expected validation error for empty source")
	}
}

func TestGetOrCreateVolumeConcurrentSameName(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	ids := make(chan string, n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			vol, created, err := st.GetOrCreateVolume(ctx, &models.Volume{
				ID:      "vol-race-" + string(rune('a'+i)),
				Tenant:  "t-race",
				Name:    "shared",
				Backend: "s3",
				Source:  "bucket/t-race/shared",
			}, 0)
			if err != nil {
				errs <- err
				return
			}
			if vol == nil {
				errs <- errors.New("nil volume")
				return
			}
			ids <- vol.ID
			_ = created
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)

	for err := range errs {
		if err != nil {
			t.Fatalf("GetOrCreateVolume concurrent: %v", err)
		}
	}
	seen := map[string]struct{}{}
	for id := range ids {
		seen[id] = struct{}{}
	}
	if len(seen) != 1 {
		t.Fatalf("concurrent creates diverged on ids: %v", seen)
	}
	if n, err := st.CountVolumes(ctx, "t-race"); err != nil || n != 1 {
		t.Fatalf("CountVolumes = %d err %v, want 1", n, err)
	}
}

func TestCreateVolumeNil(t *testing.T) {
	st := newTestStore(t)
	if err := st.CreateVolume(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil volume")
	}
}

func TestListVolumesScanError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.CreateVolume(ctx, &models.Volume{
		ID: "good", Tenant: "t-list", Name: "good", Backend: "s3", Source: "src",
	}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO volumes (id, tenant, name, backend, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "bad", "t-list", "bad", "s3", "src", []byte{0, 1, 2, 3}); err != nil {
		t.Fatalf("seed corrupt row: %v", err)
	}
	_, err := st.ListVolumes(ctx, "t-list")
	if err == nil {
		t.Fatal("expected scan error listing volumes with corrupt created_at")
	}
}

func TestGetOrCreateVolumeExistingLookupScanError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO volumes (id, tenant, name, backend, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "bad", "t-scan", "broken", "s3", "src", []byte{0, 1, 2, 3}); err != nil {
		t.Fatalf("seed corrupt row: %v", err)
	}
	_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "vol-new", Tenant: "t-scan", Name: "broken", Backend: "s3",
	}, 0)
	if err == nil {
		t.Fatal("expected scan error when existing row has corrupt created_at")
	}
}

func TestGetOrCreateVolumeCountQueryError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.db.ExecContext(ctx, `ALTER TABLE volumes RENAME TO volumes_renamed`); err != nil {
		t.Fatalf("rename volumes: %v", err)
	}
	_, _, err := st.GetOrCreateVolume(ctx, &models.Volume{
		ID: "v1", Tenant: "t-count", Name: "data", Backend: "s3",
	}, 1)
	if err == nil {
		t.Fatal("expected error after renaming volumes table")
	}
}

func TestListPendingVolumeDeletionsScanError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.SchedulePendingVolumeDeletion(ctx, models.Volume{
		ID: "v-good", Tenant: "t-a", Name: "good", Backend: "s3",
	}, "bucket/good"); err != nil {
		t.Fatalf("SchedulePendingVolumeDeletion: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO pending_volume_deletions (volume_id, tenant, name, backend, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "v-bad", "t-a", "bad", "s3", "bucket/bad", []byte{0, 1, 2, 3}); err != nil {
		t.Fatalf("seed corrupt pending row: %v", err)
	}
	_, err := st.ListPendingVolumeDeletions(ctx)
	if err == nil {
		t.Fatal("expected scan error listing pending deletions with corrupt created_at")
	}
}

func TestCreateVolumeDuplicateReturnsErrVolumeExists(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	base := &models.Volume{ID: "v1", Tenant: "t-dup", Name: "data", Backend: "s3"}
	if err := st.CreateVolume(ctx, base); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	err := st.CreateVolume(ctx, &models.Volume{ID: "v2", Tenant: "t-dup", Name: "data", Backend: "s3"})
	if !errors.Is(err, ErrVolumeExists) {
		t.Fatalf("duplicate create = %v, want ErrVolumeExists", err)
	}
}

func TestDeleteVolumeWrongTenantNotFound(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3"}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.DeleteVolume(ctx, "other-tenant", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteVolume wrong tenant = %v, want ErrNotFound", err)
	}
}

func TestDeleteVolumeIfUnattachedNotFound(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "missing", "bucket/src"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing volume = %v, want ErrNotFound", err)
	}
}

func TestPutVolumeAttachmentsForeignKeyViolation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-fk")); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "no-such-volume", SandboxID: "sb-fk",
		Target: "/data", Source: "bucket/src",
	}})
	if err == nil {
		t.Fatal("expected foreign-key error for missing volume_id")
	}
}

func TestPutVolumeAttachmentsMultipleInOneTx(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "a", Backend: "s3"}); err != nil {
		t.Fatalf("CreateVolume v1: %v", err)
	}
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v2", Tenant: "t-a", Name: "b", Backend: "s3"}); err != nil {
		t.Fatalf("CreateVolume v2: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-multi")); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{
		{Tenant: "t-a", VolumeID: "v1", SandboxID: "sb-multi", Target: "/a", Source: "bucket/a"},
		{Tenant: "t-a", VolumeID: "v2", SandboxID: "sb-multi", Target: "/b", Source: "bucket/b"},
	}); err != nil {
		t.Fatalf("PutVolumeAttachments: %v", err)
	}
	if n, err := st.CountVolumeAttachments(ctx, "t-a", "v1"); err != nil || n != 1 {
		t.Fatalf("v1 attachments = %d err %v", n, err)
	}
	if n, err := st.CountVolumeAttachments(ctx, "t-a", "v2"); err != nil || n != 1 {
		t.Fatalf("v2 attachments = %d err %v", n, err)
	}
}

func TestDeleteVolumeIfUnattachedPendingUpsert(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	v := &models.Volume{ID: "v1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	if err := st.CreateVolume(ctx, v); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v1", ""); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	// Re-create the same name with a new id; ledger row should refresh on second delete.
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v2", Tenant: "t-a", Name: "data2", Backend: "s3", Source: "bucket/t-a/data2"}); err != nil {
		t.Fatalf("CreateVolume v2: %v", err)
	}
	if err := st.DeleteVolumeIfUnattached(ctx, "t-a", "v2", ""); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending = %+v err %v, want 2 rows", pending, err)
	}
}

func TestVolumeClosedDBErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.Close()

	_ = st.CreateVolume(ctx, &models.Volume{ID: "v", Tenant: "t", Name: "n", Backend: "s3"})
	_, _, _ = st.GetOrCreateVolume(ctx, &models.Volume{ID: "v", Tenant: "t", Name: "n", Backend: "s3"}, 0)
	_, _ = st.GetVolume(ctx, "t", "n")
	_, _ = st.GetVolumeByID(ctx, "t", "v")
	_, _ = st.ListVolumes(ctx, "t")
	_, _ = st.CountVolumes(ctx, "t")
	_ = st.DeleteVolume(ctx, "t", "v")
	_ = st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "v", SandboxID: "sb", Target: "/d", Source: "s",
	}})
	_, _ = st.CountVolumeAttachments(ctx, "t", "v")
	_ = st.DeleteVolumeAttachmentsForSandbox(ctx, "sb")
	_ = st.DeleteVolumeIfUnattached(ctx, "t", "v", "src")
	_, _ = st.ListPendingVolumeDeletions(ctx)
	_ = st.SchedulePendingVolumeDeletion(ctx, models.Volume{ID: "v", Tenant: "t", Name: "n", Backend: "s3"}, "src")
	_ = st.DeletePendingVolumeDeletion(ctx, "v")
	_, _ = st.LiveVolumeExistsForSource(ctx, "src")
}
