package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// In cluster mode, volume metadata must go through the replicated cluster client
// (so it survives the tenant's API ownership moving between nodes), NOT the
// per-node SQLite store. We prove this by creating in cluster mode and asserting
// the row is absent from local SQLite but resolvable via the service.
func TestVolumeMetaRoutesToClusterWhenEnabled(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	ctx := context.Background()

	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}

	// The replicated path is the source of truth; local SQLite must be untouched.
	if _, err := s.store.GetVolumeByID(ctx, v.Tenant, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cluster-mode create leaked into SQLite: %v", err)
	}
	// Reads resolve through the cluster client.
	got, err := s.GetPlatformVolume(ctx, v.ID)
	if err != nil || got.ID != v.ID {
		t.Fatalf("GetPlatformVolume via cluster = %+v, %v", got, err)
	}
	byName, err := s.GetPlatformVolumeByName(ctx, "data")
	if err != nil || byName.ID != v.ID {
		t.Fatalf("GetPlatformVolumeByName via cluster = %+v, %v", byName, err)
	}
	list, err := s.ListPlatformVolumes(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPlatformVolumes via cluster = %+v, %v", list, err)
	}

	// Idempotent create converges on the same id through the cluster path.
	again, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil || again.ID != v.ID {
		t.Fatalf("idempotent cluster create = %+v, %v", again, err)
	}

	// Delete removes it from the replicated store and schedules backend reclaim
	// in the local ledger.
	if err := s.DeletePlatformVolume(ctx, v.ID); err != nil {
		t.Fatalf("DeletePlatformVolume: %v", err)
	}
	if _, err := s.GetPlatformVolume(ctx, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("volume still resolvable after delete: %v", err)
	}
	pending, _ := s.store.ListPendingVolumeDeletions(ctx)
	if len(pending) != 1 || pending[0].VolumeID != v.ID {
		t.Fatalf("reclaim ledger row not written on cluster delete: %+v", pending)
	}
}

// Quota errors from the cluster path map to the same sentinel as SQLite.
func TestVolumeMetaClusterQuota(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.cfg.PlatformVolumes.MaxPerTenant = 1
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	ctx := context.Background()

	if _, err := s.CreatePlatformVolume(ctx, "a"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreatePlatformVolume(ctx, "b")
	if !errors.Is(err, models.ErrPlatformVolumeQuota) {
		t.Fatalf("expected quota error, got %v", err)
	}
}

func TestVolumeMetaClusterAttachmentsBlockDelete(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	c := cluster.NewNoop("self", "http://self", "")
	s.AttachCluster(c)
	ctx := context.Background()

	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	if err := s.volumeMeta().PutAttachments(ctx, []models.VolumeAttachment{{
		Tenant:    v.Tenant,
		VolumeID:  v.ID,
		SandboxID: "sb-remote",
		Target:    "/data",
		Source:    v.Source,
	}}); err != nil {
		t.Fatalf("PutAttachments: %v", err)
	}

	if err := s.DeletePlatformVolume(ctx, v.ID); !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("DeletePlatformVolume attached = %v, want ErrPlatformVolumeInUse", err)
	}
	if err := s.volumeMeta().DeleteAttachmentsForSandbox(ctx, "sb-remote"); err != nil {
		t.Fatalf("DeleteAttachmentsForSandbox: %v", err)
	}
	if err := s.DeletePlatformVolume(ctx, v.ID); err != nil {
		t.Fatalf("DeletePlatformVolume after detach: %v", err)
	}
}

func TestVolumeMetaClusterExistsForSource(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	ctx := context.Background()

	if exists, err := s.volumeMeta().ExistsForSource(ctx, "bucket/t-a/missing"); err != nil || exists {
		t.Fatalf("ExistsForSource missing = %v, %v", exists, err)
	}
	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	exists, err := s.volumeMeta().ExistsForSource(ctx, v.Source)
	if err != nil || !exists {
		t.Fatalf("ExistsForSource live = %v, %v", exists, err)
	}
}

func TestVolumeMetaClusterPutAttachmentsEmpty(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if err := s.volumeMeta().PutAttachments(context.Background(), nil); err != nil {
		t.Fatalf("PutAttachments empty: %v", err)
	}
}

func TestVolumeMetaClusterPutAttachmentsUnknownVolume(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	err := s.volumeMeta().PutAttachments(context.Background(), []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "missing", SandboxID: "sb-1", Target: "/data", Source: "s/x",
	}})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("PutAttachments unknown volume = %v, want ErrNotFound", err)
	}
}

func TestMapVolumeNotFoundSentinels(t *testing.T) {
	if !errors.Is(mapVolumeNotFound(cluster.ErrUnknownVolume), store.ErrNotFound) {
		t.Fatal("expected ErrNotFound for ErrUnknownVolume")
	}
	if !errors.Is(mapVolumeNotFound(cluster.ErrVolumeInUse), store.ErrVolumeInUse) {
		t.Fatal("expected ErrVolumeInUse for ErrVolumeInUse")
	}
	if err := mapVolumeNotFound(errors.New("other")); err.Error() != "other" {
		t.Fatalf("unexpected passthrough: %v", err)
	}
}

func TestCleanupCreatedPlatformVolumesPreservesClusterBackend(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	ctx := context.Background()

	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	s.cleanupCreatedPlatformVolumes(ctx, []models.VolumeAttachment{{
		Tenant:        v.Tenant,
		VolumeID:      v.ID,
		Source:        v.Source,
		CreatedVolume: true,
	}})

	pending, err := s.store.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatalf("ListPendingVolumeDeletions: %v", err)
	}
	if len(pending) != 1 || pending[0].Backend != "s3" || pending[0].Name != "data" {
		t.Fatalf("pending deletion = %+v, want backend/name from full cluster volume row", pending)
	}
}
