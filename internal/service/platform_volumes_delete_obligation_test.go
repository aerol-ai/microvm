package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Same-pattern fix: a volume delete in a cluster (the Daytona API, or the
// cleanup of a failed create) used to write its ledger row on whichever node
// took the request. Only workers drain the ledger, and a worker's row dies
// with it. Now the delete records the reclaim in the replicated ledger in
// the same step as the row delete, and a worker's sweep drains it.
func TestClusterVolumeDeleteRecordsReclaimAWorkerDrains(t *testing.T) {
	for _, tc := range []struct {
		name   string
		delete func(t *testing.T, svc *Service, vol models.Volume)
	}{
		{"API delete", func(t *testing.T, svc *Service, vol models.Volume) {
			if err := svc.DeletePlatformVolume(context.Background(), vol.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"failed create's cleanup", func(t *testing.T, svc *Service, vol models.Volume) {
			svc.cleanupCreatedPlatformVolumes(context.Background(), []models.VolumeAttachment{{Tenant: vol.Tenant, VolumeID: vol.ID, CreatedVolume: true}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, fr, c, vol := clusterReclaimHarness(t)
			ctx := context.Background()
			tc.delete(t, svc, vol)

			if volumeExists(t, svc, vol) {
				t.Fatal("the volume row must be deleted")
			}
			r, ok := c.has(vol.ID)
			if !ok || c.deletes != 1 || r.Source != vol.Source {
				t.Fatalf("replicated reclaim = %+v ok=%v deletes=%d", r, ok, c.deletes)
			}
			if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
				t.Fatalf("a node-local ledger row was written too: %+v", pending)
			}
			svc.runVolumeReclaim(ctx)
			if got := reclaimedSources(fr); len(got) != 1 || got[0] != vol.Source {
				t.Fatalf("reclaimed = %v", got)
			}
			if _, ok := c.has(vol.ID); ok {
				t.Fatal("the entry must be acked once the bytes are gone")
			}
		})
	}
}

// While a server predates the replicated ledger, a cluster delete keeps the
// old path: this node's ledger row, then the row delete.
func TestClusterVolumeDeleteOnOlderServerUsesLocalLedger(t *testing.T) {
	svc, st, _, c, vol := clusterReclaimHarness(t)
	c.olderServer = true
	ctx := context.Background()
	if err := svc.DeletePlatformVolume(ctx, vol.ID); err != nil {
		t.Fatal(err)
	}
	if volumeExists(t, svc, vol) {
		t.Fatal("the volume row must be deleted")
	}
	if _, ok := c.has(vol.ID); ok || c.deletes != 0 {
		t.Fatal("an older server cannot hold the replicated record")
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil || len(pending) != 1 || pending[0].VolumeID != vol.ID {
		t.Fatalf("local ledger = %+v, %v", pending, err)
	}
}

// A delete that races an attach is refused and records nothing; a local
// ledger write that fails stops the delete before the row goes.
func TestClusterVolumeDeleteRefusalsKeepTheRow(t *testing.T) {
	svc, st, _, c, vol := clusterReclaimHarness(t)
	ctx := context.Background()
	attachTo(t, svc, vol, "sb-holder")
	if err := svc.DeletePlatformVolume(ctx, vol.ID); !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("attached delete = %v, want in use", err)
	}
	if _, ok := c.has(vol.ID); ok || !volumeExists(t, svc, vol) {
		t.Fatal("a refused delete must keep the row and record nothing")
	}
	if err := (clusterVolumeMeta{c: c, store: st}).DeleteRowOwingBytes(ctx, vol, vol.Source); !errors.Is(err, store.ErrVolumeInUse) {
		t.Fatalf("store-level attached delete = %v, want ErrVolumeInUse", err)
	}

	c.olderServer = true
	_ = st.Close()
	if err := (clusterVolumeMeta{c: c, store: st}).DeleteRowOwingBytes(ctx, vol, vol.Source); err == nil {
		t.Fatal("a failed local ledger write must stop the delete")
	}
	if !volumeExists(t, svc, vol) {
		t.Fatal("the row must stay when its ledger row could not be written")
	}
}

// Single node: the row and the ledger row change in one transaction.
func TestSingleNodeVolumeDeleteWritesLedgerWithRow(t *testing.T) {
	svc, st, _ := lifetimeHarness(t)
	ctx := context.Background()
	vol := attachVolume(t, svc, st, "sb-solo", "solo", false)
	if err := svc.DeletePlatformVolume(ctx, vol.ID); !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("attached delete = %v, want in use", err)
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
		t.Fatalf("a refused delete wrote a ledger row: %+v", pending)
	}
	if err := svc.volumeMeta().DeleteAttachmentsForSandbox(ctx, "sb-solo", "inc-sb-solo"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeletePlatformVolume(ctx, vol.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil || len(pending) != 1 || pending[0].VolumeID != vol.ID || pending[0].Source != vol.Source {
		t.Fatalf("ledger = %+v, %v", pending, err)
	}
	if volumeExists(t, svc, vol) {
		t.Fatal("the row must be gone")
	}
}
