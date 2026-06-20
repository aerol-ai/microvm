package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeReclaimer struct {
	calls []struct{ backend, source string }
	fail  map[string]error
}

func (f *fakeReclaimer) Reclaim(_ context.Context, backend, source string) error {
	f.calls = append(f.calls, struct{ backend, source string }{backend, source})
	if f.fail != nil {
		if err, ok := f.fail[source]; ok {
			return err
		}
	}
	return nil
}

// schedulePending deletes a volume (writing its ledger row) without leaving a
// live row, then returns the store to a clean slate for the worker to drain.
func seedDeletedVolume(t *testing.T, s *Service, id, name, source string) {
	t.Helper()
	ctx := context.Background()
	if err := s.store.CreateVolume(ctx, &models.Volume{ID: id, Tenant: "t-a", Name: name, Backend: "s3", Source: source}); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if err := s.store.DeleteVolumeIfUnattached(ctx, "t-a", id, ""); err != nil {
		t.Fatalf("DeleteVolumeIfUnattached: %v", err)
	}
}

func TestRunVolumeReclaimDeletesBackendThenLedger(t *testing.T) {
	s := enabledVolumeService(t)
	s.logger = slog.Default()
	fr := &fakeReclaimer{}
	s.SetVolumeReclaimer(fr)
	ctx := context.Background()

	seedDeletedVolume(t, s, "v1", "data", "aerol-volumes/volumes/t-a/data")

	s.runVolumeReclaim(ctx)

	if len(fr.calls) != 1 || fr.calls[0].source != "aerol-volumes/volumes/t-a/data" {
		t.Fatalf("reclaimer calls = %+v, want one for the source", fr.calls)
	}
	pending, _ := s.store.ListPendingVolumeDeletions(ctx)
	if len(pending) != 0 {
		t.Fatalf("ledger not drained: %+v", pending)
	}
}

func TestRunVolumeReclaimSkipsLiveSource(t *testing.T) {
	s := enabledVolumeService(t)
	s.logger = slog.Default()
	fr := &fakeReclaimer{}
	s.SetVolumeReclaimer(fr)
	ctx := context.Background()

	source := "aerol-volumes/volumes/t-a/data"
	seedDeletedVolume(t, s, "v-old", "data", source)
	// Recreate the same name → new live row pointing at the same source.
	if _, _, err := s.store.GetOrCreateVolume(ctx, &models.Volume{ID: "v-new", Tenant: "t-a", Name: "data", Backend: "s3", Source: source}, 0); err != nil {
		t.Fatalf("recreate: %v", err)
	}

	s.runVolumeReclaim(ctx)

	if len(fr.calls) != 0 {
		t.Fatalf("reclaimer must not touch live source, got %+v", fr.calls)
	}
	pending, _ := s.store.ListPendingVolumeDeletions(ctx)
	if len(pending) != 0 {
		t.Fatalf("stale ledger row should be cleared: %+v", pending)
	}
}

func TestRunVolumeReclaimKeepsLedgerWhenDeleteStillApplying(t *testing.T) {
	s := enabledVolumeService(t)
	s.cfg.EnableCluster = true
	s.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	s.logger = slog.Default()
	fr := &fakeReclaimer{}
	s.SetVolumeReclaimer(fr)
	ctx := context.Background()

	v, err := s.CreatePlatformVolume(ctx, "data")
	if err != nil {
		t.Fatalf("CreatePlatformVolume: %v", err)
	}
	if err := s.store.SchedulePendingVolumeDeletion(ctx, *v, v.Source); err != nil {
		t.Fatalf("SchedulePendingVolumeDeletion: %v", err)
	}

	s.runVolumeReclaim(ctx)

	if len(fr.calls) != 0 {
		t.Fatalf("reclaimer must not run before delete applies, got %+v", fr.calls)
	}
	pending, _ := s.store.ListPendingVolumeDeletions(ctx)
	if len(pending) != 1 {
		t.Fatalf("ledger row should remain while same volume is live: %+v", pending)
	}
}

func TestRunVolumeReclaimRetainsRowOnFailure(t *testing.T) {
	s := enabledVolumeService(t)
	s.logger = slog.Default()
	source := "aerol-volumes/volumes/t-a/data"
	fr := &fakeReclaimer{fail: map[string]error{source: errors.New("backend down")}}
	s.SetVolumeReclaimer(fr)
	ctx := context.Background()

	seedDeletedVolume(t, s, "v1", "data", source)

	s.runVolumeReclaim(ctx)

	pending, _ := s.store.ListPendingVolumeDeletions(ctx)
	if len(pending) != 1 {
		t.Fatalf("failed reclaim must retain ledger row for retry: %+v", pending)
	}
}

func TestStartVolumeReclaimNoOpWithoutReclaimer(t *testing.T) {
	s := enabledVolumeService(t)
	s.logger = slog.Default()
	// No reclaimer wired → must not panic or start anything.
	s.StartVolumeReclaim(context.Background())
}
