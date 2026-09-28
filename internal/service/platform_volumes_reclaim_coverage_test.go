package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestRunVolumeReclaimCancelAndConcurrency(t *testing.T) {
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.SetVolumeReclaimer(&fakeReclaimer{})
	s.cfg.PlatformVolumes.ReclaimConcurrency = 4
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		seedDeletedVolume(t, s, fmt.Sprintf("v%d", i), fmt.Sprintf("n%d", i), fmt.Sprintf("aerol-volumes/volumes/t-a/n%d", i))
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	s.runVolumeReclaim(cancelCtx)

	seedDeletedVolume(t, s, "vx", "nx", "aerol-volumes/volumes/t-a/nx")
	s.runVolumeReclaim(ctx)
}

func TestStartVolumeReclaimEnabled(t *testing.T) {
	s := enabledVolumeService(t)
	harness, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	s.logger = harness.logger
	s.SetVolumeReclaimer(&fakeReclaimer{})
	s.cfg.PlatformVolumes.ReclaimInterval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.StartVolumeReclaim(ctx)
	time.Sleep(20 * time.Millisecond)

	// Non-positive interval is a no-op even with a reclaimer.
	s.cfg.PlatformVolumes.ReclaimInterval = 0
	s.StartVolumeReclaim(context.Background())
}

func TestVolumeReclaimCancelAndFailWave15(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := enabledVolumeService(t)
	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := time.Now().UTC()
	if err := s.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
		ID: "vol-cancel", Tenant: "op", Name: "n", Backend: "local", Source: "/tmp/x",
		CreatedAt: now,
	}, "/tmp/x"); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	cancel()
	s.runVolumeReclaim(ctx)

	s2 := enabledVolumeService(t)
	if s2.logger == nil {
		s2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	_ = s2.store.Close()
	s2.reclaimOne(context.Background(), models.PendingVolumeDeletion{
		VolumeID: "v", Tenant: "op", Backend: "local", Source: "/nope",
	})
}

// blockingVolumeReclaimer holds the first Reclaim until released so
// runVolumeReclaim's ctx.Done arm can win the select on a subsequent job.
// blockingVolumeReclaimer holds the first Reclaim until released so
// runVolumeReclaim's ctx.Done arm can win the select on a subsequent job.
type blockingVolumeReclaimer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingVolumeReclaimer) Reclaim(context.Context, string, string) error {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return nil
}

// scriptedVolumeMeta drives reclaimOne branches: ByID not-found then
// ExistsForSource / DeletePending failure arms.
// scriptedVolumeMeta drives reclaimOne branches: ByID not-found then
// ExistsForSource / DeletePending failure arms.
type scriptedVolumeMeta struct {
	byIDErr            error
	byID               *models.Volume
	exists             bool
	existsErr          error
	deleteAttachErr    error
	putAttachmentsErr  error
	deleteRowErr       error
	getOrCreateErr     error
	byNameErr          error
	listErr            error
	attachmentCount    int
	attachmentCountErr error
}

func (m *scriptedVolumeMeta) GetOrCreate(context.Context, *models.Volume, int) (*models.Volume, bool, error) {
	return nil, false, m.getOrCreateErr
}

func (m *scriptedVolumeMeta) ByID(context.Context, string, string) (*models.Volume, error) {
	if m.byIDErr != nil {
		return nil, m.byIDErr
	}
	return m.byID, nil
}

func (m *scriptedVolumeMeta) ByName(context.Context, string, string) (*models.Volume, error) {
	return nil, m.byNameErr
}

func (m *scriptedVolumeMeta) List(context.Context, string) ([]models.Volume, error) {
	return nil, m.listErr
}

func (m *scriptedVolumeMeta) DeleteRow(context.Context, string, string) error {
	return m.deleteRowErr
}

func (m *scriptedVolumeMeta) ExistsForSource(context.Context, string) (bool, error) {
	return m.exists, m.existsErr
}

func (m *scriptedVolumeMeta) AttachmentCount(context.Context, string, string) (int, error) {
	return m.attachmentCount, m.attachmentCountErr
}

func (m *scriptedVolumeMeta) PutAttachments(context.Context, []models.VolumeAttachment) error {
	return m.putAttachmentsErr
}

func (m *scriptedVolumeMeta) DeleteAttachmentsForSandbox(context.Context, string, string) error {
	return m.deleteAttachErr
}

func TestVolumeReclaimCancelSweepLimitAndMetaWave20(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	blocker := &blockingVolumeReclaimer{started: make(chan struct{}), release: make(chan struct{})}
	s.SetVolumeReclaimer(blocker)
	s.cfg.PlatformVolumes.ReclaimConcurrency = 1

	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		id := "vol-blk-" + string(rune('a'+i))
		src := "/tmp/wave20-" + id
		if err := s.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
			ID: id, Tenant: "op", Name: id, Backend: "local", Source: src, CreatedAt: now,
		}, src); err != nil {
			t.Fatalf("schedule %s: %v", id, err)
		}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-blocker.started
		cancel()
		close(blocker.release) // unblock worker so runVolumeReclaim's Wait returns
	}()
	s.runVolumeReclaim(cancelCtx)

	// Sweep-limit truncation arm: seed > volumeReclaimSweepLimit rows.
	s2 := enabledVolumeService(t)
	s2.logger = s.logger
	s2.SetVolumeReclaimer(&fakeReclaimer{})
	s2.cfg.PlatformVolumes.ReclaimConcurrency = 2
	for i := 0; i < volumeReclaimSweepLimit+3; i++ {
		id := "vol-lim-" + itoaWave20(i)
		src := "/tmp/lim-" + id
		_ = s2.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
			ID: id, Tenant: "op", Name: id, Backend: "local", Source: src, CreatedAt: now,
		}, src)
	}
	s2.runVolumeReclaim(ctx)

	// reclaimOne: ByID not found + ExistsForSource error.
	s3 := enabledVolumeService(t)
	s3.logger = s.logger
	s3.SetVolumeReclaimer(&fakeReclaimer{})
	s3.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound, existsErr: errors.New("exists boom")}
	s3.reclaimOne(ctx, models.PendingVolumeDeletion{VolumeID: "v", Tenant: "op", Source: "/x", Backend: "local"})

	// reclaimOne: live source + DeletePending failure (close store after meta says live).
	s4 := enabledVolumeService(t)
	s4.logger = s.logger
	s4.SetVolumeReclaimer(&fakeReclaimer{})
	s4.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound, exists: true}
	_ = s4.store.Close()
	s4.reclaimOne(ctx, models.PendingVolumeDeletion{VolumeID: "v2", Tenant: "op", Source: "/y", Backend: "local"})

	// reclaimOne: reclaim ok + DeletePending failure.
	s5 := enabledVolumeService(t)
	s5.logger = s.logger
	s5.SetVolumeReclaimer(&fakeReclaimer{})
	s5.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound, exists: false}
	_ = s5.store.Close()
	s5.reclaimOne(ctx, models.PendingVolumeDeletion{VolumeID: "v3", Tenant: "op", Source: "/z", Backend: "local"})
}

func itoaWave20(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func TestVolumeReclaimWorkersClampWave21(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.SetVolumeReclaimer(&fakeReclaimer{})
	s.cfg.PlatformVolumes.ReclaimConcurrency = 50
	now := time.Now().UTC()
	_ = s.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
		ID: "one", Tenant: "op", Name: "one", Backend: "local", Source: "/tmp/one", CreatedAt: now,
	}, "/tmp/one")
	s.runVolumeReclaim(ctx)
}

func TestReclaimOneLiveSourceCheckError(t *testing.T) {
	s := enabledVolumeService(t)
	harness, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	s.logger = harness.logger
	s.SetVolumeReclaimer(&fakeReclaimer{})
	ctx := context.Background()
	seedDeletedVolume(t, s, "v-err", "n-err", "aerol-volumes/volumes/t-a/n-err")

	// Close store so ExistsForSource / ByID fail → reclaimOne warn+return arms.
	_ = s.store.Close()
	pending := models.PendingVolumeDeletion{
		VolumeID: "v-err", Tenant: "t-a", Name: "n-err",
		Backend: "s3", Source: "aerol-volumes/volumes/t-a/n-err",
	}
	s.reclaimOne(ctx, pending)
}
