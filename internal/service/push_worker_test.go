package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A wake-up still pending when the worker's context ends starts no sweep.
// TestSnapshotPushWorkerRunsOnKick failed on main (run 41805513298) when
// select picked the pending wake-up over ctx.Done and the sweep reported
// "context canceled". select is random, so try it many times.
func TestPushWorkerStopsWithAWakeUpPending(t *testing.T) {
	for range 200 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		wake := make(chan struct{}, 1)
		wake <- struct{}{}
		swept := 0
		runPushWorker(ctx, time.Hour, wake, func(context.Context) { swept++ })
		if swept != 0 {
			t.Fatalf("the worker swept %d times after its context ended", swept)
		}
	}
}

// cancellingPushStore ends the worker's context from inside the sweep's list
// call: a shutdown landing while a sweep runs.
type cancellingPushStore struct {
	*fakePushStore
	cancel context.CancelFunc
}

func (s cancellingPushStore) ListSnapshotsPendingPushPage(ctx context.Context, _ store.SnapshotPushCursor, _ int) ([]*models.SandboxSnapshot, error) {
	s.cancel()
	<-ctx.Done()
	return nil, fmt.Errorf("iterate snapshots: %w", ctx.Err())
}

// A sweep that a shutdown cuts short is not reported as a failed sweep; one
// that fails while the worker runs still is. TestSnapshotPushWorkerRunsOnKick
// failed on #916's first commit when the test's cancel landed mid-sweep.
func TestPushWorkerReportsNoFailureForASweepCutShortByShutdown(t *testing.T) {
	t.Run("cut short by shutdown", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rec := newTestReconcilerN(t, cancellingPushStore{newFakePushStore(), cancel}, &fakeSnapshotPushDocker{}, 1)
		rec.Kick()
		var reports []error
		rec.Run(ctx, time.Hour, func(_ SnapshotPushReconcileStats, err error) { reports = append(reports, err) })
		if len(reports) != 0 {
			t.Fatalf("a sweep cut short by shutdown was reported: %v", reports)
		}
	})
	t.Run("failed while running", func(t *testing.T) {
		st := newFakePushStore()
		st.listErr = errors.New("disk I/O error")
		rec := newTestReconcilerN(t, st, &fakeSnapshotPushDocker{}, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rec.Kick()
		var got error
		rec.Run(ctx, time.Hour, func(_ SnapshotPushReconcileStats, err error) {
			got = err
			cancel()
		})
		if !errors.Is(got, st.listErr) {
			t.Fatalf("reported %v, want the list failure", got)
		}
	})
}

// A sweep waiting for a slot gives up when its context ends.
func TestAcquirePushSlotGivesUpWithItsContext(t *testing.T) {
	slots := make(chan struct{}, 1)
	if err := acquirePushSlot(context.Background(), slots); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if err := acquirePushSlot(ctx, slots); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire with every slot taken = %v, want the cancellation", err)
	}
}
