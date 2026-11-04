package service

import (
	"context"
	"errors"
	"testing"
	"time"
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
