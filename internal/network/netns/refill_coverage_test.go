package netns

import (
	"context"
	"testing"
	"time"
)

func TestRefillerRunDefaultIntervalCoverage95(t *testing.T) {
	// depth 0 → refillOnce no-ops after the interval<=0 default is applied.
	r := NewRefiller(testPool(t, 1), NewFakeHost(), 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refiller did not stop")
	}
}
