package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

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
