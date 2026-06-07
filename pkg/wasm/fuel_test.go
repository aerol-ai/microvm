package wasm

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimitPages(t *testing.T) {
	if got := MemoryLimitPages(0); got != 0 {
		t.Fatalf("zero mem: got %d pages", got)
	}
	if got := MemoryLimitPages(1); got != 16 {
		t.Fatalf("1 MiB: got %d pages, want 16", got)
	}
}

func TestWithInvocationDeadlineHonorsCaps(t *testing.T) {
	caps := Capabilities{WallTimeoutNs: int64(50 * time.Millisecond)}
	ctx, cancel := WithInvocationDeadline(context.Background(), caps)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected deadline")
	}
	if d := time.Until(deadline); d > 100*time.Millisecond || d < 0 {
		t.Fatalf("unexpected deadline distance: %v", d)
	}
}

func TestCapsFromResourceLimits(t *testing.T) {
	caps := CapsFromResourceLimits(Capabilities{Args: []string{"a"}}, 128, 2*time.Second)
	if caps.MemoryMB != 128 {
		t.Fatalf("memory = %d", caps.MemoryMB)
	}
	if caps.WallTimeoutNs != (2 * time.Second).Nanoseconds() {
		t.Fatalf("timeout ns = %d", caps.WallTimeoutNs)
	}
}
