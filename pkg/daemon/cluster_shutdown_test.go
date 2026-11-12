package daemon

import (
	"context"
	"testing"
	"time"
)

type fakeShutdownPreparer struct {
	calls    int
	deadline time.Time
}

func (f *fakeShutdownPreparer) PrepareShutdown(ctx context.Context) {
	f.calls++
	f.deadline, _ = ctx.Deadline()
}

func TestPrepareClusterShutdown(t *testing.T) {
	// Outside cluster mode there is no client: nothing to do.
	prepareClusterShutdown(nil)

	f := &fakeShutdownPreparer{}
	start := time.Now()
	prepareClusterShutdown(f)
	if f.calls != 1 {
		t.Fatalf("calls = %d, want 1", f.calls)
	}
	// Bounded, so a stuck hand-off cannot eat the whole termination grace.
	if f.deadline.IsZero() || f.deadline.Sub(start) > clusterShutdownBudget+time.Second {
		t.Fatalf("deadline %v, want within %s", f.deadline, clusterShutdownBudget)
	}
}
