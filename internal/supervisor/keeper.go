package supervisor

import (
	"context"
	"log/slog"
	"time"
)

// Keeper runs one long-lived child, containerd, and starts it again whenever
// it exits. Sandboxes do not need containerd while it is away: each belongs
// to its own shim. The supervisor never gives up on it, because it has no
// better move than trying again; the wait between tries grows to MaxBackoff
// and resets once a run lasts HealthyAfter.
type Keeper struct {
	// Start starts the child and returns its pid.
	Start func() (int, error)
	// Exited delivers the pid of each child the reaper collected.
	Exited <-chan int
	// Stop asks the child to stop when the supervisor itself is told to.
	Stop func(pid int)
	Log  *slog.Logger

	MinBackoff, MaxBackoff, HealthyAfter time.Duration
	// Now and After are the clock, replaced in tests.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
}

// Run keeps the child up until ctx ends, then stops it and returns.
func (k *Keeper) Run(ctx context.Context) {
	now, after := k.Now, k.After
	if now == nil {
		now = time.Now
	}
	if after == nil {
		after = time.After
	}
	backoff := k.MinBackoff
	for {
		started := now()
		pid, err := k.Start()
		if err != nil {
			k.Log.Error("supervisor: containerd did not start; trying again", "error", err, "in", backoff)
		} else {
			k.Log.Info("supervisor: containerd started", "pid", pid)
			if !k.waitExit(ctx, pid) {
				k.Stop(pid)
				return
			}
			if now().Sub(started) >= k.HealthyAfter {
				backoff = k.MinBackoff
			}
			k.Log.Warn("supervisor: containerd exited; sandboxes keep running; starting it again", "pid", pid, "in", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-after(backoff):
		}
		backoff = min(backoff*2, k.MaxBackoff)
	}
}

// waitExit waits for pid to be reaped; false when ctx ended first.
func (k *Keeper) waitExit(ctx context.Context, pid int) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case p := <-k.Exited:
			if p == pid {
				return true
			}
		}
	}
}
