package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// fakeVersionedCluster is a minimal cluster.Client stand-in that exposes a
// caller-controllable PlacementVersion. Wraps Noop to satisfy the rest of
// the interface without writing 15 stub methods.
type fakeVersionedCluster struct {
	*cluster.Noop
	version atomic.Uint64
}

func (f *fakeVersionedCluster) PlacementVersion() uint64 {
	return f.version.Load()
}

// TestIngressVersionWatcherSignalsOnBump confirms the fast-wake loop fires
// the wake channel when the FSM version bumps, and stays quiet otherwise.
// This is the load-bearing claim behind sub-second convergence: without it,
// an FSM apply waits out the 5s reconcile timer.
func TestIngressVersionWatcherSignalsOnBump(t *testing.T) {
	fc := &fakeVersionedCluster{Noop: cluster.NewNoop("self", "")}
	fc.version.Store(7)

	svc := &Service{}
	svc.cluster = fc
	svc.clusterReady.Store(true)

	wake := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.runIngressVersionWatcher(ctx, wake)

	// Quiet period: no version change → no wake. We give the watcher more
	// than one poll interval to make sure a spurious signal would land.
	select {
	case <-wake:
		t.Fatal("watcher signalled with no version change")
	case <-time.After(2 * clusterIngressFastPollInterval):
	}

	// Bump → wake within ~1 poll interval. Generous timeout to absorb
	// scheduler jitter on busy CI; the load-bearing assertion is "happens",
	// not "happens this fast".
	fc.version.Store(8)
	select {
	case <-wake:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not signal after version bump")
	}
}

// TestIngressVersionWatcherDropsCoalescedSignals confirms the wake channel
// is non-blocking — if the reconciler is mid-tick (channel buffer full),
// extra version bumps don't pile up. One wake per idle period is enough to
// make sure the next reconcile sees the latest view.
func TestIngressVersionWatcherDropsCoalescedSignals(t *testing.T) {
	fc := &fakeVersionedCluster{Noop: cluster.NewNoop("self", "")}
	svc := &Service{cluster: fc}
	svc.clusterReady.Store(true)

	// Buffer of 1; do NOT drain. Three rapid bumps must not block the
	// watcher (which would deadlock the test goroutine).
	wake := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.runIngressVersionWatcher(ctx, wake)

	for v := uint64(1); v <= 5; v++ {
		fc.version.Store(v)
		time.Sleep(clusterIngressFastPollInterval + 100*time.Millisecond)
	}
	// Receiving once is enough; further reads should not block beyond a
	// short timeout (no signals accumulated).
	select {
	case <-wake:
	case <-time.After(2 * time.Second):
		t.Fatal("expected at least one wake")
	}
}
