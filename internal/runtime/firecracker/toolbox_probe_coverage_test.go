package firecracker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduleToolboxTCPProbe_DefaultAndNoops(t *testing.T) {
	d := New(Config{PostResumeTimeout: 0}, nil)
	d.scheduleToolboxTCPProbe("create", "sb", nil, false)
	d.scheduleToolboxTCPProbe("create", "sb", &TapSlot{}, false)

	var called atomic.Int32
	d.cfg.PostResumeTimeout = 30 * time.Millisecond
	d.toolboxTCPProbe = func(ctx context.Context, operation, sandboxID string, slot *TapSlot, snapshotLoad bool) {
		called.Add(1)
		if operation != "warm" || sandboxID != "sb-probe" || slot == nil || !snapshotLoad {
			t.Fatalf("probe args = %q %q %+v %v", operation, sandboxID, slot, snapshotLoad)
		}
		<-ctx.Done()
	}
	d.scheduleToolboxTCPProbe("warm", "sb-probe", &TapSlot{GuestIP: "10.0.0.2", TapName: "tap0"}, true)
	deadline := time.Now().Add(time.Second)
	for called.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if called.Load() != 1 {
		t.Fatalf("default probe wrapper calls = %d, want 1", called.Load())
	}

	// Nil toolboxTCPProbe exercises the default probe path (no panic).
	d.toolboxTCPProbe = nil
	d.cfg.PostResumeTimeout = 1 * time.Millisecond
	d.scheduleToolboxTCPProbe("create", "sb-default", &TapSlot{GuestIP: "127.0.0.1"}, false)
	time.Sleep(20 * time.Millisecond)
}
