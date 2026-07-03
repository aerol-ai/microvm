package firecracker

import (
	"context"
)

type toolboxTCPProbeFunc func(ctx context.Context, operation, sandboxID string, slot *TapSlot, snapshotLoad bool)

func (d *Driver) scheduleToolboxTCPProbe(operation, sandboxID string, slot *TapSlot, snapshotLoad bool) {
	if slot == nil || slot.GuestIP == "" || d.cfg.PostResumeTimeout <= 0 {
		return
	}
	probe := d.toolboxTCPProbe
	if probe == nil {
		probe = d.probeToolboxTCP
	}
	slotCopy := *slot
	timeout := d.cfg.PostResumeTimeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		probe(ctx, operation, sandboxID, &slotCopy, snapshotLoad)
	}()
}
