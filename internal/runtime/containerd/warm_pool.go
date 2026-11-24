package containerd

import (
	"context"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
)

// WarmPool is the Phase 3 park/adopt seam. Nil disables warm acquisition.
type WarmPool interface {
	HasReady(key containerdpool.Key) bool
	Acquire(ctx context.Context, key containerdpool.Key, imageID string) (*containerdpool.ParkedSlot, error)
	NoteMiss(key containerdpool.Key)
	ReleasePark(slotID string)
	// RetainFailedDestroy takes back an acquired slot whose teardown
	// failed; the pool retries it and releases the reservation once the
	// container is gone (dockerpool pending_destroy.go).
	RetainFailedDestroy(slot *containerdpool.ParkedSlot, err error)
}

// SetWarmPool wires the containerd warm pool (Phase 3). Nil disables it.
func (d *Driver) SetWarmPool(p WarmPool) {
	if d == nil {
		return
	}
	d.warmPool = p
}
