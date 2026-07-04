package wasm

import (
	"context"
	"errors"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
)

// WarmPool is the seam Driver.Create uses for pre-compiled worker hits.
// Production wiring uses *wasmpool.Pool; tests inject a fake.
type WarmPool interface {
	NoteModule(digest, modulePath string)
	Acquire(ctx context.Context, digest, modulePath string, memoryMB int) (*wasmpool.Slot, error)
}

// SetWarmPool injects the warm worker pool. Nil leaves every create on the cold path.
func (d *Driver) SetWarmPool(p WarmPool) { d.warmPool = p }

// tryAcquireWarm returns a warm slot on hit, (nil, nil) on miss.
func (d *Driver) tryAcquireWarm(ctx context.Context, digest, modulePath string, memoryMB int) (*wasmpool.Slot, error) {
	if d.warmPool == nil || digest == "" {
		return nil, nil
	}
	d.warmPool.NoteModule(digest, modulePath)
	slot, err := d.warmPool.Acquire(ctx, digest, modulePath, memoryMB)
	if err == nil {
		d.logger.Info("wasm create: warm pool hit",
			"digest", digest, "slot_id", slot.ID, "socket", slot.SocketPath)
		return slot, nil
	}
	if errors.Is(err, wasmpool.ErrNoSlot) {
		d.logger.Debug("wasm create: warm pool miss", "digest", digest)
		return nil, nil
	}
	return nil, err
}
