package netns

import (
	"context"
	"time"
)

// RuntimeHandoff adapts the native netns pool to the containerd driver's
// NetnsHandoff seam: Provision runs the reserve→realize→adopt FSM; Release
// tears down host resources and returns the slot to the free pool.
type RuntimeHandoff struct {
	builder *Builder
	pool    *Pool
	host    HostManager
	now     func() time.Time
}

func NewRuntimeHandoff(pool *Pool, host HostManager) *RuntimeHandoff {
	return &RuntimeHandoff{
		builder: NewBuilder(pool, host),
		pool:    pool,
		host:    host,
		now:     func() time.Time { return timeNow() },
	}
}

func (h *RuntimeHandoff) Provision(ctx context.Context, sandboxID string) (netnsPath, containerIP string, err error) {
	if h == nil || h.builder == nil {
		return "", "", nil
	}
	now := h.now()
	// Treat a claim as a ready hit only when the slot is actually realized
	// (non-empty netns path AND IP). ClaimPooled/Reserve short-circuit on any
	// existing row for the sandbox regardless of state, so a crash-left
	// reserved/empty slot would otherwise be returned as a "hit" and the caller
	// would build a container with no netns pin and no IP. Falling through to
	// Build re-drives the FSM for the owned slot (Reserve returns it, then
	// Realize/Adopt).
	if slot, hit, err := h.pool.ClaimPooled(ctx, sandboxID, now); err != nil {
		return "", "", err
	} else if hit && slot != nil && slot.NetnsPath != "" && slot.ContainerIP != "" {
		return slot.NetnsPath, slot.ContainerIP, nil
	}
	slot, err := h.builder.Build(ctx, sandboxID)
	if err != nil {
		return "", "", err
	}
	return slot.NetnsPath, slot.ContainerIP, nil
}

// Release tears down sandboxID's netns and returns the slot to the pool.
// Idempotent. The host teardown uses the identity CNI ADD used (which is NOT
// sandboxID for a claimed prewarmed slot or an adopted warm-park slot). If it
// fails, the slot is parked as releasing and retried by the refiller rather
// than freed with its lease and NAT chain still on the node; Release still
// returns nil then, because the failure is owned by the retry from here on.
func (h *RuntimeHandoff) Release(ctx context.Context, sandboxID string) error {
	if h == nil || h.pool == nil {
		return nil
	}
	slot, err := h.pool.Get(ctx, sandboxID)
	if err != nil {
		return err
	}
	if slot == nil {
		return nil
	}
	locked := slot.SlotID
	if releaseAfterGet != nil {
		releaseAfterGet(locked)
	}
	unlock := h.pool.lockSlot(locked)
	defer unlock()
	// Re-read under the lock: a concurrent Release for the same sandbox may
	// have freed the slot while we waited, and the refiller may already have
	// re-realized it for someone else. Only the current owner may tear down,
	// and only the slot this lock covers.
	slot, err = h.pool.Get(ctx, sandboxID)
	if err != nil {
		return err
	}
	if slot == nil || slot.SlotID != locked {
		return nil
	}
	free := func() error { return h.pool.Release(ctx, sandboxID, h.now()) }
	if h.host == nil {
		return free()
	}
	_ = h.pool.teardown(ctx, h.host, *slot, sandboxID, free, h.now())
	return nil
}

// releaseAfterGet is set only by tests, to change the slot's ownership in the
// window between Release's first read and its lock.
var releaseAfterGet func(slotID string)

// ReassignOwner transfers netns slot ownership from a park slot id to the
// adopted sandbox id (rename-free warm adopt).
func (h *RuntimeHandoff) ReassignOwner(ctx context.Context, fromSandboxID, toSandboxID string) error {
	if h == nil || h.pool == nil {
		return nil
	}
	return h.pool.ReassignOwner(ctx, fromSandboxID, toSandboxID, h.now())
}
