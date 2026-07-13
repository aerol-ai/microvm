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
	if h.host != nil {
		_ = h.host.Remove(ctx, *slot)
	}
	return h.pool.Release(ctx, sandboxID, h.now())
}

// ReassignOwner transfers netns slot ownership from a park slot id to the
// adopted sandbox id (rename-free warm adopt).
func (h *RuntimeHandoff) ReassignOwner(ctx context.Context, fromSandboxID, toSandboxID string) error {
	if h == nil || h.pool == nil {
		return nil
	}
	return h.pool.ReassignOwner(ctx, fromSandboxID, toSandboxID, h.now())
}
