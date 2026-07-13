// Package netns manages the per-host pool of prepaid network namespaces for
// the containerd engine. Bookkeeping lives in SQLite (container_netns_slots);
// CNI ADD/DEL and netns creation live in host.go — the same pool.go/host.go
// split as internal/network/tap.
package netns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

const slotNamePrefix = "aerol-netns-"

// SeedConfig describes how many native netns slots to pre-create at boot.
type SeedConfig struct {
	PoolSize int
}

// Pool is the policy layer over container_netns_slots.
type Pool struct {
	st *store.Store
}

func New(st *store.Store) *Pool {
	return &Pool{st: st}
}

// Seed lays out PoolSize free slots. Idempotent on slot_id PK.
func (p *Pool) Seed(ctx context.Context, cfg SeedConfig, now time.Time) error {
	if cfg.PoolSize <= 0 {
		return errors.New("netns: SeedConfig.PoolSize must be > 0")
	}
	if cfg.PoolSize > 10000 {
		return fmt.Errorf("netns: SeedConfig.PoolSize=%d exceeds 10000 cap", cfg.PoolSize)
	}
	for i := 0; i < cfg.PoolSize; i++ {
		slotID := fmt.Sprintf("%s%d", slotNamePrefix, i)
		if err := p.st.SeedContainerNetnsSlot(ctx, slotID, now); err != nil {
			return fmt.Errorf("netns: seed slot %d: %w", i, err)
		}
	}
	return nil
}

// Slot is the pool-level view of a claimed netns slot.
type Slot struct {
	SlotID      string
	NetnsPath   string
	ContainerIP string
	SandboxID   string
	State       string
}

// Reserve claims a slot for sandboxID. Idempotent for the same sandbox.
func (p *Pool) Reserve(ctx context.Context, sandboxID string, now time.Time) (*Slot, error) {
	raw, err := p.st.ReserveContainerNetnsSlot(ctx, sandboxID, now)
	if err != nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// MarkRealized records CNI output after host realization.
func (p *Pool) MarkRealized(ctx context.Context, sandboxID, netnsPath, containerIP string, now time.Time) (*Slot, error) {
	raw, err := p.st.MarkContainerNetnsSlotRealized(ctx, sandboxID, netnsPath, containerIP, now)
	if err != nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// Adopt marks the slot adopted once the container task is running.
func (p *Pool) Adopt(ctx context.Context, sandboxID string, now time.Time) (*Slot, error) {
	raw, err := p.st.AdoptContainerNetnsSlot(ctx, sandboxID, now)
	if err != nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// Get returns the slot owned by sandboxID, or nil.
func (p *Pool) Get(ctx context.Context, sandboxID string) (*Slot, error) {
	raw, err := p.st.GetContainerNetnsSlotBySandbox(ctx, sandboxID)
	if err != nil || raw == nil {
		return nil, err
	}
	return slotFromStore(raw), nil
}

// Release returns a sandbox's slot to the pool. Idempotent.
func (p *Pool) Release(ctx context.Context, sandboxID string, now time.Time) error {
	return p.st.ReleaseContainerNetnsSlot(ctx, sandboxID, now)
}

// ReassignOwner moves an adopted slot from a park slot id to the real sandbox id.
func (p *Pool) ReassignOwner(ctx context.Context, fromSandboxID, toSandboxID string, now time.Time) error {
	if p == nil || p.st == nil {
		return nil
	}
	return p.st.ReassignContainerNetnsSandbox(ctx, fromSandboxID, toSandboxID, now)
}

type Stats = store.ContainerNetnsPoolStats

func (p *Pool) Stats(ctx context.Context) (Stats, error) {
	return p.st.GetContainerNetnsPoolStats(ctx)
}

func slotFromStore(s *store.ContainerNetnsSlot) *Slot {
	if s == nil {
		return nil
	}
	return &Slot{
		SlotID:      s.SlotID,
		NetnsPath:   s.NetnsPath,
		ContainerIP: s.ContainerIP,
		SandboxID:   s.SandboxID,
		State:       s.State,
	}
}
