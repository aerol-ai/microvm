// Package netns manages the per-host pool of prepaid network namespaces for
// the containerd engine. Bookkeeping lives in SQLite (container_netns_slots);
// CNI ADD/DEL and netns creation live in host.go — the same pool.go/host.go
// split as internal/network/tap.
package netns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
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

	// slotLocks serializes every host mutation of one slot (realize, remove)
	// with the ownership re-check that precedes it. Without it a delayed
	// duplicate Release could run CNI DEL on a slot that another Release
	// already freed and the refiller re-realized for a different sandbox,
	// tearing down that sandbox's network. Keyed by slot id, so it is bounded
	// by the seeded pool size.
	slotLocks sync.Map // slot id -> *sync.Mutex

	logMu  sync.RWMutex
	logger *slog.Logger
}

func New(st *store.Store) *Pool {
	return &Pool{st: st}
}

// SetLogger routes the pool's teardown warnings (failed CNI DEL / netns
// delete) to logger. Nil restores the discard default.
func (p *Pool) SetLogger(logger *slog.Logger) {
	if p == nil {
		return
	}
	p.logMu.Lock()
	p.logger = logger
	p.logMu.Unlock()
}

func (p *Pool) log() *slog.Logger {
	if p != nil {
		p.logMu.RLock()
		l := p.logger
		p.logMu.RUnlock()
		if l != nil {
			return l
		}
	}
	return discardLogger
}

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// lockSlot takes the per-slot host-mutation lock and returns its release.
func (p *Pool) lockSlot(slotID string) func() {
	v, _ := p.slotLocks.LoadOrStore(slotID, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
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

// netnsName is the one identity a slot's host state is keyed by: the named
// netns (/run/netns/<name>) AND the CNI container id. CNI keys the
// host-local IP lease and the bridge plugin's masquerade chain by container
// id, so DEL must pass exactly the id ADD used or both outlive the slot.
//
// Realize names the netns after the slot's owner AT REALIZE TIME and
// records <root>/<name> as netns_path. That owner is not stable: a prewarmed
// slot is realized as "aerol-netns-N" and later claimed by a sandbox, and a
// warm-park slot is realized as the park id and later reassigned to the
// adopting sandbox. The recorded path is the only part that never changes,
// so once it exists it wins; before it is recorded (crash between ADD and
// the store write), the row's owner is still the realize-time name.
func (s Slot) netnsName() string {
	if p := strings.TrimSpace(s.NetnsPath); p != "" {
		return filepath.Base(p)
	}
	if id := strings.TrimSpace(s.SandboxID); id != "" {
		return id
	}
	return strings.TrimSpace(s.SlotID)
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

// Release returns a sandbox's slot to the pool. Idempotent. It only moves the
// row; callers that own host state go through teardown.
func (p *Pool) Release(ctx context.Context, sandboxID string, now time.Time) error {
	return p.st.ReleaseContainerNetnsSlot(ctx, sandboxID, now)
}

// netnsPathResolver lets teardown persist where a slot's netns lives even
// when the row never recorded it (crash between CNI ADD and the store write).
type netnsPathResolver interface {
	netnsPathFor(name string) string
}

// teardown removes slot's host state, then frees the row with free — but only
// once Remove succeeded. A failed Remove is logged and the row is parked as
// releasing (no owner, identity kept) so no sandbox is handed a slot whose
// CNI lease, masquerade chain or netns still exist; RetryReleasing frees it
// once a later Remove succeeds. owner is the row's sandbox_id as the caller
// read it ("" for an ownerless pooled row). Callers hold the slot lock.
func (p *Pool) teardown(ctx context.Context, host HostManager, slot Slot, owner string, free func() error, now time.Time) error {
	var rmErr error
	if host != nil {
		rmErr = host.Remove(ctx, slot)
	}
	if rmErr == nil {
		return free()
	}
	name := slot.netnsName()
	path := strings.TrimSpace(slot.NetnsPath)
	if path == "" {
		if r, ok := host.(netnsPathResolver); ok {
			path = r.netnsPathFor(name)
		}
	}
	p.log().Warn("containerd netns teardown failed; slot parked for retry instead of reuse",
		"slot_id", slot.SlotID, "netns", name, "sandbox_id", owner, "container_ip", slot.ContainerIP, "error", rmErr)
	if err := p.st.MarkContainerNetnsSlotReleasing(ctx, slot.SlotID, owner, path, slot.ContainerIP, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The row changed owner under us; whoever owns it now owns its fate.
			return rmErr
		}
		return errors.Join(rmErr, err)
	}
	return rmErr
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
