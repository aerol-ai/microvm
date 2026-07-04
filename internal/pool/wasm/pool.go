// Package wasm is the in-memory warm-worker pool for WASM sandboxes (Phase 5).
// Unlike internal/pool/vmm, slots are not persisted — worker processes do not
// survive a daemon restart.
package wasm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Slot is one warm worker with its module already compiled inside the worker.
type Slot struct {
	ID           string
	ModuleDigest string
	ModulePath   string
	SocketPath   string
	WorkerKey    string
	MemoryMB     int
	LoadedAt     time.Time
}

// Pool keeps pre-loaded workers keyed by module digest.
type Pool struct {
	logger *slog.Logger

	mu              sync.Mutex
	defaultDepth    int
	defaultMemoryMB int
	targets         map[string]string // digest -> module path
	ready           map[string][]*Slot
	spawning        map[string]int
	runDir          string
	spawner         Spawner
	metrics         *Metrics
	refillKick      chan struct{}
}

// New constructs a warm pool. runDir is the WASM runtime root (pool slots live under runDir/pool/).
func New(runDir string, logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{
		logger:     logger,
		targets:    make(map[string]string),
		ready:      make(map[string][]*Slot),
		spawning:   make(map[string]int),
		runDir:     runDir,
		metrics:    &Metrics{},
		refillKick: make(chan struct{}, 1),
	}
}

// SetSpawner injects the worker spawner (production: SupervisorSpawner).
func (p *Pool) SetSpawner(s Spawner) { p.spawner = s }

// SetDefaultMemoryMB sets the guest memory cap used when warming pool slots.
func (p *Pool) SetDefaultMemoryMB(n int) {
	p.mu.Lock()
	p.defaultMemoryMB = n
	p.mu.Unlock()
}

// SetDefaultDepth sets the target warm depth per module digest when depth is unset.
func (p *Pool) SetDefaultDepth(n int) {
	p.mu.Lock()
	p.defaultDepth = n
	p.mu.Unlock()
}

// Metrics returns the pool's counter bundle.
func (p *Pool) Metrics() *Metrics { return p.metrics }

// NoteModule registers a digest/path pair for background refill.
func (p *Pool) NoteModule(digest, modulePath string) {
	if digest == "" || modulePath == "" {
		return
	}
	p.mu.Lock()
	p.targets[digest] = modulePath
	p.mu.Unlock()
}

// DepthFor returns the target warm depth for digest.
func (p *Pool) DepthFor(digest string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.defaultDepth > 0 {
		return p.defaultDepth
	}
	return 0
}

// ReadyCount returns how many warm slots are queued for digest.
func (p *Pool) ReadyCount(digest string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready[digest])
}

// Acquire removes one warm slot for digest whose MemoryMB matches. Returns ErrNoSlot on miss.
func (p *Pool) Acquire(_ context.Context, digest, modulePath string, memoryMB int) (*Slot, error) {
	if digest == "" {
		return nil, ErrNoSlot
	}
	p.NoteModule(digest, modulePath)

	p.mu.Lock()
	defer p.mu.Unlock()
	q := p.ready[digest]
	for i := len(q) - 1; i >= 0; i-- {
		if q[i].MemoryMB != memoryMB {
			continue
		}
		slot := q[i]
		p.ready[digest] = append(q[:i], q[i+1:]...)
		if p.metrics != nil {
			p.metrics.recordHit()
		}
		return slot, nil
	}
	if p.metrics != nil {
		p.metrics.recordMiss()
	}
	p.kickRefillLocked()
	return nil, ErrNoSlot
}

func (p *Pool) kickRefillLocked() {
	if p.refillKick == nil {
		return
	}
	select {
	case p.refillKick <- struct{}{}:
	default:
	}
}

// RecordLoaded pushes a freshly warmed slot into the ready queue.
func (p *Pool) RecordLoaded(slot *Slot) {
	if slot == nil || slot.ModuleDigest == "" {
		return
	}
	p.mu.Lock()
	p.ready[slot.ModuleDigest] = append(p.ready[slot.ModuleDigest], slot)
	if p.spawning[slot.ModuleDigest] > 0 {
		p.spawning[slot.ModuleDigest]--
	}
	p.mu.Unlock()
}

// SpawnBudget returns how many slots refill should create for digest on this tick.
func (p *Pool) SpawnBudget(digest string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	depth := p.defaultDepth
	if depth <= 0 {
		return 0
	}
	path, ok := p.targets[digest]
	if !ok || path == "" {
		return 0
	}
	ready := len(p.ready[digest])
	inFlight := p.spawning[digest]
	want := depth - ready - inFlight
	if want < 0 {
		return 0
	}
	return want
}

// ListTargets returns digest/path pairs eligible for refill.
func (p *Pool) ListTargets() []struct{ Digest, Path string } {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]struct{ Digest, Path string }, 0, len(p.targets))
	for digest, path := range p.targets {
		if path != "" {
			out = append(out, struct{ Digest, Path string }{digest, path})
		}
	}
	return out
}

// MarkSpawning increments the in-flight spawn counter for digest.
func (p *Pool) MarkSpawning(digest string) {
	p.mu.Lock()
	p.spawning[digest]++
	p.mu.Unlock()
}

// DropModule evicts warm slots and refill targets for digest after module GC.
func (p *Pool) DropModule(digest string) {
	if digest == "" {
		return
	}
	p.mu.Lock()
	slots := append([]*Slot(nil), p.ready[digest]...)
	delete(p.ready, digest)
	delete(p.targets, digest)
	delete(p.spawning, digest)
	spawner := p.spawner
	p.mu.Unlock()
	for _, slot := range slots {
		if slot == nil {
			continue
		}
		if spawner != nil {
			_ = spawner.Shutdown(slot.WorkerKey)
		}
		_ = os.RemoveAll(filepath.Dir(slot.SocketPath))
	}
}

// UnmarkSpawning decrements the in-flight spawn counter after a failed warm.
func (p *Pool) UnmarkSpawning(digest string) {
	p.mu.Lock()
	if p.spawning[digest] > 0 {
		p.spawning[digest]--
	}
	p.mu.Unlock()
}

// NewSlotID mints a unique pool slot identifier.
func NewSlotID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "pool-" + hex.EncodeToString(b[:])
}

// SlotDir returns the on-disk directory for a pool slot.
func (p *Pool) SlotDir(digest, slotID string) string {
	prefix := digest
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return filepath.Join(p.runDir, "pool", prefix, slotID)
}

// WarmOne spawns a single warm slot for digest/path. Used by the refill loop.
func (p *Pool) WarmOne(ctx context.Context, digest, modulePath string) (*Slot, error) {
	if p.spawner == nil {
		return nil, fmt.Errorf("wasm pool: spawner not configured")
	}
	slotID := NewSlotID()
	dir := p.SlotDir(digest, slotID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(dir, "worker.sock")
	memMB := p.defaultMemoryMB
	if err := p.spawner.Warm(ctx, slotID, socketPath, modulePath, memMB); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &Slot{
		ID:           slotID,
		ModuleDigest: digest,
		ModulePath:   modulePath,
		SocketPath:   socketPath,
		WorkerKey:    slotID,
		MemoryMB:     memMB,
		LoadedAt:     time.Now().UTC(),
	}, nil
}

// Close shuts down all warm slots still in the pool.
func (p *Pool) Close() (drained int) {
	p.mu.Lock()
	var slots []*Slot
	for _, q := range p.ready {
		slots = append(slots, q...)
	}
	p.ready = make(map[string][]*Slot)
	spawner := p.spawner
	p.mu.Unlock()

	for _, slot := range slots {
		if spawner != nil {
			_ = spawner.Shutdown(slot.WorkerKey)
		}
		_ = os.RemoveAll(filepath.Dir(slot.SocketPath))
		drained++
	}
	return drained
}

// AcquireOrMiss is a helper that normalizes ErrNoSlot for callers that want a bool.
func AcquireOrMiss(ctx context.Context, p *Pool, digest, path string, memoryMB int) (*Slot, bool, error) {
	if p == nil {
		return nil, false, nil
	}
	slot, err := p.Acquire(ctx, digest, path, memoryMB)
	if err == nil {
		return slot, true, nil
	}
	if errors.Is(err, ErrNoSlot) {
		return nil, false, nil
	}
	return nil, false, err
}
