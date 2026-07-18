// Package isolate is the blank-workerd warm pool for the V8-isolate runtime
// (plans/isolate-runtime.md §4 Phase 3). Unlike the WASM pool (keyed by module
// digest), these slots are blank group hosts — the group router runs before
// the pool, so only a tenant's FIRST create claims a slot and injects a bundle.
package isolate

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
)

// Spawner creates a blank group host for the pool.
type Spawner interface {
	Spawn(ctx context.Context) (isolateruntime.GroupHost, error)
}

// Metrics are hit/miss/refill counters for expvar-style observation.
type Metrics struct {
	Hits      atomic.Int64
	Misses    atomic.Int64
	Refilled  atomic.Int64
	SpawnFail atomic.Int64
}

// Pool keeps pre-spawned blank workerd group hosts.
type Pool struct {
	logger   *slog.Logger
	spawner  Spawner
	metrics  *Metrics
	mu       sync.Mutex
	ready    []isolateruntime.GroupHost
	depth    int
	spawning int
	kick     chan struct{}
}

// New constructs an empty warm pool.
func New(logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{
		logger:  logger,
		metrics: &Metrics{},
		kick:    make(chan struct{}, 1),
	}
}

func (p *Pool) SetSpawner(s Spawner) { p.spawner = s }

func (p *Pool) SetDepth(n int) {
	p.mu.Lock()
	p.depth = n
	p.mu.Unlock()
}

func (p *Pool) Metrics() *Metrics { return p.metrics }

// Acquire removes one blank host. ok=false on miss (caller cold-spawns).
func (p *Pool) Acquire(_ context.Context) (isolateruntime.GroupHost, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ready) == 0 {
		p.metrics.Misses.Add(1)
		p.kickLocked()
		return nil, false
	}
	h := p.ready[len(p.ready)-1]
	p.ready = p.ready[:len(p.ready)-1]
	p.metrics.Hits.Add(1)
	p.kickLocked()
	return h, true
}

func (p *Pool) kickLocked() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// ReadyCount returns how many blank hosts are queued.
func (p *Pool) ReadyCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready)
}

// WarmOne spawns one blank host into the pool (boot prewarm + refill).
func (p *Pool) WarmOne(ctx context.Context) error {
	if p.spawner == nil {
		return nil
	}
	h, err := p.spawner.Spawn(ctx)
	if err != nil {
		p.metrics.SpawnFail.Add(1)
		return err
	}
	p.mu.Lock()
	p.ready = append(p.ready, h)
	p.mu.Unlock()
	p.metrics.Refilled.Add(1)
	return nil
}

// RunRefill tops the pool up to depth on a ticker and on Acquire miss kicks.
func (p *Pool) RunRefill(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	p.refillTick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refillTick(ctx)
		case <-p.kick:
			p.refillTick(ctx)
		}
	}
}

func (p *Pool) refillTick(ctx context.Context) {
	p.mu.Lock()
	need := p.depth - len(p.ready) - p.spawning
	if need <= 0 || p.spawner == nil {
		p.mu.Unlock()
		return
	}
	p.spawning += need
	p.mu.Unlock()
	for i := 0; i < need; i++ {
		if err := p.WarmOne(ctx); err != nil {
			p.logger.Warn("isolate warm pool spawn failed", "error", err)
		}
		p.mu.Lock()
		p.spawning--
		p.mu.Unlock()
	}
}

// Close stops every queued blank host.
func (p *Pool) Close() {
	p.mu.Lock()
	hosts := p.ready
	p.ready = nil
	p.mu.Unlock()
	for _, h := range hosts {
		_ = h.Stop()
	}
}
