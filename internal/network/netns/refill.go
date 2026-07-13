package netns

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// Prewarm reserves a free slot under its slot_id, runs CNI ADD, and parks it in
// the pooled warm queue.
func (p *Pool) Prewarm(ctx context.Context, host HostManager, now time.Time) error {
	if p == nil || host == nil {
		return errors.New("netns prewarm: pool and host are required")
	}
	slot, err := p.st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		return err
	}
	work := Slot{SlotID: slot.SlotID, SandboxID: slot.SlotID}
	path, ip, err := host.Realize(ctx, work)
	if err != nil {
		_ = p.st.ResetContainerNetnsSlotToFree(ctx, slot.SlotID, now)
		return err
	}
	if err := p.st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, path, ip, now); err != nil {
		_ = host.Remove(ctx, Slot{SlotID: slot.SlotID, SandboxID: slot.SlotID, NetnsPath: path})
		_ = p.st.ResetContainerNetnsSlotToFree(ctx, slot.SlotID, now)
		return err
	}
	return nil
}

// ClaimPooled tries the warm queue before a cold build. Returns (slot, true, nil)
// on hit; (_, false, nil) on miss.
func (p *Pool) ClaimPooled(ctx context.Context, sandboxID string, now time.Time) (*Slot, bool, error) {
	if p == nil {
		return nil, false, nil
	}
	raw, err := p.st.ClaimPooledContainerNetnsSlot(ctx, sandboxID, now)
	if errors.Is(err, store.ErrNoPooledContainerNetnsSlot) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return slotFromStore(raw), true, nil
}

// TargetDepth is the desired count of pooled+warm-ready slots.
func (p *Pool) TargetDepth(ctx context.Context, depth int) (need int, err error) {
	stats, err := p.Stats(ctx)
	if err != nil {
		return 0, err
	}
	need = depth - stats.Pooled
	if need < 0 {
		need = 0
	}
	return need, nil
}

// LiveSandbox reports whether sandboxID still has a live containerd workload.
type LiveSandbox func(ctx context.Context, sandboxID string) bool

// NetnsExists checks whether a prepaid netns path is still present on disk.
type NetnsExists func(path string) bool

// Reconcile tears down orphaned reserved/realized/pooled/adopted rows after a
// crash or daemon restart. live==nil treats every adopted/reserved owner as dead.
func (p *Pool) Reconcile(ctx context.Context, host HostManager, live LiveSandbox, exists NetnsExists, now time.Time) (reaped int, err error) {
	if p == nil {
		return 0, nil
	}
	if exists == nil {
		exists = func(path string) bool {
			if path == "" {
				return false
			}
			_, err := os.Stat(path)
			return err == nil
		}
	}
	slots, err := p.st.ListNonFreeContainerNetnsSlots(ctx)
	if err != nil {
		return 0, err
	}
	for _, raw := range slots {
		slot := slotFromStore(&raw)
		if slot == nil {
			continue
		}
		orphan := false
		switch slot.State {
		case store.NetnsSlotStatePooled:
			orphan = !exists(slot.NetnsPath)
		case store.NetnsSlotStateAdopted, store.NetnsSlotStateReserved, store.NetnsSlotStateRealized:
			owner := slot.SandboxID
			if owner == "" {
				orphan = true
			} else if owner == slot.SlotID {
				orphan = true // refill crash window
			} else if live == nil || !live(ctx, owner) {
				orphan = true
			}
		default:
			continue
		}
		if !orphan {
			continue
		}
		if host != nil {
			_ = host.Remove(ctx, *slot)
		}
		_ = p.st.ResetContainerNetnsSlotToFree(ctx, slot.SlotID, now)
		reaped++
	}
	return reaped, nil
}

// Refiller maintains the pooled warm depth on a ticker.
type Refiller struct {
	pool     *Pool
	host     HostManager
	depth    int
	interval time.Duration
	now      func() time.Time

	stopCh chan struct{}
	doneCh chan struct{}
}

func NewRefiller(pool *Pool, host HostManager, depth int, interval time.Duration) *Refiller {
	if depth <= 0 {
		depth = 4
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Refiller{
		pool:     pool,
		host:     host,
		depth:    depth,
		interval: interval,
		now:      func() time.Time { return timeNow() },
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

func (r *Refiller) Run(ctx context.Context) {
	defer close(r.doneCh)
	r.refillOnce(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.refillOnce(ctx)
		}
	}
}

func (r *Refiller) refillOnce(ctx context.Context) {
	if r == nil || r.pool == nil || r.host == nil {
		return
	}
	need, err := r.pool.TargetDepth(ctx, r.depth)
	if err != nil || need == 0 {
		return
	}
	for i := 0; i < need; i++ {
		if err := r.pool.Prewarm(ctx, r.host, r.now()); err != nil {
			return
		}
	}
}

// Stop halts the refill loop.
func (r *Refiller) Stop() {
	if r == nil {
		return
	}
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
	<-r.doneCh
}
