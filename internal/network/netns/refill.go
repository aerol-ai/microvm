package netns

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
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
	unlock := p.lockSlot(slot.SlotID)
	defer unlock()
	work := Slot{SlotID: slot.SlotID, SandboxID: slot.SlotID}
	reset := func() error { return p.st.ResetContainerNetnsSlotToFree(ctx, slot.SlotID, now) }
	path, ip, err := host.Realize(ctx, work)
	if err != nil {
		// The slot is free and named after itself, so anything still held
		// under its name is a leftover, never a live sandbox's: most often a
		// host-local lease that an earlier DEL missed (binaries before this fix
		// released claimed slots under the claimant's id), which makes every
		// ADD for this slot fail as a "duplicate allocation" and wedges the
		// refiller on it forever. Clearing it under the slot's own identity lets
		// the next tick succeed. Realize already deleted its own netns.
		_ = p.teardown(ctx, host, work, slot.SlotID, reset, now)
		return err
	}
	if err := p.st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, path, ip, now); err != nil {
		work.NetnsPath, work.ContainerIP = path, ip
		_ = p.teardown(ctx, host, work, slot.SlotID, reset, now)
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
// crash or daemon restart, and retries slots parked as releasing. A warm
// (pooled) slot survives only when its netns is there AND holds the address
// the row records; otherwise it is rebuilt, never handed out.
// live==nil treats every adopted/reserved owner as dead, so production wiring
// must pass a callback that answers "dead" only when the owner's container is
// confirmed gone: reaping a live owner runs CNI DEL inside its netns and
// deletes it, cutting a running sandbox off the network.
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
		case store.NetnsSlotStateReleasing:
			orphan = true
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
		if !orphan && slot.State == store.NetnsSlotStatePooled && !p.warmSlotHoldsItsAddress(ctx, host, slot) {
			// The netns at the recorded path is not the one the row
			// describes: rebuild the slot rather than hand it out.
			orphan = true
		}
		if !orphan && !p.disableSurvivorIPv6(ctx, host, slot) {
			// A warm slot whose IPv6 cannot be turned off is rebuilt, not
			// handed to a sandbox.
			orphan = slot.State == store.NetnsSlotStatePooled
		}
		if !orphan {
			continue
		}
		slotID := slot.SlotID
		free := func() error { return p.st.ResetContainerNetnsSlotToFree(ctx, slotID, now) }
		if slot.State == store.NetnsSlotStateReleasing {
			free = func() error { return p.st.FreeReleasingContainerNetnsSlot(ctx, slotID, now) }
		}
		unlock := p.lockSlot(slotID)
		if p.teardown(ctx, host, *slot, slot.SandboxID, free, now) == nil {
			reaped++
		}
		unlock()
	}
	return reaped, nil
}

// addressReader is the optional HostManager step Reconcile runs on every
// surviving warm slot (*Host implements it).
type addressReader interface {
	IPv4Addrs(ctx context.Context, slot Slot) ([]string, error)
}

// warmSlotHoldsItsAddress reports whether a pooled slot's netns holds the
// address its row records. A path that exists is not enough: slot names
// are fixed (aerol-netns-<i>), so it shows only that SOME netns of that
// name is there. After a backup is restored onto a fresh machine, the
// fresh install's own daemon has already prewarmed aerol-netns-0.. at the
// addresses its host-local IPAM gave out (10.88.0.2, …), while the
// restored rows still name the old machine's (10.88.2.111). A create
// handed such a slot put its rules on the recorded address before its
// task started, and the task came up at the other one (UC-316: the
// containerd driver refused it, "came up at 10.88.0.2, not at its prepaid
// address 10.88.2.111"). Also false when the address cannot be read: a
// warm slot is cheap to rebuild, and one the pool cannot vouch for is
// never handed out. A slot with an owner is never asked: its task may
// have moved the address out of the netns (gVisor), and it is not the
// pool's to rebuild.
func (p *Pool) warmSlotHoldsItsAddress(ctx context.Context, host HostManager, slot *Slot) bool {
	r, ok := host.(addressReader)
	if !ok {
		return true
	}
	want := strings.TrimSpace(slot.ContainerIP)
	addrs, err := r.IPv4Addrs(ctx, *slot)
	if err == nil && want != "" && slices.Contains(addrs, want) {
		return true
	}
	p.log().Warn("containerd netns reconcile: a warm slot's namespace does not hold the address its row records; rebuilding it",
		"slot_id", slot.SlotID, "netns", slot.NetnsPath, "recorded_ip", want, "found_ips", addrs, "error", err)
	return false
}

// ipv6Disabler is the optional HostManager step Reconcile runs on every
// surviving slot (*Host implements it).
type ipv6Disabler interface {
	DisableIPv6(ctx context.Context, slot Slot) error
}

// disableSurvivorIPv6 turns IPv6 off in a slot that outlived a restart:
// slots realized before Realize did it themselves still have it on. It
// reports false only when the host could not; a live sandbox's slot is then
// kept (the node's IPv6 fence still drops what it sends) and logged.
func (p *Pool) disableSurvivorIPv6(ctx context.Context, host HostManager, slot *Slot) bool {
	d, ok := host.(ipv6Disabler)
	if !ok || strings.TrimSpace(slot.NetnsPath) == "" {
		return true
	}
	if err := d.DisableIPv6(ctx, *slot); err != nil {
		p.log().Warn("containerd netns reconcile: could not turn IPv6 off in a surviving slot",
			"slot_id", slot.SlotID, "sandbox_id", slot.SandboxID, "state", slot.State, "error", err)
		return false
	}
	return true
}

// RetryReleasing re-runs the host teardown for every slot parked as releasing
// and frees each one whose teardown now succeeds. Returns how many it freed.
func (p *Pool) RetryReleasing(ctx context.Context, host HostManager, now time.Time) (int, error) {
	if p == nil || host == nil {
		return 0, nil
	}
	slots, err := p.st.ListContainerNetnsSlotsByState(ctx, store.NetnsSlotStateReleasing)
	if err != nil {
		return 0, err
	}
	freed := 0
	for _, raw := range slots {
		slot := slotFromStore(&raw)
		slotID := slot.SlotID
		free := func() error { return p.st.FreeReleasingContainerNetnsSlot(ctx, slotID, now) }
		unlock := p.lockSlot(slotID)
		if p.teardown(ctx, host, *slot, "", free, now) == nil {
			freed++
		}
		unlock()
	}
	return freed, nil
}

// releasingRetryEvery is how many refill ticks pass between retries of
// slots parked as releasing (15 x the 2s default = 30s). A teardown that
// keeps failing is retried and logged at this pace, not every tick.
const releasingRetryEvery = 15

// Refiller maintains the pooled warm depth on a ticker.
type Refiller struct {
	pool     *Pool
	host     HostManager
	depth    int
	interval time.Duration
	now      func() time.Time
	ticks    int

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
	if r.ticks%releasingRetryEvery == 0 {
		_, _ = r.pool.RetryReleasing(ctx, r.host, r.now())
	}
	r.ticks++
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
