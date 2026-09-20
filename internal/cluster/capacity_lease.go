package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

const (
	capacityLeaseFetchConcurrency = 32
	// capacityLeaseBackoffBase / Max pace a peer that keeps failing. Without
	// per-peer backoff every tick re-attempted every unreachable endpoint:
	// 256 timing-out peers at a 2s dial timeout is ~16s of pool work across
	// 32 workers, which is longer than the minimum 15s lease TTL, so healthy
	// peers' refreshes were postponed past their own expiry by other peers'
	// failures.
	capacityLeaseBackoffBase = 15 * time.Second
	capacityLeaseBackoffMax  = 2 * time.Minute
	// capacityLeaseFetchTimeout is what a peer gets when we are willing to
	// wait for it.
	capacityLeaseFetchTimeout = 2 * time.Second
	// capacityLeaseQuickProbeTimeout is the first pass. Reserving budget for
	// renewals bounds the CLASS, not any peer in it: at 32 slots and a 2s
	// timeout, ~96 established peers going slow occupy every slot for the
	// whole renewal phase, and a peer that would have answered in a
	// millisecond loses its lease because other nodes are slow. A short first
	// pass costs a slow peer a fraction of a slot, so every peer that can
	// answer promptly is reached regardless of how many cannot.
	capacityLeaseQuickProbeTimeout = 300 * time.Millisecond
	// capacityLeaseQuickProbeMaxConcurrency bounds the quick pass's pool.
	// The quick pass is the only part of a sweep whose per-peer cost is
	// bounded (300ms, one small GET), so it is the only part that can be
	// sized to COVER the fleet inside the sweep budget. At 32 slots it
	// cannot: 2,000 peers need 2,000*300ms/32 = 18.75s, five times a 3s
	// renewal slice, so a fleet whose stalest peers are slow spends the
	// whole sweep on them and never dials a peer that would have answered
	// in a microsecond. Sizing the pool from (peers * probe / budget)
	// bounds the CLASS by wall clock instead of by queue position. A slot is
	// held for at most one 300ms probe — and for a peer that answers
	// instantly, which is who the pass exists for, barely at all.
	capacityLeaseQuickProbeMaxConcurrency = 512
	// capacityLeaseFullPassMaxConcurrency bounds the full pass's pool. The
	// full pass is the only one that can get an answer out of a peer slower
	// than the probe, so at fleet scale it is what decides whether leases
	// survive at all, and the cap has to be derived from that rather than
	// picked:
	//
	//	2,000 peers x 2s worst-case request / 15s TTL = 267 sustained.
	//
	// A sweep covers pool*(budget/2s) peers and a TTL holds three sweeps, so
	// 512 finishes the supported fleet with room for a sweep spent probing
	// and for peers that take the whole timeout. At 128 it did not: three
	// sweeps reached 960 of 2,000, and the rest went CapacityStale — which
	// placement treats as "do not use", so healthy capacity disappeared while
	// every endpoint was answering well inside its timeout.
	capacityLeaseFullPassMaxConcurrency = 512
	// capacityLeaseQuickPassBudget* is the share of a class's budget the
	// quick pass may spend. The rest is RESERVED for the full pass: sizing
	// the quick pool to cover the class means it spends the whole budget
	// whenever a large fraction of peers are slower than the probe, and the
	// pass that would have got an answer then never ran at all. A fleet of
	// uniformly slow-but-healthy peers stayed unschedulable forever that way,
	// first contact worst of all — with no lease they are never reclassified,
	// so every sweep repeated the same futile probe.
	capacityLeaseQuickPassBudgetNumerator   = 1
	capacityLeaseQuickPassBudgetDenominator = 2
)

type capacityLease struct {
	snapshot capacity.Snapshot
	updated  time.Time
}

type capacityLeaseCache struct {
	selfID   string
	admitter *capacity.Admitter
	ttl      time.Duration
	logger   *slog.Logger

	mu     sync.RWMutex
	leases map[string]capacityLease
	// nextAttempt / failures schedule each peer INDEPENDENTLY, so one slow
	// or dead endpoint cannot postpone a healthy peer's refresh.
	nextAttempt map[string]time.Time
	failures    map[string]int
	// lastAttempt is when each peer was last DISPATCHED, successfully or not.
	// It is the fairness clock: a sweep that runs out of budget half way
	// leaves the rest of the queue with an older attempt time, so the next
	// sweep starts with them instead of re-attempting the same prefix. Sorting
	// by staleness alone made a long run of slow peers permanent: the peers
	// behind them were never dispatched, so they never entered backoff and
	// never moved out of the way.
	lastAttempt map[string]time.Time
	// slowPeers marks a peer last measured needing longer than the quick
	// probe. It is a RESPONSIVENESS mark, not a health one: such a peer is
	// alive and answers the full request, it just cannot be discovered by a
	// 300ms probe. It is what routes the peer straight to the pass that can
	// answer, and it is cleared the moment the peer is measured fast again —
	// from ANY pass, because the quick pass deliberately skips it.
	slowPeers map[string]bool

	// localTemplateInventory is the Phase 6 PR-D hook for template-aware
	// placement. cmd/sandboxd registers a callback that reads from the
	// service-layer's 5s cache; we overlay the result onto the local
	// admitter snapshot so peers gossiping /v1/capacity AND the local
	// SelectPlacement path see the same list. nil = single-node mode or
	// Firecracker disabled, and the placement path naturally degrades
	// to "no template gate" via the unknown-allow rule.
	localTemplateInventory   func() ([]string, bool)
	localTemplateCatalog     func() ([]string, bool)
	localWasmModuleInventory func() ([]string, bool)
}

func newCapacityLeaseCache(selfID string, admitter *capacity.Admitter, interval time.Duration, logger *slog.Logger) *capacityLeaseCache {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ttl := interval * 3
	if ttl < 15*time.Second {
		ttl = 15 * time.Second
	}
	return &capacityLeaseCache{
		selfID:      selfID,
		admitter:    admitter,
		ttl:         ttl,
		logger:      logger,
		leases:      make(map[string]capacityLease),
		nextAttempt: make(map[string]time.Time),
		failures:    make(map[string]int),
		lastAttempt: make(map[string]time.Time),
		slowPeers:   make(map[string]bool),
	}
}

// recordResponsiveness marks whether a peer answered inside the quick probe.
func (c *capacityLeaseCache) recordResponsiveness(nodeID string, responsive bool) {
	if c == nil || nodeID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.slowPeers == nil {
		c.slowPeers = make(map[string]bool)
	}
	if responsive {
		delete(c.slowPeers, nodeID)
		return
	}
	c.slowPeers[nodeID] = true
}

// tooSlowToProbe reports whether a peer was last measured needing longer than
// the quick probe. Such a peer skips the probe entirely: spending a 300ms
// slot on a peer measured needing more buys nothing and costs the budget that
// would have got it an answer.
func (c *capacityLeaseCache) tooSlowToProbe(nodeID string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.slowPeers[nodeID]
}

// setAdmitter swaps the local capacity source. The lease loop reads admitter
// from another goroutine, so this is not a plain field assignment: tests that
// install a real admitter on an already-running cluster were racing
// refreshLocal's read and its Snapshot() call.
func (c *capacityLeaseCache) setAdmitter(a *capacity.Admitter) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.admitter = a
	c.mu.Unlock()
}

func (c *capacityLeaseCache) refreshLocal(now time.Time) {
	if c == nil || c.selfID == "" {
		return
	}
	// One acquisition for everything the overlay needs, admitter included —
	// it is written by setAdmitter from another goroutine.
	c.mu.RLock()
	admitter := c.admitter
	templateInventory := c.localTemplateInventory
	templateCatalog := c.localTemplateCatalog
	wasmModuleInventory := c.localWasmModuleInventory
	c.mu.RUnlock()
	if admitter == nil {
		return
	}
	snap := admitter.Snapshot()
	// Overlay PR-D template inventory before storing — placement reads
	// straight off this lease, so without the overlay our own snapshot
	// would advertise no templates and the unknown-allow rule would
	// let creates land on peers that lack them.
	if templateInventory != nil {
		if ids, known := templateInventory(); known {
			snap.LocalTemplateInventoryKnown = true
			snap.LocalTemplateIDs = ids
		}
	}
	if templateCatalog != nil {
		if ids, known := templateCatalog(); known {
			snap.LocalTemplateCatalogInventoryKnown = true
			snap.LocalTemplateCatalogIDs = ids
		}
	}
	if wasmModuleInventory != nil {
		if refs, known := wasmModuleInventory(); known {
			snap.LocalWasmModuleInventoryKnown = true
			snap.LocalWasmModuleIDs = refs
		}
	}
	c.set(c.selfID, snap, now)
}

// SetLocalTemplateIDsProvider installs the PR-D callback the capacity
// lease cache invokes at every refreshLocal tick. Idempotent (call once
// at boot); passing nil unregisters. The callback should return an
// already-cached slice — refreshLocal runs on every gossip tick.
func (c *capacityLeaseCache) SetLocalTemplateIDsProvider(fn func() ([]string, bool)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localTemplateInventory = fn
}

// SetLocalTemplateCatalogProvider installs the all-lifecycle template
// catalogue used for direct administrative item routing. It is deliberately
// separate from the ready-only placement inventory.
func (c *capacityLeaseCache) SetLocalTemplateCatalogProvider(fn func() ([]string, bool)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localTemplateCatalog = fn
}

// SetLocalWasmModuleIDsProvider installs the WASM module inventory callback.
func (c *capacityLeaseCache) SetLocalWasmModuleIDsProvider(fn func() ([]string, bool)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localWasmModuleInventory = fn
}

func (c *capacityLeaseCache) set(nodeID string, snap capacity.Snapshot, updated time.Time) {
	if c == nil || nodeID == "" {
		return
	}
	c.mu.Lock()
	if c.leases == nil {
		c.leases = make(map[string]capacityLease)
	}
	c.leases[nodeID] = capacityLease{snapshot: snap, updated: updated}
	c.mu.Unlock()
}

// due reports whether nodeID may be attempted now. A peer in backoff is
// skipped so its failures do not consume pool slots healthy peers need.
func (c *capacityLeaseCache) due(nodeID string, now time.Time) bool {
	if c == nil {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	next, ok := c.nextAttempt[nodeID]
	return !ok || !now.Before(next)
}

// recordFetchResult resets or extends a peer's backoff.
func (c *capacityLeaseCache) recordFetchResult(nodeID string, now time.Time, err error) {
	if c == nil || nodeID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextAttempt == nil {
		c.nextAttempt = make(map[string]time.Time)
	}
	if c.failures == nil {
		c.failures = make(map[string]int)
	}
	if err == nil {
		delete(c.failures, nodeID)
		delete(c.nextAttempt, nodeID)
		return
	}
	fails := c.failures[nodeID] + 1
	c.failures[nodeID] = fails
	backoff := capacityLeaseBackoffBase << min(fails-1, 8)
	if backoff > capacityLeaseBackoffMax || backoff <= 0 {
		backoff = capacityLeaseBackoffMax
	}
	c.nextAttempt[nodeID] = now.Add(backoff)
}

// recordAttempt stamps the fairness clock. Called when a peer is dispatched,
// whatever the outcome: an attempt that timed out still used a slot, and the
// peers that did not get one are the ones owed the next sweep.
func (c *capacityLeaseCache) recordAttempt(nodeID string, now time.Time) {
	if c == nil || nodeID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastAttempt == nil {
		c.lastAttempt = make(map[string]time.Time)
	}
	c.lastAttempt[nodeID] = now
}

// attemptedAt reports when a peer was last dispatched; the zero time means
// "not yet this round", which sorts first.
func (c *capacityLeaseCache) attemptedAt(nodeID string) time.Time {
	if c == nil {
		return time.Time{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastAttempt[nodeID]
}

// hasLease reports whether nodeID already holds a lease that can expire. It
// is the difference between "this node is schedulable until its TTL runs out"
// and "this node has never been reached", which the sweep budgets separately.
func (c *capacityLeaseCache) hasLease(nodeID string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.leases[nodeID]
	return ok
}

// staleness orders the fetch queue: the peer closest to losing its lease goes
// first, so a long tail of failures cannot push a healthy peer past its TTL.
func (c *capacityLeaseCache) staleness(nodeID string, now time.Time) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	lease, ok := c.leases[nodeID]
	if !ok {
		// Never seen: most urgent.
		return time.Duration(1) << 62
	}
	return now.Sub(lease.updated)
}

// retain drops bookkeeping for nodes that are no longer in the membership
// view. Without it the lease, backoff and failure maps kept one entry per node
// the process had ever gossiped with — retired nodes included, forever.
func (c *capacityLeaseCache) retain(live map[string]struct{}) int {
	if c == nil || len(live) == 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for id := range c.leases {
		if id == c.selfID {
			continue
		}
		if _, ok := live[id]; !ok {
			delete(c.leases, id)
			delete(c.nextAttempt, id)
			delete(c.failures, id)
			dropped++
		}
	}
	for id := range c.nextAttempt {
		if _, ok := live[id]; !ok && id != c.selfID {
			delete(c.nextAttempt, id)
			delete(c.failures, id)
		}
	}
	for id := range c.lastAttempt {
		if _, ok := live[id]; !ok && id != c.selfID {
			delete(c.lastAttempt, id)
		}
	}
	for id := range c.slowPeers {
		if _, ok := live[id]; !ok && id != c.selfID {
			delete(c.slowPeers, id)
		}
	}
	return dropped
}

func (c *capacityLeaseCache) apply(members []Member, now time.Time) []Member {
	if c == nil {
		return members
	}
	c.refreshLocal(now)
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Member, 0, len(members))
	for _, m := range members {
		if !m.Alive || !CanOwnSandboxRole(m.Role) {
			out = append(out, m)
			continue
		}
		lease, ok := c.leases[m.NodeID]
		if !ok {
			m.CapacityStale = true
			out = append(out, m)
			continue
		}
		m.Capacity = lease.snapshot
		m.CapacityUpdatedUnix = lease.updated.Unix()
		m.CapacityStale = now.Sub(lease.updated) > c.ttl
		out = append(out, m)
	}
	return out
}

func (c *Cluster) startCapacityLeaseLoop(interval time.Duration) {
	if c.capacityLeases == nil || c.gossip == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.capacityLeaseStop = cancel
	go c.runCapacityLeaseLoop(ctx, interval)
}

func (c *Cluster) runCapacityLeaseLoop(ctx context.Context, interval time.Duration) {
	c.refreshCapacityLeases(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refreshCapacityLeases(ctx)
		}
	}
}

func (c *Cluster) refreshCapacityLeases(ctx context.Context) {
	if c == nil || c.capacityLeases == nil || c.gossip == nil {
		return
	}
	now := time.Now()
	c.capacityLeases.refreshLocal(now)

	members := c.gossip.members()
	live := make(map[string]struct{}, len(members))
	queue := make([]Member, 0, len(members))
	for _, m := range members {
		if m.NodeID == "" {
			continue
		}
		live[m.NodeID] = struct{}{}
		if m.NodeID == c.nodeID || !m.Alive || !CanOwnSandboxRole(m.Role) || m.InternalURL == "" {
			continue
		}
		// Peers in backoff are skipped entirely this tick. A dead endpoint
		// must not hold a pool slot a healthy peer needs before its TTL.
		if !c.capacityLeases.due(m.NodeID, now) {
			continue
		}
		queue = append(queue, m)
	}
	// Retire bookkeeping for nodes gossip no longer knows about.
	c.capacityLeases.retain(live)

	// Split before ordering. Every never-seen peer sorts ahead of every
	// existing lease (staleness treats "no lease" as maximally urgent), and a
	// newly visible peer is not in backoff yet — so a burst of slow newcomers
	// consumed the entire sweep before one healthy node was attempted, and
	// its lease expired while it was answering in milliseconds. A restart
	// burst or a fleet expansion reaches that shape well below 2,000 nodes.
	renewals := make([]Member, 0, len(queue))
	firstContact := make([]Member, 0, len(queue))
	for _, m := range queue {
		if c.capacityLeases.hasLease(m.NodeID) {
			renewals = append(renewals, m)
			continue
		}
		firstContact = append(firstContact, m)
	}
	// Renewals: peers not yet attempted in this round go first, then the peer
	// closest to losing its lease. The attempt clock is what carries progress
	// across sweeps — without it a budget that runs out half way means the
	// same prefix is retried forever and everything behind it starves.
	sort.Slice(renewals, func(i, j int) bool {
		ai := c.capacityLeases.attemptedAt(renewals[i].NodeID)
		aj := c.capacityLeases.attemptedAt(renewals[j].NodeID)
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		si := c.capacityLeases.staleness(renewals[i].NodeID, now)
		sj := c.capacityLeases.staleness(renewals[j].NodeID, now)
		if si == sj {
			return renewals[i].NodeID < renewals[j].NodeID
		}
		return si > sj
	})
	// First contact gets the same fairness clock: a congested sweep must not
	// re-offer the same newcomers forever while the rest are never dialled.
	sort.Slice(firstContact, func(i, j int) bool {
		ai := c.capacityLeases.attemptedAt(firstContact[i].NodeID)
		aj := c.capacityLeases.attemptedAt(firstContact[j].NodeID)
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return firstContact[i].NodeID < firstContact[j].NodeID
	})

	budget := c.capacityLeaseSweepBudget()
	// Split the renewals again, by RESPONSIVENESS. Reserving a slice of the
	// sweep for "peers that hold a lease" bounds that class as a whole, but
	// every peer in it still competes for the same slots — and a peer that
	// is alive but slow never enters the failure backoff, because missing a
	// 300ms probe is not evidence of a fault. So a fleet where most peers
	// answer in ~1s spends its entire renewal slice on them, sweep after
	// sweep, while the peers that answer instantly are never dialled and
	// lose the leases they could have renewed in microseconds.
	//
	// Responsive peers go first and cost almost nothing, so the slow class
	// still gets nearly the whole slice; and a slow peer is paced, so the
	// cost of the slow class per sweep falls instead of repeating in full.
	// Responsiveness is handled inside runCapacityFetchClass, which gives the
	// probe and the full request each their own reserved share. An earlier
	// version also PACED peers that kept missing the probe, holding them back
	// for a sweep or two; with the budget split that is pure harm — the class
	// it delayed is slow but healthy, its lease has the same TTL as everyone
	// else's, and nothing is competing for the time it was being denied.
	// The renewal reservation is a FLOOR for renewals, not a ceiling: with no
	// peer waiting to be discovered there is nothing for the rest of the
	// sweep to do, and capping renewals at three fifths of it threw away the
	// throughput that keeps leases alive.
	renewalBudget := budget
	if len(firstContact) > 0 {
		renewalBudget = budget * capacityLeaseRenewalBudgetNumerator / capacityLeaseRenewalBudgetDenominator
	}
	start := time.Now()
	c.runCapacityFetchClass(ctx, renewals, renewalBudget)
	remaining := budget - time.Since(start)
	if remaining <= 0 {
		// The renewal phase used the whole sweep. First contact retries next
		// tick; a node with no lease is not yet schedulable either way.
		return
	}
	c.runCapacityFetchClass(ctx, firstContact, remaining)
}

// runCapacityFetchClass fetches one class of peers in two passes, each under
// a RESERVED share of the class budget: a quick probe that every prompt peer
// answers, then the full timeout for whoever did not.
//
// Both halves of that are load-bearing. Without the quick pass, a peer's
// refresh depends on how many OTHER peers in its class are slow, which is how
// a node that answers instantly loses a lease. Without reserving time for the
// full pass, the opposite fails: the quick pass is sized to cover its class,
// so on a fleet that is uniformly slow-but-healthy it spends everything and
// the only pass that could have got an answer never runs — leaving a fleet
// unschedulable although every endpoint would have replied well inside the
// full timeout.
func (c *Cluster) runCapacityFetchClass(ctx context.Context, members []Member, budget time.Duration) {
	if len(members) == 0 || budget <= 0 {
		return
	}
	start := time.Now()
	// A peer already known to miss the probe skips it. Spending a 300ms slot
	// on a peer that has been measured needing longer buys nothing and costs
	// the budget that would have got it an answer; it goes straight to the
	// pass that can.
	probeable := make([]Member, 0, len(members))
	full := make([]Member, 0, len(members))
	for _, m := range members {
		if c.capacityLeases.tooSlowToProbe(m.NodeID) {
			full = append(full, m)
			continue
		}
		probeable = append(probeable, m)
	}

	// The quick pass may only spend its share; the rest belongs to the full
	// pass whatever happens here.
	quickBudget := budget * capacityLeaseQuickPassBudgetNumerator / capacityLeaseQuickPassBudgetDenominator
	// A quick-probe timeout is not evidence that a peer is unhealthy — a
	// loaded node can miss 300ms — so it does not feed the backoff. It IS
	// evidence about responsiveness, which is what schedules the peer from
	// here on.
	unanswered := c.runCapacityFetchPhase(ctx, probeable, quickBudget, capacityFetchPass{
		attemptTimeout:      capacityLeaseQuickProbeTimeout,
		marksResponsiveness: true,
		concurrency:         passConcurrency(len(probeable), quickBudget, capacityLeaseQuickProbeTimeout, capacityLeaseQuickProbeMaxConcurrency),
	})
	full = append(full, unanswered...)
	remaining := budget - time.Since(start)
	if len(full) == 0 || remaining <= 0 {
		return
	}
	c.runCapacityFetchPhase(ctx, full, remaining, capacityFetchPass{
		attemptTimeout: capacityLeaseFetchTimeout,
		recordFailures: true,
		concurrency:    passConcurrency(len(full), remaining, capacityLeaseFetchTimeout, capacityLeaseFullPassMaxConcurrency),
	})
}

// passConcurrency sizes a pass's pool from the work it has to do and the time
// it has to do it in: one peer costs at most one attempt timeout, so covering
// N peers inside the budget needs N*timeout/budget slots. Capped, because a
// pool is sockets and goroutines, not a free resource — past the cap the pass
// covers what it can and the fairness clock rotates the rest into the next
// sweep.
func passConcurrency(members int, budget, attemptTimeout time.Duration, max int) int {
	if members <= 0 || budget <= 0 || attemptTimeout <= 0 {
		return capacityLeaseFetchConcurrency
	}
	// Size for HALF the budget, not all of it. Break-even sizing leaves no
	// slack at all: the class only just fits, so scheduling jitter or a
	// couple of peers at the timeout push the tail of the queue past the
	// deadline — and the tail is where a peer that answers instantly, sorted
	// behind the stale slow ones, waits. Provisioning double means the pass
	// finishes well inside its share.
	target := budget / 2
	if target <= 0 {
		target = budget
	}
	needed := int((time.Duration(members)*attemptTimeout + target - 1) / target)
	if needed < capacityLeaseFetchConcurrency {
		needed = capacityLeaseFetchConcurrency
	}
	if needed > max {
		needed = max
	}
	if needed > members {
		needed = members
	}
	return needed
}

// capacityFetchPass is one pass's policy: how long a peer gets, and whether a
// failure counts against its backoff.
type capacityFetchPass struct {
	attemptTimeout time.Duration
	recordFailures bool
	// marksResponsiveness makes a peer that does not answer THIS pass count
	// as slower than the quick probe. Only the probe pass sets it: missing a
	// 2s request says the peer failed, which the backoff handles, not that it
	// is merely slow. A peer the sweep cut short is not marked either way.
	marksResponsiveness bool
	// concurrency overrides the default pool size for this pass; 0 means
	// capacityLeaseFetchConcurrency.
	concurrency int
}

// capacityLeaseRenewalBudget* reserve three fifths of the sweep for peers that
// already hold a lease. The split is what makes the reservation a guarantee
// rather than an ordering preference: ordering alone still lets a long enough
// run of slow newcomers occupy every request slot for the whole sweep.
const (
	capacityLeaseRenewalBudgetNumerator   = 3
	capacityLeaseRenewalBudgetDenominator = 5
)

// runCapacityFetchPhase fetches one class of peers under its own slice of the
// sweep budget.
func (c *Cluster) runCapacityFetchPhase(ctx context.Context, members []Member, budget time.Duration, pass capacityFetchPass) []Member {
	if len(members) == 0 || budget <= 0 {
		return members
	}
	phaseCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	jobs := make(chan Member)
	var (
		mu        sync.Mutex
		refreshed = make(map[string]struct{}, len(members))
		wg        sync.WaitGroup
	)
	concurrency := pass.concurrency
	if concurrency <= 0 {
		concurrency = capacityLeaseFetchConcurrency
	}
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range jobs {
				c.capacityLeases.recordAttempt(m.NodeID, time.Now())
				dialled := time.Now()
				snap, err := c.fetchMemberCapacity(phaseCtx, m, pass.attemptTimeout)
				if err != nil {
					// A request this sweep cut short says nothing about the
					// peer. It is dispatched with whatever is left of the
					// phase rather than its own allowance, so charging the
					// coordinator's deadline to the peer gave a healthy node
					// a 15s backoff whose next eligible attempt was already
					// past its lease expiry — it lost the lease without ever
					// failing.
					if !curtailedByPhase(phaseCtx, err) {
						if pass.marksResponsiveness {
							c.capacityLeases.recordResponsiveness(m.NodeID, false)
						}
						if pass.recordFailures {
							c.capacityLeases.recordFetchResult(m.NodeID, time.Now(), err)
						}
					}
					if c.logger != nil {
						c.logger.Debug("cluster: capacity heartbeat fetch failed", "node_id", m.NodeID, "error", err)
					}
					continue
				}
				// Responsiveness is measured wherever it is observed, not
				// only in the quick pass. Without this a peer classified
				// slow could never come back: the quick pass deliberately
				// skips known-slow peers, so nothing would ever re-measure
				// one that recovered, and it would stay slow for the life of
				// the process.
				c.capacityLeases.recordResponsiveness(m.NodeID, time.Since(dialled) <= capacityLeaseQuickProbeTimeout)
				c.capacityLeases.recordFetchResult(m.NodeID, time.Now(), nil)
				c.capacityLeases.set(m.NodeID, snap, time.Now())
				mu.Lock()
				refreshed[m.NodeID] = struct{}{}
				mu.Unlock()
			}
		}()
	}

	for _, m := range members {
		if phaseCtx.Err() != nil {
			break
		}
		select {
		case jobs <- m:
		case <-phaseCtx.Done():
		}
	}
	close(jobs)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	out := make([]Member, 0, len(members)-len(refreshed))
	for _, m := range members {
		if _, ok := refreshed[m.NodeID]; ok {
			continue
		}
		out = append(out, m)
	}
	return out
}

// capacityLeaseSweepBudget keeps one sweep comfortably inside the lease TTL,
// so an overrun cannot be the reason a healthy peer's lease expires.
func (c *Cluster) capacityLeaseSweepBudget() time.Duration {
	ttl := 15 * time.Second
	if c.capacityLeases != nil && c.capacityLeases.ttl > 0 {
		ttl = c.capacityLeases.ttl
	}
	budget := ttl / 3
	if budget < time.Second {
		budget = time.Second
	}
	return budget
}

func (c *Cluster) fetchMemberCapacity(ctx context.Context, m Member, attemptTimeout time.Duration) (capacity.Snapshot, error) {
	if attemptTimeout <= 0 {
		attemptTimeout = capacityLeaseFetchTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	client, base, err := c.PeerDialMember(m)
	if err != nil {
		return capacity.Snapshot{}, err
	}
	return fetchCapacitySnapshot(reqCtx, client, strings.TrimRight(base, "/")+"/v1/capacity", c.patToken)
}

func fetchCapacitySnapshot(ctx context.Context, client *http.Client, endpoint, patToken string) (capacity.Snapshot, error) {
	var snap capacity.Snapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return snap, err
	}
	req.Header.Set("Accept", "application/json")
	if patToken != "" {
		req.Header.Set("Authorization", "Bearer "+patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return snap, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return snap, statusError{status: resp.StatusCode, message: strings.TrimSpace(string(msg))}
	}
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return snap, err
	}
	return snap, nil
}

func hasCapacitySnapshot(s capacity.Snapshot) bool {
	return s.HostCPUCores > 0 || s.HostMemoryTotalMB > 0
}

// curtailedByPhase reports whether a failed attempt was ended by the sweep
// rather than by the peer. A phase gives each request its own timeout, but a
// request dispatched near the end of the phase inherits only the phase's
// remaining time — so a cancellation while the phase itself is over is the
// coordinator's budget running out, not evidence about the peer, and must not
// feed the failure backoff.
func curtailedByPhase(phaseCtx context.Context, err error) bool {
	if err == nil || phaseCtx == nil {
		return false
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return false
	}
	return phaseCtx.Err() != nil
}
