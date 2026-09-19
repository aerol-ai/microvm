package cluster

import (
	"context"
	"encoding/json"
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
	}
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

	// Most-stale first: the peer closest to losing its lease is refreshed
	// before one that was just updated.
	sort.Slice(queue, func(i, j int) bool {
		si := c.capacityLeases.staleness(queue[i].NodeID, now)
		sj := c.capacityLeases.staleness(queue[j].NodeID, now)
		if si == sj {
			return queue[i].NodeID < queue[j].NodeID
		}
		return si > sj
	})

	// Bound the sweep so it cannot run into the next tick and so a long tail
	// of slow peers cannot consume the whole TTL. Whatever is left is picked
	// up next tick, and the staleness ordering above stops it being starved.
	sweepCtx, cancel := context.WithTimeout(ctx, c.capacityLeaseSweepBudget())
	defer cancel()

	jobs := make(chan Member)
	var wg sync.WaitGroup
	for range capacityLeaseFetchConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range jobs {
				snap, err := c.fetchMemberCapacity(sweepCtx, m)
				c.capacityLeases.recordFetchResult(m.NodeID, time.Now(), err)
				if err != nil {
					if c.logger != nil {
						c.logger.Debug("cluster: capacity heartbeat fetch failed", "node_id", m.NodeID, "error", err)
					}
					continue
				}
				c.capacityLeases.set(m.NodeID, snap, time.Now())
			}
		}()
	}

	for _, m := range queue {
		if sweepCtx.Err() != nil {
			break
		}
		select {
		case jobs <- m:
		case <-sweepCtx.Done():
		}
	}
	close(jobs)
	wg.Wait()
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

func (c *Cluster) fetchMemberCapacity(ctx context.Context, m Member) (capacity.Snapshot, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
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
