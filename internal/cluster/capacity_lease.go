package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

const capacityLeaseFetchConcurrency = 32

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

	// localTemplateInventory is the Phase 6 PR-D hook for template-aware
	// placement. cmd/sandboxd registers a callback that reads from the
	// service-layer's 5s cache; we overlay the result onto the local
	// admitter snapshot so peers gossiping /v1/capacity AND the local
	// SelectPlacement path see the same list. nil = single-node mode or
	// Firecracker disabled, and the placement path naturally degrades
	// to "no template gate" via the unknown-allow rule.
	localTemplateInventory   func() ([]string, bool)
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
		selfID:   selfID,
		admitter: admitter,
		ttl:      ttl,
		logger:   logger,
		leases:   make(map[string]capacityLease),
	}
}

func (c *capacityLeaseCache) refreshLocal(now time.Time) {
	if c == nil || c.admitter == nil || c.selfID == "" {
		return
	}
	snap := c.admitter.Snapshot()
	// Overlay PR-D template inventory before storing — placement reads
	// straight off this lease, so without the overlay our own snapshot
	// would advertise no templates and the unknown-allow rule would
	// let creates land on peers that lack them.
	if c.localTemplateInventory != nil {
		if ids, known := c.localTemplateInventory(); known {
			snap.LocalTemplateInventoryKnown = true
			snap.LocalTemplateIDs = ids
		}
	}
	if c.localWasmModuleInventory != nil {
		if refs, known := c.localWasmModuleInventory(); known {
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
	jobs := make(chan Member)
	var wg sync.WaitGroup
	for i := 0; i < capacityLeaseFetchConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range jobs {
				snap, err := c.fetchMemberCapacity(ctx, m)
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

	for _, m := range members {
		if ctx.Err() != nil {
			break
		}
		if m.NodeID == "" || m.NodeID == c.nodeID || !m.Alive || !CanOwnSandboxRole(m.Role) {
			continue
		}
		if m.APIURL == "" && m.InternalURL == "" {
			continue
		}
		jobs <- m
	}
	close(jobs)
	wg.Wait()
}

func (c *Cluster) fetchMemberCapacity(ctx context.Context, m Member) (capacity.Snapshot, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if c.internalClient != nil && m.InternalURL != "" {
		snap, err := fetchCapacitySnapshot(reqCtx, c.internalClient, strings.TrimRight(m.InternalURL, "/")+"/v1/capacity", c.patToken)
		if err == nil {
			return snap, nil
		}
		if !isStatus(err, http.StatusServiceUnavailable) || m.APIURL == "" {
			return capacity.Snapshot{}, err
		}
	}
	if m.APIURL == "" {
		return capacity.Snapshot{}, fmt.Errorf("node %s has no API URL for capacity heartbeat", m.NodeID)
	}
	return fetchCapacitySnapshot(reqCtx, c.httpClient, strings.TrimRight(m.APIURL, "/")+"/v1/capacity", c.patToken)
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
