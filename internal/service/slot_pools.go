package service

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// slotPoolsCacheTTL bounds how stale this node's advertised free slots are.
// A mixed node refreshes its own capacity lease on every placement, so without
// the cache each create it routes would read SQLite (one writer,
// MaxOpenConns=1). Peers pull /v1/capacity every SB_CAPACITY_GOSSIP_INTERVAL,
// so this adds at most a second to what they already lag. It is shorter than
// the template cache's 5s because slots move with every create and destroy.
const slotPoolsCacheTTL = time.Second

// slotPoolCache holds the last LocalSlotPools answer.
type slotPoolCache struct {
	mu      sync.Mutex
	pools   []capacity.SlotPool
	expires time.Time
}

// wasmInstanceCounter is the WASM driver's cheap live count (no per-instance
// worker probe, unlike ListManaged).
type wasmInstanceCounter interface {
	ManagedCount() int
}

// LocalSlotPools reports this node's bounded per-sandbox slot pools and how
// many slots each has free. Service.Capacity and the cluster's own lease
// overlay it on the capacity snapshot, which is how placement learns that a
// node with CPU and memory to spare is still full for a runtime.
//
// The pools, and the runtimes whose creates draw on each:
//   - containerd netns pool (containerd engine with the native netns pool):
//     docker (runc) and gVisor share it. Free counts free and prewarmed rows;
//     rows held by running or stopped sandboxes, warm-parked containers and
//     slots parked as releasing after a failed teardown are not free.
//   - Firecracker TAP pool: unallocated /30 slots (warm VMMs hold theirs).
//   - WASM instances, only when SB_WASM_MAX_INSTANCES caps them.
//
// Nothing is reported for the docker engine (dockerd's own bridge) or for
// isolate's egress slots, which are per tenant group rather than per node; an
// isolate create refuses itself when its group's pool is full.
//
// On a store error it returns the last good answer: a one-off SQLite hiccup
// must not make the node advertise "no slot limit" or "no slots".
func (s *Service) LocalSlotPools(ctx context.Context) []capacity.SlotPool {
	if s == nil {
		return nil
	}
	s.slotPools.mu.Lock()
	defer s.slotPools.mu.Unlock()
	now := time.Now()
	if now.Before(s.slotPools.expires) {
		return slices.Clone(s.slotPools.pools)
	}
	pools, err := s.readSlotPools(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("capacity: read slot pools failed; advertising the last reading", "error", err)
		}
		return slices.Clone(s.slotPools.pools)
	}
	s.slotPools.pools = pools
	s.slotPools.expires = now.Add(slotPoolsCacheTTL)
	return slices.Clone(pools)
}

func (s *Service) readSlotPools(ctx context.Context) ([]capacity.SlotPool, error) {
	var pools []capacity.SlotPool
	if s.store != nil && s.cfg.ContainerEngine == models.ContainerEngineContainerd && s.cfg.ContainerdNativeNetnsPoolEnabled {
		stats, err := s.store.GetContainerNetnsPoolStats(ctx)
		if err != nil {
			return nil, err
		}
		if stats.Total > 0 {
			pools = append(pools, capacity.SlotPool{
				Name:     capacity.SlotPoolContainerNetns,
				Runtimes: []string{models.RuntimeDocker, models.RuntimeGvisor},
				Total:    stats.Total,
				// A prewarmed (pooled) row is claimed first by a create, so
				// it is as good as free.
				Free: stats.Free + stats.Pooled,
			})
		}
	}
	if s.store != nil && s.cfg.EnableFirecracker {
		stats, err := s.store.GetFirecrackerTapPoolStats(ctx)
		if err != nil {
			return nil, err
		}
		if stats.Total > 0 {
			pools = append(pools, capacity.SlotPool{
				Name:     capacity.SlotPoolFirecrackerTap,
				Runtimes: []string{models.RuntimeFirecracker},
				Total:    stats.Total,
				Free:     stats.Free,
			})
		}
	}
	if limit := s.cfg.WasmMaxInstances; limit > 0 && s.wasm != nil {
		if counter, ok := s.wasm.(wasmInstanceCounter); ok {
			pools = append(pools, capacity.SlotPool{
				Name:     capacity.SlotPoolWasmInstances,
				Runtimes: []string{models.RuntimeWasm},
				Total:    limit,
				Free:     max(limit-counter.ManagedCount(), 0),
			})
		}
	}
	return pools, nil
}
