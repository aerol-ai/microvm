package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Warm pools as an API object (plans/agent-sandbox-feature-parity.md W1).
// An entry sets how many warm slots every server with a warm pool keeps for
// one image. Single-node mode keeps entries in the store; a cluster keeps
// them in the Raft FSM, and each node's sync loop hands them to its local
// pool. Per-server status rides each node's capacity heartbeat, so a read
// on any node answers for the fleet without a fan-out.

// ErrWarmPoolNotFound is a GET of an image with no entry (404).
var ErrWarmPoolNotFound = store.ErrWarmPoolNotFound

// ErrWarmPoolLimit is a PUT of a new entry past models.MaxWarmPools (409).
var ErrWarmPoolLimit = store.ErrWarmPoolLimit

// ErrWarmPoolsUnavailable means the replicated entries could not be read or
// written right now: no leader, an unfinished rolling upgrade, or the server
// tier out of reach (503, retry).
var ErrWarmPoolsUnavailable = errors.New("warm pools are unavailable")

// warmPoolSyncInterval is how often a cluster node re-reads the entries. A
// quiet fleet answers each poll with one small "unchanged", so 2,000 workers
// cost the server tier about 200 tiny requests a second.
const warmPoolSyncInterval = 10 * time.Second

// warmPoolBehindPolls is how many polls in a row must answer an older
// version before the sync applies it. A server that lags its peers by a
// few milliseconds answers one older list; applying it would drain an
// entry's slots and park them again a poll later. An older version that
// persists is real (the Raft log was rebuilt), so it is applied in the end.
const warmPoolBehindPolls = 3

// warmPoolBackend stores entries: the store on a single node, the Raft FSM
// in a cluster.
type warmPoolBackend interface {
	PutWarmPool(ctx context.Context, in models.WarmPool, now time.Time) (models.WarmPool, bool, error)
	GetWarmPool(ctx context.Context, image string) (models.WarmPool, error)
	ListWarmPools(ctx context.Context) ([]models.WarmPool, error)
	DeleteWarmPool(ctx context.Context, image string) error
}

// warmPoolCluster is the replicated entry store: the Raft FSM on a server
// (cluster.Cluster), the server tier on a dedicated worker (cluster.Agent).
// The single-node Noop doesn't implement it.
type warmPoolCluster interface {
	WriteWarmPool(context.Context, cluster.WarmPoolWriteRequest) (cluster.WarmPoolWriteResponse, error)
	ReadWarmPools(context.Context, cluster.WarmPoolReadRequest) (cluster.WarmPoolReadResponse, error)
}

// warmPoolApplier is a node-local warm pool the entries configure
// (dockerpool.Pool, which the containerd pool also is).
type warmPoolApplier interface {
	SetConfigured([]dockerpool.Configured)
	ConfiguredStatus() []dockerpool.TargetStatus
}

// registeredWarmPool is one local pool and the runtime its keys carry: the
// node's default runtime, the same one SB_*_POOL_IMAGES pins use, so an
// entry's slots match a create that names only the image.
type registeredWarmPool struct {
	pool    warmPoolApplier
	runtime string
}

func (s *Service) warmPoolBackend() warmPoolBackend {
	if s.warmPoolStore != nil {
		return s.warmPoolStore
	}
	if s.ClusterEnabled() {
		if c, ok := s.Cluster().(warmPoolCluster); ok {
			return clusterWarmPools{c}
		}
		// A node's own store would give each node its own entries.
		return noClusterWarmPools{}
	}
	return s.store
}

// RegisterWarmPool hands a local warm pool to the entry sync. Call it before
// StartWarmPoolSync; a nil pool is ignored.
func (s *Service) RegisterWarmPool(p warmPoolApplier, runtime string) {
	if s == nil || p == nil {
		return
	}
	s.warmPoolMu.Lock()
	defer s.warmPoolMu.Unlock()
	s.warmPoolTargets = append(s.warmPoolTargets, registeredWarmPool{pool: p, runtime: strings.TrimSpace(runtime)})
}

func (s *Service) registeredWarmPools() []registeredWarmPool {
	s.warmPoolMu.Lock()
	defer s.warmPoolMu.Unlock()
	return append([]registeredWarmPool(nil), s.warmPoolTargets...)
}

// PutWarmPool creates or replaces the entry for an image. The same body
// twice is a no-op. A change reaches this node's pool at once and every
// other node's within one sync interval.
func (s *Service) PutWarmPool(ctx context.Context, image string, req models.WarmPoolRequest) (*models.WarmPool, error) {
	if err := models.ValidateWarmPoolImage(image); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	// A built or snapshot image exists on one node only. Every other node
	// would retry its park forever, since an entry is never evicted.
	if s.ClusterEnabled() && docker.IsLocalOnlyImageRef(image) {
		return nil, fmt.Errorf("%w: %s exists on one node only; a cluster warm pool needs an image every node can pull", models.ErrWarmPoolInvalid, image)
	}
	p, changed, err := s.warmPoolBackend().PutWarmPool(ctx, models.WarmPool{
		Image: image, Depth: req.Depth, MinDepth: req.MinDepth, MaxDepth: req.MaxDepth,
		OnImageChange: models.NormalizeWarmPoolOnImageChange(req.OnImageChange),
	}, time.Now())
	if err != nil {
		return nil, err
	}
	if changed {
		s.kickWarmPoolSync()
	}
	return &p, nil
}

// GetWarmPool returns one entry with its status.
func (s *Service) GetWarmPool(ctx context.Context, image string) (*models.WarmPool, error) {
	if err := models.ValidateWarmPoolImage(image); err != nil {
		return nil, err
	}
	p, err := s.warmPoolBackend().GetWarmPool(ctx, image)
	if err != nil {
		return nil, err
	}
	status := s.warmPoolStatuses()
	p.Status = status.forImage(image)
	return &p, nil
}

// ListWarmPools returns every entry, by image, with its status.
func (s *Service) ListWarmPools(ctx context.Context) (*models.WarmPoolList, error) {
	pools, err := s.warmPoolBackend().ListWarmPools(ctx)
	if err != nil {
		return nil, err
	}
	status := s.warmPoolStatuses()
	for i := range pools {
		pools[i].Status = status.forImage(pools[i].Image)
	}
	return &models.WarmPoolList{Pools: pools}, nil
}

// DeleteWarmPool removes the entry for an image; each server's pool for it
// drains. One that is already gone counts as deleted.
func (s *Service) DeleteWarmPool(ctx context.Context, image string) error {
	if err := models.ValidateWarmPoolImage(image); err != nil {
		return err
	}
	if err := s.warmPoolBackend().DeleteWarmPool(ctx, image); err != nil {
		return err
	}
	s.kickWarmPoolSync()
	return nil
}

// localWarmPoolStatus is this node's status for every entry its pools
// carry, summed over its pools, by image.
func (s *Service) localWarmPoolStatus() []capacity.WarmPoolStatus {
	if s == nil {
		return nil
	}
	byImage := map[string]capacity.WarmPoolStatus{}
	for _, reg := range s.registeredWarmPools() {
		for _, st := range reg.pool.ConfiguredStatus() {
			cur := byImage[st.Key.Image]
			cur.Image = st.Key.Image
			cur.Ready += st.Ready
			cur.Target += st.Target
			cur.Outdated += st.Outdated
			byImage[st.Key.Image] = cur
		}
	}
	if len(byImage) == 0 {
		return nil
	}
	out := make([]capacity.WarmPoolStatus, 0, len(byImage))
	for _, st := range byImage {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

// warmPoolStatusSet is each server's status, by image.
type warmPoolStatusSet map[string][]models.WarmPoolServerStatus

func (set warmPoolStatusSet) add(nodeID string, stale bool, statuses []capacity.WarmPoolStatus) {
	for _, st := range statuses {
		set[st.Image] = append(set[st.Image], models.WarmPoolServerStatus{NodeID: nodeID, Ready: st.Ready, Target: st.Target, Outdated: st.Outdated, Stale: stale})
	}
}

// forImage totals one image's servers. An image no server reports has an
// empty status (no server runs a warm pool, or none has applied it yet).
func (set warmPoolStatusSet) forImage(image string) *models.WarmPoolStatus {
	out := &models.WarmPoolStatus{Servers: []models.WarmPoolServerStatus{}}
	for _, srv := range set[image] {
		out.Ready += srv.Ready
		out.Target += srv.Target
		out.Outdated += srv.Outdated
		out.Servers = append(out.Servers, srv)
	}
	sort.Slice(out.Servers, func(i, j int) bool { return out.Servers[i].NodeID < out.Servers[j].NodeID })
	return out
}

// warmPoolStatuses gathers every server's status: this node's from its own
// pools, every other live member's from its last capacity heartbeat.
func (s *Service) warmPoolStatuses() warmPoolStatusSet {
	set := warmPoolStatusSet{}
	self := s.selfNodeID()
	set.add(self, false, s.localWarmPoolStatus())
	if !s.ClusterEnabled() {
		return set
	}
	c := s.Cluster()
	if c == nil {
		return set
	}
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == self {
			continue
		}
		set.add(m.NodeID, m.CapacityStale, m.Capacity.WarmPools)
	}
	return set
}

// StartWarmPoolSync applies the entries to this node's pools now, then on
// every change: at once after a write on this node, and, in a cluster,
// within one poll of a write anywhere. A node with no warm pool skips it.
func (s *Service) StartWarmPoolSync(ctx context.Context) {
	if s == nil || len(s.registeredWarmPools()) == 0 {
		return
	}
	kick := s.warmPoolKickChan()
	go func() {
		ticker := time.NewTicker(warmPoolSyncInterval)
		defer ticker.Stop()
		s.syncWarmPoolsLogged(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// A single node's entries change only through its own API,
				// which kicks; polling its store would only add reads.
				if s.ClusterEnabled() {
					s.syncWarmPoolsLogged(ctx)
				}
			case <-kick:
				s.syncWarmPoolsLogged(ctx)
			}
		}
	}()
}

func (s *Service) warmPoolKickChan() chan struct{} {
	s.warmPoolKickOnce.Do(func() { s.warmPoolKick = make(chan struct{}, 1) })
	return s.warmPoolKick
}

func (s *Service) kickWarmPoolSync() {
	select {
	case s.warmPoolKickChan() <- struct{}{}:
	default:
	}
}

// syncWarmPoolsLogged runs one sync and logs only a change of outcome, so a
// server tier that is away for an hour logs once, not 360 times. A failed
// read leaves the pools as they were.
func (s *Service) syncWarmPoolsLogged(ctx context.Context) {
	err := s.syncWarmPools(ctx)
	s.warmPoolMu.Lock()
	wasFailing := s.warmPoolSyncFailing
	s.warmPoolSyncFailing = err != nil
	s.warmPoolMu.Unlock()
	if s.logger == nil {
		return
	}
	switch {
	case err != nil && !wasFailing:
		s.logger.Warn("warm pool sync failed; pools keep their last entries", "error", err)
	case err == nil && wasFailing:
		s.logger.Info("warm pool sync recovered")
	}
}

// syncWarmPools reads the entries and applies them to every local pool.
func (s *Service) syncWarmPools(ctx context.Context) error {
	pools := s.registeredWarmPools()
	if len(pools) == 0 {
		return nil
	}
	entries, kube, ok, err := s.readWarmPoolsForSync(ctx)
	if err != nil || !ok {
		return err
	}
	for _, reg := range pools {
		reg.pool.SetConfigured(configuredFor(reg.runtime, entries, kube))
	}
	return nil
}

// configuredFor is what a pool of runtime parks: every operator entry, in
// this runtime, plus the agent-sandbox API's depths for this runtime
// (cluster.KubeWarmDepth, C17). Both are per worker, so where they name the
// same image their depths add up.
func configuredFor(runtime string, entries []models.WarmPool, kube []cluster.KubeWarmDepth) []dockerpool.Configured {
	configured := make([]dockerpool.Configured, 0, len(entries)+len(kube))
	at := make(map[string]int, len(entries))
	for _, e := range entries {
		at[e.Image] = len(configured)
		configured = append(configured, dockerpool.Configured{
			Key:   dockerpool.Key{Image: e.Image, Runtime: runtime},
			Depth: e.Depth, MinDepth: e.MinDepth, MaxDepth: e.MaxDepth,
			ReplaceAsUsed: e.OnImageChange == models.WarmPoolReplaceAsUsed,
		})
	}
	for _, k := range kube {
		if k.Runtime != runtime {
			continue
		}
		if i, ok := at[k.Image]; ok {
			c := &configured[i]
			c.Depth += k.Depth
			if c.MaxDepth > 0 {
				c.MinDepth, c.MaxDepth = c.MinDepth+k.Depth, c.MaxDepth+k.Depth
			}
			continue
		}
		at[k.Image] = len(configured)
		configured = append(configured, dockerpool.Configured{Key: dockerpool.Key{Image: k.Image, Runtime: runtime}, Depth: k.Depth})
	}
	return configured
}

// readWarmPoolsForSync returns the entries to apply, and the agent-sandbox
// API's depths (a cluster's only); ok is false when there is nothing new
// (an "unchanged" answer, or an older one being held back).
func (s *Service) readWarmPoolsForSync(ctx context.Context) ([]models.WarmPool, []cluster.KubeWarmDepth, bool, error) {
	if s.warmPoolStore != nil || !s.ClusterEnabled() {
		entries, err := s.warmPoolBackend().ListWarmPools(ctx)
		return entries, nil, err == nil, err
	}
	c, ok := s.Cluster().(warmPoolCluster)
	if !ok {
		return nil, nil, false, nil
	}
	s.warmPoolMu.Lock()
	since := s.warmPoolSyncVersion
	s.warmPoolMu.Unlock()
	resp, err := c.ReadWarmPools(ctx, cluster.WarmPoolReadRequest{Since: since})
	if err != nil {
		return nil, nil, false, err
	}
	if resp.Unchanged {
		return nil, nil, false, nil
	}
	s.warmPoolMu.Lock()
	defer s.warmPoolMu.Unlock()
	if resp.Version < s.warmPoolSyncVersion {
		s.warmPoolSyncBehind++
		if s.warmPoolSyncBehind < warmPoolBehindPolls {
			return nil, nil, false, nil
		}
	}
	s.warmPoolSyncBehind = 0
	s.warmPoolSyncVersion = resp.Version
	entries := make([]models.WarmPool, 0, len(resp.Pools))
	for _, rec := range resp.Pools {
		entries = append(entries, warmPoolFromRecord(rec))
	}
	return entries, resp.Kube, true, nil
}

// clusterWarmPools adapts the replicated store to warmPoolBackend.
type clusterWarmPools struct{ c warmPoolCluster }

func (b clusterWarmPools) PutWarmPool(ctx context.Context, in models.WarmPool, _ time.Time) (models.WarmPool, bool, error) {
	resp, err := b.c.WriteWarmPool(ctx, cluster.WarmPoolWriteRequest{Pool: cluster.WarmPoolRecord{
		Image: in.Image, Depth: in.Depth, MinDepth: in.MinDepth, MaxDepth: in.MaxDepth, OnImageChange: in.OnImageChange,
	}})
	if err != nil {
		return models.WarmPool{}, false, clusterWarmPoolError(err)
	}
	return warmPoolFromRecord(resp.Pool), resp.Changed, nil
}

func (b clusterWarmPools) GetWarmPool(ctx context.Context, image string) (models.WarmPool, error) {
	all, err := b.ListWarmPools(ctx)
	if err != nil {
		return models.WarmPool{}, err
	}
	for _, p := range all {
		if p.Image == image {
			return p, nil
		}
	}
	return models.WarmPool{}, ErrWarmPoolNotFound
}

func (b clusterWarmPools) ListWarmPools(ctx context.Context) ([]models.WarmPool, error) {
	resp, err := b.c.ReadWarmPools(ctx, cluster.WarmPoolReadRequest{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWarmPoolsUnavailable, err)
	}
	out := make([]models.WarmPool, 0, len(resp.Pools))
	for _, rec := range resp.Pools {
		out = append(out, warmPoolFromRecord(rec))
	}
	return out, nil
}

func (b clusterWarmPools) DeleteWarmPool(ctx context.Context, image string) error {
	if _, err := b.c.WriteWarmPool(ctx, cluster.WarmPoolWriteRequest{Delete: true, Pool: cluster.WarmPoolRecord{Image: image}}); err != nil {
		return clusterWarmPoolError(err)
	}
	return nil
}

// clusterWarmPoolError maps the cluster's verdicts onto the service's: the
// FSM's limit keeps its 409, and everything else (no leader, an unfinished
// rolling upgrade, an unreachable server tier) is a retryable 503.
func clusterWarmPoolError(err error) error {
	if errors.Is(err, cluster.ErrWarmPoolLimit) {
		return fmt.Errorf("%w: %v", ErrWarmPoolLimit, err)
	}
	return fmt.Errorf("%w: %v", ErrWarmPoolsUnavailable, err)
}

func warmPoolFromRecord(r cluster.WarmPoolRecord) models.WarmPool {
	return models.WarmPool{
		Image:         r.Image,
		Depth:         r.Depth,
		MinDepth:      r.MinDepth,
		MaxDepth:      r.MaxDepth,
		OnImageChange: models.NormalizeWarmPoolOnImageChange(r.OnImageChange),
		Generation:    r.Generation,
		CreatedAt:     time.Unix(0, r.CreatedUnixNano).UTC(),
		UpdatedAt:     time.Unix(0, r.UpdatedUnixNano).UTC(),
	}
}

// noClusterWarmPools answers every call on a cluster that has no replicated
// entry store wired.
type noClusterWarmPools struct{}

var errNoClusterWarmPools = fmt.Errorf("%w: this cluster has no replicated warm-pool store", ErrWarmPoolsUnavailable)

func (noClusterWarmPools) PutWarmPool(context.Context, models.WarmPool, time.Time) (models.WarmPool, bool, error) {
	return models.WarmPool{}, false, errNoClusterWarmPools
}

func (noClusterWarmPools) GetWarmPool(context.Context, string) (models.WarmPool, error) {
	return models.WarmPool{}, errNoClusterWarmPools
}

func (noClusterWarmPools) ListWarmPools(context.Context) ([]models.WarmPool, error) {
	return nil, errNoClusterWarmPools
}

func (noClusterWarmPools) DeleteWarmPool(context.Context, string) error {
	return errNoClusterWarmPools
}
