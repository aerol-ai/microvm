package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeWarmPool records what the sync applies and reports a fixed status.
type fakeWarmPool struct {
	mu      sync.Mutex
	applied [][]dockerpool.Configured
	status  []dockerpool.TargetStatus
	applyCh chan struct{}
}

func newFakeWarmPool() *fakeWarmPool { return &fakeWarmPool{applyCh: make(chan struct{}, 16)} }

func (f *fakeWarmPool) SetConfigured(c []dockerpool.Configured) {
	f.mu.Lock()
	f.applied = append(f.applied, c)
	f.mu.Unlock()
	f.applyCh <- struct{}{}
}

func (f *fakeWarmPool) ConfiguredStatus() []dockerpool.TargetStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dockerpool.TargetStatus(nil), f.status...)
}

func (f *fakeWarmPool) last() []dockerpool.Configured {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return nil
	}
	return f.applied[len(f.applied)-1]
}

func (f *fakeWarmPool) applies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func (f *fakeWarmPool) waitApply(t *testing.T) []dockerpool.Configured {
	t.Helper()
	select {
	case <-f.applyCh:
		return f.last()
	case <-time.After(5 * time.Second):
		t.Fatal("the sync never applied the entries")
		return nil
	}
}

// waitFor waits until the last applied set satisfies ok. A kick sent before
// the loop started can add one extra apply of the same set, so tests wait
// for the state they expect rather than count applies.
func (f *fakeWarmPool) waitFor(t *testing.T, ok func([]dockerpool.Configured) bool) []dockerpool.Configured {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if last := f.last(); f.applies() > 0 && ok(last) {
			return last
		}
		select {
		case <-f.applyCh:
		case <-deadline:
			t.Fatalf("the sync never applied the expected entries; last = %+v", f.last())
			return nil
		}
	}
}

func newWarmPoolService(t *testing.T) *Service {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), &recordingRuntime{})
	return svc
}

func TestWarmPoolSingleNodeCRUD(t *testing.T) {
	svc := newWarmPoolService(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		image string
		depth int
	}{
		{"empty image", "", 1},
		{"spaces", " python:3.12", 1},
		{"a URL", "https://ghcr.io/x/y", 1},
		{"an empty segment", "ghcr.io//y", 1},
		{"negative depth", "python:3.12", -1},
		{"depth past the limit", "python:3.12", models.MaxWarmPoolDepth + 1},
	} {
		if _, err := svc.PutWarmPool(ctx, tc.image, models.WarmPoolRequest{Depth: tc.depth}); !errors.Is(err, models.ErrWarmPoolInvalid) {
			t.Fatalf("%s: err = %v, want ErrWarmPoolInvalid", tc.name, err)
		}
	}
	p, err := svc.PutWarmPool(ctx, "ghcr.io/acme/agent:1", models.WarmPoolRequest{Depth: 2})
	if err != nil || p.Generation != 1 || p.Depth != 2 || p.Status != nil {
		t.Fatalf("put = %+v %v (a PUT answers without status)", p, err)
	}
	if p, _ = svc.PutWarmPool(ctx, "ghcr.io/acme/agent:1", models.WarmPoolRequest{Depth: 2}); p.Generation != 1 {
		t.Fatalf("the same PUT again must keep generation 1: %+v", p)
	}
	// A single node pools its own built images: they are on this node.
	if _, err := svc.PutWarmPool(ctx, "aerolvm-build/x:1", models.WarmPoolRequest{Depth: 1}); err != nil {
		t.Fatalf("a single node may pool a built image: %v", err)
	}
	got, err := svc.GetWarmPool(ctx, "ghcr.io/acme/agent:1")
	if err != nil || got.Status == nil || got.Status.Servers == nil || len(got.Status.Servers) != 0 {
		t.Fatalf("get = %+v %v (no pool on this node: an empty, non-null server list)", got, err)
	}
	if _, err := svc.GetWarmPool(ctx, "node:22"); !errors.Is(err, ErrWarmPoolNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if _, err := svc.GetWarmPool(ctx, ""); !errors.Is(err, models.ErrWarmPoolInvalid) {
		t.Fatalf("bad image on get = %v", err)
	}
	list, err := svc.ListWarmPools(ctx)
	if err != nil || len(list.Pools) != 2 || list.Pools[0].Status == nil {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := svc.DeleteWarmPool(ctx, "ghcr.io/acme/agent:1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteWarmPool(ctx, "ghcr.io/acme/agent:1"); err != nil {
		t.Fatalf("a repeated delete must succeed: %v", err)
	}
	if err := svc.DeleteWarmPool(ctx, "bad image"); !errors.Is(err, models.ErrWarmPoolInvalid) {
		t.Fatalf("bad image on delete = %v", err)
	}
}

// TestWarmPoolSingleNodeSyncAndStatus: a single node applies its entries at
// start and after every write, with its default runtime on the key, and
// reports its pool's status on reads and on /v1/capacity.
func TestWarmPoolSingleNodeSyncAndStatus(t *testing.T) {
	svc := newWarmPoolService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 3}); err != nil {
		t.Fatal(err)
	}
	pool := newFakeWarmPool()
	svc.RegisterWarmPool(nil, "ignored")
	svc.RegisterWarmPool(pool, " gvisor ")
	svc.StartWarmPoolSync(ctx)
	want := []dockerpool.Configured{{Key: dockerpool.Key{Image: "python:3.12", Runtime: "gvisor"}, Depth: 3}}
	if got := pool.waitApply(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("applied at start = %+v, want %+v", got, want)
	}
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 1}); err != nil {
		t.Fatal(err)
	}
	pool.waitFor(t, func(c []dockerpool.Configured) bool { return len(c) == 1 && c[0].Depth == 1 })
	if err := svc.DeleteWarmPool(ctx, "python:3.12"); err != nil {
		t.Fatal(err)
	}
	pool.waitFor(t, func(c []dockerpool.Configured) bool { return len(c) == 0 })

	pool.mu.Lock()
	pool.status = []dockerpool.TargetStatus{{Key: dockerpool.Key{Image: "python:3.12"}, Ready: 1, Target: 2}}
	pool.mu.Unlock()
	second := newFakeWarmPool()
	second.status = []dockerpool.TargetStatus{{Key: dockerpool.Key{Image: "python:3.12"}, Ready: 2, Target: 2}, {Key: dockerpool.Key{Image: "alpine:3.20"}, Ready: 0, Target: 1}}
	svc.RegisterWarmPool(second, "docker")
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 2}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetWarmPool(ctx, "python:3.12")
	if err != nil {
		t.Fatal(err)
	}
	wantStatus := &models.WarmPoolStatus{Ready: 3, Target: 4, Servers: []models.WarmPoolServerStatus{{NodeID: svc.selfNodeID(), Ready: 3, Target: 4}}}
	if !reflect.DeepEqual(got.Status, wantStatus) {
		t.Fatalf("status = %+v, want %+v (two local pools summed into one server)", got.Status, wantStatus)
	}
	snap := svc.Capacity()
	wantCap := []capacity.WarmPoolStatus{{Image: "alpine:3.20", Ready: 0, Target: 1}, {Image: "python:3.12", Ready: 3, Target: 4}}
	if !reflect.DeepEqual(snap.WarmPools, wantCap) {
		t.Fatalf("capacity warm_pools = %+v, want %+v", snap.WarmPools, wantCap)
	}
}

func TestStartWarmPoolSyncWithoutPools(t *testing.T) {
	svc := newWarmPoolService(t)
	svc.StartWarmPoolSync(context.Background())
	if svc.warmPoolKick != nil {
		t.Fatal("a node with no warm pool must not start the sync")
	}
	var nilSvc *Service
	nilSvc.StartWarmPoolSync(context.Background())
	nilSvc.RegisterWarmPool(newFakeWarmPool(), "docker")
	if nilSvc.localWarmPoolStatus() != nil {
		t.Fatal("a nil service has no status")
	}
	if err := svc.syncWarmPools(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// warmPoolTestCluster is an in-memory replicated entry store with a member
// list, standing in for cluster.Cluster or cluster.Agent.
type warmPoolTestCluster struct {
	*cluster.Noop
	mu       sync.Mutex
	pools    map[string]cluster.WarmPoolRecord
	version  uint64
	members  []cluster.Member
	writeErr error
	readErr  error
	reads    []cluster.WarmPoolReadRequest
	// answer, when set, replaces the next read's response.
	answer *cluster.WarmPoolReadResponse
}

func newWarmPoolTestCluster() *warmPoolTestCluster {
	return &warmPoolTestCluster{Noop: cluster.NewNoop("self", "http://self", ""), pools: map[string]cluster.WarmPoolRecord{}}
}

func (c *warmPoolTestCluster) WriteWarmPool(_ context.Context, req cluster.WarmPoolWriteRequest) (cluster.WarmPoolWriteResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return cluster.WarmPoolWriteResponse{}, c.writeErr
	}
	c.version++
	if req.Delete {
		delete(c.pools, req.Pool.Image)
		return cluster.WarmPoolWriteResponse{}, nil
	}
	p := req.Pool
	p.Generation = c.pools[p.Image].Generation + 1
	p.CreatedUnixNano, p.UpdatedUnixNano = 1, 2
	c.pools[p.Image] = p
	return cluster.WarmPoolWriteResponse{Pool: p, Changed: true}, nil
}

func (c *warmPoolTestCluster) ReadWarmPools(_ context.Context, req cluster.WarmPoolReadRequest) (cluster.WarmPoolReadResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads = append(c.reads, req)
	if c.readErr != nil {
		return cluster.WarmPoolReadResponse{}, c.readErr
	}
	if c.answer != nil {
		out := *c.answer
		c.answer = nil
		return out, nil
	}
	out := cluster.WarmPoolReadResponse{Version: c.version, Authoritative: true}
	if req.Since != 0 && req.Since == c.version {
		out.Unchanged = true
		return out, nil
	}
	out.Pools = []cluster.WarmPoolRecord{}
	for _, p := range c.pools {
		out.Pools = append(out.Pools, p)
	}
	return out, nil
}

func (c *warmPoolTestCluster) Members() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Member(nil), c.members...)
}

func newClusterWarmPoolService(t *testing.T) (*Service, *warmPoolTestCluster) {
	t.Helper()
	svc := newWarmPoolService(t)
	c := newWarmPoolTestCluster()
	svc.AttachCluster(c)
	svc.cfg.EnableCluster = true
	return svc, c
}

func TestClusterWarmPoolBackend(t *testing.T) {
	svc, c := newClusterWarmPoolService(t)
	ctx := context.Background()
	p, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 2})
	if err != nil || p.Generation != 1 || p.Depth != 2 || p.CreatedAt.IsZero() {
		t.Fatalf("put = %+v %v", p, err)
	}
	if rec := c.pools["python:3.12"]; rec.Depth != 2 {
		t.Fatalf("replicated = %+v", rec)
	}
	if _, err := svc.PutWarmPool(ctx, "aerolvm-build/node-x/abc:latest", models.WarmPoolRequest{Depth: 1}); !errors.Is(err, models.ErrWarmPoolInvalid) {
		t.Fatalf("a cluster must refuse a node-local image: %v", err)
	}
	if got, err := svc.GetWarmPool(ctx, "python:3.12"); err != nil || got.Generation != 1 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := svc.GetWarmPool(ctx, "missing:1"); !errors.Is(err, ErrWarmPoolNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if list, err := svc.ListWarmPools(ctx); err != nil || len(list.Pools) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := svc.DeleteWarmPool(ctx, "python:3.12"); err != nil || len(c.pools) != 0 {
		t.Fatalf("delete = %v (%d left)", err, len(c.pools))
	}

	for _, tc := range []struct {
		err  error
		want error
	}{
		{cluster.ErrWarmPoolLimit, ErrWarmPoolLimit},
		{cluster.ErrClusterVersion, ErrWarmPoolsUnavailable},
		{cluster.ErrNotLeader, ErrWarmPoolsUnavailable},
	} {
		c.writeErr = tc.err
		if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 1}); !errors.Is(err, tc.want) {
			t.Fatalf("put with %v = %v, want %v", tc.err, err, tc.want)
		}
		if err := svc.DeleteWarmPool(ctx, "python:3.12"); !errors.Is(err, tc.want) {
			t.Fatalf("delete with %v = %v, want %v", tc.err, err, tc.want)
		}
	}
	c.writeErr = nil
	c.readErr = errors.New("server tier away")
	if _, err := svc.ListWarmPools(ctx); !errors.Is(err, ErrWarmPoolsUnavailable) {
		t.Fatalf("list with the server tier away = %v", err)
	}
	if _, err := svc.GetWarmPool(ctx, "python:3.12"); !errors.Is(err, ErrWarmPoolsUnavailable) {
		t.Fatalf("get with the server tier away = %v", err)
	}

	// A cluster whose client has no replicated store refuses rather than
	// letting each node keep its own entries.
	svc.AttachCluster(cluster.NewNoop("self", "", ""))
	for _, call := range []func() error{
		func() error { _, err := svc.PutWarmPool(ctx, "a", models.WarmPoolRequest{Depth: 1}); return err },
		func() error { _, err := svc.GetWarmPool(ctx, "a"); return err },
		func() error { _, err := svc.ListWarmPools(ctx); return err },
		func() error { return svc.DeleteWarmPool(ctx, "a") },
	} {
		if err := call(); !errors.Is(err, ErrWarmPoolsUnavailable) {
			t.Fatalf("no replicated store = %v", err)
		}
	}
	if err := svc.syncWarmPools(ctx); err != nil {
		t.Fatalf("the sync has nothing to read without a replicated store: %v", err)
	}
}

// TestClusterWarmPoolStatusPerServer: this node reports from its own pools,
// every other live member from its last capacity heartbeat; a dead member
// is left out and a stale one is marked.
func TestClusterWarmPoolStatusPerServer(t *testing.T) {
	svc, c := newClusterWarmPoolService(t)
	ctx := context.Background()
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 2}); err != nil {
		t.Fatal(err)
	}
	local := newFakeWarmPool()
	local.status = []dockerpool.TargetStatus{{Key: dockerpool.Key{Image: "python:3.12"}, Ready: 2, Target: 2}}
	svc.RegisterWarmPool(local, "docker")
	heartbeat := func(ready int) capacity.Snapshot {
		return capacity.Snapshot{WarmPools: []capacity.WarmPoolStatus{{Image: "python:3.12", Ready: ready, Target: 2}}}
	}
	c.members = []cluster.Member{
		{NodeID: "self", Alive: true, Capacity: heartbeat(0)}, // ignored: self reports live
		{NodeID: "worker-b", Alive: true, Capacity: heartbeat(1)},
		{NodeID: "worker-c", Alive: true, Capacity: heartbeat(2), CapacityStale: true},
		{NodeID: "worker-dead", Alive: false, Capacity: heartbeat(2)},
		{NodeID: "server-1", Alive: true}, // no warm pool: not listed
	}
	got, err := svc.GetWarmPool(ctx, "python:3.12")
	if err != nil {
		t.Fatal(err)
	}
	want := &models.WarmPoolStatus{Ready: 5, Target: 6, Servers: []models.WarmPoolServerStatus{
		{NodeID: "self", Ready: 2, Target: 2},
		{NodeID: "worker-b", Ready: 1, Target: 2},
		{NodeID: "worker-c", Ready: 2, Target: 2, Stale: true},
	}}
	if !reflect.DeepEqual(got.Status, want) {
		t.Fatalf("status = %+v\nwant     %+v", got.Status, want)
	}
}

// TestClusterWarmPoolSyncCursor: the sync sends the last version it
// applied, applies nothing on "unchanged", holds back an older answer until
// it repeats warmPoolBehindPolls times, and keeps the pools as they are
// while the server tier is away, logging the outage once.
func TestClusterWarmPoolSyncCursor(t *testing.T) {
	svc, c := newClusterWarmPoolService(t)
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()
	pool := newFakeWarmPool()
	svc.RegisterWarmPool(pool, "docker")
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 2}); err != nil {
		t.Fatal(err)
	}
	sync := func() { svc.syncWarmPoolsLogged(ctx) }
	sync()
	if pool.applies() != 1 || len(pool.last()) != 1 || svc.warmPoolSyncVersion != 1 {
		t.Fatalf("first sync: applies=%d last=%+v version=%d", pool.applies(), pool.last(), svc.warmPoolSyncVersion)
	}
	sync()
	if pool.applies() != 1 || c.reads[len(c.reads)-1].Since != 1 {
		t.Fatalf("an unchanged answer must apply nothing (applies=%d, since=%d)", pool.applies(), c.reads[len(c.reads)-1].Since)
	}
	// A lagging server answers an older, empty list: held back twice, then
	// believed on the third poll in a row.
	for i := 1; i <= warmPoolBehindPolls; i++ {
		c.answer = &cluster.WarmPoolReadResponse{Version: 0, Authoritative: true, Pools: []cluster.WarmPoolRecord{}}
		sync()
		wantApplies := 1
		if i == warmPoolBehindPolls {
			wantApplies = 2
		}
		if pool.applies() != wantApplies {
			t.Fatalf("older answer %d: applies = %d, want %d", i, pool.applies(), wantApplies)
		}
	}
	if len(pool.last()) != 0 || svc.warmPoolSyncVersion != 0 {
		t.Fatalf("after a persistent older answer: last=%+v version=%d", pool.last(), svc.warmPoolSyncVersion)
	}

	c.readErr = errors.New("server tier away")
	sync()
	sync()
	if pool.applies() != 2 {
		t.Fatal("a failed read must leave the pools alone")
	}
	if n := strings.Count(logs.String(), "warm pool sync failed"); n != 1 {
		t.Fatalf("an outage must log once, logged %d times:\n%s", n, logs.String())
	}
	c.readErr = nil
	sync()
	if !strings.Contains(logs.String(), "warm pool sync recovered") || pool.applies() != 3 {
		t.Fatalf("recovery: applies=%d logs=%s", pool.applies(), logs.String())
	}
}

// TestClusterWarmPoolSyncLoopKick: in a cluster a write on this node is
// applied here at once, without waiting for the next poll.
func TestClusterWarmPoolSyncLoopKick(t *testing.T) {
	svc, _ := newClusterWarmPoolService(t)
	ctx, cancel := context.WithCancel(context.Background())
	pool := newFakeWarmPool()
	svc.RegisterWarmPool(pool, "docker")
	svc.StartWarmPoolSync(ctx)
	pool.waitApply(t)
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 2}); err != nil {
		t.Fatal(err)
	}
	pool.waitFor(t, func(c []dockerpool.Configured) bool { return len(c) == 1 })
	cancel()
}

// TestWarmPoolDemandRangeReachesPoolAndCluster (W2): a demand-following
// entry's range is validated, stored, replicated and handed to the pool.
func TestWarmPoolDemandRangeReachesPoolAndCluster(t *testing.T) {
	svc := newWarmPoolService(t)
	ctx := context.Background()
	for _, bad := range []models.WarmPoolRequest{{Depth: 2, MaxDepth: 4}, {MinDepth: 1}, {MinDepth: 5, MaxDepth: 4}} {
		if _, err := svc.PutWarmPool(ctx, "python:3.12", bad); !errors.Is(err, models.ErrWarmPoolInvalid) {
			t.Fatalf("%+v = %v, want ErrWarmPoolInvalid", bad, err)
		}
	}
	p, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{MinDepth: 1, MaxDepth: 4})
	if err != nil || p.MinDepth != 1 || p.MaxDepth != 4 || p.Depth != 0 {
		t.Fatalf("put = %+v %v", p, err)
	}
	pool := newFakeWarmPool()
	svc.RegisterWarmPool(pool, "docker")
	if err := svc.syncWarmPools(ctx); err != nil {
		t.Fatal(err)
	}
	want := []dockerpool.Configured{{Key: dockerpool.Key{Image: "python:3.12", Runtime: "docker"}, MinDepth: 1, MaxDepth: 4}}
	if got := pool.last(); !reflect.DeepEqual(got, want) {
		t.Fatalf("applied = %+v, want %+v", got, want)
	}

	csvc, c := newClusterWarmPoolService(t)
	if p, err := csvc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{MaxDepth: 3}); err != nil || p.MaxDepth != 3 {
		t.Fatalf("cluster put = %+v %v", p, err)
	}
	if rec := c.pools["python:3.12"]; rec.MaxDepth != 3 || rec.MinDepth != 0 {
		t.Fatalf("replicated = %+v", rec)
	}
	if got, err := csvc.GetWarmPool(ctx, "python:3.12"); err != nil || got.MaxDepth != 3 {
		t.Fatalf("cluster get = %+v %v", got, err)
	}
}

// TestWarmPoolOnImageChangeAndOutdated (W3): the strategy is validated,
// answered spelled out, handed to the pool, and each pool's outdated count
// is summed into the server's and the entry's status.
func TestWarmPoolOnImageChangeAndOutdated(t *testing.T) {
	svc := newWarmPoolService(t)
	ctx := context.Background()
	if _, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 1, OnImageChange: "recreate"}); !errors.Is(err, models.ErrWarmPoolInvalid) {
		t.Fatalf("unknown strategy = %v", err)
	}
	p, err := svc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 2})
	if err != nil || p.OnImageChange != models.WarmPoolReplaceNow {
		t.Fatalf("default = %+v %v", p, err)
	}
	if _, err := svc.PutWarmPool(ctx, "node:22", models.WarmPoolRequest{Depth: 1, OnImageChange: models.WarmPoolReplaceAsUsed}); err != nil {
		t.Fatal(err)
	}
	pool := newFakeWarmPool()
	pool.status = []dockerpool.TargetStatus{{Key: dockerpool.Key{Image: "node:22"}, Ready: 2, Target: 2, Outdated: 1}}
	svc.RegisterWarmPool(pool, "docker")
	if err := svc.syncWarmPools(ctx); err != nil {
		t.Fatal(err)
	}
	asUsed := map[string]bool{}
	for _, c := range pool.last() {
		asUsed[c.Key.Image] = c.ReplaceAsUsed
	}
	if !asUsed["node:22"] || asUsed["python:3.12"] {
		t.Fatalf("applied strategies = %v", asUsed)
	}
	got, err := svc.GetWarmPool(ctx, "node:22")
	if err != nil || got.Status.Outdated != 1 || got.Status.Servers[0].Outdated != 1 || got.OnImageChange != models.WarmPoolReplaceAsUsed {
		t.Fatalf("status = %+v %v", got.Status, err)
	}
	if snap := svc.Capacity(); len(snap.WarmPools) != 1 || snap.WarmPools[0].Outdated != 1 {
		t.Fatalf("capacity = %+v", snap.WarmPools)
	}

	csvc, c := newClusterWarmPoolService(t)
	if _, err := csvc.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{Depth: 1, OnImageChange: models.WarmPoolReplaceAsUsed}); err != nil {
		t.Fatal(err)
	}
	if rec := c.pools["python:3.12"]; rec.OnImageChange != models.WarmPoolReplaceAsUsed {
		t.Fatalf("replicated = %+v", rec)
	}
	c.pools["old:1"] = cluster.WarmPoolRecord{Image: "old:1", Depth: 1}
	if got, err := csvc.GetWarmPool(ctx, "old:1"); err != nil || got.OnImageChange != models.WarmPoolReplaceNow {
		t.Fatalf("a record with no strategy reads as replace_now: %+v %v", got, err)
	}
}

// The agent-sandbox API's depths (C17) reach only the pool of their
// runtime, and add to an operator entry for the same image (both are per
// worker).
// A template with no runtimeClassName is parked by every worker in its own
// default runtime: whichever runtime a pool is registered under, it takes
// the default entry, adding to an entry of the same image.
func TestConfiguredForParksTheDefaultRuntimeEntry(t *testing.T) {
	kube := []cluster.KubeWarmDepth{
		{Image: "busybox:1.36", Runtime: cluster.KubeWarmDefaultRuntime, Depth: 1},
		{Image: "python:3.12", Runtime: cluster.KubeWarmDefaultRuntime, Depth: 2},
		{Image: "python:3.12", Runtime: "gvisor", Depth: 3},
	}
	for _, runtime := range []string{"gvisor", "docker"} {
		got := map[string]dockerpool.Configured{}
		for _, c := range configuredFor(runtime, nil, kube) {
			got[c.Key.Image] = c
		}
		want := map[string]int{"busybox:1.36": 1, "python:3.12": 2}
		if runtime == "gvisor" {
			want["python:3.12"] = 5
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %+v, want depths %v", runtime, got, want)
		}
		for img, d := range want {
			if got[img].Depth != d || got[img].Key.Runtime != runtime {
				t.Errorf("%s: %s = %+v, want depth %d in %s", runtime, img, got[img], d, runtime)
			}
		}
	}
}

func TestConfiguredForAddsTheAgentSandboxDepths(t *testing.T) {
	entries := []models.WarmPool{
		{Image: "python:3.12", Depth: 2},
		{Image: "node:22", Depth: 1, MinDepth: 1, MaxDepth: 4},
	}
	kube := []cluster.KubeWarmDepth{
		{Image: "python:3.12", Runtime: "gvisor", Depth: 3},
		{Image: "node:22", Runtime: "gvisor", Depth: 1},
		{Image: "alpine:3.20", Runtime: "gvisor", Depth: 2},
		{Image: "alpine:3.20", Runtime: "runc", Depth: 5},
	}
	byImage := func(c []dockerpool.Configured) map[string]dockerpool.Configured {
		out := map[string]dockerpool.Configured{}
		for _, x := range c {
			out[x.Key.Image] = x
		}
		return out
	}
	g := byImage(configuredFor("gvisor", entries, kube))
	if len(g) != 3 || g["python:3.12"].Depth != 5 || g["alpine:3.20"].Depth != 2 || g["alpine:3.20"].Key.Runtime != "gvisor" {
		t.Fatalf("gvisor pool = %+v", g)
	}
	if n := g["node:22"]; n.Depth != 2 || n.MinDepth != 2 || n.MaxDepth != 5 {
		t.Fatalf("a demand range moves with the added depth: %+v", n)
	}
	d := byImage(configuredFor("docker", entries, kube))
	if len(d) != 2 || d["python:3.12"].Depth != 2 {
		t.Fatalf("another runtime's pool takes none of them: %+v", d)
	}
}

// The depths ride the read a worker already polls.
func TestClusterWarmPoolSyncCarriesTheAgentSandboxDepths(t *testing.T) {
	svc, c := newClusterWarmPoolService(t)
	pool := newFakeWarmPool()
	svc.RegisterWarmPool(pool, "gvisor")
	c.answer = &cluster.WarmPoolReadResponse{Version: 4, Authoritative: true,
		Kube: []cluster.KubeWarmDepth{{Image: "python:3.12", Runtime: "gvisor", Depth: 2}}}
	svc.syncWarmPoolsLogged(context.Background())
	if last := pool.last(); len(last) != 1 || last[0].Key.Image != "python:3.12" || last[0].Depth != 2 {
		t.Fatalf("applied = %+v", last)
	}
}

// A worker logs a warm-pool apply when what it applies changes, not on
// every poll of a cluster that never had an entry (it answers in full).
func TestWarmPoolApplyLogsOnlyAChange(t *testing.T) {
	svc, c := newClusterWarmPoolService(t)
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	svc.RegisterWarmPool(newFakeWarmPool(), "gvisor")
	empty := &cluster.WarmPoolReadResponse{Version: 0, Authoritative: true}
	for range 3 {
		c.answer = empty
		svc.syncWarmPoolsLogged(context.Background())
	}
	if n := strings.Count(logs.String(), "warm pool entries applied"); n != 1 {
		t.Fatalf("logged %d times for the same empty set", n)
	}
	c.answer = &cluster.WarmPoolReadResponse{Version: 5, Authoritative: true, Kube: []cluster.KubeWarmDepth{{Image: "a", Runtime: "gvisor", Depth: 1}}}
	svc.syncWarmPoolsLogged(context.Background())
	if n := strings.Count(logs.String(), "warm pool entries applied"); n != 2 {
		t.Fatalf("a change was not logged (%d)", n)
	}
}
