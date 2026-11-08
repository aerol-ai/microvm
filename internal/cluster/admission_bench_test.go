package cluster

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// reserveBenchLogDelay stands in for the fsync a real Raft log store pays on
// every write (plan item E2: "measure offline first"). 6.5 ms is a typical
// cloud block-volume sync.
const reserveBenchLogDelay = 6500 * time.Microsecond

// slowLogStore is an in-memory Raft log store that sleeps before every write,
// like a disk sync, and counts the writes. hashicorp/raft writes a whole
// group of entries with one StoreLogs call, so writes per reserve shows how
// well concurrent reserves share a sync.
type slowLogStore struct {
	*raft.InmemStore
	delay  time.Duration
	writes atomic.Int64
	// gate, when set, stops every write until it is opened: a commit that
	// tests can freeze half way.
	gate atomic.Pointer[storeGate]
}

// storeGate holds log writes back. entered closes when the first write
// arrives; writes continue once open is called.
type storeGate struct {
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
	openOnce    sync.Once
}

func newStoreGate() *storeGate {
	return &storeGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *storeGate) open() { g.openOnce.Do(func() { close(g.release) }) }

func (s *slowLogStore) StoreLog(l *raft.Log) error { return s.StoreLogs([]*raft.Log{l}) }

func (s *slowLogStore) StoreLogs(logs []*raft.Log) error {
	s.writes.Add(1)
	if g := s.gate.Load(); g != nil {
		g.enteredOnce.Do(func() { close(g.entered) })
		<-g.release
	}
	time.Sleep(s.delay)
	return s.InmemStore.StoreLogs(logs)
}

// reserveBenchCluster is three Raft servers in one process, joined by
// in-memory transports, each with a slow log store. A commit then needs the
// leader's sync and one follower's, as on a real three-server cluster.
type reserveBenchCluster struct {
	leader      *Cluster
	leaderStore *slowLogStore
	target      PlacementTarget
	// nodes, fsms, stores and transports are every server's, leader included.
	ids        []string
	nodes      []*raft.Raft
	fsms       []*placementFSM
	stores     []*slowLogStore
	transports []*raft.InmemTransport
}

func newReserveBenchCluster(tb testing.TB, delay time.Duration) *reserveBenchCluster {
	return newReserveTestCluster(tb, delay, 1<<20)
}

// newReserveTestCluster is newReserveBenchCluster with a target worker of
// workerCPU one-CPU slots.
func newReserveTestCluster(tb testing.TB, delay time.Duration, workerCPU int) *reserveBenchCluster {
	tb.Helper()
	ids := []string{"bench-s1", "bench-s2", "bench-s3"}
	transports := make([]*raft.InmemTransport, len(ids))
	servers := make([]raft.Server, len(ids))
	for i, id := range ids {
		_, transports[i] = raft.NewInmemTransport(raft.ServerAddress(id))
		servers[i] = raft.Server{ID: raft.ServerID(id), Address: raft.ServerAddress(id), Suffrage: raft.Voter}
	}
	for i := range transports {
		for j := range transports {
			if i != j {
				transports[i].Connect(raft.ServerAddress(ids[j]), transports[j])
			}
		}
	}
	nodes := make([]*raft.Raft, len(ids))
	fsms := make([]*placementFSM, len(ids))
	stores := make([]*slowLogStore, len(ids))
	for i, id := range ids {
		conf := raft.DefaultConfig()
		conf.LocalID = raft.ServerID(id)
		conf.HeartbeatTimeout = 300 * time.Millisecond
		conf.ElectionTimeout = 300 * time.Millisecond
		conf.LeaderLeaseTimeout = 150 * time.Millisecond
		conf.LogOutput = io.Discard
		stores[i] = &slowLogStore{InmemStore: raft.NewInmemStore(), delay: delay}
		stable, snaps := raft.NewInmemStore(), raft.NewInmemSnapshotStore()
		if err := raft.BootstrapCluster(conf, stores[i], stable, snaps, transports[i], raft.Configuration{Servers: servers}); err != nil {
			tb.Fatal(err)
		}
		fsms[i] = newPlacementFSM()
		r, err := raft.NewRaft(conf, fsms[i], stores[i], stable, snaps, transports[i])
		if err != nil {
			tb.Fatal(err)
		}
		nodes[i] = r
	}
	tb.Cleanup(func() {
		for _, r := range nodes {
			_ = r.Shutdown().Error()
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		for i, r := range nodes {
			if r.State() != raft.Leader {
				continue
			}
			// The benchmark's worker has room for every reserve a run makes,
			// so it measures the commit path, never a refusal.
			worker := slotWorker("bench-worker", workerCPU, containerAndFC)
			index := newGossipMemberIndex()
			index.replace([]Member{worker})
			c := &Cluster{
				nodeID:        ids[i],
				cfg:           config.Config{},
				raft:          &raftNode{raft: r},
				fsm:           fsms[i],
				gossip:        &gossipNode{memberIndex: index},
				commitTimeout: 10 * time.Second,
			}
			// Wait out the leader's first entries so the run starts on a
			// quiet log.
			if err := r.Barrier(10 * time.Second).Error(); err != nil {
				tb.Fatalf("barrier on the new leader: %v", err)
			}
			return &reserveBenchCluster{
				leader:      c,
				leaderStore: stores[i],
				target:      PlacementTarget{NodeID: worker.NodeID, APIURL: worker.APIURL},
				ids:         ids,
				nodes:       nodes,
				fsms:        fsms,
				stores:      stores,
				transports:  transports,
			}
		}
		if time.Now().After(deadline) {
			tb.Fatal("the in-memory cluster never elected a leader")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// run makes n reserves on the leader from concurrency goroutines, each for
// its own sandbox, and returns the wall time and the leader's log writes.
func (bc *reserveBenchCluster) run(tb testing.TB, prefix string, n, concurrency int) (time.Duration, int64) {
	tb.Helper()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}
	ctx := context.Background()
	writesBefore := bc.leaderStore.writes.Load()
	var next atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := next.Add(1)
				if i > int64(n) {
					return
				}
				id := fmt.Sprintf("sb-%s-%d", prefix, i)
				if err := bc.leader.ReserveOnTarget(ctx, id, bc.target, spec, PlacementSecrets{}, time.Hour); err != nil {
					tb.Errorf("reserve %s: %v", id, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	return time.Since(start), bc.leaderStore.writes.Load() - writesBefore
}

// BenchmarkReserveCommit measures cluster reserves per second through the
// leader's admission and Raft commit, with a 6.5 ms sync on every log write,
// at 1, 16 and 64 concurrent callers. syncs/reserve is the leader's log writes
// per reserve: 1 means every reserve paid its own sync.
//
//	go test -run '^$' -bench BenchmarkReserveCommit -benchtime 512x ./internal/cluster/
func BenchmarkReserveCommit(b *testing.B) {
	for _, concurrency := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("concurrency=%d", concurrency), func(b *testing.B) {
			bc := newReserveBenchCluster(b, reserveBenchLogDelay)
			b.ResetTimer()
			elapsed, writes := bc.run(b, fmt.Sprintf("c%d-n%d", concurrency, b.N), b.N, concurrency)
			b.StopTimer()
			b.ReportMetric(float64(b.N)/elapsed.Seconds(), "reserves/s")
			b.ReportMetric(float64(writes)/float64(b.N), "syncs/reserve")
		})
	}
}
