//go:build s4live

package cluster

// S4's live half (plans/kubernetes-v2-architecture.md §18): the reserve
// benchmark (BenchmarkReserveCommit) on three real servers, with the
// production Raft setup (setupRaft: TCP transport, raft-wal log, Bolt stable
// store, file snapshots, production timers) on each machine's own disk, so a
// real fsync and network replace the 6.5 ms model. Run the same binary on
// three machines:
//
//	go test -c -tags s4live -o cluster.test ./internal/cluster/
//	S4_ID=s1 S4_ADDR=10.0.0.11:7400 S4_PEERS=s1=10.0.0.11:7400,s2=10.0.0.12:7400,s3=10.0.0.13:7400 \
//	  S4_DIR=/var/lib/s4 ./cluster.test -test.run '^TestS4Live$' -test.v -test.timeout 60m
//
// s1 bootstraps itself and adds the other two as voters, then runs the
// reserves and prints "S4 ..." lines; s2 and s3 serve until S4_HOLD.
// integration-tests/k8s/s4live.sh launches the machines.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func s4Env(t *testing.T, key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	if def == "" {
		t.Skipf("%s is not set: S4 runs on the three machines s4live.sh launches", key)
	}
	return def
}

func s4Placements(f *placementFSM) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.placements)
}

func TestS4Live(t *testing.T) {
	id := s4Env(t, "S4_ID", "")
	addr := s4Env(t, "S4_ADDR", "")
	peers := map[string]string{}
	for _, p := range strings.Split(s4Env(t, "S4_PEERS", ""), ",") {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			t.Fatalf("S4_PEERS entry %q is not id=host:port", p)
		}
		peers[k] = v
	}
	dir := s4Env(t, "S4_DIR", "/var/lib/s4")
	hold, err := time.ParseDuration(s4Env(t, "S4_HOLD", "40m"))
	if err != nil {
		t.Fatal(err)
	}
	// Production timers, not the package tests' short ones.
	testTuneRaft = nil
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fsm := newPlacementFSM()
	rn, err := setupRaft(raftSetupConfig{NodeID: id, BindAddr: addr, AdvertiseAddr: addr, DataDir: dir, BootstrapCluster: id == "s1"}, fsm, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rn.raft.Shutdown().Error() }()
	if id != "s1" {
		t.Logf("S4 %s serving as a follower for %s", id, hold)
		time.Sleep(hold)
		return
	}

	r := rn.raft
	deadline := time.Now().Add(2 * time.Minute)
	for r.State() != raft.Leader {
		if time.Now().After(deadline) {
			t.Fatal("s1 never led its bootstrap")
		}
		time.Sleep(100 * time.Millisecond)
	}
	ids := make([]string, 0, len(peers))
	for p := range peers {
		ids = append(ids, p)
	}
	sort.Strings(ids)
	for _, p := range ids {
		if p == id {
			continue
		}
		for {
			if err := r.AddVoter(raft.ServerID(p), raft.ServerAddress(peers[p]), 0, 30*time.Second).Error(); err == nil {
				break
			} else if time.Now().After(deadline.Add(8 * time.Minute)) {
				t.Fatalf("add %s: %v", p, err)
			}
			time.Sleep(2 * time.Second)
		}
	}
	if err := r.Barrier(30 * time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	t.Logf("S4 three voters: %v", r.GetConfiguration().Configuration().Servers)

	worker := slotWorker("s4-worker", 1<<22, containerAndFC)
	index := newGossipMemberIndex()
	index.replace([]Member{worker})
	c := &Cluster{nodeID: id, cfg: config.Config{}, raft: rn, fsm: fsm, gossip: &gossipNode{memberIndex: index}, commitTimeout: 30 * time.Second}
	target := PlacementTarget{NodeID: worker.NodeID, APIURL: worker.APIURL}
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}

	run := func(prefix string, n, concurrency int) {
		var next atomic.Int64
		lat := make([]time.Duration, n)
		var failed atomic.Int64
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
					t0 := time.Now()
					if err := c.ReserveOnTarget(context.Background(), fmt.Sprintf("sb-%s-%d", prefix, i), target, spec, PlacementSecrets{}, time.Hour); err != nil {
						failed.Add(1)
					}
					lat[i-1] = time.Since(t0)
				}
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)
		sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
		q := func(p float64) time.Duration {
			return lat[min(n-1, int(p*float64(n-1)+0.5))].Round(10 * time.Microsecond)
		}
		fmt.Printf("S4 concurrency=%d reserves=%d failed=%d reserves/s=%.0f latency p50=%s p99=%s max=%s\n",
			concurrency, n, failed.Load(), float64(n)/elapsed.Seconds(), q(0.5), q(0.99), lat[n-1].Round(10*time.Microsecond))
	}
	n1, _ := strconv.Atoi(s4Env(t, "S4_N1", "300"))
	n16, _ := strconv.Atoi(s4Env(t, "S4_N16", "3000"))
	n64, _ := strconv.Atoi(s4Env(t, "S4_N64", "10000"))
	run("c1", n1, 1)
	run("c16", n16, 16)
	run("c64", n64, 64)

	// Fill to S4_FILL placements, then time a snapshot on this disk.
	fill, _ := strconv.Atoi(s4Env(t, "S4_FILL", "100000"))
	if have := s4Placements(fsm); have < fill {
		run("fill", fill-have, 64)
	}
	t0 := time.Now()
	if err := r.Snapshot().Error(); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	fmt.Printf("S4 snapshot at %d placements: %s (copy under the FSM lock, persist to this disk)\n", s4Placements(fsm), time.Since(t0).Round(time.Millisecond))
}
