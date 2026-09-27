package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"
)

func encodedMeta(t *testing.T, nodeID, role string) []byte {
	t.Helper()
	raw, err := json.Marshal(nodeMeta{NodeID: nodeID, Role: role, InternalURL: "https://" + nodeID})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGossipPeerCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := newGossipPeerCache(dir)
	if got := c.load(); got != nil {
		t.Fatalf("load on a missing cache = %v, want nil", got)
	}

	if err := c.remember([]string{"10.0.0.3:7001", "10.0.0.2:7001", "10.0.0.2:7001", ""}); err != nil {
		t.Fatalf("remember: %v", err)
	}
	want := []string{"10.0.0.2:7001", "10.0.0.3:7001"}
	if got := newGossipPeerCache(dir).load(); !slices.Equal(got, want) {
		t.Fatalf("reloaded peers = %v, want %v (sorted, de-duplicated)", got, want)
	}
	info, err := os.Stat(filepath.Join(dir, gossipPeerCacheFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cache mode = %o, want 600", perm)
	}
}

// The moment a node is alone is the moment it needs its old peers; an empty
// observation must never overwrite them.
func TestGossipPeerCacheNeverForgetsWhenIsolated(t *testing.T) {
	dir := t.TempDir()
	c := newGossipPeerCache(dir)
	if err := c.remember([]string{"10.0.0.2:7001"}); err != nil {
		t.Fatal(err)
	}
	if err := c.remember(nil); err != nil {
		t.Fatal(err)
	}
	if got := newGossipPeerCache(dir).load(); !slices.Equal(got, []string{"10.0.0.2:7001"}) {
		t.Fatalf("peers after an isolated observation = %v, want the previous list kept", got)
	}
}

func TestGossipPeerCacheSkipsUnchangedWrites(t *testing.T) {
	dir := t.TempDir()
	c := newGossipPeerCache(dir)
	if err := c.remember([]string{"10.0.0.2:7001"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, gossipPeerCacheFile)
	// Make the file unwritable-by-replacement: if remember wrote again the
	// rename onto a directory would fail and surface as an error.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.remember([]string{"10.0.0.2:7001"}); err != nil {
		t.Fatalf("unchanged remember touched the disk: %v", err)
	}
	if err := c.remember([]string{"10.0.0.9:7001"}); err == nil {
		t.Fatal("changed remember onto a directory = nil error, want the write failure surfaced")
	}
}

func TestGossipPeerCacheIgnoresCorruptFileAndNilReceiver(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, gossipPeerCacheFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := newGossipPeerCache(dir).load(); got != nil {
		t.Fatalf("load of a corrupt cache = %v, want nil", got)
	}
	var none *gossipPeerCache
	if newGossipPeerCache("") != nil {
		t.Fatal("empty dir should disable the cache")
	}
	if none.load() != nil || none.remember([]string{"x:1"}) != nil {
		t.Fatal("nil cache must be inert")
	}
}

func TestNormalizeGossipPeersBoundsTheList(t *testing.T) {
	var in []string
	for i := 20; i > 0; i-- {
		in = append(in, fmt.Sprintf("10.0.0.%02d:7001", i))
	}
	got := normalizeGossipPeers(in)
	if len(got) != maxCachedGossipPeers {
		t.Fatalf("len = %d, want %d", len(got), maxCachedGossipPeers)
	}
	if !slices.IsSorted(got) {
		t.Fatalf("not sorted: %v", got)
	}
}

func TestMergeRejoinPeers(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		cached     []string
		self       string
		want       []string
	}{
		{"seed with no configured peers uses the cache", nil, []string{"b:1", "c:1"}, "a:1", []string{"b:1", "c:1"}},
		{"configured first, cache de-duplicated", []string{"c:1"}, []string{"b:1", "c:1"}, "a:1", []string{"c:1", "b:1"}},
		{"self never dialled", []string{"a:1"}, []string{"a:1", ""}, "a:1", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeRejoinPeers(tc.configured, tc.cached, tc.self); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLiveControlPlanePeerAddrsKeepsOnlyLiveServers(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	nodes := []*memberlist.Node{
		nil,
		{Name: "self", Addr: ip, Port: 7001, State: memberlist.StateAlive, Meta: encodedMeta(t, "self", "mixed")},
		{Name: "srv", Addr: net.ParseIP("10.0.0.2"), Port: 7001, State: memberlist.StateAlive, Meta: encodedMeta(t, "srv", "server")},
		{Name: "mix", Addr: net.ParseIP("10.0.0.3"), Port: 7001, State: memberlist.StateAlive, Meta: encodedMeta(t, "mix", "mixed")},
		{Name: "wrk", Addr: net.ParseIP("10.0.0.4"), Port: 7001, State: memberlist.StateAlive, Meta: encodedMeta(t, "wrk", "worker")},
		{Name: "dead", Addr: net.ParseIP("10.0.0.5"), Port: 7001, State: memberlist.StateDead, Meta: encodedMeta(t, "dead", "server")},
		{Name: "noaddr", State: memberlist.StateAlive, Meta: encodedMeta(t, "noaddr", "server")},
	}
	got := liveControlPlanePeerAddrs(nodes, "self")
	want := []string{"10.0.0.2:7001", "10.0.0.3:7001"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A node with no configured peers — the seed — must still rejoin through the
// peers it remembers. Before the cache, maybeRejoinBootstrapPeers returned
// early whenever SB_CLUSTER_PEERS was empty.
func TestMaybeRejoinUsesRememberedPeersWithoutConfiguredOnes(t *testing.T) {
	dir := t.TempDir()
	if err := newGossipPeerCache(dir).remember([]string{"10.0.0.2:7001"}); err != nil {
		t.Fatal(err)
	}
	var dialled []string
	gn := &gossipNode{
		joinBootstrapPeers: func(peers []string) (int, error) {
			dialled = append(dialled, peers...)
			return len(peers), nil
		},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		delegate:       &gossipDelegate{nodeID: "self"},
		peerCache:      newGossipPeerCache(dir),
		selfGossipAddr: "10.0.0.1:7001",
	}
	gn.peerCache.load()

	gn.maybeRejoinBootstrapPeers(nil)
	if !slices.Equal(dialled, []string{"10.0.0.2:7001"}) {
		t.Fatalf("dialled %v, want the remembered peer", dialled)
	}

	gn.rememberLivePeers([]*memberlist.Node{{Name: "p", Addr: net.ParseIP("10.0.0.7"), Port: 7001, State: memberlist.StateAlive, Meta: encodedMeta(t, "p", "server")}})
	if got := newGossipPeerCache(dir).load(); !slices.Equal(got, []string{"10.0.0.7:7001"}) {
		t.Fatalf("remembered %v after observing a new live peer", got)
	}
}

// TestRestartedSeedRejoinsAfterEviction replays the live S2 failure on
// loopback: the seed (bootstrap, no peers) is stopped, the two joiners elect a
// leader and evict it, then the seed restarts from its own raft dir — still
// with no peers, exactly as systemd restarts it. It must find the cluster
// again and be re-admitted as a voter. Without the peer cache the seed stays a
// gossip island and a lone raft candidate forever.
func TestRestartedSeedRejoinsAfterEviction(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node raft election test")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	seedDir := t.TempDir()
	seedTLS := writeTestClusterTLSDir(t, "seed")
	seedCfg := func() config.Config {
		return config.Config{
			EnableCluster:                 true,
			NodeID:                        "seed",
			RaftBindAddr:                  "127.0.0.1:0",
			RaftAdvertiseAddr:             "127.0.0.1:0",
			RaftDataDir:                   filepath.Join(seedDir, "raft"),
			GossipBindAddr:                "127.0.0.1:0",
			GossipAdvertiseAddr:           "127.0.0.1:0",
			ClusterBootstrap:              true,
			SelfAPIAdvertiseURL:           fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t)),
			ClusterRaftCommitTimeout:      2 * time.Second,
			ClusterCapacityGossipInterval: 500 * time.Millisecond,
			ClusterTLSDir:                 seedTLS,
			ClusterInternalListenAddr:     "127.0.0.1:0",
		}
	}

	testClusterMu.Lock()
	seed, err := New(seedCfg(), logger, nil)
	testClusterMu.Unlock()
	if err != nil {
		t.Fatalf("seed New: %v", err)
	}
	waitForLeader(t, seed, 10*time.Second)
	seedGossip := seed.gossip.ml.LocalNode().Address()

	n2, close2 := newTestClusterWithCfg(t, "n2", false, []string{seedGossip}, func(c *config.Config) {
		c.ClusterDeadOwnerGrace = 200 * time.Millisecond
	})
	defer close2()
	n3, close3 := newTestClusterWithCfg(t, "n3", false, []string{seedGossip}, func(c *config.Config) {
		c.ClusterDeadOwnerGrace = 200 * time.Millisecond
	})
	defer close3()
	waitForVoter(t, seed, "n2", 20*time.Second)
	waitForVoter(t, seed, "n3", 20*time.Second)
	// The seed has to have observed its peers alive to remember them.
	waitFor(t, 10*time.Second, "seed to remember its peers", func() bool {
		return len(newGossipPeerCache(seedCfg().RaftDataDir).load()) == 2
	})

	testClusterMu.Lock()
	_ = seed.Close()
	testClusterMu.Unlock()

	var leader *Cluster
	waitFor(t, 20*time.Second, "survivors to elect a leader", func() bool {
		for _, c := range []*Cluster{n2, n3} {
			if c.raft.raft.State() == raft.Leader {
				leader = c
				return true
			}
		}
		return false
	})
	waitFor(t, 30*time.Second, "leader to evict the stopped seed", func() bool {
		_, ok := leader.configuredServer("seed")
		return !ok
	})

	testClusterMu.Lock()
	restarted, err := New(seedCfg(), logger, nil)
	testClusterMu.Unlock()
	if err != nil {
		t.Fatalf("seed restart: %v", err)
	}
	defer func() {
		testClusterMu.Lock()
		_ = restarted.Close()
		testClusterMu.Unlock()
	}()

	waitForVoter(t, leader, "seed", 40*time.Second)
	waitFor(t, 20*time.Second, "restarted seed to follow the new leader", func() bool {
		return restarted.Leader() == leader.SelfNodeID()
	})
}

func waitFor(t *testing.T, max time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", max, what)
}
