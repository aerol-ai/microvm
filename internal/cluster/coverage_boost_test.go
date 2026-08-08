package cluster

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"
)

func TestFollowerForwardApplyInternalChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-int-fwd", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-int-fwd", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	internalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != InternalAPIPath {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := leader.ApplyEncoded(r.Context(), body); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer internalSrv.Close()

	follower.internalClient = internalSrv.Client()
	follower.gossip.memberIndex.upsert(Member{
		NodeID:      leader.nodeID,
		InternalURL: internalSrv.URL,
		APIURL:      leader.apiURL,
		Alive:       true,
		Role:        config.NodeRoleServer,
	})

	payload, err := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-int-fwd",
		OwnerNodeID: follower.nodeID,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	forwardApplyEventually(t, follower, payload)
	if _, err := leader.OwnerOf("sb-int-fwd"); err != nil {
		t.Fatalf("leader OwnerOf after internal forward: %v", err)
	}
}

func TestForwardApplyLeaderAPIURLMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-missing-url", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-missing-url", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	follower.internalClient = nil
	follower.gossip.memberIndex.upsert(Member{
		NodeID: leader.nodeID,
		Alive:  true,
		Role:   config.NodeRoleServer,
	})

	payload, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-missing-url", OwnerNodeID: follower.nodeID})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	err = follower.forwardApplyToLeader(context.Background(), payload)
	if !errors.Is(err, ErrNotLeader) {
		t.Fatalf("forwardApplyToLeader missing API URL = %v, want ErrNotLeader", err)
	}
}

func TestLeaderApplyEncodedSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-apply-encoded", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	payload, err := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-apply-encoded",
		OwnerNodeID: c.nodeID,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := c.ApplyEncoded(context.Background(), payload); err != nil {
		t.Fatalf("ApplyEncoded on leader: %v", err)
	}
	if _, err := c.OwnerOf("sb-apply-encoded"); err != nil {
		t.Fatalf("OwnerOf after ApplyEncoded: %v", err)
	}
}

func TestApplyCommandReturnsPlacementConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-conflict", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	seed, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-conflict", OwnerNodeID: "other-node"})
	if err != nil {
		t.Fatalf("encode seed placement: %v", err)
	}
	if err := c.raft.raft.Apply(seed, 2*time.Second).Error(); err != nil {
		t.Fatalf("seed placement: %v", err)
	}
	err = c.RecordPlacement(context.Background(), "sb-conflict", nil, PlacementSecrets{})
	if err == nil || !strings.Contains(err.Error(), ErrReservationConflict.Error()) {
		t.Fatalf("RecordPlacement conflicting owner = %v, want reservation conflict", err)
	}
}

func TestAgentDoHTTPRequestErrorBranches(t *testing.T) {
	type testcase struct {
		status int
		body   string
		check  func(error) bool
	}
	cases := []testcase{
		{http.StatusTooManyRequests, ErrCreateBackpressure.Error(), func(err error) bool {
			return errors.Is(err, ErrCreateBackpressure)
		}},
		{http.StatusServiceUnavailable, ErrNotLeader.Error(), func(err error) bool {
			return errors.Is(err, ErrNotLeader)
		}},
		{http.StatusServiceUnavailable, ErrCapacityExceeded.Error(), func(err error) bool {
			return errors.Is(err, ErrCapacityExceeded)
		}},
		{http.StatusServiceUnavailable, ErrNoPlacementTarget.Error(), func(err error) bool {
			return errors.Is(err, ErrNoPlacementTarget)
		}},
		{http.StatusNotFound, ErrUnknownMember.Error(), func(err error) bool {
			return errors.Is(err, ErrUnknownMember)
		}},
		{http.StatusConflict, ErrMemberStillAlive.Error(), func(err error) bool {
			return errors.Is(err, ErrMemberStillAlive)
		}},
		{http.StatusConflict, ErrLastVoter.Error(), func(err error) bool {
			return errors.Is(err, ErrLastVoter)
		}},
		{http.StatusTeapot, "", func(err error) bool {
			return isStatus(err, http.StatusTeapot)
		}},
	}

	for i, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, tc.body, tc.status)
		}))
		index := newGossipMemberIndex()
		index.upsert(Member{NodeID: "server-1", APIURL: srv.URL, Alive: true, Role: config.NodeRoleServer})
		agent := &Agent{
			nodeID:     "worker-self",
			httpClient: srv.Client(),
			gossip:     &gossipNode{memberIndex: index},
			logger:     slog.Default(),
		}
		err := agent.RemoveMember(context.Background(), "ghost", false)
		srv.Close()
		if !tc.check(err) {
			t.Fatalf("case %d status=%d: err=%v", i, tc.status, err)
		}
	}
}

func TestAgentControlPlaneFailoverAfterNotLeader(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, ErrNotLeader.Error(), http.StatusServiceUnavailable)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"leader": "server-2"})
	}))
	defer srv2.Close()

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "server-1", APIURL: srv1.URL, Alive: true, Role: config.NodeRoleServer})
	index.upsert(Member{NodeID: "server-2", APIURL: srv2.URL, Alive: true, Role: config.NodeRoleServer})
	agent := &Agent{
		nodeID:     "worker-self",
		httpClient: http.DefaultClient,
		gossip:     &gossipNode{memberIndex: index},
		logger:     slog.Default(),
	}
	for range 8 {
		if got := agent.Leader(); got == "server-2" {
			return
		}
	}
	t.Fatal("Leader() never observed server-2 after retrying shuffled control-plane members")
}

func TestAgentTryControlPlaneInternalSuccess(t *testing.T) {
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("public API should not be called when internal succeeds")
	}))
	defer public.Close()
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != InternalAPIPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer internal.Close()

	index := newGossipMemberIndex()
	index.upsert(Member{
		NodeID:      "server-1",
		APIURL:      public.URL,
		InternalURL: internal.URL,
		Alive:       true,
		Role:        config.NodeRoleServer,
	})
	agent := &Agent{
		nodeID:         "worker-self",
		httpClient:     public.Client(),
		internalClient: internal.Client(),
		gossip:         &gossipNode{memberIndex: index},
		logger:         slog.Default(),
	}
	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-internal-apply", OwnerNodeID: "worker-self"})
	if err := agent.applyEncodedToControlPlane(context.Background(), payload); err != nil {
		t.Fatalf("applyEncodedToControlPlane via internal: %v", err)
	}
}

func TestAgentAssertOwnershipLookupFailureAndStale(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-lookup-fail" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return true
		}
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-stale" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-stale",
				Placement: Placement{
					SandboxID:   "sb-stale",
					OwnerNodeID: "other-owner",
					OwnerState:  PlacementOwnerStateActive,
				},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{
		{ID: "sb-lookup-fail"},
		{ID: "sb-stale"},
	})
	if err == nil {
		t.Fatal("expected lookup failure to propagate")
	}
	if len(capture.commandsSnapshot()) != 0 {
		t.Fatalf("stale/non-claimable rows should not mutate FSM, got %+v", capture.commandsSnapshot())
	}
}

func TestAgentAssertOwnershipClaimsOrphanWithPortsAndDomains(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-orphan" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-orphan",
				Placement: Placement{
					SandboxID:           "sb-orphan",
					OwnerNodeID:         "",
					OwnerState:          PlacementOwnerStateOrphaned,
					OrphanedOwnerNodeID: "worker-self",
				},
				Orphaned: true,
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	spec := &models.CreateSandboxRequest{Image: "alpine"}
	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-orphan",
		Spec:            spec,
		CustomHostnames: []string{"orphan.example.com"},
		ExposedPorts:    map[int]ExposedPortRoute{8080: {Protocol: "http", PublicURL: "https://orphan"}},
	}}); err != nil {
		t.Fatalf("AssertOwnership claim orphan: %v", err)
	}
	cmds := capture.commandsSnapshot()
	if len(cmds) != 3 {
		t.Fatalf("commands = %+v, want claim + port + domain", cmds)
	}
}

func TestAgentSecretsOfAndExposedPortsLookupFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "server-1", APIURL: srv.URL, Alive: true, Role: config.NodeRoleServer})
	agent := &Agent{
		nodeID:     "worker-self",
		httpClient: srv.Client(),
		gossip:     &gossipNode{memberIndex: index},
		logger:     slog.Default(),
	}
	if got := agent.SecretsOf("sb-x"); got.Ref != "" || got.Version != 0 {
		t.Fatalf("SecretsOf on error = %+v", got)
	}
	if got := agent.ExposedPortsOf("sb-x"); got != nil {
		t.Fatalf("ExposedPortsOf on error = %+v", got)
	}
}

func TestAgentPlacementsShardQueryCaches(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	shard := PlacementShardForSandbox("sb-shard-cache", DefaultPlacementShardCount)
	filter := PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{shard}}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsQueryPath {
			var got PlacementShardFilter
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode shard filter: %v", err)
			}
			capture.appendShardFilter(got)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]Placement{{SandboxID: "sb-shard-cache", Version: 7}})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	got := agent.PlacementsForShards(filter)
	if len(got) != 1 || got[0].SandboxID != "sb-shard-cache" {
		t.Fatalf("PlacementsForShards = %+v", got)
	}
	if filters := capture.shardFiltersSnapshot(); len(filters) != 1 {
		t.Fatalf("shard filters = %+v", filters)
	}
	cached := agent.PlacementsForShards(filter)
	if len(cached) != 1 {
		t.Fatalf("cached shard placements = %+v", cached)
	}
}

func TestAgentMembersPrefersControlPlaneResponse(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/cluster/members" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Members []Member `json:"members"`
			}{Members: []Member{{NodeID: "from-api", Alive: true}}})
			return true
		}
		return false
	}), Member{NodeID: "from-gossip", Alive: true, Role: config.NodeRoleServer})

	members := agent.Members()
	if len(members) != 1 || members[0].NodeID != "from-api" {
		t.Fatalf("Members() = %+v, want control-plane response", members)
	}
	_ = capture
}

func TestHandleMemberJoinIdempotentOnVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-join-idem", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-join-idem", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	leader.handleMemberJoin(follower.nodeID)
	waitForVoter(t, leader, follower.nodeID, 2*time.Second)
}

func TestHandleMemberJoinSkipsMissingRaftAddr(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-join-no-raft", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	leader.gossip.memberIndex.upsert(Member{NodeID: "ghost-peer", Alive: true, Role: config.NodeRoleServer})
	leader.handleMemberJoin("ghost-peer")
}

func TestDoLeaderApplyNotLeaderAndBackpressure(t *testing.T) {
	c := &Cluster{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "warming", http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	if err := c.doLeaderApply(context.Background(), ts.Client(), ts.URL, []byte("x")); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("503 generic = %v, want ErrNotLeader", err)
	}

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, ErrCreateBackpressure.Error(), http.StatusServiceUnavailable)
	}))
	defer ts2.Close()
	if err := c.doLeaderApply(context.Background(), ts2.Client(), ts2.URL, []byte("x")); !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("503 backpressure = %v", err)
	}
}

func TestStatusErrorEmptyMessage(t *testing.T) {
	err := statusError{status: http.StatusBadGateway}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("statusError empty message = %q", err.Error())
	}
}

func TestNewAgentJoinsGossipWithoutRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-agent-join", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-agent-join", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	waitForGossipMember(t, leader, agent.SelfNodeID(), 10*time.Second)
	agent.AttachInternalHandler(http.NotFoundHandler())
}

func TestClusterReserveOnTargetApplyReservationPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-reserve-apply", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 8192, DiskTotalGB: 100, DiskFreeGB: 100},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	)
	c.gossip.delegate.mu.Lock()
	c.gossip.delegate.admitter = admitter
	c.gossip.delegate.mu.Unlock()
	c.gossip.refreshMemberIndex()
	c.capacityLeases.admitter = admitter
	c.capacityLeases.set(c.nodeID, admitter.Snapshot(), time.Now())

	ctx := context.Background()
	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost}
	if err := c.ReserveOnTarget(ctx, "sb-reserve-path", target, nil, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if _, ok := c.PlacementOf("sb-reserve-path"); !ok {
		t.Fatal("expected reserved placement")
	}
}

func writeTestClusterTLSDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, tlsCert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, tlsCAFile), caPEM, 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, tlsNodeCertFile), caPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, tlsNodeKeyFile), keyPEM, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return dir
}

func newTestClusterWithTLSDir(t *testing.T, nodeID string, bootstrap bool, gossipPeers []string, tlsDir string) (*Cluster, func()) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for attempt := 0; attempt < 5; attempt++ {
		testClusterMu.Lock()
		apiURL := fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t))
		raftPort := pickFreeTCPPort(t)
		gossipPort := pickFreeTCPPort(t)
		dir := t.TempDir()
		cfg := config.Config{
			EnableCluster:                 true,
			NodeID:                        nodeID,
			RaftBindAddr:                  fmt.Sprintf("127.0.0.1:%d", raftPort),
			RaftAdvertiseAddr:             fmt.Sprintf("127.0.0.1:%d", raftPort),
			RaftDataDir:                   filepath.Join(dir, "raft"),
			GossipBindAddr:                fmt.Sprintf("127.0.0.1:%d", gossipPort),
			GossipAdvertiseAddr:           fmt.Sprintf("127.0.0.1:%d", gossipPort),
			BootstrapPeers:                gossipPeers,
			ClusterBootstrap:              bootstrap,
			SelfAPIAdvertiseURL:           apiURL,
			ClusterRaftCommitTimeout:      2 * time.Second,
			ClusterCapacityGossipInterval: time.Second,
			ClusterTLSDir:                 tlsDir,
			ClusterInternalListenAddr:     fmt.Sprintf("127.0.0.1:%d", pickFreeTCPPort(t)),
		}
		c, err := New(cfg, logger, nil)
		testClusterMu.Unlock()
		if err == nil {
			return c, func() {
				testClusterMu.Lock()
				defer testClusterMu.Unlock()
				if err := c.Close(); err != nil {
					t.Logf("cluster.Close(%s): %v", nodeID, err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("cluster.New(%s, tls): %v", nodeID, err)
		}
	}
	t.Fatalf("cluster.New(%s, tls): failed after retries due to port collisions", nodeID)
	return nil, nil
}

func newTestClusterWithTLS(t *testing.T, nodeID string, bootstrap bool, gossipPeers []string) (*Cluster, func()) {
	t.Helper()
	return newTestClusterWithTLSDir(t, nodeID, bootstrap, gossipPeers, writeTestClusterTLSDir(t))
}

func newTestAgentWithTLS(t *testing.T, nodeID, role string, gossipPeers []string) (*Agent, func()) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tlsDir := writeTestClusterTLSDir(t)
	for attempt := 0; attempt < 5; attempt++ {
		testClusterMu.Lock()
		gossipPort := pickFreeTCPPort(t)
		apiURL := fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t))
		cfg := config.Config{
			EnableCluster:                 true,
			NodeID:                        nodeID,
			NodeRole:                      role,
			GossipBindAddr:                fmt.Sprintf("127.0.0.1:%d", gossipPort),
			GossipAdvertiseAddr:           fmt.Sprintf("127.0.0.1:%d", gossipPort),
			BootstrapPeers:                gossipPeers,
			SelfAPIAdvertiseURL:           apiURL,
			ClusterRaftCommitTimeout:      2 * time.Second,
			ClusterCapacityGossipInterval: time.Second,
			ClusterTLSDir:                 tlsDir,
			ClusterInternalListenAddr:     fmt.Sprintf("127.0.0.1:%d", pickFreeTCPPort(t)),
		}
		a, err := NewAgent(cfg, logger, nil)
		testClusterMu.Unlock()
		if err == nil {
			return a, func() {
				testClusterMu.Lock()
				defer testClusterMu.Unlock()
				if err := a.Close(); err != nil {
					t.Logf("agent.Close(%s): %v", nodeID, err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("cluster.NewAgent(%s, tls): %v", nodeID, err)
		}
	}
	t.Fatalf("cluster.NewAgent(%s, tls): failed after retries due to port collisions", nodeID)
	return nil, nil
}

func TestClusterBootstrapWithTLSInternalServer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestClusterWithTLS(t, "ldr-tls", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	if c.internalClient == nil || c.internalURL == "" || c.internalServer == nil {
		t.Fatalf("tls cluster missing internal wiring: client=%v url=%q server=%v", c.internalClient, c.internalURL, c.internalServer)
	}
	if got := c.LeaderAPIURL(); got != c.apiURL {
		t.Fatalf("LeaderAPIURL(self) = %q, want %q", got, c.apiURL)
	}
	c.AttachInternalHandler(http.NotFoundHandler())
}

func TestNewAgentWithTLSInternalServer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestClusterWithTLS(t, "ldr-tls-agent", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	agent, cleanupAgent := newTestAgentWithTLS(t, "wkr-tls", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	if agent.internalClient == nil || agent.internalURL == "" || agent.internalServer == nil {
		t.Fatalf("tls agent missing internal wiring")
	}
	agent.AttachInternalHandler(http.NotFoundHandler())
}

func TestDeriveInternalAdvertiseURLAndSplitHost(t *testing.T) {
	if got := deriveInternalAdvertiseURL("https://custom.internal", "0.0.0.0:8443", "0.0.0.0:9443"); got != "https://custom.internal" {
		t.Fatalf("operator override = %q", got)
	}
	if got := deriveInternalAdvertiseURL("", "127.0.0.5:0", "0.0.0.0:9443"); got != "https://127.0.0.5:9443" {
		t.Fatalf("listen host fallback = %q", got)
	}
	if got := deriveInternalAdvertiseURL("", "0.0.0.0:0", "0.0.0.0:9443"); got != "https://127.0.0.1:9443" {
		t.Fatalf("loopback fallback = %q", got)
	}
	host, port := splitHostForAdvertise("[::1]:8443")
	if host != "::1" || port != "8443" {
		t.Fatalf("ipv6 split = (%q, %q)", host, port)
	}
	host, port = splitHostForAdvertise("bare-host")
	if host != "bare-host" || port != "" {
		t.Fatalf("bare host split = (%q, %q)", host, port)
	}
}

func TestClusterReadWrapperPaths(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{
		Op:            opPlace,
		SandboxID:     "sb-read",
		OwnerNodeID:   "node-a",
		Spec:          &models.CreateSandboxRequest{Image: "alpine"},
		SecretRef:     "secret-ref",
		SecretVersion: 2,
	})
	applyOp(t, fsm, command{Op: opAddExposedPort, SandboxID: "sb-read", Port: 80, Protocol: "http"})
	applyOp(t, fsm, command{Op: opAddCustomDomain, SandboxID: "sb-read", Hostname: "read.example.com"})

	c := &Cluster{nodeID: "node-a", apiURL: "http://node-a", fsm: fsm}
	if spec := c.SpecOf("sb-read"); spec == nil || spec.Image != "alpine" {
		t.Fatalf("SpecOf = %+v", spec)
	}
	if got := c.SecretsOf("sb-read"); got.Ref != "secret-ref" {
		t.Fatalf("SecretsOf = %+v", got)
	}
	ports := c.ExposedPortsOf("sb-read")
	if ports[80].Protocol != "http" {
		t.Fatalf("ExposedPortsOf = %+v", ports)
	}
	if len(c.CustomDomainsOf("sb-read")) != 1 {
		t.Fatalf("CustomDomainsOf = %v", c.CustomDomainsOf("sb-read"))
	}
	_, ok := c.ResolveCustomDomain("read.example.com")
	if !ok {
		t.Fatal("ResolveCustomDomain expected true")
	}
}

func TestAgentPlacementPageHarness(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsPagePath {
			var req PlacementPageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode page req: %v", err)
			}
			capture.appendPageRequest(req)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementPageResponse{
				Placements:    []Placement{{SandboxID: "sb-page", Version: 3}},
				NextPageToken: "next",
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	out := agent.PlacementPage(PlacementPageRequest{Limit: 5})
	if out.NextPageToken != "next" || len(out.Placements) != 1 {
		t.Fatalf("PlacementPage = %+v", out)
	}
}

func TestApplyEncodedLocalReturnsNotLeaderWhenFollowerApplies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-apply-local", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	payload, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-local-apply", OwnerNodeID: c.nodeID})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if c.raft.raft.State() != raft.Leader {
		t.Fatal("expected leader for setup")
	}
	if err := c.applyEncodedLocal(context.Background(), payload); err != nil {
		t.Fatalf("applyEncodedLocal on leader: %v", err)
	}
}

func TestClusterAssertOwnershipClaimOrphanIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-claim-orphan", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx := context.Background()
	if err := c.RecordPlacement(ctx, "sb-orphan-int", &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}); err != nil {
		t.Fatalf("seed placement: %v", err)
	}
	orphanPayload, err := encodeCommand(command{Op: opOrphanOwner, NodeID: c.nodeID})
	if err != nil {
		t.Fatalf("encode orphan: %v", err)
	}
	if err := c.raft.raft.Apply(orphanPayload, 2*time.Second).Error(); err != nil {
		t.Fatalf("orphan owner: %v", err)
	}

	spec := &models.CreateSandboxRequest{Image: "alpine"}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-orphan-int",
		Spec:            spec,
		CustomHostnames: []string{"orphan-int.example.com"},
		ExposedPorts:    map[int]ExposedPortRoute{9000: {Protocol: "http"}},
	}}); err != nil {
		t.Fatalf("AssertOwnership claim orphan: %v", err)
	}
	got, ok := c.PlacementOf("sb-orphan-int")
	if !ok || got.OwnerNodeID != c.nodeID || got.IsOrphaned() {
		t.Fatalf("placement after claim = %+v, ok=%v", got, ok)
	}
}

func TestFollowerForwardApplySharedTLSInternalChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	tlsDir := writeTestClusterTLSDir(t)
	leader, cleanupLeader := newTestClusterWithTLSDir(t, "ldr-tls-fwd", true, nil, tlsDir)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestClusterWithTLSDir(t, "fol-tls-fwd", false, []string{leader.gossip.ml.LocalNode().Address()}, tlsDir)
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	follower.gossip.memberIndex.upsert(Member{
		NodeID:      leader.nodeID,
		InternalURL: leader.internalURL,
		APIURL:      leader.apiURL,
		Alive:       true,
		Role:        config.NodeRoleServer,
	})

	payload, err := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-tls-fwd",
		OwnerNodeID: follower.nodeID,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	forwardApplyEventually(t, follower, payload)
	if _, err := leader.OwnerOf("sb-tls-fwd"); err != nil {
		t.Fatalf("leader OwnerOf after tls forward: %v", err)
	}
}

func TestFSMValidateHostPortLazyIndexRebuild(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placements["sb-existing"] = Placement{
		SandboxID: "sb-existing",
		ExposedPortRoutes: map[int]ExposedPortRoute{
			443: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22443},
		},
	}
	fsm.hostPortIndex = nil

	if err := fsm.validateHostPortAvailableLocked("sb-new", 443, ExposedPortRoute{
		Protocol: models.ExposedPortProtocolTCP,
		HostPort: 22443,
	}); err == nil {
		t.Fatal("expected host port conflict after lazy index rebuild")
	}
	if err := fsm.validateHostPortAvailableLocked("sb-new", 80, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("non-tcp route should skip validation: %v", err)
	}
}

func TestRemoveMemberRejectsLastVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-last-voter", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	err := c.RemoveMember(context.Background(), c.nodeID, true)
	if !errors.Is(err, ErrLastVoter) {
		t.Fatalf("RemoveMember(self) = %v, want ErrLastVoter", err)
	}
}

func TestHandleMemberJoinWaitsForRaftAddrThenPromotes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-join-addr", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-join-addr", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()

	leader.gossip.memberIndex.upsert(Member{NodeID: follower.nodeID, Alive: true, Role: config.NodeRoleServer})
	leader.handleMemberJoin(follower.nodeID)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if leader.peerRaftAddr(follower.nodeID) != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	leader.handleMemberJoin(follower.nodeID)
	waitForVoter(t, leader, follower.nodeID, 10*time.Second)
}

func TestClusterRefreshCapacityLeases(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-cap-refresh", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	worker, cleanupWorker := newTestAgentWithRole(t, "wkr-cap-refresh", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupWorker()
	waitForGossipMember(t, leader, worker.SelfNodeID(), 10*time.Second)

	leader.refreshCapacityLeases(context.Background())
	members := leader.Members()
	if len(members) == 0 {
		t.Fatal("expected members after capacity refresh")
	}
}

func TestNewClusterRejectsInvalidTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, tlsCAFile), []byte("not-a-pem"), 0o644); err != nil {
		t.Fatalf("write bad ca: %v", err)
	}
	cfg := config.Config{
		EnableCluster:       true,
		NodeRole:            config.NodeRoleServer,
		SelfAPIAdvertiseURL: "http://127.0.0.1:1",
		ClusterTLSDir:       dir,
		RaftBindAddr:        "127.0.0.1:0",
		RaftAdvertiseAddr:   "127.0.0.1:0",
		RaftDataDir:         t.TempDir(),
		GossipBindAddr:      "127.0.0.1:0",
		GossipAdvertiseAddr: "127.0.0.1:0",
		ClusterBootstrap:    true,
	}
	_, err := New(cfg, slog.Default(), nil)
	if err == nil {
		t.Fatal("expected error for invalid tls material")
	}
}

func TestVoterAutoJoinDelegateNotifyUpdateNoPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-notify-update", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	d := &voterAutoJoinDelegate{c: leader}
	d.NotifyUpdate(&memberlist.Node{Name: leader.nodeID})
}
