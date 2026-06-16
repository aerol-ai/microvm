package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func TestGossipDelegateUnusedMethodsCallable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-gossip-stubs", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	d := c.gossip.delegate
	d.NotifyMsg([]byte("ping"))
	if got := d.GetBroadcasts(0, 0); got != nil {
		t.Fatalf("GetBroadcasts() = %v, want nil", got)
	}
	if got := d.LocalState(false); got != nil {
		t.Fatalf("LocalState() = %v, want nil", got)
	}
	d.MergeRemoteState([]byte("state"), false)
}

func TestClusterWasmMigrateHTTPClientBranches(t *testing.T) {
	c := &Cluster{
		httpClient:     http.DefaultClient,
		internalClient: http.DefaultClient,
	}
	if client, base, err := c.wasmMigrateHTTPClient("https://internal", "http://api"); err != nil || client != c.internalClient || base != "https://internal" {
		t.Fatalf("internal path = (%p, %q, %v), want internal client", client, base, err)
	}
	if client, base, err := c.wasmMigrateHTTPClient("", "http://api"); err != nil || client != c.httpClient || base != "http://api" {
		t.Fatalf("public path = (%p, %q, %v)", client, base, err)
	}
	if _, _, err := c.wasmMigrateHTTPClient("", ""); err == nil {
		t.Fatal("expected error when both URLs are empty")
	}
}

func TestClusterApplyEncodedRejectsInvalidPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-bad-encoded", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	if err := c.ApplyEncoded(context.Background(), []byte("not-json")); err == nil {
		t.Fatal("ApplyEncoded() accepted invalid JSON")
	}
}

func TestClusterApplyEncodedRejectsMissingRecoveryRef(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-missing-recovery", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	payload, err := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-missing-recovery",
		OwnerNodeID: c.nodeID,
		RecoveryRef: placementRecoveryRefPrefix + strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := c.ApplyEncoded(context.Background(), payload); err == nil {
		t.Fatal("ApplyEncoded() accepted missing recovery ref")
	}
}

func TestClusterApplyEncodedReservePath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-reserve-encoded", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

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

	payload, err := encodeCommand(command{
		Op:          opReserve,
		SandboxID:   "sb-encoded-reserve",
		OwnerNodeID: c.nodeID,
		Spec:        &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1},
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := c.ApplyEncoded(context.Background(), payload); err != nil {
		t.Fatalf("ApplyEncoded(opReserve): %v", err)
	}
	p, ok := c.PlacementOf("sb-encoded-reserve")
	if !ok || !p.IsReserved() {
		t.Fatalf("placement = %+v ok=%v, want reserved", p, ok)
	}
}

func TestHandleMemberJoinIdempotentForConfiguredVoter(t *testing.T) {
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
	leader.handleMemberJoin(follower.nodeID)
	waitForVoter(t, leader, follower.nodeID, 5*time.Second)
}

func TestHandleMemberJoinSkipsConfiguredNonVoterWithSameAddr(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-nv-join", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	leader.cfg.ClusterMaxAutoVoters = 1

	follower, cleanupFollower := newTestCluster(t, "fol-nv-join", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForServerSuffrage(t, leader, follower.nodeID, raft.Nonvoter, 20*time.Second)

	leader.handleMemberJoin(follower.nodeID)
	waitForServerSuffrage(t, leader, follower.nodeID, raft.Nonvoter, 5*time.Second)
}

func TestAgentTryControlPlaneInternal503DoesNotFallback(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusServiceUnavailable)
	}))
	defer internal.Close()
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("public API must not be called when internal returns 503")
	}))
	defer public.Close()

	agent := &Agent{
		nodeID:         "worker-self",
		httpClient:     public.Client(),
		internalClient: internal.Client(),
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	m := Member{NodeID: "server-1", APIURL: public.URL, InternalURL: internal.URL, Alive: true}
	err := agent.tryControlPlaneMember(context.Background(), m, http.MethodGet, "/v1/cluster/members", InternalAPIPath, nil, nil)
	if err == nil || !isStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("tryControlPlaneMember() = %v, want 503 status error", err)
	}
}

func TestAgentTryControlPlaneMissingAPIURL(t *testing.T) {
	agent := &Agent{
		nodeID:     "worker-self",
		httpClient: http.DefaultClient,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	m := Member{NodeID: "server-1", Alive: true}
	err := agent.tryControlPlaneMember(context.Background(), m, http.MethodGet, "/v1/cluster/members", "/v1/internal/cluster/members", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "API URL unknown") {
		t.Fatalf("tryControlPlaneMember() = %v, want missing API URL error", err)
	}
}

func TestAgentAssertOwnershipFreshPlacementReplaysPortsAndDomains(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-fresh" {
			http.Error(w, "not found", http.StatusNotFound)
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	spec := &models.CreateSandboxRequest{Image: "alpine:3.20"}
	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-fresh",
		Spec:            spec,
		ExposedPorts:    map[int]ExposedPortRoute{8080: {Protocol: "http"}},
		CustomHostnames: []string{"fresh.example.com"},
	}}); err != nil {
		t.Fatalf("AssertOwnership(fresh): %v", err)
	}
	ops := capture.commandsSnapshot()
	wantOps := map[opCode]int{opPlace: 1, opAddExposedPort: 1, opAddCustomDomain: 1}
	for _, cmd := range ops {
		wantOps[cmd.Op]--
	}
	for op, remaining := range wantOps {
		if remaining != 0 {
			t.Fatalf("commands %+v missing op %v (remaining=%d)", ops, op, remaining)
		}
	}
}

func TestAgentAssertOwnershipPromotesSelfReservation(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-reserved" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-reserved",
				Placement: Placement{
					SandboxID:   "sb-reserved",
					OwnerNodeID: "worker-self",
					State:       PlacementStateReserved,
					ExpiresUnix: time.Now().Add(time.Minute).Unix(),
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:           "sb-reserved",
		Spec:         &models.CreateSandboxRequest{Image: "alpine:3.20"},
		ExposedPorts: map[int]ExposedPortRoute{9000: {Protocol: "tcp", HostPort: 29000}},
	}}); err != nil {
		t.Fatalf("AssertOwnership(reserved): %v", err)
	}
	if !captureContainsOp(capture, opPlace) {
		t.Fatalf("expected RecordPlacement promotion, got %+v", capture.commandsSnapshot())
	}
}

func TestAgentAssertOwnershipBackfillsNilSpecOnSelfOwnedRow(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-nil-spec" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-nil-spec",
				Placement: Placement{
					SandboxID:   "sb-nil-spec",
					OwnerNodeID: "worker-self",
					OwnerState:  PlacementOwnerStateActive,
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	spec := &models.CreateSandboxRequest{Image: "alpine:3.20"}
	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-nil-spec",
		Spec: spec,
	}}); err != nil {
		t.Fatalf("AssertOwnership(nil spec): %v", err)
	}
	if !captureContainsOp(capture, opUpsertSpec) {
		t.Fatalf("expected UpsertSpec, got %+v", capture.commandsSnapshot())
	}
}

func TestClusterAssertOwnershipStaleForeignOwnedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-stale-assert", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	payload, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-foreign",
		OwnerNodeID: "other-node",
	})
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("seed placement: %v", err)
	}

	err := c.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-foreign",
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"},
	}})
	if err != nil {
		t.Fatalf("AssertOwnership stale foreign = %v, want nil", err)
	}
	owner, err := c.OwnerOf("sb-foreign")
	if err != nil || owner.NodeID != "other-node" {
		t.Fatalf("OwnerOf after stale assert = %+v err=%v, want other-node", owner, err)
	}
}

func TestClusterAssertOwnershipSkipsEmptySandboxID(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-empty-id", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	if err := c.AssertOwnership(context.Background(), []LocalSandboxState{{ID: ""}}); err != nil {
		t.Fatalf("AssertOwnership empty id = %v, want nil", err)
	}
}

func TestForwardRemoveMemberToLeaderInternalMock(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-rm-fwd", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-rm-fwd", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	// forwardRemoveMemberToLeader resolves the leader via the follower's own raft
	// state; wait until that has propagated, otherwise Leader() is briefly empty.
	waitForLeader(t, follower, 20*time.Second)

	var deleted string
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "ghost-node") {
			deleted = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer internal.Close()

	follower.internalClient = internal.Client()
	follower.gossip.memberIndex.upsert(Member{
		NodeID:      leader.nodeID,
		InternalURL: internal.URL,
		APIURL:      leader.apiURL,
		Alive:       true,
		Role:        config.NodeRoleServer,
	})

	err := follower.forwardRemoveMemberToLeader(context.Background(), "ghost-node", true)
	if err != nil {
		t.Fatalf("forwardRemoveMemberToLeader: %v", err)
	}
	if deleted == "" {
		t.Fatal("internal DELETE was not invoked")
	}
}

func TestTryReassignStuckPlacementNoAlternateTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-no-reassign", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	c.gossip.memberIndex.replace([]Member{recreateCandidate(c.nodeID, "worker", 10)})
	spec := failoverRecreateSpec()
	c.tryReassignStuckPlacement(context.Background(), "sb-stuck", Placement{
		SandboxID:   "sb-stuck",
		Spec:        spec,
		OwnerNodeID: c.nodeID,
	})
}

func TestFSMPlacementsForShardsCustomShardCountScan(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-a", OwnerNodeID: "n1"})
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "n1"})

	shard := PlacementShardForSandbox("sb-a", 7)
	filter := PlacementShardFilter{ShardCount: 7, Shards: []int{shard}}
	got := fsm.placementsForShards(filter)
	if len(got) != 1 || got[0].SandboxID != "sb-a" {
		t.Fatalf("placementsForShards(custom) = %+v, want only sb-a", got)
	}
}

func TestFSMClaimPendingReservationLockedIndexesReservedRow(t *testing.T) {
	fsm := newPlacementFSM()
	expires := time.Now().Add(time.Minute).Unix()
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-res", OwnerNodeID: "node-a",
		Spec:        &models.CreateSandboxRequest{CPU: 2, MemoryMB: 512},
		ExpiresUnix: expires,
	})
	p, ok := fsm.get("sb-res")
	if !ok || !p.IsReserved() {
		t.Fatalf("seed reserved placement = %+v ok=%v", p, ok)
	}
	fsm.mu.Lock()
	fsm.claimPendingReservationLocked("sb-res", p)
	fsm.mu.Unlock()
	if _, ok := fsm.reservedIndex["sb-res"]; !ok {
		t.Fatal("reserved index missing after claimPendingReservationLocked")
	}
}

func TestFSMHydrateCommandRecoveryBatchMissingRef(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb-batch", RecoveryRef: placementRecoveryRefPrefix + strings.Repeat("a", 64)},
		},
	}
	if err := fsm.hydrateCommandRecovery(&cmd); err == nil {
		t.Fatal("hydrateCommandRecovery() accepted missing batch recovery ref")
	}
}

func TestFSMHostnameHelpersEdgeCases(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.claimCustomHostnameLocked("", "example.com")
	fsm.claimCustomHostnameLocked("sb1", "")

	got := insertSortedHostname([]string{"b.example.com"}, "a.example.com")
	want := []string{"a.example.com", "b.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("insertSortedHostname() = %v, want %v", got, want)
	}
	if dup := insertSortedHostname([]string{"a.example.com"}, "a.example.com"); len(dup) != 1 {
		t.Fatalf("duplicate insert = %v, want unchanged slice", dup)
	}
	if removed := removeHostname([]string{"a.example.com", "b.example.com"}, "missing.example.com"); len(removed) != 2 {
		t.Fatalf("removeHostname(missing) = %v, want unchanged", removed)
	}
	if removed := removeHostname([]string{"only.example.com"}, "only.example.com"); removed != nil {
		t.Fatalf("removeHostname(last) = %v, want nil", removed)
	}
}

func TestMemberAliveNilGossipAndMissingMember(t *testing.T) {
	c := &Cluster{}
	if c.memberAlive("any") {
		t.Fatal("memberAlive with nil gossip should be false")
	}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	c.gossip.memberIndex.upsert(Member{NodeID: "alive-node", Alive: true})
	if !c.memberAlive("alive-node") {
		t.Fatal("memberAlive(alive-node) = false, want true")
	}
	if c.memberAlive("missing-node") {
		t.Fatal("memberAlive(missing-node) = true, want false")
	}
}

func TestClusterRemoveMemberUnknownOnLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-unknown-member", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	err := c.RemoveMember(context.Background(), "never-joined", true)
	if !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("RemoveMember(unknown) = %v, want ErrUnknownMember", err)
	}
}

func captureContainsOp(capture *agentControlPlaneCapture, want opCode) bool {
	for _, cmd := range capture.commandsSnapshot() {
		if cmd.Op == want {
			return true
		}
	}
	return false
}

func TestApplyEncodedLocalReturnsFSMErrorOnDuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-fsm-apply-err", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	first, err := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-dup-a", OwnerNodeID: c.nodeID,
		Spec: &models.CreateSandboxRequest{Name: "dup-name"},
	})
	if err != nil {
		t.Fatalf("encode first: %v", err)
	}
	if err := c.applyEncodedLocal(context.Background(), first); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second, err := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-dup-b", OwnerNodeID: c.nodeID,
		Spec: &models.CreateSandboxRequest{Name: "dup-name"},
	})
	if err != nil {
		t.Fatalf("encode second: %v", err)
	}
	if err := c.applyEncodedLocal(context.Background(), second); err == nil {
		t.Fatal("second apply with duplicate name should fail")
	}
}

func TestApplyEncodedLocalUsesShorterContextDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-ctx-deadline", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	payload, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-ctx-deadline", OwnerNodeID: c.nodeID})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer cancel()
	if err := c.applyEncodedLocal(ctx, payload); err != nil {
		t.Fatalf("applyEncodedLocal with deadline: %v", err)
	}
}

func TestAgentAssertOwnershipForeignActiveDefaultBranch(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-foreign-active" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-foreign-active",
				Placement: Placement{
					SandboxID:   "sb-foreign-active",
					OwnerNodeID: "other-node",
					OwnerState:  PlacementOwnerStateActive,
				},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-foreign-active",
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"},
	}}); err != nil {
		t.Fatalf("AssertOwnership foreign active = %v, want nil", err)
	}
	if len(capture.commandsSnapshot()) != 0 {
		t.Fatalf("foreign active row should not mutate FSM, got %+v", capture.commandsSnapshot())
	}
}

func TestAgentAssertOwnershipClaimOrphanErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-orphan-err":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-orphan-err",
				Placement: Placement{
					SandboxID:           "sb-orphan-err",
					OwnerState:          PlacementOwnerStateOrphaned,
					OrphanedOwnerNodeID: "worker-self",
				},
				Orphaned: true,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, PublicInternalRecoveryPath):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
			http.Error(w, "apply failed", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "server-1", APIURL: srv.URL, Alive: true, Role: config.NodeRoleServer})
	agent := &Agent{
		nodeID:     "worker-self",
		apiURL:     "http://worker-self",
		httpClient: srv.Client(),
		gossip:     &gossipNode{memberIndex: index},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-orphan-err",
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"},
	}})
	if err == nil {
		t.Fatal("expected claim orphan failure to propagate")
	}
}

func TestAgentPlacementPageSuccessAndFailure(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsPagePath {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementPageResponse{
				Placements: []Placement{{SandboxID: "sb-page", Version: 3}},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer okSrv.Close()

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "server-1", APIURL: okSrv.URL, Alive: true, Role: config.NodeRoleServer})
	agent := &Agent{
		nodeID:     "worker-self",
		httpClient: okSrv.Client(),
		gossip:     &gossipNode{memberIndex: index},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	page := agent.PlacementPage(PlacementPageRequest{Limit: 10})
	if len(page.Placements) != 1 || page.Placements[0].SandboxID != "sb-page" {
		t.Fatalf("PlacementPage() = %+v, want sb-page", page)
	}
	if agent.PlacementVersion() != 3 {
		t.Fatalf("PlacementVersion() = %d, want 3", agent.PlacementVersion())
	}

	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failSrv.Close()
	index.upsert(Member{NodeID: "server-1", APIURL: failSrv.URL, Alive: true, Role: config.NodeRoleServer})
	agent.httpClient = failSrv.Client()
	if got := agent.PlacementPage(PlacementPageRequest{Limit: 5}); len(got.Placements) != 0 {
		t.Fatalf("PlacementPage() on failure = %+v, want empty", got)
	}
}

func TestNewAgentCloseReleasesGossip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestClusterWithRole(t, "ldr-agent-close", config.NodeRoleServer, true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 5*time.Second)

	agent, _ := newTestAgentWithRole(t, "wkr-close", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	waitForGossipMember(t, leader, agent.SelfNodeID(), 10*time.Second)
	if err := agent.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func TestCapacityLeaseCacheNilAndEmptyNodeGuards(t *testing.T) {
	var nilCache *capacityLeaseCache
	nilCache.set("node", capacity.Snapshot{}, time.Now())
	nilCache.SetLocalTemplateIDsProvider(func() ([]string, bool) { return nil, false })
	nilCache.SetLocalWasmModuleIDsProvider(func() ([]string, bool) { return nil, false })

	cache := newCapacityLeaseCache("self", nil, time.Second, nil)
	cache.set("", capacity.Snapshot{}, time.Now())
}

func TestClusterAttachInternalHandlerWithoutServer(t *testing.T) {
	c := &Cluster{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.AttachInternalHandler(http.NotFoundHandler())
}

func TestClusterUpsertSpecOnLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-upsert-spec", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	if err := c.RecordPlacement(context.Background(), "sb-upsert", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 2}
	if err := c.UpsertSpec(context.Background(), "sb-upsert", spec, PlacementSecrets{Ref: "secret-ref", Version: 1}); err != nil {
		t.Fatalf("UpsertSpec: %v", err)
	}
	got, ok := c.PlacementOf("sb-upsert")
	if !ok || got.Spec == nil || got.Spec.CPU != 2 {
		t.Fatalf("placement after upsert = %+v ok=%v", got, ok)
	}
}

func TestAgentAssertOwnershipSkipsEmptyID(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-real" {
			http.Error(w, "not found", http.StatusNotFound)
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{
		{ID: ""},
		{ID: "sb-real", Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"}},
	}); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}
}

func TestAgentAssertOwnershipSelfOwnedReplaysPortsAndDomains(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-owned" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-owned",
				Placement: Placement{
					SandboxID:   "sb-owned",
					OwnerNodeID: "worker-self",
					Spec:        spec,
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-owned",
		Spec:            spec,
		ExposedPorts:    map[int]ExposedPortRoute{8080: {Protocol: "http"}},
		CustomHostnames: []string{"owned.example.com"},
	}}); err != nil {
		t.Fatalf("AssertOwnership(self owned): %v", err)
	}
	if captureContainsOp(capture, opUpsertSpec) {
		t.Fatalf("expected no UpsertSpec when spec already present, got %+v", capture.commandsSnapshot())
	}
	if !captureContainsOp(capture, opAddExposedPort) || !captureContainsOp(capture, opAddCustomDomain) {
		t.Fatalf("expected port/domain replay, got %+v", capture.commandsSnapshot())
	}
}

func TestAgentAssertOwnershipReservedReplaysCustomDomains(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-res-domains" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-res-domains",
				Placement: Placement{
					SandboxID:   "sb-res-domains",
					OwnerNodeID: "worker-self",
					State:       PlacementStateReserved,
					ExpiresUnix: time.Now().Add(time.Minute).Unix(),
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-res-domains",
		Spec:            &models.CreateSandboxRequest{Image: "alpine:3.20"},
		CustomHostnames: []string{"reserved.example.com"},
	}}); err != nil {
		t.Fatalf("AssertOwnership(reserved domains): %v", err)
	}
	if !captureContainsOp(capture, opPlace) || !captureContainsOp(capture, opAddCustomDomain) {
		t.Fatalf("expected promote + domain replay, got %+v", capture.commandsSnapshot())
	}
}

func TestClusterAssertOwnershipForeignOrphanNotClaimable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-foreign-orphan", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-foreign-orphan", OwnerNodeID: "other-node"})
	if err := c.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatalf("place: %v", err)
	}
	orphan, _ := encodeCommand(command{Op: opOrphanOwner, NodeID: "other-node"})
	if err := c.raft.raft.Apply(orphan, 2*time.Second).Error(); err != nil {
		t.Fatalf("orphan: %v", err)
	}

	err := c.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-foreign-orphan",
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"},
	}})
	if err != nil {
		t.Fatalf("AssertOwnership foreign orphan = %v, want nil", err)
	}
	if p, ok := c.PlacementOf("sb-foreign-orphan"); !ok || !p.IsOrphaned() || p.OrphanedOwnerNodeID != "other-node" {
		t.Fatalf("placement should remain foreign orphan, got %+v ok=%v", p, ok)
	}
}

func TestCapacityLeaseLoopTicksOnInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-lease-tick", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	worker, cleanupWorker := newTestAgentWithRole(t, "wkr-lease-tick", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupWorker()
	waitForGossipMember(t, leader, worker.SelfNodeID(), 10*time.Second)

	time.Sleep(1500 * time.Millisecond)
	leader.refreshCapacityLeases(context.Background())
	members := leader.Members()
	if len(members) < 2 {
		t.Fatalf("Members() = %d, want at least leader+worker", len(members))
	}
}

func TestEvictDeadOwnerRemovesRaftVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-evict-voter", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-evict-voter", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-on-follower", OwnerNodeID: follower.nodeID})
	if err := leader.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatalf("place on follower: %v", err)
	}

	leader.gossip.memberIndex.upsert(Member{NodeID: follower.nodeID, Alive: false, Role: config.NodeRoleServer, RaftAddr: follower.cfg.RaftAdvertiseAddr})
	leader.deadOwners.markDead(follower.nodeID, time.Now().Add(-time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leader.evictDeadOwner(ctx, follower.nodeID)

	cfgFuture := leader.raft.raft.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		t.Fatalf("GetConfiguration: %v", err)
	}
	for _, srv := range cfgFuture.Configuration().Servers {
		if string(srv.ID) == follower.nodeID {
			t.Fatalf("follower %q still in raft config after eviction", follower.nodeID)
		}
	}
}

func TestClusterPlacementsForShardsCustomCount(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-shard-wrap", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	if err := c.RecordPlacement(context.Background(), "sb-shard-wrap", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	shard := PlacementShardForSandbox("sb-shard-wrap", 7)
	filter := PlacementShardFilter{ShardCount: 7, Shards: []int{shard}}
	got := c.PlacementsForShards(filter)
	if len(got) != 1 || got[0].SandboxID != "sb-shard-wrap" {
		t.Fatalf("PlacementsForShards(custom) = %+v", got)
	}
}

func TestAgentApplyCommandExternalizeFailure(t *testing.T) {
	agent := &Agent{
		nodeID: "worker-self",
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip: &gossipNode{memberIndex: newGossipMemberIndex()},
	}
	err := agent.applyCommand(context.Background(), command{
		Op:        opPlace,
		SandboxID: "sb-no-recovery-peers",
		Spec:      &models.CreateSandboxRequest{Image: "alpine"},
	})
	if err == nil || !strings.Contains(err.Error(), "no live server-role control-plane members") {
		t.Fatalf("applyCommand() = %v, want recovery replication failure", err)
	}
}
