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

func TestClusterAssertOwnershipSelfOwnedBackfillsSpecAndPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-self-backfill", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	ctx := context.Background()
	if err := c.RecordPlacement(ctx, "sb-self-backfill", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 4}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-self-backfill",
		Spec:            spec,
		CustomHostnames: []string{"self-backfill.example.com"},
		ExposedPorts:    map[int]ExposedPortRoute{8080: {Protocol: "http", PublicURL: "https://self"}},
	}}); err != nil {
		t.Fatalf("AssertOwnership self-owned backfill: %v", err)
	}
	got, ok := c.PlacementOf("sb-self-backfill")
	if !ok || got.Spec == nil || got.Spec.CPU != 4 {
		t.Fatalf("placement spec = %+v ok=%v, want CPU=4", got, ok)
	}
	ports := c.ExposedPortsOf("sb-self-backfill")
	if ports == nil || ports[8080].PublicURL != "https://self" {
		t.Fatalf("ExposedPortsOf = %+v", ports)
	}
}

func TestClusterAssertOwnershipReservedReplaysPortsAndDomains(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-reserved-ports", true, nil)
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

	ctx := context.Background()
	if err := c.ReserveOnTarget(ctx, "sb-reserved-ports", PlacementTarget{
		NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost,
	}, &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-reserved-ports",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"reserved-ports.example.com"},
		ExposedPorts:    map[int]ExposedPortRoute{7070: {Protocol: "tcp", HostPort: 17070}},
	}}); err != nil {
		t.Fatalf("AssertOwnership reserved replay: %v", err)
	}
	ports := c.ExposedPortsOf("sb-reserved-ports")
	if ports == nil || ports[7070].HostPort != 17070 {
		t.Fatalf("ExposedPortsOf after reserved promote = %+v", ports)
	}
}

func TestClusterAssertOwnershipFailsWithoutLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	iso, cleanup := newTestCluster(t, "iso-no-leader", false, nil)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := iso.AssertOwnership(ctx, []LocalSandboxState{{
		ID:   "sb-no-leader",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}})
	if err == nil {
		t.Fatal("AssertOwnership without leader expected error")
	}
}

func TestApplyEncodedLocalOnFollowerReturnsNotLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-local-follower", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "fol-local-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	payload, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-follower-local", OwnerNodeID: follower.nodeID})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if follower.raft.raft.State() == raft.Leader {
		t.Fatal("follower should not be leader")
	}
	if err := follower.applyEncodedLocal(context.Background(), payload); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("follower applyEncodedLocal = %v, want ErrNotLeader", err)
	}
}

func TestApplyReservationEncodedLocalNotLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-res-local", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "fol-res-local", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	payload, err := encodeCommand(command{
		Op: opReserve, SandboxID: "sb-res-local", OwnerNodeID: follower.nodeID,
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	err = follower.applyReservationEncodedLocal(context.Background(), payload, command{Op: opReserve, SandboxID: "sb-res-local"})
	if !errors.Is(err, ErrNotLeader) {
		t.Fatalf("follower applyReservationEncodedLocal = %v, want ErrNotLeader", err)
	}
}

func TestReserveOnTargetAdmitFailureMissingWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-admit-fail", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	err := c.ReserveOnTarget(context.Background(), "sb-admit-fail", PlacementTarget{
		NodeID: "ghost-worker", APIURL: "http://ghost:8080",
	}, nil, PlacementSecrets{}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "not an alive placement target") {
		t.Fatalf("ReserveOnTarget ghost worker = %v, want placement target error", err)
	}
}

func TestClusterSecretsAndExposedPortHelpers(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-port-helpers", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	ctx := context.Background()
	secrets := PlacementSecrets{Ref: "ref-1", Version: 2, LegacySealed: []byte("sealed")}
	if err := c.RecordPlacement(ctx, "sb-helpers", &models.CreateSandboxRequest{Image: "alpine"}, secrets); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if got := c.SecretsOf("missing"); got.Ref != "" {
		t.Fatalf("SecretsOf(missing) = %+v, want zero", got)
	}
	if got := c.SecretsOf("sb-helpers"); got.Ref != "ref-1" || got.Version != 2 {
		t.Fatalf("SecretsOf = %+v", got)
	}
	if sealed := c.SealedSecretsOf("sb-helpers"); string(sealed) != "sealed" {
		t.Fatalf("SealedSecretsOf = %q", sealed)
	}
	if err := c.AddExposedPort(ctx, "sb-helpers", 3000, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("AddExposedPort: %v", err)
	}
	if ports := c.ExposedPortsOf("sb-helpers"); ports == nil || ports[3000].Protocol != "http" {
		t.Fatalf("ExposedPortsOf = %+v", ports)
	}
	if err := c.RemoveExposedPort(ctx, "sb-helpers", 3000); err != nil {
		t.Fatalf("RemoveExposedPort: %v", err)
	}
	if ports := c.ExposedPortsOf("sb-helpers"); len(ports) != 0 {
		t.Fatalf("ExposedPortsOf after remove = %+v, want empty", ports)
	}
	if err := c.AddExposedPort(ctx, "sb-helpers", 0, ExposedPortRoute{}); err != nil {
		t.Fatalf("AddExposedPort port<=0: %v", err)
	}
	if err := c.RemoveExposedPort(ctx, "sb-helpers", 0); err != nil {
		t.Fatalf("RemoveExposedPort port<=0: %v", err)
	}
}

func TestClusterUpsertSpecNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-upsert-noop", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	if err := c.UpsertSpec(context.Background(), "sb-none", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec no-op: %v", err)
	}
}

func TestRemoveMemberRejectsAliveMemberWithoutForce(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-alive-member", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "fol-alive-member", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	err := leader.RemoveMember(context.Background(), follower.nodeID, false)
	if !errors.Is(err, ErrMemberStillAlive) {
		t.Fatalf("RemoveMember(alive) = %v, want ErrMemberStillAlive", err)
	}
}

func TestNoopAttachInternalHandlerCallable(t *testing.T) {
	n := &Noop{nodeID: "solo", apiURL: "http://127.0.0.1:8080"}
	n.AttachInternalHandler(http.NotFoundHandler())
}

func TestFSMValidateReservationBatchLockedErrors(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now().Unix()

	fsm.mu.Lock()
	err := fsm.validateReservationBatchLocked([]reservationCommand{{SandboxID: "", OwnerNodeID: "n"}}, now)
	fsm.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "sandbox_id") {
		t.Fatalf("empty sandbox_id = %v", err)
	}

	fsm.mu.Lock()
	err = fsm.validateReservationBatchLocked([]reservationCommand{
		{SandboxID: "dup", OwnerNodeID: "n1"},
		{SandboxID: "dup", OwnerNodeID: "n1"},
	}, now)
	fsm.mu.Unlock()
	if err == nil || !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("duplicate sandbox in batch = %v", err)
	}

	applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "placed", OwnerNodeID: "owner-a",
		Spec: &models.CreateSandboxRequest{Name: "live"},
	})
	fsm.mu.Lock()
	err = fsm.validateReservationBatchLocked([]reservationCommand{
		{SandboxID: "placed", OwnerNodeID: "owner-b", ExpiresUnix: now + 60},
	}, now)
	fsm.mu.Unlock()
	if err == nil || !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("reserve over active placement = %v", err)
	}
}

func TestReservationNameHelpers(t *testing.T) {
	if got := reservationName(reservationCommand{Name: "  named  "}); got != "named" {
		t.Fatalf("reservationName explicit = %q", got)
	}
	if got := reservationName(reservationCommand{Spec: &models.CreateSandboxRequest{Name: "from-spec"}}); got != "from-spec" {
		t.Fatalf("reservationName from spec = %q", got)
	}
	if got := placementName(Placement{Name: "p-name"}); got != "p-name" {
		t.Fatalf("placementName = %q", got)
	}
}

func TestOrphanOwnerEmptyNodeID(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-orphan-empty", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)
	if err := c.orphanOwner(context.Background(), ""); err != nil {
		t.Fatalf("orphanOwner empty = %v, want nil", err)
	}
}

func TestAgentAssertOwnershipLookupErrorPreservesFirstErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath) {
			http.Error(w, "lookup failed", http.StatusBadGateway)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	agent := &Agent{
		nodeID:     "worker-self",
		apiURL:     srv.URL,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		httpClient: srv.Client(),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	agent.gossip.memberIndex.upsert(Member{
		NodeID: "cp-leader", Alive: true, Role: config.NodeRoleServer, APIURL: srv.URL,
	})

	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{
		{ID: "sb-lookup-err", Spec: &models.CreateSandboxRequest{Image: "alpine"}},
		{ID: "sb-lookup-err-2", Spec: &models.CreateSandboxRequest{Image: "alpine"}},
	})
	if err == nil {
		t.Fatal("AssertOwnership expected lookup error")
	}
}

func TestPlacementRecoveryFileStorePutRejectsEmptySandboxID(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Put("  ", placementRecovery{}); err == nil {
		t.Fatal("Put empty sandbox id expected error")
	}
}

func TestRunCapacityLeaseLoopHonorsCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-lease-cancel", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.runCapacityLeaseLoop(ctx, 20*time.Millisecond)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCapacityLeaseLoop did not exit after cancel")
	}
}

func TestEvictDeadOwnerOrphansWithoutFailoverTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-evict-orphan", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-evict-orphan", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-evict-orphan", OwnerNodeID: follower.nodeID,
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 9999, MemoryMB: 999999},
	})
	if err := leader.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatalf("place: %v", err)
	}

	leader.gossip.memberIndex.upsert(Member{NodeID: follower.nodeID, Alive: false, Role: config.NodeRoleServer, RaftAddr: follower.cfg.RaftAdvertiseAddr})
	leader.deadOwners.markDead(follower.nodeID, time.Now().Add(-time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leader.evictDeadOwner(ctx, follower.nodeID)

	if p, ok := leader.PlacementOf("sb-evict-orphan"); !ok || !p.IsOrphaned() {
		t.Fatalf("placement after evict = %+v ok=%v, want orphaned", p, ok)
	}
}

func TestFSMSnapshotReleaseCallable(t *testing.T) {
	var snap fsmSnapshot
	snap.Release()
}

func TestGossipMembersFallsBackToScan(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-gossip-scan", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	c.gossip.memberIndex = nil
	members := c.gossip.members()
	if len(members) == 0 {
		t.Fatal("members() with nil index expected scan fallback")
	}
	c.gossip.refreshMemberIndex() // nil index early return
}

func TestAgentAssertOwnershipClaimOrphanReplaysPortsAfterSuccess(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-orphan-replay":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-orphan-replay",
				Placement: Placement{
					SandboxID:           "sb-orphan-replay",
					OwnerState:          PlacementOwnerStateOrphaned,
					OrphanedOwnerNodeID: "worker-self",
				},
				Orphaned: true,
			})
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-orphan-replay",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		ExposedPorts:    map[int]ExposedPortRoute{5555: {Protocol: "http"}},
		CustomHostnames: []string{"orphan-replay.example.com"},
	}}); err != nil {
		t.Fatalf("AssertOwnership claim orphan replay: %v", err)
	}
	if !captureContainsOp(capture, opClaimOrphan) {
		t.Fatalf("commands = %+v, want opClaimOrphan", capture.commandsSnapshot())
	}
	if !captureContainsOp(capture, opAddExposedPort) {
		t.Fatalf("commands = %+v, want opAddExposedPort", capture.commandsSnapshot())
	}
	if !captureContainsOp(capture, opAddCustomDomain) {
		t.Fatalf("commands = %+v, want opAddCustomDomain", capture.commandsSnapshot())
	}
}

func TestClusterRemoveMemberForceOrphansAndRemoves(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-force-remove", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "fol-force-remove", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-on-fol", OwnerNodeID: follower.nodeID})
	if err := leader.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatalf("place: %v", err)
	}

	leader.gossip.memberIndex.upsert(Member{NodeID: follower.nodeID, Alive: false, Role: config.NodeRoleServer, RaftAddr: follower.cfg.RaftAdvertiseAddr})
	if err := leader.RemoveMember(context.Background(), follower.nodeID, true); err != nil {
		t.Fatalf("RemoveMember force: %v", err)
	}
	if p, ok := leader.PlacementOf("sb-on-fol"); !ok || !p.IsOrphaned() {
		t.Fatalf("placement after force remove = %+v ok=%v", p, ok)
	}
}
