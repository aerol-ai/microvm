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
	secrets := PlacementSecrets{Ref: "ref-1", Version: 2}
	if err := c.RecordPlacement(ctx, "sb-helpers", &models.CreateSandboxRequest{Image: "alpine"}, secrets); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if got := c.SecretsOf("missing"); got.Ref != "" {
		t.Fatalf("SecretsOf(missing) = %+v, want zero", got)
	}
	if got := c.SecretsOf("sb-helpers"); got.Ref != "ref-1" || got.Version != 2 {
		t.Fatalf("SecretsOf = %+v", got)
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
	if ports := c.ExposedPortsOf("sb-helpers"); ports != nil && len(ports) != 0 {
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
	if got := specName(&models.CreateSandboxRequest{Name: "  from-spec  "}); got != "from-spec" {
		t.Fatalf("specName = %q", got)
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
		nodeID: "worker-self",
		apiURL: srv.URL,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	(&fsmSnapshot{}).Release()
}

func TestStartCapacityLeaseLoopStartsAndStops(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-lease-start", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	c.startCapacityLeaseLoop(0)
	if c.capacityLeaseStop == nil {
		t.Fatal("startCapacityLeaseLoop did not register stop func")
	}
	c.capacityLeaseStop()
}

func TestPeerForcedNonVoterRoleMatrix(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{"", false},
		{config.NodeRoleServer, false},
		{config.NodeRoleMixed, false},
		{config.NodeRoleWorker, true},
		{config.NodeRoleIngress, true},
		{"worker,ingress", true},
		{"server,worker", false},
	}
	for _, tc := range cases {
		if got := isForcedNonVoterRole(tc.role); got != tc.want {
			t.Fatalf("isForcedNonVoterRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
	c := &Cluster{gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	c.gossip.memberIndex.upsert(Member{NodeID: "w1", Role: config.NodeRoleWorker})
	if !c.peerForcedNonVoter("w1") {
		t.Fatal("peerForcedNonVoter(worker) = false, want true")
	}
}

func TestHandleMemberJoinPromotesWorkerAsNonVoter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-join-worker", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	worker, cleanupWorker := newTestAgentWithRole(t, "wkr-join-nv", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupWorker()
	waitForGossipMember(t, leader, worker.SelfNodeID(), 10*time.Second)

	leader.handleMemberJoin(worker.SelfNodeID())
	cfgFuture := leader.raft.raft.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		t.Fatalf("GetConfiguration: %v", err)
	}
	for _, srv := range cfgFuture.Configuration().Servers {
		if string(srv.ID) == worker.SelfNodeID() {
			t.Fatalf("worker %q should not be added to raft config", worker.SelfNodeID())
		}
	}
}

func TestAgentMembersNilGossipReturnsNil(t *testing.T) {
	agent := &Agent{nodeID: "solo"}
	if got := agent.Members(); got != nil {
		t.Fatalf("Members() with nil gossip = %v, want nil", got)
	}
}

func TestAgentAssertOwnershipRecordPlacementFailureOnFresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-place-fail":
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, PublicInternalRecoveryPath):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
			http.Error(w, "apply denied", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	agent := &Agent{
		nodeID: "worker-self",
		apiURL: srv.URL,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	agent.gossip.memberIndex.upsert(Member{
		NodeID: "cp-leader", Alive: true, Role: config.NodeRoleServer, APIURL: srv.URL,
	})

	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-place-fail",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}})
	if err == nil {
		t.Fatal("AssertOwnership expected RecordPlacement failure")
	}
}

func TestAgentAssertOwnershipUpsertSpecFailureOnSelfOwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-upsert-fail":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-upsert-fail",
				Placement: Placement{SandboxID: "sb-upsert-fail", OwnerNodeID: "worker-self"},
			})
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
			payload, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if cmd.Op == opUpsertSpec {
				http.Error(w, "upsert denied", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	agent := &Agent{
		nodeID: "worker-self",
		apiURL: srv.URL,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	agent.gossip.memberIndex.upsert(Member{
		NodeID: "cp-leader", Alive: true, Role: config.NodeRoleServer, APIURL: srv.URL,
	})

	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-upsert-fail",
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 2},
	}})
	if err == nil {
		t.Fatal("AssertOwnership expected UpsertSpec failure")
	}
}

func TestAgentCloseWithTLSInternalServer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestClusterWithTLS(t, "ldr-agent-close-tls", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	agent, _ := newTestAgentWithTLS(t, "wkr-close-tls", config.NodeRoleWorker,
		[]string{leader.gossip.ml.LocalNode().Address()})
	if err := agent.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func TestFollowerForwardRemoveMemberViaPublicAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-fwd-rm-pub", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "fol-fwd-rm-pub", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.HasPrefix(follower.LeaderAPIURL(), "http://") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	leader.gossip.memberIndex.upsert(Member{NodeID: "gone-node", Alive: false, Role: config.NodeRoleServer})
	err := follower.forwardRemoveMemberToLeader(context.Background(), "gone-node", true)
	if err == nil || errors.Is(err, ErrNotLeader) {
		t.Fatalf("forwardRemoveMemberToLeader = %v", err)
	}
}

func TestFSMReleaseCustomHostnameWrongOwner(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.claimCustomHostnameLocked("sb-a", "host.example.com")
	fsm.releaseCustomHostnameLocked("sb-b", "host.example.com")
	if owner := fsm.customHostnameIndex["host.example.com"]; owner != "sb-a" {
		t.Fatalf("stale release changed owner to %q, want sb-a", owner)
	}
	fsm.releaseCustomHostnameLocked("sb-a", "host.example.com")
	if _, ok := fsm.customHostnameIndex["host.example.com"]; ok {
		t.Fatal("expected hostname released for matching owner")
	}
}

func TestFSMClaimPendingReservationReindexesOnOwnerChange(t *testing.T) {
	fsm := newPlacementFSM()
	past := time.Now().Add(-time.Minute).Unix()
	future := time.Now().Add(time.Minute).Unix()
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-swap", OwnerNodeID: "owner-a",
		Spec: &models.CreateSandboxRequest{CPU: 1}, ExpiresUnix: past,
	})
	got := applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-swap", OwnerNodeID: "owner-b",
		Spec: &models.CreateSandboxRequest{CPU: 2}, ExpiresUnix: future,
	})
	if got != nil {
		t.Fatalf("re-reserve after expiry = %v", got)
	}
	if ids := fsm.pendingReservationIDsLocked("owner-a"); len(ids) != 0 {
		t.Fatalf("owner-a pending ids = %v, want empty", ids)
	}
	if ids := fsm.pendingReservationIDsLocked("owner-b"); len(ids) != 1 || ids[0] != "sb-swap" {
		t.Fatalf("owner-b pending ids = %v, want [sb-swap]", ids)
	}
}

func TestGossipNodeCloseWithoutMemberlist(t *testing.T) {
	g := &gossipNode{}
	if err := g.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
}

func TestHandleMemberJoinAddsNonvoterWhenVoterCapReached(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-cap-join", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	leader.cfg.ClusterMaxAutoVoters = 1

	follower, cleanupFollower := newTestCluster(t, "fol-cap-join", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForServerSuffrage(t, leader, follower.nodeID, raft.Nonvoter, 20*time.Second)

	leader.handleMemberJoin(follower.nodeID)
	waitForServerSuffrage(t, leader, follower.nodeID, raft.Nonvoter, 5*time.Second)
}

func newAgentAssertOwnershipTestServer(
	t *testing.T,
	sandboxID string,
	lookup PlacementLookupResponse,
	lookupFound bool,
	failOp opCode,
) (*httptest.Server, *Agent) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+sandboxID:
			if !lookupFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(lookup)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, PublicInternalRecoveryPath):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
			payload, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if cmd.Op == failOp {
				http.Error(w, "denied", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	agent := &Agent{
		nodeID: "worker-self",
		apiURL: srv.URL,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	agent.gossip.memberIndex.upsert(Member{
		NodeID: "cp-leader", Alive: true, Role: config.NodeRoleServer, APIURL: srv.URL,
	})
	return srv, agent
}

func TestAgentAssertOwnershipFreshExposedPortFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-fresh-port", PlacementLookupResponse{}, false, opAddExposedPort)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:           "sb-fresh-port",
		Spec:         &models.CreateSandboxRequest{Image: "alpine"},
		ExposedPorts: map[int]ExposedPortRoute{3001: {Protocol: "http"}},
	}})
	if err == nil {
		t.Fatal("expected AddExposedPort failure on fresh placement")
	}
}

func TestAgentAssertOwnershipFreshCustomDomainFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-fresh-host", PlacementLookupResponse{}, false, opAddCustomDomain)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-fresh-host",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"fresh.example.com"},
	}})
	if err == nil {
		t.Fatal("expected AddCustomDomain failure on fresh placement")
	}
}

func TestAgentAssertOwnershipReservedExposedPortFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-res-port", PlacementLookupResponse{
		SandboxID: "sb-res-port",
		Placement: Placement{
			SandboxID:   "sb-res-port",
			OwnerNodeID: "worker-self",
			State:       PlacementStateReserved,
			ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		},
	}, true, opAddExposedPort)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:           "sb-res-port",
		Spec:         &models.CreateSandboxRequest{Image: "alpine"},
		ExposedPorts: map[int]ExposedPortRoute{3002: {Protocol: "http"}},
	}})
	if err == nil {
		t.Fatal("expected AddExposedPort failure on reserved placement")
	}
}

func TestAgentAssertOwnershipReservedCustomDomainFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-res-host", PlacementLookupResponse{
		SandboxID: "sb-res-host",
		Placement: Placement{
			SandboxID:   "sb-res-host",
			OwnerNodeID: "worker-self",
			State:       PlacementStateReserved,
			ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		},
	}, true, opAddCustomDomain)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-res-host",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"reserved.example.com"},
	}})
	if err == nil {
		t.Fatal("expected AddCustomDomain failure on reserved placement")
	}
}

func TestAgentAssertOwnershipClaimOrphanCustomDomainFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-orphan-host", PlacementLookupResponse{
		SandboxID: "sb-orphan-host",
		Placement: Placement{
			SandboxID:           "sb-orphan-host",
			OwnerState:          PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "worker-self",
		},
		Orphaned: true,
	}, true, opAddCustomDomain)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:              "sb-orphan-host",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"orphan.example.com"},
	}})
	if err == nil {
		t.Fatal("expected AddCustomDomain failure after orphan claim")
	}
}

func TestAgentAssertOwnershipReservedRecordPlacementFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-res-place", PlacementLookupResponse{
		SandboxID: "sb-res-place",
		Placement: Placement{
			SandboxID:   "sb-res-place",
			OwnerNodeID: "worker-self",
			State:       PlacementStateReserved,
			ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		},
	}, true, opPlace)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:   "sb-res-place",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}})
	if err == nil {
		t.Fatal("expected RecordPlacement failure on reserved placement")
	}
}

func TestAgentAssertOwnershipClaimOrphanExposedPortFailure(t *testing.T) {
	srv, agent := newAgentAssertOwnershipTestServer(t, "sb-orphan-port", PlacementLookupResponse{
		SandboxID: "sb-orphan-port",
		Placement: Placement{
			SandboxID:           "sb-orphan-port",
			OwnerState:          PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "worker-self",
		},
		Orphaned: true,
	}, true, opAddExposedPort)
	defer srv.Close()
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:           "sb-orphan-port",
		Spec:         &models.CreateSandboxRequest{Image: "alpine"},
		ExposedPorts: map[int]ExposedPortRoute{3003: {Protocol: "http"}},
	}})
	if err == nil {
		t.Fatal("expected AddExposedPort failure after orphan claim")
	}
}

func TestAgentAssertOwnershipAddExposedPortFailureOnSelfOwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-port-fail":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-port-fail",
				Placement: Placement{
					SandboxID:   "sb-port-fail",
					OwnerNodeID: "worker-self",
					Spec:        &models.CreateSandboxRequest{Image: "alpine"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
			payload, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if cmd.Op == opAddExposedPort {
				http.Error(w, "port denied", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	agent := &Agent{
		nodeID: "worker-self",
		apiURL: srv.URL,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	agent.gossip.memberIndex.upsert(Member{
		NodeID: "cp-leader", Alive: true, Role: config.NodeRoleServer, APIURL: srv.URL,
	})

	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:           "sb-port-fail",
		ExposedPorts: map[int]ExposedPortRoute{4444: {Protocol: "http"}},
	}})
	if err == nil {
		t.Fatal("AssertOwnership expected AddExposedPort failure")
	}
}

func TestClusterAssertOwnershipReturnsErrorOnDuplicateHostname(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-dup-host", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	ctx := context.Background()
	host := "dup-host.example.com"
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-host-a",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{host},
	}}); err != nil {
		t.Fatalf("first AssertOwnership: %v", err)
	}
	err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-host-b",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{host},
	}})
	if err == nil {
		t.Fatal("second AssertOwnership with duplicate hostname expected error")
	}
}

func TestClusterAssertOwnershipUpsertSpecBackfillOnSelfOwned(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-upsert-backfill", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	ctx := context.Background()
	if err := c.RecordPlacement(ctx, "sb-upsert-backfill", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 8}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:   "sb-upsert-backfill",
		Spec: spec,
	}}); err != nil {
		t.Fatalf("AssertOwnership upsert backfill: %v", err)
	}
	got, ok := c.PlacementOf("sb-upsert-backfill")
	if !ok || got.Spec == nil || got.Spec.CPU != 8 {
		t.Fatalf("placement after upsert backfill = %+v ok=%v", got, ok)
	}
}

func TestClusterSpecOfDeepCopiesMutableFields(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-spec-copy", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	spec := &models.CreateSandboxRequest{
		Image:            "alpine",
		Env:              map[string]string{"A": "1"},
		Mounts:           []models.MountSpec{{Type: "tmpfs", Target: "/data"}},
		PlatformVolumes:  []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
		ContainerCommand: []string{"sleep", "inf"},
	}
	if err := c.RecordPlacement(context.Background(), "sb-spec-copy", spec, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	got := c.SpecOf("sb-spec-copy")
	if got == nil {
		t.Fatal("SpecOf returned nil")
	}
	got.Env["A"] = "mutated"
	got.Mounts[0].Target = "/mutated"
	got.PlatformVolumes[0].Path = "/mutated"
	got.ContainerCommand[0] = "mutated"
	again := c.SpecOf("sb-spec-copy")
	if again.Env["A"] != "1" || again.Mounts[0].Target != "/data" || again.PlatformVolumes[0].Path != "/workspace" || again.ContainerCommand[0] != "sleep" {
		t.Fatalf("SpecOf did not deep-copy mutable fields: %+v", again)
	}
}

func TestGossipMembersFallsBackToScan(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-gossip-scan", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	c.gossip.setMemberIndex(nil)
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
