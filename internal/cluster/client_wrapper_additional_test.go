package cluster

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	secretspkg "github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/hashicorp/raft"
)

func TestClusterLocalClientReadWrappers(t *testing.T) {
	c := &Cluster{
		nodeID:         "self-node",
		apiURL:         "http://self-node",
		fsm:            newPlacementFSM(),
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
		internalServer: &internalServer{},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	c.gossip.memberIndex.replace([]Member{
		{NodeID: "self-node", APIURL: "http://self-node", Alive: true},
		{NodeID: "owner-node", APIURL: "http://owner-node", InternalURL: "https://owner-node.internal", Alive: true},
	})
	if got := c.LocalMembers(); len(got) != 2 {
		t.Fatalf("LocalMembers() = %+v, want two indexed members", got)
	}
	if got, ok := c.LookupMember("owner-node"); !ok || got.NodeID != "owner-node" {
		t.Fatalf("LookupMember(owner-node) = (%+v, %v)", got, ok)
	}
	if _, ok := c.LookupMember(""); ok {
		t.Fatal("LookupMember(empty) found a member")
	}
	if c.PeerInternalHTTPClient() != nil {
		t.Fatal("cluster without mTLS returned an internal client")
	}
	c.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return []string{"template-a"}, true })

	applyOp(t, c.fsm, command{
		Op:                   opPlace,
		SandboxID:            "sb-demo",
		OwnerNodeID:          "owner-node",
		Spec:                 &models.CreateSandboxRequest{Name: "demo", Image: "alpine:3.20"},
		IncarnationID:        "inc-demo",
		SecretRef:            testSecretRef("sb-demo", "inc-demo"),
		SecretVersion:        1,
		SecretSealGeneration: 4,
	})
	applyOp(t, c.fsm, command{Op: opAddExposedPort, SandboxID: "sb-demo", Port: 8080, Protocol: "http"})
	applyOp(t, c.fsm, command{Op: opSetNodeDrainState, NodeID: "drained-node", Drained: true})
	applyOp(t, c.fsm, command{
		Op:          opPlace,
		SandboxID:   "sb-legacy",
		OwnerNodeID: "self-node",
		Spec:        &models.CreateSandboxRequest{Name: "legacy", Image: "busybox"},
	})

	if got := c.SelfNodeID(); got != "self-node" {
		t.Fatalf("SelfNodeID() = %q, want self-node", got)
	}
	if got := c.SelfAPIURL(); got != "http://self-node" {
		t.Fatalf("SelfAPIURL() = %q, want http://self-node", got)
	}
	c.AttachInternalHandler(http.NotFoundHandler())
	if c.internalServer.extra.Load() == nil {
		t.Fatal("AttachInternalHandler() did not install the extra handler")
	}

	sandboxID, owner, err := c.OwnerOfName("demo")
	if err != nil {
		t.Fatalf("OwnerOfName() error = %v", err)
	}
	if sandboxID != "sb-demo" {
		t.Fatalf("OwnerOfName() sandbox id = %q, want sb-demo", sandboxID)
	}
	if owner.NodeID != "owner-node" || owner.APIURL != "http://owner-node" || owner.InternalURL != "https://owner-node.internal" || owner.IsSelf {
		t.Fatalf("OwnerOfName() owner = %+v, want gossip-enriched remote owner", owner)
	}
	if _, _, err := c.OwnerOfName("missing"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfName(missing) error = %v, want ErrUnknownSandbox", err)
	}

	secrets := c.SecretsOf("sb-demo")
	if secrets.Ref != testSecretRef("sb-demo", "inc-demo") || secrets.Version != 1 || secrets.SealGeneration != 4 {
		t.Fatalf("SecretsOf() = %+v, want stored secret handle", secrets)
	}
	routes := c.ExposedPortsOf("sb-demo")
	if routes[8080].Protocol != "http" {
		t.Fatalf("ExposedPortsOf() = %+v, want http route", routes)
	}
	if !c.IsNodeDrained("drained-node") {
		t.Fatal("IsNodeDrained() = false, want true")
	}
	if got := c.Placements(); len(got) != 2 {
		t.Fatalf("Placements() = %+v, want two placements", got)
	}
	filter := PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{PlacementShardForSandbox("sb-demo", DefaultPlacementShardCount)}}
	if got := c.PlacementsForShards(filter); len(got) != 1 || got[0].SandboxID != "sb-demo" {
		t.Fatalf("PlacementsForShards() = %+v, want shard-filtered placement", got)
	}
	page := c.PlacementPage(PlacementPageRequest{Limit: 1})
	if len(page.Placements) != 1 || page.Placements[0].SandboxID != "sb-demo" || page.NextPageToken != "sb-demo" {
		t.Fatalf("PlacementPage() = %+v, want single row page with next token", page)
	}
	if placement, ok := c.PlacementOf("sb-demo"); !ok || placement.SandboxID != "sb-demo" {
		t.Fatalf("PlacementOf() = (%+v, %v), want sb-demo placement and true", placement, ok)
	}
	byID := c.PlacementsByIDs([]string{"sb-demo", "missing", "sb-demo"})
	if len(byID) != 1 || byID["sb-demo"].OwnerNodeID != "owner-node" {
		t.Fatalf("PlacementsByIDs() = %+v, want one point lookup", byID)
	}
	if got := c.PlacementVersion(); got != 0 {
		t.Fatalf("PlacementVersion() = %d, want 0 for zero-index local FSM applies", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := c.SubscribePlacement(ctx)
	if wake == nil {
		t.Fatal("SubscribePlacement() returned nil")
	}
	applyOp(t, c.fsm, command{Op: opPlace, SandboxID: "sb-second", OwnerNodeID: "self-node"})
	select {
	case <-wake:
	case <-time.After(2 * time.Second):
		t.Fatal("SubscribePlacement() did not receive a wake signal")
	}
}

func TestClusterClientReservationAndMutationWrappers(t *testing.T) {
	c, cleanup := newTestCluster(t, "client-wrap-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	c.gossip.delegate.mu.Lock()
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 8192, DiskTotalGB: 100, DiskFreeGB: 100},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	)
	c.gossip.delegate.admitter = admitter
	c.gossip.delegate.mu.Unlock()
	c.gossip.refreshMemberIndex()
	c.capacityLeases.setAdmitter(admitter)
	c.capacityLeases.set(c.nodeID, admitter.Snapshot(), time.Now())

	ctx := context.Background()
	if err := c.RecordPlacement(ctx, "sb-expose", nil, PlacementSecrets{
		Ref:            secretspkg.FormatRef("sb-expose", "inc-expose", secretspkg.RefVersion),
		Version:        secretspkg.RefVersion,
		IncarnationID:  "inc-expose",
		SealGeneration: 3,
	}); err != nil {
		t.Fatalf("RecordPlacement() error = %v", err)
	}
	if got := c.SecretsOf("sb-expose"); got.SealGeneration != 3 {
		t.Fatalf("RecordPlacement secret handle = %+v, want seal generation 3", got)
	}
	if err := c.UpdatePlacementSecretRecipients(ctx, "sb-expose", []string{" node-z ", "node-z"}, PlacementSecrets{
		Ref:            secretspkg.FormatRef("sb-expose", "inc-expose", secretspkg.RefVersion),
		Version:        secretspkg.RefVersion,
		IncarnationID:  "inc-expose",
		SealGeneration: 4,
	}, "inc-expose", c.nodeID, 3); err != nil {
		t.Fatalf("UpdatePlacementSecretRecipients() error = %v", err)
	}
	if got := c.SecretsOf("sb-expose"); got.SealGeneration != 4 || len(got.Recipients) != 1 || got.Recipients[0] != "node-z" {
		t.Fatalf("updated secret handle = %+v", got)
	}
	if err := c.UpdatePlacementSecretRecipients(ctx, "", []string{"node-z"}, PlacementSecrets{}, "", "", 0); !errors.Is(err, ErrSecretRecipientsCASMismatch) {
		t.Fatalf("empty sandbox update = %v, want ErrSecretRecipientsCASMismatch", err)
	}
	if err := c.AddExposedPort(ctx, "sb-expose", 8080, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("AddExposedPort() error = %v", err)
	}
	if err := c.RemoveExposedPort(ctx, "sb-expose", 8080); err != nil {
		t.Fatalf("RemoveExposedPort() error = %v", err)
	}
	if routes := c.ExposedPortsOf("sb-expose"); len(routes) != 0 {
		t.Fatalf("ExposedPortsOf() after remove = %+v, want empty map", routes)
	}

	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost}
	if err := c.ReserveOnTarget(ctx, "sb-reserve", target, nil, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget() error = %v", err)
	}
	if placement, ok := c.PlacementOf("sb-reserve"); !ok || placement.State != PlacementStateReserved {
		t.Fatalf("reserved placement = (%+v, %v), want reserved row", placement, ok)
	}
	if err := c.CancelReservation(ctx, "sb-reserve"); err != nil {
		t.Fatalf("CancelReservation() error = %v", err)
	}
	if _, ok := c.PlacementOf("sb-reserve"); ok {
		t.Fatal("CancelReservation() left the reserved placement behind")
	}

	batch := []PlacementReservation{
		{SandboxID: "sb-batch-a", Target: target, TTL: time.Minute},
		{SandboxID: "sb-batch-b", Target: target, TTL: time.Minute},
	}
	if err := c.ReserveBatchOnTargets(ctx, batch); err != nil {
		t.Fatalf("ReserveBatchOnTargets() error = %v", err)
	}
	for _, id := range []string{"sb-batch-a", "sb-batch-b"} {
		if placement, ok := c.PlacementOf(id); !ok || placement.State != PlacementStateReserved {
			t.Fatalf("batch reservation %q = (%+v, %v), want reserved row", id, placement, ok)
		}
	}

	if err := c.SetNodeDrainState(ctx, "node-drain", true); err != nil {
		t.Fatalf("SetNodeDrainState() error = %v", err)
	}
	if !c.IsNodeDrained("node-drain") {
		t.Fatal("SetNodeDrainState() did not mark node as drained")
	}
	if err := c.SetNodeDrainState(ctx, "", true); err == nil {
		t.Fatal("SetNodeDrainState() accepted an empty node id")
	}
	if err := c.ReserveOnTarget(ctx, "sb-bad-ttl", target, nil, PlacementSecrets{}, 0); err == nil {
		t.Fatal("ReserveOnTarget() accepted ttl <= 0")
	}
	if err := c.ReserveBatchOnTargets(ctx, []PlacementReservation{{SandboxID: "sb-bad-batch", Target: target, TTL: 0}}); err == nil {
		t.Fatal("ReserveBatchOnTargets() accepted ttl <= 0")
	}
}

func TestClusterAndAgentNewReadWrappersFailClosed(t *testing.T) {
	if got := normalizeSecretRecipientIDs(nil); got != nil {
		t.Fatalf("normalized nil recipients = %v", got)
	}
	if got := normalizeSecretRecipientIDs([]string{" node-a ", "", "node-a", "node-b"}); len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("normalized recipients = %v", got)
	}
	(&fsmSnapshot{}).Release()

	var c *Cluster
	if c.PeerInternalHTTPClient() != nil || c.ClientForPeer("node-a") != nil {
		t.Fatal("nil cluster returned a peer client")
	}
	if got := c.LocalMembers(); got != nil {
		t.Fatalf("nil cluster members = %+v", got)
	}
	if _, ok := c.LookupMember("node-a"); ok {
		t.Fatal("nil cluster resolved a member")
	}
	if got := c.PlacementsByIDs([]string{"sb"}); len(got) != 0 {
		t.Fatalf("nil-FSM point lookup = %+v", got)
	}
	c.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return nil, true })
	if err := c.UpdatePlacementSecretRecipients(context.Background(), "", nil, PlacementSecrets{}, "", "", 0); !errors.Is(err, ErrSecretRecipientsCASMismatch) {
		t.Fatalf("nil cluster empty update = %v, want ErrSecretRecipientsCASMismatch", err)
	}

	var a *Agent
	if a.PeerInternalHTTPClient() != nil || a.ClientForPeer("node-a") != nil {
		t.Fatal("nil agent returned a peer client")
	}
	if got := a.LocalMembers(); got != nil {
		t.Fatalf("nil agent members = %+v", got)
	}
	if _, ok := a.LookupMember("node-a"); ok {
		t.Fatal("nil agent resolved a member")
	}
	if err := a.UpdatePlacementSecretRecipients(context.Background(), "", nil, PlacementSecrets{}, "", "", 0); !errors.Is(err, ErrSecretRecipientsCASMismatch) {
		t.Fatalf("nil agent empty update = %v, want ErrSecretRecipientsCASMismatch", err)
	}
}

func TestNoopSecurityAndListContracts(t *testing.T) {
	ctx := context.Background()
	n := NewNoop("node-a", "http://node-a", "node-a.example.test")
	if err := n.UpdatePlacementSecretRecipients(ctx, "sb", []string{"node-a"}, PlacementSecrets{}, "", "", 0); err != nil {
		t.Fatalf("standalone recipient update = %v", err)
	}
	if owner, ok, err := n.AuditOwnerRef(ctx, "sb"); err != nil || ok || owner != "" {
		t.Fatalf("standalone audit owner = (%q, %v, %v)", owner, ok, err)
	}
	if acl, ok, err := n.AuditACLForSandbox(ctx, "sb", ""); err != nil || ok || acl.SandboxID != "" {
		t.Fatalf("standalone audit ACL = (%+v, %v, %v)", acl, ok, err)
	}
	if err := n.PruneAuditACL(ctx, time.Now()); err != nil {
		t.Fatalf("standalone audit ACL prune = %v", err)
	}
	n.AttachInternalHandler(http.NotFoundHandler())
	if n.PeerInternalHTTPClient() != nil {
		t.Fatal("standalone mode exposed a cluster-internal client")
	}
	if got := n.LocalMembers(); len(got) != 1 || got[0].NodeID != "node-a" {
		t.Fatalf("standalone local members = %+v", got)
	}
	if got, ok := n.LookupMember("node-a"); !ok || !got.Alive {
		t.Fatalf("standalone member lookup = (%+v, %v)", got, ok)
	}
	if _, ok := n.LookupMember("node-b"); ok {
		t.Fatal("standalone mode resolved a different node")
	}
	if got := n.PlacementsByIDs([]string{"sb"}); len(got) != 0 {
		t.Fatalf("standalone placement lookup = %+v", got)
	}
}

func TestAgentMembershipAndSecretRecipientUpdate(t *testing.T) {
	var sawApply bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != InternalAPIPath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sawApply = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	index := newGossipMemberIndex()
	index.replace([]Member{
		{NodeID: "agent-a", Alive: true, Role: "worker"},
		{NodeID: "server-a", Alive: true, Role: "server", InternalURL: server.URL},
	})
	a := &Agent{
		nodeID:         "agent-a",
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip:         &gossipNode{memberIndex: index},
		internalClient: server.Client(),
	}
	if got := a.PeerInternalHTTPClient(); got != server.Client() {
		t.Fatal("agent did not expose its internal peer client")
	}
	if got := a.LocalMembers(); len(got) != 2 {
		t.Fatalf("agent LocalMembers() = %+v", got)
	}
	if got, ok := a.LookupMember("server-a"); !ok || got.InternalURL != server.URL {
		t.Fatalf("agent LookupMember(server-a) = (%+v, %v)", got, ok)
	}
	if _, ok := a.LookupMember("missing"); ok {
		t.Fatal("agent resolved a missing member")
	}
	if err := a.UpdatePlacementSecretRecipients(context.Background(), "sb-a", []string{" node-b ", "node-b"}, PlacementSecrets{
		Ref:            secretspkg.FormatRef("sb-a", "inc-a", secretspkg.RefVersion),
		Version:        secretspkg.RefVersion,
		IncarnationID:  "inc-a",
		SealGeneration: 4,
	}, "inc-a", "server-a", 3); err != nil {
		t.Fatalf("agent recipient update: %v", err)
	}
	if !sawApply {
		t.Fatal("agent recipient update was not forwarded")
	}
}

func TestClusterRemoveMemberLocalForcePath(t *testing.T) {
	leader, cleanupLeader := newTestCluster(t, "leader-remove", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "follower-remove", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()

	waitForLeader(t, leader, 5*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	ctx := context.Background()
	if err := leader.RemoveMember(ctx, "", false); err == nil {
		t.Fatal("RemoveMember() accepted an empty node id")
	}
	if err := leader.RemoveMember(ctx, follower.nodeID, false); !errors.Is(err, ErrMemberStillAlive) {
		t.Fatalf("RemoveMember(alive follower) error = %v, want ErrMemberStillAlive", err)
	}
	if err := leader.RemoveMember(ctx, follower.nodeID, true); err != nil {
		t.Fatalf("RemoveMember(force) error = %v", err)
	}
	cfgFuture := leader.raft.raft.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		t.Fatalf("GetConfiguration() error = %v", err)
	}
	for _, srv := range cfgFuture.Configuration().Servers {
		if srv.ID == raft.ServerID(follower.nodeID) {
			t.Fatalf("removed follower still present in raft config: %+v", cfgFuture.Configuration().Servers)
		}
	}
}

func TestClusterDoLeaderLifecycleMapsResponses(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "success", status: http.StatusNoContent},
		{name: "not leader", status: http.StatusServiceUnavailable, body: ErrNotLeader.Error(), wantErr: ErrNotLeader},
		{name: "unknown member", status: http.StatusNotFound, body: ErrUnknownMember.Error(), wantErr: ErrUnknownMember},
		{name: "member alive", status: http.StatusConflict, body: ErrMemberStillAlive.Error(), wantErr: ErrMemberStillAlive},
		{name: "last voter", status: http.StatusConflict, body: ErrLastVoter.Error(), wantErr: ErrLastVoter},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sawAuth := false
			sawContentType := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawAuth = r.Header.Get("Authorization") == "Bearer cluster-pat"
				sawContentType = r.Header.Get("Content-Type") == "application/json"
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			c := &Cluster{patToken: "cluster-pat"}
			err := c.doLeaderLifecycle(ctx, server.Client(), server.URL+"/v1/cluster/members/node-a", http.MethodDelete, []byte(`{"force":true}`))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("doLeaderLifecycle() error = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("doLeaderLifecycle() error = %v, want %v", err, tt.wantErr)
			}
			if !sawAuth {
				t.Fatal("doLeaderLifecycle() did not send PAT auth header")
			}
			if !sawContentType {
				t.Fatal("doLeaderLifecycle() did not mark JSON request bodies")
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	c := &Cluster{}
	if err := c.doLeaderLifecycle(ctx, server.Client(), server.URL+"/v1/cluster/members/node-a", http.MethodDelete, nil); err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("doLeaderLifecycle(500) error = %v, want status 500 message", err)
	}
}
