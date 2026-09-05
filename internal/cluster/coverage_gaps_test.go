package cluster

import (
	"bytes"
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
	"github.com/hashicorp/memberlist"
)

func TestWasmMigratePathsAndLocalExport(t *testing.T) {
	if got := wasmMigrateExportPath("sb/1"); !strings.Contains(got, "sb%2F1") {
		t.Fatalf("export path = %q", got)
	}
	if got := wasmMigrateImportPath("sb-2"); !strings.Contains(got, "sb-2/import") {
		t.Fatalf("import path = %q", got)
	}
	data, gen, err := ExportWasmMigrateLocal(func(w io.Writer) (string, error) {
		if _, err := w.Write([]byte("tar")); err != nil {
			return "", err
		}
		return "gen-1", nil
	})
	if err != nil || gen != "gen-1" || string(data) != "tar" {
		t.Fatalf("ExportWasmMigrateLocal = (%q, %q, %v)", data, gen, err)
	}
}

func TestWasmMigratePeerClientAndPAT(t *testing.T) {
	client, base, err := wasmMigratePeerClient(nil, "peer-1", "https://internal")
	if !errors.Is(err, ErrPeerInternalURLRequired) || base != "" || client != nil {
		t.Fatalf("provider-less client = (%v, %q, %v)", client, base, err)
	}
	_, _, err = wasmMigratePeerClient(nil, "", "")
	if err == nil {
		t.Fatal("expected error when both URLs empty")
	}

	agent := &Agent{patToken: "pat-token"}
	if got := wasmMigratePAT(agent); got != "pat-token" {
		t.Fatalf("wasmMigratePAT(agent) = %q", got)
	}
	if wasmMigratePAT(&Noop{}) != "" {
		t.Fatal("noop should not provide PAT")
	}
	agent.internalClient = http.DefaultClient
	client, base, err = agent.PeerDialMember(Member{NodeID: "peer-1", InternalURL: "https://internal"})
	if err != nil || base != "https://internal" {
		t.Fatalf("agent internal client = (%v, %q, %v)", client, base, err)
	}
	agent.internalClient = nil
	client, base, err = agent.PeerDialMember(Member{NodeID: "peer-1"})
	if !errors.Is(err, ErrPeerInternalURLRequired) || client != nil || base != "" {
		t.Fatalf("agent missing internal URL = (%v, %q, %v)", client, base, err)
	}
	_, _, err = agent.PeerDialMember(Member{})
	if err == nil {
		t.Fatal("expected agent peer URL error")
	}
}

func TestWasmMigrateHTTPRoundTrip(t *testing.T) {
	const cloneGen = "clone-gen-42"
	srv, internalClient := newNodeBoundForwardServer(t, "agent-self", "owner-1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/bad/"):
			http.Error(w, "nope", http.StatusBadGateway)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/export"):
			if got := r.Header.Get("Authorization"); got != "Bearer pat" {
				t.Fatalf("export auth = %q", got)
			}
			w.Header().Set(WasmMigrateCloneGenHeader, cloneGen)
			_, _ = w.Write([]byte("snapshot"))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/import"):
			if got := r.Header.Get(WasmMigrateCloneGenHeader); got != cloneGen {
				t.Fatalf("import clone gen = %q", got)
			}
			if ct := r.Header.Get("Content-Type"); ct != WasmMigrateTarMediaType {
				t.Fatalf("content type = %q", ct)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))

	agent := &Agent{
		nodeID:         "agent-self",
		patToken:       "pat",
		internalClient: internalClient,
	}

	var buf bytes.Buffer
	gen, err := StreamWasmMigrateExport(context.Background(), agent, OwnerInfo{
		NodeID:      "owner-1",
		InternalURL: srv.URL,
	}, "sb-migrate", &buf)
	if err != nil {
		t.Fatalf("StreamWasmMigrateExport: %v", err)
	}
	if gen != cloneGen || buf.String() != "snapshot" {
		t.Fatalf("export = gen %q body %q", gen, buf.String())
	}
	if _, err := StreamWasmMigrateExport(context.Background(), agent, OwnerInfo{IsSelf: true}, "sb", &buf); err == nil {
		t.Fatal("self export expected error")
	}

	if err := PostWasmMigrateImport(context.Background(), agent, Member{NodeID: "agent-self", InternalURL: srv.URL}, "sb-migrate", cloneGen, strings.NewReader("import")); err == nil {
		t.Fatal("self import expected error")
	}
	if err := PostWasmMigrateImport(context.Background(), agent, Member{NodeID: "owner-1", InternalURL: srv.URL}, "sb-migrate", cloneGen, strings.NewReader("import")); err != nil {
		t.Fatalf("PostWasmMigrateImport: %v", err)
	}

	_, err = StreamWasmMigrateExport(context.Background(), agent, OwnerInfo{NodeID: "owner-1", InternalURL: srv.URL}, "bad", &buf)
	if err == nil {
		t.Fatal("expected status error on export failure")
	}
	var st statusError
	if !errors.As(err, &st) || st.status != http.StatusBadGateway {
		t.Fatalf("export error = %v", err)
	}
}

func TestAgentCustomDomainsAndIngressTargets(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	ingressMember := Member{NodeID: "ingress-1", Alive: true, Role: config.NodeRoleIngress, PublicHost: "ingress.example.com"}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/cluster/members":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"members": []Member{
					{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker},
					ingressMember,
				},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-domains":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-domains",
				Placement: Placement{
					SandboxID:       "sb-domains",
					CustomHostnames: []string{"api.acme.com", "shop.beta.io"},
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"missing":
			http.Error(w, "not found", http.StatusNotFound)
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker}, ingressMember)

	ctx := context.Background()
	if err := agent.AddCustomDomain(ctx, "sb-domains", " API.Acme.COM "); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	if err := agent.RemoveCustomDomain(ctx, "sb-domains", "shop.beta.io"); err != nil {
		t.Fatalf("RemoveCustomDomain: %v", err)
	}
	if err := agent.AddCustomDomain(ctx, "", ""); err != nil {
		t.Fatalf("empty AddCustomDomain: %v", err)
	}
	if err := agent.RemoveCustomDomain(ctx, "", ""); err != nil {
		t.Fatalf("empty RemoveCustomDomain: %v", err)
	}

	got := agent.CustomDomainsOf("sb-domains")
	if len(got) != 2 || got[0] != "api.acme.com" {
		t.Fatalf("CustomDomainsOf = %#v", got)
	}
	if agent.CustomDomainsOf("missing") != nil {
		t.Fatal("missing sandbox should return nil domains")
	}
	if sid, ok := agent.ResolveCustomDomain("api.acme.com"); ok || sid != "" {
		t.Fatalf("ResolveCustomDomain on agent = (%q, %v)", sid, ok)
	}

	targets := agent.IngressTargets()
	if targets.Hostname != "ingress.example.com" {
		t.Fatalf("IngressTargets = %+v", targets)
	}

	cmds := capture.commandsSnapshot()
	if len(cmds) != 2 || cmds[0].Op != opAddCustomDomain || cmds[0].Hostname != "api.acme.com" {
		t.Fatalf("commands = %+v", cmds)
	}
}

func TestAgentReassignPlacementAndAssertOwnership(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-new":
			http.Error(w, "not found", http.StatusNotFound)
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-reserved":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-reserved",
				Placement: Placement{
					SandboxID:   "sb-reserved",
					OwnerNodeID: "worker-self",
					State:       PlacementStateReserved,
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-stale":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-stale",
				Placement: Placement{SandboxID: "sb-stale", OwnerNodeID: "other-node"},
				Owner:     OwnerInfo{NodeID: "other-node"},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-owned":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-owned",
				Placement: Placement{SandboxID: "sb-owned", OwnerNodeID: "worker-self"},
				Owner:     OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-orphan":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-orphan",
				Placement: Placement{
					SandboxID:           "sb-orphan",
					OwnerState:          PlacementOwnerStateOrphaned,
					OrphanedOwnerNodeID: "worker-self",
				},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-err":
			http.Error(w, "boom", http.StatusInternalServerError)
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	ctx := context.Background()
	target := PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", DataPlaneHost: "dp-b"}
	if err := agent.ReassignPlacement(ctx, "sb-reassign", target); err != nil {
		t.Fatalf("ReassignPlacement: %v", err)
	}
	if err := agent.ReassignPlacement(ctx, "", target); err == nil {
		t.Fatal("empty sandbox id expected error")
	}
	if err := agent.ReassignPlacement(ctx, "sb-reassign", PlacementTarget{}); err == nil {
		t.Fatal("empty target expected error")
	}

	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-new",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"new.acme.com"},
		ExposedPorts:    map[int]ExposedPortRoute{8080: {Protocol: "http", PublicURL: "https://x"}},
	}}); err != nil {
		t.Fatalf("AssertOwnership new: %v", err)
	}
	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{
		ID:   "sb-reserved",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}}); err != nil {
		t.Fatalf("AssertOwnership reserved: %v", err)
	}
	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{ID: "sb-stale"}}); err != nil {
		t.Fatalf("AssertOwnership stale: %v", err)
	}
	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{ID: ""}}); err != nil {
		t.Fatalf("AssertOwnership skip empty: %v", err)
	}
	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{
		ID:   "sb-owned",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}}); err != nil {
		t.Fatalf("AssertOwnership owned upsert: %v", err)
	}
	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{
		ID:   "sb-orphan",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}}); err != nil {
		t.Fatalf("AssertOwnership orphan claim: %v", err)
	}
	if err := agent.AssertOwnership(ctx, []LocalSandboxState{{ID: "sb-err"}}); err == nil {
		t.Fatal("AssertOwnership lookup error expected")
	}
}

func TestAgentOwnerOfAndSelectPlacementBranches(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-owner":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-owner",
				Owner:     OwnerInfo{NodeID: "worker-self"},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-orphan-owner":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: "sb-orphan-owner", Orphaned: true})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-bad-owner":
			http.Error(w, "boom", http.StatusInternalServerError)
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"missing":
			http.Error(w, "not found", http.StatusNotFound)
			return true
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalSelectPlacementPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(SelectPlacementResponse{
				Error: ErrInvalidTopology.Error() + ": live cluster contains mixed nodes",
			})
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	owner, err := agent.OwnerOf("sb-owner")
	if err != nil || !owner.IsSelf {
		t.Fatalf("OwnerOf() = (%+v, %v)", owner, err)
	}
	if _, err := agent.OwnerOf("missing"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOf(missing) = %v", err)
	}
	if _, err := agent.OwnerOf("sb-orphan-owner"); !errors.Is(err, ErrOrphaned) {
		t.Fatalf("OwnerOf(orphan) = %v", err)
	}
	if _, err := agent.OwnerOf("sb-bad-owner"); err == nil {
		t.Fatal("OwnerOf(server error) expected error")
	}
	if _, err := agent.SelectPlacement(capacity.Request{CPU: 1}); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("SelectPlacement(topology) = %v", err)
	}
	if agent.SpecOf("sb-bad-owner") != nil {
		t.Fatal("SpecOf on error should return nil")
	}
	if got := agent.SecretsOf("sb-bad-owner"); got.Ref != "" {
		t.Fatalf("SecretsOf on error = %+v", got)
	}
	if err := agent.UpsertSpec(context.Background(), "sb", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec noop: %v", err)
	}
	if err := agent.AddExposedPort(context.Background(), "sb", 0, ExposedPortRoute{}); err != nil {
		t.Fatalf("AddExposedPort skip: %v", err)
	}
	if err := agent.RemoveExposedPort(context.Background(), "sb", 0); err != nil {
		t.Fatalf("RemoveExposedPort skip: %v", err)
	}
	if err := agent.ReserveOnTarget(context.Background(), "sb", PlacementTarget{NodeID: "n"}, nil, PlacementSecrets{}, 0); err == nil {
		t.Fatal("ReserveOnTarget ttl=0 expected error")
	}
}

func TestAgentTryControlPlaneMemberInternalPath(t *testing.T) {
	const placementPath = PublicInternalPlacementPath + "sb-internal"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == placementPath {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-internal",
				Placement: Placement{SandboxID: "sb-internal"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "server-1", APIURL: "http://dead", InternalURL: srv.URL, Alive: true, Role: config.NodeRoleServer})
	agent := &Agent{
		nodeID:         "worker-self",
		internalClient: srv.Client(),
		gossip:         &gossipNode{memberIndex: index},
		logger:         slog.Default(),
	}
	placement, ok := agent.PlacementOf("sb-internal")
	if !ok || placement.SandboxID != "sb-internal" {
		t.Fatalf("PlacementOf via internal = (%+v, %v)", placement, ok)
	}
}

func TestNoopCustomDomainAndReassignWrappers(t *testing.T) {
	n := NewNoop("standalone", "http://localhost:21212", "")
	ctx := context.Background()
	_ = n.AddCustomDomain(ctx, "sb", "host.example.com")
	_ = n.RemoveCustomDomain(ctx, "sb", "host.example.com")
	if n.CustomDomainsOf("sb") != nil {
		t.Fatal("CustomDomainsOf should be nil on noop")
	}
	if _, ok := n.ResolveCustomDomain("host.example.com"); ok {
		t.Fatal("ResolveCustomDomain should be false on noop")
	}
	if err := n.ReassignPlacement(ctx, "sb", PlacementTarget{NodeID: "n"}); err != nil {
		t.Fatalf("ReassignPlacement noop: %v", err)
	}
	n.AttachInternalHandler(http.NotFoundHandler())
}

func TestClusterWasmMigrateAndReassignWrappers(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "wasm-reassign-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 5*time.Second)

	if wasmMigratePAT(c) != c.patToken {
		t.Fatal("cluster wasmMigratePAT mismatch")
	}
	if _, _, err := c.PeerDialMember(Member{}); err == nil {
		t.Fatal("expected peer URL error")
	}

	ctx := context.Background()
	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost}
	if err := c.RecordPlacement(ctx, "sb-reassign", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if err := c.ReassignPlacement(ctx, "sb-reassign", target); err != nil {
		t.Fatalf("ReassignPlacement: %v", err)
	}
	if err := c.ReassignPlacement(ctx, "", target); err == nil {
		t.Fatal("empty sandbox id expected error")
	}
}

func TestFollowerForwardsRemoveMemberToLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "leader-fwd-remove", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "follower-fwd-remove", false, []string{leader.gossip.ml.LocalNode().Address()})
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

	err := follower.RemoveMember(context.Background(), "ghost-node", true)
	if err == nil || errors.Is(err, ErrNotLeader) {
		t.Fatalf("follower RemoveMember forward = %v, want forwarded lifecycle error", err)
	}
	if errors.Is(err, ErrUnknownMember) {
		return
	}
	// Forward path executed; leader may be unreachable from the follower's cached API URL in CI.
	if !strings.Contains(err.Error(), "lifecycle request") {
		t.Fatalf("follower RemoveMember forward = %v", err)
	}
}

func TestGossipDelegateUnusedMethodsAndFSMRelease(t *testing.T) {
	d := &gossipDelegate{}
	d.NotifyMsg(nil)
	d.MergeRemoteState(nil, false)
	if got := d.GetBroadcasts(1, 1); got != nil {
		t.Fatalf("GetBroadcasts = %v", got)
	}
	if got := d.LocalState(false); got != nil {
		t.Fatalf("LocalState = %v", got)
	}
	(&fsmSnapshot{}).Release()
}

func TestHandleMemberJoinEarlyReturns(t *testing.T) {
	c := &Cluster{nodeID: "self"}
	c.handleMemberJoin("")
	c.handleMemberJoin("self")
	c.handleMemberJoin("peer-1")
}

func TestNewAgentAndClusterValidationErrors(t *testing.T) {
	logger := slog.Default()
	admitter := capacity.New(capacity.HostInfo{CPUCores: 1}, capacity.Limits{}, nil)

	if _, err := NewAgent(config.Config{}, logger, admitter); err == nil {
		t.Fatal("NewAgent without cluster expected error")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true,
		NodeRole:      config.NodeRoleServer,
	}, logger, admitter); err == nil {
		t.Fatal("NewAgent on server role expected error")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true,
		NodeRole:      config.NodeRoleWorker,
	}, logger, admitter); err == nil {
		t.Fatal("NewAgent without advertise URL expected error")
	}

	if _, err := New(config.Config{}, logger, admitter); err == nil {
		t.Fatal("New without cluster expected error")
	}
	if _, err := New(config.Config{
		EnableCluster: true,
		NodeRole:      config.NodeRoleWorker,
	}, logger, admitter); err == nil {
		t.Fatal("New on worker role expected error")
	}
	if _, err := New(config.Config{
		EnableCluster: true,
		NodeRole:      config.NodeRoleServer,
	}, logger, admitter); err == nil {
		t.Fatal("New without advertise URL expected error")
	}
}

func TestWaitForLeaderAndHealthyForReads(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "wait-leader-node", true, nil)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.waitForLeader(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForLeader(cancelled) = %v", err)
	}

	waitForLeader(t, c, 10*time.Second)
	if !c.HealthyForReads() {
		t.Fatal("HealthyForReads should be true once leader is elected")
	}
}

func TestFetchMemberCapacityFailClosedNoPublicDowngrade(t *testing.T) {
	publicHits := 0
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4})
	}))
	defer public.Close()

	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "warming", http.StatusServiceUnavailable)
	}))
	defer internal.Close()

	c := &Cluster{
		internalClient: internal.Client(),
		patToken:       "pat",
	}
	_, err := c.fetchMemberCapacity(context.Background(), Member{
		NodeID:      "worker-1",
		APIURL:      public.URL,
		InternalURL: internal.URL,
	})
	if err == nil {
		t.Fatal("expected fail-closed error on internal 503")
	}
	if publicHits != 0 {
		t.Fatalf("public hits = %d, want 0", publicHits)
	}
	_, err = c.fetchMemberCapacity(context.Background(), Member{NodeID: "worker-2"})
	if err == nil {
		t.Fatal("expected error without peer URL")
	}
}

func TestFSMPagePlacementIDsFromBTree(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placements["sb-a"] = Placement{}
	fsm.placements["sb-b"] = Placement{}
	fsm.placementIDs.ReplaceOrInsert("sb-a")
	fsm.placementIDs.ReplaceOrInsert("sb-b")

	ids := fsm.pagePlacementIDsLocked(PlacementPageRequest{Limit: 1}, PlacementShardFilter{}, true, nil)
	if len(ids) != 1 || ids[0] != "sb-a" {
		t.Fatalf("btree page = %v", ids)
	}
	ids = fsm.pagePlacementIDsLocked(PlacementPageRequest{Limit: 10, PageToken: ids[0]}, PlacementShardFilter{}, true, nil)
	if len(ids) != 1 || ids[0] != "sb-b" {
		t.Fatalf("btree page token = %v", ids)
	}
}

func TestClusterProviderNilGuardsAndLeaderAPIURL(t *testing.T) {
	cache := newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil)
	c := &Cluster{
		nodeID:         "self-node",
		apiURL:         "http://self-node",
		capacityLeases: cache,
		gossip:         &gossipNode{memberIndex: newGossipMemberIndex()},
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "leader-1", APIURL: "http://leader-1", Alive: true})
	c.SetLocalTemplateIDsProvider(func() ([]string, bool) { return nil, false })
	var nilCluster *Cluster
	nilCluster.SetLocalTemplateIDsProvider(nil)
	nilCluster.SetLocalWasmModuleIDsProvider(nil)
}

func TestClusterAssertOwnershipBranches(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "assert-own-branches", true, nil)
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
	if err := c.AssertOwnership(ctx, nil); err != nil {
		t.Fatalf("empty AssertOwnership: %v", err)
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-cluster-new",
		Spec:            &models.CreateSandboxRequest{Image: "alpine"},
		CustomHostnames: []string{"new.example.com"},
		ExposedPorts:    map[int]ExposedPortRoute{9090: {Protocol: "http", PublicURL: "https://x"}},
	}}); err != nil {
		t.Fatalf("fresh AssertOwnership: %v", err)
	}
	if err := c.ReserveOnTarget(ctx, "sb-cluster-reserved", PlacementTarget{
		NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost,
	}, nil, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:   "sb-cluster-reserved",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	}}); err != nil {
		t.Fatalf("reserved AssertOwnership: %v", err)
	}
}

func TestStatusErrorString(t *testing.T) {
	err := statusError{status: http.StatusTeapot, message: "short and stout"}
	if !strings.Contains(err.Error(), "418") || !strings.Contains(err.Error(), "short and stout") {
		t.Fatalf("statusError.Error() = %q", err.Error())
	}
}

func TestFSMPagePlacementIDsShardIndexAtDefaultShardCount(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placements["sb-shard"] = Placement{}
	shard := PlacementShardForSandbox("sb-shard", DefaultPlacementShardCount)
	fsm.shardIndex[shard] = map[string]struct{}{"sb-shard": {}}
	fsm.placementIDs.ReplaceOrInsert("sb-shard")

	filter := PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{shard}}
	want := map[int]struct{}{shard: {}}
	ids := fsm.pagePlacementIDsLocked(PlacementPageRequest{Limit: 10}, filter, false, want)
	if len(ids) != 1 || ids[0] != "sb-shard" {
		t.Fatalf("shard-index page = %v", ids)
	}
}

func TestReconcileReservationsCancelsExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "reconcile-reserve", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx := context.Background()
	applyOp(t, c.fsm, command{
		Op:          opReserve,
		SandboxID:   "sb-expired-reconcile",
		OwnerNodeID: c.nodeID,
		ExpiresUnix: time.Now().Add(-time.Second).Unix(),
	})
	c.reconcileReservations(ctx)
	if _, ok := c.PlacementOf("sb-expired-reconcile"); ok {
		t.Fatal("expected expired reservation to be cancelled")
	}
}

func TestFollowerApplyEncodedReturnsNotLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "leader-apply-encoded", true, nil)
	defer cleanupLeader()
	follower, cleanupFollower := newTestCluster(t, "follower-apply-encoded", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	payload, err := encodeCommand(command{Op: opDelete, SandboxID: "sb-follower-apply"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := follower.ApplyEncoded(context.Background(), payload); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("follower ApplyEncoded = %v, want ErrNotLeader", err)
	}
}

func TestAgentAssertOwnershipSelfOwnedAddsPorts(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-live" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-live",
				Placement: Placement{
					SandboxID:   "sb-live",
					OwnerNodeID: "worker-self",
					Spec:        &models.CreateSandboxRequest{Image: "alpine"},
				},
				Owner: OwnerInfo{NodeID: "worker-self", IsSelf: true},
			})
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
		ID:           "sb-live",
		ExposedPorts: map[int]ExposedPortRoute{3000: {Protocol: "http", PublicURL: "https://live"}},
	}}); err != nil {
		t.Fatalf("AssertOwnership live owner: %v", err)
	}
	cmds := capture.commandsSnapshot()
	if len(cmds) != 1 || cmds[0].Op != opAddExposedPort || cmds[0].Port != 3000 {
		t.Fatalf("commands = %+v", cmds)
	}
}

func TestClusterCustomDomainsOnLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "custom-domains-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx := context.Background()
	if err := c.RecordPlacement(ctx, "sb-dom", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if err := c.AddCustomDomain(ctx, "sb-dom", "API.Example.COM"); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	got := c.CustomDomainsOf("sb-dom")
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("CustomDomainsOf = %v", got)
	}
	sid, ok := c.ResolveCustomDomain("api.example.com")
	if !ok || sid != "sb-dom" {
		t.Fatalf("ResolveCustomDomain = (%q, %v)", sid, ok)
	}
	if err := c.RemoveCustomDomain(ctx, "sb-dom", "api.example.com"); err != nil {
		t.Fatalf("RemoveCustomDomain: %v", err)
	}
}

func TestVoterAutoJoinGossipHelpers(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer-1", RaftAddr: "127.0.0.1:7001", Role: config.NodeRoleWorker, Alive: true})
	c := &Cluster{nodeID: "self", gossip: &gossipNode{memberIndex: index}}

	if got := c.peerRaftAddr("peer-1"); got != "127.0.0.1:7001" {
		t.Fatalf("peerRaftAddr = %q", got)
	}
	if c.peerRaftAddr("missing") != "" {
		t.Fatal("missing peer should return empty raft addr")
	}
	if !c.peerForcedNonVoter("peer-1") {
		t.Fatal("worker role should force non-voter")
	}

	d := &voterAutoJoinDelegate{c: c}
	d.NotifyUpdate(&memberlist.Node{Name: "peer-1"})
}

func TestInvalidTopologyFromMessagePassthrough(t *testing.T) {
	if err := invalidTopologyFromMessage("unrelated"); err != nil {
		t.Fatalf("unrelated message = %v, want nil", err)
	}
	if err := invalidTopologyFromMessage(ErrInvalidTopology.Error()); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("bare sentinel = %v", err)
	}
	msg := ErrInvalidTopology.Error() + ": live cluster contains mixed nodes"
	if err := invalidTopologyFromMessage(msg); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("prefixed message = %v", err)
	}
}

func TestSetLocalWasmModuleIDsProvider(t *testing.T) {
	admitter := capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil)
	cache := newCapacityLeaseCache("self", admitter, time.Second, nil)
	cache.SetLocalWasmModuleIDsProvider(func() ([]string, bool) {
		return []string{"mod-a"}, true
	})
	cache.refreshLocal(time.Now())
	cache.mu.RLock()
	lease := cache.leases["self"]
	cache.mu.RUnlock()
	if !lease.snapshot.LocalWasmModuleInventoryKnown || len(lease.snapshot.LocalWasmModuleIDs) != 1 {
		t.Fatalf("wasm module inventory = %+v", lease.snapshot)
	}

	c := &Cluster{capacityLeases: cache}
	c.SetLocalWasmModuleIDsProvider(func() ([]string, bool) {
		return []string{"mod-b"}, true
	})
}
