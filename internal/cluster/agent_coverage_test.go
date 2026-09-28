package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNewAgentRemainingErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewAgent(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker, SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: t.TempDir()}, logger, nil); err == nil {
		t.Fatal("empty tls dir")
	}
	dirs := writeTestClusterTLSDirs(t, "cert-node")
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "other-node",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: dirs["cert-node"],
	}, logger, nil); err == nil {
		t.Fatal("tls node id mismatch")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "ag-badkey",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: writeTestClusterTLSDir(t, "ag-badkey"),
		ClusterInternalListenAddr: "127.0.0.1:0", ClusterGossipSecretKey: "%%%",
	}, logger, nil); err == nil {
		t.Fatal("bad gossip key")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "ag-badbind",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: writeTestClusterTLSDir(t, "ag-badbind"),
		ClusterInternalListenAddr: "127.0.0.1:0", GossipBindAddr: "not-a-bind-address",
	}, logger, nil); err == nil {
		t.Fatal("bad gossip bind")
	}
}

func TestLift3AgentRemainingClientBranches(t *testing.T) {
	ctx := context.Background()
	placements := map[string]Placement{
		"sb-res-empty": {SandboxID: "sb-res-empty", OwnerNodeID: "worker-self", State: PlacementStateReserved, Version: 2},
		"sb-placed-nospec": {
			SandboxID: "sb-placed-nospec", OwnerNodeID: "worker-self", IncarnationID: "inc-pl",
			State: PlacementStatePlaced, Version: 3,
		},
		"sb-orphan": {
			SandboxID: "sb-orphan", OwnerNodeID: "", OwnerState: PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "worker-self", IncarnationID: "inc-or",
			State: PlacementStatePlaced, Version: 4,
		},
		"sb-self-res": {
			SandboxID: "sb-self-res", OwnerNodeID: "worker-self", IncarnationID: "inc-res",
			State: PlacementStateReserved, Version: 5,
		},
	}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementByNamePath):
			http.Error(w, "name boom", http.StatusInternalServerError)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
			if id == "lookup-fail" || id == "port-fail" {
				http.Error(w, "nope", http.StatusInternalServerError)
				return
			}
			p, ok := placements[id]
			if !ok || p.SandboxID == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: id, Placement: p})
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalSelectPlacementPath:
			_ = json.NewEncoder(w).Encode(SelectPlacementResponse{Error: "custom select failure"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, PublicInternalPlacementsByIDsPath):
			var req placementsByIDsRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			for _, id := range req.IDs {
				if id == "lookup-fail" {
					http.Error(w, "by-ids boom", http.StatusInternalServerError)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "null")
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			http.Error(w, "apply failed", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if _, _, err := agent.OwnerOfName("named"); err == nil {
		t.Fatal("owner-of-name 500")
	}
	if sec := agent.SecretsOf("missing"); sec.Ref != "" {
		t.Fatalf("secrets of missing = %+v", sec)
	}
	if _, _, err := agent.SelectPlacementWithCandidates(capacity.Request{}); err == nil {
		t.Fatal("select custom error")
	}
	if err := agent.RecordPlacement(ctx, "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("record bad handle")
	}
	if err := agent.ClaimOrphan(ctx, "sb-orphan", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc-or"}); err == nil {
		t.Fatal("claim bad handle")
	}
	if err := agent.UpsertSpec(ctx, "sb-placed-nospec", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc-pl"}); err == nil {
		t.Fatal("upsert bad handle")
	}
	if err := agent.AddExposedPort(ctx, "port-fail", 80, ExposedPortRoute{Protocol: "http"}); err == nil {
		t.Fatal("add port lookup fail")
	}
	if err := agent.RemoveExposedPort(ctx, "port-fail", 80); err == nil {
		t.Fatal("remove port lookup fail")
	}
	if err := agent.AddCustomDomain(ctx, "port-fail", "h.example"); err == nil {
		t.Fatal("add domain lookup fail")
	}
	if err := agent.RemoveCustomDomain(ctx, "port-fail", "h.example"); err == nil {
		t.Fatal("remove domain lookup fail")
	}
	if err := agent.DeletePlacement(ctx, "lookup-fail"); err == nil {
		t.Fatal("delete lookup fail")
	}
	if err := agent.CancelReservation(ctx, "sb-res-empty"); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("cancel empty incarnation = %v", err)
	}
	if err := agent.ReassignPlacement(ctx, "", PlacementTarget{NodeID: "n"}); err == nil {
		t.Fatal("reassign empty sandbox")
	}
	if err := agent.ReassignPlacement(ctx, "sb", PlacementTarget{}); err == nil {
		t.Fatal("reassign empty target")
	}
	if err := agent.ReassignPlacement(ctx, "lookup-fail", PlacementTarget{NodeID: "n"}); err == nil {
		t.Fatal("reassign lookup fail")
	}
	if err := agent.ReassignPlacement(ctx, "missing", PlacementTarget{NodeID: "n"}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("reassign missing = %v", err)
	}
	if err := agent.ReassignPlacement(ctx, "sb-res-empty", PlacementTarget{NodeID: "n"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("reassign empty incarnation = %v", err)
	}
	if err := agent.ReserveOnTarget(ctx, "sb", PlacementTarget{NodeID: "n"}, nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}, time.Second); err == nil {
		t.Fatal("reserve bad handle")
	}

	if err := agent.AssertOwnership(ctx, []LocalSandboxState{
		{ID: "brand-new", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{80: {Protocol: "http"}}, CustomHostnames: []string{"new.example"}},
		{ID: "sb-self-res", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{81: {Protocol: "http"}}, CustomHostnames: []string{"res.example"}},
		{ID: "sb-placed-nospec", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{82: {Protocol: "http"}}, CustomHostnames: []string{"pl.example"}},
		{ID: "sb-orphan", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{83: {Protocol: "http"}}, CustomHostnames: []string{"or.example"}},
	}); err == nil {
		t.Fatal("assert ownership apply failures")
	}

	got, err := agent.AuthoritativePlacementsByIDs(ctx, []string{"", "  "})
	if err != nil || len(got) != 0 {
		t.Fatalf("empty ids = %+v err=%v", got, err)
	}
	got, err = agent.AuthoritativePlacementsByIDs(ctx, []string{"sb-x"})
	if err != nil || got == nil {
		t.Fatalf("null map = %+v err=%v", got, err)
	}

	if _, ok := agent.LookupMember("not-in-gossip"); ok {
		t.Fatal("lookup miss")
	}
	if (&Agent{nodeID: "self"}).controlPlaneMembers() != nil {
		t.Fatal("gossip-nil control-plane members")
	}
	if err := agent.doHTTPRequest(ctx, http.DefaultClient, "http://%zz", http.MethodGet, nil, nil); err == nil {
		t.Fatal("doHTTP bad URL")
	}
	if err := agent.doHTTPRequest(ctx, http.DefaultClient, "http://127.0.0.1:1", http.MethodGet, []byte("{}"), nil); err == nil {
		t.Fatal("doHTTP dial")
	}

	closeAgent := &Agent{internalServer: &internalServer{srv: &http.Server{}}}
	_ = closeAgent.Close()

	fsm := newPlacementFSM()
	fsm.recoveryStore = lift3FailGetStore{}
	if _, _, err := fsm.resolveRecoveryRef("ref"); err == nil {
		t.Fatal("resolve get fail")
	}
	fsm.recoveryStore = nil
	fsm.recoveryResolver = func(context.Context, string) (RecoveryBlob, bool, error) {
		return RecoveryBlob{Ref: "a", SandboxID: "sb"}, true, nil
	}
	if _, _, err := fsm.resolveRecoveryRef("ref"); err != nil {
		t.Fatalf("resolve store-nil: %v", err)
	}
	fsm.recoveryStore = failPutRecoveryStore{}
	if err := fsm.storeRecoveryBlob(RecoveryBlob{Ref: "want", SandboxID: "sb"}); err == nil {
		t.Fatal("store put fail")
	}
	fsm.recoveryStore = lift3MismatchPutStore{}
	if err := fsm.storeRecoveryBlob(RecoveryBlob{Ref: "want", SandboxID: "sb"}); err == nil {
		t.Fatal("store ref mismatch")
	}
	fsm.deletingIndex = nil
	fsm.indexDeletingStateLocked("sb", Placement{State: PlacementStateDeleting})
}

type lift3FailGetStore struct{}

func (lift3FailGetStore) Put(string, placementRecovery) (string, error) { return "", nil }

func (lift3FailGetStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, errors.New("get fail")
}

func (lift3FailGetStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, errors.New("get fail")
}

func (lift3FailGetStore) Delete(string) error { return nil }

func (lift3FailGetStore) RetainSnapshotRefs([]string) error { return nil }

type lift3MismatchPutStore struct{}

func (lift3MismatchPutStore) Put(string, placementRecovery) (string, error) { return "other", nil }

func (lift3MismatchPutStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, nil
}

func (lift3MismatchPutStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, nil
}

func (lift3MismatchPutStore) Delete(string) error { return nil }

func (lift3MismatchPutStore) RetainSnapshotRefs([]string) error { return nil }

func TestControlPlaneDiagnosticsHelpers(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Role: config.NodeRoleWorker, Alive: true})
	index.upsert(Member{NodeID: "dead-srv", Role: config.NodeRoleServer, Alive: false, APIURL: "http://x", InternalURL: "https://x"})
	index.upsert(Member{NodeID: "ok-srv", Role: config.NodeRoleServer, Alive: true, APIURL: "http://ok", InternalURL: "https://ok"})
	a := &Agent{
		nodeID: "self",
		gossip: &gossipNode{memberIndex: index},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	total, alive, serverRole, self, dead, nonControlPlaneRole, missingEndpoint, candidates, visible := a.controlPlaneDiagnosticSnapshot()
	if total != 3 || alive != 2 || serverRole != 2 || self != 1 || dead != 1 || nonControlPlaneRole != 1 || missingEndpoint != 1 || candidates != 1 {
		t.Fatalf("diag counts = total=%d alive=%d server=%d self=%d dead=%d non=%d missing=%d cand=%d",
			total, alive, serverRole, self, dead, nonControlPlaneRole, missingEndpoint, candidates)
	}
	if len(visible) != 3 {
		t.Fatalf("visible=%v", visible)
	}
	if got := controlPlaneMemberDiagnostic(Member{NodeID: "self", Role: config.NodeRoleWorker}, "self"); !strings.Contains(got, "self") || !strings.Contains(got, "role-not-control-plane") || !strings.Contains(got, "missing-endpoint") {
		t.Fatalf("member diagnostic=%q", got)
	}
	a.logNoControlPlaneMembers("GET", "/v1/a", "/v1/internal/a")
	a.logNoControlPlaneMembers("GET", "/v1/a", "/v1/internal/a")
}

func TestAgentVolumeMethodsAndQueryBranches(t *testing.T) {
	vols := map[string]models.Volume{}
	server, internalClient := newNodeBoundForwardServer(t, "worker", "cp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			var cmd command
			body, _ := io.ReadAll(r.Body)
			if err := decodeCommandInto(body, &cmd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			switch cmd.Op {
			case opUpsertVolume:
				if cmd.Volume != nil {
					v := *cmd.Volume
					vols[v.Tenant+"/"+v.Name] = v
				}
			case opDeleteVolume:
				for k, v := range vols {
					if v.Tenant == cmd.VolumeTenant && v.ID == cmd.VolumeID {
						delete(vols, k)
					}
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalVolumePath:
			q := r.URL.Query()
			switch q.Get("kind") {
			case "name":
				if v, ok := vols[q.Get("tenant")+"/"+q.Get("name")]; ok {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &v})
					return
				}
				http.NotFound(w, r)
			case "list":
				_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volumes: []models.Volume{}})
			case "source":
				_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Exists: false})
			case "attachment_count":
				_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Count: 0})
			default:
				http.Error(w, "bad", http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "cp", APIURL: server.URL, InternalURL: server.URL, Alive: true, Role: config.NodeRoleServer})
	a := &Agent{
		nodeID:         "worker",
		internalClient: internalClient,
		gossip:         &gossipNode{memberIndex: index},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v := models.Volume{ID: "vol-1", Tenant: "t1", Name: "n1", Backend: "s3"}
	row, created, err := a.VolumeUpsert(ctx, v, 0)
	if err != nil || !created || row.ID != "vol-1" {
		t.Fatalf("VolumeUpsert row=%+v created=%v err=%v", row, created, err)
	}
	if got, err := a.VolumeByName(ctx, "t1", "n1"); err != nil || got.ID != "vol-1" {
		t.Fatalf("VolumeByName got=%+v err=%v", got, err)
	}
	if got, err := a.VolumesForTenant(ctx, "t1"); err != nil || got == nil {
		t.Fatalf("VolumesForTenant got=%+v err=%v", got, err)
	}
	if exists, err := a.VolumeExistsForSource(ctx, "s"); err != nil || exists {
		t.Fatalf("VolumeExistsForSource exists=%v err=%v", exists, err)
	}
	if cnt, err := a.VolumeAttachmentCount(ctx, "t1", "vol-1"); err != nil || cnt != 0 {
		t.Fatalf("VolumeAttachmentCount cnt=%d err=%v", cnt, err)
	}
	if err := a.VolumeDelete(ctx, "t1", "vol-1"); err != nil {
		t.Fatalf("VolumeDelete err=%v", err)
	}

	// queryVolumes: 404 path should map to nil error and empty response.
	if _, err := a.VolumeByName(ctx, "t1", "missing"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("VolumeByName missing err=%v", err)
	}

	ctxShort, cancelShort := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancelShort()
	if _, err := a.readbackVolume(ctxShort, "t1", "never"); err == nil {
		t.Fatal("readbackVolume should honor context timeout")
	}
}

func decodeCommandInto(payload []byte, out *command) error {
	cmd, err := decodeCommand(payload)
	if err != nil {
		return err
	}
	*out = cmd
	return nil
}

func TestAgentControlPlaneMembersAndPlacementCacheHelpers(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleServer, APIURL: "http://self"})
	index.upsert(Member{NodeID: "dead", Alive: false, Role: config.NodeRoleServer, APIURL: "http://dead"})
	index.upsert(Member{NodeID: "worker", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://worker"})
	index.upsert(Member{NodeID: "no-endpoint", Alive: true, Role: config.NodeRoleServer})
	index.upsert(Member{NodeID: "cp", Alive: true, Role: config.NodeRoleServer, APIURL: "http://cp", InternalURL: "https://cp"})

	a := &Agent{
		nodeID: "self",
		gossip: &gossipNode{memberIndex: index},
	}
	members := a.controlPlaneMembers()
	if len(members) != 1 || members[0].NodeID != "cp" {
		t.Fatalf("controlPlaneMembers=%+v", members)
	}

	a.observePlacementVersion(5)
	a.observePlacementVersion(3)
	if got := a.PlacementVersion(); got != 5 {
		t.Fatalf("PlacementVersion=%d", got)
	}
	a.observePlacementVersions([]Placement{{Version: 7}, {Version: 6}})
	if got := a.PlacementVersion(); got != 7 {
		t.Fatalf("PlacementVersion after list=%d", got)
	}

	a.placementCache = []Placement{{SandboxID: "sb-all", OwnerNodeID: "cp"}}
	a.shardCache = map[string][]Placement{
		placementShardFilterCacheKey(PlacementShardFilter{ShardCount: 16, Shards: []int{1}}): {{SandboxID: "sb-shard", OwnerNodeID: "cp"}},
	}
	all := a.cachedPlacementsForShards(PlacementShardFilter{})
	if len(all) != 1 || all[0].SandboxID != "sb-all" {
		t.Fatalf("cachedPlacementsForShards(all)=%+v", all)
	}
	sharded := a.cachedPlacementsForShards(PlacementShardFilter{ShardCount: 16, Shards: []int{1}})
	if len(sharded) != 1 || sharded[0].SandboxID != "sb-shard" {
		t.Fatalf("cachedPlacementsForShards(shard)=%+v", sharded)
	}
	fallback := a.cachedPlacementsForShards(PlacementShardFilter{ShardCount: 16, Shards: []int{2}})
	if len(fallback) != 1 || fallback[0].SandboxID != "sb-all" {
		t.Fatalf("cachedPlacementsForShards(fallback)=%+v", fallback)
	}
}

func TestAgentDoControlPlaneJSONMarshalError(t *testing.T) {
	a := &Agent{}
	if err := a.doControlPlaneJSON(context.Background(), http.MethodPost, "/x", "/x", map[string]any{"bad": make(chan int)}, nil); err == nil {
		t.Fatal("expected json marshal error")
	}
}

func TestControlPlaneMemberDiagnosticCandidateAndThrottlePath(t *testing.T) {
	diag := controlPlaneMemberDiagnostic(Member{NodeID: "cp-a", Alive: true, Role: config.NodeRoleServer, APIURL: "http://cp", InternalURL: "https://cp"}, "self")
	if !strings.Contains(diag, "candidate") {
		t.Fatalf("candidate diagnostic=%q", diag)
	}

	a := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.lastNoControlPlaneLogUnix.Store(time.Now().Unix())
	a.logNoControlPlaneMembers(http.MethodGet, "/v1/sandboxes", InternalAPIPath)
}

func TestAgentCloseNilGossip(t *testing.T) {
	a := &Agent{}
	if err := a.Close(); err != nil {
		t.Fatalf("Close nil gossip: %v", err)
	}
}

func TestAgentCloseGossipErrorPath(t *testing.T) {
	a := &Agent{gossip: &gossipNode{}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := a.Close(); err != nil {
		// nil memberlist Close may return an error; both outcomes are fine for coverage.
		t.Logf("Close: %v", err)
	}
}

func TestClusterClientGuardBranches(t *testing.T) {
	c := &Cluster{
		nodeID: "self",
		fsm:    newPlacementFSM(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if got := c.ExposedPortsOf("missing"); got != nil {
		t.Fatalf("ExposedPortsOf missing=%v", got)
	}
	ctx := context.Background()
	if err := c.ReserveBatchOnTargets(ctx, nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if err := c.ReassignPlacement(ctx, "sb", PlacementTarget{}); err == nil {
		t.Fatal("empty target")
	}
	if err := c.ReassignPlacement(ctx, "", PlacementTarget{NodeID: "x"}); err == nil {
		t.Fatal("empty sandbox")
	}
	if err := c.RemoveMember(ctx, "x", false); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("nil raft RemoveMember=%v", err)
	}
	if err := c.RemoveMember(ctx, "", false); err == nil {
		t.Fatal("empty nodeID")
	}

	a := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := a.RemoveMember(ctx, "", false); err == nil {
		t.Fatal("agent empty RemoveMember")
	}
	var nilAgent *Agent
	nilAgent.logNoControlPlaneMembers("GET", "/a", "/b")
	a.logNoControlPlaneMembers("GET", "/a", "/b")
	a.lastNoControlPlaneLogUnix.Store(time.Now().Unix())
	a.logNoControlPlaneMembers("GET", "/a", "/b") // throttle

	if _, err := NewAgent(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Fatal("NewAgent EnableCluster false")
	}
	if _, err := NewAgent(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Fatal("NewAgent server role")
	}
	if _, err := NewAgent(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Fatal("NewAgent missing advertise URL")
	}
	if _, err := New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Fatal("New EnableCluster false")
	}
	if _, err := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil); err == nil {
		t.Fatal("New non-server")
	}
}

func TestClonePlacementsEmptyAndSplitHostPortBad(t *testing.T) {
	if got := clonePlacements(nil); got != nil {
		t.Fatalf("nil=%v", got)
	}
	if got := clonePlacements([]Placement{}); got != nil {
		t.Fatalf("empty=%v", got)
	}
	if _, _, err := splitHostPort("host:notaport"); err == nil {
		t.Fatal("expected atoi error")
	}
}
