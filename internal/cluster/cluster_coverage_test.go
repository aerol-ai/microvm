package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestBeginDeletePlacementExactSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	// Guards are already covered; this is the applyCommand success path that
	// actually fences the placement so later recreate cannot race cleanup.
	c, cleanup := newTestCluster(t, "ldr-begin-del-exact", true, nil)
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
	c.capacityLeases.setAdmitter(admitter)
	c.capacityLeases.set(c.nodeID, admitter.Snapshot(), time.Now())
	ctx := context.Background()

	if err := c.RecordPlacement(ctx, "sb-begin-del", &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if err := c.UpsertSpec(ctx, "sb-begin-del", &models.CreateSandboxRequest{Image: "alpine", CPU: 2}, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec inherit: %v", err)
	}
	placed, ok := c.PlacementOf("sb-begin-del")
	if !ok || placed.IncarnationID == "" {
		t.Fatalf("placement = %+v ok=%v", placed, ok)
	}
	if err := c.BeginDeletePlacementExact(ctx, placed.SandboxID, placed.OwnerNodeID, placed.IncarnationID); err != nil {
		t.Fatalf("BeginDeletePlacementExact: %v", err)
	}
	got, ok := c.PlacementOf("sb-begin-del")
	if !ok || !got.IsDeleting() {
		t.Fatalf("after begin delete = %+v ok=%v, want deleting fence", got, ok)
	}

	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost}
	if err := c.ReserveOnTarget(ctx, "sb-res-lift", target, &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if err := c.CancelReservation(ctx, "sb-res-lift"); err != nil {
		t.Fatalf("CancelReservation: %v", err)
	}
	if _, reserved := c.PlacementOf("sb-res-lift"); reserved {
		t.Fatal("cancelled reservation should be gone")
	}

	if err := c.RecordPlacement(ctx, "sb-claim-src", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("seed claim source: %v", err)
	}
	src, _ := c.PlacementOf("sb-claim-src")
	orphanPayload, err := encodeCommand(command{Op: opOrphanOwner, NodeID: c.nodeID})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.applyEncodedLocal(ctx, orphanPayload); err != nil {
		t.Fatalf("orphan: %v", err)
	}
	if err := c.ClaimOrphan(ctx, "sb-claim-src", nil, PlacementSecrets{IncarnationID: src.IncarnationID}); err != nil {
		t.Fatalf("ClaimOrphan: %v", err)
	}

	byID := c.PlacementsByIDs([]string{"sb-begin-del", "missing"})
	if _, ok := byID["sb-begin-del"]; !ok {
		t.Fatalf("PlacementsByIDs = %+v", byID)
	}

	// Seed expired reservation/delete-fence rows so the leader sweep body runs.
	c.fsm.mu.Lock()
	c.fsm.placements["sb-exp-res"] = Placement{
		SandboxID: "sb-exp-res", State: PlacementStateReserved, ExpiresUnix: 1,
		IncarnationID: "inc-exp-res", OwnerNodeID: c.nodeID,
	}
	c.fsm.reservedIndex["sb-exp-res"] = struct{}{}
	c.fsm.placements["sb-exp-del"] = Placement{
		SandboxID: "sb-exp-del", State: PlacementStateDeleting, ExpiresUnix: 1,
		IncarnationID: "inc-exp-del", OwnerNodeID: "dead-peer",
	}
	c.fsm.deletingIndex["sb-exp-del"] = struct{}{}
	c.fsm.mu.Unlock()
	c.reconcileReservations(ctx)
	gotAuth, err := c.AuthoritativePlacementsByIDs(ctx, []string{"sb-begin-del"})
	if err != nil || gotAuth["sb-begin-del"].SandboxID == "" {
		t.Fatalf("AuthoritativePlacementsByIDs = %+v err=%v", gotAuth, err)
	}
}

func TestClusterAgentClientAndDialCoverage(t *testing.T) {
	ctx := context.Background()
	var nilCluster *Cluster
	nilCluster.invalidatePeerClient("peer")
	if _, _, err := nilCluster.PeerDialMember(Member{}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil cluster dial = %v", err)
	}
	var nilAgent *Agent
	nilAgent.invalidatePeerClient("peer")
	if _, _, err := nilAgent.PeerDialMember(Member{}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil agent dial = %v", err)
	}

	c := &Cluster{nodeID: "self", fsm: newPlacementFSM(), internalServer: &internalServer{}}
	c.AttachInternalHandler(http.NotFoundHandler())
	if c.internalServer.extra.Load() == nil {
		t.Fatal("cluster AttachInternalHandler did not store handler")
	}
	c.invalidatePeerClient("")
	c.peerClients.get(http.DefaultClient, "peer-a")
	c.invalidatePeerClient("peer-a")
	if _, _, err := c.PeerDialMember(Member{NodeID: "peer-a", InternalURL: "https://peer.example"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("cluster dial without internal client = %v", err)
	}
	c.setInternalClient(http.DefaultClient)
	if _, _, err := c.PeerDialMember(Member{NodeID: "peer-a", InternalURL: "https://peer.example"}); err != nil {
		t.Fatalf("cluster PeerDialMember: %v", err)
	}
	if _, err := c.AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("authoritative read without raft should fail")
	}
	if _, err := (*Cluster)(nil).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("nil cluster authoritative read should fail")
	}
	if err := (*Cluster)(nil).DeletePlacement(ctx, "sb"); err != nil {
		t.Fatalf("nil delete: %v", err)
	}
	if err := c.DeletePlacement(ctx, "missing-local"); err != nil {
		t.Fatalf("local FSM miss must not consult the leader: %v", err)
	}
	if err := c.PruneAuditACL(ctx, time.Time{}); err != nil {
		t.Fatalf("zero prune: %v", err)
	}
	if inc, ok, err := c.currentPlacementIncarnation(""); err != nil || ok || inc != "" {
		t.Fatalf("empty incarnation lookup = %q %v %v", inc, ok, err)
	}
	if inc, ok, err := c.currentPlacementIncarnation("missing"); err != nil || ok || inc != "" {
		t.Fatalf("missing incarnation lookup = %q %v %v", inc, ok, err)
	}
	c.fsm.mu.Lock()
	c.fsm.placements["sb-inc-empty"] = Placement{SandboxID: "sb-inc-empty"}
	c.fsm.mu.Unlock()
	if _, ok, err := c.currentPlacementIncarnation("sb-inc-empty"); !ok || !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("empty placement incarnation = ok=%v err=%v", ok, err)
	}
	if got := c.PlacementsByIDs(nil); len(got) != 0 {
		t.Fatalf("empty PlacementsByIDs = %+v", got)
	}
	if got := (*Cluster)(nil).PlacementsByIDs([]string{"x"}); len(got) != 0 {
		t.Fatalf("nil cluster PlacementsByIDs = %+v", got)
	}

	(&Agent{}).AttachInternalHandler(http.NotFoundHandler())
	a := &Agent{nodeID: "self", internalServer: &internalServer{}}
	a.AttachInternalHandler(http.NotFoundHandler())
	if a.internalServer.extra.Load() == nil {
		t.Fatal("agent AttachInternalHandler did not store handler")
	}
	a.invalidatePeerClient("peer-b")
	if _, _, err := a.PeerDialMember(Member{NodeID: "peer-b", InternalURL: "https://peer.example"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent dial without client = %v", err)
	}
	a.internalClient = http.DefaultClient
	if _, _, err := a.PeerDialMember(Member{NodeID: "peer-b", InternalURL: "https://peer.example"}); err != nil {
		t.Fatalf("agent PeerDialMember: %v", err)
	}

	// Early returns before applyCommand — no Raft needed.
	if err := c.CancelReservation(ctx, "never-reserved"); err != nil {
		t.Fatalf("cancel missing: %v", err)
	}
	if err := (*Cluster)(nil).CancelReservation(ctx, "x"); err != nil {
		t.Fatalf("nil cancel: %v", err)
	}
	if err := c.UpsertSpec(ctx, "sb", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("upsert no-op: %v", err)
	}
	if err := c.ClaimOrphan(ctx, "missing", nil, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("claim missing = %v", err)
	}
	c.fsm.mu.Lock()
	c.fsm.placements["sb-noinc"] = Placement{SandboxID: "sb-noinc"}
	c.fsm.mu.Unlock()
	if err := c.ClaimOrphan(ctx, "sb-noinc", nil, PlacementSecrets{}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("claim empty incarnation = %v", err)
	}
	if err := c.UpsertSpec(ctx, "missing", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("upsert missing = %v", err)
	}
	c.fsm.mu.Lock()
	c.fsm.placements["sb-noinc-up"] = Placement{SandboxID: "sb-noinc-up"}
	c.fsm.mu.Unlock()
	if err := c.UpsertSpec(ctx, "sb-noinc-up", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("upsert empty incarnation = %v", err)
	}
	if err := c.RecordPlacement(ctx, "sb-bad-secret", nil, PlacementSecrets{Ref: "not-a-ref", Version: 1, IncarnationID: "inc", SealGeneration: 1}); !errors.Is(err, ErrInvalidSecretHandle) {
		t.Fatalf("record invalid secret = %v", err)
	}
	if err := c.ReserveOnTarget(ctx, "sb", PlacementTarget{}, nil, PlacementSecrets{}, 0); err == nil {
		t.Fatal("zero ttl reserve accepted")
	}
	if err := c.ReserveOnTarget(ctx, "sb-bad", PlacementTarget{}, nil, PlacementSecrets{Ref: "x", Version: 1, IncarnationID: "inc", SealGeneration: 1}, time.Second); !errors.Is(err, ErrInvalidSecretHandle) {
		t.Fatalf("reserve invalid secret = %v", err)
	}
	c.fsm.mu.Lock()
	c.fsm.placements["sb-res-empty"] = Placement{SandboxID: "sb-res-empty", State: PlacementStateReserved}
	c.fsm.mu.Unlock()
	if err := c.CancelReservation(ctx, "sb-res-empty"); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("cancel empty incarnation = %v", err)
	}

	// Existing placement without incarnation must not mint a new lifecycle.
	c.fsm.mu.Lock()
	c.fsm.placements["sb-place-noinc"] = Placement{SandboxID: "sb-place-noinc"}
	c.fsm.mu.Unlock()
	if err := c.RecordPlacement(ctx, "sb-place-noinc", nil, PlacementSecrets{}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("record existing empty incarnation = %v", err)
	}
}

func TestAgentPlacementMutationsViaControlPlane(t *testing.T) {
	ctx := context.Background()
	placements := map[string]Placement{
		"sb-known": {
			SandboxID: "sb-known", IncarnationID: "inc-known",
			State: PlacementStateReserved, Version: 3,
		},
		"sb-noinc": {SandboxID: "sb-noinc", Version: 1},
	}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
			p, ok := placements[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: id, Placement: p})
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsByIDsPath:
			http.Error(w, "batch unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.RecordPlacement(ctx, "sb-new", &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{IncarnationID: "inc-new"}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if err := agent.RecordPlacement(ctx, "sb-known", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement inherit incarnation: %v", err)
	}
	if err := agent.RecordPlacement(ctx, "sb-noinc", nil, PlacementSecrets{}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("record existing empty incarnation = %v", err)
	}
	if err := agent.RecordPlacement(ctx, "missing-place", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("record mint on 404: %v", err)
	}
	if err := agent.ClaimOrphan(ctx, "missing", nil, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("claim missing = %v", err)
	}
	if err := agent.ClaimOrphan(ctx, "sb-noinc", nil, PlacementSecrets{}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("claim empty incarnation = %v", err)
	}
	if err := agent.ClaimOrphan(ctx, "sb-known", nil, PlacementSecrets{IncarnationID: "inc-known"}); err != nil {
		t.Fatalf("ClaimOrphan: %v", err)
	}
	if err := agent.UpsertSpec(ctx, "sb-none", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("upsert no-op: %v", err)
	}
	if err := agent.UpsertSpec(ctx, "missing", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("upsert missing = %v", err)
	}
	if err := agent.UpsertSpec(ctx, "sb-noinc", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("upsert empty incarnation = %v", err)
	}
	if err := agent.UpsertSpec(ctx, "sb-known", &models.CreateSandboxRequest{Image: "alpine", CPU: 2}, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec: %v", err)
	}
	if err := agent.BeginDeletePlacementExact(ctx, "sb-known", "worker-self", "inc-known"); err != nil {
		t.Fatalf("BeginDeletePlacementExact: %v", err)
	}
	if err := agent.ReserveOnTarget(ctx, "sb-res", PlacementTarget{NodeID: "worker-self"}, nil, PlacementSecrets{}, 0); err == nil {
		t.Fatal("zero ttl reserve accepted")
	}
	if err := agent.ReserveOnTarget(ctx, "sb-bad", PlacementTarget{NodeID: "worker-self"}, nil, PlacementSecrets{Ref: "x", Version: 1, IncarnationID: "inc", SealGeneration: 1}, time.Minute); !errors.Is(err, ErrInvalidSecretHandle) {
		t.Fatalf("reserve invalid secret = %v", err)
	}
	if err := agent.ReserveOnTarget(ctx, "sb-res", PlacementTarget{NodeID: "worker-self"}, nil, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget mint: %v", err)
	}
	if err := agent.ReserveOnTarget(ctx, "sb-res", PlacementTarget{NodeID: "worker-self"}, nil, PlacementSecrets{IncarnationID: "inc-res"}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if inc, ok, err := agent.currentPlacementIncarnation(ctx, ""); err != nil || ok || inc != "" {
		t.Fatalf("agent empty incarnation = %q %v %v", inc, ok, err)
	}
	if _, ok, err := agent.currentPlacementIncarnation(ctx, "sb-noinc"); !ok || !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("agent empty placement incarnation = ok=%v err=%v", ok, err)
	}
	if inc, ok, err := agent.currentPlacementIncarnation(ctx, "sb-known"); err != nil || !ok || inc != "inc-known" {
		t.Fatalf("agent known incarnation = %q ok=%v err=%v", inc, ok, err)
	}
	if err := agent.CancelReservation(ctx, "missing"); err != nil {
		t.Fatalf("cancel missing: %v", err)
	}
	if err := agent.CancelReservation(ctx, "sb-noinc"); err != nil {
		t.Fatalf("cancel non-reserved: %v", err)
	}
	if err := agent.CancelReservation(ctx, "sb-known"); err != nil {
		t.Fatalf("CancelReservation: %v", err)
	}
	if got := agent.PlacementsByIDs([]string{"sb-known"}); got != nil {
		t.Fatalf("failed batch should be nil, got %+v", got)
	}
}

func TestAgentRecordPlacementLookupError(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	if err := agent.RecordPlacement(context.Background(), "sb", nil, PlacementSecrets{}); err == nil {
		t.Fatal("lookup 500 should fail record")
	}
	if err := agent.ClaimOrphan(context.Background(), "sb", nil, PlacementSecrets{}); err == nil {
		t.Fatal("lookup 500 should fail claim")
	}
	if err := agent.UpsertSpec(context.Background(), "sb", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); err == nil {
		t.Fatal("lookup 500 should fail upsert")
	}
	if err := agent.CancelReservation(context.Background(), "sb"); err == nil {
		t.Fatal("lookup 500 should fail cancel")
	}
}

func TestAgentDeleteAndAssertOwnershipBranches(t *testing.T) {
	ctx := context.Background()
	placements := map[string]Placement{
		"sb-missing": {},
		"sb-self-res": {
			SandboxID: "sb-self-res", OwnerNodeID: "worker-self", IncarnationID: "inc-res",
			State: PlacementStateReserved, Version: 2,
		},
		"sb-self-placed": {
			SandboxID: "sb-self-placed", OwnerNodeID: "worker-self", IncarnationID: "inc-pl",
			State: PlacementStatePlaced, Version: 3,
		},
		"sb-orphan": {
			SandboxID: "sb-orphan", OwnerNodeID: "", OwnerState: PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "worker-self", IncarnationID: "inc-or",
			State: PlacementStatePlaced, Version: 4,
		},
		"sb-other": {
			SandboxID: "sb-other", OwnerNodeID: "other", IncarnationID: "inc-ot",
			State: PlacementStatePlaced, Version: 5,
		},
	}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsByIDsPath:
			var req placementsByIDsRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			out := map[string]Placement{}
			for _, id := range req.IDs {
				if p, ok := placements[id]; ok && p.SandboxID != "" {
					out[id] = p
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
			if id == "lookup-fail" {
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
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.DeletePlacement(ctx, "unknown"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if err := agent.DeletePlacement(ctx, "sb-self-placed"); err != nil {
		t.Fatalf("delete existing: %v", err)
	}
	if err := agent.DeletePlacementExact(ctx, "", "owner", "inc"); err != nil {
		t.Fatalf("exact empty sandbox: %v", err)
	}
	if err := agent.DeletePlacementExact(ctx, "sb", "owner", ""); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("exact empty incarnation = %v", err)
	}
	if err := agent.ApplyEncoded(ctx, []byte("not-json")); err == nil {
		t.Fatal("ApplyEncoded garbage")
	}

	if err := agent.AssertOwnership(ctx, []LocalSandboxState{
		{},
		{ID: "lookup-fail"},
		{ID: "brand-new", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{80: {Protocol: "http"}}, CustomHostnames: []string{"new.example"}},
		{ID: "sb-self-res", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{81: {Protocol: "http"}}, CustomHostnames: []string{"res.example"}},
		{ID: "sb-self-placed", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{82: {Protocol: "http"}}, CustomHostnames: []string{"pl.example"}},
		{ID: "sb-orphan", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{83: {Protocol: "http"}}, CustomHostnames: []string{"or.example"}},
		{ID: "sb-other"},
	}); err != nil {
		t.Logf("AssertOwnership firstErr=%v", err)
	}

	var nilSrv *internalServer
	nilSrv.SetPeerAuthorizer(nil)
	srv := &internalServer{}
	srv.SetPeerAuthorizer(nil)
	srv.SetPeerAuthorizer(func(string) bool { return true })

	tlsState := &ClusterTLS{}
	if _, err := tlsState.lastGoodCertificate(errors.New("reload")); err == nil {
		t.Fatal("lastGood without current")
	}
	leaf := tls.Certificate{}
	tlsState.current.Store(&leaf)
	if got, err := tlsState.lastGoodCertificate(errors.New("reload")); err != nil || got != &leaf {
		t.Fatalf("lastGood cached = %v err=%v", got, err)
	}

	id, err := MintIncarnationID()
	if err != nil || id == "" {
		t.Fatalf("MintIncarnationID = %q %v", id, err)
	}
}

func TestLift3NoopShardsNilGuards(t *testing.T) {
	if _, _, err := (&Noop{nodeID: "self"}).SelectPlacementWithCandidates(capacity.Request{RequiredNodeID: "other"}); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("required other node = %v", err)
	}
	(&Noop{}).releaseVolumeAttachmentsForIncarnationLocked("sb", "")

	if got := rendezvousIngressOwnerIndex(0, nil); got != -1 {
		t.Fatalf("empty rendezvous = %d", got)
	}
	if got := rendezvousIngressOwnerIndexes(0, nil, 1); got != nil {
		t.Fatalf("empty indexes = %v", got)
	}
	if got := rendezvousIngressOwnerIndexes(0, []string{"a"}, 0); got != nil {
		t.Fatalf("n<=0 = %v", got)
	}
	if got := rendezvousIngressOwnerIndexes(0, []string{"a"}, 8); len(got) != 1 {
		t.Fatalf("n>len = %v", got)
	}

	var nilCluster *Cluster
	if nilCluster.currentInternalClient() != nil {
		t.Fatal("nil currentInternalClient")
	}
	nilCluster.setInternalClient(http.DefaultClient)
	var nilGossip *gossipNode
	if nilGossip.currentMemberIndex() != nil {
		t.Fatal("nil currentMemberIndex")
	}
	nilGossip.setMemberIndex(newGossipMemberIndex())
	var nilIndex *gossipMemberIndex
	if _, ok := nilIndex.get("x"); ok {
		t.Fatal("nil index get")
	}

	if err := (*Cluster)(nil).DeletePlacementExact(context.Background(), "sb", "owner", "inc"); err != nil {
		t.Fatalf("nil exact delete: %v", err)
	}
	empty := &Cluster{}
	if err := empty.DeletePlacementExact(context.Background(), "sb", "owner", "inc"); err != nil {
		t.Fatalf("fsm-nil exact delete: %v", err)
	}
	if err := empty.BeginDeletePlacementExact(context.Background(), "sb", "", "inc"); err != nil {
		t.Fatalf("fsm-nil begin delete: %v", err)
	}
	if err := empty.DeletePlacementExact(context.Background(), "sb", "owner", ""); !errors.Is(err, ErrIncarnationConflict) && err != nil {
		// fsm-nil returns before the incarnation check
	}
	fsmOnly := &Cluster{fsm: newPlacementFSM()}
	if err := fsmOnly.DeletePlacementExact(context.Background(), "sb", "owner", ""); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("exact empty incarnation = %v", err)
	}
	if err := fsmOnly.BeginDeletePlacementExact(context.Background(), "sb", "", "inc"); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("begin empty owner = %v", err)
	}
	if err := fsmOnly.ReassignPlacement(context.Background(), "", PlacementTarget{NodeID: "n"}); err == nil {
		t.Fatal("reassign empty sandbox")
	}
	if err := fsmOnly.ReassignPlacement(context.Background(), "sb", PlacementTarget{}); err == nil {
		t.Fatal("reassign empty target")
	}
	if err := fsmOnly.ReassignPlacement(context.Background(), "missing", PlacementTarget{NodeID: "n"}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("reassign missing = %v", err)
	}
	if err := fsmOnly.ClaimOrphan(context.Background(), "missing", nil, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("claim missing = %v", err)
	}
	if err := fsmOnly.UpsertSpec(context.Background(), "missing", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("upsert missing = %v", err)
	}
	if err := fsmOnly.ClaimOrphan(context.Background(), "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("claim bad secret handle")
	}
	if err := fsmOnly.UpsertSpec(context.Background(), "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("upsert bad secret handle")
	}
	if err := fsmOnly.RecordPlacement(context.Background(), "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("record bad secret handle")
	}
	if err := fsmOnly.AddExposedPort(context.Background(), "missing", 80, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("add port missing placement = %v", err)
	}
	if err := fsmOnly.RemoveExposedPort(context.Background(), "missing", 80); err != nil {
		t.Fatalf("remove port missing = %v", err)
	}
	if err := fsmOnly.AddCustomDomain(context.Background(), "missing", "h.example"); err != nil {
		t.Fatalf("add domain missing = %v", err)
	}
	if err := fsmOnly.RemoveCustomDomain(context.Background(), "missing", "h.example"); err != nil {
		t.Fatalf("remove domain missing = %v", err)
	}

	if err := validateSecretRecipientUpdate("", []string{"n"}, PlacementSecrets{}, "", 0); err == nil {
		t.Fatal("empty recipient update")
	}
	if err := validateSecretRecipientUpdate("sb", []string{"n"}, PlacementSecrets{IncarnationID: "inc"}, "", 0); err == nil {
		t.Fatal("missing expected generation")
	}
	sec := testPlacementSecrets("sb", "inc", 1)
	if err := validateSecretRecipientUpdate("sb", []string{"n"}, sec, "inc", 1); err == nil {
		t.Fatal("generation must advance")
	}
	sec.SealGeneration = 2
	sec.Ref = "not-a-ref"
	if err := validateSecretRecipientUpdate("sb", []string{"n"}, sec, "inc", 1); err == nil {
		t.Fatal("bad replacement ref")
	}
}

func TestBeginDeletePlacementExactGuards(t *testing.T) {
	ctx := context.Background()
	var c *Cluster
	if err := c.BeginDeletePlacementExact(ctx, "sb", "owner", "inc"); err != nil {
		t.Fatalf("nil cluster = %v", err)
	}
	empty := &Cluster{}
	if err := empty.BeginDeletePlacementExact(ctx, "", "owner", "inc"); err != nil {
		t.Fatalf("empty sandbox = %v", err)
	}
	// fsm == nil short-circuits before the owner/incarnation guard.
	if err := empty.BeginDeletePlacementExact(ctx, "sb", "", "inc"); err != nil {
		t.Fatalf("nil fsm = %v", err)
	}

	a := &Agent{}
	if err := a.BeginDeletePlacementExact(ctx, "", "owner", "inc"); err != nil {
		t.Fatalf("agent empty sandbox = %v", err)
	}
	if err := a.BeginDeletePlacementExact(ctx, "sb", "", ""); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("agent missing owner/incarnation = %v", err)
	}
}

func TestCloneBytesAndNoopAttachInternalHandler(t *testing.T) {
	if got := cloneBytes(nil); got != nil {
		t.Fatalf("cloneBytes(nil)=%v", got)
	}
	if got := cloneBytes([]byte{}); got != nil {
		t.Fatalf("cloneBytes(empty)=%v", got)
	}
	in := []byte("abc")
	out := cloneBytes(in)
	if string(out) != "abc" {
		t.Fatalf("cloneBytes=%q", string(out))
	}
	out[0] = 'z'
	if string(in) != "abc" {
		t.Fatalf("clone should be independent; input mutated to %q", string(in))
	}

	n := &Noop{nodeID: "solo", apiURL: "http://127.0.0.1:8080"}
	n.AttachInternalHandler(http.NotFoundHandler())
}

func TestClusterPlacementAndSecretHelpers(t *testing.T) {
	placed := Placement{State: PlacementStatePlaced}
	if placed.IsReserved() {
		t.Fatal("placed placement should not be reserved")
	}
	reserved := Placement{State: PlacementStateReserved}
	if !reserved.IsReserved() {
		t.Fatal("reserved placement should report reserved")
	}

	if !(Placement{}).IsOrphaned() {
		t.Fatal("zero placement should be orphaned")
	}
	if !(Placement{OwnerState: PlacementOwnerStateOrphaned, OwnerNodeID: "node-a"}).IsOrphaned() {
		t.Fatal("orphan state should report orphaned")
	}
	if (Placement{OwnerNodeID: "node-a", OwnerState: PlacementOwnerStateActive}).IsOrphaned() {
		t.Fatal("active owner should not be orphaned")
	}

	p := Placement{SecretRef: "ref-1", SecretVersion: 2}
	secrets := secretsFromPlacement(p)
	if secrets.Ref != "ref-1" || secrets.Version != 2 {
		t.Fatalf("secretsFromPlacement=%+v", secrets)
	}
	if !secrets.hasUpdate() {
		t.Fatal("non-empty secrets should report update")
	}
	if (PlacementSecrets{}).hasUpdate() {
		t.Fatal("zero secrets should not report update")
	}
}

func TestNoopExtraBranches(t *testing.T) {
	n := NewNoop("node-a", "http://127.0.0.1:9000", "")
	ctx := context.Background()

	if row, created, err := n.VolumeUpsert(ctx, models.Volume{Tenant: "t", Name: "n", ID: "id-1"}, 0); err != nil || !created || row.ID != "id-1" {
		t.Fatalf("VolumeUpsert row=%+v created=%v err=%v", row, created, err)
	}
	if _, _, err := n.OwnerOfName("missing"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfName error=%v", err)
	}
	if _, err := n.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1}); err != nil {
		t.Fatalf("SelectPlacement err=%v", err)
	}
	if got := n.SpecOf("sb-1"); got != nil {
		t.Fatalf("SpecOf should be nil, got %+v", got)
	}
	if got := n.SecretsOf("sb-1"); got.Ref != "" || got.Version != 0 || len(got.Recipients) != 0 {
		t.Fatalf("SecretsOf=%+v", got)
	}
	if err := n.AddExposedPort(ctx, "sb-1", 8080, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("AddExposedPort err=%v", err)
	}
	if err := n.RemoveExposedPort(ctx, "sb-1", 8080); err != nil {
		t.Fatalf("RemoveExposedPort err=%v", err)
	}
	if got := n.ExposedPortsOf("sb-1"); got != nil {
		t.Fatalf("ExposedPortsOf=%v", got)
	}
	if err := n.AddCustomDomain(ctx, "sb-1", "example.com"); err != nil {
		t.Fatalf("AddCustomDomain err=%v", err)
	}
	if err := n.RemoveCustomDomain(ctx, "sb-1", "example.com"); err != nil {
		t.Fatalf("RemoveCustomDomain err=%v", err)
	}
	if got := n.CustomDomainsOf("sb-1"); got != nil {
		t.Fatalf("CustomDomainsOf=%v", got)
	}
	if sandboxID, ok := n.ResolveCustomDomain("example.com"); ok || sandboxID != "" {
		t.Fatalf("ResolveCustomDomain=(%q,%v)", sandboxID, ok)
	}
	if err := n.ReserveOnTarget(ctx, "sb-1", PlacementTarget{}, nil, PlacementSecrets{}, 5*time.Second); err != nil {
		t.Fatalf("ReserveOnTarget err=%v", err)
	}
	if err := n.CancelReservation(ctx, "sb-1"); err != nil {
		t.Fatalf("CancelReservation err=%v", err)
	}
	if err := n.SetNodeDrainState(ctx, "node-a", true); err != nil {
		t.Fatalf("SetNodeDrainState err=%v", err)
	}
	if err := n.ReassignPlacement(ctx, "sb-1", PlacementTarget{}); err != nil {
		t.Fatalf("ReassignPlacement err=%v", err)
	}
	if !errors.Is(n.RemoveMember(ctx, "missing", false), ErrUnknownMember) {
		t.Fatal("RemoveMember should return ErrUnknownMember")
	}
	if n.IsNodeDrained("node-a") {
		t.Fatal("Noop should never mark nodes drained")
	}
	if err := n.ApplyEncoded(ctx, []byte("{}")); err != nil {
		t.Fatalf("ApplyEncoded err=%v", err)
	}

	w := httptest.NewRecorder()
	n.ForwardHTTP(Endpoint{}, w, httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("ForwardHTTP status=%d", w.Code)
	}

	n.AttachInternalHandler(http.NotFoundHandler())
	if len(n.Placements()) != 0 {
		t.Fatalf("Placements=%v", n.Placements())
	}
	if len(n.PlacementsForShards(PlacementShardFilter{})) != 0 {
		t.Fatalf("PlacementsForShards=%v", n.PlacementsForShards(PlacementShardFilter{}))
	}
	if page := n.PlacementPage(PlacementPageRequest{}); len(page.Placements) != 0 || page.NextPageToken != "" {
		t.Fatalf("PlacementPage=%+v", page)
	}
	if p, ok := n.PlacementOf("sb-1"); ok || p.SandboxID != "" || p.OwnerNodeID != "" {
		t.Fatalf("PlacementOf=(%+v,%v)", p, ok)
	}
	if n.PlacementVersion() != 0 {
		t.Fatalf("PlacementVersion=%d", n.PlacementVersion())
	}
	if ch := n.SubscribePlacement(ctx); ch != nil {
		t.Fatal("SubscribePlacement should be nil channel")
	}
	if n.Leader() != "node-a" {
		t.Fatalf("Leader=%q", n.Leader())
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close err=%v", err)
	}
}

func TestFSMStorePlacementInlineRecoveryWithoutStore(t *testing.T) {
	fsm := newPlacementFSMWithRecoveryStore(nil)
	fsm.recovery = nil
	if got := applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "sb-inline", OwnerNodeID: "n",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}, IncarnationID: "inc-inline", SecretRef: testSecretRef("sb-inline", "inc-inline"), SecretVersion: 1, SecretSealGeneration: 1,
	}); got != nil {
		t.Fatalf("place inline recovery: %v", got)
	}
	if _, ok := fsm.recovery["sb-inline"]; !ok {
		t.Fatal("expected inline recovery map entry")
	}
	p, ok := fsm.get("sb-inline")
	if !ok || p.Spec == nil || p.Spec.Image != "alpine" {
		t.Fatalf("full placement=%+v ok=%v", p, ok)
	}
}

func TestAddExposedPortMissingPlacement(t *testing.T) {
	fsm := newPlacementFSM()
	if got := applyOp(t, fsm, command{Op: opAddExposedPort, SandboxID: "missing", Port: 80, Protocol: "http"}); got != nil {
		t.Fatalf("missing placement add port=%v", got)
	}
	if got := applyOp(t, fsm, command{Op: opAddExposedPort, SandboxID: "missing", Port: 0, Protocol: "http"}); got != nil {
		t.Fatalf("zero port=%v", got)
	}
}
