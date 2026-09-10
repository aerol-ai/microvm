package cluster

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/aerol-ai/microvm/pkg/secrets"
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
	c.capacityLeases.admitter = admitter
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

func TestSecretReplicationNilErrorAndNoDialBranches(t *testing.T) {
	ctx := context.Background()
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}

	// Dead recipient must stay pending on delete, matching put-outbox semantics.
	members := []Member{{NodeID: "peer", Alive: false, InternalURL: "https://peer.internal"}}
	if acked, err := deleteSecretOnPeers(ctx, members, http.DefaultClient, "pat", "self", "sb", "inc", []string{"peer"}, 1); err == nil || len(acked) != 0 {
		t.Fatalf("dead delete acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeers(ctx, members, http.DefaultClient, "pat", "self", "sb", "inc", []string{"peer"}, 1); err != nil || len(holding) != 0 {
		t.Fatalf("dead probe holding=%v err=%v", holding, err)
	}

	// Dial succeeded with no usable client/URL — incomplete, not silent ACK.
	lookup := func(string) (Member, bool) {
		return Member{NodeID: "peer", Alive: true, InternalURL: "https://peer.internal"}, true
	}
	noPath := func(Member) (*http.Client, string, error) { return nil, "", nil }
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, lookup, http.DefaultClient, noPath, "pat", "self", blob, []string{"peer"}); err == nil || len(acked) != 0 {
		t.Fatalf("no-path push acked=%v err=%v", acked, err)
	}
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, noPath, "pat", "self", "sb", "inc", []string{"peer"}, 1); err == nil || len(acked) != 0 {
		t.Fatalf("no-path delete acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, noPath, "pat", "self", "sb", "inc", []string{"peer"}, 1); err != nil || len(holding) != 0 {
		t.Fatalf("no-path probe holding=%v err=%v", holding, err)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.Method {
		case http.MethodHead:
			if hits == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost, http.MethodDelete:
			if hits == 1 {
				http.Error(w, "retry", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	dial := func(Member) (*http.Client, string, error) { return srv.Client(), srv.URL, nil }

	holding, err := probeSecretOnPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", "sb", "inc", []string{"peer"}, 1)
	if err != nil || len(holding) != 1 {
		t.Fatalf("HEAD 200 holding=%v err=%v", holding, err)
	}
	holding, err = probeSecretOnPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", "sb", "inc", []string{"peer"}, 1)
	if err != nil || len(holding) != 0 {
		t.Fatalf("HEAD 404 holding=%v err=%v", holding, err)
	}

	// First attempt fails so withSecretFanoutBackoff exercises the timer path.
	hits = 0
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", blob, []string{"peer"}); err != nil || len(acked) != 1 {
		t.Fatalf("retry push acked=%v err=%v", acked, err)
	}
	hits = 0
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", "sb", "inc", []string{"peer"}, 1); err != nil || len(acked) != 1 {
		t.Fatalf("retry delete acked=%v err=%v", acked, err)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	attempt := 0
	err = withSecretFanoutBackoff(cancelCtx, func() error {
		attempt++
		cancel()
		return errors.New("force backoff")
	})
	if !errors.Is(err, context.Canceled) || attempt != 1 {
		t.Fatalf("cancel-during-backoff err=%v attempt=%d", err, attempt)
	}

	// Cluster/Agent wrappers go through PeerDialMember, which rejects plaintext.
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer", Alive: true, InternalURL: "http://peer.internal"})
	c := &Cluster{nodeID: "self", patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	c.setInternalClient(http.DefaultClient)
	a := &Agent{nodeID: "self", patToken: "pat", internalClient: http.DefaultClient, gossip: &gossipNode{memberIndex: index}}
	if _, err := c.PushSecretBlobToPeers(ctx, blob, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("cluster plaintext push = %v", err)
	}
	if _, err := a.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("agent plaintext delete = %v", err)
	}
	if _, err := c.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("cluster plaintext probe = %v", err)
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

func TestDeleteFenceOwnerUnavailableAndReconcileGuards(t *testing.T) {
	if (*Cluster)(nil).deleteFenceOwnerUnavailable("") != true {
		t.Fatal("nil cluster empty owner should treat fence as abandoned")
	}
	c := &Cluster{nodeID: "self", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if !c.deleteFenceOwnerUnavailable("") {
		t.Fatal("empty owner is unavailable")
	}
	if c.deleteFenceOwnerUnavailable("self") {
		t.Fatal("self fence must stay while this node is retrying cleanup")
	}
	if c.deleteFenceOwnerUnavailable("peer") {
		t.Fatal("nil gossip must not expire a live owner's fence")
	}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	if !c.deleteFenceOwnerUnavailable("missing") {
		t.Fatal("unknown owner is unavailable")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "dead", Alive: false})
	if !c.deleteFenceOwnerUnavailable("dead") {
		t.Fatal("dead owner is unavailable")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "live", Alive: true})
	if c.deleteFenceOwnerUnavailable("live") {
		t.Fatal("live owner fence must not expire")
	}
	c.reconcileReservations(context.Background())
}

func TestFSMAuditACLNewerPageByOwnerRefAndRelease(t *testing.T) {
	if !auditACLNewer("b", AuditACL{RetainedVersion: 2}, "a", AuditACL{RetainedVersion: 1}) {
		t.Fatal("higher retained version should win")
	}
	if auditACLNewer("a", AuditACL{RetainedVersion: 1}, "b", AuditACL{RetainedVersion: 2}) {
		t.Fatal("lower retained version should lose")
	}
	if !auditACLNewer("b", AuditACL{RetainedVersion: 1}, "a", AuditACL{RetainedVersion: 1}) {
		t.Fatal("tie-break prefers lexicographically greater key")
	}
	if auditACLNewer("a", AuditACL{RetainedVersion: 1}, "b", AuditACL{RetainedVersion: 1}) {
		t.Fatal("lower key at same version should lose")
	}

	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "own-aaa", OwnerNodeID: "n1", OwnerRef: "tenant-a", IncarnationID: "inc-a", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "own-bbb", OwnerNodeID: "n1", OwnerRef: "tenant-a", IncarnationID: "inc-b", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "own-ccc", OwnerNodeID: "n2", OwnerRef: "tenant-b", IncarnationID: "inc-c", Spec: &models.CreateSandboxRequest{Image: "alpine"}})

	page := fsm.placementPage(PlacementPageRequest{Limit: 1, OwnerRef: "tenant-a"})
	if len(page.Placements) != 1 || page.Placements[0].SandboxID != "own-aaa" || page.NextPageToken == "" {
		t.Fatalf("owner-ref first page = %+v", page)
	}
	page = fsm.placementPage(PlacementPageRequest{Limit: 10, OwnerRef: "tenant-a", PageToken: page.NextPageToken})
	if len(page.Placements) != 1 || page.Placements[0].SandboxID != "own-bbb" {
		t.Fatalf("owner-ref second page = %+v", page)
	}
	if got := fsm.placementPage(PlacementPageRequest{Limit: 10, OwnerRef: "missing-tenant"}); len(got.Placements) != 0 {
		t.Fatalf("missing owner-ref page = %+v", got)
	}

	// Shard filter walks ownerRefIndex and skips IDs outside the requested shards.
	wantShard := PlacementShardForSandbox("own-aaa", DefaultPlacementShardCount)
	filtered := fsm.placementPage(PlacementPageRequest{
		Limit: 10, OwnerRef: "tenant-a",
		ShardFilter: PlacementShardFilter{Shards: []int{wantShard}, ShardCount: DefaultPlacementShardCount},
	})
	for _, p := range filtered.Placements {
		if PlacementShardForSandbox(p.SandboxID, DefaultPlacementShardCount) != wantShard {
			t.Fatalf("shard filter leaked %s", p.SandboxID)
		}
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snap.Release()

	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := placementRecoveryGCManifest{Snapshots: []placementRecoverySnapshotRefs{{CreatedUnix: 9, Refs: []string{"ref-a"}}}}
	if err := store.writeGCManifest(want); err != nil {
		t.Fatalf("writeGCManifest: %v", err)
	}
	got, err := store.readGCManifest()
	if err != nil || len(got.Snapshots) != 1 || got.Snapshots[0].CreatedUnix != 9 {
		t.Fatalf("readGCManifest = %+v err=%v", got, err)
	}
	payload, err := os.ReadFile(filepath.Join(store.dir, "snapshots.json"))
	if err != nil || !strings.Contains(string(payload), "ref-a") {
		t.Fatalf("manifest file = %s err=%v", payload, err)
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
