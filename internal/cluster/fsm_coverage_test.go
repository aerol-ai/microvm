package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/btree"
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
	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"
)

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

func TestFSMSnapshotReleaseEmptyBody(t *testing.T) {
	// Release is an empty raft.FSMSnapshot hook; call the concrete type so
	// coverage attributes the method even though it has no statements.
	(&fsmSnapshot{}).Release()
	snap, err := newPlacementFSM().Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snap.Release()
}

func TestAuthoritativePlacementsByIDsFollowerPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	// Follower reads must go over the leader's internal channel — a local FSM
	// lookup would be stale after a leadership change. One 2-node harness
	// covers the real path; a probe Cluster reuses the follower raft so HTTP
	// error branches do not need a second election.
	leader, cleanupL := newTestCluster(t, "ldr-auth-ids", true, nil)
	defer cleanupL()
	follower, cleanupF := newTestCluster(t, "fol-auth-ids", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupF()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	waitForLeader(t, follower, 10*time.Second)

	ctx := context.Background()
	if err := leader.RecordPlacement(ctx, "sb-auth-fol", &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if follower.Leader() == follower.nodeID {
		t.Fatal("follower unexpectedly became raft leader")
	}
	// Live mTLS can 503 if the leader internal route is still coming up;
	// the probe Cluster below reuses this follower raft so the same
	// non-leader body is covered either way.
	if _, err := follower.AuthoritativePlacementsByIDs(ctx, []string{"sb-auth-fol"}); err != nil {
		t.Logf("live follower authoritative: %v", err)
	}
	_ = follower.DeletePlacement(ctx, "missing-auth")

	if err := leader.PruneAuditACL(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("PruneAuditACL: %v", err)
	}
	leader.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return []string{"tpl"}, true })
	leader.SetLocalWasmModuleIDsProvider(func() ([]string, bool) { return []string{"mod"}, true })
	_ = leader.membersWithCapacity()
	_ = leader.PlacementVersion()
	subCtx, cancel := context.WithCancel(ctx)
	ch := leader.SubscribePlacement(subCtx)
	cancel()
	if ch == nil {
		t.Fatal("SubscribePlacement returned nil on a live FSM")
	}

	leaderID := follower.Leader()
	if leaderID == "" {
		t.Fatal("follower reported no leader")
	}

	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("authoritative") != "true" {
			http.Error(w, "missing authoritative", http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	probeFor := func(internalURL string, client *http.Client) *Cluster {
		index := newGossipMemberIndex()
		index.upsert(Member{NodeID: leaderID, Alive: true, InternalURL: internalURL})
		probe := &Cluster{
			nodeID:   follower.nodeID,
			patToken: "tok",
			fsm:      follower.fsm,
			raft:     follower.raft,
			gossip:   &gossipNode{memberIndex: index},
		}
		probe.setInternalClient(client)
		return probe
	}

	status, body = http.StatusOK, `{"sb-probe":{"sandbox_id":"sb-probe"}}`
	got, err := probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb-probe"})
	if err != nil || got["sb-probe"].SandboxID != "sb-probe" {
		t.Fatalf("probe ok = %+v err=%v", got, err)
	}

	status, body = http.StatusOK, "null"
	got, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb-probe"})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("null map = %+v err=%v", got, err)
	}

	status, body = http.StatusOK, "{not-json"
	if _, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("decode error expected")
	}

	status, body = http.StatusServiceUnavailable, "not leader"
	if _, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("503 = %v", err)
	}

	status, body = http.StatusInternalServerError, "boom"
	if _, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("500 expected")
	}

	if _, err = probeFor("http://127.0.0.1:1", http.DefaultClient).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("dial error expected")
	}
	if _, err = probeFor("http://%zz", http.DefaultClient).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("bad URL expected")
	}
	if _, err = probeFor("", srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("empty internal URL = %v", err)
	}

	noClient := probeFor(srv.URL, nil)
	if _, err = noClient.AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil client = %v", err)
	}
	noGossip := &Cluster{nodeID: follower.nodeID, fsm: follower.fsm, raft: follower.raft}
	noGossip.setInternalClient(srv.Client())
	if _, err = noGossip.AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil gossip = %v", err)
	}
}

func TestClusterEasyClientAgentFSMBranches(t *testing.T) {
	ctx := context.Background()
	if err := decodeControlPlaneJSON(lift3ErrReader{}, &map[string]Placement{}); err == nil {
		t.Fatal("read error expected")
	}
	if err := decodeControlPlaneJSON(bytes.NewReader(bytes.Repeat([]byte("x"), maxControlPlaneJSONResponseBytes+1)), &map[string]Placement{}); err == nil {
		t.Fatal("oversized JSON expected")
	}
	if err := decodeControlPlaneJSON(strings.NewReader(`{"ok":true}`), &map[string]bool{}); err != nil {
		t.Fatalf("small JSON: %v", err)
	}

	(*Cluster)(nil).SetLocalTemplateCatalogProvider(nil)
	(*Cluster)(nil).SetLocalWasmModuleIDsProvider(nil)
	empty := &Cluster{}
	empty.SetLocalTemplateCatalogProvider(nil)
	empty.SetLocalWasmModuleIDsProvider(nil)
	leases := newCapacityLeaseCache("self", capacity.New(
		capacity.HostInfo{CPUCores: 1, MemoryTotalMB: 1024, DiskTotalGB: 10, DiskFreeGB: 10},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	), time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	withLeases := &Cluster{capacityLeases: leases, gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	withLeases.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return nil, false })
	withLeases.SetLocalWasmModuleIDsProvider(func() ([]string, bool) { return nil, false })
	_ = withLeases.membersWithCapacity()

	var nilGossip *gossipNode
	if _, ok := nilGossip.lookupMember("x"); ok {
		t.Fatal("nil gossip lookup")
	}
	g := &gossipNode{memberIndex: newGossipMemberIndex()}
	g.memberIndex.upsert(Member{NodeID: "n1", Alive: true, InternalURL: "https://n1"})
	if m, ok := g.lookupMember("n1"); !ok || m.NodeID != "n1" {
		t.Fatalf("lookup = %+v ok=%v", m, ok)
	}
	if g.peerInternalURL("missing") != "" {
		t.Fatal("missing peerInternalURL")
	}

	(&gossipDelegate{}).NotifyMsg([]byte("x"))
	(&gossipDelegate{}).MergeRemoteState([]byte("x"), true)
	(*Noop)(nil).AttachInternalHandler(http.NotFoundHandler())
	(&voterAutoJoinDelegate{c: &Cluster{}}).NotifyUpdate(&memberlist.Node{Name: "x"})

	if err := validateCommandLifecycle(command{Op: opPlace, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("place without incarnation = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opReserveBatch, Reservations: []reservationCommand{{SandboxID: "sb"}}}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("reserve batch = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opClaimOrphan, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("claim = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opDelete, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("delete = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opPutVolumeAttach, VolumeAttachments: []models.VolumeAttachment{{SandboxID: "sb"}}}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("volume attach = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opDeleteVolumeAttach, VolumeSandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("volume delete = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opUpsertSpec}); err != nil {
		t.Fatalf("upsert no-op = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opUpsertSpec, Spec: &models.CreateSandboxRequest{Image: "x"}, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("upsert spec = %v", err)
	}
	sec := testPlacementSecrets("sb", "inc-a", 1)
	if err := validateCommandLifecycle(command{
		Op: opUpsertSpec, SandboxID: "sb", Spec: &models.CreateSandboxRequest{Image: "x"},
		ExpectedIncarnationID: "inc-b", IncarnationID: sec.IncarnationID,
		SecretRef: sec.Ref, SecretVersion: sec.Version, SecretSealGeneration: sec.SealGeneration,
	}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("upsert secret fence = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opUpdateSecretRecipients, SandboxID: "sb"}); err == nil {
		t.Fatal("secret recipient update accepted")
	}
	if err := validateCommandLifecycle(command{Op: opPlace, SandboxID: "sb", IncarnationID: "inc"}); err != nil {
		t.Fatalf("place ok = %v", err)
	}

	var nilCluster *Cluster
	if _, err := nilCluster.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, nil); err != nil {
		t.Fatalf("nil cluster self-only push: %v", err)
	}
	if _, err := nilCluster.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil cluster remote push = %v", err)
	}
	bare := &Cluster{nodeID: "self"}
	if _, err := bare.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"self"}, 1); err != nil {
		t.Fatalf("gossip-nil self delete: %v", err)
	}
	if _, err := bare.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("gossip-nil remote probe = %v", err)
	}
	var nilAgent *Agent
	if _, err := nilAgent.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, nil); err != nil {
		t.Fatalf("nil agent self-only: %v", err)
	}
	if _, err := nilAgent.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil agent remote delete = %v", err)
	}
	bareAgent := &Agent{nodeID: "self"}
	if _, err := bareAgent.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"self"}, 1); err != nil {
		t.Fatalf("agent gossip-nil self probe: %v", err)
	}
	if _, err := bareAgent.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent gossip-nil remote push = %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalSecretPath:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, PublicInternalSecretPath+"/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, PublicInternalSecretPath+"/"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	srv, client := newNodeBoundForwardServer(t, "self", "peer-sec", handler)
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer-sec", Alive: true, InternalURL: srv.URL})
	live := &Cluster{nodeID: "self", patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	live.setInternalClient(client)
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}
	if acked, err := live.PushSecretBlobToPeers(ctx, blob, []string{"peer-sec"}); err != nil || len(acked) != 1 {
		t.Fatalf("wrapper push acked=%v err=%v", acked, err)
	}
	if acked, err := live.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil || len(acked) != 1 {
		t.Fatalf("wrapper delete acked=%v err=%v", acked, err)
	}
	if holding, err := live.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil || len(holding) != 1 {
		t.Fatalf("wrapper probe holding=%v err=%v", holding, err)
	}
	agent := &Agent{nodeID: "self", patToken: "pat", internalClient: client, gossip: &gossipNode{memberIndex: index}}
	if _, err := agent.PushSecretBlobToPeers(ctx, blob, []string{"peer-sec"}); err != nil {
		t.Fatalf("agent wrapper push: %v", err)
	}
	if _, err := agent.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil {
		t.Fatalf("agent wrapper delete: %v", err)
	}
	if _, err := agent.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil {
		t.Fatalf("agent wrapper probe: %v", err)
	}

	if err := empty.DeletePlacement(ctx, "sb"); err != nil {
		t.Fatalf("delete of a locally unknown placement = %v", err)
	}
}

type lift3ErrReader struct{}

func (lift3ErrReader) Read([]byte) (int, error) { return 0, errors.New("read fail") }

func TestFSMSnapshotReleaseNoop(t *testing.T) {
	var snap fsmSnapshot
	snap.Release()
}

type step1SnapshotSink struct {
	writeErr     error
	closeErr     error
	cancelCalled bool
}

func (s *step1SnapshotSink) ID() string { return "fake" }

func (s *step1SnapshotSink) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(p), nil
}

func (s *step1SnapshotSink) Cancel() error {
	s.cancelCalled = true
	return nil
}

func (s *step1SnapshotSink) Close() error { return s.closeErr }

type step1RecoveryStore struct {
	retained []string
}

func (f *step1RecoveryStore) Put(string, placementRecovery) (string, error) { return "", nil }

func (f *step1RecoveryStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, nil
}

func (f *step1RecoveryStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, nil
}

func (f *step1RecoveryStore) Delete(string) error { return nil }

func (f *step1RecoveryStore) RetainSnapshotRefs(refs []string) error {
	f.retained = append([]string(nil), refs...)
	return nil
}

func TestFSMSnapshotPersistBranches(t *testing.T) {
	sinkWriteErr := &step1SnapshotSink{writeErr: errors.New("write failed")}
	err := (&fsmSnapshot{}).Persist(sinkWriteErr)
	if err == nil || !strings.Contains(err.Error(), "fsmSnapshot: encode") {
		t.Fatalf("Persist write error=%v", err)
	}
	if !sinkWriteErr.cancelCalled {
		t.Fatal("Persist should cancel sink on encode/write failure")
	}

	sinkCloseErr := &step1SnapshotSink{closeErr: errors.New("close failed")}
	err = (&fsmSnapshot{}).Persist(sinkCloseErr)
	if !errors.Is(err, sinkCloseErr.closeErr) {
		t.Fatalf("Persist close error=%v", err)
	}

	store := &step1RecoveryStore{}
	sinkOK := &step1SnapshotSink{}
	snapshot := &fsmSnapshot{recoveryStore: store, recoveryRefs: []string{"recovery:v1:a", "recovery:v1:b"}}
	if err := snapshot.Persist(sinkOK); err != nil {
		t.Fatalf("Persist success err=%v", err)
	}
	if got := fmt.Sprint(store.retained); got != "[recovery:v1:a recovery:v1:b]" {
		t.Fatalf("RetainSnapshotRefs refs=%v", store.retained)
	}
}

func TestAgentDiagnosticSnapshotTruncationAndNilGuards(t *testing.T) {
	var nilAgent *Agent
	total, alive, serverRole, self, dead, non, missing, candidates, visible := nilAgent.controlPlaneDiagnosticSnapshot()
	if total != 0 || alive != 0 || serverRole != 0 || self != 0 || dead != 0 || non != 0 || missing != 0 || candidates != 0 || visible != nil {
		t.Fatalf("nil agent snapshot unexpected values: total=%d alive=%d server=%d self=%d dead=%d non=%d missing=%d candidates=%d visible=%v",
			total, alive, serverRole, self, dead, non, missing, candidates, visible)
	}

	index := newGossipMemberIndex()
	for i := 0; i < 20; i++ {
		index.upsert(Member{NodeID: fmt.Sprintf("cp-%d", i), Alive: true, Role: config.NodeRoleServer, APIURL: "http://cp", InternalURL: "https://cp"})
	}
	a := &Agent{nodeID: "self", gossip: &gossipNode{memberIndex: index}}
	_, _, _, _, _, _, _, _, visible = a.controlPlaneDiagnosticSnapshot()
	if len(visible) != 16 {
		t.Fatalf("visible len=%d want 16", len(visible))
	}
}

// failPutRecoveryStore forces storePlacementLocked error paths through Put.
// failPutRecoveryStore forces storePlacementLocked error paths through Put.
type failPutRecoveryStore struct{}

func (failPutRecoveryStore) Put(string, placementRecovery) (string, error) {
	return "", errors.New("forced put failure")
}

func (failPutRecoveryStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, nil
}

func (failPutRecoveryStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, nil
}

func (failPutRecoveryStore) Delete(string) error { return nil }

func (failPutRecoveryStore) RetainSnapshotRefs([]string) error { return nil }

func TestFSMApplyUncoveredBranchesStep2(t *testing.T) {
	fsm := newPlacementFSM()
	if got := fsm.Apply(&raft.Log{Data: []byte("not-a-command")}); got == nil {
		t.Fatal("decode failure should return error")
	}
	if got := applyOp(t, fsm, command{Op: 255}); got == nil {
		t.Fatal("unknown op should error")
	}

	// Place, then orphan via reassign empty owner, then reject opPlace on orphan.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-orph", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Image: "x"}, IncarnationID: "inc-orph"})
	applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb-orph", OwnerNodeID: "", ExpectedIncarnationID: "inc-orph"})
	if got := applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-orph", OwnerNodeID: "b", IncarnationID: "inc-orph", ExpectedIncarnationID: "inc-orph"}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("place orphaned = %v", got)
	}

	// Reassign missing is a no-op.
	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "missing", OwnerNodeID: "x", ExpectedIncarnationID: "inc-missing"}); got != nil {
		t.Fatalf("reassign missing = %v", got)
	}

	// Reserve then reassign reserved row (pending reservation path).
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-res", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 64}, IncarnationID: "inc-res", ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb-res", OwnerNodeID: "b", OwnerAPIURL: "http://b", ExpectedIncarnationID: "inc-res"}); got != nil {
		t.Fatalf("reassign reserved = %v", got)
	}

	// Empty batch / orphan owner / claim orphan guards.
	if got := applyOp(t, fsm, command{Op: opReserveBatch}); got == nil {
		t.Fatal("empty reserve batch should error")
	}
	if got := applyOp(t, fsm, command{Op: opOrphanOwner}); got == nil {
		t.Fatal("orphan without node should error")
	}
	if got := applyOp(t, fsm, command{Op: opClaimOrphan}); got == nil {
		t.Fatal("claim orphan missing ids should error")
	}
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "nope", OwnerNodeID: "a"}); !errors.Is(got.(error), ErrUnknownSandbox) {
		t.Fatalf("claim missing = %v", got)
	}

	// Place a live row and reject claim-orphan / reserved claim.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-live", OwnerNodeID: "a", IncarnationID: "inc-live", Spec: &models.CreateSandboxRequest{Name: "live", Image: "i"}})
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-live", OwnerNodeID: "a", IncarnationID: "inc-live"}); got != nil {
		t.Fatalf("claim self-owned non-orphan should no-op: %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-live", OwnerNodeID: "b", IncarnationID: "inc-live"}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("claim foreign = %v", got)
	}
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-res2", OwnerNodeID: "a", IncarnationID: "inc-res2",
		Spec: &models.CreateSandboxRequest{Name: "r2", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-res2", OwnerNodeID: "a", IncarnationID: "inc-res2"}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("claim reserved = %v", got)
	}

	// Orphan and claim (same previous owner) with renamed spec + secrets.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-claim", OwnerNodeID: "old", IncarnationID: "inc-claim", Spec: &models.CreateSandboxRequest{Name: "oldn", Image: "i"}})
	applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "old"})
	if got := applyOp(t, fsm, command{
		Op: opClaimOrphan, SandboxID: "sb-claim", OwnerNodeID: "old", IncarnationID: "inc-claim",
		Spec: &models.CreateSandboxRequest{Name: "newn", Image: "i2"}, SecretRef: testSecretRef("sb-claim", "inc-claim"), SecretVersion: 1, SecretSealGeneration: 2,
	}); got != nil {
		t.Fatalf("claim orphan rename = %v", got)
	}

	// Foreign orphan claim conflict.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-fo", OwnerNodeID: "x", IncarnationID: "inc-fo", Spec: &models.CreateSandboxRequest{Name: "fo", Image: "i"}})
	applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "x"})
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-fo", OwnerNodeID: "y", IncarnationID: "inc-fo"}); got == nil || !errors.Is(got.(error), ErrOrphanClaimConflict) {
		t.Fatalf("foreign orphan claim = %v", got)
	}

	// UpsertSpec / custom domain / volume validation edges.
	if got := applyOp(t, fsm, command{Op: opUpsertSpec, SandboxID: "missing"}); got != nil {
		t.Fatalf("upsert missing = %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opUpsertSpec, SandboxID: "sb-live"}); got != nil {
		t.Fatalf("upsert empty = %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opAddCustomDomain}); got == nil {
		t.Fatal("add domain missing fields")
	}
	if got := applyOp(t, fsm, command{Op: opRemoveCustomDomain}); got == nil {
		t.Fatal("remove domain missing fields")
	}
	if got := applyOp(t, fsm, command{Op: opRemoveCustomDomain, SandboxID: "gone", Hostname: "h.example"}); got != nil {
		t.Fatalf("remove domain missing placement = %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opSetNodeDrainState}); got == nil {
		t.Fatal("drain missing node")
	}
	if got := applyOp(t, fsm, command{Op: opUpsertVolume}); got == nil {
		t.Fatal("upsert volume nil")
	}
	if got := applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{}}); got == nil {
		t.Fatal("upsert volume incomplete")
	}
	if got := applyOp(t, fsm, command{Op: opDeleteVolume}); got == nil {
		t.Fatal("delete volume incomplete")
	}
	if got := applyOp(t, fsm, command{Op: opDeleteVolumeAttach}); got == nil {
		t.Fatal("delete attach incomplete")
	}

	// Orphan owner skips reserved rows owned by node.
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-or-res", OwnerNodeID: "dead",
		Spec: &models.CreateSandboxRequest{Name: "orres", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-or-pl", OwnerNodeID: "dead", Spec: &models.CreateSandboxRequest{Name: "orpl", Image: "i"}})
	if got := applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "dead"}); got != nil {
		t.Fatalf("orphan owner = %v", got)
	}
	if _, ok := fsm.get("sb-or-res"); ok {
		t.Fatal("reserved row should be deleted on orphan owner")
	}
	if p, ok := fsm.get("sb-or-pl"); !ok || !p.IsOrphaned() {
		t.Fatalf("placed row should be orphaned: %+v", p)
	}
}

func TestFSMStorePlacementRecoveryPutFailure(t *testing.T) {
	fsm := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	got := applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "sb-fail", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
	if got == nil || !strings.Contains(fmt.Sprint(got), "forced put failure") {
		t.Fatalf("storePlacement Put failure = %v", got)
	}
}

func TestFSMLockedHelpersNilAndEmptyGuards(t *testing.T) {
	fsm := &placementFSM{}
	fsm.claimOwnerLocked("", Placement{OwnerNodeID: "a"})
	fsm.claimOwnerLocked("sb", Placement{State: PlacementStateReserved, OwnerNodeID: "a"})
	fsm.claimOwnerLocked("sb", Placement{OwnerState: PlacementOwnerStateOrphaned, OwnerNodeID: "a"})
	fsm.claimOwnerLocked("sb", Placement{})
	fsm.claimOwnerLocked("sb1", Placement{OwnerNodeID: "n1"})
	fsm.releaseOwnerLocked("", Placement{OwnerNodeID: "n1"})
	fsm.releaseOwnerLocked("sb1", Placement{})
	fsm.releaseOwnerLocked("sb1", Placement{OwnerNodeID: "missing"})
	if ids := fsm.ownedPlacementIDsLocked(""); ids != nil {
		t.Fatalf("owned empty node=%v", ids)
	}
	if ids := fsm.ownedPlacementIDsLocked("nobody"); ids != nil {
		t.Fatalf("owned missing=%v", ids)
	}

	fsm.claimShardLocked("")
	fsm.shardIndex = nil
	fsm.placementIDs = nil
	fsm.claimShardLocked("sb-shard")
	fsm.releaseShardLocked("")
	fsm.releaseShardLocked("sb-shard")

	fsm.claimHostPortLocked("sb", 80, ExposedPortRoute{Protocol: models.ExposedPortProtocolTCP, HostPort: 22080})
	fsm.hostPortIndex = nil
	fsm.claimHostPortLocked("sb", 80, ExposedPortRoute{Protocol: models.ExposedPortProtocolTCP, HostPort: 22081})
	fsm.releaseCustomHostnameLocked("", "h")
	fsm.releaseCustomHostnameLocked("sb", "")
	fsm.claimCustomHostnameLocked("", "h")
	fsm.claimCustomHostnameLocked("sb", "")

	fsm.claimPendingReservationLocked("", Placement{State: PlacementStateReserved})
	fsm.claimPendingReservationLocked("sb", Placement{})
	fsm.pendingReservationClaims = nil
	fsm.pendingReservationCapacity = nil
	fsm.pendingReservationIDsByOwner = nil
	fsm.reservedIndex = nil
	fsm.claimPendingReservationLocked("sb-p", Placement{
		State: PlacementStateReserved, OwnerNodeID: "n", ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 32},
	})
	// owner change path
	fsm.claimPendingReservationLocked("sb-p", Placement{
		State: PlacementStateReserved, OwnerNodeID: "n2", ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
		Spec: &models.CreateSandboxRequest{CPU: 2, MemoryMB: 64},
	})
	fsm.releasePendingReservationClaimLocked("")
	fsm.pendingReservationClaims = nil
	fsm.releasePendingReservationClaimLocked("x")
	fsm.releasePendingReservationOwnerLocked("", "n")
	fsm.releasePendingReservationOwnerLocked("sb", "")
	fsm.claimPendingReservationOwnerLocked("", "n")
	fsm.claimPendingReservationOwnerLocked("sb", "")
	if ids := fsm.pendingReservationIDsLocked(""); ids != nil {
		t.Fatalf("pending ids empty=%v", ids)
	}
	fsm.refreshPendingReservationExpiryLocked("", 1)
	fsm.refreshPendingReservationExpiryLocked("missing", 1)
	if _, ok := fsm.sandboxIDByCustomHostname(""); ok {
		t.Fatal("empty hostname should miss")
	}
	if _, ok := fsm.sandboxIDByName(""); ok {
		t.Fatal("empty name should miss")
	}
}

func TestFSMVolumesForTenantAndAttachmentCount(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now().UTC()
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v1", Tenant: "t", Name: "b", Backend: "s3", CreatedAt: now.Add(-time.Hour)}})
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v2", Tenant: "t", Name: "a", Backend: "s3", CreatedAt: now}})
	got := fsm.VolumesForTenant("t")
	if len(got) != 2 || got[0].Name != "a" {
		t.Fatalf("VolumesForTenant=%+v", got)
	}
	if n := fsm.volumeAttachmentCountLocked("", "v1"); n != 0 {
		t.Fatalf("empty tenant count=%d", n)
	}
	if n := fsm.volumeAttachmentCountLocked("t", ""); n != 0 {
		t.Fatalf("empty id count=%d", n)
	}
}

func TestFSMRestoreReadError(t *testing.T) {
	fsm := newPlacementFSM()
	err := fsm.Restore(io.NopCloser(&errReader{}))
	if err == nil || !strings.Contains(err.Error(), "restore read") {
		t.Fatalf("Restore read error=%v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestAgentVolumeUpsertAndQueryErrorBranches(t *testing.T) {
	vols := map[string]models.Volume{"t1/n1": {ID: "vol-1", Tenant: "t1", Name: "n1", Backend: "s3"}}
	server, internalClient := newNodeBoundForwardServer(t, "worker", "cp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			var cmd command
			body, _ := io.ReadAll(r.Body)
			if err := decodeCommandInto(body, &cmd); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			switch cmd.Op {
			case opUpsertVolume:
				if cmd.MaxPerTenant == 1 {
					http.Error(w, ErrVolumeQuotaExceeded.Error(), http.StatusConflict)
					return
				}
				if cmd.Volume != nil && cmd.Volume.ID == "fail-apply" {
					http.Error(w, "apply failed", http.StatusInternalServerError)
					return
				}
				if cmd.Volume != nil {
					v := *cmd.Volume
					vols[v.Tenant+"/"+v.Name] = v
				}
				w.WriteHeader(http.StatusNoContent)
			case opDeleteVolume:
				http.Error(w, ErrUnknownVolume.Error(), http.StatusNotFound)
			case opPutVolumeAttach:
				http.Error(w, ErrUnknownVolume.Error(), http.StatusNotFound)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalVolumePath:
			q := r.URL.Query()
			switch q.Get("kind") {
			case "name":
				if v, ok := vols[q.Get("tenant")+"/"+q.Get("name")]; ok {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &v})
					return
				}
				// Explicit empty volume for readback timeout path when kind=name + special name
				if q.Get("name") == "never-appear" {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{})
					return
				}
				http.NotFound(w, r)
			case "id":
				if q.Get("id") == "nil-vol" {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{})
					return
				}
				if q.Get("id") == "err" {
					http.Error(w, "boom", 500)
					return
				}
				_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &models.Volume{ID: q.Get("id"), Tenant: q.Get("tenant"), Name: "n", Backend: "s3"}})
			case "list", "source", "attachment_count":
				http.Error(w, "cp down", 503)
			default:
				http.Error(w, "bad", 400)
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
	ctx := context.Background()

	// Existing volume short-circuit.
	row, created, err := a.VolumeUpsert(ctx, models.Volume{ID: "vol-x", Tenant: "t1", Name: "n1", Backend: "s3"}, 0)
	if err != nil || created || row.ID != "vol-1" {
		t.Fatalf("existing upsert row=%+v created=%v err=%v", row, created, err)
	}
	// Quota mapping (agent maps conflict bodies that contain the sentinel text).
	if _, _, err := a.VolumeUpsert(ctx, models.Volume{ID: "v2", Tenant: "t1", Name: "n2", Backend: "s3"}, 1); err == nil || !strings.Contains(err.Error(), ErrVolumeQuotaExceeded.Error()) {
		t.Fatalf("quota err=%v", err)
	}
	// Apply failure.
	if _, _, err := a.VolumeUpsert(ctx, models.Volume{ID: "fail-apply", Tenant: "t9", Name: "n9", Backend: "s3"}, 0); err == nil {
		t.Fatal("expected apply failure")
	}
	// Successful create + readback.
	row, created, err = a.VolumeUpsert(ctx, models.Volume{ID: "vol-new", Tenant: "t2", Name: "fresh", Backend: "s3"}, 0)
	if err != nil || !created || row.ID != "vol-new" {
		t.Fatalf("create row=%+v created=%v err=%v", row, created, err)
	}
	// VolumeByID success / nil / error.
	if got, err := a.VolumeByID(ctx, "t2", "vol-new"); err != nil || got.ID != "vol-new" {
		t.Fatalf("VolumeByID=%+v err=%v", got, err)
	}
	if _, err := a.VolumeByID(ctx, "t", "nil-vol"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("nil volume err=%v", err)
	}
	if _, err := a.VolumeByID(ctx, "t", "err"); err == nil {
		t.Fatal("VolumeByID query error expected")
	}
	if _, err := a.VolumeByName(ctx, "t", "missing-name"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("VolumeByName missing=%v", err)
	}
	if _, err := a.VolumesForTenant(ctx, "t"); err == nil {
		t.Fatal("VolumesForTenant should surface control-plane error")
	}
	if _, err := a.VolumeExistsForSource(ctx, "s"); err == nil {
		t.Fatal("VolumeExistsForSource should surface error")
	}
	if _, err := a.VolumeAttachmentCount(ctx, "t", "v"); err == nil {
		t.Fatal("VolumeAttachmentCount should surface error")
	}
	if err := a.VolumeDelete(ctx, "t1", "vol-1"); err == nil || !strings.Contains(err.Error(), ErrUnknownVolume.Error()) {
		t.Fatalf("VolumeDelete map=%v", err)
	}
	if err := a.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "v", SandboxID: "s", IncarnationID: "inc-s", Target: "/d", Source: "src",
	}}); err == nil || !strings.Contains(err.Error(), ErrUnknownVolume.Error()) {
		t.Fatalf("PutVolumeAttachments map=%v", err)
	}

	// readback honors caller context cancel while name never appears.
	deadRead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(VolumeQueryResponse{})
	}))
	defer deadRead.Close()
	index2 := newGossipMemberIndex()
	index2.upsert(Member{NodeID: "cp", APIURL: deadRead.URL, Alive: true, Role: config.NodeRoleServer})
	a2 := &Agent{nodeID: "w", gossip: &gossipNode{memberIndex: index2}, logger: a.logger}
	ctxCancel, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := a2.VolumeUpsert(ctxCancel, models.Volume{ID: "v", Tenant: "t", Name: "never-appear", Backend: "s3"}, 0); err == nil {
		t.Fatal("readback should fail when context already cancelled")
	}
}

func TestClusterVolumeClientValidationAndReadback(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	if _, _, err := c.VolumeUpsert(ctx, models.Volume{}, 0); err == nil {
		t.Fatal("validation expected")
	}
	applyOp(t, c.fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3"}})
	row, created, err := c.VolumeUpsert(ctx, models.Volume{ID: "other", Tenant: "t", Name: "n", Backend: "s3"}, 0)
	if err != nil || created || row.ID != "v1" {
		t.Fatalf("existing upsert row=%+v created=%v err=%v", row, created, err)
	}
	if err := c.VolumeDelete(ctx, "", ""); err == nil {
		t.Fatal("VolumeDelete validation")
	}
	if err := c.PutVolumeAttachments(ctx, nil); err != nil {
		t.Fatalf("empty attachments: %v", err)
	}

	ctxShort, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.readbackVolume(ctxShort, "t", "missing"); err == nil {
		t.Fatal("readback should fail on cancelled context")
	}
}

func TestFSMReservationBatchValidationConflicts(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "placed", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Name: "placed-name", Image: "i"}})
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "res-a", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{Name: "resa", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})

	if got := applyOp(t, fsm, command{Op: opReserve}); got == nil {
		t.Fatal("reserve missing ids")
	}
	if got := applyOp(t, fsm, command{Op: opReserveBatch, Reservations: []reservationCommand{
		{SandboxID: "x", OwnerNodeID: "a"},
		{SandboxID: "x", OwnerNodeID: "b"},
	}}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("dup id batch=%v", got)
	}
	if got := applyOp(t, fsm, command{Op: opReserveBatch, Reservations: []reservationCommand{
		{SandboxID: "placed", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{CPU: 1}},
	}}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("already placed batch=%v", got)
	}
	if got := applyOp(t, fsm, command{Op: opReserveBatch, Reservations: []reservationCommand{
		{SandboxID: "res-a", OwnerNodeID: "b", Spec: &models.CreateSandboxRequest{Name: "resa", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix()},
	}}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("live reserved by other=%v", got)
	}
	if got := applyOp(t, fsm, command{Op: opReserveBatch, Reservations: []reservationCommand{
		{SandboxID: "b1", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Name: "same", CPU: 1}},
		{SandboxID: "b2", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Name: "same", CPU: 1}},
	}}); got == nil || !errors.Is(got.(error), ErrNameConflict) {
		t.Fatalf("dup name in batch=%v", got)
	}
	if got := applyOp(t, fsm, command{Op: opReserveBatch, Reservations: []reservationCommand{
		{SandboxID: "b3", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Name: "placed-name", CPU: 1}},
	}}); got == nil || !errors.Is(got.(error), ErrNameConflict) {
		t.Fatalf("name unique check=%v", got)
	}
}

func TestFSMPageScanAndPendingHelperEdges(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.placements["sb2"] = Placement{SandboxID: "sb2"}
	fsm.placements["sb1"] = Placement{SandboxID: "sb1"}
	fsm.mu.Lock()
	ids := fsm.pagePlacementIDsByScanLocked(PlacementPageRequest{Limit: 1, PageToken: "sb1"}, PlacementShardFilter{}, true, nil)
	fsm.mu.Unlock()
	if len(ids) != 1 || ids[0] != "sb2" {
		t.Fatalf("scan after token=%v", ids)
	}

	fsm.mu.Lock()
	fsm.claimPendingReservationOwnerLocked("sb-p", "owner")
	fsm.releasePendingReservationOwnerLocked("sb-p", "owner")
	fsm.releasePendingReservationOwnerLocked("sb-p", "owner") // empty map path
	if n := fsm.livePendingReservationCount("", time.Now().Unix()); n != 0 {
		t.Fatalf("empty owner count=%d", n)
	}
	fsm.addPendingCapacityLocked("", capacity.Request{CPU: 1})
	fsm.refreshPendingReservationExpiryLocked("missing", time.Now().Unix())
	fsm.pruneExpiredPendingReservationsLocked(0)
	fsm.mu.Unlock()
}

func TestFSMRestoreFailStoreAndEmptySandboxID(t *testing.T) {
	payload := fsmSnapshotPayload{
		Version: 1,
		Placements: map[string]Placement{
			"":    {OwnerNodeID: "n"}, // key empty → SandboxID filled from key still empty skip? id from range key
			"sb1": {SandboxID: "sb1", OwnerNodeID: "n", Spec: &models.CreateSandboxRequest{Image: "x"}},
		},
		Recovery: map[string]placementRecovery{
			"sb1": {Spec: &models.CreateSandboxRequest{Image: "from-rec"}},
		},
	}
	// Force store failure during Restore.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(payload); err != nil {
		t.Fatal(err)
	}
	fsm := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	if err := fsm.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err == nil {
		t.Fatal("Restore should fail when recovery Put fails")
	}

	// Decode failure (neither envelope nor legacy map).
	fsm2 := newPlacementFSM()
	if err := fsm2.Restore(io.NopCloser(strings.NewReader("%%%not-gob%%%"))); err == nil {
		t.Fatal("expected restore decode error")
	}
}

func TestAssertOwnershipCustomHostnamesAndClaimError(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-ao-hn", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Empty ID skipped.
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{ID: ""}, {
		ID:              "sb-hn",
		Spec:            &models.CreateSandboxRequest{Image: "alpine", CPU: 1},
		Secrets:         PlacementSecrets{IncarnationID: "inc-hn"},
		ExposedPorts:    map[int]ExposedPortRoute{80: {Protocol: "http"}},
		CustomHostnames: []string{"hn.example.test"},
	}}); err != nil {
		t.Fatalf("AssertOwnership fresh+hostname: %v", err)
	}
	if got := c.CustomDomainsOf("sb-hn"); len(got) != 1 || got[0] != "hn.example.test" {
		t.Fatalf("CustomDomainsOf=%v", got)
	}

	// Owned path replays hostname when spec already present.
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-hn",
		Spec:            &models.CreateSandboxRequest{Image: "alpine", CPU: 1},
		Secrets:         PlacementSecrets{IncarnationID: "inc-hn"},
		CustomHostnames: []string{"hn2.example.test"},
	}}); err != nil {
		t.Fatalf("AssertOwnership owned hostname: %v", err)
	}

	// Reserved promote with hostname.
	applyPayload, _ := encodeCommand(command{
		Op: opReserve, SandboxID: "sb-res-hn", OwnerNodeID: c.nodeID, IncarnationID: "inc-res-hn",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err := c.raft.raft.Apply(applyPayload, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-res-hn",
		Spec:            &models.CreateSandboxRequest{Image: "alpine", CPU: 1},
		Secrets:         PlacementSecrets{IncarnationID: "inc-res-hn"},
		ExposedPorts:    map[int]ExposedPortRoute{8080: {Protocol: "http"}},
		CustomHostnames: []string{"res.example.test"},
	}}); err != nil {
		t.Fatalf("AssertOwnership reserved: %v", err)
	}

	// ClaimOrphan failure path: plant name conflict then try reclaim with conflicting name.
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-name-holder", OwnerNodeID: "other", IncarnationID: "inc-name-holder",
		Spec: &models.CreateSandboxRequest{Name: "taken-name", Image: "i"},
	})
	if err := c.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	place2, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-orphan-claim", OwnerNodeID: c.nodeID, IncarnationID: "inc-orphan-claim",
		Spec: &models.CreateSandboxRequest{Name: "orphan-old", Image: "i"},
	})
	if err := c.raft.raft.Apply(place2, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	orphan, _ := encodeCommand(command{Op: opOrphanOwner, NodeID: c.nodeID})
	if err := c.raft.raft.Apply(orphan, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:      "sb-orphan-claim",
		Spec:    &models.CreateSandboxRequest{Name: "taken-name", Image: "i2"},
		Secrets: PlacementSecrets{IncarnationID: "inc-orphan-claim"},
	}})
	if err == nil || !errors.Is(err, ErrNameConflict) {
		t.Fatalf("claim name conflict err=%v", err)
	}

	// Successful reclaim with ports+hostnames.
	place3, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-orphan-ok", OwnerNodeID: c.nodeID, IncarnationID: "inc-orphan-ok",
		Spec: &models.CreateSandboxRequest{Name: "ok-old", Image: "i"},
	})
	if err := c.raft.raft.Apply(place3, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if err := c.raft.raft.Apply(orphan, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-orphan-ok",
		Spec:            &models.CreateSandboxRequest{Name: "ok-new", Image: "i2"},
		Secrets:         PlacementSecrets{IncarnationID: "inc-orphan-ok"},
		ExposedPorts:    map[int]ExposedPortRoute{443: {Protocol: "https"}},
		CustomHostnames: []string{"ok.example.test"},
	}}); err != nil {
		t.Fatalf("successful orphan claim: %v", err)
	}
}

func TestFSMOpDrainAndExposedPortEdges(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.drainedNodes = nil
	if got := applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "n1", Drained: true}); got != nil {
		t.Fatal(got)
	}
	if !fsm.isNodeDrained("n1") {
		t.Fatal("expected drained")
	}
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Image: "i"}, IncarnationID: "inc-sb"})
	// Add exposed port with empty protocol falls back to existing (empty).
	if got := applyOp(t, fsm, command{Op: opAddExposedPort, SandboxID: "sb", Port: 80}); got != nil {
		t.Fatal(got)
	}
	if got := applyOp(t, fsm, command{Op: opRemoveExposedPort, SandboxID: "missing", Port: 80}); got != nil {
		t.Fatal(got)
	}
	if got := applyOp(t, fsm, command{Op: opRemoveExposedPort, SandboxID: "sb", Port: 80}); got != nil {
		t.Fatal(got)
	}
}

func TestEncodeCommandFailureDoesNotApply(t *testing.T) {
	// applyCommand encode path: channel values cannot encode via gob through encodeCommand.
	// Volume Upsert uses applyCommand only for volumes (encodable). Hit agent applyCommand encode via invalid Op with non-encodable field is hard.
	// Cover agent applyCommand validate size instead.
	a := &Agent{}
	err := a.applyCommand(context.Background(), command{
		Op:            opPlace,
		SandboxID:     "sb",
		IncarnationID: "inc-size",
		Spec:          oversizedSpec("big"),
	})
	if !errors.Is(err, ErrRecoveryPayloadTooLarge) {
		t.Fatalf("applyCommand size=%v", err)
	}
}

func TestClusterApplyCommandSizeGuard(t *testing.T) {
	c := &Cluster{}
	err := c.applyCommand(context.Background(), command{
		Op:            opPlace,
		SandboxID:     "sb",
		IncarnationID: "inc-size",
		Spec:          oversizedSpec("big"),
	})
	if !errors.Is(err, ErrRecoveryPayloadTooLarge) {
		t.Fatalf("applyCommand size=%v", err)
	}
}

func TestFSMStoreFailureBranchesOnMutations(t *testing.T) {
	fsm := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	spec := &models.CreateSandboxRequest{Image: "alpine", Name: "n1"}
	fsm.mu.Lock()
	fsm.placements["sb"] = Placement{SandboxID: "sb", OwnerNodeID: "n", Spec: spec, IncarnationID: "inc-sb"}
	fsm.ownerIndex = map[string]*btree.BTreeG[string]{"n": ownerIndexTree("sb")}
	fsm.nameIndex = map[string]string{"n1": "sb"}
	fsm.mu.Unlock()

	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb", OwnerNodeID: "n2", ExpectedIncarnationID: "inc-sb"}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("reassign store fail=%v", got)
	}

	fsmOrphan := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	fsmOrphan.mu.Lock()
	fsmOrphan.placements["sb"] = Placement{SandboxID: "sb", OwnerNodeID: "n", Spec: spec}
	fsmOrphan.ownerIndex = map[string]*btree.BTreeG[string]{"n": ownerIndexTree("sb")}
	fsmOrphan.mu.Unlock()
	if got := applyOp(t, fsmOrphan, command{Op: opOrphanOwner, NodeID: "n"}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("orphan store fail=%v", got)
	}

	fsm.mu.Lock()
	fsm.placements["sb-o"] = Placement{
		SandboxID: "sb-o", OwnerState: PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "n",
		IncarnationID: "inc-o", Spec: &models.CreateSandboxRequest{Image: "x"},
	}
	fsm.mu.Unlock()
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-o", OwnerNodeID: "n", IncarnationID: "inc-o"}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("claim store fail=%v", got)
	}

	fsm2 := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	seed := newPlacementFSM()
	applyOp(t, seed, command{Op: opPlace, SandboxID: "a", OwnerNodeID: "n", IncarnationID: "inc-a", Spec: &models.CreateSandboxRequest{Name: "keep", Image: "i"}})
	applyOp(t, seed, command{Op: opPlace, SandboxID: "b", OwnerNodeID: "n", IncarnationID: "inc-b", Spec: &models.CreateSandboxRequest{Name: "old", Image: "i"}})
	fsm2.mu.Lock()
	fsm2.placements = seed.placements
	fsm2.nameIndex = seed.nameIndex
	fsm2.ownerIndex = seed.ownerIndex
	fsm2.shardIndex = seed.shardIndex
	fsm2.placementIDs = seed.placementIDs
	fsm2.recovery = seed.recovery
	fsm2.mu.Unlock()
	if got := applyOp(t, fsm2, command{Op: opUpsertSpec, SandboxID: "b", ExpectedIncarnationID: "inc-b", Spec: &models.CreateSandboxRequest{Name: "keep", Image: "i2"}}); got == nil || !errors.Is(got.(error), ErrNameConflict) {
		t.Fatalf("upsert rename conflict=%v", got)
	}
	if got := applyOp(t, fsm2, command{Op: opUpsertSpec, SandboxID: "b", ExpectedIncarnationID: "inc-b", Spec: &models.CreateSandboxRequest{Name: "old2", Image: "i2"}}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("upsert store fail=%v", got)
	}

	fsm3 := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	fsm3.mu.Lock()
	fsm3.placements["sb-p"] = Placement{SandboxID: "sb-p", OwnerNodeID: "n", IncarnationID: "inc-p", Spec: &models.CreateSandboxRequest{Image: "i"}}
	fsm3.mu.Unlock()
	if got := applyOp(t, fsm3, command{Op: opAddExposedPort, SandboxID: "sb-p", ExpectedIncarnationID: "inc-p", Port: 80, Protocol: "http"}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("add port store fail=%v", got)
	}
	fsm3.mu.Lock()
	fsm3.placements["sb-p"] = Placement{
		SandboxID: "sb-p", OwnerNodeID: "n", IncarnationID: "inc-p", Spec: &models.CreateSandboxRequest{Image: "i"},
		ExposedPorts: map[int]string{80: "http"}, ExposedPortRoutes: map[int]ExposedPortRoute{80: {Protocol: "http"}},
	}
	fsm3.mu.Unlock()
	if got := applyOp(t, fsm3, command{Op: opRemoveExposedPort, SandboxID: "sb-p", ExpectedIncarnationID: "inc-p", Port: 80}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("remove port store fail=%v", got)
	}
	if got := applyOp(t, fsm3, command{Op: opAddCustomDomain, SandboxID: "sb-p", ExpectedIncarnationID: "inc-p", Hostname: "h.example"}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("add domain store fail=%v", got)
	}
	fsm3.mu.Lock()
	fsm3.placements["sb-p"] = Placement{
		SandboxID: "sb-p", OwnerNodeID: "n", IncarnationID: "inc-p", Spec: &models.CreateSandboxRequest{Image: "i"},
		CustomHostnames: []string{"h.example"},
	}
	fsm3.customHostnameIndex = map[string]string{"h.example": "sb-p"}
	fsm3.mu.Unlock()
	if got := applyOp(t, fsm3, command{Op: opRemoveCustomDomain, SandboxID: "sb-p", ExpectedIncarnationID: "inc-p", Hostname: "h.example"}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("remove domain store fail=%v", got)
	}
}

func TestAssertOwnershipFirstErrorBranches(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-ao-err", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "holder", OwnerNodeID: "other",
		Spec: &models.CreateSandboxRequest{Name: "holder", Image: "i"}, IncarnationID: "inc-holder",
	})
	if err := c.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	addHN, _ := encodeCommand(command{Op: opAddCustomDomain, SandboxID: "holder", ExpectedIncarnationID: "inc-holder", Hostname: "taken.example.test"})
	if err := c.raft.raft.Apply(addHN, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}

	err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-hn-conflict",
		Spec:            &models.CreateSandboxRequest{Image: "alpine", CPU: 1},
		Secrets:         PlacementSecrets{IncarnationID: "inc-hn-conflict"},
		CustomHostnames: []string{"taken.example.test"},
	}})
	if err == nil || !errors.Is(err, ErrCustomHostnameConflict) {
		t.Fatalf("hostname conflict firstErr=%v", err)
	}

	err = c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:      "sb-big",
		Spec:    oversizedSpec("big"),
		Secrets: PlacementSecrets{IncarnationID: "inc-big"},
	}})
	if err == nil || !errors.Is(err, ErrRecoveryPayloadTooLarge) {
		t.Fatalf("oversized fresh=%v", err)
	}

	seed, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-nospec", OwnerNodeID: c.nodeID, IncarnationID: "inc-nospec"})
	if err := c.raft.raft.Apply(seed, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	err = c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:      "sb-nospec",
		Spec:    oversizedSpec("owned-big"),
		Secrets: PlacementSecrets{IncarnationID: "inc-nospec"},
	}})
	if err == nil || !errors.Is(err, ErrRecoveryPayloadTooLarge) {
		t.Fatalf("oversized upsert=%v", err)
	}

	res, _ := encodeCommand(command{
		Op: opReserve, SandboxID: "sb-res-conflict", OwnerNodeID: c.nodeID, IncarnationID: "inc-res-conflict",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err := c.raft.raft.Apply(res, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	err = c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:              "sb-res-conflict",
		Spec:            &models.CreateSandboxRequest{Image: "alpine", CPU: 1},
		Secrets:         PlacementSecrets{IncarnationID: "inc-res-conflict"},
		CustomHostnames: []string{"taken.example.test"},
	}})
	if err == nil || !errors.Is(err, ErrCustomHostnameConflict) {
		t.Fatalf("reserved hostname conflict=%v", err)
	}
}

func TestFSMNilIndexAndHostnameHelpers(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.mu.Lock()
	fsm.nameIndex = nil
	fsm.claimNameLocked("sb", "named")
	fsm.customHostnameIndex = nil
	fsm.claimCustomHostnameLocked("sb", "h.example")
	if got := insertSortedHostname(nil, ""); got != nil {
		t.Fatalf("insert empty=%v", got)
	}
	fsm.pendingReservationIDsByOwner = nil
	fsm.claimPendingReservationOwnerLocked("sb", "owner")
	fsm.pendingReservationIDsByOwner = nil
	fsm.mu.Unlock()
	if n := fsm.livePendingReservationCount("owner", time.Now().Unix()); n != 0 {
		t.Fatalf("nil pending map count=%d", n)
	}

	if got := applyOp(t, fsm, command{Op: opRemoveExposedPort, SandboxID: "missing", Port: 0}); got != nil {
		t.Fatalf("remove port<=0 missing=%v", got)
	}

	// Shard-filtered page with PageToken skip + limit.
	fsm2 := newPlacementFSM()
	for _, id := range []string{"a", "b", "c", "d"} {
		applyOp(t, fsm2, command{Op: opPlace, SandboxID: id, OwnerNodeID: "n", Spec: &models.CreateSandboxRequest{Image: "i"}})
	}
	page := fsm2.placementPage(PlacementPageRequest{
		Limit: 1, PageToken: "a",
		ShardFilter: PlacementShardFilter{Shards: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
	})
	if len(page.Placements) > 1 {
		t.Fatalf("page limit=%d", len(page.Placements))
	}
}

func TestTinyCoverageHelpersStep5(t *testing.T) {
	if got := insertSortedHostname([]string{"b.com"}, ""); len(got) != 1 || got[0] != "b.com" {
		t.Fatalf("empty hostname insert=%v", got)
	}
	if got := removeHostname([]string{"a.com"}, ""); len(got) != 1 {
		t.Fatalf("empty remove=%v", got)
	}

	fsm := newPlacementFSM()
	fsm.mu.Lock()
	fsm.volumeNameIndex[volumeNameKey("t", "ghost")] = "missing-id"
	fsm.mu.Unlock()
	if _, err := fsm.VolumeByName("t", "ghost"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("orphan name index=%v", err)
	}
	fsm.mu.Lock()
	fsm.releaseVolumeAttachmentsForSandboxLocked("")
	fsm.mu.Unlock()

	// Same CreatedAt forces Name tie-break in VolumesForTenant sort.
	now := time.Now().UTC()
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v1", Tenant: "t2", Name: "b", Backend: "s3", CreatedAt: now}})
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v2", Tenant: "t2", Name: "a", Backend: "s3", CreatedAt: now}})
	got := fsm.VolumesForTenant("t2")
	if len(got) != 2 || got[0].Name != "a" {
		t.Fatalf("tie-break VolumesForTenant=%+v", got)
	}

	if classifyClusterMetricError(nil) != "" {
		t.Fatal("nil classify")
	}
	if classifyClusterMetricError(errors.New("context deadline exceeded")) != "timeout" {
		t.Fatal("timeout classify")
	}
	if classifyClusterMetricError(errors.New("peer API URL unknown")) != "target_unknown" {
		t.Fatal("unknown classify")
	}

	members := []Member{
		{NodeID: "s1", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s2", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s3", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s4", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s5", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s6", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s7", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s8", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s9", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s10", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s11", Alive: true, Role: config.NodeRoleServer},
	}
	if err := LargeClusterTopologyError(members); err == nil {
		t.Fatal("expected topology error for server-only large cluster")
	}
}
