package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/memberlist"
)

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

func TestGossipAndVoterDelegateNoopMethods(t *testing.T) {
	d := &gossipDelegate{}
	d.NotifyMsg([]byte("x"))
	d.MergeRemoteState([]byte("x"), false)
	if got := d.GetBroadcasts(0, 0); got != nil {
		t.Fatalf("GetBroadcasts=%v", got)
	}
	if got := d.LocalState(false); got != nil {
		t.Fatalf("LocalState=%v", got)
	}

	v := &voterAutoJoinDelegate{}
	v.NotifyUpdate(nil)
}

func TestControlPlaneDiagnosticsHelpers(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Role: config.NodeRoleWorker, Alive: true})
	index.upsert(Member{NodeID: "dead-srv", Role: config.NodeRoleServer, Alive: false, APIURL: "http://x"})
	index.upsert(Member{NodeID: "ok-srv", Role: config.NodeRoleServer, Alive: true, APIURL: "http://ok"})
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

func TestRecoveryStoreHelpersAndErrors(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pathForRef(placementRecoveryRefPrefix + strings.Repeat("g", 64)); err == nil {
		t.Fatal("pathForRef should reject invalid hex")
	}

	// Force readGCManifest read error by making snapshots.json a directory.
	if err := os.MkdirAll(store.gcManifestPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readGCManifest(); err == nil {
		t.Fatal("readGCManifest should fail when manifest path is a directory")
	}

	refs := normalizeRecoveryRefs([]string{"", "a", "b", "a", "  ", "c"})
	if len(refs) != 3 || refs[0] != "a" || refs[1] != "b" || refs[2] != "c" {
		t.Fatalf("normalizeRecoveryRefs=%v", refs)
	}
	if isRecoveryBlobFilename("snapshots.json") {
		t.Fatal("manifest filename should not be considered a blob")
	}
	if isRecoveryBlobFilename(strings.Repeat("x", 64) + ".json") {
		t.Fatal("non-hex blob filename should be rejected")
	}

	rec := placementRecoveryStoreRecord{
		SandboxID: "sb-rec",
		Recovery:  placementRecovery{Spec: &models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"A": "1"}}},
	}
	blob := recoveryBlobFromRecord("ref-1", rec)
	if blob.SandboxID != "sb-rec" || blob.Ref != "ref-1" || blob.Spec == nil {
		t.Fatalf("blob=%+v", blob)
	}
	blob.Spec.Image = "mutated"
	blob.Spec.Env["A"] = "x"
	if rec.Recovery.Spec.Image != "alpine" || rec.Recovery.Spec.Env["A"] != "1" {
		t.Fatalf("record mutated via blob clone: %+v", rec.Recovery.Spec)
	}
}

func TestAgentVolumeMethodsAndQueryBranches(t *testing.T) {
	vols := map[string]models.Volume{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
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
	defer server.Close()

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "cp", APIURL: server.URL, Alive: true, Role: config.NodeRoleServer})
	a := &Agent{
		nodeID:     "worker",
		httpClient: server.Client(),
		gossip:     &gossipNode{memberIndex: index},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	if got := n.SecretsOf("sb-1"); got != (PlacementSecrets{}) {
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

func TestFSMSnapshotReleaseNoop(t *testing.T) {
	var snap fsmSnapshot
	snap.Release()
}

func TestGossipHelpersAdditionalBranches(t *testing.T) {
	var nilNode *gossipNode
	if got := nilNode.memberlistNodes(); got != nil {
		t.Fatalf("nil gossip node members=%v", got)
	}

	encodedServer, err := json.Marshal(nodeMeta{NodeID: "server-1", Role: config.NodeRoleServer, APIURL: "http://cp"})
	if err != nil {
		t.Fatal(err)
	}
	encodedWorker, err := json.Marshal(nodeMeta{NodeID: "worker-1", Role: config.NodeRoleWorker, APIURL: "http://w"})
	if err != nil {
		t.Fatal(err)
	}

	if hasLiveControlPlaneMember(nil, "") {
		t.Fatal("nil members should not report control-plane")
	}
	if hasLiveControlPlaneMember([]*memberlist.Node{{Name: "w", State: memberlist.StateAlive, Meta: encodedWorker}}, "") {
		t.Fatal("worker-only members should not report control-plane")
	}
	if !hasLiveControlPlaneMember([]*memberlist.Node{{Name: "s", State: memberlist.StateAlive, Meta: encodedServer}}, "") {
		t.Fatal("server with endpoint should report control-plane")
	}
	if hasLiveControlPlaneMember([]*memberlist.Node{{Name: "self", State: memberlist.StateAlive, Meta: encodedServer}}, "server-1") {
		t.Fatal("self control-plane member should be ignored")
	}

	joined := 0
	gn := &gossipNode{
		bootstrapPeers: []string{"127.0.0.1:7946"},
		joinBootstrapPeers: func(peers []string) (int, error) {
			joined++
			return len(peers), nil
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		delegate: &gossipDelegate{nodeID: "self"},
	}

	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{{Name: "self", State: memberlist.StateAlive, Meta: encodedWorker}})
	if joined != 1 {
		t.Fatalf("expected one bootstrap rejoin, got %d", joined)
	}
	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{{Name: "other", State: memberlist.StateAlive, Meta: encodedServer}})
	if joined != 1 {
		t.Fatalf("expected no extra rejoin when control-plane member alive, got %d", joined)
	}
}

func TestClusterWasmMigrateHTTPClientBranchesStep1(t *testing.T) {
	internalClient := &http.Client{Timeout: 100 * time.Millisecond}
	publicClient := &http.Client{Timeout: 100 * time.Millisecond}
	c := &Cluster{internalClient: internalClient, httpClient: publicClient}

	client, endpoint, err := c.wasmMigrateHTTPClient("https://internal", "https://public")
	if err != nil || client != internalClient || endpoint != "https://internal" {
		t.Fatalf("internal path client=%p endpoint=%q err=%v", client, endpoint, err)
	}

	client, endpoint, err = c.wasmMigrateHTTPClient("", "https://public")
	if err != nil || client != publicClient || endpoint != "https://public" {
		t.Fatalf("public fallback client=%p endpoint=%q err=%v", client, endpoint, err)
	}

	if _, _, err := c.wasmMigrateHTTPClient("", ""); err == nil {
		t.Fatal("expected error when both internal and public endpoints are empty")
	}
}

func TestAgentControlPlaneMembersAndPlacementCacheHelpers(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleServer, APIURL: "http://self"})
	index.upsert(Member{NodeID: "dead", Alive: false, Role: config.NodeRoleServer, APIURL: "http://dead"})
	index.upsert(Member{NodeID: "worker", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://worker"})
	index.upsert(Member{NodeID: "no-endpoint", Alive: true, Role: config.NodeRoleServer})
	index.upsert(Member{NodeID: "cp", Alive: true, Role: config.NodeRoleServer, APIURL: "http://cp"})

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

func TestGossipDelegateNodeMetaFallbacks(t *testing.T) {
	d := newGossipDelegate("node-a", "", "http://127.0.0.1:8080", "", "10.0.0.1:7001", "", config.NodeRoleServer, "", nil)
	if meta := d.NodeMeta(0); meta != nil {
		t.Fatalf("NodeMeta(0)=%q", string(meta))
	}
	if meta := d.NodeMeta(2); string(meta) != "{}" {
		t.Fatalf("NodeMeta tiny limit=%q", string(meta))
	}
	if meta := d.NodeMeta(memberlist.MetaMaxSize); len(meta) == 0 {
		t.Fatal("NodeMeta default limit should not be empty")
	}
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

func TestNoopVolumeQuotaAndAttachmentHelpers(t *testing.T) {
	n := NewNoop("node-a", "http://127.0.0.1:9000", "")
	ctx := context.Background()

	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v1", Tenant: "tq", Name: "n1", Backend: "s3"}, 1); err != nil {
		t.Fatalf("VolumeUpsert first err=%v", err)
	}
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v2", Tenant: "tq", Name: "n2", Backend: "s3"}, 1); !errors.Is(err, ErrVolumeQuotaExceeded) {
		t.Fatalf("VolumeUpsert quota err=%v", err)
	}

	n.volMu.Lock()
	n.ensureVolumeAttachmentMapsLocked()
	if got := n.volumeAttachmentCountLocked("", ""); got != 0 {
		n.volMu.Unlock()
		t.Fatalf("volumeAttachmentCountLocked empty=%d", got)
	}
	a := models.VolumeAttachment{Tenant: "tq", VolumeID: "v1", SandboxID: "sb-1", Target: "/data", Source: "s3://x"}
	n.putVolumeAttachmentLocked(a)
	if got := n.volumeAttachmentCountLocked("tq", "v1"); got != 1 {
		n.volMu.Unlock()
		t.Fatalf("volumeAttachmentCountLocked=%d", got)
	}
	key := volumeAttachmentKey(a.Tenant, a.VolumeID, a.SandboxID, a.Target)
	n.releaseVolumeAttachmentKeyLocked(key, a)
	if got := n.volumeAttachmentCountLocked("tq", "v1"); got != 0 {
		n.volMu.Unlock()
		t.Fatalf("volumeAttachmentCountLocked after release=%d", got)
	}
	n.releaseVolumeAttachmentsForSandboxLocked("")
	n.volMu.Unlock()
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
		index.upsert(Member{NodeID: fmt.Sprintf("cp-%d", i), Alive: true, Role: config.NodeRoleServer, APIURL: "http://cp"})
	}
	a := &Agent{nodeID: "self", gossip: &gossipNode{memberIndex: index}}
	_, _, _, _, _, _, _, _, visible = a.controlPlaneDiagnosticSnapshot()
	if len(visible) != 16 {
		t.Fatalf("visible len=%d want 16", len(visible))
	}
}

func TestControlPlaneMemberDiagnosticCandidateAndThrottlePath(t *testing.T) {
	diag := controlPlaneMemberDiagnostic(Member{NodeID: "cp-a", Alive: true, Role: config.NodeRoleServer, APIURL: "http://cp"}, "self")
	if !strings.Contains(diag, "candidate") {
		t.Fatalf("candidate diagnostic=%q", diag)
	}

	a := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.lastNoControlPlaneLogUnix.Store(time.Now().Unix())
	a.logNoControlPlaneMembers(http.MethodGet, "/v1/sandboxes", InternalAPIPath)
}
