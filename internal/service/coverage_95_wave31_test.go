package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestReconcileSecretDeleteOutboxRemainingBranches(t *testing.T) {
	ctx := context.Background()
	(*Service)(nil).reconcileSecretDeleteOutboxIncarnation(ctx, "sb", "inc")
	(*Service)(nil).reconcileSecretDeleteOutboxRecord(ctx, nil, nil)
	(&Service{}).reconcileSecretDeleteOutboxRecord(ctx, &storepkg.SecretDeleteOutboxRecord{SandboxID: "sb"}, nil)
	if err := (*Service)(nil).ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}

	st := openSealTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &Service{store: st, logger: logger, cluster: cluster.NewNoop("node-a", "http://a", "")}

	staged := &storepkg.SecretDeleteOutboxRecord{
		SandboxID: "sb-stage31", IncarnationID: "inc-a", Recipients: []string{"node-b"},
		Generation: 2, AwaitingPromotion: true,
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, staged, nil)
	svc.reconcileSecretDeleteOutboxRecord(ctx, staged, map[string]cluster.Placement{
		"sb-stage31": {SandboxID: "sb-stage31", IncarnationID: "inc-a", SecretSealGeneration: 1},
	})

	retired := []string{"node-b"}
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-retire31", "inc-a", secrets.RefVersion),
		SandboxID: "sb-retire31", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-c"}, RetireRecipients: &retired,
		SealedPayload: []byte("sealed"), SealGeneration: 2,
	}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-retire31", "inc-a")
	if err != nil || rec == nil || !rec.AwaitingPromotion {
		t.Fatalf("staged retire = %+v err=%v", rec, err)
	}
	svc.cluster = &wave30AuthCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placements: map[string]cluster.Placement{
			"sb-retire31": {SandboxID: "sb-retire31", IncarnationID: "inc-a", SecretSealGeneration: 2},
		},
	}
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("peer delete down")}
	svc.reconcileSecretDeleteOutboxIncarnation(nil, "sb-retire31", "inc-a")

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-selfdel31", "inc-a", []string{"node-a"}, 1); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-selfdel31", "inc-a")

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-nopush31", "inc-a", []string{"node-b"}, 1); err != nil {
		t.Fatal(err)
	}
	svc.testSecretPeerPusher = nil
	svc.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-nopush31", "inc-a")

	closed := openSealTestStore(t)
	if err := closed.UpsertSecretDeleteOutbox(ctx, "sb-closed-del", "inc-a", []string{"node-b"}, 1); err != nil {
		t.Fatal(err)
	}
	closedSvc := &Service{
		store: closed, logger: logger, cluster: cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"node-b"}},
	}
	_ = closed.Close()
	closedSvc.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-closed-del", "inc-a")
	if err := closedSvc.ReconcileSecretDeleteOutbox(ctx); err == nil {
		t.Fatal("closed-store delete reconcile succeeded")
	}
}

func TestRefreshHolderPossessionEnableClusterCleanup(t *testing.T) {
	st := openSealTestStore(t)
	cl := &placementOnlyCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-hold31", OwnerNodeID: "node-a", IncarnationID: "inc-new",
			State: cluster.PlacementStateDeleting, SecretSealGeneration: 1,
			SecretRecipients: []string{"node-a", "node-b"},
		},
	}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st, cluster: cl,
		testSecretPeerPusher: &fakePeerPusher{probeErr: errors.New("probe down")},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	addSecretHolderNodes("sb-hold31", "inc-old", 2, "node-dead")
	addSecretHolderNodes("sb-hold31", "inc-new", 2, "node-b")
	hs := holderSetFor("sb-hold31", "inc-new")
	hs.mu.Lock()
	hs.nodes["node-b"] = time.Now().Add(-secretHolderACKTTL)
	hs.targets["node-b"] = struct{}{}
	hs.lastExpand = time.Time{}
	hs.mu.Unlock()
	svc.refreshSecretHolderPossession(context.Background())
	secretFanoutHolders.Delete(secretHolderKey{sandboxID: "sb-hold31", incarnationID: "inc-old"})
	secretFanoutHolders.Delete(secretHolderKey{sandboxID: "sb-hold31", incarnationID: "inc-new"})

	cl.placement.State = cluster.PlacementStatePlaced
	cl.placement.SecretSealGeneration = 1
	putSecretRow(t, st, "sb-hold31", "inc-new", 1, []string{"node-a", "node-b"})
	addSecretHolderNodes("sb-hold31", "inc-new", 1, "node-b")
	hs = holderSetFor("sb-hold31", "inc-new")
	hs.mu.Lock()
	hs.nodes["node-b"] = time.Now().Add(-secretHolderACKTTL)
	hs.targets["node-b"] = struct{}{}
	hs.mu.Unlock()
	svc.cluster = &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")}
	svc.refreshSecretHolderPossession(nil)
	secretFanoutHolders.Delete(secretHolderKey{sandboxID: "sb-hold31", incarnationID: "inc-new"})
}

func TestOpenClusterSecretsRemainingGuards(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "alpine", Registry: &models.RegistryAuth{Server: "ghcr.io", Username: "u"}}
	out, err := (*Service)(nil).OpenClusterSecretsForNode(ctx, "sb", req, cluster.PlacementSecrets{}, "node-a")
	if err != nil || out.Image != "alpine" {
		t.Fatalf("empty handle = %+v %v", out, err)
	}

	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{store: st, cipher: cipher, secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st))}
	bad := cluster.PlacementSecrets{Ref: "not-a-ref", Version: secrets.RefVersion, SealGeneration: 1, IncarnationID: "inc-a"}
	if _, err := svc.OpenClusterSecretsForNode(ctx, "sb", req, bad, ""); err == nil {
		t.Fatal("invalid handle was accepted")
	}

	ref := secrets.FormatRef("sb-open31", "inc-a", secrets.RefVersion)
	handle := cluster.PlacementSecrets{Ref: ref, Version: secrets.RefVersion, SealGeneration: 1, IncarnationID: "inc-a"}
	if _, err := (&Service{store: st}).OpenClusterSecretsForNode(ctx, "", req, handle, "node-a"); err == nil {
		t.Fatal("nil provider was accepted")
	}
	if _, err := svc.OpenClusterSecretsForNode(ctx, "sb-open31", req, handle, "node-a"); err == nil {
		t.Fatal("missing blob open succeeded")
	}

	blob := wave30BoundBlob(t, cipher, "sb-open31", "inc-a", []string{"node-a"}, 1)
	if err := newSecretBlobStore(st).Put(ctx, blob); err != nil {
		t.Fatal(err)
	}
	got, err := svc.OpenClusterSecretsForNode(ctx, "", req, handle, "node-a")
	if err != nil {
		t.Fatalf("open by ref: %v", err)
	}
	if got.Registry == nil || got.Registry.Password != "p" {
		t.Fatalf("merged secrets = %+v", got.Registry)
	}
}

func TestFailoverReadyRemainingBranches(t *testing.T) {
	ctx := context.Background()
	if (*Service)(nil).computeFailoverReady(ctx, nil) != nil {
		t.Fatal("nil sandbox ready")
	}
	(*Service)(nil).attachFailoverReady(ctx, nil)
	(&Service{}).failoverReadyBatch(ctx, nil)
	(&Service{}).failoverReadyBatch(ctx, []*models.Sandbox{nil, {}})

	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-ready31", "inc-a", 1, []string{"node-a", "node-b"})
	cl := &stubMembersCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: true},
		},
		placement: cluster.Placement{
			SandboxID: "sb-ready31", OwnerNodeID: "node-a", IncarnationID: "inc-a",
			SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
		},
	}
	svc := &Service{store: st, cluster: cl}
	addSecretHolderNodes("sb-ready31", "inc-a", 1, "node-a", "node-b")
	t.Cleanup(func() { clearSecretFanoutHolders("sb-ready31") })
	sb := &models.Sandbox{
		ID: "sb-ready31", AuditIncarnationID: "inc-a",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	svc.attachFailoverReady(ctx, sb)
	if sb.FailoverReady == nil || !*sb.FailoverReady {
		t.Fatalf("local+peer ready = %v", sb.FailoverReady)
	}
	svc.attachFailoverReadyAll(ctx, []*models.Sandbox{nil, sb})
	if ready := svc.computeFailoverReadyRow(sb, &failoverReadyInputs{placements: nil, seals: map[string]storepkg.ClusterSecretSealSummary{}}); ready == nil || *ready {
		t.Fatalf("nil placement snapshot must fail closed, got %v", ready)
	}
	if ready := svc.computeFailoverReadyRow(sb, &failoverReadyInputs{placements: map[string]cluster.Placement{}, seals: nil}); ready == nil || *ready {
		t.Fatalf("failed sealed-row read must fail closed, got %v", ready)
	}
	if svc.computeFailoverReadyRow(&models.Sandbox{ID: "plain"}, &failoverReadyInputs{}) != nil {
		t.Fatal("non-recreate row must be omitted")
	}
	single := &models.Sandbox{ID: "solo", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	in := &failoverReadyInputs{
		selfID:      "node-a",
		alive:       map[string]struct{}{"node-a": {}, "node-b": {}},
		placements:  map[string]cluster.Placement{},
		incarnation: map[string]string{"solo": ""},
		seals:       map[string]storepkg.ClusterSecretSealSummary{},
	}
	if ready := svc.computeFailoverReadyRow(single, in); ready == nil || !*ready {
		t.Fatalf("single-recipient ready = %v", ready)
	}
}

func TestShipAndExportAuditRemainingGuards(t *testing.T) {
	if err := (*Service)(nil).shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	(*Service)(nil).stopSecretAuditWitnessLoop()
	(*Service)(nil).ConfigureHTTPAuditExporter()
	(&Service{}).ConfigureHTTPAuditExporter()
	if n, err := (*Service)(nil).exportSecretAuditBatchOnce(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil export = %d %v", n, err)
	}
	if err := (*Service)(nil).drainSecretAuditExport(context.Background()); err != nil {
		t.Fatal(err)
	}

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatalf("no witness: %v", err)
	}
	if err := svc.exportSecretAuditBatch(context.Background()); err != nil {
		t.Fatalf("no exporter: %v", err)
	}

	w := &stubWitness{shipErr: errors.New("witness down")}
	svc.SetWitness(w)
	sink := svc.secretAuditSink().(*fileAuditSink)
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "ship-fail", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := svc.shipSecretAuditHead(context.Background()); err == nil {
		t.Fatal("ship error was swallowed")
	}
	w.shipErr = nil
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatalf("already-witnessed ship: %v", err)
	}

	svc.cfg.SecretAuditExportURL = "http://127.0.0.1:1/export"
	svc.cfg.SecretAuditExportBearerToken = "tok"
	svc.ConfigureHTTPAuditExporter()
	if svc.getAuditExporter() == nil {
		t.Fatal("HTTP exporter was not installed")
	}

	cursorPath := filepath.Join(t.TempDir(), "cursor.json")
	if err := os.WriteFile(cursorPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadAuditExportCursor(cursorPath); got.Generation != "" {
		t.Fatalf("malformed cursor = %+v", got)
	}
	if err := persistAuditExportCursor(filepath.Join(t.TempDir(), "ok.json"), auditExportCursor{Generation: "g", Offset: 1, Head: "h"}); err != nil {
		t.Fatal(err)
	}
	if gen, err := auditFileGeneration(nil); err == nil || gen != "" {
		t.Fatalf("nil generation = %q %v", gen, err)
	}

	ok, _, _, err := (*Service)(nil).VerifySecretAuditWitness()
	if err != nil || !ok {
		t.Fatalf("nil verify = %v %v", ok, err)
	}
	if err := (*Service)(nil).ValidateSecretAuditWitness(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteClusterSecretsAndRecipientsWave31(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{store: st, cluster: cluster.NewNoop("node-a", "http://a", ""), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	putSecretRow(t, st, "sb-del31", "inc-a", 1, []string{"node-a", "node-b"})
	if err := svc.DeleteClusterSecrets(ctx, "sb-del31", "inc-a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb-del31", "inc-a", 2); err != nil {
		t.Fatal(err)
	}

	if err := st.UpsertSecretPutOutbox(ctx, "sb-putdel31", "inc-a", 1, []string{"node-b", "node-c"}); err != nil {
		t.Fatal(err)
	}
	recips, err := svc.secretRecipientsForDelete(ctx, "sb-putdel31", "inc-a")
	if err != nil || !sameStringSlice(recips, []string{"node-b", "node-c"}) {
		t.Fatalf("put-outbox recipients = %v %v", recips, err)
	}

	svc.cfg.EnableCluster = true
	svc.cluster = &wave30AuthCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placements: map[string]cluster.Placement{
			"sb-place-del31": {SandboxID: "sb-place-del31", IncarnationID: "inc-a", SecretRecipients: []string{"node-a", "node-d"}},
		},
	}
	recips, err = svc.secretRecipientsForDelete(ctx, "sb-place-del31", "inc-a")
	if err != nil || !sameStringSlice(recips, []string{"node-a", "node-d"}) {
		t.Fatalf("placement recipients = %v %v", recips, err)
	}
	if recips, err = svc.secretRecipientsForDelete(ctx, "sb-place-del31", "inc-other"); recips != nil || err != nil {
		t.Fatalf("other incarnation = %v %v", recips, err)
	}

	svc.maybeAsyncDeleteFanout("sb-del31", "inc-a")
	svc.maybeAsyncDeleteFanout("sb-del31", "inc-a")
}

func TestReplicateSpecPatchAndAliveMembers(t *testing.T) {
	ctx := context.Background()
	(&Service{}).replicateSpecPatch(ctx, "sb", func(*models.CreateSandboxRequest) {})
	svc := &Service{cluster: cluster.NewNoop("self", "http://self", "")}
	svc.replicateSpecPatch(ctx, "missing", func(*models.CreateSandboxRequest) {})

	if got := (*Service)(nil).aliveMemberSet(); len(got) != 0 {
		t.Fatalf("nil alive = %v", got)
	}
	if got := (&Service{}).aliveMemberSet(); len(got) != 0 {
		t.Fatalf("detached alive = %v", got)
	}
	cl := &stubMembersCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		members: []cluster.Member{
			{NodeID: "self", Alive: true},
			{NodeID: "peer", Alive: true},
			{NodeID: "dead", Alive: false},
			{NodeID: "", Alive: true},
		},
	}
	got := (&Service{cluster: cl}).aliveMemberSet()
	if _, ok := got["peer"]; !ok {
		t.Fatalf("alive set = %v", got)
	}
	if _, ok := got["dead"]; ok {
		t.Fatal("dead member counted alive")
	}

	raw, _ := json.Marshal(SecretAuditEvent{EventID: "unused"})
	_ = raw
}

func TestPutOutboxRecordClosedStoreAndInvalidPersist(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-rec31", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-rec31", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-rec31", "inc-a")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	svc := &Service{
		store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster: cluster.NewNoop("node-a", "http://a", ""), testSecretPeerPusher: &fakePeerPusher{},
	}
	_ = st.Close()
	svc.reconcileSecretPutOutboxRecord(ctx, rec, nil)
	if err := svc.persistSecretPutOutboxRecipients(ctx, "sb-rec31", "inc-a", []string{"node-b"}, 1); err == nil {
		t.Fatal("closed persist succeeded")
	}
	svc.reconcileSecretPutOutboxIncarnationWithPlacements(ctx, "sb-rec31", "inc-a", map[string]cluster.Placement{})
}

func TestListSandboxesWithOptionsEnvAndTags(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := testEnvService(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-list31", Image: "alpine", Status: models.SandboxStatusStarted,
		Tags: map[string]string{"env": "prod"}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	sealed, err := svc.sealEnv(map[string]string{"K": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-list31", sealed); err != nil {
		t.Fatal(err)
	}
	listed, err := svc.ListSandboxesWithOptions(ctx, map[string]string{"env": "prod"}, GetSandboxOptions{IncludeEnv: true})
	if err != nil || len(listed) != 1 || listed[0].Env["K"] != "v" {
		t.Fatalf("tagged include-env = %+v err=%v", listed, err)
	}
	if _, err := svc.ListSandboxesWithOptions(ctx, map[string]string{"env": "dev"}, GetSandboxOptions{}); err != nil {
		t.Fatal(err)
	}
	svc.cipher = nil
	if _, err := svc.ListSandboxesWithOptions(ctx, nil, GetSandboxOptions{IncludeEnv: true}); err == nil {
		t.Fatal("include-env without cipher succeeded")
	}
	if _, err := svc.ListSandboxesWithOptions(ctx, map[string]string{"env": "prod"}, GetSandboxOptions{IncludeEnv: true}); err == nil {
		t.Fatal("tagged include-env without cipher succeeded")
	}

	closed, err := storepkg.Open(filepath.Join(t.TempDir(), "list31.db"))
	if err != nil {
		t.Fatal(err)
	}
	closedSvc := &Service{store: closed}
	_ = closed.Close()
	if _, err := closedSvc.ListSandboxesWithOptions(ctx, nil, GetSandboxOptions{}); err == nil {
		t.Fatal("closed list succeeded")
	}
}

func TestBeginSelfOwnedClusterPlacementDeleteStrict(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).beginSelfOwnedClusterPlacementDeleteStrict(ctx, nil); err != nil {
		t.Fatal(err)
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	sb := wave30SeedSandbox(t, st, "sb-begin31", "inc-local")
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err != nil {
		t.Fatal(err)
	}
	svc.cfg.EnableCluster = true
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("nil cluster = %v", err)
	}
	blank := *sb
	blank.AuditIncarnationID = ""
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	svc.AttachCluster(cl)
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, &blank); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("blank incarnation = %v", err)
	}
	cl.err = errors.New("raft down")
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("lookup = %v", err)
	}
	cl.err = nil
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err != nil {
		t.Fatalf("missing placement = %v", err)
	}
	cl.placements = map[string]cluster.Placement{
		"sb-begin31": {SandboxID: "sb-begin31", OwnerNodeID: "other", IncarnationID: "inc-local"},
	}
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "ownership changed") {
		t.Fatalf("foreign owner = %v", err)
	}
	cl.placements["sb-begin31"] = cluster.Placement{SandboxID: "sb-begin31", OwnerNodeID: "self", IncarnationID: "inc-local"}
	cl.deleteErr = errors.New("cas lost")
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "begin authoritative") {
		t.Fatalf("begin fail = %v", err)
	}
	cl.deleteErr = nil
	if err := svc.beginSelfOwnedClusterPlacementDeleteStrict(ctx, sb); err != nil {
		t.Fatalf("begin: %v", err)
	}
}

func TestSecretBlobStoreAdapterGuards(t *testing.T) {
	ctx := context.Background()
	if newSecretBlobStore(nil) != nil {
		t.Fatal("nil store adapter")
	}
	st := openSealTestStore(t)
	a := newSecretBlobStore(st).(secretBlobStoreAdapter)
	if err := a.Put(ctx, secrets.SecretBlob{Ref: "bad", SandboxID: "sb", IncarnationID: "inc", Version: 1, SealGeneration: 1}); err == nil {
		t.Fatal("invalid put identity")
	}
	if _, err := a.Get(ctx, secrets.FormatRef("missing", "inc", secrets.RefVersion)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing get = %v", err)
	}
	if err := a.DeleteForSandbox(ctx, "sb"); err == nil {
		t.Fatal("delete without incarnation")
	}
	if _, err := a.NextSealGeneration(ctx, "sb"); err == nil {
		t.Fatal("next gen without incarnation")
	}
	inc := secrets.ContextWithIncarnationID(ctx, "inc-a")
	if err := a.DeleteForSandbox(inc, "missing"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	gen, err := a.NextSealGeneration(inc, "sb-next31")
	if err != nil || gen < 1 {
		t.Fatalf("next gen = %d %v", gen, err)
	}
	_ = st.Close()
	if _, err := a.Get(ctx, secrets.FormatRef("sb", "inc", secrets.RefVersion)); err == nil {
		t.Fatal("closed get succeeded")
	}
}

func TestExpandResealGuardsAndHolderTargets(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).expandAndResealDeadSecretTargets(ctx, ""); err != nil {
		t.Fatal(err)
	}
	svc := &Service{}
	if err := svc.expandAndResealDeadSecretTargets(ctx, "sb"); err != nil {
		t.Fatal(err)
	}
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")}
	svc.cluster = cl
	if err := svc.expandAndResealDeadSecretTargets(ctx, "sb-exp31"); err == nil {
		t.Fatal("placement read failure swallowed")
	}
	cl.err = nil
	svc.cfg.EnableCluster = true
	if err := svc.expandAndResealDeadSecretTargets(ctx, "sb-exp31"); err != nil {
		t.Fatalf("missing placement: %v", err)
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, cluster.Placement{}); err == nil {
		t.Fatal("blank placement identity")
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, cluster.Placement{
		SandboxID: "sb-exp31", IncarnationID: "inc-a", State: cluster.PlacementStateDeleting,
	}); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, cluster.Placement{
		SandboxID: "sb-exp31", IncarnationID: "inc-a", OwnerNodeID: "other",
	}); err != nil {
		t.Fatalf("non-owner: %v", err)
	}

	setSecretHolderTargets("", "inc", 1, []string{"n"})
	setSecretHolderTargets("sb-tgt31", "inc-a", 1, []string{"node-a", "", "node-b"})
	setSecretHolderTargets("sb-tgt31", "inc-a", 3, []string{"node-c"})
	setSecretHolderTargets("sb-tgt31", "inc-a", 2, []string{"node-d"})
	secretFanoutHolders.Delete(secretHolderKey{sandboxID: "sb-tgt31", incarnationID: "inc-a"})
}

func TestValidateSinkStrictAndSpillOverflow(t *testing.T) {
	if err := (*Service)(nil).ValidateSecretAuditSink(); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), SecretAuditStrictBoot: true}}
	t.Cleanup(svc.CloseSecretAuditSink)
	if err := svc.ValidateSecretAuditSink(); err != nil {
		t.Fatalf("fresh strict sink: %v", err)
	}
	svc.secretAuditInitErr = errors.New("init failed")
	if err := svc.ValidateSecretAuditSink(); err == nil || !strings.Contains(err.Error(), "initialize") {
		t.Fatalf("strict init = %v", err)
	}

	sink, err := newFileAuditSinkOpts(t.TempDir(), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	block := make(chan struct{})
	sink.writeHook = func() { <-block }
	done := make(chan error, 1)
	go func() {
		done <- sink.EmitDurable(SecretAuditEvent{EventID: "block", Result: secretAuditResultSuccess})
	}()
	time.Sleep(50 * time.Millisecond)
	for i := range 8 {
		sink.Emit(SecretAuditEvent{EventID: "overflow-" + string(rune('a'+i)), Result: secretAuditResultSuccess})
	}
	close(block)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked durable emit did not finish")
	}

	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistWitnessReceipt("", filepath.Join(blocked, "tip.json"), witnessReceiptRecord{HeadHex: "h"}); err == nil {
		t.Fatal("witness tip under a file succeeded")
	}
}

func TestFinalizeDestroyFailAndMissingPlacements(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{destroyErr: errors.New("docker destroy failed")}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	sb := wave30SeedSandbox(t, st, "sb-fin31", "inc-old")
	if err := svc.finalizeStaleLocalSandbox(ctx, sb, cluster.Placement{
		SandboxID: "sb-fin31", OwnerNodeID: "other", IncarnationID: "inc-new",
	}, false); err == nil {
		t.Fatal("destroy failure was swallowed")
	}

	cl := &wave30AuthCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-ghost31": {SandboxID: "sb-ghost31", OwnerNodeID: "self", IncarnationID: "inc-g"},
			"":           {OwnerNodeID: "self"},
			"sb-skip31":  {SandboxID: "sb-skip31", OwnerNodeID: "self", State: cluster.PlacementStateReserved},
		},
	}
	svc.AttachCluster(cl)
	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{"sb-skip31": {}})
	empty := &Service{cfg: config.Config{EnableCluster: true}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	empty.reconcileMissingSelfOwnedPlacements(ctx, nil)
	empty.AttachCluster(&emptySelfCluster{Noop: cluster.NewNoop("self", "http://self", "")})
	empty.reconcileMissingSelfOwnedPlacements(ctx, nil)

	if _, err := (&Service{store: st}).HasLocalSealedSecretGeneration(ctx, "sb", "inc", 0); err == nil {
		t.Fatal("non-positive generation was accepted")
	}
}

func TestPersistCreateGetSweepAndDestroyEvent(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).persistSandboxCreate(ctx, &models.Sandbox{ID: "sb"}); err == nil {
		t.Fatal("nil persist succeeded")
	}
	if err := (&Service{}).persistSandboxCreate(ctx, &models.Sandbox{ID: "sb"}); err == nil {
		t.Fatal("storeless persist succeeded")
	}

	svc, _, _ := testEnvService(t)
	now := time.Now().UTC()
	if err := svc.persistSandboxCreate(ctx, &models.Sandbox{
		ID: "sb-persist31", Image: "alpine", Status: models.SandboxStatusStarted,
		Env: map[string]string{"K": "v"}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("mint+persist: %v", err)
	}
	if got, err := svc.GetSandboxWithOptions(ctx, "sb-persist31", GetSandboxOptions{IncludeEnv: true, CorrelationID: "c-31"}); err != nil || got.Env["K"] != "v" {
		t.Fatalf("include-env get = %+v err=%v", got, err)
	}
	svc.cipher = nil
	if err := svc.persistSandboxCreate(ctx, &models.Sandbox{
		ID: "sb-nocipher", Image: "alpine", Status: models.SandboxStatusStarted,
		Env: map[string]string{"K": "v"}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		AuditIncarnationID: "inc-x",
	}); err == nil {
		t.Fatal("persist sealed env without cipher")
	}
	if _, err := svc.GetSandboxWithOptions(ctx, "sb-persist31", GetSandboxOptions{IncludeEnv: true}); err == nil {
		t.Fatal("get include-env without cipher")
	}

	rt := &recordingRuntime{}
	life, st2, _ := newServiceRuntimeHarness(t, rt)
	life.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	aged := wave30SeedSandbox(t, st2, "sb-life31", "inc-life")
	aged.CreatedAt = now.Add(-2 * time.Hour)
	aged.LastActiveAt = now.Add(-2 * time.Hour)
	aged.Lifecycle = models.Lifecycle{DestroyAtAge: time.Minute}
	if err := st2.Upsert(ctx, aged); err != nil {
		t.Fatal(err)
	}
	life.docker = nil
	life.runLifecycleSweep(ctx)

	closed := openSealTestStore(t)
	sweep := &Service{store: closed, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_ = closed.Close()
	sweep.runLifecycleSweep(ctx)

	harness, st3, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	harness.cfg.EnableCluster = true
	sb := wave30SeedSandbox(t, st3, "sb-evt31", "inc-old")
	sb.ContainerIP = "10.1.2.3"
	sb.ExposedPorts = []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}}
	harness.AttachCluster(&wave30AuthCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-evt31": {SandboxID: "sb-evt31", OwnerNodeID: "other", IncarnationID: "inc-new"},
		},
	})
	if err := harness.handleDestroyEvent(ctx, sb); err != nil {
		t.Fatalf("obsolete destroy event: %v", err)
	}

	local := wave30SeedSandbox(t, st3, "sb-evt-local", "inc-local")
	_ = st3.Close()
	if err := harness.handleDestroyEvent(ctx, local); err == nil {
		t.Fatal("closed-store destroy event succeeded")
	}
}

func TestValidatePeerSecretBlobGuardsAndCancelledReconcile(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{store: st, cipher: cipher, cluster: cluster.NewNoop("node-b", "http://b", "")}
	if err := svc.UpsertClusterSecretBlob(ctx, secrets.SecretBlob{}, "node-a"); err == nil {
		t.Fatal("empty blob")
	}
	if err := svc.UpsertClusterSecretBlob(ctx, secrets.SecretBlob{
		Ref: "r", SandboxID: "sb", SealedPayload: []byte("x"), Version: 0,
	}, "node-a"); err == nil {
		t.Fatal("version 0")
	}
	if err := svc.UpsertClusterSecretBlob(ctx, secrets.SecretBlob{
		Ref: "not-a-ref", SandboxID: "sb", SealedPayload: []byte("x"), Version: 1,
	}, "node-a"); err == nil {
		t.Fatal("bad ref")
	}
	ref := secrets.FormatRef("sb-val31", "inc-a", secrets.RefVersion)
	if err := svc.UpsertClusterSecretBlob(ctx, secrets.SecretBlob{
		Ref: ref, SandboxID: "sb-val31", IncarnationID: "", SealedPayload: []byte("x"), Version: secrets.RefVersion,
	}, "node-a"); err == nil {
		t.Fatal("blank incarnation")
	}
	if err := svc.UpsertClusterSecretBlob(ctx, secrets.SecretBlob{
		Ref: ref, SandboxID: "sb-val31", IncarnationID: "inc-a", SealedPayload: []byte("not-sealed"),
		Version: secrets.RefVersion, Recipients: []string{"node-a", "node-b"}, SealGeneration: 1,
	}, "node-a"); err == nil {
		t.Fatal("garbage envelope")
	}
	blob := wave30BoundBlob(t, cipher, "sb-val31", "inc-a", []string{"node-a", "node-b"}, 1)
	blob.Recipients = []string{"node-a"}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil {
		t.Fatal("recipient mismatch")
	}
	mismatch := wave30BoundBlob(t, cipher, "sb-val31", "inc-a", []string{"node-a", "node-b"}, 1)
	mismatch.IncarnationID = "inc-other"
	if err := svc.UpsertClusterSecretBlob(ctx, mismatch, "node-a"); err == nil {
		t.Fatal("incarnation mismatch")
	}

	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := svc.ReconcileSecretDeleteOutbox(cancelled); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled delete reconcile = %v", err)
	}
	if err := svc.ReconcileSecretPutOutbox(cancelled); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled put reconcile = %v", err)
	}
	key := secretDeleteReconcileKey("sb-inflight31", "inc-a")
	putReconcileInflight.Store(key, struct{}{})
	t.Cleanup(func() { putReconcileInflight.Delete(key) })
	if err := st.UpsertSecretPutOutbox(ctx, "sb-inflight31", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.testSecretPeerPusher = &fakePeerPusher{}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestExpandResealErrorWindowsAndAuditInitFail(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cl := &stubMembersCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
		},
		placement: cluster.Placement{
			SandboxID: "sb-reseal31", OwnerNodeID: "node-a", IncarnationID: "inc-a",
			SecretRecipients: []string{"node-a", "node-dead"}, SecretSealGeneration: 1,
		},
	}
	svc := &Service{
		cfg:   config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store: st, cluster: cl, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, cl.placement); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing provider = %v", err)
	}

	cipher := newTestCipher(t)
	svc.cipher = cipher
	svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, cl.placement); err == nil || !strings.Contains(err.Error(), "no local sealed") {
		t.Fatalf("missing ciphertext = %v", err)
	}

	closed := openSealTestStore(t)
	closedSvc := &Service{
		cfg: config.Config{EnableCluster: true}, store: closed,
		cluster: cluster.NewNoop("node-a", "http://a", ""),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	_ = closed.Close()
	if err := closedSvc.expandAndResealDeadSecretTargetsForPlacement(ctx, closedSvc.cluster, cluster.Placement{
		SandboxID: "sb-closed-re", OwnerNodeID: "node-a", IncarnationID: "inc-a", SecretSealGeneration: 1,
		SecretRecipients: []string{"node-a", "node-dead"},
	}); err == nil {
		t.Fatal("closed-store reseal load succeeded")
	}

	putSecretRow(t, st, "sb-stale-put31", "inc-old", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-stale-put31", "inc-old", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-stale-put31", "inc-old")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	retire := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster: cluster.NewNoop("node-a", "http://a", ""),
	}
	_ = st.Close()
	retire.reconcileSecretPutOutboxRecord(ctx, rec, map[string]cluster.Placement{
		"sb-stale-put31": {SandboxID: "sb-stale-put31", OwnerNodeID: "node-a", IncarnationID: "inc-new"},
	})

	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := &Service{
		cfg:    config.Config{DBPath: filepath.Join(block, "state.db")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	audit.ensureSecretAuditSink()
	if audit.secretAuditInitErr == nil {
		t.Fatal("blocked audit dir did not record init error")
	}
	if err := audit.ValidateSecretAuditSink(); err != nil {
		t.Fatalf("non-strict init error leaked: %v", err)
	}
	audit.cfg.SecretAuditStrictBoot = true
	if err := audit.ValidateSecretAuditSink(); err == nil {
		t.Fatal("strict boot ignored init error")
	}
}

func TestExpandResealStopsWithoutPeerTransport(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	cl := &stubMembersCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: true},
		},
	}
	svc := &Service{
		cfg:   config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store: st, cipher: cipher, secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: cl, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-reseal-tx", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	placement := cluster.Placement{
		SandboxID: "sb-reseal-tx", OwnerNodeID: "node-a", IncarnationID: handle.IncarnationID,
		SecretRef: handle.Ref, SecretVersion: handle.Version, SecretSealGeneration: handle.SealGeneration,
		SecretRecipients: []string{"node-a", "node-dead"},
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, placement); err == nil || !strings.Contains(err.Error(), "peer transport") {
		t.Fatalf("transportless reseal = %v", err)
	}

	sink, err := newFileAuditSinkOpts(t.TempDir(), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink.spillPath = filepath.Join(block, "secrets.spill.jsonl")
	if err := sink.appendSpill(SecretAuditEvent{EventID: "spill-dir", Result: secretAuditResultSuccess}); err == nil {
		t.Fatal("spill under a file succeeded")
	}
	if err := (&fileAuditSink{}).appendSpill(SecretAuditEvent{}); err == nil {
		t.Fatal("empty spill path succeeded")
	}
}

func TestRefanoutBindingAndAuthoritativeGuards(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).ReFanoutClusterSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-refan31", "inc-a", 1, []string{"node-a", "node-b"})
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", "")},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := svc.ReFanoutClusterSecrets(ctx); err == nil {
		t.Fatal("unbound ciphertext re-fanout succeeded")
	}
	if err := svc.runSecretRetirementScan(ctx); err == nil {
		t.Fatal("unbound ciphertext retirement succeeded")
	}
	svc.cluster = &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")}
	if err := svc.ReFanoutClusterSecrets(ctx); err == nil {
		t.Fatal("placement-down re-fanout succeeded")
	}
	oversize := make([]string, cluster.MaxPlacementPageLimit+1)
	for i := range oversize {
		oversize[i] = fmt.Sprintf("sb-%d", i)
	}
	if _, err := svc.authoritativeSecretPlacements(ctx, oversize); err == nil {
		t.Fatal("oversize placement page was accepted")
	}
	if got, err := svc.authoritativeSecretPlacements(ctx, []string{"", " "}); err != nil || got == nil {
		t.Fatalf("blank IDs = %v %v", got, err)
	}
	svc.cluster = &nilSnapshotCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}
	if _, err := svc.authoritativeSecretPlacements(ctx, []string{"sb"}); err == nil {
		t.Fatal("nil snapshot was accepted")
	}

	closed := openSealTestStore(t)
	closedSvc := &Service{cfg: config.Config{EnableCluster: true}, store: closed, cluster: cluster.NewNoop("node-a", "http://a", "")}
	_ = closed.Close()
	if err := closedSvc.ReFanoutClusterSecrets(ctx); err == nil {
		t.Fatal("closed-store re-fanout succeeded")
	}
	if err := closedSvc.runSecretRetirementScan(ctx); err == nil {
		t.Fatal("closed-store retirement succeeded")
	}
}

func TestRemainingEasyGuardsWave31(t *testing.T) {
	ctx := context.Background()
	(*Service)(nil).emitEgressAudit("sb", "tcp", "dst")
	(&Service{}).emitEgressAudit("sb", "tcp", "dst")
	disabled := &Service{cfg: config.Config{EgressAttributionEnabled: false}}
	if disabled.EgressAuditObserver() == nil {
		t.Fatal("disabled observer")
	}
	disabled.emitEgressAudit("", "tcp", "dst")
	enabled := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(enabled.CloseSecretAuditSink)
	enabled.emitEgressAudit(" ", "tcp", "dst")
	enabled.emitEgressAudit("sb", "tcp", " ")
	enabled.EgressAuditObserver()("sb-e31", "tcp", "example.com:443")

	if (*Service)(nil).secretPeerPusher() != nil {
		t.Fatal("nil pusher")
	}
	if (&Service{}).secretPeerPusher() != nil {
		t.Fatal("detached pusher")
	}

	empty, err := (*Service)(nil).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb", models.CreateSandboxRequest{Image: "alpine"}, nil, "")
	if err != nil || empty.Ref != "" {
		t.Fatalf("empty bag = %+v %v", empty, err)
	}
	if _, err := (&Service{cipher: newTestCipher(t)}).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a"}, "inc-a"); err == nil {
		t.Fatal("providerless put succeeded")
	}
	if _, err := (&Service{}).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a"}, "inc-a"); err == nil {
		t.Fatal("cipherless put succeeded")
	}

	st := openSealTestStore(t)
	if blob, err := (&Service{store: st}).loadSecretBlob(ctx, secrets.FormatRef("missing", "inc", secrets.RefVersion)); blob != nil || err == nil {
		t.Fatalf("missing blob = %v %v", blob, err)
	}
	_ = st.Close()
	if _, err := (&Service{store: st}).loadSecretBlob(ctx, secrets.FormatRef("sb", "inc", secrets.RefVersion)); err == nil {
		t.Fatal("closed loadSecretBlob succeeded")
	}

	(*Service)(nil).runWasmOrphanStateKVSweep(ctx)
	closedKV := openSealTestStore(t)
	kv := &Service{store: closedKV, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_ = closedKV.Close()
	kv.runWasmOrphanStateKVSweep(ctx)

	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicDurable(filepath.Join(block, "tip"), []byte("h"), 0o600); err == nil {
		t.Fatal("durable write under a file succeeded")
	}
	if err := persistWitnessReceipt(filepath.Join(block, "receipts.jsonl"), "", witnessReceiptRecord{HeadHex: "h"}); err == nil {
		t.Fatal("witness receipt under a file succeeded")
	}

	if _, _, err := (&Service{}).openSecretAuditSnapshot(filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Fatal("missing snapshot opened")
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if _, _, err := svc.openSecretAuditSnapshot(svc.secretAuditFile.path); err != nil {
		t.Fatalf("open snapshot: %v", err)
	}

	(&Service{store: openSealTestStore(t)}).reconcileSecretDeleteOutboxIncarnationWithPlacements(ctx, "missing", "inc", nil)
	if id := newSecretAuditCorrelationID(); id == "" {
		t.Fatal("empty correlation id")
	}

	if err := (*Service)(nil).attachWasmRegistryAuth(nil); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).attachWasmRegistryAuth(&models.Sandbox{ID: "sb", RegistryAuthSealed: []byte("bad")}); err == nil {
		t.Fatal("bad wasm registry unseal succeeded")
	}

	cipher := newTestCipher(t)
	prov := secrets.NewLocalProvider(cipher, newSecretBlobStore(openSealTestStore(t)))
	if _, err := (&Service{
		cipher: cipher, secretProvider: prov, cluster: cluster.NewNoop("node-a", "http://a", ""),
	}).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb-peers31", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a", "node-b"}, "inc-a"); err == nil || !strings.Contains(err.Error(), "put-outbox") {
		t.Fatalf("storeless put-outbox = %v", err)
	}

	st2 := openSealTestStore(t)
	retired := []string{"node-b"}
	if _, err := st2.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-delauth31", "inc-a", secrets.RefVersion),
		SandboxID: "sb-delauth31", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-c"}, RetireRecipients: &retired,
		SealedPayload: []byte("sealed"), SealGeneration: 2,
	}); err != nil {
		t.Fatal(err)
	}
	del := &Service{
		cfg: config.Config{EnableCluster: true}, store: st2,
		cluster:              &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		testSecretPeerPusher: &fakePeerPusher{},
	}
	del.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-delauth31", "inc-a")
	rec, err := st2.GetSecretDeleteOutboxForIncarnation(ctx, "sb-delauth31", "inc-a")
	if err != nil || rec == nil {
		t.Fatalf("staged delete missing: %v", err)
	}
	_ = st2.Close()
	del.reconcileSecretDeleteOutboxRecord(ctx, rec, map[string]cluster.Placement{
		"sb-delauth31": {SandboxID: "sb-delauth31", IncarnationID: "inc-a", SecretSealGeneration: 2},
	})
}
