package service

import (
	"context"
	"encoding/json"
	"errors"
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

func TestOpenClusterSecretsBadPayloadWave11(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cipher = newTestCipher(t)
	ref := secrets.FormatRef("sb-bad", "inc-test", 1)
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-bad", Version: 1, SealGeneration: 1, SealedPayload: []byte("not-json"),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.OpenClusterSecretsForNode(ctx, "sb-bad", models.CreateSandboxRequest{Image: "x"}, cluster.PlacementSecrets{Ref: ref, Version: 1, IncarnationID: "inc-test", SealGeneration: 1}, "node-a")
	if err == nil {
		t.Fatal("expected bad payload error")
	}
}

func TestReplicateSpecPatchFailWave17(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.AttachCluster(&failingSpecCluster{Noop: cluster.NewNoop("self", "http://self", ""), err: errors.New("raft")})
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-spec", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc.replicateSpecPatch(context.Background(), "sb-spec", func(spec *models.CreateSandboxRequest) {
		spec.CPU = 4
	})
}

type failingSpecCluster struct {
	*cluster.Noop
	err error
}

func (c *failingSpecCluster) UpsertSpec(context.Context, string, *models.CreateSandboxRequest, cluster.PlacementSecrets) error {
	return c.err
}

func (c *failingSpecCluster) SpecOf(string) *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{Image: "a"}
}

type authPlacementsCluster struct {
	*cluster.Noop
	err        error
	placements map[string]cluster.Placement
}

func (c *authPlacementsCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.placements, nil
}

func TestDeleteClusterSecretsForAuthoritativePlacementGuards(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb"); err != nil {
		t.Fatalf("nil service = %v", err)
	}
	if err := (&Service{}).DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("no cluster = %v", err)
	}

	svc := &Service{cluster: &authPlacementsCluster{Noop: cluster.NewNoop("self", "", ""), err: errors.New("raft down")}}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-1"); err == nil || !strings.Contains(err.Error(), "authoritative placement read") {
		t.Fatalf("read error = %v", err)
	}

	svc.cluster = &authPlacementsCluster{Noop: cluster.NewNoop("self", "", ""), placements: map[string]cluster.Placement{}}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-1"); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("missing placement = %v", err)
	}

	svc.cluster = &authPlacementsCluster{Noop: cluster.NewNoop("self", "", ""), placements: map[string]cluster.Placement{
		"sb-1": {SandboxID: "sb-1"},
	}}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-1"); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("missing incarnation = %v", err)
	}
}

func TestDeleteClusterSecretsForAuthoritativePlacementSuccess(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-auth-ok", "inc-live", 3, []string{"node-a", "node-b"})
	svc := &Service{
		store: st,
		cluster: &authPlacementsCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""),
			placements: map[string]cluster.Placement{
				"sb-auth-ok": {
					SandboxID: "sb-auth-ok", OwnerNodeID: "node-a", IncarnationID: "inc-live",
					SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 3,
				},
			},
		},
		testSecretPeerPusher: &fakePeerPusher{},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, "sb-auth-ok"); err != nil {
		t.Fatalf("authoritative delete: %v", err)
	}
	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-auth-ok", "inc-live"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("ciphertext remains after authoritative cleanup: %v", err)
	}
	outbox, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-auth-ok", "inc-live")
	if err != nil {
		t.Fatal(err)
	}
	// Peer cleanup must stay durable even if the async fan-out already ACKed.
	if outbox != nil && (len(outbox.Recipients) != 1 || outbox.Recipients[0] != "node-b") {
		t.Fatalf("delete outbox = %+v", outbox)
	}

	if err := svc.DeleteClusterSecretsForAuthoritativePlacement(ctx, " "); err == nil {
		t.Fatal("blank sandbox id was accepted")
	}
}

func TestSecretRecipientsForDeleteUsesOutboxAndRejectsInvalidIdentity(t *testing.T) {
	ctx := context.Background()
	if got, err := (*Service)(nil).secretRecipientsForDelete(ctx, "sb", "inc"); err != nil || got != nil {
		t.Fatalf("nil service = %v %v", got, err)
	}
	if got, err := (&Service{}).secretRecipientsForDelete(ctx, "sb", "inc"); err != nil || got != nil {
		t.Fatalf("storeless = %v %v", got, err)
	}
	st := openSealTestStore(t)
	svc := &Service{store: st}
	if _, err := svc.secretRecipientsForDelete(ctx, " ", "inc"); err == nil {
		t.Fatal("blank identity was accepted")
	}

	if err := st.UpsertSecretPutOutbox(ctx, "sb-put-only", "inc-put", 4, []string{"node-a", "node-c"}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.secretRecipientsForDelete(ctx, "sb-put-only", "inc-put")
	if err != nil || len(got) != 2 || got[0] != "node-a" || got[1] != "node-c" {
		t.Fatalf("put-outbox recipients = %v err=%v", got, err)
	}

	if err := svc.persistSecretPutOutboxRecipients(ctx, "sb-recreate", "inc-r", []string{"node-b"}, 2); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-recreate", "inc-r"); err != nil || rec == nil || rec.SealGeneration != 2 {
		t.Fatalf("missing put-outbox was not recreated: rec=%+v err=%v", rec, err)
	}

	clusterSvc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cluster.NewNoop("node-a", "http://a", "")}
	if got, err := clusterSvc.secretRecipientsFromExactPlacement(ctx, "missing", "inc"); err != nil || got != nil {
		t.Fatalf("absent placement = %v %v", got, err)
	}
}

func TestOpenClusterSecretsWrapsProviderErrorWithRef(t *testing.T) {
	ctx := context.Background()
	ref := secrets.FormatRef("sb-wrap", "inc-wrap", secrets.RefVersion)
	provider := &secretProviderStub{openErr: errors.New("decrypt boom")}
	svc := &Service{secretProvider: provider}
	_, err := svc.OpenClusterSecretsForNode(ctx, "sb-wrap", models.CreateSandboxRequest{Image: "alpine"}, cluster.PlacementSecrets{
		Ref: ref, Version: secrets.RefVersion, IncarnationID: "inc-wrap", SealGeneration: 1,
	}, "node-a")
	if err == nil || !strings.Contains(err.Error(), ref) || !strings.Contains(err.Error(), "decrypt boom") {
		t.Fatalf("wrapped open error = %v", err)
	}

	mismatch := &secretProviderStub{openErr: secrets.ErrVersionMismatch}
	svc.secretProvider = mismatch
	if _, err := svc.OpenClusterSecretsForNode(ctx, "sb-wrap", models.CreateSandboxRequest{Image: "alpine"}, cluster.PlacementSecrets{
		Ref: ref, Version: secrets.RefVersion, IncarnationID: "inc-wrap", SealGeneration: 1,
	}, "node-a"); !errors.Is(err, secrets.ErrVersionMismatch) {
		t.Fatalf("mismatch wrap = %v", err)
	}
}

func TestFinalizeResealedSecretFailureWindows(t *testing.T) {
	ctx := context.Background()
	cl := &resealPlacementCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-fin", OwnerNodeID: "node-a", IncarnationID: "inc-a",
			SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
		},
	}
	svc := &Service{cluster: cl, store: openSealTestStore(t), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.finalizeResealedSecret(ctx, cl, cl.placement, &storepkg.ClusterSecretRecord{
		Ref: "not-a-ref", SandboxID: "sb-fin", Version: 1, SealGeneration: 2,
	}); err == nil || !strings.Contains(err.Error(), "invalid current-format") {
		t.Fatalf("invalid identity = %v", err)
	}

	ref := secrets.FormatRef("sb-fin", "inc-a", secrets.RefVersion)
	local := &storepkg.ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-fin", Version: secrets.RefVersion,
		Recipients: []string{"node-a"}, SealedPayload: []byte("sealed"), SealGeneration: 2,
	}
	if err := svc.finalizeResealedSecret(ctx, cl, cl.placement, local); err == nil || !strings.Contains(err.Error(), "no remote replacement") {
		t.Fatalf("owner-only finalize = %v", err)
	}

	local.Recipients = []string{"node-a", "node-b"}
	if err := svc.finalizeResealedSecret(ctx, cl, cl.placement, local); err == nil || !strings.Contains(err.Error(), "peer transport") {
		t.Fatalf("transportless finalize = %v", err)
	}

	svc.testSecretPeerPusher = &fakePeerPusher{probeStrict: true}
	if err := svc.finalizeResealedSecret(ctx, cl, cl.placement, local); err == nil || !strings.Contains(err.Error(), "no acknowledged replacement") {
		t.Fatalf("unacked finalize = %v", err)
	}

	svc.testSecretPeerPusher = &fakePeerPusher{probeHolding: []string{"node-b"}, probeStrict: true}
	cl.rejectCAS = true
	if err := svc.finalizeResealedSecret(ctx, cl, cl.placement, local); err == nil || !errors.Is(err, cluster.ErrSecretRecipientsCASMismatch) {
		t.Fatalf("CAS finalize = %v", err)
	}
}

type wave30LeaderCluster struct {
	*cluster.Noop
	leader    string
	placement cluster.Placement
}

func (c *wave30LeaderCluster) Leader() string { return c.leader }

func (c *wave30LeaderCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if id == c.placement.SandboxID {
			out[id] = c.placement
		}
	}
	return out, nil
}

type wave30FailSpecCluster struct {
	*cluster.Noop
	spec *models.CreateSandboxRequest
}

func (c *wave30FailSpecCluster) SpecOf(string) *models.CreateSandboxRequest { return c.spec }

func (c *wave30FailSpecCluster) UpsertSpec(context.Context, string, *models.CreateSandboxRequest, cluster.PlacementSecrets) error {
	return errors.New("raft spec write failed")
}

func TestStartSecretDeleteOutboxReconcileStartupErrors(t *testing.T) {
	st := openSealTestStore(t)
	_ = st.Close()
	svc := &Service{
		cfg:   config.Config{SecretTombRetentionDays: 7, SecretAuditRetentionDays: 30},
		store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster: cluster.NewNoop("self", "http://self", ""),
	}
	svc.refreshSecretLifecycleMetrics(context.Background())
	if err := svc.pruneClusterSecretTombs(context.Background()); err == nil {
		t.Fatal("closed-store tomb prune should fail")
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	cancel()
	// Startup prune/ACL/metrics plus the cancelled select must not wait on the 30s ticker.
	svc.StartSecretDeleteOutboxReconcile(loopCtx)
	time.Sleep(30 * time.Millisecond)

	(*Service)(nil).refreshSecretLifecycleMetrics(context.Background())
	(&Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).refreshSecretLifecycleMetrics(context.Background())
}

func TestReconcileSecretPutOutboxRemainingBranches(t *testing.T) {
	ctx := context.Background()
	(*Service)(nil).reconcileSecretPutOutboxIncarnation(ctx, "sb", "inc")
	(*Service)(nil).reconcileSecretPutOutboxRecord(ctx, nil, nil)
	(&Service{}).reconcileSecretPutOutboxRecord(ctx, &storepkg.SecretPutOutboxRecord{SandboxID: "sb"}, nil)

	st := openSealTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st, logger: logger,
		cluster:              &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")},
		testSecretPeerPusher: &fakePeerPusher{},
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-auth-fail", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(nil, "sb-auth-fail", "inc-a")
	// A placement read failure defers (touch) rather than counts an attempt.
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-auth-fail", "inc-a"); err != nil || rec == nil || rec.Attempts != 0 {
		t.Fatalf("auth-fail deferral: rec=%+v err=%v", rec, err)
	}

	putSecretRow(t, st, "sb-nil-place", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-nil-place", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-nil-place", "inc-a")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxRecord(ctx, rec, nil)

	leader := &wave30LeaderCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""), leader: "node-other",
		placement: cluster.Placement{SandboxID: "sb-leader", IncarnationID: "inc-a"},
	}
	svc.cluster = leader
	putSecretRow(t, st, "sb-leader", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-leader", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-leader", "inc-a")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-leader", "inc-a"); err != nil || rec != nil {
		t.Fatalf("reassigned owner left put-outbox: rec=%+v err=%v", rec, err)
	}

	svc.cfg.EnableCluster = false
	svc.cluster = cluster.NewNoop("node-a", "http://a", "")
	if err := st.UpsertSecretPutOutbox(ctx, "sb-self-only", "inc-a", 1, []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-self-only", "inc-a")

	svc.testSecretPeerPusher = nil
	putSecretRow(t, st, "sb-nopush", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-nopush", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-nopush", "inc-a")

	closed := openSealTestStore(t)
	putSecretRow(t, closed, "sb-closed", "inc-a", 1, []string{"node-a", "node-b"})
	if err := closed.UpsertSecretPutOutbox(ctx, "sb-closed", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	closedSvc := &Service{
		store: closed, logger: logger, cluster: cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: &fakePeerPusher{pushErr: errors.New("peer down")},
	}
	_ = closed.Close()
	closedSvc.reconcileSecretPutOutboxIncarnation(ctx, "sb-closed", "inc-a")

	st2 := openSealTestStore(t)
	putSecretRow(t, st2, "sb-behind", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st2.UpsertSecretPutOutbox(ctx, "sb-behind", "inc-a", 3, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	pushSvc := &Service{
		store: st2, logger: logger, cluster: cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: &fakePeerPusher{pushErr: errors.New("partial"), acked: []string{"node-b"}},
	}
	pushSvc.reconcileSecretPutOutboxIncarnation(ctx, "sb-behind", "inc-a")

	if err := pushSvc.persistSecretPutOutboxRecipients(ctx, "sb-recreate", "inc-a", []string{"node-b"}, 1); err != nil {
		t.Fatalf("recreate put-outbox: %v", err)
	}
	if err := (*Service)(nil).persistSecretPutOutboxRecipients(ctx, "sb", "inc", nil, 1); err == nil {
		t.Fatal("nil persist succeeded")
	}
}

func TestClusterSecretsEasyGuardsWave30(t *testing.T) {
	ctx := context.Background()
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	fail := &wave30FailSpecCluster{Noop: cluster.NewNoop("self", "http://self", ""), spec: spec}
	svc := &Service{cluster: fail, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.replicateSpecPatch(ctx, "sb", func(req *models.CreateSandboxRequest) { req.CPU = 2 })

	(*Service)(nil).maybeAsyncDeleteFanout("", "inc")
	svc.maybeAsyncDeleteFanout("sb-async30", "inc-a")

	if (*Service)(nil).provider() != nil {
		t.Fatal("nil provider")
	}
	if got := (*Service)(nil).SecretRecipientBackupCount(); got != 2 {
		t.Fatalf("nil backup count = %d", got)
	}
	neg := &Service{cfg: config.Config{SecretRecipientBackupCount: -3}}
	if got := neg.SecretRecipientBackupCount(); got != 0 {
		t.Fatalf("negative backup count = %d", got)
	}
	if (*Service)(nil).WantsSecretRecipientFanout(models.CreateSandboxRequest{Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}) {
		t.Fatal("nil service wanted fan-out")
	}
	if (*Service)(nil).secretIncarnationForSeal("sb") != "" {
		t.Fatal("nil incarnation")
	}

	st := openSealTestStore(t)
	if err := (*Service)(nil).DeleteClusterSecrets(ctx, "sb", "inc"); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{store: st}).DeleteClusterSecrets(ctx, " ", "inc"); err == nil {
		t.Fatal("blank delete id was accepted")
	}
	if err := (*Service)(nil).DeleteClusterSecretsLocal(ctx, "sb", "inc", 1, ""); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{store: st}).DeleteClusterSecretsLocal(ctx, "sb", " ", 1, ""); err == nil {
		t.Fatal("blank local incarnation was accepted")
	}

	if recips, err := (*Service)(nil).secretRecipientsForDelete(ctx, "sb", "inc"); recips != nil || err != nil {
		t.Fatalf("nil recipients = %v %v", recips, err)
	}
	if recips, err := (&Service{}).secretRecipientsForDelete(ctx, "sb", "inc"); recips != nil || err != nil {
		t.Fatalf("storeless recipients = %v %v", recips, err)
	}
	if _, err := (&Service{store: st}).secretRecipientsForDelete(ctx, " ", "inc"); err == nil {
		t.Fatal("blank identity delete recipients succeeded")
	}
	if recips, err := (&Service{store: st}).secretRecipientsFromExactPlacement(ctx, "missing", "inc"); recips != nil || err != nil {
		t.Fatalf("disabled placement recipients = %v %v", recips, err)
	}
	if _, err := (&Service{store: st, cfg: config.Config{EnableCluster: true}}).secretRecipientsFromExactPlacement(ctx, "missing", "inc"); err == nil {
		t.Fatal("cluster-enabled storeless placement lookup succeeded")
	}

	(*Service)(nil).refreshSecretHolderPossession(ctx)
	(&Service{}).refreshSecretHolderPossession(nil)
	hold := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster:              &placementOnlyCluster{Noop: cluster.NewNoop("node-a", "http://a", "")},
		testSecretPeerPusher: &fakePeerPusher{},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	secretFanoutHolders.Store(secretHolderKey{}, &holderNodeSet{})
	addSecretHolderNodes("sb-hold30", "inc-old", 2, "node-dead")
	hold.refreshSecretHolderPossession(nil)
	secretFanoutHolders.Delete(secretHolderKey{sandboxID: "sb-hold30", incarnationID: "inc-old"})
	secretFanoutHolders.Delete(secretHolderKey{})
}

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

func TestDeleteClusterSecretsAndRecipientsWave31(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{store: st, cluster: cluster.NewNoop("node-a", "http://a", ""), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	putSecretRow(t, st, "sb-del31", "inc-a", 1, []string{"node-a", "node-b"})
	if err := svc.DeleteClusterSecrets(ctx, "sb-del31", "inc-a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb-del31", "inc-a", 2, ""); err != nil {
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
	svc.AttachCluster(&wave30AuthCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placements: map[string]cluster.Placement{
			"sb-place-del31": {SandboxID: "sb-place-del31", IncarnationID: "inc-a", SecretRecipients: []string{"node-a", "node-d"}},
		},
	})
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

func TestClusterSecretsErrorArmsWave8(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Mounts: []models.MountSpec{{
			Type: models.MountTypeS3, Target: "/data", Source: "s3://b/k",
			Credentials: map[string]string{"access_key": "a", "secret_key": "s"},
		}},
	}

	s := &Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	binding := secrets.SealBinding{SandboxID: "sb", IncarnationID: "inc-test", Ref: secrets.FormatRef("sb", "inc-test", 1), Version: 1, Generation: 1}
	if _, err := secrets.SealEnvelopeBound(s.cipher, secretsFromRequest(req), []string{"node-a"}, binding); err == nil || !strings.Contains(err.Error(), "cipher") {
		t.Fatalf("nil cipher = %v", err)
	}

	s.cipher = newTestCipher(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("dek fail")}})
	if _, err := secrets.SealEnvelopeBound(s.cipher, secretsFromRequest(req), []string{"node-a"}, binding); err == nil {
		t.Fatal("expected dek entropy failure")
	}

	setRandReader(t, &scriptedRandReader{errs: []error{nil /*dek*/, errors.New("nonce fail")}})
	if _, err := secrets.SealEnvelopeBound(s.cipher, secretsFromRequest(req), []string{"node-a"}, binding); err == nil {
		t.Fatal("expected nonce entropy failure")
	}

	// Broken cipher (zero value) fails EncryptWithAAD on wrap.
	s.cipher = &secrets.Cipher{}
	if _, err := secrets.SealEnvelopeBound(s.cipher, secretsFromRequest(req), []string{"node-a"}, binding); err == nil {
		t.Fatal("expected wrap failure")
	}

	s2 := &Service{cipher: newTestCipher(t), store: nil, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := s2.SealAndDistribute(ctx, "sb", req, []string{"n1"}); err == nil || !strings.Contains(err.Error(), "store") {
		t.Fatalf("nil store put = %v", err)
	}
	if _, err := s2.SealAndDistribute(ctx, "", req, []string{"n1"}); err == nil {
		t.Fatal("expected empty sandbox id")
	}
	empty, err := s2.SealAndDistribute(ctx, "sb", models.CreateSandboxRequest{Image: "x"}, []string{"n1"})
	if err != nil || empty.Ref != "" {
		t.Fatalf("no secrets = %+v %v", empty, err)
	}
}

func TestOpenClusterSecretsStoreMissWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cipher = newTestCipher(t)
	_, err := svc.OpenClusterSecretsForNode(ctx, "sb", models.CreateSandboxRequest{Image: "x"}, cluster.PlacementSecrets{
		Ref: "missing-ref", Version: 1,
	}, "node-a")
	if err == nil {
		t.Fatal("expected missing secret ref error")
	}
}
