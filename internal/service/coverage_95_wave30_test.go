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
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type wave30AuthCluster struct {
	*cluster.Noop
	err        error
	placements map[string]cluster.Placement
	deleteErr  error
	deleted    []string
}

func (c *wave30AuthCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	if c.err != nil {
		return nil, c.err
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *wave30AuthCluster) DeletePlacementExact(_ context.Context, sandboxID, _, _ string) error {
	c.deleted = append(c.deleted, sandboxID)
	return c.deleteErr
}

func (c *wave30AuthCluster) BeginDeletePlacementExact(_ context.Context, sandboxID, _, _ string) error {
	c.deleted = append(c.deleted, "begin:"+sandboxID)
	return c.deleteErr
}

func (c *wave30AuthCluster) Placements() []cluster.Placement {
	out := make([]cluster.Placement, 0, len(c.placements))
	for _, p := range c.placements {
		out = append(out, p)
	}
	return out
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

type emptySelfCluster struct{ *cluster.Noop }

func (*emptySelfCluster) SelfNodeID() string { return "" }

type wave30FailSpecCluster struct {
	*cluster.Noop
	spec *models.CreateSandboxRequest
}

func (c *wave30FailSpecCluster) SpecOf(string) *models.CreateSandboxRequest { return c.spec }
func (c *wave30FailSpecCluster) UpsertSpec(context.Context, string, *models.CreateSandboxRequest, cluster.PlacementSecrets) error {
	return errors.New("raft spec write failed")
}

func wave30BoundBlob(t *testing.T, cipher *secrets.Cipher, sandboxID, incarnationID string, recipients []string, gen int64) secrets.SecretBlob {
	t.Helper()
	ref := secrets.FormatRef(sandboxID, incarnationID, secrets.RefVersion)
	sealed, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{Registry: &models.RegistryAuth{Password: "p"}}, recipients, secrets.SealBinding{
		SandboxID: sandboxID, IncarnationID: incarnationID, Ref: ref, Version: secrets.RefVersion, Generation: gen,
	})
	if err != nil {
		t.Fatal(err)
	}
	return secrets.SecretBlob{
		Ref: ref, SandboxID: sandboxID, IncarnationID: incarnationID, Version: secrets.RefVersion,
		Recipients: recipients, SealedPayload: sealed, SealGeneration: gen,
	}
}

func wave30SeedSandbox(t *testing.T, st *storepkg.Store, id, incarnation string) *models.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: id, Image: "alpine", Status: models.SandboxStatusStarted,
		AuditIncarnationID: incarnation, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	return sb
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

func TestConfigureSecretProviderAWSKMSCanaryOffline(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{store: st, cfg: config.Config{SecretProvider: "awskms"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.ConfigureSecretProvider(ctx); err == nil {
		t.Fatal("empty AWS KMS key was accepted")
	}

	svc.cfg.SecretProvider = "local"
	svc.cipher = nil
	if err := svc.ConfigureSecretProvider(ctx); err == nil {
		t.Fatal("local provider without cipher was accepted")
	}

	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
	svc.cfg.SecretProvider = "awskms"
	svc.cfg.SecretAWSkmsKeyID = "alias/aerolvm-canary"
	canaryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := svc.ConfigureSecretProvider(canaryCtx); err != nil {
		t.Fatalf("non-strict canary must continue: %v", err)
	}
	svc.cfg.SecretProviderStrictBoot = true
	if err := svc.ConfigureSecretProvider(canaryCtx); err == nil || !strings.Contains(err.Error(), "canary") {
		t.Fatalf("strict canary = %v", err)
	}
}

func TestUpsertClusterSecretBlobRemainingFences(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).UpsertClusterSecretBlob(ctx, secrets.SecretBlob{}, ""); err == nil {
		t.Fatal("nil service upsert succeeded")
	}
	if err := (&Service{}).UpsertClusterSecretBlob(ctx, secrets.SecretBlob{}, ""); err == nil {
		t.Fatal("storeless upsert succeeded")
	}

	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	blob := wave30BoundBlob(t, cipher, "sb-peer30", "inc-cur", []string{"node-a", "node-b"}, 1)

	svc := &Service{store: st, cipher: cipher, cluster: &emptySelfCluster{Noop: cluster.NewNoop("node-b", "http://b", "")}}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "receiving node identity") {
		t.Fatalf("blank self = %v", err)
	}

	svc.cfg.EnableCluster = true
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("node-b", "http://b", ""), err: errors.New("raft down")}
	svc.cluster = cl
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); !errors.Is(err, ErrClusterSecretPlacementUnavailable) {
		t.Fatalf("placement read = %v", err)
	}

	cl.err = nil
	cl.placements = map[string]cluster.Placement{
		"sb-peer30": {SandboxID: "sb-peer30", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
			State: cluster.PlacementStateReserved, SecretRecipients: []string{"node-a"}, SecretSealGeneration: 0},
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "reserved placement") {
		t.Fatalf("reserved recipient mismatch = %v", err)
	}

	cl.placements["sb-peer30"] = cluster.Placement{
		SandboxID: "sb-peer30", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		State: cluster.PlacementStateReserved, SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 2,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "reserved placement") {
		t.Fatalf("reserved published gen = %v", err)
	}

	cl.placements["sb-peer30"] = cluster.Placement{
		SandboxID: "sb-peer30", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 4,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("published gen mismatch = %v", err)
	}

	newer := wave30BoundBlob(t, cipher, "sb-peer30", "inc-cur", []string{"node-a", "node-b"}, 5)
	cl.placements["sb-peer30"] = cluster.Placement{
		SandboxID: "sb-peer30", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 5,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, newer, "node-a"); err != nil {
		t.Fatalf("matching published upsert: %v", err)
	}
	stale := newer
	stale.SealGeneration = 4
	// Wire generation no longer matches the envelope, so ingress rejects before tomb/gen fences.
	if err := svc.UpsertClusterSecretBlob(ctx, stale, "node-a"); err == nil {
		t.Fatal("stale generation was accepted")
	}

	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb30", "inc-cur", 2); err != nil {
		t.Fatal(err)
	}
	tomb := wave30BoundBlob(t, cipher, "sb-tomb30", "inc-cur", []string{"node-a", "node-b"}, 1)
	cl.placements["sb-tomb30"] = cluster.Placement{
		SandboxID: "sb-tomb30", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, tomb, "node-a"); err == nil || !strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("tomb fence = %v", err)
	}
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
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-auth-fail", "inc-a"); err != nil || rec == nil || rec.Attempts < 1 {
		t.Fatalf("auth-fail bump: rec=%+v err=%v", rec, err)
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

func TestSecretAuditWitnessAndTipPaths(t *testing.T) {
	if (*Service)(nil).secretAuditWitnessPath() != "" || (*Service)(nil).secretAuditWitnessTipPath() != "" {
		t.Fatal("nil service leaked audit paths")
	}
	if (&Service{}).secretAuditWitnessPath() != "" || (&Service{}).secretAuditWitnessTipPath() != "" {
		t.Fatal("fileless service leaked audit paths")
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if svc.secretAuditWitnessPath() == "" || svc.secretAuditWitnessTipPath() == "" {
		t.Fatal("initialized sink must expose witness/tip sidecar paths")
	}
	if !strings.HasSuffix(svc.secretAuditWitnessPath(), secretAuditWitnessReceiptFile) {
		t.Fatalf("witness path = %q", svc.secretAuditWitnessPath())
	}
	if !strings.HasSuffix(svc.secretAuditWitnessTipPath(), secretAuditWitnessTipFile) {
		t.Fatalf("tip path = %q", svc.secretAuditWitnessTipPath())
	}
}

func TestWriteEventBatchPoisonRecomputeAndTipFail(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	sink.chainMu.Lock()
	sink.writePoison = errors.New("injected poison")
	sink.chainMu.Unlock()
	if err := sink.writeEventBatch([]SecretAuditEvent{{EventID: "poisoned", Result: secretAuditResultSuccess}}, true, true); err == nil {
		t.Fatal("poisoned writer succeeded")
	}

	ok, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ok.Close)
	if err := os.WriteFile(ok.path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok.chainMu.Lock()
	ok.chainHead = ""
	ok.chainMu.Unlock()
	if err := ok.writeEvent(SecretAuditEvent{EventID: "after-corrupt", Result: secretAuditResultSuccess}); err == nil {
		t.Fatal("corrupt recompute succeeded")
	}

	tip, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tip.Close)
	_ = os.Remove(tip.tipPath)
	if err := os.Mkdir(tip.tipPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := tip.writeEventBatch([]SecretAuditEvent{{EventID: "tip-dir", Result: secretAuditResultSuccess}}, true, false); err != nil {
		t.Fatalf("durable write with tip dir: %v", err)
	}
}

func TestPruneLockedMalformedChainAndGuards(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if err := os.WriteFile(sink.path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sink.pruneLocked(time.Now().UTC(), "", ""); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed prune = %v", err)
	}

	broken, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broken.Close)
	now := time.Now().UTC()
	first := SecretAuditEvent{Time: now.Add(-2 * time.Hour), EventID: "first", Result: secretAuditResultSuccess}
	auditlog.LinkEvent(auditlog.GenesisPrevHash, &first)
	second := SecretAuditEvent{Time: now.Add(-time.Hour), EventID: "second", Result: secretAuditResultSuccess}
	auditlog.LinkEvent("not-the-prev", &second)
	line1, _ := json.Marshal(first)
	line2, _ := json.Marshal(second)
	if err := os.WriteFile(broken.path, append(append(line1, '\n'), append(line2, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := broken.pruneLocked(now, "", ""); err == nil || !strings.Contains(err.Error(), "invalid chain") {
		t.Fatalf("broken chain prune = %v", err)
	}

	guard, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guard.Close)
	if err := guard.EmitDurable(SecretAuditEvent{Time: now.Add(-2 * time.Hour), EventID: "old", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")
	if err := persistAuditExportCursor(cursorPath, auditExportCursor{Generation: "other-gen", Offset: 0, Head: "head"}); err != nil {
		t.Fatal(err)
	}
	if err := guard.pruneLocked(now, cursorPath, ""); !errors.Is(err, errSecretAuditPruneGuardChanged) {
		t.Fatalf("export cursor guard = %v", err)
	}
	if err := guard.pruneLocked(now.Add(time.Hour), "", "not-the-verified-head"); !errors.Is(err, errSecretAuditPruneGuardChanged) {
		t.Fatalf("witnessed-head guard = %v", err)
	}

	ok, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ok.Close)
	called := make(chan struct{}, 1)
	ok.afterPrune = func() { called <- struct{}{} }
	if err := ok.EmitDurable(SecretAuditEvent{Time: now.Add(-3 * time.Hour), EventID: "drop-me", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := ok.EmitDurable(SecretAuditEvent{Time: now, EventID: "keep-me", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := ok.pruneLocked(now.Add(-time.Hour), "", ""); err != nil {
		t.Fatalf("prefix prune: %v", err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("afterPrune was not scheduled")
	}
}

func TestSealLoadEnvAndApplyListEnvError(t *testing.T) {
	ctx := context.Background()
	if sealed, err := (&Service{}).sealEnv(nil); sealed != nil || err != nil {
		t.Fatalf("empty env = %v %v", sealed, err)
	}
	if _, err := (&Service{}).sealEnv(map[string]string{"K": "v"}); err == nil {
		t.Fatal("seal without cipher succeeded")
	}

	svc, st, _ := testEnvService(t)
	if _, err := svc.loadEnv(ctx, "missing"); err != nil {
		t.Fatalf("missing env: %v", err)
	}
	for _, id := range []string{"sb-garbage", "sb-null", "sb-badjson", "sb-sealed"} {
		seedEnvSandbox(t, st, id, nil)
	}
	if err := st.PutEnv(ctx, "sb-garbage", []byte("not-an-envelope")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.loadEnv(ctx, "sb-garbage"); err == nil || !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("garbage decrypt = %v", err)
	}
	plainNull, err := svc.cipher.Encrypt([]byte("null"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-null", plainNull); err != nil {
		t.Fatal(err)
	}
	got, err := svc.loadEnv(ctx, "sb-null")
	if err != nil || got == nil {
		t.Fatalf("null env = %+v err=%v", got, err)
	}
	plainBad, err := svc.cipher.Encrypt([]byte("{not-json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-badjson", plainBad); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.loadEnv(ctx, "sb-badjson"); err == nil || !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("bad json = %v", err)
	}

	sealed, err := svc.sealEnv(map[string]string{"A": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-sealed", sealed); err != nil {
		t.Fatal(err)
	}
	svc.cipher = nil
	if _, err := svc.loadEnv(ctx, "sb-sealed"); err == nil {
		t.Fatal("load without cipher succeeded")
	}
	if err := svc.applyListEnvOptions(ctx, []*models.Sandbox{{ID: "sb-sealed"}}, GetSandboxOptions{IncludeEnv: true}); err == nil {
		t.Fatal("include-env without cipher succeeded")
	}

	closed, err := storepkg.Open(filepath.Join(t.TempDir(), "closed-env.db"))
	if err != nil {
		t.Fatal(err)
	}
	closedSvc := &Service{store: closed, cipher: newTestCipher(t)}
	_ = closed.Close()
	if _, err := closedSvc.loadEnv(ctx, "sb"); err == nil {
		t.Fatal("closed-store loadEnv succeeded")
	}
}

func TestDeleteSelfOwnedAndObsoleteLocalPlacement(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).deleteSelfOwnedClusterPlacementStrict(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := (*Service)(nil).obsoleteLocalPlacement(ctx, nil); ok || err != nil {
		t.Fatalf("nil obsolete = %v %v", ok, err)
	}

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	sb := wave30SeedSandbox(t, st, "sb-place30", "inc-local")
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err != nil {
		t.Fatalf("cluster disabled: %v", err)
	}
	if _, ok, err := svc.obsoleteLocalPlacement(ctx, sb); ok || err != nil {
		t.Fatalf("cluster disabled obsolete = %v %v", ok, err)
	}

	svc.cfg.EnableCluster = true
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("nil cluster delete = %v", err)
	}
	if _, _, err := svc.obsoleteLocalPlacement(ctx, sb); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("nil cluster obsolete = %v", err)
	}

	blank := *sb
	blank.AuditIncarnationID = ""
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	svc.AttachCluster(cl)
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, &blank); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("blank incarnation delete = %v", err)
	}

	cl.err = errors.New("raft down")
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("lookup fail delete = %v", err)
	}
	if _, _, err := svc.obsoleteLocalPlacement(ctx, sb); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("lookup fail obsolete = %v", err)
	}

	cl.err = nil
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err != nil {
		t.Fatalf("missing placement delete = %v", err)
	}
	if _, ok, err := svc.obsoleteLocalPlacement(ctx, sb); ok || err != nil {
		t.Fatalf("missing placement obsolete = %v %v", ok, err)
	}

	cl.placements = map[string]cluster.Placement{
		"sb-place30": {SandboxID: "sb-place30", OwnerNodeID: "self", IncarnationID: ""},
	}
	if _, _, err := svc.obsoleteLocalPlacement(ctx, sb); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("blank placement incarnation = %v", err)
	}

	cl.placements["sb-place30"] = cluster.Placement{SandboxID: "sb-place30", OwnerNodeID: "self", IncarnationID: "inc-other"}
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "lifecycles differ") {
		t.Fatalf("incarnation mismatch delete = %v", err)
	}
	if p, ok, err := svc.obsoleteLocalPlacement(ctx, sb); err != nil || !ok || p.IncarnationID != "inc-other" {
		t.Fatalf("obsolete other incarnation = %+v ok=%v err=%v", p, ok, err)
	}

	cl.placements["sb-place30"] = cluster.Placement{SandboxID: "sb-place30", OwnerNodeID: "other", IncarnationID: "inc-local"}
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err != nil {
		t.Fatalf("foreign owner delete = %v", err)
	}
	if _, ok, err := svc.obsoleteLocalPlacement(ctx, sb); err != nil || !ok {
		t.Fatalf("obsolete foreign owner = %v %v", ok, err)
	}

	cl.placements["sb-place30"] = cluster.Placement{SandboxID: "sb-place30", OwnerNodeID: "self", IncarnationID: "inc-local"}
	cl.deleteErr = errors.New("cas lost")
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err == nil || !strings.Contains(err.Error(), "delete authoritative") {
		t.Fatalf("exact delete fail = %v", err)
	}
	cl.deleteErr = nil
	if err := svc.deleteSelfOwnedClusterPlacementStrict(ctx, sb); err != nil {
		t.Fatalf("exact delete: %v", err)
	}
	if len(cl.deleted) == 0 || cl.deleted[len(cl.deleted)-1] != "sb-place30" {
		t.Fatalf("delete calls = %v", cl.deleted)
	}
	if _, ok, err := svc.obsoleteLocalPlacement(ctx, sb); ok || err != nil {
		t.Fatalf("self-owned current = %v %v", ok, err)
	}
}

func TestReconcileStaleOwnershipAndFinalizeRemaining(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).finalizeStaleLocalSandbox(ctx, nil, cluster.Placement{}, false); err != nil {
		t.Fatal(err)
	}

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	owned := wave30SeedSandbox(t, st, "sb-self30", "inc-sb-self30")
	missingInc := wave30SeedSandbox(t, st, "sb-noinc30", "inc-sb-noinc30")
	stale := wave30SeedSandbox(t, st, "sb-stale30", "inc-old")
	wasm := wave30SeedSandbox(t, st, "sb-wasm30", "inc-old-wasm")
	wasm.Runtime = models.RuntimeWasm
	wasm.UpdatedAt = time.Now().UTC()
	if err := st.Upsert(ctx, wasm); err != nil {
		t.Fatal(err)
	}

	cl := &wave30AuthCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-self30":  {SandboxID: "sb-self30", OwnerNodeID: "self", IncarnationID: "inc-sb-self30"},
			"sb-noinc30": {SandboxID: "sb-noinc30", OwnerNodeID: "other", IncarnationID: ""},
			"sb-stale30": {SandboxID: "sb-stale30", OwnerNodeID: "other", IncarnationID: "inc-new"},
		},
	}
	svc.AttachCluster(cl)
	if err := svc.finalizeStaleLocalSandbox(ctx, wasm, cluster.Placement{
		SandboxID: "sb-wasm30", OwnerNodeID: "other", IncarnationID: "inc-new-wasm",
	}, true); err != nil {
		t.Fatalf("stale wasm finalize: %v", err)
	}
	svc.reconcileStaleOwnership(ctx)
	if _, err := st.Get(ctx, stale.ID); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("stale docker row remains: %v", err)
	}
	if _, err := st.Get(ctx, wasm.ID); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("stale wasm row remains: %v", err)
	}
	if _, err := st.Get(ctx, owned.ID); err != nil {
		t.Fatalf("self-owned row was removed: %v", err)
	}
	if _, err := st.Get(ctx, missingInc.ID); err != nil {
		t.Fatalf("missing-incarnation row was removed: %v", err)
	}

	same := wave30SeedSandbox(t, st, "sb-same30", "inc-same")
	if err := svc.finalizeStaleLocalSandbox(ctx, same, cluster.Placement{
		SandboxID: "sb-same30", OwnerNodeID: "self", IncarnationID: "inc-same",
	}, false); err != nil {
		t.Fatalf("current self lifecycle: %v", err)
	}
	if err := svc.finalizeStaleLocalSandbox(ctx, same, cluster.Placement{SandboxID: "other", IncarnationID: "inc-same"}, false); err == nil {
		t.Fatal("mismatched sandbox id was accepted")
	}

	cl.err = errors.New("raft down")
	svc.reconcileStaleOwnership(ctx)

	failRT := &recordingRuntime{destroyErr: errors.New("docker gone")}
	svc2, st2, _ := newServiceRuntimeHarness(t, failRT)
	svc2.cfg.EnableCluster = true
	svc2.AttachCluster(&wave30AuthCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-fail30": {SandboxID: "sb-fail30", OwnerNodeID: "other", IncarnationID: "inc-new"},
		},
	})
	wave30SeedSandbox(t, st2, "sb-fail30", "inc-old")
	svc2.docker = nil
	svc2.reconcileStaleOwnership(ctx)
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
	if err := (*Service)(nil).DeleteClusterSecretsLocal(ctx, "sb", "inc", 1); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{store: st}).DeleteClusterSecretsLocal(ctx, "sb", " ", 1); err == nil {
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

func TestSealDistributeEasyGuardsWave30(t *testing.T) {
	ctx := context.Background()
	if recips := (&Service{}).SecretRecipientsForSeal("sb"); recips != nil {
		t.Fatalf("detached recipients = %v", recips)
	}
	if recips := (&Service{cluster: cluster.NewNoop("self", "http://self", "")}).SecretRecipientsForSeal("missing"); !sameStringSlice(recips, []string{"self"}) {
		t.Fatalf("self fallback = %v", recips)
	}
	if (&Service{cluster: cluster.NewNoop("self", "http://self", "")}).SelectReplacementRecipients(" ", 2) != nil {
		t.Fatal("blank replacement")
	}
	if (&Service{}).selectReplacementRecipients("sb", "self", 1) != nil {
		t.Fatal("detached selectReplacement")
	}

	svc := &Service{cluster: cluster.NewNoop("node-a", "http://a", "")}
	if svc.anySecretTargetDead([]string{"", "node-a", "dead"}, map[string]struct{}{"node-a": {}}, "node-a") != true {
		t.Fatal("dead target not detected")
	}
	if svc.anySecretTargetDead([]string{"node-a"}, map[string]struct{}{"node-a": {}}, "node-a") {
		t.Fatal("self-only looked dead")
	}

	st := openSealTestStore(t)
	closed := &Service{store: st}
	_ = st.Close()
	if _, err := closed.prepareAuditIncarnation(ctx, "sb-closed", ""); err == nil {
		t.Fatal("closed-store prepare succeeded")
	}
	(*Service)(nil).clearPendingAuditIncarnation("sb", "inc")
}
