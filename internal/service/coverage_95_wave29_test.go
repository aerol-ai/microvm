package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestEnqueueSecretFanoutSchedulesAndDrainsOutbox(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID = "sb-enqueue-ok"
	putSecretRow(t, st, sandboxID, "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, sandboxID, "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	pusher := &fakePeerPusher{acked: []string{"node-b"}}
	svc := &Service{
		store: st, cluster: cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	svc.enqueueSecretFanout(sandboxID, secrets.SecretBlob{
		Ref: secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion), SandboxID: sandboxID,
		IncarnationID: "inc-a", Version: secrets.RefVersion, SealGeneration: 1,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
	}, []string{"node-a", "node-b"}, pusher)
	waitForSecretCreateFanoutIdle(t, sandboxID)
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, "inc-a"); err != nil || rec != nil {
		t.Fatalf("scheduled fan-out left put-outbox: rec=%+v err=%v", rec, err)
	}
}

func TestSecretRecipientsForSandboxCachedPlacementAndStore(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-cached", "inc-c", 2, []string{"node-store-a", "node-store-b"})
	cl := &placementOnlyCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-cached", IncarnationID: "inc-c",
			SecretRecipients: []string{"node-place-a", "node-place-b"},
		},
	}
	svc := &Service{store: st, cluster: cl}

	// A live placement snapshot is preferred over a possibly-stale local row.
	if got := svc.secretRecipientsForSandboxCached(ctx, "sb-cached", "inc-c", map[string]cluster.Placement{
		"sb-cached": cl.placement,
	}); !sameStringSlice(got, []string{"node-place-a", "node-place-b"}) {
		t.Fatalf("placement snapshot = %v", got)
	}
	if got := svc.secretRecipientsForSandboxCached(ctx, "sb-cached", "inc-c", nil); !sameStringSlice(got, []string{"node-place-a", "node-place-b"}) {
		t.Fatalf("PlacementOf fallback = %v", got)
	}
	if got := svc.secretRecipientsForSandboxCached(ctx, "sb-cached", "inc-c", map[string]cluster.Placement{}); !sameStringSlice(got, []string{"node-store-a", "node-store-b"}) {
		t.Fatalf("store fallback = %v", got)
	}
	if got := svc.secretRecipientsForSandboxCached(ctx, "missing", "inc-c", map[string]cluster.Placement{}); got != nil {
		t.Fatalf("missing store row = %v", got)
	}
	if got := (&Service{cluster: cl}).secretRecipientsForSandboxCached(ctx, "sb-cached", "inc-c", map[string]cluster.Placement{}); got != nil {
		t.Fatalf("storeless = %v", got)
	}
}

func TestFanoutSecretAfterSealGuardsAndRetract(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).fanoutSecretAfterSeal(ctx, "sb", models.CreateSandboxRequest{}, nil, cluster.PlacementSecrets{}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cluster: cluster.NewNoop("node-a", "http://a", ""), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := models.CreateSandboxRequest{Image: "alpine"}
	if err := svc.fanoutSecretAfterSeal(ctx, "sb", req, []string{"node-a", "node-b"}, cluster.PlacementSecrets{Ref: "r"}); err != nil {
		t.Fatalf("non-HA = %v", err)
	}
	req.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	if err := svc.fanoutSecretAfterSeal(ctx, "sb", req, []string{"node-a"}, cluster.PlacementSecrets{Ref: "r"}); err != nil {
		t.Fatalf("single recipient = %v", err)
	}
	if err := svc.fanoutSecretAfterSeal(ctx, "sb", req, []string{"node-a", "node-b"}, cluster.PlacementSecrets{}); err != nil {
		t.Fatalf("empty handle = %v", err)
	}
	if err := svc.fanoutSecretAfterSeal(ctx, "sb", req, []string{"node-a", "node-b"}, cluster.PlacementSecrets{Ref: "r"}); err == nil || !strings.Contains(err.Error(), "peer pusher") {
		t.Fatalf("missing pusher = %v", err)
	}

	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc.store = st
	svc.cipher = cipher
	svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
	svc.testSecretPeerPusher = &fakePeerPusher{}
	if err := svc.fanoutSecretAfterSeal(ctx, "sb-missing", req, []string{"node-a", "node-b"}, cluster.PlacementSecrets{
		Ref: secrets.FormatRef("sb-missing", "inc-a", secrets.RefVersion), Version: secrets.RefVersion,
		IncarnationID: "inc-a", SealGeneration: 1,
	}); err == nil || !strings.Contains(err.Error(), "cannot load") {
		t.Fatalf("missing blob = %v", err)
	}

	handle, err := svc.SealAndDistribute(ctx, "sb-ha-retract", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	svc.testSecretPeerPusher = &fakePeerPusher{acked: nil}
	if err := svc.fanoutSecretAfterSeal(ctx, "sb-ha-retract", req, []string{"node-a", "node-b"}, handle); err == nil || !strings.Contains(err.Error(), "no backup ACK") {
		t.Fatalf("zero-ACK HA = %v", err)
	}
}

func TestPrepareAuditIncarnationSourcesAndSecretRecipientsForSeal(t *testing.T) {
	ctx := context.Background()
	if _, err := (*Service)(nil).prepareAuditIncarnation(ctx, "sb", ""); err == nil {
		t.Fatal("nil service minted an incarnation")
	}
	if _, err := (&Service{}).prepareAuditIncarnation(ctx, " ", ""); err == nil {
		t.Fatal("blank sandbox minted an incarnation")
	}

	bound := secrets.ContextWithIncarnationID(ctx, "inc-bound")
	svc := &Service{}
	got, err := svc.prepareAuditIncarnation(bound, "sb-bound", "")
	if err != nil || got != "inc-bound" {
		t.Fatalf("context binding = %q %v", got, err)
	}
	if _, err := svc.prepareAuditIncarnation(secrets.ContextWithIncarnationID(ctx, "inc-other"), "sb-bound", ""); err == nil {
		t.Fatal("conflicting bound incarnation was accepted")
	}
	if again, err := svc.prepareAuditIncarnation(bound, "sb-bound", ""); err != nil || again != "inc-bound" {
		t.Fatalf("idempotent bound = %q %v", again, err)
	}

	cl := &placementOnlyCluster{
		Noop:      cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{SandboxID: "sb-place", IncarnationID: "inc-place", SecretRecipients: []string{"node-a", "node-c"}},
	}
	placed := &Service{cluster: cl}
	if got, err := placed.prepareAuditIncarnation(ctx, "sb-place", ""); err != nil || got != "inc-place" {
		t.Fatalf("placement incarnation = %q %v", got, err)
	}
	if got := placed.SecretRecipientsForSeal("sb-place"); !sameStringSlice(got, []string{"node-a", "node-c"}) {
		t.Fatalf("seal recipients = %v", got)
	}
	if got := (&Service{cluster: cluster.NewNoop("node-a", "http://a", "")}).SecretRecipientsForSeal("missing"); len(got) != 1 || got[0] != "node-a" {
		t.Fatalf("self fallback = %v", got)
	}
	if got := (&Service{}).SecretRecipientsForSeal("sb"); got != nil {
		t.Fatalf("clusterless recipients = %v", got)
	}

	st := openSealTestStore(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-live", Image: "alpine", Status: models.SandboxStatusStarted,
		AuditIncarnationID: "inc-live", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	stored := &Service{store: st}
	if got, err := stored.prepareAuditIncarnation(ctx, "sb-live", ""); err != nil || got != "inc-live" {
		t.Fatalf("live row incarnation = %q %v", got, err)
	}
	if got := stored.secretIncarnationForSeal("sb-live"); got != "inc-live" {
		t.Fatalf("seal incarnation = %q", got)
	}
}

func TestLoadSecretBlobAndPeerPusherFallback(t *testing.T) {
	ctx := context.Background()
	if blob, err := (*Service)(nil).loadSecretBlob(ctx, "ref"); err != nil || blob != nil {
		t.Fatalf("nil load = %v %v", blob, err)
	}
	st := openSealTestStore(t)
	svc := &Service{store: st, cluster: cluster.NewNoop("node-a", "http://a", "")}
	if blob, err := svc.loadSecretBlob(ctx, ""); err != nil || blob != nil {
		t.Fatalf("empty ref = %v %v", blob, err)
	}
	putSecretRow(t, st, "sb-blob", "inc-b", 1, []string{"node-a"})
	blob, err := svc.loadSecretBlob(ctx, secrets.FormatRef("sb-blob", "inc-b", secrets.RefVersion))
	if err != nil || blob == nil || blob.SandboxID != "sb-blob" {
		t.Fatalf("loaded blob = %+v err=%v", blob, err)
	}
	if got := svc.secretPeerPusher(); got != nil {
		t.Fatalf("Noop must not pretend to be a pusher: %T", got)
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

func TestExpandAndResealPublishesAcknowledgedReplacement(t *testing.T) {
	ctx := context.Background()
	const sandboxID = "sb-reseal-ok"
	base := cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-a",
		SecretRecipients: []string{"node-a", "dead-a", "dead-b"},
		SecretRef:        secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion),
		SecretVersion:    secrets.RefVersion, SecretSealGeneration: 1,
	}
	cl := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placement: base}
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{
		cfg: config.Config{SecretRecipientBackupCount: 2}, cipher: cipher, store: st, cluster: cl,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"live-b"}},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	sealCtx := secrets.ContextWithIncarnationID(ctx, "inc-a")
	handle, err := svc.secretProvider.Put(sealCtx, sandboxID, secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}, base.SecretRecipients)
	if err != nil {
		t.Fatal(err)
	}
	cl.mu.Lock()
	cl.placement.SecretRef = handle.Ref
	cl.placement.SecretVersion = handle.Version
	cl.placement.SecretSealGeneration = handle.SealGeneration
	cl.mu.Unlock()
	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
	resetSecretHoldersForGeneration(sandboxID, "inc-a", handle.SealGeneration, "node-a")
	setSecretHolderTargets(sandboxID, "inc-a", handle.SealGeneration, base.SecretRecipients)

	if err := svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err != nil {
		t.Fatalf("acked reseal: %v", err)
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.updateCalls != 1 || cl.placement.SecretSealGeneration <= handle.SealGeneration {
		t.Fatalf("published gen=%d updates=%d old=%d", cl.placement.SecretSealGeneration, cl.updateCalls, handle.SealGeneration)
	}
}

func TestReconcilePutOutboxMissingRowAndStaleLifecycle(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""),
			placement: cluster.Placement{
				SandboxID: "sb-stale-put", OwnerNodeID: "node-a", IncarnationID: "inc-new",
			},
		},
		testSecretPeerPusher: &fakePeerPusher{},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "missing", "inc-missing")
	putSecretRow(t, st, "sb-stale-put", "inc-old", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-stale-put", "inc-old", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(nil, "sb-stale-put", "inc-old")
	if rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-stale-put", "inc-old"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("stale lifecycle ciphertext remains: rec=%+v err=%v", rec, err)
	}
}

func TestWriteEventBatchRecomputesEmptyTipAndNilMemSink(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "tip-seed", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	sink.chainMu.Lock()
	sink.chainHead = ""
	sink.chainMu.Unlock()
	if err := sink.writeEvent(SecretAuditEvent{EventID: "after-recompute", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}

	var mem *memSecretAuditSink
	mem.Emit(SecretAuditEvent{EventID: "ignored"})
	if evs := mem.Events(); evs != nil {
		t.Fatalf("nil mem events = %v", evs)
	}
	mem = &memSecretAuditSink{}
	mem.Emit(SecretAuditEvent{})
	if len(mem.Events()) != 1 {
		t.Fatal("mem sink dropped an event")
	}

	egress := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: t.TempDir() + "/state.db"}}
	t.Cleanup(egress.CloseSecretAuditSink)
	obs := egress.EgressAuditObserver()
	obs("sb-e", "tcp", "example.com:443")
}

func TestUpsertClusterSecretBlobEnableClusterFences(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	cl := &placementOnlyCluster{
		Noop: cluster.NewNoop("node-b", "http://b", ""),
		placement: cluster.Placement{
			SandboxID: "sb-peer", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
			State: cluster.PlacementStateReserved, SecretRecipients: []string{"node-a", "node-b"},
			SecretSealGeneration: 0,
		},
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cipher: cipher, cluster: cl}
	bag := secrets.Secrets{Registry: &models.RegistryAuth{Password: "p"}}
	ref := secrets.FormatRef("sb-peer", "inc-cur", secrets.RefVersion)
	sealed, err := secrets.SealEnvelopeBound(cipher, bag, []string{"node-a", "node-b"}, secrets.SealBinding{
		SandboxID: "sb-peer", IncarnationID: "inc-cur", Ref: ref, Version: secrets.RefVersion, Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob := secrets.SecretBlob{
		Ref: ref, SandboxID: "sb-peer", IncarnationID: "inc-cur", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: sealed, SealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-other"); !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("foreign originator = %v", err)
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err != nil {
		t.Fatalf("reserved matching upsert: %v", err)
	}

	cl.placement.State = cluster.PlacementStatePlaced
	cl.placement.SecretSealGeneration = 1
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err != nil {
		t.Fatalf("matching generation upsert: %v", err)
	}
	stale := blob
	stale.SealGeneration = 1
	cl.placement.SecretRecipients = []string{"node-a", "node-c"}
	if err := svc.UpsertClusterSecretBlob(ctx, stale, "node-a"); err == nil {
		t.Fatal("recipient drift was accepted")
	}
}

func TestHasLocalSealedSecretGenerationRequiresIncarnation(t *testing.T) {
	ctx := context.Background()
	svc := &Service{store: openSealTestStore(t)}
	if ok, err := svc.HasLocalSealedSecretGeneration(ctx, "sb", " ", 1); err == nil || ok {
		t.Fatalf("blank incarnation = %v %v", ok, err)
	}
	if gen, holds := (*Service)(nil).localSealedSecretGeneration(ctx, "sb", "inc"); gen != 0 || holds {
		t.Fatalf("nil local gen = %d %v", gen, holds)
	}
}

func TestEnqueueSecretFanoutDefersWhenQueueSaturated(t *testing.T) {
	st := openSealTestStore(t)
	total := secretRefanoutWorkers + secretCreateFanoutQueue
	started := make(chan struct{}, total)
	release := make(chan struct{})
	pusher := &blockingRefanoutPusher{started: started, release: release}
	svc := &Service{
		store: st, cluster: cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	blobFor := func(id string) secrets.SecretBlob {
		return secrets.SecretBlob{
			Ref: secrets.FormatRef(id, "inc-a", secrets.RefVersion), SandboxID: id,
			IncarnationID: "inc-a", Version: secrets.RefVersion, SealGeneration: 1,
			Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
		}
	}
	for i := range total {
		id := fmt.Sprintf("sb-sat-%03d", i)
		svc.enqueueSecretFanout(id, blobFor(id), []string{"node-a", "node-b"}, pusher)
	}
	for range secretRefanoutWorkers {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("workers did not start")
		}
	}
	overflowID := "sb-sat-overflow"
	before := secretFanoutFailuresTotal.Value()
	svc.enqueueSecretFanout(overflowID, blobFor(overflowID), []string{"node-a", "node-b"}, pusher)
	close(release)
	if secretFanoutFailuresTotal.Value() <= before {
		t.Fatal("saturated queue did not record a fan-out failure")
	}
	rec, err := st.GetSecretPutOutboxForIncarnation(context.Background(), overflowID, "inc-a")
	if err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "node-b" {
		t.Fatalf("saturated queue must journal remaining peers: rec=%+v err=%v", rec, err)
	}
}

func TestApplyListEnvOptionsAndConfigureProviderGuards(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).ConfigureSecretProvider(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).ConfigureSecretProvider(ctx); err != nil {
		t.Fatal(err)
	}

	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{store: st, cipher: cipher, cfg: config.Config{SecretProvider: "local"}}
	if err := svc.ConfigureSecretProvider(ctx); err != nil || svc.secretProvider == nil {
		t.Fatalf("local configure = %v provider=%v", err, svc.secretProvider)
	}
	svc.cfg.SecretProvider = "not-a-provider"
	if err := svc.ConfigureSecretProvider(ctx); err == nil {
		t.Fatal("unknown provider was accepted")
	}

	stripped := &models.Sandbox{ID: "sb-noenv", Env: map[string]string{"KEEP": "1"}}
	if err := svc.applyListEnvOptions(ctx, []*models.Sandbox{nil, stripped}, GetSandboxOptions{}); err != nil || stripped.Env != nil {
		t.Fatalf("strip env = %+v err=%v", stripped.Env, err)
	}
	loaded := &models.Sandbox{ID: "missing"}
	if err := svc.applyListEnvOptions(ctx, []*models.Sandbox{nil, loaded}, GetSandboxOptions{IncludeEnv: true, CorrelationID: "c-29"}); err != nil {
		t.Fatalf("include env: %v", err)
	}
}

func TestUpsertClusterSecretBlobRejectsMissingAndStalePlacement(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	cl := &placementOnlyCluster{Noop: cluster.NewNoop("node-b", "http://b", "")}
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cipher: cipher, cluster: cl}
	ref := secrets.FormatRef("sb-gone", "inc-cur", secrets.RefVersion)
	sealed, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"node-a", "node-b"}, secrets.SealBinding{
		SandboxID: "sb-gone", IncarnationID: "inc-cur", Ref: ref, Version: secrets.RefVersion, Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob := secrets.SecretBlob{
		Ref: ref, SandboxID: "sb-gone", IncarnationID: "inc-cur", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: sealed, SealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "no live placement") {
		t.Fatalf("missing placement = %v", err)
	}

	cl.placement = cluster.Placement{
		SandboxID: "sb-gone", OwnerNodeID: "node-a", IncarnationID: "inc-other",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("incarnation fence = %v", err)
	}

	cl.placement.IncarnationID = "inc-cur"
	cl.placement.SecretRecipients = nil
	cl.placement.SecretSealGeneration = 3
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "next placement generation") {
		t.Fatalf("stale staged reseal = %v", err)
	}
}

func TestReconcileOutboxesNilContextAndDeletingPlacement(t *testing.T) {
	st := openSealTestStore(t)
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""),
			placement: cluster.Placement{
				SandboxID: "sb-del-put", OwnerNodeID: "node-a", IncarnationID: "inc-a",
				State: cluster.PlacementStateDeleting,
			},
		},
		testSecretPeerPusher: &fakePeerPusher{},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	putSecretRow(t, st, "sb-del-put", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(context.Background(), "sb-del-put", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileSecretPutOutbox(nil); err != nil {
		t.Fatalf("nil-ctx put reconcile: %v", err)
	}
	if rec, err := st.GetClusterSecretForSandboxIncarnation(context.Background(), "sb-del-put", "inc-a"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("deleting placement left ciphertext: rec=%+v err=%v", rec, err)
	}
	if err := svc.ReconcileSecretDeleteOutbox(nil); err != nil {
		t.Fatalf("nil-ctx delete reconcile: %v", err)
	}
}
