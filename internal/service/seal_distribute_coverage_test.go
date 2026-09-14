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

func TestClusterSecretHelpersWave15(t *testing.T) {
	_ = secrets.NormalizeRecipients([]string{"", " b ", "a", "a", "  "})
	_ = secrets.NormalizeRecipients(nil)
	binding := secrets.SealBinding{SandboxID: "sb", IncarnationID: "inc-test", Ref: secrets.FormatRef("sb", "inc-test", 1), Version: 1, Generation: 1}

	if _, err := secrets.OpenEnvelopePayloadBound([]byte("short"), []byte("x"), []string{"n1"}, binding); err == nil {
		t.Fatal("expected bad dek")
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	if _, err := secrets.OpenEnvelopePayloadBound(dek, []byte("tiny"), []string{"n1"}, binding); err == nil {
		t.Fatal("expected short payload")
	}

	s := &Service{cipher: newTestCipher(t)}
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no dek entropy")}})
	if _, err := secrets.SealRawEnvelopeBound(s.cipher, []byte(`{}`), []string{"n1"}, binding); err == nil {
		t.Fatal("expected dek entropy fail")
	}
	setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("no nonce")}})
	if _, err := secrets.SealRawEnvelopeBound(s.cipher, []byte(`{}`), []string{"n1"}, binding); err == nil {
		t.Fatal("expected nonce entropy fail")
	}

	if _, err := s.SealAndDistribute(context.Background(), "", models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, []string{"n1"}); err == nil {
		t.Fatal("expected empty sandbox id")
	}
	if _, err := (&Service{}).SealAndDistribute(context.Background(), "sb", models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, []string{"n1"}); err == nil {
		t.Fatal("expected nil cipher/store")
	}
}

func TestSealClusterSecretsMarshalEmptyCipherWave16(t *testing.T) {
	s := &Service{}
	_, err := s.SealAndDistribute(context.Background(), "sb", models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, []string{"node-a"})
	if err == nil {
		t.Fatal("expected nil cipher")
	}
}

type panicAuthPlacementsCluster struct {
	*cluster.Noop
}

func (*panicAuthPlacementsCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	// ReservedSecretBinding must convert identity-lookup panics into a
	// retractable error instead of crashing a failed reserved create.
	panic("identity lookup exploded")
}

type nilSnapshotCluster struct {
	*cluster.Noop
}

func (*nilSnapshotCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	return nil, nil
}

func TestReservedSecretBindingGuardsAndSuccess(t *testing.T) {
	ctx := context.Background()
	if _, err := (*Service)(nil).ReservedSecretBinding(ctx, "sb"); err == nil {
		t.Fatal("nil service accepted a reserved binding")
	}
	if _, err := (&Service{}).ReservedSecretBinding(ctx, "sb-res"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("clusterless binding = %v", err)
	}
	if _, err := (&Service{cluster: cluster.NewNoop("node-a", "http://a", "")}).ReservedSecretBinding(ctx, " "); err == nil {
		t.Fatal("blank sandbox id was accepted")
	}

	cl := &authPlacementsCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placements: map[string]cluster.Placement{}}
	svc := &Service{cluster: cl}
	if _, err := svc.ReservedSecretBinding(ctx, "sb-res"); err == nil || !strings.Contains(err.Error(), "no longer authoritative") {
		t.Fatalf("missing reserved placement = %v", err)
	}

	cl.placements["sb-res"] = cluster.Placement{SandboxID: "sb-res", OwnerNodeID: "node-a", IncarnationID: "inc-res"}
	if _, err := svc.ReservedSecretBinding(ctx, "sb-res"); err == nil || !strings.Contains(err.Error(), "no longer authoritative") {
		t.Fatalf("non-reserved placement = %v", err)
	}

	cl.placements["sb-res"] = cluster.Placement{
		SandboxID: "sb-res", OwnerNodeID: "node-other", IncarnationID: "inc-res",
		State: cluster.PlacementStateReserved,
	}
	if _, err := svc.ReservedSecretBinding(ctx, "sb-res"); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("foreign owner = %v", err)
	}

	cl.placements["sb-res"] = cluster.Placement{
		SandboxID: "sb-res", OwnerNodeID: "node-a", State: cluster.PlacementStateReserved,
	}
	if _, err := svc.ReservedSecretBinding(ctx, "sb-res"); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("missing incarnation = %v", err)
	}

	cl.placements["sb-res"] = cluster.Placement{
		SandboxID: "sb-res", OwnerNodeID: "node-a", IncarnationID: "inc-res",
		State: cluster.PlacementStateReserved, ExpiresUnix: time.Now().Add(-time.Minute).Unix(),
	}
	if _, err := svc.ReservedSecretBinding(ctx, "sb-res"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired reservation = %v", err)
	}

	cl.placements["sb-res"] = cluster.Placement{
		SandboxID: "sb-res", OwnerNodeID: "node-a", IncarnationID: "inc-res",
		State: cluster.PlacementStateReserved, SecretRecipients: []string{"node-a", "node-b"},
	}
	got, err := svc.ReservedSecretBinding(ctx, "sb-res")
	if err != nil || got.IncarnationID != "inc-res" || len(got.Recipients) != 2 {
		t.Fatalf("success binding = %+v err=%v", got, err)
	}

	cl.placements["sb-res"] = cluster.Placement{
		SandboxID: "sb-res", OwnerNodeID: "node-a", IncarnationID: "inc-empty",
		State: cluster.PlacementStateReserved,
	}
	got, err = svc.ReservedSecretBinding(ctx, "sb-res")
	if err != nil || len(got.Recipients) != 1 || got.Recipients[0] != "node-a" {
		t.Fatalf("self fallback = %+v err=%v", got, err)
	}

	panicSvc := &Service{cluster: &panicAuthPlacementsCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}}
	if _, err := panicSvc.ReservedSecretBinding(ctx, "sb-panic"); err == nil || !strings.Contains(err.Error(), "resolve reserved") {
		t.Fatalf("panic recovery = %v", err)
	}
}

func TestStartSecretRetirementScanRetiresStaleAndSingleFlights(t *testing.T) {
	ctx := context.Background()
	(*Service)(nil).startSecretRetirementScan(ctx)
	(&Service{}).startSecretRetirementScan(ctx)
	(&Service{cfg: config.Config{EnableCluster: true}}).startSecretRetirementScan(ctx)

	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const activeID = "sb-retire-scan-active"
	const staleID = "sb-retire-scan-stale"
	const incarnationID = "inc-scan"
	recipients := []string{"node-a", "node-b"}
	put := func(id string) string {
		t.Helper()
		ref := secrets.FormatRef(id, incarnationID, secrets.RefVersion)
		payload, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{
			Registry: &models.RegistryAuth{Server: "registry", Username: "u", Password: "p"},
		}, recipients, secrets.SealBinding{
			SandboxID: id, IncarnationID: incarnationID, Ref: ref,
			Version: secrets.RefVersion, Generation: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
			Ref: ref, SandboxID: id, Version: secrets.RefVersion, Recipients: recipients,
			SealedPayload: payload, SealGeneration: 1,
		}); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	activeRef := put(activeID)
	staleRef := put(staleID)
	svc := &Service{
		cfg:   config.Config{EnableCluster: true},
		store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""),
			placement: cluster.Placement{
				SandboxID: activeID, OwnerNodeID: "node-a", IncarnationID: incarnationID,
				SecretRecipients: recipients, SecretSealGeneration: 1,
			},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	svc.secretRefanoutMu.Lock()
	svc.secretRefanoutRunning = true
	svc.secretRefanoutMu.Unlock()
	svc.startSecretRetirementScan(ctx)
	if rec, err := st.GetClusterSecret(ctx, staleRef); err != nil || rec == nil {
		t.Fatalf("in-flight gate retired ciphertext: rec=%+v err=%v", rec, err)
	}
	svc.secretRefanoutMu.Lock()
	svc.secretRefanoutRunning = false
	svc.secretRefanoutMu.Unlock()

	svc.startSecretRetirementScan(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := st.GetClusterSecret(ctx, staleRef)
		if errors.Is(err, storepkg.ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retirement scan did not tomb stale ciphertext: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec, err := st.GetClusterSecret(ctx, activeRef); err != nil || rec == nil {
		t.Fatalf("active lifecycle was retired by the async scan: rec=%+v err=%v", rec, err)
	}

	svc.startSecretMaintenanceScan(ctx, "unused", nil)
}

func TestEnqueueAndRunSecretFanoutRemainingPaths(t *testing.T) {
	ctx := context.Background()
	(*Service)(nil).enqueueSecretFanout("sb", secrets.SecretBlob{IncarnationID: "inc", SealGeneration: 1}, []string{"node-b"}, &fakePeerPusher{})
	st := openSealTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &Service{
		store: st, cluster: cluster.NewNoop("node-a", "http://a", ""),
		logger: logger, testSecretPeerPusher: &fakePeerPusher{acked: []string{"node-b"}},
	}

	// Incomplete identity is a hard refuse: a gen-0 push would poison failover_ready.
	before := secretFanoutFailuresTotal.Value()
	svc.enqueueSecretFanout("sb-no-id", secrets.SecretBlob{SandboxID: "sb-no-id"}, []string{"node-b"}, svc.testSecretPeerPusher)
	svc.runSecretFanout("sb-no-id", secrets.SecretBlob{SandboxID: "sb-no-id"}, []string{"node-b"}, svc.testSecretPeerPusher)
	if secretFanoutFailuresTotal.Value() <= before {
		t.Fatal("incomplete fan-out identity was not counted")
	}

	const sandboxID = "sb-fanout-run"
	putSecretRow(t, st, sandboxID, "inc-a", 2, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, sandboxID, "inc-a", 2, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	blob := secrets.SecretBlob{
		Ref: secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion), SandboxID: sandboxID,
		IncarnationID: "inc-a", Version: secrets.RefVersion, SealGeneration: 2,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
	}
	svc.runSecretFanout(sandboxID, blob, []string{"node-a", "node-b"}, svc.testSecretPeerPusher)
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, "inc-a"); err != nil || rec != nil {
		t.Fatalf("acked fan-out left put-outbox: rec=%+v err=%v", rec, err)
	}

	const incompleteID = "sb-fanout-incomplete"
	putSecretRow(t, st, incompleteID, "inc-a", 1, []string{"node-a", "node-b", "node-c"})
	if err := st.UpsertSecretPutOutbox(ctx, incompleteID, "inc-a", 1, []string{"node-b", "node-c"}); err != nil {
		t.Fatal(err)
	}
	incomplete := blob
	incomplete.SandboxID = incompleteID
	incomplete.IncarnationID = "inc-a"
	incomplete.SealGeneration = 1
	incomplete.Ref = secrets.FormatRef(incompleteID, "inc-a", secrets.RefVersion)
	svc.runSecretFanout(incompleteID, incomplete, []string{"node-a", "node-b", "node-c"}, &fakePeerPusher{acked: []string{"node-b"}})
	remaining, err := st.GetSecretPutOutboxForIncarnation(ctx, incompleteID, "inc-a")
	if err != nil || remaining == nil || len(remaining.Recipients) != 1 || remaining.Recipients[0] != "node-c" {
		t.Fatalf("incomplete fan-out obligation = %+v err=%v", remaining, err)
	}

	key := secretHolderKey{sandboxID: "sb-inflight", incarnationID: "inc-a"}
	secretCreateFanoutInflight.Store(key, struct{}{})
	t.Cleanup(func() { secretCreateFanoutInflight.Delete(key) })
	svc.enqueueSecretFanout("sb-inflight", secrets.SecretBlob{
		SandboxID: "sb-inflight", IncarnationID: "inc-a", SealGeneration: 1,
	}, []string{"node-b"}, svc.testSecretPeerPusher)

	storeless := &Service{cluster: cluster.NewNoop("node-a", "http://a", ""), logger: logger}
	storeless.runSecretFanout("sb-storeless", blob, []string{"node-a", "node-b"}, &fakePeerPusher{acked: []string{"node-b"}})
}

func TestAuthoritativeSecretPlacementsFailClosed(t *testing.T) {
	ctx := context.Background()
	svc := &Service{}
	if got, err := svc.authoritativeSecretPlacements(ctx, []string{"sb"}); err != nil || got != nil {
		t.Fatalf("clusterless = %v %v", got, err)
	}
	svc.cfg.EnableCluster = true
	if _, err := svc.authoritativeSecretPlacements(ctx, []string{"sb"}); err == nil {
		t.Fatal("nil cluster snapshot was accepted")
	}
	if got, err := svc.authoritativeSecretPlacements(ctx, nil); err != nil || got != nil {
		t.Fatalf("empty ids = %v %v", got, err)
	}
	svc.cluster = cluster.NewNoop("node-a", "http://a", "")
	got, err := svc.authoritativeSecretPlacements(ctx, []string{" ", ""})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("blank ids = %v %v", got, err)
	}
	tooMany := make([]string, cluster.MaxPlacementPageLimit+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("sb-%d", i)
	}
	if _, err := svc.authoritativeSecretPlacements(ctx, tooMany); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize snapshot = %v", err)
	}
	svc.cluster = &nilSnapshotCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}
	if _, err := svc.authoritativeSecretPlacements(ctx, []string{"sb"}); err == nil || !strings.Contains(err.Error(), "no result") {
		t.Fatalf("nil snapshot = %v", err)
	}
}

func TestRefreshSecretLifecycleMetricsAndHolderHelpers(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	if err := st.UpsertSecretPutOutbox(ctx, "sb-metrics", "inc-m", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-metrics-del", "inc-m", []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.refreshSecretLifecycleMetrics(ctx)

	clearSecretFanoutHolders("sb-holders")
	t.Cleanup(func() { clearSecretFanoutHolders("sb-holders") })
	addSecretHolderNodes("", "inc", 1, "node-a")
	addSecretHolderNodes("sb-holders", "", 1, "node-a")
	addSecretHolderNodes("sb-holders", "inc-a", 1, "node-a", "", "node-b")
	addSecretHolderNodes("sb-holders", "inc-a", 2, "node-stale")
	if got := secretHolderCount("sb-holders", "inc-a"); got != 2 {
		t.Fatalf("holders = %d, want 2 after stale-generation ACK drop", got)
	}
	resetSecretHoldersForGeneration("sb-holders", "inc-a", 1, "node-a")
	replaceSecretHoldersForGeneration("sb-holders", "inc-a", 3, "node-a")
	setSecretHolderTargets("sb-holders", "inc-a", 3, []string{"node-a", "node-c"})
	pruneDeadSecretHolders("sb-holders", "inc-a", map[string]struct{}{"node-a": {}})
	if got := secretHolderNodeIDs("sb-holders", "inc-a"); len(got) != 1 || got[0] != "node-a" {
		t.Fatalf("pruned holders = %v", got)
	}
	if secretHolderGeneration("missing", "inc") != 0 || secretHolderNodeIDs("missing", "inc") != nil {
		t.Fatal("missing holder set leaked state")
	}

	if (*Service)(nil).SecretRecipientBackupCount() != 2 {
		t.Fatal("nil backup count")
	}
	if (&Service{cfg: config.Config{SecretRecipientBackupCount: -3}}).SecretRecipientBackupCount() != 0 {
		t.Fatal("negative backup count must clamp to zero")
	}
	req := models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"A": "1"}}
	if got := (&Service{}).RedactClusterSecretsConfigured(req); len(got.Env) != 0 {
		t.Fatalf("configured redact leaked env: %+v", got)
	}
}

func TestSelectReplacementAndFailoverReadyBatch(t *testing.T) {
	ctx := context.Background()
	svc := &Service{cluster: cluster.NewNoop("node-a", "http://a", "")}
	if got := svc.SelectReplacementRecipients(" ", 2); got != nil {
		t.Fatalf("blank select = %v", got)
	}
	cl := &resealPlacementCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{
			SandboxID: "sb-ready", OwnerNodeID: "node-a", IncarnationID: "inc-ready",
			SecretRecipients: []string{"node-a", "live-b"},
		},
	}
	svc.cluster = cl
	svc.cfg.SecretRecipientBackupCount = 2
	if got := svc.SelectReplacementRecipients("sb-ready", 2); len(got) == 0 {
		t.Fatalf("replacement recipients = %v", got)
	}

	svc.attachFailoverReady(ctx, nil)
	svc.failoverReadyBatch(ctx, nil)
	svc.failoverReadyBatch(ctx, []*models.Sandbox{nil})
	sb := &models.Sandbox{
		ID: "sb-ready", AuditIncarnationID: "inc-ready",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	svc.attachFailoverReadyAll(ctx, []*models.Sandbox{sb})
	if sb.FailoverReady == nil {
		t.Fatal("failover_ready was not attached")
	}

	if !svc.anySecretTargetDead([]string{"node-a", "dead-a"}, map[string]struct{}{"node-a": {}}, "node-a") {
		t.Fatal("dead backup was not detected")
	}
	if !svc.anySecretTargetDead([]string{"node-a"}, map[string]struct{}{"node-a": {}}, "node-a") {
		t.Fatal("self-only HA set was not selected for width repair")
	}
}

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

type emptySelfCluster struct{ *cluster.Noop }

func (*emptySelfCluster) SelfNodeID() string { return "" }

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

	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb30", "inc-cur", 1); err != nil {
		t.Fatal(err)
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

func TestUpsertClusterSecretBlobWave32Fences(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		store: st, cipher: cipher,
		cfg:     config.Config{EnableCluster: true},
		cluster: cluster.NewNoop("node-b", "http://b", ""),
	}

	denied := wave30BoundBlob(t, cipher, "sb-denied32", "inc-a", []string{"node-a"}, 1)
	if err := svc.UpsertClusterSecretBlob(ctx, denied, "node-a"); err == nil || !errors.Is(err, secrets.ErrRecipientDenied) {
		t.Fatalf("recipient denied = %v", err)
	}

	zeroGen := wave30BoundBlob(t, cipher, "sb-zerogen32", "inc-a", []string{"node-a", "node-b"}, 1)
	zeroGen.SealGeneration = 0
	if err := svc.UpsertClusterSecretBlob(ctx, zeroGen, "node-a"); err == nil || !strings.Contains(err.Error(), "seal_generation") {
		t.Fatalf("zero seal generation = %v", err)
	}

	refSwap := wave30BoundBlob(t, cipher, "sb-ref32", "inc-a", []string{"node-a", "node-b"}, 1)
	// ParseRef only accepts v1; a different incarnation keeps the ref parseable
	// while disagreeing with the authenticated envelope binding.
	refSwap.Ref = secrets.FormatRef("sb-ref32", "inc-other", secrets.RefVersion)
	refSwap.IncarnationID = "inc-other"
	if err := svc.UpsertClusterSecretBlob(ctx, refSwap, "node-a"); err == nil || !strings.Contains(err.Error(), "envelope ref") {
		t.Fatalf("envelope ref mismatch = %v", err)
	}

	blob := wave30BoundBlob(t, cipher, "sb-peer32", "inc-cur", []string{"node-a", "node-b"}, 1)
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("node-b", "http://b", "")}
	svc.cluster = cl

	cl.placements = map[string]cluster.Placement{
		"sb-peer32": {SandboxID: "sb-peer32", IncarnationID: "inc-cur", SecretRecipients: []string{"node-a", "node-b"}},
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "no live placement") {
		t.Fatalf("orphaned = %v", err)
	}

	cl.placements["sb-peer32"] = cluster.Placement{
		SandboxID: "sb-peer32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-wrong"); err == nil || !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("originator denied = %v", err)
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, ""); err == nil || !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("blank originator = %v", err)
	}

	cl.placements["sb-peer32"] = cluster.Placement{
		SandboxID: "sb-peer32", OwnerNodeID: "node-a", IncarnationID: "inc-other",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("placement incarnation = %v", err)
	}

	cl.placements["sb-peer32"] = cluster.Placement{
		SandboxID: "sb-peer32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		State: cluster.PlacementStateReserved, SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 0,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err != nil {
		t.Fatalf("reserved initial put: %v", err)
	}

	stagedFail := wave30BoundBlob(t, cipher, "sb-stage32", "inc-cur", []string{"node-a", "node-b"}, 3)
	cl.placements["sb-stage32"] = cluster.Placement{
		SandboxID: "sb-stage32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, stagedFail, "node-a"); err == nil || !strings.Contains(err.Error(), "next placement generation") {
		t.Fatalf("staged reseal skip = %v", err)
	}

	stagedOK := wave30BoundBlob(t, cipher, "sb-stage32", "inc-cur", []string{"node-a", "node-b"}, 2)
	if err := svc.UpsertClusterSecretBlob(ctx, stagedOK, "node-a"); err != nil {
		t.Fatalf("staged reseal: %v", err)
	}

	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb32", "inc-cur", 1); err != nil {
		t.Fatal(err)
	}
	newer := wave30BoundBlob(t, cipher, "sb-tomb32", "inc-cur", []string{"node-a", "node-b"}, 3)
	cl.placements["sb-tomb32"] = cluster.Placement{
		SandboxID: "sb-tomb32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 3,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, newer, "node-a"); err != nil {
		t.Fatalf("newer-than-tomb put: %v", err)
	}

	putSecretRow(t, st, "sb-stale32", "inc-cur", 5, []string{"node-a", "node-b"})
	stale := wave30BoundBlob(t, cipher, "sb-stale32", "inc-cur", []string{"node-a", "node-b"}, 3)
	cl.placements["sb-stale32"] = cluster.Placement{
		SandboxID: "sb-stale32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 3,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, stale, "node-a"); err == nil || !strings.Contains(err.Error(), "stale seal_generation") {
		t.Fatalf("local max-gen fence = %v", err)
	}

	closed := openSealTestStore(t)
	closedSvc := &Service{store: closed, cluster: cluster.NewNoop("node-b", "http://b", "")}
	valid := wave30BoundBlob(t, cipher, "sb-closed32", "inc-a", []string{"node-a", "node-b"}, 1)
	_ = closed.Close()
	if err := closedSvc.UpsertClusterSecretBlob(ctx, valid, "node-a"); err == nil {
		t.Fatal("closed-store tomb lookup succeeded")
	}
}
