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
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// mismatchWitness ACKs a ship but then reports a different (or failed) remote
// head so retention cannot treat a local receipt as proof of off-node durability.
type mismatchWitness struct {
	remoteErr error
}

func (mismatchWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "rcpt-mismatch"}, nil
}

func (w mismatchWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	if w.remoteErr != nil {
		return "", false, w.remoteErr
	}
	return "other", true, nil
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

func TestSecretAuditSinkGuardsSidecarsAndEnterpriseInit(t *testing.T) {
	var nilSink *fileAuditSink
	nilSink.Emit(SecretAuditEvent{})
	if err := nilSink.EmitDurable(SecretAuditEvent{}); err == nil {
		t.Fatal("nil durable emit succeeded")
	}
	if err := nilSink.Sync(); err != nil {
		t.Fatalf("nil sync = %v", err)
	}
	nilSink.Close()
	if err := nilSink.Prune(time.Now()); err != nil {
		t.Fatalf("nil prune = %v", err)
	}
	if err := nilSink.pruneWithGuards(time.Now(), "", ""); err != nil {
		t.Fatalf("nil prune guards = %v", err)
	}
	if nilSink.drainSpill() || nilSink.appendSpill(SecretAuditEvent{}) == nil {
		t.Fatal("nil spill helpers succeeded")
	}
	head, id := nilSink.chainTip()
	if head != "" || id != "" {
		t.Fatalf("nil tip = %q %q", head, id)
	}
	nilSink.persistGapState(1)
	if err := writeFileAtomicDurable(" ", []byte("x"), 0o600); err == nil {
		t.Fatal("empty durable sidecar path was accepted")
	}
	if err := persistSpillOffset("", 1); err == nil {
		t.Fatal("empty spill offset was accepted")
	}
	if loadSpillOffset("") != 0 || loadGapCount(filepath.Join(t.TempDir(), "missing")) != 0 {
		t.Fatal("missing sidecars must be zero")
	}
	persistGapCount("", 1)
	clearGapCount("")
	persistChainTip("", "head", "id")
	if err := persistChainTipErr("", "head", "id"); err != nil {
		t.Fatal(err)
	}

	sink, err := newFileAuditSink(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if cap(sink.ch) != defaultSecretAuditBuffer {
		t.Fatalf("default buffer = %d", cap(sink.ch))
	}
	if err := sink.writeEventBatch(nil, true, true); err != nil {
		t.Fatal(err)
	}
	if err := sink.pruneLocked(time.Time{}, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sink.spillPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if sink.drainSpill() {
		t.Fatal("empty spill segment should not report work")
	}
	line, _ := json.Marshal(SecretAuditEvent{EventID: "spill-resume", Result: secretAuditResultSuccess})
	if err := os.WriteFile(sink.spillWorkingPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sink.drainSpill() {
		t.Fatal("interrupted spill working file was not resumed")
	}
	if err := persistSpillOffset(filepath.Join(t.TempDir(), "off"), 12); err != nil {
		t.Fatal(err)
	}
	if got := loadSpillOffset(filepath.Join(t.TempDir(), "missing")); got != 0 {
		t.Fatalf("missing offset = %d", got)
	}

	if err := sink.EmitDurable(SecretAuditEvent{EventID: "close-me", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	sink.Close()
	sink.Emit(SecretAuditEvent{EventID: "after-close"})
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "after-close-d"}); err == nil {
		t.Fatal("closed durable emit succeeded")
	}
	if err := sink.Sync(); err != nil {
		t.Fatalf("closed sync = %v", err)
	}
	if err := sink.pruneWithGuards(time.Now(), "", ""); err != nil {
		t.Fatalf("closed prune = %v", err)
	}
	sink.Close()

	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"), EnterpriseMode: true,
	}}
	t.Cleanup(svc.CloseSecretAuditSink)
	got := svc.secretAuditSink().(*fileAuditSink)
	if !got.spillEnabled || cap(got.ch) != enterpriseSecretAuditBuffer {
		t.Fatalf("enterprise sink spill=%v cap=%d", got.spillEnabled, cap(got.ch))
	}
	if err := svc.ValidateSecretAuditSink(); err != nil {
		t.Fatalf("validate enterprise sink: %v", err)
	}
	svc.startSecretAuditPruneTicker()

	(*Service)(nil).ensureSecretAuditSink()
	(*Service)(nil).CloseSecretAuditSink()
	if (*Service)(nil).secretAuditSink() != nil || (*Service)(nil).auditActor() != "" {
		t.Fatal("nil service leaked audit state")
	}
	if secretAuditDataDir(" ") != "" || secretAuditDataDir("/tmp/state.db") != "/tmp" {
		t.Fatalf("audit data dir = %q", secretAuditDataDir("/tmp/state.db"))
	}
}

func TestSecretAuditQueryAndClassifyRemaining(t *testing.T) {
	if _, _, err := (*Service)(nil).ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err != nil {
		t.Fatal(err)
	}
	if err := (*Service)(nil).PruneSecretAudit(nil); err != nil {
		t.Fatal(err)
	}
	page, err := (&Service{}).ListSecretAudit(nil, "sb", SecretAuditQuery{})
	if err != nil || page.Events != nil {
		t.Fatalf("storeless list = %+v %v", page, err)
	}

	held := cap(secretAuditLocalQuerySlots)
	for range held {
		secretAuditLocalQuerySlots <- struct{}{}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, cancelErr := (&Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "x.db")}}).ListSecretAuditLocal(cancelled, "sb", SecretAuditQuery{})
	for range held {
		<-secretAuditLocalQuerySlots
	}
	if !errors.Is(cancelErr, context.Canceled) {
		t.Fatalf("cancelled local list = %v", cancelErr)
	}

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	if _, _, err := svc.ListSecretAuditLocal(context.Background(), " ", SecretAuditQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{Cursor: "not-a-time\x1fkey"}); err == nil {
		t.Fatal("malformed cursor was accepted")
	}
	sink := svc.secretAuditSink().(*fileAuditSink)
	if err := sink.EmitDurable(SecretAuditEvent{
		EventID: "kind-open", SandboxID: "sb-kind", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess,
	}); err != nil {
		t.Fatal(err)
	}
	events, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-kind", SecretAuditQuery{Limit: maxSecretAuditLimit + 10, Kind: secretAuditKindEgress})
	if err != nil || len(events) != 0 {
		t.Fatalf("kind filter = %+v err=%v", events, err)
	}

	if ctx := ContextWithSecretAuditCorrelation(nil, "id"); ctx != nil {
		t.Fatal("nil context was rewritten")
	}
	if ctx := ContextWithSecretAuditCorrelation(context.Background(), " "); ctx != context.Background() {
		t.Fatal("blank correlation attached a value")
	}
	ctx := ContextWithSecretAuditCorrelation(context.Background(), "corr-28")
	if got := correlationIDFromContext(ctx); got != "corr-28" {
		t.Fatalf("correlation = %q", got)
	}
	if correlationIDFromContext(nil) != "" || correlationIDFromContext(context.Background()) != "" {
		t.Fatal("empty correlation leaked")
	}

	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("row not found"), secretAuditReasonNotFound},
		{errors.New("recipient is not allowed to open"), secretAuditReasonRecipientDenied},
		{errors.New("envelope version mismatch"), secretAuditReasonVersionMismatch},
		{errors.New("sealed blob is truncated"), secretAuditReasonDecryptFailed},
		{errors.New("cipher: auth failed"), secretAuditReasonDecryptFailed},
	} {
		if got := classifySecretAuditReason(tc.err); got != tc.want {
			t.Fatalf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if registryAuditRef("sb") != "registry:sb" || mountsAuditRef("sb") != "mounts:sb" || envAuditRef("sb") != "env:sb" {
		t.Fatal("audit ref helpers")
	}
	if sandboxIDFromSecretRef("cluster-secret://sandbox/sb-x/i/inc/v1") != "sb-x" {
		t.Fatal("sandbox id parse")
	}

	fan := &Service{
		cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")},
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "ingress", Alive: true, Role: config.NodeRoleIngress, InternalURL: "https://ingress"},
				{NodeID: "dead", Alive: false, InternalURL: "https://dead"},
				{NodeID: "blank", Alive: true},
				{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
			},
			placement: cluster.Placement{
				SandboxID: "sb-fan", OwnerNodeID: "self", IncarnationID: "inc-fan",
				AuditNodeIDs: []string{"self", "peer", "dead", "missing-node"},
			},
		},
	}
	t.Cleanup(fan.CloseSecretAuditSink)
	page, err = fan.ListSecretAudit(context.Background(), "sb-fan", SecretAuditQuery{IncarnationID: "inc-fan"})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Coverage.Partial {
		t.Fatalf("fetcherless coverage = %+v", page.Coverage)
	}
}

func TestSecretAuditWitnessAndExportRemaining(t *testing.T) {
	if _, err := (*Service)(nil).requireCurrentSecretAuditWitness(context.Background()); err == nil {
		t.Fatal("nil require witness succeeded")
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	if _, err := svc.requireCurrentSecretAuditWitness(context.Background()); err == nil {
		t.Fatal("missing external witness was accepted")
	}
	w := &stubWitness{shipErr: errors.New("offline")}
	svc.auditWitness = w
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatalf("empty-head ship = %v", err)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "need-witness", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.requireCurrentSecretAuditWitness(nil); err == nil {
		t.Fatal("ship failure was ignored")
	}
	w.shipErr = nil
	head, err := svc.requireCurrentSecretAuditWitness(context.Background())
	if err != nil || head == "" {
		t.Fatalf("current witness = %q %v", head, err)
	}
	svc.auditWitness = &mismatchWitness{}
	if _, err := svc.requireCurrentSecretAuditWitness(context.Background()); err == nil || !strings.Contains(err.Error(), "not witnessed") {
		t.Fatalf("stale remote head = %v", err)
	}
	svc.auditWitness = &mismatchWitness{remoteErr: errors.New("read failed")}
	if _, err := svc.requireCurrentSecretAuditWitness(context.Background()); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("remote read = %v", err)
	}

	if ok, err := svc.secretAuditFullyExported(); ok || err != nil {
		t.Fatalf("unexported = %v %v", ok, err)
	}
	if n, err := svc.exportSecretAuditBatchOnce(context.Background()); n != 0 || err != nil {
		t.Fatalf("exporterless batch = %d %v", n, err)
	}

	scan, err := recomputeChain(filepath.Join(t.TempDir(), "missing.jsonl"))
	if err != nil || scan.head == "" || scan.eventID != "" || scan.records != 0 || scan.found != nil {
		t.Fatalf("missing chain = %+v %v", scan, err)
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
	if svc.anySecretTargetDead([]string{"node-a"}, map[string]struct{}{"node-a": {}}, "node-a") {
		t.Fatal("self-only set is not a dead-target trigger")
	}
}
