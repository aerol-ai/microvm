package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type secretProviderStub struct {
	bag         secrets.Secrets
	openErr     error
	putHandle   secrets.Handle
	putErr      error
	deleteErr   error
	openCalls   int
	deleteCalls int
}

func (p *secretProviderStub) Put(context.Context, string, secrets.Secrets, []string) (secrets.Handle, error) {
	return p.putHandle, p.putErr
}

func (p *secretProviderStub) Open(context.Context, string, secrets.Handle, string) (secrets.Secrets, error) {
	p.openCalls++
	return p.bag, p.openErr
}

func (p *secretProviderStub) Delete(context.Context, string) error {
	p.deleteCalls++
	return p.deleteErr
}

func TestDeleteClusterSecretsStopsBeforeMutationWhenRecipientsCannotBeLoaded(t *testing.T) {
	st := openSealTestStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	provider := &secretProviderStub{}
	svc := &Service{store: st, secretProvider: provider}
	if err := svc.DeleteClusterSecrets(context.Background(), "sb-delete-lookup-failure", "inc-live"); err == nil {
		t.Fatal("delete accepted an unknown peer cleanup set")
	}
	if provider.deleteCalls != 0 {
		t.Fatalf("provider delete calls = %d, want 0 before cleanup set is known", provider.deleteCalls)
	}
}

func TestDeleteClusterSecretsUsesLocalLifecycleNotReusedPlacement(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-reused-delete", Image: "alpine", Status: models.SandboxStatusStarted,
		AuditIncarnationID: "inc-old", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	putSecretRow(t, st, "sb-reused-delete", "inc-old", 2, []string{"node-old", "node-backup"})
	putSecretRow(t, st, "sb-reused-delete", "inc-new", 1, []string{"node-new", "node-new-backup"})
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-old", "http://old", ""),
			placement: cluster.Placement{
				SandboxID: "sb-reused-delete", OwnerNodeID: "node-new", IncarnationID: "inc-new",
				SecretRecipients: []string{"node-new", "node-new-backup"},
			},
		},
		testSecretPeerPusher: &fakePeerPusher{},
	}
	if err := svc.DeleteClusterSecrets(ctx, "sb-reused-delete", "inc-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-reused-delete", "inc-old"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("old local lifecycle ciphertext remains: %v", err)
	}
	if rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-reused-delete", "inc-new"); err != nil || rec == nil {
		t.Fatalf("new remote lifecycle ciphertext was deleted: rec=%+v err=%v", rec, err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-reused-delete", "inc-new"); err != nil || rec != nil {
		t.Fatalf("new remote lifecycle received delete work: rec=%+v err=%v", rec, err)
	}
}

func TestDeleteClusterSecretsRecoversRecipientsFromExactPlacement(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{
		cfg:   config.Config{EnableCluster: true},
		store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""),
			placement: cluster.Placement{
				SandboxID: "sb-placement-delete", OwnerNodeID: "node-a", IncarnationID: "inc-live",
				SecretRecipients: []string{"node-a", "node-b"},
			},
		},
	}
	// Simulate a retry after the local ciphertext and PUT outbox disappeared.
	// The authoritative exact lifecycle still carries the remote cleanup set.
	if err := svc.DeleteClusterSecrets(ctx, "sb-placement-delete", "inc-live"); err != nil {
		t.Fatal(err)
	}
	outbox, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-placement-delete", "inc-live")
	if err != nil || outbox == nil || len(outbox.Recipients) != 1 || outbox.Recipients[0] != "node-b" {
		t.Fatalf("placement-backed delete outbox = %+v, err=%v", outbox, err)
	}
}

func TestPeerDeleteCleansExactOldLifecycleDespiteReusedPlacement(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-peer-delete-reuse", "inc-old", 4, []string{"node-a", "node-b"})
	putSecretRow(t, st, "sb-peer-delete-reuse", "inc-new", 1, []string{"node-a", "node-c"})
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-b", "http://b", ""),
			placement: cluster.Placement{
				SandboxID: "sb-peer-delete-reuse", OwnerNodeID: "node-a", IncarnationID: "inc-new",
			},
		},
	}
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb-peer-delete-reuse", "inc-old", 4); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-peer-delete-reuse", "inc-old"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("old lifecycle ciphertext remains after acknowledged peer delete: %v", err)
	}
	if rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-peer-delete-reuse", "inc-new"); err != nil || rec == nil {
		t.Fatalf("current lifecycle was affected: rec=%+v err=%v", rec, err)
	}
}

type generationBumpPusher struct {
	sandboxID     string
	incarnationID string
}

func (*generationBumpPusher) PushSecretBlobToPeers(context.Context, secrets.SecretBlob, []string) ([]string, error) {
	return nil, nil
}

func (*generationBumpPusher) DeleteSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func (p *generationBumpPusher) ProbeSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	resetSecretHoldersForGeneration(p.sandboxID, p.incarnationID, 2, "node-a")
	setSecretHolderTargets(p.sandboxID, p.incarnationID, 2, []string{"node-a", "node-c"})
	return []string{"node-b"}, nil
}

type partialDeletePusher struct{}

func (*partialDeletePusher) PushSecretBlobToPeers(context.Context, secrets.SecretBlob, []string) ([]string, error) {
	return nil, nil
}

func (*partialDeletePusher) DeleteSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return []string{"node-b"}, errors.New("node-c response lost")
}

func (*partialDeletePusher) ProbeSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func TestClusterSecretLifecycleGuardsAndProviderFallback(t *testing.T) {
	ctx := context.Background()
	var nilService *Service
	if nilService.provider() != nil || nilService.selfNodeID() != "" {
		t.Fatal("nil service exposed secret state")
	}
	if err := nilService.deleteClusterSecretsOriginator(ctx, "sb", "inc-test", nil); err != nil {
		t.Fatalf("nil originator delete = %v", err)
	}
	if err := nilService.DeleteClusterSecretsLocal(ctx, "sb", "inc-test", 1); err != nil {
		t.Fatalf("nil local delete = %v", err)
	}
	if err := nilService.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatalf("nil delete reconcile = %v", err)
	}
	if err := nilService.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatalf("nil put reconcile = %v", err)
	}
	nilService.refreshSecretLifecycleMetrics(ctx)
	nilService.refreshSecretHolderPossession(ctx)
	if got := nilService.aliveMemberSet(); len(got) != 0 {
		t.Fatalf("nil alive members = %v", got)
	}
	if err := nilService.expandAndResealDeadSecretTargets(ctx, "sb"); err != nil {
		t.Fatalf("nil reseal = %v", err)
	}
	if err := nilService.finalizeResealedSecret(ctx, nil, cluster.Placement{}, nil); err != nil {
		t.Fatalf("nil finalization = %v", err)
	}
	if err := nilService.persistSecretPutOutboxRecipients(ctx, "sb", "inc", []string{"node-b"}, 1); err == nil {
		t.Fatal("nil service accepted a durable outbox update")
	}
	nilService.maybeAsyncDeleteFanout(" ", " ")
	if mapKeys(nil) != nil {
		t.Fatal("empty holder map did not return nil")
	}

	redacted := models.CreateSandboxRequest{Image: "alpine"}
	if got, err := (&Service{}).OpenClusterSecretsForNode(ctx, "sb", redacted, cluster.PlacementSecrets{}, "node-a"); err != nil || got.Image != "alpine" {
		t.Fatalf("empty secret handle = (%+v, %v)", got, err)
	}
	if _, err := (&Service{}).OpenClusterSecretsForNode(ctx, "", redacted, cluster.PlacementSecrets{Ref: secrets.FormatRef("sb-ref", "inc-test", 1), Version: 1, IncarnationID: "inc-test", SealGeneration: 1}, ""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("storeless open error = %v", err)
	}
	staleProvider := &secretProviderStub{bag: secrets.Secrets{Env: map[string]string{"TOKEN": "old-tenant"}}}
	staleService := &Service{secretProvider: staleProvider}
	if _, err := staleService.OpenClusterSecretsForNode(ctx, "sb-reused", redacted, cluster.PlacementSecrets{
		Ref:            secrets.FormatRef("sb-reused", "inc-old", secrets.RefVersion),
		Version:        secrets.RefVersion,
		IncarnationID:  "inc-current",
		SealGeneration: 1,
	}, "node-a"); !errors.Is(err, secrets.ErrVersionMismatch) || staleProvider.openCalls != 0 {
		t.Fatalf("stale lifecycle open = %v, provider calls=%d", err, staleProvider.openCalls)
	}

	provider := &secretProviderStub{deleteErr: errors.New("delete failed")}
	svc := &Service{secretProvider: provider}
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb-local", "inc-local", 1); !errors.Is(err, provider.deleteErr) || provider.deleteCalls != 1 {
		t.Fatalf("provider local delete calls=%d err=%v", provider.deleteCalls, err)
	}
	provider.deleteErr = nil
	if err := svc.deleteClusterSecretsOriginator(ctx, "sb-origin", "inc-origin", nil); err != nil || provider.deleteCalls != 2 {
		t.Fatalf("provider origin delete calls=%d err=%v", provider.deleteCalls, err)
	}

	configuredNoCluster := &Service{cfg: config.Config{SecretAuditRetentionDays: 1}}
	if err := configuredNoCluster.pruneClusterAuditACL(ctx); err != nil {
		t.Fatalf("clusterless ACL prune = %v", err)
	}
	configuredNoCluster.refreshSecretHolderPossession(nil)
	if err := configuredNoCluster.expandAndResealDeadSecretTargets(ctx, "sb"); err != nil {
		t.Fatalf("clusterless reseal = %v", err)
	}
}

func TestValidateClusterIsolateBundleReferenceContract(t *testing.T) {
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "hook",
	}); err == nil {
		t.Fatal("unbound cluster isolate ref was accepted")
	}
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate,
	}); err != nil {
		t.Fatalf("missing ref should be left to create validation: %v", err)
	}
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: models.JSBundleRefForNode("sha256:abc", "isolate-a"),
	}); err != nil {
		t.Fatalf("node-bound cluster isolate ref rejected: %v", err)
	}
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime: models.RuntimeDocker, Image: "alpine",
	}); err != nil {
		t.Fatalf("non-isolate request rejected: %v", err)
	}
}

func TestSecretProviderCanaryMetricReflectsLatestProbe(t *testing.T) {
	recordSecretProviderCanary(false)
	if secretProviderCanaryOK.Value() != 0 {
		t.Fatal("failed provider canary remained healthy")
	}
	recordSecretProviderCanary(true)
	if secretProviderCanaryOK.Value() != 1 {
		t.Fatal("successful provider canary remained unhealthy")
	}
}

func putSecretRow(t *testing.T, st *storepkg.Store, sandboxID, incarnationID string, generation int64, recipients []string) {
	t.Helper()
	if _, err := st.PutClusterSecret(context.Background(), storepkg.ClusterSecretRecord{
		Ref: secrets.FormatRef(sandboxID, incarnationID, secrets.RefVersion), SandboxID: sandboxID,
		Version: secrets.RefVersion, Recipients: append([]string(nil), recipients...),
		SealedPayload: []byte("sealed"), SealGeneration: generation,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("put secret row %s: %v", sandboxID, err)
	}
}

func TestPutAndDeleteOutboxFailurePathsRemainDurable(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{store: st, cluster: cluster.NewNoop("node-a", "http://a", "")}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatalf("transportless put reconcile = %v", err)
	}
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatalf("transportless delete reconcile = %v", err)
	}

	if err := st.UpsertSecretPutOutbox(ctx, "sb-missing", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.testSecretPeerPusher = &fakePeerPusher{}
	svc.reconcileSecretPutOutboxIncarnation(nil, "sb-missing", "inc-a")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-missing", "inc-a"); err != nil || rec == nil || rec.Attempts != 1 {
		t.Fatalf("missing-row put job was not retained: rec=%+v err=%v", rec, err)
	}

	putSecretRow(t, st, "sb-stale", "inc-a", 2, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-stale", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-stale", "inc-a")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-stale", "inc-a"); err != nil || rec != nil {
		t.Fatalf("stale put job not discarded: rec=%+v err=%v", rec, err)
	}

	putSecretRow(t, st, "sb-local-behind", "inc-a", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-local-behind", "inc-a", 2, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-local-behind", "inc-a")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-local-behind", "inc-a"); err != nil || rec == nil || rec.Attempts != 1 {
		t.Fatalf("newer put obligation was not retained over older ciphertext: rec=%+v err=%v", rec, err)
	}

	putSecretRow(t, st, "sb-self", "inc-a", 1, []string{"node-a"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-self", "inc-a", 1, []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-self", "inc-a")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-self", "inc-a"); err != nil || rec != nil {
		t.Fatalf("self-only put job not drained: rec=%+v err=%v", rec, err)
	}

	putSecretRow(t, st, "sb-partial", "inc-a", 1, []string{"node-a", "node-b", "node-c"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-partial", "inc-a", 1, []string{"node-b", "node-c"}); err != nil {
		t.Fatal(err)
	}
	pushFailure := errors.New("node-c unavailable")
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.testSecretPeerPusher = &fakePeerPusher{acked: []string{"node-b"}, pushErr: pushFailure}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-partial", "inc-a")
	remaining, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-partial", "inc-a")
	if err != nil || remaining == nil || len(remaining.Recipients) != 1 || remaining.Recipients[0] != "node-c" {
		t.Fatalf("partial put obligation = %+v err=%v", remaining, err)
	}

	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-delete-self", "inc-self", []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretDeleteOutboxIncarnation(nil, "sb-delete-self", "inc-self")
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-delete-self", "inc-self"); err != nil || rec != nil {
		t.Fatalf("self-only delete job not drained: rec=%+v err=%v", rec, err)
	}

	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-delete-fail", "inc-fail", []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	deleteFailure := errors.New("peer delete unavailable")
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: deleteFailure}
	svc.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-delete-fail", "inc-fail")
	deleteRow, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-delete-fail", "inc-fail")
	if err != nil || deleteRow == nil || len(deleteRow.Recipients) != 1 {
		t.Fatalf("failed delete obligation lost: rec=%+v err=%v", deleteRow, err)
	}
}

func TestDeleteOutboxDerivesPendingOnlyFromACKs(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-delete-acks", "inc-acks", []string{"node-b", "node-c"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		store: st, cluster: cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: &partialDeletePusher{},
	}
	svc.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-delete-acks", "inc-acks")
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-delete-acks", "inc-acks")
	if err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "node-c" {
		t.Fatalf("unacknowledged delete obligation lost: rec=%+v err=%v", rec, err)
	}
}

func TestPutOutboxPlacementReadFailureCannotRetireLiveCiphertext(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-put-placement-down", "inc-live", 4, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put-placement-down", "inc-live", 4, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true},
		store:                st,
		cluster:              &unavailablePlacementSnapshotCluster{Noop: cluster.NewNoop("node-a", "http://a", "")},
		testSecretPeerPusher: &fakePeerPusher{},
	}
	if err := svc.ReconcileSecretPutOutbox(ctx); err == nil {
		t.Fatal("authoritative placement failure was not reported")
	}
	if rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-put-placement-down", "inc-live"); err != nil || rec == nil {
		t.Fatalf("live ciphertext was retired on ambiguous placement read: rec=%+v err=%v", rec, err)
	}
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-put-placement-down", "inc-live"); err != nil || rec == nil || rec.Attempts != 1 {
		t.Fatalf("put obligation was not retained and deferred: rec=%+v err=%v", rec, err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-put-placement-down", "inc-live"); err != nil || rec != nil {
		t.Fatalf("ambiguous placement read created destructive work: rec=%+v err=%v", rec, err)
	}
}

func TestReservedSealPlacementReadFailureCannotFallBackToSelf(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, cipher: cipher, store: st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        &unavailablePlacementSnapshotCluster{Noop: cluster.NewNoop("node-a", "http://a", "")},
	}
	_, err := svc.ReservedSecretBinding(ctx, "sb-reserved-placement-down")
	if err == nil {
		t.Fatal("reserved seal fell back to a non-authoritative recipient set")
	}
	rows, listErr := st.ListClusterSecretsBatch(ctx, "", 2)
	if listErr != nil || len(rows) != 0 {
		t.Fatalf("reserved seal wrote ciphertext before proving placement: rows=%+v err=%v", rows, listErr)
	}
}

func TestPutOutboxStopsOriginatingAfterOwnershipReassignment(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-put-reassigned", "inc-live", 2, []string{"node-old", "node-new"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put-reassigned", "inc-live", 2, []string{"node-new"}); err != nil {
		t.Fatal(err)
	}
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-old", "http://old", ""),
			placement: cluster.Placement{
				SandboxID: "sb-put-reassigned", OwnerNodeID: "node-new", IncarnationID: "inc-live",
				SecretRecipients: []string{"node-old", "node-new"}, SecretSealGeneration: 2,
			},
		},
		testSecretPeerPusher: pusher,
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-put-reassigned", "inc-live")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-put-reassigned", "inc-live"); err != nil || rec != nil {
		t.Fatalf("former-owner PUT obligation remains: rec=%+v err=%v", rec, err)
	}
	if rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-put-reassigned", "inc-live"); err != nil || rec == nil {
		t.Fatalf("valid backup ciphertext was retired on reassignment: rec=%+v err=%v", rec, err)
	}
	pusher.mu.Lock()
	pushes := pusher.pushCalls
	pusher.mu.Unlock()
	if pushes != 0 {
		t.Fatalf("former owner originated %d peer PUTs", pushes)
	}
}

func TestStagedRetirementPlacementReadFailureCannotCreateRecoveryVacuum(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	retired := []string{"node-old"}
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-retire-placement-down", "inc-live", secrets.RefVersion),
		SandboxID: "sb-retire-placement-down", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-new"}, RetireRecipients: &retired,
		SealedPayload: []byte("sealed"), SealGeneration: 5,
	}); err != nil {
		t.Fatal(err)
	}
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true},
		store:                st,
		cluster:              &unavailablePlacementSnapshotCluster{Noop: cluster.NewNoop("node-a", "http://a", "")},
		testSecretPeerPusher: pusher,
	}
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err == nil {
		t.Fatal("authoritative placement failure was not reported")
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-retire-placement-down", "inc-live")
	if err != nil || rec == nil || !rec.AwaitingPromotion || rec.Attempts != 1 {
		t.Fatalf("staged retirement was promoted on ambiguous placement read: rec=%+v err=%v", rec, err)
	}
	pusher.mu.Lock()
	deletes := len(pusher.deletes)
	pusher.mu.Unlock()
	if deletes != 0 {
		t.Fatalf("retired holders were deleted before authoritative promotion: calls=%d", deletes)
	}
}

func TestHolderRefreshRepushesMissingReplicaAndFencesStaleProbe(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID = "sb-refresh-repush"
	putSecretRow(t, st, sandboxID, "inc-a", 3, []string{"node-a", "node-b"})
	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
	resetSecretHoldersForGeneration(sandboxID, "inc-a", 3, "node-a")
	setSecretHolderTargets(sandboxID, "inc-a", 3, []string{"node-a", "node-b"})
	pusher := &fakePeerPusher{probeStrict: true, acked: []string{"node-b"}}
	svc := &Service{
		cfg: config.Config{SecretRecipientBackupCount: 1}, store: st,
		cluster: cluster.NewNoop("node-a", "http://a", ""), testSecretPeerPusher: pusher,
	}
	svc.refreshSecretHolderPossession(ctx)
	pusher.mu.Lock()
	pushes := pusher.pushCalls
	pusher.mu.Unlock()
	if pushes != 1 {
		t.Fatalf("missing holder repushes = %d, want 1", pushes)
	}
	holders := secretHolderNodeIDs(sandboxID, "inc-a")
	sort.Strings(holders)
	if !sameStringSlice(holders, []string{"node-a", "node-b"}) {
		t.Fatalf("holders after repush = %v", holders)
	}

	const racedID = "sb-refresh-generation-race"
	clearSecretFanoutHolders(racedID)
	t.Cleanup(func() { clearSecretFanoutHolders(racedID) })
	resetSecretHoldersForGeneration(racedID, "inc-a", 1, "node-a")
	setSecretHolderTargets(racedID, "inc-a", 1, []string{"node-a", "node-b"})
	raceSvc := &Service{
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: &generationBumpPusher{sandboxID: racedID, incarnationID: "inc-a"},
	}
	raceSvc.refreshSecretHolderPossession(ctx)
	hs := holderSetFor(racedID, "inc-a")
	hs.mu.Lock()
	gen := hs.gen
	_, staleAdded := hs.nodes["node-b"]
	hs.mu.Unlock()
	if gen != 2 || staleAdded {
		t.Fatalf("stale probe crossed generation fence: gen=%d stale=%v", gen, staleAdded)
	}
}

func TestResealFailureWindowsNeverPublishAnUnrecoverableGeneration(t *testing.T) {
	ctx := context.Background()
	const sandboxID = "sb-reseal-failure"
	basePlacement := cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-a",
		SecretRecipients: []string{"node-a", "dead-a", "dead-b"},
		SecretRef:        secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion),
		SecretVersion:    secrets.RefVersion, SecretSealGeneration: 1,
	}

	t.Run("leader coordinates ownerless placement", func(t *testing.T) {
		cl := &resealPlacementCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""), leader: "node-b",
			placement: cluster.Placement{SandboxID: sandboxID, IncarnationID: "inc-a", SecretRecipients: []string{"dead-a"}},
		}
		if err := (&Service{cluster: cl}).expandAndResealDeadSecretTargets(ctx, sandboxID); err != nil {
			t.Fatalf("non-leader ownerless reseal = %v", err)
		}
	})

	t.Run("no live replacement", func(t *testing.T) {
		cl := &resealPlacementCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""), placement: basePlacement,
			members: []cluster.Member{{NodeID: "dead-a", Alive: false, Role: config.NodeRoleWorker}},
		}
		svc := &Service{cfg: config.Config{SecretRecipientBackupCount: 2}, cluster: cl}
		clearSecretFanoutHolders(sandboxID)
		resetSecretHoldersForGeneration(sandboxID, basePlacement.IncarnationID, 1, "node-a")
		setSecretHolderTargets(sandboxID, basePlacement.IncarnationID, 1, basePlacement.SecretRecipients)
		if err := svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err == nil || !strings.Contains(err.Error(), "no live") {
			t.Fatalf("no-replacement reseal error = %v", err)
		}
		clearSecretFanoutHolders(sandboxID)
	})

	t.Run("owner-only replacement cannot downgrade HA", func(t *testing.T) {
		cl := &resealPlacementCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""), placement: basePlacement,
			members: []cluster.Member{{NodeID: "node-a", Alive: true, Role: config.NodeRoleMixed}},
		}
		st := openSealTestStore(t)
		cipher := newTestCipher(t)
		svc := &Service{
			cfg: config.Config{SecretRecipientBackupCount: 2}, cipher: cipher, store: st, cluster: cl,
			secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		}
		sealCtx := secrets.ContextWithIncarnationID(ctx, "inc-a")
		handle, err := svc.secretProvider.Put(sealCtx, sandboxID, secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}, basePlacement.SecretRecipients)
		if err != nil {
			t.Fatal(err)
		}
		cl.mu.Lock()
		cl.placement.SecretRef = handle.Ref
		cl.placement.SecretVersion = handle.Version
		cl.placement.SecretSealGeneration = handle.SealGeneration
		cl.mu.Unlock()
		clearSecretFanoutHolders(sandboxID)
		resetSecretHoldersForGeneration(sandboxID, basePlacement.IncarnationID, handle.SealGeneration, "node-a")
		setSecretHolderTargets(sandboxID, basePlacement.IncarnationID, handle.SealGeneration, basePlacement.SecretRecipients)
		if err := svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err == nil || !strings.Contains(err.Error(), "replacement backup") {
			t.Fatalf("owner-only reseal error = %v", err)
		}
		cl.mu.Lock()
		updates := cl.updateCalls
		publishedGen := cl.placement.SecretSealGeneration
		cl.mu.Unlock()
		if updates != 0 || publishedGen != handle.SealGeneration {
			t.Fatalf("owner-only generation was published: updates=%d gen=%d", updates, publishedGen)
		}
		clearSecretFanoutHolders(sandboxID)
	})

	t.Run("missing local ciphertext", func(t *testing.T) {
		cl := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placement: basePlacement}
		cl.placement.SecretRef = ""
		cl.placement.SecretSealGeneration = 0
		st := openSealTestStore(t)
		svc := &Service{
			cfg: config.Config{SecretRecipientBackupCount: 2}, cluster: cl, store: st,
			secretProvider: &secretProviderStub{bag: secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}},
		}
		clearSecretFanoutHolders(sandboxID)
		resetSecretHoldersForGeneration(sandboxID, basePlacement.IncarnationID, 1, "node-a")
		setSecretHolderTargets(sandboxID, basePlacement.IncarnationID, 1, basePlacement.SecretRecipients)
		if err := svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err == nil || !strings.Contains(err.Error(), "no local sealed") {
			t.Fatalf("missing ciphertext reseal error = %v", err)
		}
		clearSecretFanoutHolders(sandboxID)
	})

	for _, tc := range []struct {
		name       string
		provider   *secretProviderStub
		wantErr    string
		wantUpdate int
	}{
		{name: "open failure", provider: &secretProviderStub{openErr: errors.New("decrypt unavailable")}, wantErr: "open for reseal"},
		{name: "empty decrypted bag", provider: &secretProviderStub{}, wantUpdate: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placement: basePlacement}
			st := openSealTestStore(t)
			svc := &Service{
				cfg: config.Config{SecretRecipientBackupCount: 2}, cluster: cl, store: st,
				secretProvider: tc.provider,
			}
			clearSecretFanoutHolders(sandboxID)
			resetSecretHoldersForGeneration(sandboxID, basePlacement.IncarnationID, 1, "node-a")
			setSecretHolderTargets(sandboxID, basePlacement.IncarnationID, 1, basePlacement.SecretRecipients)
			err := svc.expandAndResealDeadSecretTargets(ctx, sandboxID)
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("reseal error = %v, want %q", err, tc.wantErr)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("empty-bag reseal = %v", err)
			}
			cl.mu.Lock()
			updates := cl.updateCalls
			cl.mu.Unlock()
			if updates != tc.wantUpdate {
				t.Fatalf("Raft updates = %d, want %d", updates, tc.wantUpdate)
			}
			clearSecretFanoutHolders(sandboxID)
		})
	}

	for _, tc := range []struct {
		name   string
		pusher *fakePeerPusher
	}{
		{name: "transport unavailable"},
		{name: "no backup acknowledgement", pusher: &fakePeerPusher{probeStrict: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placement: basePlacement}
			st := openSealTestStore(t)
			cipher := newTestCipher(t)
			svc := &Service{
				cfg: config.Config{SecretRecipientBackupCount: 2}, cipher: cipher, store: st, cluster: cl,
				secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
			}
			if tc.pusher != nil {
				svc.testSecretPeerPusher = tc.pusher
			}
			sealCtx := secrets.ContextWithIncarnationID(ctx, "inc-a")
			handle, err := svc.secretProvider.Put(sealCtx, sandboxID, secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}, basePlacement.SecretRecipients)
			if err != nil {
				t.Fatalf("seed seal: %v", err)
			}
			cl.mu.Lock()
			cl.placement.SecretRef = handle.Ref
			cl.placement.SecretVersion = handle.Version
			cl.placement.SecretSealGeneration = handle.SealGeneration
			cl.mu.Unlock()
			clearSecretFanoutHolders(sandboxID)
			resetSecretHoldersForGeneration(sandboxID, basePlacement.IncarnationID, handle.SealGeneration, "node-a")
			setSecretHolderTargets(sandboxID, basePlacement.IncarnationID, handle.SealGeneration, basePlacement.SecretRecipients)
			err = svc.expandAndResealDeadSecretTargets(ctx, sandboxID)
			if err == nil {
				t.Fatal("unreplicated generation was published")
			}
			cl.mu.Lock()
			updates := cl.updateCalls
			publishedGen := cl.placement.SecretSealGeneration
			cl.mu.Unlock()
			if updates != 0 || publishedGen != handle.SealGeneration {
				t.Fatalf("unacknowledged generation published: updates=%d gen=%d old=%d", updates, publishedGen, handle.SealGeneration)
			}
			row, loadErr := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, "inc-a")
			if loadErr != nil || row == nil || len(row.Recipients) == 0 {
				t.Fatalf("staged generation lost durable replication work: row=%+v err=%v", row, loadErr)
			}
			clearSecretFanoutHolders(sandboxID)
		})
	}
}
