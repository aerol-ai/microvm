package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type fakePeerPusher struct {
	mu            sync.Mutex
	pushes        []secrets.SecretBlob
	deletes       []string
	pushErr       error
	deleteErr     error
	acked         []string
	probeHolding  []string
	probeErr      error
	probeStrict   bool // when true, Probe returns probeHolding only (ignore recipients)
	probeCalls    int
	probeByID     map[string]int
	pushCalls     int
	deletePending bool
	done          chan struct{}
}

type blockingRefanoutPusher struct {
	active  atomic.Int64
	max     atomic.Int64
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (p *blockingRefanoutPusher) PushSecretBlobToPeers(context.Context, secrets.SecretBlob, []string) ([]string, error) {
	active := p.active.Add(1)
	for {
		prior := p.max.Load()
		if active <= prior || p.max.CompareAndSwap(prior, active) {
			break
		}
	}
	p.calls.Add(1)
	p.started <- struct{}{}
	<-p.release
	p.active.Add(-1)
	return []string{"node-b"}, nil
}

func (*blockingRefanoutPusher) DeleteSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func (*blockingRefanoutPusher) ProbeSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func (f *fakePeerPusher) PushSecretBlobToPeers(_ context.Context, blob secrets.SecretBlob, _ []string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushCalls++
	f.pushes = append(f.pushes, blob)
	if f.done != nil {
		select {
		case <-f.done:
		default:
			close(f.done)
		}
	}
	return append([]string(nil), f.acked...), f.pushErr
}

func waitForSecretCreateFanoutIdle(t *testing.T, sandboxID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		active := false
		secretCreateFanoutInflight.Range(func(key, _ any) bool {
			if holderKey, ok := key.(secretHolderKey); ok && holderKey.sandboxID == sandboxID {
				active = true
				return false
			}
			return true
		})
		if !active {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for create fan-out to finish for %s", sandboxID)
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *fakePeerPusher) DeleteSecretOnPeers(_ context.Context, sandboxID, _ string, recipients []string, _ int64) (acked []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, sandboxID)
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	if f.deletePending {
		return nil, nil
	}
	return append([]string(nil), recipients...), nil
}

func (f *fakePeerPusher) ProbeSecretOnPeers(_ context.Context, sandboxID, _ string, recipients []string, _ int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeCalls++
	if f.probeByID == nil {
		f.probeByID = make(map[string]int)
	}
	f.probeByID[sandboxID]++
	if f.probeStrict {
		return append([]string(nil), f.probeHolding...), f.probeErr
	}
	if len(f.acked) > 0 {
		return append([]string(nil), f.acked...), f.probeErr
	}
	return append([]string(nil), recipients...), f.probeErr
}

func TestReconcileSecretDeleteOutboxDrainsBeyondOneWorkerWave(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	const total = deleteReconcileWorkers*2 + 7
	ctx := context.Background()
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("sb-delete-backlog-%03d", i)
		if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, id, "inc-1", []string{"node-b"}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg:                  config.Config{},
		store:                st,
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	remaining, err := st.ListSecretDeleteOutboxBatch(ctx, total+1)
	if err != nil {
		t.Fatalf("list remaining: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("remaining outbox rows = %d, want 0", len(remaining))
	}
	pusher.mu.Lock()
	deletes := len(pusher.deletes)
	pusher.mu.Unlock()
	if deletes != total {
		t.Fatalf("peer deletes = %d, want %d", deletes, total)
	}
}

func TestReconcileSecretDeleteOutboxDeferredRowsDoNotStarveReadyWork(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	retired := []string{"retired-peer"}
	for i := 0; i < secretDeleteReconcileBatch; i++ {
		id := fmt.Sprintf("sb-staged-%04d", i)
		if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
			Ref: secrets.FormatRef(id, "inc-1", secrets.RefVersion), SandboxID: id, Version: secrets.RefVersion,
			Recipients: []string{"node-a", "replacement-peer"}, SealedPayload: []byte("sealed"),
			SealGeneration: 2, RetireRecipients: &retired,
		}); err != nil {
			t.Fatalf("stage %s: %v", id, err)
		}
	}
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-ready-delete", "inc-ready", []string{"ready-peer"}); err != nil {
		t.Fatalf("seed ready delete: %v", err)
	}
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: cluster.NewNoop("node-a", "http://a", ""), testSecretPeerPusher: pusher,
	}
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-ready-delete", "inc-ready"); err != nil || rec != nil {
		t.Fatalf("ready delete was starved: rec=%+v err=%v", rec, err)
	}
	pusher.mu.Lock()
	deletes := append([]string(nil), pusher.deletes...)
	pusher.mu.Unlock()
	if !slices.Contains(deletes, "sb-ready-delete") {
		t.Fatalf("ready delete was not attempted: %v", deletes)
	}
}

func TestReconcileSecretDeleteOutboxRetainsDecommissionedRecipients(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-retired", "inc-retired", []string{"retired-node"}); err != nil {
		t.Fatalf("seed outbox: %v", err)
	}
	pusher := &fakePeerPusher{deletePending: true}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true},
		store:                st,
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	svc.reconcileSecretDeleteOutboxIncarnation(context.Background(), "sb-retired", "inc-retired")
	remaining, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-retired", "inc-retired")
	if err != nil {
		t.Fatalf("get outbox: %v", err)
	}
	if remaining == nil || !sameStringSlice(remaining.Recipients, []string{"retired-node"}) {
		t.Fatalf("decommissioned recipient cleanup obligation was lost: %+v", remaining)
	}
	pusher.mu.Lock()
	deletes := len(pusher.deletes)
	pusher.mu.Unlock()
	if deletes != 1 {
		t.Fatalf("peer delete attempts = %d, want 1 with recipient retained pending", deletes)
	}
}

func TestRefreshSecretHolderPossessionRetriesAfterProbeFailure(t *testing.T) {
	clearSecretFanoutHolders("sb-probe-retry")
	t.Cleanup(func() { clearSecretFanoutHolders("sb-probe-retry") })
	pusher := &fakePeerPusher{probeStrict: true, probeErr: errors.New("temporary partition")}
	svc := &Service{
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	resetSecretHoldersForGeneration("sb-probe-retry", "inc-probe-retry", 7, "node-a", "node-b")
	setSecretHolderTargets("sb-probe-retry", "inc-probe-retry", 7, []string{"node-a", "node-b"})
	hs := holderSetFor("sb-probe-retry", "inc-probe-retry")
	hs.mu.Lock()
	hs.nodes["node-b"] = time.Now().Add(-secretHolderACKTTL)
	hs.mu.Unlock()

	svc.refreshSecretHolderPossession(context.Background())
	hs.mu.Lock()
	_, targetKept := hs.targets["node-b"]
	hs.mu.Unlock()
	if !targetKept {
		t.Fatal("failed probe erased intended recipient")
	}

	// Simulate readiness pruning the expired ACK, then let the peer recover.
	_ = secretHolderNodeIDs("sb-probe-retry", "inc-probe-retry")
	pusher.mu.Lock()
	pusher.probeErr = nil
	pusher.probeHolding = []string{"node-b"}
	pusher.mu.Unlock()
	svc.refreshSecretHolderPossession(context.Background())

	hs.mu.Lock()
	_, recovered := hs.nodes["node-b"]
	hs.mu.Unlock()
	if !recovered {
		t.Fatal("recovered peer was not re-probed after its ACK expired")
	}
}

func TestSecretHolderCacheFencesReusedSandboxLifecycle(t *testing.T) {
	const sandboxID = "sb-holder-reuse"
	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })

	resetSecretHoldersForGeneration(sandboxID, "inc-old", 7, "node-a", "node-b")
	resetSecretHoldersForGeneration(sandboxID, "inc-new", 1, "node-a")
	setSecretHolderTargets(sandboxID, "inc-new", 1, []string{"node-a", "node-c"})

	// A delayed old ACK must remain isolated from the replacement even though
	// both lifecycles reuse the same sandbox ID.
	addSecretHolderNodes(sandboxID, "inc-old", 7, "node-c")
	if got := secretHolderCount(sandboxID, "inc-new"); got != 1 {
		t.Fatalf("replacement holders = %d, want only its local copy", got)
	}
	if got := secretHolderGeneration(sandboxID, "inc-new"); got != 1 {
		t.Fatalf("replacement generation = %d, want 1", got)
	}

	// A stale same-incarnation reset cannot roll generation 2 back to 1.
	resetSecretHoldersForGeneration(sandboxID, "inc-new", 2, "node-a")
	resetSecretHoldersForGeneration(sandboxID, "inc-new", 1, "node-b")
	if got := secretHolderGeneration(sandboxID, "inc-new"); got != 2 {
		t.Fatalf("stale reset rolled generation back to %d", got)
	}
	if holders := secretHolderNodeIDs(sandboxID, "inc-new"); len(holders) != 1 || holders[0] != "node-a" {
		t.Fatalf("stale reset mutated replacement holders: %v", holders)
	}

	clearSecretFanoutHoldersForIncarnation(sandboxID, "inc-old")
	if got := secretHolderGeneration(sandboxID, "inc-new"); got != 2 {
		t.Fatalf("old lifecycle cleanup erased replacement generation: %d", got)
	}
}

func TestRefreshSecretHolderPossessionSkipsFreshACK(t *testing.T) {
	clearSecretFanoutHolders("sb-probe-fresh")
	t.Cleanup(func() { clearSecretFanoutHolders("sb-probe-fresh") })
	pusher := &fakePeerPusher{probeStrict: true, probeHolding: []string{"node-b"}}
	svc := &Service{
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	resetSecretHoldersForGeneration("sb-probe-fresh", "inc-probe-fresh", 8, "node-a", "node-b")
	setSecretHolderTargets("sb-probe-fresh", "inc-probe-fresh", 8, []string{"node-a", "node-b"})
	svc.refreshSecretHolderPossession(context.Background())
	pusher.mu.Lock()
	calls := pusher.probeByID["sb-probe-fresh"]
	pusher.mu.Unlock()
	if calls != 0 {
		t.Fatalf("fresh ACK probes for sandbox=%d, want 0", calls)
	}
}

func TestRefreshSecretHolderPossessionBatchIsFair(t *testing.T) {
	pusher := &fakePeerPusher{}
	svc := &Service{
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	const total = secretHolderRefreshBatch + 1
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("sb-fair-%04d", i)
		ids = append(ids, id)
		resetSecretHoldersForGeneration(id, "inc-"+id, 1, "node-a", "node-b")
		setSecretHolderTargets(id, "inc-"+id, 1, []string{"node-a", "node-b"})
		hs := holderSetFor(id, "inc-"+id)
		hs.mu.Lock()
		hs.nodes["node-b"] = time.Now().Add(-secretHolderACKTTL)
		hs.mu.Unlock()
	}
	t.Cleanup(func() {
		for _, id := range ids {
			clearSecretFanoutHolders(id)
		}
	})

	svc.refreshSecretHolderPossession(context.Background())
	pusher.mu.Lock()
	firstCalls := pusher.probeCalls
	lastFirst := pusher.probeByID[ids[len(ids)-1]]
	pusher.mu.Unlock()
	if firstCalls != secretHolderRefreshBatch || lastFirst != 0 {
		t.Fatalf("first refresh calls=%d last=%d, want %d and 0", firstCalls, lastFirst, secretHolderRefreshBatch)
	}
	lastHolder := holderSetFor(ids[len(ids)-1], "inc-"+ids[len(ids)-1])
	lastHolder.mu.Lock()
	lastExpandFirst := lastHolder.lastExpand
	lastHolder.mu.Unlock()
	if !lastExpandFirst.IsZero() {
		t.Fatalf("deferred reseal candidate was attempted in the first bounded batch: %v", lastExpandFirst)
	}

	svc.refreshSecretHolderPossession(context.Background())
	pusher.mu.Lock()
	lastSecond := pusher.probeByID[ids[len(ids)-1]]
	pusher.mu.Unlock()
	if lastSecond != 1 {
		t.Fatalf("deferred holder probes=%d, want 1 on next fair pass", lastSecond)
	}
	lastHolder.mu.Lock()
	lastExpandSecond := lastHolder.lastExpand
	lastHolder.mu.Unlock()
	if lastExpandSecond.IsZero() {
		t.Fatal("deferred reseal candidate starved behind the first bounded batch")
	}
}

func openSealTestStore(t *testing.T) *storepkg.Store {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestUpsertClusterSecretBlobValidatesRecipientAndRef(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		cfg:    config.Config{},
		store:  st,
		cipher: cipher,
	}
	svc.AttachCluster(cluster.NewNoop("node-b", "http://b", ""))

	bag := secrets.Secrets{Registry: &models.RegistryAuth{Password: "p"}}
	binding := secrets.SealBinding{SandboxID: "sb-ok", IncarnationID: "inc-current", Ref: secrets.FormatRef("sb-ok", "inc-current", 1), Version: 1, Generation: 1}
	sealed, err := secrets.SealEnvelopeBound(cipher, bag, []string{"node-a", "node-b"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	ok := secrets.SecretBlob{
		Ref: secrets.FormatRef("sb-ok", "inc-current", 1), SandboxID: "sb-ok", IncarnationID: "inc-current", Version: 1,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: sealed, SealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, ok, "node-a"); err != nil {
		t.Fatalf("valid upsert: %v", err)
	}
	missingGeneration := ok
	missingGeneration.SealGeneration = 0
	if err := svc.UpsertClusterSecretBlob(ctx, missingGeneration, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("missing wire generation = %v, want ErrInvalidClusterSecretBlob", err)
	}

	badRef := ok
	badRef.Ref = secrets.FormatRef("other", "inc-current", 1)
	if err := svc.UpsertClusterSecretBlob(ctx, badRef, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("bad ref = %v, want ErrInvalidClusterSecretBlob", err)
	}

	// Older unbound envelope versions are rejected at peer ingress.
	legacy := []byte(`{"version":3,"recipients":["node-a","node-b"],"wrapped_key":"YQ==","payload":"YQ=="}`)
	v3 := secrets.SecretBlob{
		Ref: secrets.FormatRef("sb-v3", "inc-current", 1), SandboxID: "sb-v3", IncarnationID: "inc-current", Version: 1,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: legacy, SealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, v3, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("unbound v3 upsert = %v, want ErrInvalidClusterSecretBlob", err)
	}

	foreign, err := secrets.SealEnvelopeBound(cipher, bag, []string{"node-a", "node-c"}, secrets.SealBinding{
		SandboxID: "sb-deny", IncarnationID: "inc-current", Ref: secrets.FormatRef("sb-deny", "inc-current", 1), Version: 1, Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	denied := secrets.SecretBlob{
		Ref: secrets.FormatRef("sb-deny", "inc-current", 1), SandboxID: "sb-deny", IncarnationID: "inc-current", Version: 1,
		Recipients: []string{"node-a", "node-c"}, SealedPayload: foreign, SealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, denied, "node-a"); !errors.Is(err, secrets.ErrRecipientDenied) {
		t.Fatalf("non-recipient = %v, want ErrRecipientDenied", err)
	}

	// Empty authenticated ref must be rejected even when sandbox_id is set.
	if _, err := secrets.SealEnvelopeBound(cipher, bag, []string{"node-a", "node-b"}, secrets.SealBinding{
		SandboxID: "sb-empty-ref", IncarnationID: "inc-current", Ref: "", Version: 1, Generation: 1,
	}); err == nil {
		t.Fatal("empty authenticated ref was accepted")
	}
}

func TestSealAndDistributeFailsClosedWithoutProvider(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}

	s := &Service{}
	if _, err := s.SealAndDistribute(ctx, "sb", req, []string{"n1"}); err == nil {
		t.Fatal("missing provider expected error")
	}
}

func TestSecretDistributionCurrentContractHelpers(t *testing.T) {
	ctx := context.Background()
	var nilService *Service
	if nilService.WantsSecretRecipientFanout(models.CreateSandboxRequest{}) {
		t.Fatal("nil service requested recipient fan-out")
	}
	svc := &Service{}
	if svc.WantsSecretRecipientFanout(models.CreateSandboxRequest{}) {
		t.Fatal("ordinary create requested recipient fan-out")
	}
	if !svc.WantsSecretRecipientFanout(models.CreateSandboxRequest{Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}) {
		t.Fatal("recreate create did not request recipient fan-out")
	}
	req := models.CreateSandboxRequest{
		Env:      map[string]string{"TOKEN": "secret"},
		Registry: &models.RegistryAuth{Password: "secret"},
		Mounts:   []models.MountSpec{{Target: "/data", Credentials: map[string]string{"key": "secret"}}},
	}
	redacted := svc.RedactClusterSecretsConfigured(req)
	if len(redacted.Env) != 0 || redacted.Registry == nil || redacted.Registry.Password != "" || len(redacted.Mounts[0].Credentials) != 0 {
		t.Fatalf("configured redaction leaked credentials: %+v", redacted)
	}
	if ok, err := nilService.HasLocalSealedSecretGeneration(ctx, "sb", "inc", 1); err != nil || ok {
		t.Fatalf("nil generation probe = %v, %v", ok, err)
	}
	st := openSealTestStore(t)
	svc.store = st
	if ok, err := svc.HasLocalSealedSecretGeneration(ctx, "sb", "inc", 0); err == nil || ok {
		t.Fatalf("invalid generation probe = %v, %v", ok, err)
	}
	if ok, err := svc.HasLocalSealedSecretGeneration(ctx, "missing", "inc", 1); err != nil || ok {
		t.Fatalf("missing generation probe = %v, %v", ok, err)
	}
	putSecretRow(t, st, "sb", "inc", 3, []string{"node-a"})
	if ok, err := svc.HasLocalSealedSecretGeneration(ctx, "sb", "inc", 3); err != nil || !ok {
		t.Fatalf("current generation probe = %v, %v", ok, err)
	}
	if ok, err := svc.HasLocalSealedSecretGeneration(ctx, "sb", "inc", 4); err != nil || ok {
		t.Fatalf("future generation probe = %v, %v", ok, err)
	}
}

func TestSealAndDistributeCrossNodeOpenCRITICAL(t *testing.T) {
	// CRITICAL regression: seal on node-A with recipients [A,B], put blob into
	// B's store (simulate fan-out), B opens successfully. Wrong recipient denied.
	ctx := context.Background()
	cipher := newTestCipher(t)
	storeA := openSealTestStore(t)
	storeB := openSealTestStore(t)

	svcA := &Service{
		cfg:                  config.Config{},
		cipher:               cipher,
		store:                storeA,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(storeA)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"node-b"}},
	}
	svcB := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          storeB,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(storeB)),
		cluster:        cluster.NewNoop("node-b", "http://b", ""),
	}

	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "reg.io", Username: "u", Password: "secret-pw"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	handle, err := svcA.SealAndDistribute(ctx, "sb-xnode", req, []string{"node-a", "node-b"})
	if err != nil || handle.Ref == "" {
		t.Fatalf("seal on A: handle=%+v err=%v", handle, err)
	}

	blob, err := newSecretBlobStore(storeA).Get(ctx, handle.Ref)
	if err != nil || blob == nil {
		t.Fatalf("load blob from A: %v", err)
	}
	if err := svcB.UpsertClusterSecretBlob(ctx, *blob, "node-a"); err != nil {
		t.Fatalf("upsert on B: %v", err)
	}

	redacted := RedactClusterSecrets(req)
	merged, err := svcB.OpenClusterSecretsForNode(ctx, "sb-xnode", redacted, handle, "node-b")
	if err != nil {
		t.Fatalf("CRITICAL: node-b open failed: %v", err)
	}
	if merged.Registry == nil || merged.Registry.Password != "secret-pw" {
		t.Fatalf("CRITICAL: node-b password = %v", merged.Registry)
	}

	if _, err := svcB.OpenClusterSecretsForNode(ctx, "sb-xnode", redacted, handle, "node-c"); err == nil || !errors.Is(err, secrets.ErrRecipientDenied) {
		t.Fatalf("wrong recipient = %v, want ErrRecipientDenied", err)
	}
}

func TestSealAndDistributeFansOutWhenHA(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg: config.Config{
			SecretFanoutMinACKWait: 50 * time.Millisecond,
		},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-fan", req, []string{"node-a", "node-b"})
	if err != nil || handle.Ref == "" {
		t.Fatalf("seal: %+v %v", handle, err)
	}
	// Min-ACK wait already called Push synchronously; holders should be ≥2.
	if got := secretHolderCount("sb-fan", handle.IncarnationID); got < 2 {
		t.Fatalf("after min-ACK holders=%d, want >=2", got)
	}
	select {
	case <-pusher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected fan-out push")
	}
	pusher.mu.Lock()
	defer pusher.mu.Unlock()
	if pusher.pushCalls == 0 {
		t.Fatal("pushCalls=0")
	}
}

func TestEnterpriseSealRequiresBackupACKAndRetractsLocalSecret(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg: config.Config{
			EnterpriseMode:         true,
			SecretFanoutMinACKWait: 20 * time.Millisecond,
		},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	if handle, err := svc.SealAndDistribute(ctx, "sb-enterprise-no-ack", req, []string{"node-a", "node-b"}); err == nil || handle.Ref != "" {
		t.Fatalf("enterprise seal = %+v, %v; want no handle and backup-ACK error", handle, err)
	}
	incarnationID := svc.secretIncarnationForSeal("sb-enterprise-no-ack")
	rows, err := st.ListClusterSecretsBatch(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("unreplicated local secret was not retracted: %+v", rows)
	}
	if generation, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-enterprise-no-ack", incarnationID); err != nil || generation == 0 {
		t.Fatalf("retraction tomb generation = %d, %v", generation, err)
	}
	if outbox, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-enterprise-no-ack", incarnationID); err != nil || outbox == nil {
		t.Fatalf("retraction outbox = %+v, %v", outbox, err)
	}
	if putOutbox, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-enterprise-no-ack", incarnationID); err != nil || putOutbox != nil {
		t.Fatalf("retraction left contradictory put obligation = %+v, %v", putOutbox, err)
	}
}

func TestPeerSecretPutRequiresLivePlacementAfterTombGC(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	recipients := []string{"node-a", "node-b"}
	const incarnationID = "inc-no-vacuum"
	ref := secrets.FormatRef("sb-no-vacuum", incarnationID, 1)
	payload, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, recipients, secrets.SealBinding{SandboxID: "sb-no-vacuum", IncarnationID: incarnationID, Ref: ref, Version: 1, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	blob := secrets.SecretBlob{
		Ref: ref, SandboxID: "sb-no-vacuum", IncarnationID: incarnationID, Version: 1, Recipients: recipients,
		SealedPayload: payload, SealGeneration: 1,
	}
	placements := &placementOnlyCluster{
		Noop: cluster.NewNoop("node-b", "http://b", ""),
		placement: cluster.Placement{
			SandboxID: "sb-no-vacuum", OwnerNodeID: "node-a", SecretRecipients: recipients, IncarnationID: incarnationID, SecretSealGeneration: 1,
		},
	}
	svc := &Service{
		cfg:            config.Config{EnableCluster: true},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        placements,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err != nil {
		t.Fatalf("live placement put: %v", err)
	}
	if err := svc.DeleteClusterSecretsLocal(ctx, blob.SandboxID, blob.IncarnationID, blob.SealGeneration, "node-a"); err != nil {
		t.Fatalf("peer delete: %v", err)
	}
	if n, err := st.PruneClusterSecretTombs(ctx, time.Now().UTC().Add(time.Hour), 1); err != nil || n != 1 {
		t.Fatalf("prune tomb = %d, %v", n, err)
	}
	placements.placement = cluster.Placement{}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("stale put after tomb GC = %v, want invalid blob due to absent placement", err)
	}
	if rows, err := st.ListClusterSecretsBatch(ctx, "", 10); err != nil || len(rows) != 0 {
		t.Fatalf("stale put resurrected rows = %+v, %v", rows, err)
	}
}

func TestPeerSecretPutAllowsOnlyOwnerStagedNextGenerationReseal(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const sandboxID = "sb-staged-reseal-ingress"
	const incarnationID = "inc-current"
	recipients := []string{"node-a", "node-b"}
	ref := secrets.FormatRef(sandboxID, incarnationID, secrets.RefVersion)
	payload, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, recipients, secrets.SealBinding{
		SandboxID: sandboxID, IncarnationID: incarnationID, Ref: ref,
		Version: secrets.RefVersion, Generation: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob := secrets.SecretBlob{
		Ref: ref, SandboxID: sandboxID, IncarnationID: incarnationID, Version: secrets.RefVersion,
		Recipients: recipients, SealedPayload: payload, SealGeneration: 2,
	}
	placements := &placementOnlyCluster{
		Noop: cluster.NewNoop("node-b", "http://b", ""),
		placement: cluster.Placement{
			SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: incarnationID,
			SecretRecipients: []string{"node-a", "node-old"}, SecretSealGeneration: 1,
		},
	}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, cipher: cipher, store: st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)), cluster: placements,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-c"); !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("non-owner staged reseal = %v, want originator denied", err)
	}
	tooNew := blob
	tooNew.SealGeneration = 3
	if err := svc.UpsertClusterSecretBlob(ctx, tooNew, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("generation skip = %v, want invalid blob", err)
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err != nil {
		t.Fatalf("owner next-generation staged reseal: %v", err)
	}
	if rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, incarnationID); err != nil || rec == nil || rec.SealGeneration != 2 {
		t.Fatalf("staged replacement ciphertext = %+v err=%v", rec, err)
	}
}

func TestSealAndDistributeMinACKTimeoutRetracts(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	slow := &slowPeerPusher{delay: 200 * time.Millisecond, acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg: config.Config{
			SecretFanoutMinACKWait: 20 * time.Millisecond, // shorter than delay → sync gets 0
		},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: slow,
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	clearSecretFanoutHolders("sb-slow")
	handle, err := svc.SealAndDistribute(ctx, "sb-slow", req, []string{"node-a", "node-b"})
	if err == nil || handle.Ref != "" {
		t.Fatalf("seal must fail without a backup ACK: %+v %v", handle, err)
	}
	if rows, listErr := st.ListClusterSecretsBatch(ctx, "", 10); listErr != nil || len(rows) != 0 {
		t.Fatalf("failed HA seal left local rows: %+v %v", rows, listErr)
	}
}

type slowPeerPusher struct {
	delay time.Duration
	acked []string
	done  chan struct{}
	mu    sync.Mutex
	n     int
}

func (s *slowPeerPusher) PushSecretBlobToPeers(ctx context.Context, _ secrets.SecretBlob, _ []string) ([]string, error) {
	timer := time.NewTimer(s.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if s.done != nil {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
	return append([]string(nil), s.acked...), nil
}

func (s *slowPeerPusher) DeleteSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}
func (s *slowPeerPusher) ProbeSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func TestReFanoutClusterSecretsRebuildsHolders(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg: config.Config{
			SecretFanoutMinACKWait: 50 * time.Millisecond,
		},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-refan", req, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Seal performs one synchronous MinACK push and then enqueues a full push.
	// Wait on the queue's single-flight marker, which is removed only after
	// holder ACKs and the durable outbox have both been updated.
	waitForSecretCreateFanoutIdle(t, "sb-refan")
	clearSecretFanoutHolders("sb-refan")
	if secretHolderCount("sb-refan", handle.IncarnationID) != 0 {
		t.Fatal("expected cleared holders")
	}
	pusher.mu.Lock()
	pusher.done = make(chan struct{})
	pusher.mu.Unlock()
	if err := svc.ReFanoutClusterSecrets(ctx); err != nil {
		t.Fatalf("refanout: %v", err)
	}
	if got := secretHolderCount("sb-refan", handle.IncarnationID); got < 1 {
		t.Fatalf("after re-fanout local holders=%d, want >=1", got)
	}
	select {
	case <-pusher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected re-fanout push")
	}
}

func TestReFanoutClusterSecretsDoesNotLetCorruptRowStarveSafeRows(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{acked: []string{"node-b"}}
	placements := &placementOnlyCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretFanoutMinACKWait: 50 * time.Millisecond},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              placements,
		testSecretPeerPusher: pusher,
	}
	safeID := "sb-refan-safe"
	t.Cleanup(func() { clearSecretFanoutHolders(safeID) })
	req := models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	safeHandle, err := svc.SealAndDistribute(ctx, safeID, req, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	placements.placement = cluster.Placement{
		SandboxID: safeID, OwnerNodeID: "node-a", IncarnationID: safeHandle.IncarnationID,
		SecretRef: safeHandle.Ref, SecretVersion: safeHandle.Version,
		SecretSealGeneration: safeHandle.SealGeneration, SecretRecipients: []string{"node-a", "node-b"},
	}
	waitForSecretCreateFanoutIdle(t, safeID)
	clearSecretFanoutHolders(safeID)
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: secrets.FormatRef("sb-refan-corrupt", "inc-bad", secrets.RefVersion), SandboxID: "sb-refan-corrupt",
		Version: secrets.RefVersion, Recipients: []string{"node-a"}, SealedPayload: []byte("not-an-envelope"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReFanoutClusterSecrets(ctx); err == nil {
		t.Fatal("corrupt durable secret was not reported")
	}
	if got := secretHolderCount(safeID, safeHandle.IncarnationID); got == 0 {
		t.Fatal("corrupt row starved safe holder reconstruction")
	}
}

type unavailablePlacementSnapshotCluster struct{ *cluster.Noop }

func (c *unavailablePlacementSnapshotCluster) PlacementsByIDs([]string) map[string]cluster.Placement {
	return nil
}

func (c *unavailablePlacementSnapshotCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	return nil, errors.New("control plane unavailable")
}

func TestReFanoutClusterSecretsDoesNotDeleteOnPlacementReadFailure(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	ref := secrets.FormatRef("sb-placement-down", "inc-1", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-placement-down", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("durable-ciphertext"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &unavailablePlacementSnapshotCluster{Noop: cluster.NewNoop("node-a", "http://a", "")},
	}
	if err := svc.ReFanoutClusterSecrets(ctx); err == nil {
		t.Fatal("placement snapshot failure was not reported")
	}
	if rec, err := st.GetClusterSecret(ctx, ref); err != nil || rec == nil {
		t.Fatalf("durable secret was deleted on an ambiguous placement read: rec=%v err=%v", rec, err)
	}
}

func TestSecretRetirementScanRetiresOnlyMissingLifecycles(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const activeID = "sb-retirement-active"
	const staleID = "sb-retirement-stale"
	const incarnationID = "inc-1"
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
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-a", "http://a", ""),
			placement: cluster.Placement{
				SandboxID: activeID, OwnerNodeID: "node-a", IncarnationID: incarnationID,
				SecretRecipients: recipients, SecretSealGeneration: 1,
			},
		},
	}
	if err := svc.runSecretRetirementScan(ctx); err != nil {
		t.Fatalf("retirement scan: %v", err)
	}
	if rec, err := st.GetClusterSecret(ctx, activeRef); err != nil || rec == nil {
		t.Fatalf("active lifecycle was retired: rec=%+v err=%v", rec, err)
	}
	if _, err := st.GetClusterSecret(ctx, staleRef); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("missing lifecycle ciphertext remains: %v", err)
	}
	outbox, err := st.GetSecretDeleteOutboxForIncarnation(ctx, staleID, incarnationID)
	if err != nil || outbox == nil || len(outbox.Recipients) != 1 || outbox.Recipients[0] != "node-b" {
		t.Fatalf("missing lifecycle cleanup journal = %+v, err=%v", outbox, err)
	}
}

func TestSecretRefanoutPoolBoundsRestartConcurrency(t *testing.T) {
	const total = secretRefanoutWorkers + 17
	ctx := context.Background()
	st := openSealTestStore(t)
	for i := range total {
		id := fmt.Sprintf("sb-refanout-bound-%03d", i)
		if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
			Ref:            secrets.FormatRef(id, "inc-1", secrets.RefVersion),
			SandboxID:      id,
			Version:        secrets.RefVersion,
			Recipients:     []string{"node-a", "node-b"},
			SealedPayload:  []byte("sealed"),
			SealGeneration: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	pusher := &blockingRefanoutPusher{
		started: make(chan struct{}, total),
		release: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		if err := (&Service{store: st}).runSecretRefanoutScan(ctx, pusher); err != nil {
			t.Errorf("run paged re-fanout: %v", err)
		}
		close(done)
	}()
	for range secretRefanoutWorkers {
		select {
		case <-pusher.started:
		case <-time.After(2 * time.Second):
			t.Fatal("worker pool did not reach its configured concurrency")
		}
	}
	select {
	case <-pusher.started:
		t.Fatal("re-fanout exceeded the worker bound")
	case <-time.After(25 * time.Millisecond):
	}
	close(pusher.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("re-fanout pool did not drain")
	}
	if got := pusher.max.Load(); got != secretRefanoutWorkers {
		t.Fatalf("max concurrent pushes = %d, want %d", got, secretRefanoutWorkers)
	}
	if got := pusher.calls.Load(); got != total {
		t.Fatalf("push calls = %d, want %d", got, total)
	}
}

func TestComputeFailoverReady(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	sb := &models.Sandbox{ID: "sb1", AuditIncarnationID: "inc-sb1", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	clearSecretFanoutHolders("sb1")

	ready := svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || !*ready {
		t.Fatalf("no recipients → ready want true, got %v", ready)
	}

	addSecretHolderNodes("sb1", "inc-sb1", 1, "node-a")
	svc.AttachCluster(&placementRecipientsCluster{
		Noop:          cluster.NewNoop("node-a", "", ""),
		recipients:    []string{"node-a", "node-b"},
		incarnationID: "inc-sb1",
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: true},
		},
	})
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || *ready {
		t.Fatalf("holders=1 multi → want false, got %v", ready)
	}
	addSecretHolderNodes("sb1", "inc-sb1", 1, "node-b")
	// Self is counted only when the local sealed row exists.
	st := openSealTestStore(t)
	svc.store = st
	svc.cipher = newTestCipher(t)
	svc.secretProvider = secrets.NewLocalProvider(svc.cipher, newSecretBlobStore(st))
	pusher := &fakePeerPusher{acked: []string{"node-b"}, done: make(chan struct{})}
	svc.testSecretPeerPusher = pusher
	if _, err := svc.SealAndDistribute(context.Background(), "sb1", models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}, []string{"node-a", "node-b"}); err != nil {
		t.Fatalf("seal for ready: %v", err)
	}
	select {
	case <-pusher.done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for async fan-out ACK before failover-ready check")
	}
	waitForSecretCreateFanoutIdle(t, "sb1")
	addSecretHolderNodes("sb1", "inc-sb1", secretHolderGeneration("sb1", "inc-sb1"), "node-a", "node-b")
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || !*ready {
		t.Fatalf("holders=2 live with local row → want true, got %v", ready)
	}
	// Dead backup must flip ready false even if historically ACK'd.
	svc.AttachCluster(&placementRecipientsCluster{
		Noop:          cluster.NewNoop("node-a", "", ""),
		recipients:    []string{"node-a", "node-b"},
		incarnationID: "inc-sb1",
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: false},
		},
	})
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || *ready {
		t.Fatalf("dead backup → want false, got %v", ready)
	}

	sbNone := &models.Sandbox{ID: "x"}
	if got := svc.computeFailoverReady(context.Background(), sbNone); got != nil {
		t.Fatalf("non-recreate should omit, got %v", got)
	}
}

type placementRecipientsCluster struct {
	*cluster.Noop
	recipients    []string
	members       []cluster.Member
	incarnationID string
}

func TestFailoverReadyRejectsSingleRecipientForClusterHASecret(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, "sb-single-copy", "inc-single", 1, []string{"self"})
	c := &placementRecipientsCluster{
		Noop: cluster.NewNoop("self", "http://self", ""), recipients: []string{"self"}, incarnationID: "inc-single",
		members: []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleWorker}},
	}
	svc := &Service{cfg: config.Config{EnableCluster: true, SecretRecipientBackupCount: 2}, store: st, cluster: c}
	clearSecretFanoutHolders("sb-single-copy")
	t.Cleanup(func() { clearSecretFanoutHolders("sb-single-copy") })
	addSecretHolderNodes("sb-single-copy", "inc-single", 1, "self")
	sb := &models.Sandbox{ID: "sb-single-copy", AuditIncarnationID: "inc-single", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	ready := svc.computeFailoverReady(ctx, sb)
	if ready == nil || *ready {
		t.Fatalf("single-copy cluster HA readiness = %v, want false", ready)
	}
}

func (c *placementRecipientsCluster) PlacementOf(sandboxID string) (cluster.Placement, bool) {
	owner := c.SelfNodeID()
	return cluster.Placement{
		SandboxID:        sandboxID,
		OwnerNodeID:      owner,
		SecretRecipients: c.recipients,
		IncarnationID:    c.incarnationID,
	}, true
}

func (c *placementRecipientsCluster) Members() []cluster.Member {
	if len(c.members) > 0 {
		return append([]cluster.Member(nil), c.members...)
	}
	return c.Noop.Members()
}

func (c *placementRecipientsCluster) LocalMembers() []cluster.Member { return c.Members() }

func (c *placementRecipientsCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if p, ok := c.PlacementOf(id); ok {
			out[id] = p
		}
	}
	return out
}

func TestComputeFailoverReadyExpiresStaleACKWithoutAliveFlap(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: &placementRecipientsCluster{
			Noop:          cluster.NewNoop("node-a", "", ""),
			recipients:    []string{"node-a", "node-b"},
			incarnationID: "inc-sb-ttl",
			members: []cluster.Member{
				{NodeID: "node-a", Alive: true},
				{NodeID: "node-b", Alive: true},
			},
		},
		testSecretPeerPusher: pusher,
	}
	clearSecretFanoutHolders("sb-ttl")
	sb := &models.Sandbox{ID: "sb-ttl", AuditIncarnationID: "inc-sb-ttl", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	if _, err := svc.SealAndDistribute(ctx, "sb-ttl", models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}, []string{"node-a", "node-b"}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	select {
	case <-pusher.done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for async fan-out ACK")
	}
	// MinACK wait Push closes done; create-path enqueueSecretFanout runs a
	// second Push that would refresh holder timestamps — wait for it before
	// aging the ACK, otherwise computeFailoverReady races to ready=true.
	deadline := time.Now().Add(5 * time.Second)
	for {
		pusher.mu.Lock()
		n := pusher.pushCalls
		pusher.mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for async create-path fan-out, pushCalls=%d", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	gen := secretHolderGeneration("sb-ttl", "inc-sb-ttl")
	addSecretHolderNodes("sb-ttl", "inc-sb-ttl", gen, "node-a", "node-b")
	// Simulate peer losing SQLite without Alive=false: age the remote ACK past TTL.
	hs := holderSetFor("sb-ttl", "inc-sb-ttl")
	hs.mu.Lock()
	hs.nodes["node-a"] = time.Now()
	hs.nodes["node-b"] = time.Now().Add(-secretHolderACKTTL - time.Second)
	hs.mu.Unlock()
	ready := svc.computeFailoverReady(ctx, sb)
	if ready == nil || *ready {
		t.Fatalf("expired remote ACK without Alive flap must keep ready=false, got ready=%v holders=%v", ready != nil && *ready, secretHolderNodeIDs("sb-ttl", "inc-sb-ttl"))
	}
}

func TestComputeFailoverReadyResetsStaleGenerationHolders(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: &placementRecipientsCluster{
			Noop:          cluster.NewNoop("node-a", "", ""),
			recipients:    []string{"node-a", "node-b"},
			incarnationID: "inc-sb-probe",
			members: []cluster.Member{
				{NodeID: "node-a", Alive: true},
				{NodeID: "node-b", Alive: true},
			},
		},
		testSecretPeerPusher: pusher,
	}
	clearSecretFanoutHolders("sb-probe")
	sb := &models.Sandbox{ID: "sb-probe", AuditIncarnationID: "inc-sb-probe", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	if _, err := svc.SealAndDistribute(ctx, "sb-probe", models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}, []string{"node-a", "node-b"}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	select {
	case <-pusher.done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for async fan-out ACK")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		pusher.mu.Lock()
		n := pusher.pushCalls
		pusher.mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for async create-path fan-out, pushCalls=%d", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Stale remote ACK from a prior generation must not count until re-ACK.
	resetSecretHoldersForGeneration("sb-probe", "inc-sb-probe", 99, "node-a", "node-b")
	ready := svc.computeFailoverReady(ctx, sb)
	if ready == nil || *ready {
		t.Fatalf("stale generation holders must keep ready=false, got ready=%v holders=%v gen=%d", ready != nil && *ready, secretHolderNodeIDs("sb-probe", "inc-sb-probe"), secretHolderGeneration("sb-probe", "inc-sb-probe"))
	}
}

func TestPeerPutDeleteRaceDoesNotResurrect(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        cluster.NewNoop("node-b", "http://b", ""),
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-race", req, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := svc.loadSecretBlob(ctx, handle.Ref)
	if err != nil || blob == nil {
		t.Fatalf("load blob: %v", err)
	}
	gen := blob.SealGeneration

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = svc.DeleteClusterSecretsLocal(ctx, "sb-race", blob.IncarnationID, gen, "node-a")
		}()
		go func() {
			defer wg.Done()
			_ = svc.UpsertClusterSecretBlob(ctx, *blob, "node-a")
		}()
	}
	wg.Wait()

	tombGeneration, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-race", blob.IncarnationID)
	if err != nil {
		t.Fatal(err)
	}
	_, getErr := st.GetClusterSecret(ctx, handle.Ref)
	// After concurrent put/delete, either tomb wins (no row) or a strictly newer
	// reseal exists. Equal-gen resurrection with no tomb must not occur.
	if tombGeneration == 0 && errors.Is(getErr, storepkg.ErrNotFound) {
		t.Fatal("credentials missing without tomb — inconsistent delete state")
	}
	if tombGeneration == 0 {
		got, err := st.GetClusterSecret(ctx, handle.Ref)
		if err != nil {
			t.Fatal(err)
		}
		if got.SealGeneration <= gen {
			t.Fatalf("resurrected equal/stale generation %d without tomb", got.SealGeneration)
		}
	}
}

func TestDeleteClusterSecretsFansOut(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{done: make(chan struct{})}
	svc := &Service{
		cfg:                  config.Config{},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-del", req, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := svc.DeleteClusterSecrets(ctx, "sb-del", handle.IncarnationID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Give async delete a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pusher.mu.Lock()
		n := len(pusher.deletes)
		pusher.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected delete-fanout")
}

func TestRunSecretFanoutDeadRecipientKeepsOutbox(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	now := time.Now().UTC()
	const sandboxID = "sb-dead-fanout"
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: secrets.FormatRef(sandboxID, "inc-1", 1), SandboxID: sandboxID, Version: 1,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Seed an outbox row that a buggy success path would clear.
	if err := st.UpsertSecretPutOutbox(ctx, sandboxID, "inc-1", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		cfg:   config.Config{},
		store: st,
		cluster: &placementRecipientsCluster{
			Noop:       cluster.NewNoop("node-a", "http://a", ""),
			recipients: []string{"node-a", "node-b"},
			members: []cluster.Member{
				{NodeID: "node-a", Alive: true},
				{NodeID: "node-b", Alive: false},
			},
		},
	}
	// Empty ACK + nil err used to DeleteSecretPutOutbox — must now keep pending.
	pusher := &fakePeerPusher{acked: nil}
	svc.runSecretFanout(sandboxID, secrets.SecretBlob{
		SandboxID: sandboxID, IncarnationID: "inc-1", Version: 1, SealGeneration: 1,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
	}, []string{"node-a", "node-b"}, pusher)

	got, err := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, "inc-1")
	if err != nil || got == nil {
		t.Fatalf("expected put-outbox retained after dead-recipient fan-out, got %#v err=%v", got, err)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != "node-b" {
		t.Fatalf("pending recipients = %v, want [node-b]", got.Recipients)
	}
}

func TestUpsertClusterSecretBlobRejectsWrongIncarnation(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	recipients := []string{"node-a", "node-b"}
	ref := secrets.FormatRef("sb-inc", "deadbeefcafebabe", 1)
	payload, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, recipients, secrets.SealBinding{
		SandboxID: "sb-inc", IncarnationID: "deadbeefcafebabe", Ref: ref, Version: 1, Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob := secrets.SecretBlob{
		Ref: ref, SandboxID: "sb-inc", IncarnationID: "deadbeefcafebabe", Version: 1,
		Recipients: recipients, SealedPayload: payload, SealGeneration: 1,
	}
	svc := &Service{
		cfg:            config.Config{EnableCluster: true},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-b", "http://b", ""),
			placement: cluster.Placement{
				SandboxID: "sb-inc", OwnerNodeID: "node-a",
				SecretRecipients: recipients, IncarnationID: "aaaaaaaaaaaaaaaa",
			},
		},
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("wrong incarnation = %v, want ErrInvalidClusterSecretBlob", err)
	}

	// Empty blob incarnation must also be rejected when placement has one.
	emptyInc := blob
	emptyInc.IncarnationID = ""
	if err := svc.UpsertClusterSecretBlob(ctx, emptyInc, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("empty incarnation = %v, want ErrInvalidClusterSecretBlob", err)
	}
}

func TestSelectReplacementRecipientsAndFrozenSealRecipients(t *testing.T) {
	cl := &placementRecipientsCluster{
		Noop:       cluster.NewNoop("owner", "", ""),
		recipients: []string{"owner", "dead-a", "dead-b"},
		members: []cluster.Member{
			{NodeID: "owner", Alive: true, Role: config.NodeRoleMixed},
			{NodeID: "dead-a", Alive: false, Role: config.NodeRoleWorker},
			{NodeID: "dead-b", Alive: false, Role: config.NodeRoleWorker},
			{NodeID: "live-b", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "live-c", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "ingress-only", Alive: true, Role: config.NodeRoleIngress},
		},
	}
	svc := &Service{cfg: config.Config{SecretRecipientBackupCount: 2}, cluster: cl}

	got := svc.SelectReplacementRecipients("sb-expand", 2)
	if len(got) < 2 || got[0] != "owner" {
		t.Fatalf("SelectReplacementRecipients=%v, want owner-first with live backups", got)
	}
	for _, id := range got {
		if id == "ingress-only" || id == "dead-a" || id == "dead-b" {
			t.Fatalf("unexpected recipient %q in %v", id, got)
		}
	}

	frozen := svc.SecretRecipientsForSeal("sb-expand")
	if len(frozen) != 3 || frozen[1] != "dead-a" {
		t.Fatalf("frozen SecretRecipientsForSeal=%v", frozen)
	}
}

func TestPutOutboxExistsImmediatelyAfterPut(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        cluster.NewNoop("node-a", "http://a", ""),
	}
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}
	handle, err := svc.putClusterSecretsForRecipients(ctx, "sb-outbox-put", req, []string{"node-a", "node-b", "node-c"})
	if err != nil || handle.Ref == "" {
		t.Fatalf("put: %+v %v", handle, err)
	}
	got, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-outbox-put", handle.IncarnationID)
	if err != nil || got == nil {
		t.Fatalf("expected put-outbox immediately after Put, got %#v err=%v", got, err)
	}
	if got.SealGeneration != handle.SealGeneration || handle.SealGeneration <= 0 {
		t.Fatalf("outbox gen=%d handle gen=%d", got.SealGeneration, handle.SealGeneration)
	}
	if len(got.Recipients) != 2 {
		t.Fatalf("outbox recipients=%v, want non-self [node-b node-c]", got.Recipients)
	}
	for _, id := range got.Recipients {
		if id == "node-a" {
			t.Fatalf("self should not be in put-outbox: %v", got.Recipients)
		}
	}
}

func TestPutOutboxCrashVacuumReconcileWithoutEnqueue(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const sandboxID = "sb-crash-vacuum"
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        cluster.NewNoop("node-a", "http://a", ""),
		// No enqueue — crash vacuum relies solely on durable outbox.
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"node-b"}},
	}
	handle, err := svc.putClusterSecretsForRecipients(ctx, sandboxID, req, []string{"node-a", "node-b"})
	if err != nil || handle.Ref == "" {
		t.Fatalf("put: %+v %v", handle, err)
	}
	got, err := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, handle.IncarnationID)
	if err != nil || got == nil || len(got.Recipients) != 1 || got.Recipients[0] != "node-b" {
		t.Fatalf("pre-reconcile outbox=%#v err=%v", got, err)
	}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	remaining, err := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, handle.IncarnationID)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != nil {
		t.Fatalf("expected put-outbox drained from crash vacuum, still %#v", remaining)
	}
}

func TestPutOutboxFromReusedSandboxBecomesDurableDeleteWork(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID = "sb-put-outbox-reused"
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: secrets.FormatRef(sandboxID, "inc-old", secrets.RefVersion), SandboxID: sandboxID,
		Version: secrets.RefVersion, Recipients: []string{"node-a", "node-b"},
		SealedPayload: []byte("old-sealed"), SealGeneration: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, sandboxID, "inc-old", 3, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st,
		cluster: &placementOnlyCluster{
			Noop:      cluster.NewNoop("node-a", "http://a", ""),
			placement: cluster.Placement{SandboxID: sandboxID, IncarnationID: "inc-new", OwnerNodeID: "node-a"},
		},
		testSecretPeerPusher: &fakePeerPusher{},
	}
	svc.reconcileSecretPutOutboxIncarnation(ctx, sandboxID, "inc-old")
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, sandboxID, "inc-old"); err != nil || rec != nil {
		t.Fatalf("obsolete put obligation = %+v err=%v", rec, err)
	}
	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, "inc-old"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("obsolete local ciphertext remains: %v", err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, "inc-old"); err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "node-b" {
		t.Fatalf("old remote cleanup obligation = %+v err=%v", rec, err)
	}
}

func TestReconcileSecretPutOutboxDrainsBeyondOneWorkerWave(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const total = deleteReconcileWorkers*2 + 7
	now := time.Now().UTC()
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("sb-put-backlog-%03d", i)
		if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
			Ref: secrets.FormatRef(id, "inc-1", 1), SandboxID: id, Version: 1,
			Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
			SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed secret %s: %v", id, err)
		}
		if err := st.UpsertSecretPutOutbox(ctx, id, "inc-1", 1, []string{"node-b"}); err != nil {
			t.Fatalf("seed outbox %s: %v", id, err)
		}
	}
	pusher := &fakePeerPusher{acked: []string{"node-b"}}
	svc := &Service{
		cfg:                  config.Config{},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cluster.NewNoop("node-a", "http://a", ""),
		testSecretPeerPusher: pusher,
	}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	remaining, err := st.ListSecretPutOutboxBatch(ctx, total+1)
	if err != nil {
		t.Fatalf("list remaining: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("remaining put-outbox rows = %d, want 0", len(remaining))
	}
	pusher.mu.Lock()
	pushes := pusher.pushCalls
	pusher.mu.Unlock()
	if pushes != total {
		t.Fatalf("peer pushes = %d, want %d", pushes, total)
	}
}

type resealPlacementCluster struct {
	*cluster.Noop
	mu           sync.Mutex
	placement    cluster.Placement
	members      []cluster.Member
	leader       string
	updateCalls  int
	lastExpected int64
	rejectCAS    bool
}

func (c *resealPlacementCluster) PlacementOf(string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.placement, c.placement.SandboxID != ""
}

func (c *resealPlacementCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]cluster.Placement)
	for _, id := range ids {
		if id == c.placement.SandboxID && id != "" {
			out[id] = c.placement
		}
	}
	return out, nil
}

func (c *resealPlacementCluster) SecretsOf(string) cluster.PlacementSecrets {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cluster.PlacementSecrets{
		Ref:            c.placement.SecretRef,
		Version:        c.placement.SecretVersion,
		Recipients:     append([]string(nil), c.placement.SecretRecipients...),
		IncarnationID:  c.placement.IncarnationID,
		SealGeneration: c.placement.SecretSealGeneration,
	}
}

func (c *resealPlacementCluster) Members() []cluster.Member {
	if c.members != nil {
		return append([]cluster.Member(nil), c.members...)
	}
	return []cluster.Member{
		{NodeID: "node-a", Alive: true, Role: config.NodeRoleMixed},
		{NodeID: "dead-a", Alive: false, Role: config.NodeRoleWorker},
		{NodeID: "dead-b", Alive: false, Role: config.NodeRoleWorker},
		{NodeID: "live-b", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "live-c", Alive: true, Role: config.NodeRoleWorker},
	}
}

func (c *resealPlacementCluster) LocalMembers() []cluster.Member { return c.Members() }

func (c *resealPlacementCluster) Leader() string {
	if c.leader != "" {
		return c.leader
	}
	return c.Noop.Leader()
}

func (c *resealPlacementCluster) UpdatePlacementSecretRecipients(_ context.Context, sandboxID string, recipients []string, secrets cluster.PlacementSecrets, expectedIncarnationID string, expectedSealGeneration int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateCalls++
	c.lastExpected = expectedSealGeneration
	if c.rejectCAS {
		return cluster.ErrSecretRecipientsCASMismatch
	}
	c.placement.SecretRecipients = append([]string(nil), recipients...)
	if secrets.Ref != "" {
		c.placement.SecretRef = secrets.Ref
		c.placement.SecretVersion = secrets.Version
	}
	if secrets.SealGeneration > 0 {
		c.placement.SecretSealGeneration = secrets.SealGeneration
	}
	if expectedIncarnationID != "" && c.placement.IncarnationID == "" {
		c.placement.IncarnationID = expectedIncarnationID
	}
	_ = sandboxID
	return nil
}

func TestExpandAndResealSkipsNonOwner(t *testing.T) {
	ctx := context.Background()
	cl := &resealPlacementCluster{
		Noop: cluster.NewNoop("node-b", "http://b", ""),
		placement: cluster.Placement{
			SandboxID:            "sb-reseal-skip",
			OwnerNodeID:          "node-a",
			SecretRecipients:     []string{"node-a", "dead-a", "dead-b"},
			IncarnationID:        "inc-1",
			SecretSealGeneration: 1,
			SecretRef:            secrets.FormatRef("sb-reseal-skip", "inc-1", 1),
			SecretVersion:        1,
		},
	}
	svc := &Service{
		cfg:     config.Config{SecretRecipientBackupCount: 2},
		cluster: cl,
		store:   openSealTestStore(t),
	}
	clearSecretFanoutHolders("sb-reseal-skip")
	t.Cleanup(func() { clearSecretFanoutHolders("sb-reseal-skip") })
	resetSecretHoldersForGeneration("sb-reseal-skip", "inc-1", 1, "node-b")
	setSecretHolderTargets("sb-reseal-skip", "inc-1", 1, []string{"node-a", "dead-a", "dead-b"})

	if err := svc.expandAndResealDeadSecretTargets(ctx, "sb-reseal-skip"); err != nil {
		t.Fatalf("non-owner reseal: %v", err)
	}
	cl.mu.Lock()
	calls := cl.updateCalls
	cl.mu.Unlock()
	if calls != 0 {
		t.Fatalf("non-owner triggered %d raft updates", calls)
	}
}

func TestExpandAndResealOwnerCASRejectsStaleGeneration(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const sandboxID = "sb-reseal-cas"
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}
	cl := &resealPlacementCluster{
		Noop:      cluster.NewNoop("node-a", "http://a", ""),
		rejectCAS: true,
		placement: cluster.Placement{
			SandboxID:            sandboxID,
			OwnerNodeID:          "node-a",
			SecretRecipients:     []string{"node-a", "dead-a", "dead-b"},
			IncarnationID:        "inc-1",
			SecretSealGeneration: 9,
			SecretRef:            secrets.FormatRef(sandboxID, "inc-1", 1),
			SecretVersion:        1,
		},
	}
	svc := &Service{
		cfg:                  config.Config{SecretRecipientBackupCount: 2},
		cipher:               cipher,
		store:                st,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:              cl,
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"live-b"}},
	}
	if _, err := svc.putClusterSecretsForRecipients(ctx, sandboxID, req, []string{"node-a", "dead-a", "dead-b"}); err != nil {
		t.Fatalf("seed put: %v", err)
	}
	// Align placement handle with the sealed row and force a Raft CAS conflict.
	rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, "inc-1")
	if err != nil || rec == nil {
		t.Fatalf("load sealed: %v", err)
	}
	cl.mu.Lock()
	cl.placement.SecretRef = rec.Ref
	cl.placement.SecretVersion = rec.Version
	cl.placement.SecretSealGeneration = rec.SealGeneration
	cl.mu.Unlock()

	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
	resetSecretHoldersForGeneration(sandboxID, "inc-1", 3, "node-a") // stale vs placement gen 9
	// Deliberately omit dead-b from volatile holder memory. Raft placement must
	// still drive retirement so the peer's ciphertext is not forgotten.
	setSecretHolderTargets(sandboxID, "inc-1", 3, []string{"node-a", "dead-a"})

	err = svc.expandAndResealDeadSecretTargets(ctx, sandboxID)
	if err == nil || !errors.Is(err, cluster.ErrSecretRecipientsCASMismatch) {
		t.Fatalf("reseal = %v, want wrapped ErrSecretRecipientsCASMismatch", err)
	}
	outbox, outboxErr := st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, "inc-1")
	if outboxErr != nil || outbox == nil || !outbox.AwaitingPromotion {
		t.Fatalf("failed Raft CAS lost staged recipient retirement: outbox=%+v err=%v", outbox, outboxErr)
	}
	if !sameStringSlice(outbox.Recipients, []string{"dead-a", "dead-b"}) {
		t.Fatalf("staged retired recipients = %v, want [dead-a dead-b]", outbox.Recipients)
	}
}

func TestExpandAndResealFinalizesInterruptedLocalGeneration(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	const sandboxID = "sb-reseal-finalize"
	recipients := []string{"live-b", "live-c", "node-a"}
	cl := &resealPlacementCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{
			SandboxID:            sandboxID,
			OwnerNodeID:          "node-a",
			SecretRecipients:     append([]string(nil), recipients...),
			IncarnationID:        "inc-1",
			SecretSealGeneration: 1,
			SecretRef:            secrets.FormatRef(sandboxID, "inc-1", secrets.RefVersion),
			SecretVersion:        secrets.RefVersion,
		},
	}
	svc := &Service{
		cfg:            config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        cl,
		testSecretPeerPusher: &fakePeerPusher{
			probeStrict:  true,
			probeHolding: []string{"live-b"},
		},
	}
	bag := secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}
	sealCtx := secrets.ContextWithIncarnationID(ctx, "inc-1")
	if _, err := svc.secretProvider.Put(sealCtx, sandboxID, bag, recipients); err != nil {
		t.Fatalf("put generation 1: %v", err)
	}
	if _, err := svc.secretProvider.Put(sealCtx, sandboxID, bag, recipients); err != nil {
		t.Fatalf("put interrupted generation 2: %v", err)
	}
	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
	resetSecretHoldersForGeneration(sandboxID, "inc-1", 2, "node-a", "live-b")
	setSecretHolderTargets(sandboxID, "inc-1", 2, recipients)

	// All recipients are healthy, so only the explicit generation-split
	// recovery path in the periodic scheduler can finish the interrupted Raft
	// commit without waiting for a member to die.
	svc.refreshSecretHolderPossession(ctx)
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.placement.SecretSealGeneration != 2 || cl.updateCalls != 1 {
		t.Fatalf("placement generation=%d updates=%d, want generation=2 updates=1", cl.placement.SecretSealGeneration, cl.updateCalls)
	}
}

func TestStagedRetirementWaitsForRaftPromotion(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID = "sb-retirement-fence"
	retired := []string{"dead-a"}
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: secrets.FormatRef(sandboxID, "inc-1", secrets.RefVersion), SandboxID: sandboxID,
		Version: 1, Recipients: []string{"node-a", "live-b"},
		SealedPayload: []byte("sealed-generation-2"), SealGeneration: 2,
		RetireRecipients: &retired,
	}); err != nil {
		t.Fatalf("stage reseal: %v", err)
	}
	cl := &resealPlacementCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		placement: cluster.Placement{
			SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-1",
			SecretRecipients: []string{"node-a", "dead-a"}, SecretSealGeneration: 1,
		},
	}
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st, cluster: cl,
		testSecretPeerPusher: pusher,
	}

	svc.reconcileSecretDeleteOutboxIncarnation(ctx, sandboxID, "inc-1")
	pusher.mu.Lock()
	deleteCalls := len(pusher.deletes)
	pusher.mu.Unlock()
	if deleteCalls != 0 {
		t.Fatalf("staged retirement deleted a peer before Raft promotion")
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, "inc-1"); err != nil || rec == nil || !rec.AwaitingPromotion {
		t.Fatalf("staged retirement was not retained: rec=%+v err=%v", rec, err)
	}

	cl.mu.Lock()
	cl.placement.SecretRecipients = []string{"node-a", "live-b"}
	cl.placement.SecretSealGeneration = 2
	cl.mu.Unlock()
	svc.reconcileSecretDeleteOutboxIncarnation(ctx, sandboxID, "inc-1")
	pusher.mu.Lock()
	deleteCalls = len(pusher.deletes)
	pusher.mu.Unlock()
	if deleteCalls != 1 {
		t.Fatalf("promoted retirement delete calls = %d, want 1", deleteCalls)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, "inc-1"); err != nil || rec != nil {
		t.Fatalf("promoted retirement outbox not drained: rec=%+v err=%v", rec, err)
	}
}
