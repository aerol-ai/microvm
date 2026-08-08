package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type fakePeerPusher struct {
	mu        sync.Mutex
	pushes    []secrets.SecretBlob
	deletes   []string
	pushErr   error
	acked     []string
	pushCalls int
	done      chan struct{}
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

func (f *fakePeerPusher) DeleteSecretOnPeers(_ context.Context, sandboxID string, recipients []string, _ int64) (acked, pending []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, sandboxID)
	return append([]string(nil), recipients...), nil, nil
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
	sealed, err := secrets.SealEnvelope(cipher, bag, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	ok := secrets.SecretBlob{
		Ref: secrets.FormatRef("sb-ok", 1), SandboxID: "sb-ok", Version: 1,
		Recipients: []string{"node-a", "node-b"}, SealedPayload: sealed,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, ok); err != nil {
		t.Fatalf("valid upsert: %v", err)
	}

	badRef := ok
	badRef.Ref = secrets.FormatRef("other", 1)
	if err := svc.UpsertClusterSecretBlob(ctx, badRef); !errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("bad ref = %v, want ErrInvalidClusterSecretBlob", err)
	}

	foreign, err := secrets.SealEnvelope(cipher, bag, []string{"node-a", "node-c"})
	if err != nil {
		t.Fatal(err)
	}
	denied := secrets.SecretBlob{
		Ref: secrets.FormatRef("sb-deny", 1), SandboxID: "sb-deny", Version: 1,
		Recipients: []string{"node-a", "node-c"}, SealedPayload: foreign,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, denied); !errors.Is(err, secrets.ErrRecipientDenied) {
		t.Fatalf("non-recipient = %v, want ErrRecipientDenied", err)
	}
}

func TestSealAndDistributeStrictVsBestEffort(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}

	s := &Service{}
	if _, err := s.SealAndDistribute(ctx, "sb", req, []string{"n1"}, SealStrict); err == nil {
		t.Fatal("strict without cipher/store expected error")
	}

	out, err := s.SealAndDistribute(ctx, "sb", req, []string{"n1"}, SealBestEffort)
	if err != nil || out.Ref != "" {
		t.Fatalf("best-effort = %+v err=%v", out, err)
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
		cfg:            config.Config{SecretRecipientFanoutEnabled: true},
		cipher:         cipher,
		store:          storeA,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(storeA)),
		cluster:        cluster.NewNoop("node-a", "http://a", ""),
	}
	svcB := &Service{
		cfg:            config.Config{SecretRecipientFanoutEnabled: true},
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
	handle, err := svcA.SealAndDistribute(ctx, "sb-xnode", req, []string{"node-a", "node-b"}, SealStrict)
	if err != nil || handle.Ref == "" {
		t.Fatalf("seal on A: handle=%+v err=%v", handle, err)
	}

	blob, err := newSecretBlobStore(storeA).Get(ctx, handle.Ref)
	if err != nil || blob == nil {
		t.Fatalf("load blob from A: %v", err)
	}
	if err := svcB.UpsertClusterSecretBlob(ctx, *blob); err != nil {
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
			SecretRecipientFanoutEnabled: true,
			SecretFanoutMinACKWait:       50 * time.Millisecond,
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
	handle, err := svc.SealAndDistribute(ctx, "sb-fan", req, []string{"node-a", "node-b"}, SealStrict)
	if err != nil || handle.Ref == "" {
		t.Fatalf("seal: %+v %v", handle, err)
	}
	// Min-ACK wait already called Push synchronously; holders should be ≥2.
	if got := secretHolderCount("sb-fan"); got < 2 {
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

func TestSealAndDistributeMinACKTimeoutContinuesAsync(t *testing.T) {
	// GAP-1 mitigation: slow peers still get async retry; create does not fail.
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	slow := &slowPeerPusher{delay: 200 * time.Millisecond, acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg: config.Config{
			SecretRecipientFanoutEnabled: true,
			SecretFanoutMinACKWait:       20 * time.Millisecond, // shorter than delay → sync gets 0
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
	handle, err := svc.SealAndDistribute(ctx, "sb-slow", req, []string{"node-a", "node-b"}, SealStrict)
	if err != nil || handle.Ref == "" {
		t.Fatalf("seal must succeed despite min-ACK timeout: %+v %v", handle, err)
	}
	if got := secretHolderCount("sb-slow"); got != 1 {
		t.Fatalf("after timed-out min-ACK holders=%d, want 1 (local only)", got)
	}
	select {
	case <-slow.done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected async fan-out after min-ACK timeout")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if secretHolderCount("sb-slow") >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("async fan-out never raised holders (got %d)", secretHolderCount("sb-slow"))
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

func (s *slowPeerPusher) DeleteSecretOnPeers(context.Context, string, []string, int64) ([]string, []string, error) {
	return nil, nil, nil
}

func TestReFanoutClusterSecretsRebuildsHolders(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{acked: []string{"node-b"}, done: make(chan struct{})}
	svc := &Service{
		cfg: config.Config{
			SecretRecipientFanoutEnabled: true,
			SecretFanoutMinACKWait:       0, // fully async for this setup
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
	if _, err := svc.SealAndDistribute(ctx, "sb-refan", req, []string{"node-a", "node-b"}, SealStrict); err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Drain the seal-time async fan-out before mutating pusher.done (race detector).
	select {
	case <-pusher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected initial seal fan-out")
	}
	clearSecretFanoutHolders("sb-refan")
	if secretHolderCount("sb-refan") != 0 {
		t.Fatal("expected cleared holders")
	}
	pusher.mu.Lock()
	pusher.done = make(chan struct{})
	pusher.mu.Unlock()
	if err := svc.ReFanoutClusterSecrets(ctx); err != nil {
		t.Fatalf("refanout: %v", err)
	}
	if got := secretHolderCount("sb-refan"); got < 1 {
		t.Fatalf("after re-fanout local holders=%d, want >=1", got)
	}
	select {
	case <-pusher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected re-fanout push")
	}
}

func TestComputeFailoverReady(t *testing.T) {
	svc := &Service{cfg: config.Config{SecretRecipientFanoutEnabled: true}}
	sb := &models.Sandbox{ID: "sb1", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	clearSecretFanoutHolders("sb1")

	ready := svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || !*ready {
		t.Fatalf("no recipients → ready want true, got %v", ready)
	}

	addSecretHolderNodes("sb1", "node-a")
	svc.cluster = &placementRecipientsCluster{
		Noop:       cluster.NewNoop("node-a", "", ""),
		recipients: []string{"node-a", "node-b"},
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: true},
		},
	}
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || *ready {
		t.Fatalf("holders=1 multi → want false, got %v", ready)
	}
	addSecretHolderNodes("sb1", "node-b")
	// Self is counted only when the local sealed row exists.
	st := openSealTestStore(t)
	svc.store = st
	svc.cipher = newTestCipher(t)
	svc.secretProvider = secrets.NewLocalProvider(svc.cipher, newSecretBlobStore(st))
	if _, err := svc.SealAndDistribute(context.Background(), "sb1", models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}, []string{"node-a", "node-b"}, SealStrict); err != nil {
		t.Fatalf("seal for ready: %v", err)
	}
	addSecretHolderNodes("sb1", "node-a", "node-b")
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || !*ready {
		t.Fatalf("holders=2 live with local row → want true, got %v", ready)
	}
	// Dead backup must flip ready false even if historically ACK'd.
	svc.cluster = &placementRecipientsCluster{
		Noop:       cluster.NewNoop("node-a", "", ""),
		recipients: []string{"node-a", "node-b"},
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: false},
		},
	}
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
	recipients []string
	members    []cluster.Member
}

func (c *placementRecipientsCluster) PlacementOf(sandboxID string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: sandboxID, SecretRecipients: c.recipients}, true
}

func (c *placementRecipientsCluster) Members() []cluster.Member {
	if len(c.members) > 0 {
		return append([]cluster.Member(nil), c.members...)
	}
	return c.Noop.Members()
}

func TestDeleteClusterSecretsFansOut(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{done: make(chan struct{})}
	svc := &Service{
		cfg:                  config.Config{SecretRecipientFanoutEnabled: true},
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
	if _, err := svc.SealAndDistribute(ctx, "sb-del", req, []string{"node-a", "node-b"}, SealStrict); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := svc.DeleteClusterSecrets(ctx, "sb-del"); err != nil {
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
