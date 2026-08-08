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
	acked     int
	pushCalls int
	done      chan struct{}
}

func (f *fakePeerPusher) PushSecretBlobToPeers(_ context.Context, blob secrets.SecretBlob, _ []string) (int, error) {
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
	return f.acked, f.pushErr
}

func (f *fakePeerPusher) DeleteSecretOnPeers(_ context.Context, sandboxID string, _ []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, sandboxID)
	return nil
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
	pusher := &fakePeerPusher{acked: 1, done: make(chan struct{})}
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
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-fan", req, []string{"node-a", "node-b"}, SealStrict)
	if err != nil || handle.Ref == "" {
		t.Fatalf("seal: %+v %v", handle, err)
	}
	select {
	case <-pusher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected async fan-out push")
	}
	pusher.mu.Lock()
	defer pusher.mu.Unlock()
	if pusher.pushCalls == 0 {
		t.Fatal("pushCalls=0")
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

	secretFanoutHolders.Store("sb1", 1)
	svc.cluster = &placementRecipientsCluster{
		Noop:       cluster.NewNoop("node-a", "", ""),
		recipients: []string{"node-a", "node-b"},
	}
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || *ready {
		t.Fatalf("holders=1 multi → want false, got %v", ready)
	}
	secretFanoutHolders.Store("sb1", 2)
	ready = svc.computeFailoverReady(context.Background(), sb)
	if ready == nil || !*ready {
		t.Fatalf("holders=2 → want true, got %v", ready)
	}

	sbNone := &models.Sandbox{ID: "x"}
	if got := svc.computeFailoverReady(context.Background(), sbNone); got != nil {
		t.Fatalf("non-recreate should omit, got %v", got)
	}
}

type placementRecipientsCluster struct {
	*cluster.Noop
	recipients []string
}

func (c *placementRecipientsCluster) PlacementOf(sandboxID string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: sandboxID, SecretRecipients: c.recipients}, true
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
