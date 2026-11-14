package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/kubeapi"
	"github.com/aerol-ai/microvm/internal/testport"
	"github.com/aerol-ai/microvm/pkg/models"
)

// writePair writes a self-signed serving pair for cn.
func writePair(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	cert, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, keyFile
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, "one")
	r := &certReloader{certFile: cert, keyFile: key}
	first, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := r.GetCertificate(nil); again != first {
		t.Fatal("an unchanged pair was read again")
	}
	time.Sleep(10 * time.Millisecond)
	writePair(t, dir, "two")
	later := time.Now().Add(time.Second)
	_ = os.Chtimes(cert, later, later)
	second, err := r.GetCertificate(nil)
	if err != nil || second == first {
		t.Fatalf("a renewed pair was not read: %v", err)
	}
	// A half-written renewal keeps the last good pair.
	_ = os.WriteFile(key, []byte("garbage"), 0o600)
	evenLater := later.Add(time.Second)
	_ = os.Chtimes(key, evenLater, evenLater)
	if kept, err := r.GetCertificate(nil); err != nil || kept != second {
		t.Fatalf("a broken renewal = %v", err)
	}
	if _, err := (&certReloader{certFile: filepath.Join(dir, "nope"), keyFile: key}).GetCertificate(nil); err == nil {
		t.Fatal("a missing file")
	}
	if _, err := (&certReloader{certFile: key, keyFile: key}).GetCertificate(nil); err == nil {
		t.Fatal("a pair that never loaded")
	}
}

type fakeKube struct {
	kubeapi.ObjectStore // the store is not called here
	fails               int
	calls               int
}

func (k *fakeKube) FrontProxyConfig(context.Context) (*kubeapi.FrontProxy, error) {
	k.calls++
	if k.calls <= k.fails {
		return nil, errors.New("not yet")
	}
	return &kubeapi.FrontProxy{CAs: x509.NewCertPool()}, nil
}

func (k *fakeKube) SubjectAccessReview(context.Context, kubeapi.User, kubeapi.Attributes) (bool, string, error) {
	return true, "", nil
}

func TestFrontProxyHolderAndTLS(t *testing.T) {
	h := &frontProxyHolder{}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	if _, err := h.Authenticate(req); !errors.Is(err, kubeapi.ErrUnauthenticated) {
		t.Fatalf("before load: %v", err)
	}
	cfg := agentSandboxTLS(&certReloader{}, h)
	got, _ := cfg.GetConfigForClient(nil)
	if got.ClientAuth != tls.RequestClientCert || got.ClientCAs != nil {
		t.Fatalf("before load = %v", got.ClientAuth)
	}
	old := frontProxyRetry
	frontProxyRetry = time.Millisecond
	t.Cleanup(func() { frontProxyRetry = old })
	k := &fakeKube{fails: 2}
	h.load(context.Background(), k, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if k.calls != 3 || h.p.Load() == nil {
		t.Fatalf("load = %d calls", k.calls)
	}
	got, _ = cfg.GetConfigForClient(nil)
	if got.ClientAuth != tls.VerifyClientCertIfGiven || got.ClientCAs == nil {
		t.Fatalf("after load = %v", got.ClientAuth)
	}
	if _, err := h.Authenticate(req); !errors.Is(err, kubeapi.ErrUnauthenticated) {
		t.Fatalf("no client certificate: %v", err)
	}
	// A cancelled load gives up.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	(&frontProxyHolder{}).load(ctx, &fakeKube{fails: 100}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type fakeFeedClient struct {
	*cluster.Noop
	feedOn bool
}

func (f *fakeFeedClient) WatchPlacementFeed(_ context.Context, fn cluster.PlacementFeedHandler) bool {
	if !f.feedOn {
		return false
	}
	fn(cluster.PlacementFeedEvent{View: true, Next: 5})
	return true
}

type nopBackend struct{}

func (nopBackend) Create(context.Context, string, models.CreateSandboxRequest, string) (string, error) {
	return "", nil
}
func (nopBackend) Delete(context.Context, string, string) error           { return nil }
func (nopBackend) SetRunning(context.Context, string, string, bool) error { return nil }
func (nopBackend) Specs(context.Context, []kubeapi.SpecRef) map[string]kubeapi.SpecSummary {
	return nil
}

func TestStartAgentSandboxAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	on := config.Config{AgentSandboxAPI: true, EnableCluster: true, NodeRole: config.NodeRoleIngress}
	for name, cfg := range map[string]config.Config{
		"off":         {EnableCluster: true, NodeRole: config.NodeRoleIngress},
		"single node": {AgentSandboxAPI: true, NodeRole: config.NodeRoleIngress},
		"a worker":    {AgentSandboxAPI: true, EnableCluster: true, NodeRole: config.NodeRoleWorker},
	} {
		if srv, err := startAgentSandboxAPI(ctx, cfg, &fakeFeedClient{Noop: cluster.NewNoop("n", "", "")}, nopBackend{}, logger); srv != nil || err != nil {
			t.Fatalf("%s: %v %v", name, srv, err)
		}
	}
	if _, err := startAgentSandboxAPI(ctx, on, cluster.NewNoop("n", "", ""), nopBackend{}, logger); err == nil {
		t.Fatal("a client without a feed")
	}
	old := newKubeClient
	t.Cleanup(func() { newKubeClient = old })
	newKubeClient = func() (kubeClient, error) { return nil, errors.New("not in a pod") }
	if _, err := startAgentSandboxAPI(ctx, on, &fakeFeedClient{Noop: cluster.NewNoop("n", "", ""), feedOn: true}, nopBackend{}, logger); err == nil {
		t.Fatal("no kube client")
	}
	newKubeClient = func() (kubeClient, error) { return &fakeKube{}, nil }
	if _, err := startAgentSandboxAPI(ctx, on, &fakeFeedClient{Noop: cluster.NewNoop("n", "", "")}, nopBackend{}, logger); err == nil {
		t.Fatal("the feed off")
	}

	// It serves: health at once; anything else needs a front-proxy cert.
	on.AgentSandboxAPIAddr = testport.Addr(t)
	on.AgentSandboxAPICertFile, on.AgentSandboxAPIKeyFile = writePair(t, t.TempDir(), "localhost")
	runCtx, cancel := context.WithCancel(ctx)
	srv, err := startAgentSandboxAPI(runCtx, on, &fakeFeedClient{Noop: cluster.NewNoop("n", "", ""), feedOn: true}, nopBackend{}, logger)
	if err != nil || srv == nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = client.Get("https://" + on.AgentSandboxAPIAddr + "/readyz")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz = %v %v", resp, err)
	}
	resp.Body.Close()
	resp, err = client.Get("https://" + on.AgentSandboxAPIAddr + "/apis/agents.x-k8s.io/v1beta1/sandboxes")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no client certificate = %v %v", resp, err)
	}
	resp.Body.Close()
	cancel()
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, err := client.Get("https://" + on.AgentSandboxAPIAddr + "/healthz"); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server did not stop with its context")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
