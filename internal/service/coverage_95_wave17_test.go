package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNewTemplateArtifactPusherValidationWave17(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := NewTemplateArtifactPusher(SnapshotPushConfig{Enabled: false}, nil, "", logger)
	if err != nil || p != nil {
		t.Fatalf("disabled = %v %v", p, err)
	}
	_, err = NewTemplateArtifactPusher(SnapshotPushConfig{Enabled: true}, nil, "/tmp", logger)
	if err == nil {
		t.Fatal("expected validate fail")
	}
	cfg := SnapshotPushConfig{Enabled: true, Host: "r.example", ClusterID: "c", PATPath: filepath.Join(t.TempDir(), "pat")}
	_ = os.WriteFile(cfg.PATPath, []byte("token"), 0o600)
	_, err = NewTemplateArtifactPusher(cfg, nil, "/tmp", logger)
	if err == nil {
		t.Fatal("expected nil docker")
	}
	_, err = NewTemplateArtifactPusher(cfg, &fakeTemplatePushDocker{}, "", logger)
	if err == nil {
		t.Fatal("expected empty templatesDir")
	}
	p, err = NewTemplateArtifactPusher(cfg, &fakeTemplatePushDocker{}, t.TempDir(), nil)
	if err != nil || p == nil {
		t.Fatalf("ok = %v %v", p, err)
	}

	_, err = p.PushOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("nil tpl")
	}
	_, err = p.PushOnce(context.Background(), &models.Template{})
	if err == nil {
		t.Fatal("empty id")
	}
	_, err = (*TemplateArtifactPusher)(nil).PushOnce(context.Background(), &models.Template{ID: "x"})
	if err == nil {
		t.Fatal("nil pusher")
	}
	_, err = p.PushOnce(context.Background(), &models.Template{ID: "missing"})
	if err == nil {
		t.Fatal("missing artifacts")
	}
}

func TestWasmCacheAndModuleGCWave17(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmModulesDir = t.TempDir()
	svc.cfg.WasmCacheDir = filepath.Join(svc.cfg.WasmModulesDir, "cache")
	svc.cfg.WasmCacheGCTTL = time.Hour
	svc.cfg.WasmCacheMaxBytes = 1024
	_ = os.MkdirAll(svc.cfg.WasmCacheDir, 0o755)
	old := filepath.Join(svc.cfg.WasmCacheDir, "deadbeef.wasm")
	_ = os.WriteFile(old, []byte("x"), 0o644)
	_ = os.Chtimes(old, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	_ = os.Mkdir(filepath.Join(svc.cfg.WasmCacheDir, "subdir"), 0o755)
	svc.runWasmCacheGC(ctx, time.Now().UTC())

	svc.cfg.WasmCacheDir = filepath.Join(t.TempDir(), "missing-cache")
	svc.runWasmCacheGC(ctx, time.Now().UTC())

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.cfg.EnableWasm = true
	svc2.cfg.WasmModulesDir = t.TempDir()
	svc2.cfg.WasmModuleGCTTL = time.Hour
	now := time.Now().UTC()
	_ = st2.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-gc", ModuleRef: "file:///tmp/m.wasm", ModulePath: filepath.Join(svc2.cfg.WasmModulesDir, "m.wasm"),
		Status: string(models.WasmModuleStatusReady), CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour),
	})
	_ = st2.Close()
	svc2.runWasmModuleGC(ctx, time.Now().UTC())
}

func TestClusterSecretsOpenEnvelopeFailWave17(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	sealed, err := s.SealClusterSecretsForRecipient(models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, "node-a")
	if err != nil || len(sealed) == 0 {
		t.Fatalf("seal: %v", err)
	}
	if _, err := s.UnsealClusterSecretsForNode(models.CreateSandboxRequest{Image: "x"}, sealed, "wrong-node"); err == nil {
		t.Fatal("expected recipient mismatch / decrypt fail")
	}
	if _, err := s.UnsealClusterSecretsForNode(models.CreateSandboxRequest{Image: "x"}, append([]byte{0}, sealed...), "node-a"); err == nil {
		t.Fatal("expected corrupt fail")
	}
	_, _ = openClusterSecretEnvelopePayload(make([]byte, 32), make([]byte, 64), []string{"*"})
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

func TestCreateWithNilMountsCleanupWave17(t *testing.T) {
	// Cover cleanupMounts early return when mounts is nil after a failed create.
	// MountAll requires mounts; so we only assert the helper shape via Destroy path.
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.mounts = nil
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-nil-mnt", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if err := svc.DestroySandbox(ctx, "sb-nil-mnt"); err != nil {
		t.Fatalf("destroy: %v", err)
	}
}

func TestEnsureNetstatsReadyConcurrentWave17(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.NetstatsPollInterval = time.Second
	svc.events = nil
	done := make(chan struct{})
	go func() {
		_ = svc.EnsureNetstatsReady(context.Background())
		close(done)
	}()
	_ = svc.EnsureNetstatsReady(context.Background())
	<-done
}

func TestL4WakeGetPortHTTPExposureWave17(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-http-l4", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(context.Background(), models.ExposedPort{
		SandboxID: "sb-http-l4", Port: 80, Protocol: models.ExposedPortProtocolHTTP,
		HostPort: 42000, PublicURL: "https://x", CreatedAt: now,
	})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c2.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 42000\r\n"))
		_ = c2.Close()
	}()
	svc.handleL4WakeTCPConn(c1)
}
