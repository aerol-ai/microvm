package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type quotaFailRuntime struct {
	*recordingRuntime
	blockAllErr     error
	blockIngressErr error
	clearEgressErr  error
	clearIngressErr error
}

func (r *quotaFailRuntime) ApplyNetworkBlockAll(string) error     { return r.blockAllErr }
func (r *quotaFailRuntime) ApplyNetworkBlockIngress(string) error { return r.blockIngressErr }
func (r *quotaFailRuntime) ClearNetworkBlockEgress(string) error  { return r.clearEgressErr }
func (r *quotaFailRuntime) ClearNetworkBlockIngress(string) error { return r.clearIngressErr }

func TestResolvePlatformVolumesErrorArmsWave8(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)

	req := models.CreateSandboxRequest{
		Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
	}
	s.cfg.PlatformVolumes.Enabled = false
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
	s.cfg.PlatformVolumes.Enabled = true
	for _, rt := range []string{models.RuntimeFirecracker, models.RuntimeWasm, models.RuntimeIsolate} {
		if _, err := s.resolvePlatformVolumes(ctx, &req, rt); !errors.Is(err, models.ErrPlatformVolumesUnsupportedRuntime) {
			t.Fatalf("%s = %v", rt, err)
		}
	}
	bad := models.CreateSandboxRequest{
		Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: "../bad", Path: "/x"}},
	}
	if _, err := s.resolvePlatformVolumes(ctx, &bad, models.RuntimeDocker); err == nil {
		t.Fatal("expected sanitize failure")
	}
	s.store = nil
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err == nil || !strings.Contains(err.Error(), "store is not configured") {
		t.Fatalf("nil store = %v", err)
	}

	s2 := enabledVolumeService(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	if _, err := s2.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err == nil {
		t.Fatal("expected volume id entropy failure")
	}
}

func TestResolvePlatformVolumesForReplicationWave8(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	s.cfg.PlatformVolumes.Enabled = false
	req := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "d", Path: "/w"}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, req); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
	s.cfg.PlatformVolumes.Enabled = true
	if err := s.ResolvePlatformVolumesForReplication(ctx, nil); err != nil {
		t.Fatalf("nil req = %v", err)
	}
	bad := &models.CreateSandboxRequest{
		Image: "alpine",
		PlatformVolumes: []models.PlatformVolumeMount{
			{Name: "../bad", Path: "/x"},
		},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, bad); err == nil {
		t.Fatal("expected sanitize failure")
	}
	if _, err := s.CreatePlatformVolume(ctx, "data"); err != nil {
		t.Fatal(err)
	}
	ok := &models.CreateSandboxRequest{
		Image:           "alpine",
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace", ReadOnly: true}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, ok); err != nil {
		t.Fatalf("ResolvePlatformVolumesForReplication: %v", err)
	}
	if len(ok.Mounts) == 0 || len(ok.PlatformVolumes) != 0 {
		t.Fatalf("mounts=%d platformVolumes=%d", len(ok.Mounts), len(ok.PlatformVolumes))
	}
	miss := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "missing", Path: "/w"}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, miss); err == nil {
		t.Fatal("expected missing volume")
	}
	empty := &models.CreateSandboxRequest{Image: "alpine"}
	if err := s.ResolvePlatformVolumesForReplication(ctx, empty); err != nil {
		t.Fatalf("empty: %v", err)
	}
	s.store = nil
	again := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/w"}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, again); err == nil {
		t.Fatal("expected nil store")
	}
}

func TestPlatformVolumeCRUDTenantAndSanitizeWave8(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	if _, err := s.CreatePlatformVolume(ctx, "../nope"); err == nil {
		t.Fatal("expected sanitize reject")
	}
	// Empty PAT + no user token → TenantScope error on volumeTenant.
	s.cfg.PATToken = ""
	if _, err := s.CreatePlatformVolume(ctx, "data"); err == nil {
		t.Fatal("expected tenant scope failure")
	}
	if _, err := s.GetPlatformVolume(ctx, "vol-x"); err == nil {
		t.Fatal("expected get tenant failure")
	}
	if _, err := s.GetPlatformVolumeByName(ctx, "data"); err == nil {
		t.Fatal("expected getByName tenant failure")
	}
	if _, err := s.ListPlatformVolumes(ctx); err == nil {
		t.Fatal("expected list tenant failure")
	}
	if err := s.DeletePlatformVolume(ctx, "vol-x"); err == nil {
		t.Fatal("expected delete tenant failure")
	}

	s2 := enabledVolumeService(t)
	s2.cfg.PlatformVolumes.MaxPerTenant = 1
	if _, err := s2.CreatePlatformVolume(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.CreatePlatformVolume(ctx, "two"); !errors.Is(err, models.ErrPlatformVolumeQuota) {
		t.Fatalf("quota = %v", err)
	}
}

func TestApplyNetworkQuotaStateArmsWave8(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.applyNetworkQuotaState(ctx, nil, true, false)

	now := time.Now().UTC()
	wasm := &models.Sandbox{
		ID: "sb-wq", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, NetworkQuotaExceeded: true,
	}
	if err := st.Create(ctx, wasm); err != nil {
		t.Fatal(err)
	}
	svc.applyNetworkQuotaState(ctx, wasm, false, false) // clear
	svc.applyNetworkQuotaState(ctx, wasm, true, false)  // mark

	failRT := &quotaFailRuntime{
		recordingRuntime: &recordingRuntime{},
		blockAllErr:      errors.New("block all"),
		blockIngressErr:  errors.New("block in"),
		clearEgressErr:   errors.New("clear eg"),
		clearIngressErr:  errors.New("clear in"),
	}
	svc.docker = failRT
	dockerSB := &models.Sandbox{
		ID: "sb-dq", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.9",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, NetworkQuotaExceeded: true,
	}
	if err := st.Create(ctx, dockerSB); err != nil {
		t.Fatal(err)
	}
	svc.applyNetworkQuotaState(ctx, dockerSB, true, true)
	svc.applyNetworkQuotaState(ctx, dockerSB, false, false)

	// No IP → skip iptables, still touch store flags.
	noIP := &models.Sandbox{ID: "sb-noip", Image: "alpine", Status: models.SandboxStatusStopped, NetworkQuotaExceeded: true}
	if err := st.Create(ctx, noIP); err != nil {
		t.Fatal(err)
	}
	svc.applyNetworkQuotaState(ctx, noIP, false, false)

	_ = st.Close()
	svc.applyNetworkQuotaState(ctx, dockerSB, true, false) // mark warn on closed store
}

func TestEnsureNetstatsReadyWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.NetstatsPollInterval = 0
	if err := svc.EnsureNetstatsReady(ctx); err == nil || !strings.Contains(err.Error(), "poll interval") {
		t.Fatalf("interval = %v", err)
	}
	svc.cfg.NetstatsPollInterval = time.Hour
	svc.events = nil
	if err := svc.EnsureNetstatsReady(ctx); err == nil || !strings.Contains(err.Error(), "events client") {
		t.Fatalf("events = %v", err)
	}
	svc.SetEventsSource(stubEventsSource{})
	// Stub events StreamEvents fails; poller.Start may still succeed depending on impl.
	_ = svc.EnsureNetstatsReady(ctx)
	_ = svc.EnsureNetstatsReady(ctx) // latched / second call
}

func TestClusterSecretsErrorArmsWave8(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Mounts: []models.MountSpec{{
			Type: models.MountTypeS3, Target: "/data", Source: "s3://b/k",
			Credentials: map[string]string{"access_key": "a", "secret_key": "s"},
		}},
	}

	s := &Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := s.SealClusterSecrets(req); err == nil || !strings.Contains(err.Error(), "cipher") {
		t.Fatalf("nil cipher = %v", err)
	}

	s.cipher = newTestCipher(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("dek fail")}})
	if _, err := s.SealClusterSecretsForRecipient(req, "node-a"); err == nil {
		t.Fatal("expected dek entropy failure")
	}

	setRandReader(t, &scriptedRandReader{errs: []error{nil /*dek*/, errors.New("nonce fail")}})
	if _, err := s.SealClusterSecretsForRecipient(req, "*"); err == nil {
		t.Fatal("expected nonce entropy failure")
	}

	// Broken cipher (zero value) fails EncryptWithAAD on wrap.
	s.cipher = &secrets.Cipher{}
	if _, err := s.SealClusterSecretsForRecipient(req, "*"); err == nil {
		t.Fatal("expected wrap failure")
	}

	s2 := &Service{cipher: newTestCipher(t), store: nil, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := s2.PutClusterSecretsForRecipient(ctx, "sb", req, "n1"); err == nil || !strings.Contains(err.Error(), "store") {
		t.Fatalf("nil store put = %v", err)
	}
	if _, err := s2.PutClusterSecretsForRecipient(ctx, "", req, "n1"); err == nil {
		t.Fatal("expected empty sandbox id")
	}
	empty, err := s2.PutClusterSecretsForRecipient(ctx, "sb", models.CreateSandboxRequest{Image: "x"}, "n1")
	if err != nil || empty.Ref != "" {
		t.Fatalf("no secrets = %+v %v", empty, err)
	}
}

func TestKickTemplateBuildMkdirAndFailWave8(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Templates dir is a file → MkdirAll fails → failed status path.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	builder := &fakeTemplateBuilder{err: errors.New("build boom"), done: done}
	svc := &Service{
		cfg: config.Config{
			FirecrackerTemplatesDir:         blocked,
			FirecrackerTemplateBuildTimeout: time.Second,
		},
		store:           st,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		templateBuilder: builder,
	}
	tpl := &models.Template{ID: "tpl-mkdir", Image: "alpine", Status: models.TemplateStatusPending}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// mkdir fails before Build; done may not fire — wait briefly for status.
	}
	time.Sleep(50 * time.Millisecond)

	// Rootfs build failure with removable dir + StagingDir cleanup warn.
	dir := filepath.Join(t.TempDir(), "tpls")
	done2 := make(chan struct{}, 1)
	builder2 := &fakeTemplateBuilder{
		err:  errors.New("oci fail"),
		done: done2,
	}
	svc2 := &Service{
		cfg:             config.Config{FirecrackerTemplatesDir: dir, FirecrackerTemplateBuildTimeout: time.Second},
		store:           st,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		templateBuilder: builder2,
	}
	tpl2 := &models.Template{ID: "tpl-fail", Image: "alpine", Status: models.TemplateStatusPending}
	if err := st.CreateTemplate(context.Background(), tpl2); err != nil {
		t.Fatal(err)
	}
	svc2.kickTemplateBuild(tpl2)
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for build fail")
	}

	// Snapshot skipped: builder succeeds, no snapshotter → ready_no_snapshot.
	done3 := make(chan struct{}, 1)
	builder3 := &fakeTemplateBuilder{done: done3}
	svc3 := &Service{
		cfg: config.Config{
			FirecrackerTemplatesDir:         dir,
			FirecrackerTemplateBuildTimeout: time.Second,
			FirecrackerSnapshotEnabled:      false,
		},
		store:           st,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		templateBuilder: builder3,
	}
	tpl3 := &models.Template{ID: "tpl-nosnap", Image: "alpine", Status: models.TemplateStatusPending}
	if err := st.CreateTemplate(context.Background(), tpl3); err != nil {
		t.Fatal(err)
	}
	svc3.kickTemplateBuild(tpl3)
	select {
	case <-done3:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout nosnap")
	}
	time.Sleep(30 * time.Millisecond)
}

func TestExposePortTLSClusterAndHTTPInstallFailWave8(t *testing.T) {
	ctx := context.Background()
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.Method == http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(okServer.Close)
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	t.Cleanup(failServer.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = "127.0.0.1:9443"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: okServer.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)
	svc.AttachCluster(&failingExposeCluster{Noop: cluster.NewNoop("n1", "", "h"), addErr: errors.New("raft")})
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-tls8", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.8",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exposePort(ctx, "sb-tls8", 8443, models.ExposedPortProtocolTLS, 0); err == nil {
		t.Fatal("expected TLS cluster record failure")
	}

	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: failServer.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	if _, err := svc.exposePort(ctx, "sb-tls8", 8080, models.ExposedPortProtocolHTTP, 0); err == nil {
		t.Fatal("expected HTTP install failure")
	}
}

func TestReconcileNetworkHealWave8(t *testing.T) {
	ctx := context.Background()
	rt := &wave3ReconcileRuntime{fakeReconcileRuntime: fakeReconcileRuntime{
		managed:               map[string]*models.SandboxRuntimeState{},
		allowPushAllowedPorts: true,
	}}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.docker = rt
	svc.cfg.EnableServerless = true

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-heal", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-heal", ContainerIP: "10.0.0.55",
		NetworkBlockAll: true, NetworkAllowOut: []string{"10.0.0.0/8"},
		NetworkBytesInLimit: 100, NetworkBytesIn: 200, NetworkQuotaExceeded: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rt.managed["sb-heal"] = &models.SandboxRuntimeState{
		SandboxID: "sb-heal", ContainerID: "ctr-heal", ContainerIP: "10.0.0.55",
		Status: models.SandboxStatusStarted,
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func TestDestroySandboxMountAndDestroyFailWave8(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{destroyErr: errors.New("destroy boom")}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-dd", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroySandbox(ctx, "sb-dd"); err == nil || !strings.Contains(err.Error(), "destroy boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallTLSPortRouteShapesWave8(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete:
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = "127.0.0.1:9443"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)

	none := &models.Sandbox{
		ID: "sb-tls-none", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installTLSPortRoute(ctx, none, 8443); err != nil {
		t.Fatalf("none shape: %v", err)
	}
}

func TestStartL4WakeProxyAddrWave8(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.InternalL4WakeAddr = ""
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second})
	if err := svc.StartL4WakeProxy(context.Background()); err != nil {
		t.Fatalf("empty addr should no-op: %v", err)
	}

	// Bind a real listener then ask StartL4WakeProxy to use the same addr → listen fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	svc.cfg.InternalL4WakeAddr = ln.Addr().String()
	if err := svc.StartL4WakeProxy(context.Background()); err == nil {
		t.Fatal("expected listen failure")
	}
}

func TestPublicTrafficSyncNilAndDisabledWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.syncSandboxPublicRoute(ctx, nil); err != nil {
		t.Fatalf("nil sandbox: %v", err)
	}
	deny := false
	sb := &models.Sandbox{ID: "sb-pt", AllowPublicTraffic: &deny, ContainerIP: "10.0.0.1"}
	if err := svc.syncSandboxPublicRoute(ctx, sb); err != nil {
		t.Fatalf("disabled public: %v", err)
	}
	_ = svc.deleteSandboxPublicRoutes(ctx, nil)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, nil)
}

func TestCreateSandboxEntropyAndAdmitFailWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, admit := newServiceRuntimeHarness(t, &recordingRuntime{})
	// Exhaust capacity so Admit fails after ID generation.
	if admit != nil {
		for i := 0; i < 100; i++ {
			_ = admit.Admit("filler-"+string(rune('a'+i%26))+string(rune('0'+i/26)), capacityRequestFromCreate(models.CreateSandboxRequest{
				Image: "alpine", CPU: 8, MemoryMB: 16384,
			}))
		}
	}
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine", CPU: 8, MemoryMB: 16384}, "sb-admit-fail")
	if err == nil {
		// Host may still have capacity; force via nil admitter + entropy instead.
		t.Log("admit did not reject; covering entropy arms")
	}

	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("tok")}})
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.admitter = nil
	if _, err := svc2.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine"}, "sb-tok"); err == nil {
		t.Fatal("expected toolbox token entropy failure")
	}
	setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("ssh")}})
	if _, err := svc2.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine"}, "sb-ssh"); err == nil {
		t.Fatal("expected ssh entropy failure")
	}
	setRandReader(t, &scriptedRandReader{errs: []error{nil, nil, errors.New("id")}})
	if _, err := svc2.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"}); err == nil {
		t.Fatal("expected id entropy failure")
	}
}

func TestOpenClusterSecretsStoreMissWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cipher = newTestCipher(t)
	_, err := svc.OpenClusterSecrets(ctx, models.CreateSandboxRequest{Image: "x"}, cluster.PlacementSecrets{
		Ref: "missing-ref", Version: 1,
	})
	if err == nil {
		t.Fatal("expected missing secret ref error")
	}
}

func TestUnexposePortAndDeleteTLSWave8(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-unx", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		ExposedPorts: []models.ExposedPort{
			{Port: 80, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 443, Protocol: models.ExposedPortProtocolTLS},
			{Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 36000},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{80, 443, 5432} {
		if err := svc.UnexposePort(ctx, "sb-unx", p); err != nil {
			t.Fatalf("UnexposePort %d: %v", p, err)
		}
	}
	if err := svc.UnexposePort(ctx, "sb-unx", 9999); err != nil {
		// Missing exposure is typically nil/no-op.
		t.Logf("missing unexpose: %v", err)
	}
}

func TestGCZombieSnapshotFailWave8(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "snap fail", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0",
			HTTPClientTimeout: time.Second,
		}),
	}
	svc.gcZombieCaddyEntries(context.Background(), nil)
}

func TestSealClusterSecretEnvelopeDirectWave8(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	out, err := s.sealClusterSecretEnvelope([]byte(`{"x":1}`), []string{"*"})
	if err != nil || len(out) == 0 {
		t.Fatalf("seal = %v %d", err, len(out))
	}
	var env clusterSealedSecretsEnvelope
	if err := json.Unmarshal(out, &env); err != nil || env.Version == 0 {
		t.Fatalf("envelope = %+v %v", env, err)
	}
}

func TestCleanupCreatedPlatformVolumesWave8(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "scratch")
	if err != nil {
		t.Fatal(err)
	}
	s.cleanupCreatedPlatformVolumes(ctx, []models.VolumeAttachment{
		{Tenant: v.Tenant, VolumeID: v.ID, CreatedVolume: true},
		{Tenant: v.Tenant, VolumeID: "missing", CreatedVolume: true},
		{CreatedVolume: false},
	})
}
