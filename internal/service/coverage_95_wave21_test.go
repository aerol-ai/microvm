package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestApplyInFluxRouteUpsertFailAfterOKWave21(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			return
		case http.MethodPut, http.MethodPatch, http.MethodPost:
			http.Error(w, "upsert boom", http.StatusInternalServerError)
			return
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"apps":{}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	p := cluster.Placement{
		SandboxID: "sb-flux21",
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			80:  {Protocol: models.ExposedPortProtocolHTTP},
			443: {Protocol: models.ExposedPortProtocolTLS},
		},
	}
	_ = svc.applyInFluxRoute(ctx, p)
	_ = svc.applyInFluxSandboxRoute(ctx, p)
	_ = svc.applyInFluxPortRoute(ctx, p, 80)
}

func TestGCUnexpectedIngressDeleteErrorsWave21(t *testing.T) {
	ctx := context.Background()
	fake := newGCCaddyFake()
	fake.httpRouteIDs["sandbox-zombie21"] = struct{}{}
	fake.l4TCPServerIDs["tcp-port-39991"] = struct{}{}
	fake.l4TLSRouteIDs["sandbox-zombie21-port-8443-tls"] = struct{}{}
	base := fake.handler(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.Error(w, "delete boom", http.StatusInternalServerError)
			return
		}
		base.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	if err := svc.gcUnexpectedClusterIngressRoutes(ctx, map[string]ingressRouteIntent{}); err == nil {
		t.Fatal("expected firstErr from delete failures")
	}
}

func TestDeletePlatformVolumeMetaArmsWave21(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	tenant, err := s.volumeTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	vol := models.Volume{ID: "v1", Tenant: tenant, Name: "n1", Backend: "s3", Source: "bucket/x", CreatedAt: time.Now().UTC()}

	s.testVolumeMeta = &scriptedVolumeMeta{byID: &vol, attachmentCountErr: errors.New("count boom")}
	if err := s.DeletePlatformVolume(ctx, "v1"); err == nil {
		t.Fatal("expected count error")
	}

	s.testVolumeMeta = &scriptedVolumeMeta{byID: &vol, attachmentCount: 2}
	if err := s.DeletePlatformVolume(ctx, "v1"); !errors.Is(err, models.ErrPlatformVolumeInUse) {
		t.Fatalf("in use: %v", err)
	}

	s2 := enabledVolumeService(t)
	s2.logger = s.logger
	empty := vol
	empty.Source = ""
	s2.testVolumeMeta = &scriptedVolumeMeta{byID: &empty, attachmentCount: 0}
	_ = s2.store.Close()
	_ = s2.DeletePlatformVolume(ctx, "v1")

	s3 := enabledVolumeService(t)
	s3.logger = s.logger
	s3.testVolumeMeta = &scriptedVolumeMeta{byID: &vol, attachmentCount: 0, deleteRowErr: errors.New("del row")}
	if err := s3.DeletePlatformVolume(ctx, "v1"); err == nil {
		t.Fatal("expected delete row error")
	}

	s4 := enabledVolumeService(t)
	s4.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound}
	if err := s4.DeletePlatformVolume(ctx, "missing"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestCustomDomainCapAlreadyHeldWave21(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.CustomDomainsMaxPerSandbox = 1
	svc.cfg.Domain = "example.com"
	svc.cfg.CustomDomainVerifyPrefix = "_aerol-verify"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerol-verify="
	svc.dnsResolver = &mockDNSResolver{records: map[string][]string{
		"_aerol-verify.api.customer.dev": {"aerol-verify=api.customer.dev"},
	}}
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-cap", Image: "a", Status: models.SandboxStatusStarted,
		CustomDomains: []models.CustomDomain{{Hostname: "api.customer.dev", TargetPort: 8080}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	})
	err := svc.AddCustomDomain(ctx, "sb-cap", "api.customer.dev", 8080)
	t.Logf("AddCustomDomain re-add: %v", err)
}

func TestInstallTLSPortRouteFailArmsWave21(t *testing.T) {
	ctx := context.Background()
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(failServer.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.L4PortRangeStart = 21000
	svc.cfg.L4PortRangeEnd = 21100
	svc.cfg.InternalL4WakeDir = t.TempDir()
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: failServer.URL, CaddyServerID: "srv0",
		L4PortRangeStart: 21000, L4PortRangeEnd: 21100, HTTPClientTimeout: time.Second,
	})
	if err := svc.installTLSPortRoute(ctx, &models.Sandbox{ID: "tls-fail", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1"}, 443); err == nil {
		t.Fatal("expected EnsureLayer4Ready failure")
	}

	delServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(delServer.Close)
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableCaddy = true
	svc2.cfg.EnableServerless = true
	svc2.cfg.L4WakeDirectBypassEnabled = true
	svc2.cfg.Domain = "sandbox.example.com"
	svc2.cfg.InternalL4WakeDir = t.TempDir()
	svc2.l4Ready.Store(true)
	svc2.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: delServer.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	sb := &models.Sandbox{
		ID: "tls-none-err", Status: models.SandboxStatusCreating,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc2.installTLSPortRoute(ctx, sb, 443); err == nil {
		t.Fatal("expected delete TLS route failure")
	}
}

func TestStartBuiltImageGCNilDockerWave21(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.ImageBuildGCEnabled = true
	svc.cfg.ImageBuildGCInterval = time.Hour
	svc.dockerAux = nil
	svc.StartBuiltImageGC(context.Background())
	svc.cfg.ImageBuildGCEnabled = false
	svc.StartBuiltImageGC(context.Background())
	svc.cfg.ImageBuildGCEnabled = true
	svc.cfg.ImageBuildGCInterval = 0
	svc.StartBuiltImageGC(context.Background())
}

func TestHandleDuplicateStoreCreateMissWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := svc.handleDuplicateStoreCreate(ctx, "missing-dup", models.ErrSandboxExists); !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestWasmSyncGuestListenWarnWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.SetWasmRuntime(wasmPortsSyncErrRuntime{syncErr: errors.New("sync boom")})
	svc.syncWasmAllowedPorts(ctx, &models.Sandbox{
		ID: "sb-sync", Runtime: models.RuntimeWasm,
		ExposedPorts: []models.ExposedPort{{Port: 8080}},
	})
}

func TestRegisterSnapshotNormalizeFailWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.testNormalizeSnapshotErr = errors.New("norm boom")
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "n", Image: "img"}); err == nil {
		t.Fatal("expected normalize fail")
	}
}

func TestTemplateGCDeleteFailWave21(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-gc21", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	_ = st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-gc21", Status: models.TemplateStatusReadyNoSnapshot, RootfsPath: rootfs,
		CreatedAt: stale, UpdatedAt: stale,
	})
	svc.testAfterTemplateGCSandboxRefCheck = func() { _ = st.Close() }
	svc.runTemplateGC(ctx, now)
}

func TestVolumeReclaimWorkersClampWave21(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.SetVolumeReclaimer(&fakeReclaimer{})
	s.cfg.PlatformVolumes.ReclaimConcurrency = 50
	now := time.Now().UTC()
	_ = s.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
		ID: "one", Tenant: "op", Name: "one", Backend: "local", Source: "/tmp/one", CreatedAt: now,
	}, "/tmp/one")
	s.runVolumeReclaim(ctx)
}

func TestL4WakePendingLimitWave21(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.L4WakeMaxPendingGlobal = 1
	svc.cfg.L4WakeMaxPendingPerSandbox = 1

	release, ok := svc.tryAcquireL4Pending("sb-lim")
	if !ok {
		t.Fatal("first pending should succeed")
	}
	if _, ok := svc.tryAcquireL4Pending("sb-lim"); ok {
		t.Fatal("second pending should fail")
	}
	release()

	svc.cfg.L4WakeMaxActivePerSandbox = 1
	svc.cfg.L4WakeMaxActiveGlobal = 1
	r1, ok := svc.tryAcquireL4Active("sb-act")
	if !ok {
		t.Fatal("first active")
	}
	if _, ok := svc.tryAcquireL4Active("sb-act"); ok {
		t.Fatal("second active should fail")
	}
	r1()
}

func TestServerlessReconstructWakeArmedStoreFailWave21(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = false
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-recon", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(ctx, sb)
	_ = st.Close()
	svc.ReconstructWakeArmedIfNeeded(ctx, sb)
}

func TestL4ListenPortBareNumberWave21(t *testing.T) {
	if got := l4ListenPort("8443"); got != 8443 {
		t.Fatalf("bare = %d", got)
	}
	if got := l4ListenPort("not-a-port"); got != 0 {
		t.Fatalf("bad = %d", got)
	}
}

func TestWriteTemplateManifestBadPathWave21(t *testing.T) {
	if err := writeTemplateManifest("/no/such/dir/manifest.json", templateManifest{SourceImage: "a"}); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestClusterOwnershipNilClusterWave21(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: nil, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n, err := svc.assertClusterOwnership(context.Background(), nil, nil)
	if n != 0 || err != nil {
		t.Fatalf("nil cluster = %d %v", n, err)
	}
}

func TestWasmInstallHTTPRouteShapeNoneExplicitWave21(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableServerless = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.SetWasmRuntime(&wasmPortsRuntime{recordingRuntime: &recordingRuntime{}})
	sb := &models.Sandbox{
		ID: "wasm-none21", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installWasmHTTPPortRoute(ctx, sb, 9090); err != nil {
		t.Fatalf("none: %v", err)
	}
}

func TestCreateForcePlatformAttachmentsWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.admitter = nil
	svc.cfg.PlatformVolumes = enabledVolumeService(t).cfg.PlatformVolumes
	svc.cfg.PATToken = "operator-pat"
	tenant, _ := svc.volumeTenant(ctx)
	svc.testForcePlatformAttachments = []models.VolumeAttachment{{
		VolumeID: "ghost", Tenant: tenant, Target: "/data",
	}}
	svc.testVolumeMeta = &scriptedVolumeMeta{putAttachmentsErr: errors.New("put boom")}
	pub := true
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", AllowPublicTraffic: &pub,
	}, "sb-attach21")
	if err == nil || !strings.Contains(err.Error(), "persist platform") {
		t.Fatalf("err = %v", err)
	}
}
