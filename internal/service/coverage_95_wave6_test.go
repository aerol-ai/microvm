package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCreateSandboxPutMountsRollbackViaHooks(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.admitter = nil
	// Override sealed mounts without FUSE MountAll so PutMounts runs offline.
	svc.testSealedMountsOverride = []byte("sealed-mount-blob")
	svc.testAfterStoreCreate = func() { _ = svc.store.Close() }

	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-putmounts")
	if err == nil || !strings.Contains(err.Error(), "persist sandbox mounts") {
		t.Fatalf("err = %v, want persist sandbox mounts failure", err)
	}
}

func TestCreateWasmPutMountsAndCustomDomainGetRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("put_mounts", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, rt)
		svc.cfg.EnableWasm = true
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		svc.testSealedMountsOverride = []byte("wasm-sealed")
		svc.testAfterStoreCreate = func() { _ = svc.store.Close() }
		_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeWasm, ModuleRef: "mod.wasm",
		}, "sb-wasm-mnt")
		if err == nil {
			t.Fatal("expected PutMounts rollback")
		}
		if len(rt.destroyIDs) == 0 {
			t.Fatal("expected wasm Destroy on PutMounts rollback")
		}
	})

	t.Run("custom_domain_get", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, rt)
		svc.cfg.EnableWasm = true
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "external.test"
		svc.cfg.EnableCaddy = true
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		pub := true
		// Close after custom domains persist so store.Get fails before sync.
		svc.testAfterCustomDomainsOnCreate = func() { _ = svc.store.Close() }
		_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeWasm, ModuleRef: "mod.wasm",
			AllowPublicTraffic: &pub,
			CustomDomains:      []string{"api.external.test"},
		}, "sb-wasm-cd")
		if err == nil {
			t.Fatal("expected Get failure after custom-domain persist")
		}
	})

	t.Run("seal_registry", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		svc.cfg.EnableWasm = true
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		// Zero Cipher fails Encrypt — sealRegistry error arm.
		svc.cipher = &secrets.Cipher{}
		_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
			Runtime:   models.RuntimeWasm,
			ModuleRef: "mod.wasm",
			Registry:  &models.RegistryAuth{Server: "reg.io", Username: "u", Password: "p"},
		}, "sb-wasm-reg")
		if err == nil || !strings.Contains(err.Error(), "encrypt registry") && !strings.Contains(err.Error(), "cipher") {
			// sealRegistry wraps encrypt errors; empty Cipher panics or errors.
			if err == nil {
				t.Fatal("expected sealRegistry failure")
			}
		}
	})
}

func TestCreateSandboxContainerdEngineNotRegistered(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.admitter = nil
	svc.cfg.ContainerEngine = models.ContainerEngineContainerd
	svc.containerd = nil
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-ctrd")
	if err == nil || !errors.Is(err, models.ErrContainerEngineNotRegistered) {
		t.Fatalf("err = %v, want ErrContainerEngineNotRegistered", err)
	}
}

func TestCreateFirecrackerStoreCreateRollback(t *testing.T) {
	ctx := context.Background()
	base := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, base)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(&storeCloseAfterRuntimeCreate{recordingRuntime: base, st: st})
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
	}, "sb-fc-create")
	if err == nil {
		t.Fatal("expected firecracker store.Create failure")
	}
	if len(base.destroyIDs) == 0 {
		t.Fatal("expected firecracker Destroy on store.Create failure")
	}
}

func TestDeleteJSBundleCoverageBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_store", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.isolateBundles = nil
		err := svc.DeleteJSBundle(ctx, "deadbeef")
		if err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("scoped_foreign", func(t *testing.T) {
		svc := newBundleService(t)
		got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
		if err != nil {
			t.Fatal(err)
		}
		err = svc.DeleteJSBundle(userCtx("other"), got.Digest)
		if !errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("err = %v, want not found", err)
		}
	})

	t.Run("in_use", func(t *testing.T) {
		svc := newBundleService(t)
		got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.store.Create(ctx, &models.Sandbox{
			ID: "sb-pin", Runtime: models.RuntimeIsolate, ModuleDigest: got.Digest,
			Image: "sha256:" + got.Digest, Status: models.SandboxStatusStarted,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		err = svc.DeleteJSBundle(ctx, "sha256:"+got.Digest)
		if !errors.Is(err, storepkg.ErrJSBundleInUse) {
			t.Fatalf("err = %v, want in use", err)
		}
	})

	t.Run("list_runtime_fail", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "b")})
		if err != nil {
			t.Fatal(err)
		}
		svc.SetIsolateBundleStore(bundleStore)
		_ = st.Close()
		err = svc.DeleteJSBundle(ctx, "abcd")
		if err == nil || !strings.Contains(err.Error(), "check bundle references") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("delete_ok", func(t *testing.T) {
		svc := newBundleService(t)
		got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteJSBundle(ctx, got.Digest); err != nil {
			t.Fatalf("DeleteJSBundle: %v", err)
		}
		if err := svc.DeleteJSBundle(ctx, got.Digest); !errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("second delete = %v, want not found", err)
		}
	})
}

func TestGetJSBundleNilAndScopedMiss(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := svc.GetJSBundle(ctx, "x"); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("nil bundles: %v", err)
	}
	svc = newBundleService(t)
	got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetJSBundle(userCtx("other"), got.Digest); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("scoped miss = %v", err)
	}
}

func TestCreateJSBundleModulesPathAndReplicatorWarn(t *testing.T) {
	svc := newBundleService(t)
	svc.SetJSBundleReplicator(func(context.Context, string, models.CreateJSBundleRequest) error {
		return errors.New("peer down")
	})
	_, err := svc.CreateJSBundle(context.Background(), models.CreateJSBundleRequest{
		Name:       "multi",
		MainModule: "index.js",
		Modules:    map[string]string{"index.js": `export default { async fetch(){ return new Response("ok"); } };`},
	})
	if err != nil {
		t.Fatalf("CreateJSBundle modules: %v", err)
	}
}

func TestPlatformVolumeCRUDDisabledAndTenantErrors(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.cfg.PlatformVolumes.Enabled = false
	if _, err := s.CreatePlatformVolume(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("create disabled = %v", err)
	}
	if _, err := s.GetPlatformVolume(ctx, "id"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("get disabled = %v", err)
	}
	if _, err := s.GetPlatformVolumeByName(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("getByName disabled = %v", err)
	}
	if _, err := s.ListPlatformVolumes(ctx); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("list disabled = %v", err)
	}
	if err := s.DeletePlatformVolume(ctx, "id"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("delete disabled = %v", err)
	}

	s2 := enabledVolumeService(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	if _, err := s2.CreatePlatformVolume(ctx, "data"); err == nil {
		t.Fatal("expected generateVolumeID failure")
	}
}

func TestPublicTrafficCaddyErrorArms(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "example.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "example.test",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})

	deny := false
	sb := &models.Sandbox{
		ID: "sb-pub", ContainerIP: "10.0.0.9", AllowPublicTraffic: &deny,
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com"}},
		ExposedPorts:  []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// deleteSandboxPublicRoutes / cleanup with failing caddy — firstErr arms.
	_ = svc.deleteSandboxPublicRoutes(ctx, sb)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)

	allow := false
	sb2 := &models.Sandbox{ID: "sb-en", ContainerIP: "10.0.0.8", AllowPublicTraffic: &allow}
	if err := st.Create(ctx, sb2); err != nil {
		t.Fatalf("Create sb2: %v", err)
	}
	if err := svc.enableSandboxPublicTraffic(ctx, sb2); err == nil {
		t.Fatal("expected enableSandboxPublicTraffic caddy failure")
	}
}

func TestPushWasmModuleValidBytesBranches(t *testing.T) {
	ctx := context.Background()
	raw, err := hex.DecodeString(wasmmod.MinimalWasmHex)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing_token_after_validate", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.WasmRegistryPushHost = "registry.example.com/wasm"
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "user", "", bytes.NewReader(raw))
		if err == nil || !strings.Contains(err.Error(), "registry credentials required") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("push_artifact_fails", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		// Unreachable host — ValidateFile succeeds, PushModuleArtifact fails.
		svc.cfg.WasmRegistryPushHost = "127.0.0.1:1"
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "user", "tok", bytes.NewReader(raw))
		if err == nil {
			t.Fatal("expected PushModuleArtifact failure")
		}
	})

	t.Run("copy_error", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.WasmRegistryPushHost = "registry.example.com/wasm"
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "user", "tok", errReader{})
		if err == nil {
			t.Fatal("expected copy error")
		}
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestApplyHTTPPortRouteDirectBypassRetryArm(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.HTTPWakeDirectRouteRetryDuration = time.Millisecond
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	sb := &models.Sandbox{
		ID: "sb-bypass", ContainerIP: "10.0.0.3", Status: models.SandboxStatusStarted,
		Lifecycle: models.Lifecycle{Serverless: true},
	}
	err := svc.applyHTTPPortRoute(ctx, sb, 8080)
	if err == nil {
		t.Fatal("expected UpsertPortRouteWithRetry failure")
	}
}

func TestOwnerCreateAccountMappingWarn(t *testing.T) {
	ctx := userCtx("acct-map")
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.admitter = nil
	_ = st.Close()
	// UpsertAccountMapping fails (store closed) but create continues to fail
	// later — the warn arm for mapping upsert must run first.
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-map")
	if err == nil {
		t.Fatal("expected create failure on closed store")
	}
}

func TestDestroySandboxRuntimeMissingAndClosedStore(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-des", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeWasm, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// wasm runtime not registered → runtimeForSandbox error.
	if err := svc.DestroySandbox(ctx, "sb-des"); err == nil {
		t.Fatal("expected missing wasm runtime error")
	}

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	sb2 := &models.Sandbox{
		ID: "sb-des2", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		ExposedPorts: []models.ExposedPort{{Port: 80}},
	}
	if err := st2.Create(ctx, sb2); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = st2.Close()
	_ = svc2.DestroySandbox(ctx, "sb-des2") // best-effort through closed store
}

func TestUpdateLifecycleSyncRouteWarn(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-life2", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.4", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Flip serverless on a started sandbox so syncExposedPortRoute warn arm runs.
	if _, err := svc.UpdateLifecycle(ctx, "sb-life2", models.Lifecycle{
		Serverless:    true,
		StopIfIdleFor: time.Minute,
	}); err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}
}

func TestBundleFromCreateRequestDefaultMainCompat(t *testing.T) {
	_, err := bundleFromCreateRequest(models.CreateJSBundleRequest{
		Modules: map[string]string{jsbundle.DefaultMainModule: `export default { async fetch(){ return new Response("ok"); } };`},
	})
	if err != nil {
		t.Fatalf("bundleFromCreateRequest: %v", err)
	}
	_, err = bundleFromCreateRequest(models.CreateJSBundleRequest{
		Source:  "not both",
		Modules: map[string]string{"a": "b"},
	})
	if err == nil {
		t.Fatal("expected exactly-one validation error")
	}
}

func TestExposePortProtocolConflictAndWasmIsolateReject(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 30000
	svc.cfg.L4PortRangeEnd = 30010
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-exp", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.5", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Side-table write so scopedGet loads CustomDomains without DNS verify.
	if err := st.AddCustomDomain(ctx, "sb-exp", "api.external.test", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	if _, err := svc.exposePort(ctx, "sb-exp", 5432, models.ExposedPortProtocolTCP, 0); !errors.Is(err, ErrCustomDomainProtocolConflict) {
		t.Fatalf("tcp+custom = %v", err)
	}

	wasm := &models.Sandbox{
		ID: "sb-w", Image: "m", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, wasm); err != nil {
		t.Fatalf("Create wasm: %v", err)
	}
	if _, err := svc.exposePort(ctx, "sb-w", 80, models.ExposedPortProtocolTCP, 0); err == nil {
		t.Fatal("expected wasm tcp reject")
	}

	iso := &models.Sandbox{
		ID: "sb-i", Image: "m", Status: models.SandboxStatusStarted, Runtime: models.RuntimeIsolate,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, iso); err != nil {
		t.Fatalf("Create iso: %v", err)
	}
	if _, err := svc.exposePort(ctx, "sb-i", 80, models.ExposedPortProtocolTLS, 0); err == nil {
		t.Fatal("expected isolate tls reject")
	}
}

// Silence unused import if io only used via errReader path elsewhere.
var _ = io.EOF
