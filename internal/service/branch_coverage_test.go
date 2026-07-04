package service

import (
	"context"
	crand "crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type scriptedRandReader struct {
	errs  []error
	calls int
}

func (r *scriptedRandReader) Read(p []byte) (int, error) {
	idx := r.calls
	r.calls++
	if idx < len(r.errs) && r.errs[idx] != nil {
		return 0, r.errs[idx]
	}
	for i := range p {
		p[i] = byte(0x40 + idx)
	}
	return len(p), nil
}

func setRandReader(t *testing.T, reader *scriptedRandReader) {
	t.Helper()
	old := crand.Reader
	crand.Reader = reader
	t.Cleanup(func() {
		crand.Reader = old
	})
}

type failingImageDistributionProvider struct {
	err error
}

func (p failingImageDistributionProvider) ClassifyImage(context.Context, string) (models.ImageDistributionMetadata, error) {
	return models.ImageDistributionMetadata{}, p.err
}

type closingCustomDomainCluster struct {
	*cluster.Noop
	store      *storepkg.Store
	addErr     error
	closeStore bool
}

func (c *closingCustomDomainCluster) AddCustomDomain(_ context.Context, _ string, _ string) error {
	if c.closeStore && c.store != nil {
		_ = c.store.Close()
	}
	return c.addErr
}

func (c *closingCustomDomainCluster) RemoveCustomDomain(context.Context, string, string) error {
	return nil
}

type wasmStartHostRuntime struct {
	*recordingRuntime
	hostState *models.SandboxRuntimeState
	hostErr   error
	hostCalls int
}

func (r *wasmStartHostRuntime) StartSandbox(context.Context, *models.Sandbox, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.hostCalls++
	if r.hostErr != nil {
		return nil, r.hostErr
	}
	if r.hostState != nil {
		state := *r.hostState
		return &state, nil
	}
	return &models.SandboxRuntimeState{
		ContainerID: "ctr-wasm-host",
		ContainerIP: "10.0.0.77",
		Status:      models.SandboxStatusStarted,
	}, nil
}

type wasmListErrRuntime struct {
	*wasmRecordingRuntime
	listErr error
}

func (r *wasmListErrRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	if r.wasmRecordingRuntime == nil {
		return map[string]*models.SandboxRuntimeState{}, nil
	}
	return r.wasmRecordingRuntime.ListManaged(context.Background())
}

func TestServiceHelperRandomBranches(t *testing.T) {
	t.Run("toolbox token failure", func(t *testing.T) {
		setRandReader(t, &scriptedRandReader{errs: []error{errors.New("entropy exhausted")}})
		if _, err := generateToolboxToken(); err == nil || !strings.Contains(err.Error(), "entropy exhausted") {
			t.Fatalf("generateToolboxToken() error = %v, want entropy failure", err)
		}
	})

	t.Run("ssh key failure", func(t *testing.T) {
		setRandReader(t, &scriptedRandReader{errs: []error{errors.New("ssh entropy exhausted")}})
		if _, _, err := generateSandboxSSHKeys(); err == nil || !strings.Contains(err.Error(), "ssh entropy exhausted") {
			t.Fatalf("generateSandboxSSHKeys() error = %v, want ssh entropy failure", err)
		}
	})

	t.Run("sandbox id failure", func(t *testing.T) {
		setRandReader(t, &scriptedRandReader{errs: []error{errors.New("id entropy exhausted")}})
		if _, err := generateSandboxID(); err == nil || !strings.Contains(err.Error(), "id entropy exhausted") {
			t.Fatalf("generateSandboxID() error = %v, want id entropy failure", err)
		}
	})

	t.Run("template id failure", func(t *testing.T) {
		setRandReader(t, &scriptedRandReader{errs: []error{errors.New("template entropy exhausted")}})
		if _, err := generateTemplateID(); err == nil || !strings.Contains(err.Error(), "template entropy exhausted") {
			t.Fatalf("generateTemplateID() error = %v, want template id failure", err)
		}
	})
}

func TestCreateSandboxValidationBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("image distribution provider error", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		svc.images = failingImageDistributionProvider{err: errors.New("classifier down")}
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
		if err == nil || !strings.Contains(err.Error(), "classifier down") {
			t.Fatalf("CreateSandbox() error = %v, want classifier failure", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})

	t.Run("invalid runtime string", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: "bogus"})
		if err == nil || !strings.Contains(err.Error(), "unsupported runtime") {
			t.Fatalf("CreateSandbox() error = %v, want unsupported runtime", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})

	t.Run("custom domain validation", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		allowPublic := true
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Image:              "alpine:3.20",
			CustomDomains:      []string{"not-a-host"},
			AllowPublicTraffic: &allowPublic,
		})
		if err == nil || !strings.Contains(err.Error(), "custom domain") {
			t.Fatalf("CreateSandbox() error = %v, want custom domain validation failure", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})

	t.Run("failover recreate on local-only image", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Image:    docker.BuiltImageNamespace + "/abc123:latest",
			Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		})
		if err == nil || !strings.Contains(err.Error(), "portable image") {
			t.Fatalf("CreateSandbox() error = %v, want recreate failover rejection", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})

	t.Run("invalid durability", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Image:      "alpine:3.20",
			Durability: models.DurabilityDurable,
		})
		if err == nil || !strings.Contains(err.Error(), "durability") {
			t.Fatalf("CreateSandbox() error = %v, want durability rejection", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})

	t.Run("mount validation failure", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Image: "alpine:3.20",
			Mounts: []models.MountSpec{{
				Type:   models.MountTypeS3,
				Target: "not-absolute",
				Source: "bucket",
			}},
		})
		if err == nil || !strings.Contains(err.Error(), "mount 0") {
			t.Fatalf("CreateSandbox() error = %v, want mount validation failure", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})

	t.Run("valid lifecycle reaches later validation", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Image:     "alpine:3.20",
			Lifecycle: &models.Lifecycle{StopIfIdleFor: time.Minute},
			GPUs:      &models.GPURequest{Vendor: "bogus"},
		})
		if err == nil || !strings.Contains(err.Error(), "invalid gpu request") {
			t.Fatalf("CreateSandbox() error = %v, want gpu validation failure", err)
		}
		if rt.createCalls != 0 {
			t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
		}
	})
}

func TestCreateSandboxRollbackAndCustomDomainBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("caddy failure rolls back runtime", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)
		svc.cfg.EnableCaddy = true
		svc.cfg.CaddyAdminURL = server.URL
		svc.cfg.CaddyServerID = "srv0"
		svc.cfg.Domain = "sandbox.test"
		svc.caddy = caddy.New(svc.cfg)
		svc.admitter = nil

		allowPublic := true
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: &allowPublic})
		if err == nil || !strings.Contains(err.Error(), "patch caddy route failed") {
			t.Fatalf("CreateSandbox() error = %v, want caddy failure", err)
		}
		if rt.createCalls != 1 || len(rt.destroyIDs) != 1 {
			t.Fatalf("runtime create/destroy = %d/%v, want 1 destroy rollback", rt.createCalls, rt.destroyIDs)
		}
		if _, err := st.Get(ctx, rt.destroyIDs[0]); err == nil {
			t.Fatal("failed create should not persist sandbox row")
		}
	})

	t.Run("custom-domain conflict rolls back runtime", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		svc.admitter = nil

		allowPublic := true
		first, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
			Image:              "alpine:3.20",
			CustomDomains:      []string{"api.external.test"},
			AllowPublicTraffic: &allowPublic,
		}, "sb-domain-1")
		if err != nil {
			t.Fatalf("seed create: %v", err)
		}
		if first == nil {
			t.Fatal("seed create returned nil response")
		}
		_, err = svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
			Image:              "alpine:3.20",
			CustomDomains:      []string{"api.external.test"},
			AllowPublicTraffic: &allowPublic,
		}, "sb-domain-2")
		if err == nil || !errors.Is(err, storepkg.ErrCustomDomainConflict) {
			t.Fatalf("CreateSandboxWithID() error = %v, want custom domain conflict", err)
		}
		if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != "sb-domain-2" {
			t.Fatalf("runtime destroy ids = %v, want [sb-domain-2]", rt.destroyIDs)
		}
		if _, err := st.Get(ctx, "sb-domain-2"); err == nil {
			t.Fatal("conflicting sandbox leaked into store")
		}
	})

	t.Run("custom-domain cluster close forces final read failure", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		svc.admitter = nil
		clusterStub := &closingCustomDomainCluster{
			Noop:       cluster.NewNoop("self", "http://self", "sandbox.test"),
			store:      st,
			closeStore: true,
		}
		svc.AttachCluster(clusterStub)

		allowPublic := true
		_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
			Image:              "alpine:3.20",
			CustomDomains:      []string{"api.external.test"},
			AllowPublicTraffic: &allowPublic,
		}, "sb-domain-close")
		if err == nil || !strings.Contains(err.Error(), "database is closed") {
			t.Fatalf("CreateSandboxWithID() error = %v, want store close failure", err)
		}
	})
}

func TestCreateWasmSandboxBranchCoverage(t *testing.T) {
	ctx := context.Background()

	t.Run("list managed failure", func(t *testing.T) {
		rt := &wasmListErrRuntime{listErr: errors.New("list managed failed")}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.WasmMaxInstances = 1
		svc.SetWasmRuntime(rt)

		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
			Lifecycle: &models.Lifecycle{StopIfIdleFor: time.Minute},
		})
		if err == nil || !strings.Contains(err.Error(), "list managed failed") {
			t.Fatalf("CreateSandbox() error = %v, want list-managed failure", err)
		}
	})

	t.Run("admitter failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		svc.admitter = capacity.New(
			capacity.HostInfo{CPUCores: 1, MemoryTotalMB: 1},
			capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
			nil,
		)

		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
			Lifecycle: &models.Lifecycle{StopIfIdleFor: time.Minute},
		})
		if err == nil || !errors.Is(err, capacity.ErrCapacityExceeded) {
			t.Fatalf("CreateSandbox() error = %v, want admission failure", err)
		}
	})

	t.Run("mount manager disabled", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		svc.mounts = nil
		svc.cipher = newTestCipher(t)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
			Mounts: []models.MountSpec{{
				Type:   models.MountTypeS3,
				Target: "/data",
				Source: "bucket",
			}},
		})
		if err == nil || !strings.Contains(err.Error(), "mount manager not configured") {
			t.Fatalf("CreateSandbox() error = %v, want mount manager error", err)
		}
	})

	t.Run("mount manager mount-all failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		svc.cipher = newTestCipher(t)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
			Mounts: []models.MountSpec{{
				Type:   "bogus",
				Target: "/data",
				Source: "bucket",
			}},
		})
		if err == nil || !strings.Contains(err.Error(), "mount external storage") {
			t.Fatalf("CreateSandbox() error = %v, want mount-all failure", err)
		}
	})

	t.Run("toolbox token failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		setRandReader(t, &scriptedRandReader{errs: []error{errors.New("entropy exhausted")}})
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
		})
		if err == nil || !strings.Contains(err.Error(), "entropy exhausted") {
			t.Fatalf("CreateSandbox() error = %v, want toolbox token failure", err)
		}
	})

	t.Run("ssh key failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("ssh entropy exhausted")}})
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
		})
		if err == nil || !strings.Contains(err.Error(), "ssh entropy exhausted") {
			t.Fatalf("CreateSandbox() error = %v, want ssh key failure", err)
		}
	})

	t.Run("sandbox id failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(rt)
		setRandReader(t, &scriptedRandReader{errs: []error{nil, nil, errors.New("id entropy exhausted")}})
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			ModuleRef: "hello.wasm",
			Runtime:   models.RuntimeWasm,
		})
		if err == nil || !strings.Contains(err.Error(), "id entropy exhausted") {
			t.Fatalf("CreateSandbox() error = %v, want sandbox id failure", err)
		}
	})

	t.Run("custom domain sync failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		var customPatchCalls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/sandbox-sb-wasm-sync-fail-custom-"):
				customPatchCalls++
				if customPatchCalls == 1 {
					http.NotFound(w, r)
					return
				}
				http.Error(w, "boom", http.StatusInternalServerError)
			case r.Method == http.MethodPatch && r.URL.Path == "/id/sandbox-sb-wasm-sync-fail":
				http.NotFound(w, r)
			case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)
		svc.cfg.EnableCaddy = true
		svc.cfg.CaddyAdminURL = server.URL
		svc.cfg.CaddyServerID = "srv0"
		svc.caddy = caddy.New(svc.cfg)

		allowPublic := true
		_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
			ModuleRef:          "hello.wasm",
			Runtime:            models.RuntimeWasm,
			CustomDomains:      []string{"api.external.test"},
			AllowPublicTraffic: &allowPublic,
		}, "sb-wasm-sync-fail")
		if err == nil || !strings.Contains(err.Error(), "install wasm custom-domain route") {
			t.Fatalf("CreateSandboxWithID() error = %v, want caddy sync failure", err)
		}
		if rt.createCalls != 1 {
			t.Fatalf("runtime Create calls = %d, want 1", rt.createCalls)
		}
		if _, err := st.Get(ctx, "sb-wasm-sync-fail"); err == nil {
			t.Fatal("failed create should not leave a sandbox row")
		}
	})

	t.Run("cluster close forces final read failure", func(t *testing.T) {
		rt := &wasmRecordingRuntime{}
		svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		var customPatchCalls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/sandbox-sb-wasm-close-custom-"):
				customPatchCalls++
				if customPatchCalls == 1 {
					http.NotFound(w, r)
					return
				}
				_ = st.Close()
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodPatch && r.URL.Path == "/id/sandbox-sb-wasm-close":
				http.NotFound(w, r)
			case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)
		svc.cfg.EnableCaddy = true
		svc.cfg.CaddyAdminURL = server.URL
		svc.cfg.CaddyServerID = "srv0"
		svc.caddy = caddy.New(svc.cfg)

		allowPublic := true
		_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
			ModuleRef:          "hello.wasm",
			Runtime:            models.RuntimeWasm,
			CustomDomains:      []string{"api.external.test"},
			AllowPublicTraffic: &allowPublic,
		}, "sb-wasm-close")
		if err == nil || !strings.Contains(err.Error(), "database is closed") {
			t.Fatalf("CreateSandboxWithID() error = %v, want final store read failure", err)
		}
	})
}

func TestStartSandboxBranchCoverage(t *testing.T) {
	ctx := context.Background()

	t.Run("foreign owner gets not found", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-start-owner",
			Image:        "alpine:3.20",
			Status:       models.SandboxStatusStopped,
			Runtime:      models.RuntimeDocker,
			ContainerID:  "ctr-start-owner",
			ContainerIP:  "10.0.0.20",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			OwnerRef:     "acct-1",
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if _, err := svc.StartSandbox(userCtx("acct-2"), "sb-start-owner"); !errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("StartSandbox() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("admitter failure", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.admitter = capacity.New(
			capacity.HostInfo{CPUCores: 1, MemoryTotalMB: 1},
			capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
			nil,
		)
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-start-admit",
			Image:        "alpine:3.20",
			Status:       models.SandboxStatusStopped,
			Runtime:      models.RuntimeDocker,
			ContainerID:  "ctr-start-admit",
			ContainerIP:  "10.0.0.21",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-start-admit"); err == nil || !errors.Is(err, capacity.ErrCapacityExceeded) {
			t.Fatalf("StartSandbox() error = %v, want admitter failure", err)
		}
	})

	t.Run("regular start mount reestablish failure", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cipher = newTestCipher(t)
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-start-mounts",
			Image:        "alpine:3.20",
			Status:       models.SandboxStatusStopped,
			Runtime:      models.RuntimeDocker,
			ContainerID:  "ctr-start-mounts",
			ContainerIP:  "10.0.0.22",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		sealed, err := svc.sealMounts([]models.MountSpec{{
			Type:   "bogus",
			Target: "/data",
			Source: "bucket",
		}})
		if err != nil {
			t.Fatalf("sealMounts: %v", err)
		}
		if err := st.PutMounts(ctx, "sb-start-mounts", sealed); err != nil {
			t.Fatalf("PutMounts: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-start-mounts"); err == nil || !strings.Contains(err.Error(), "reestablish mounts") {
			t.Fatalf("StartSandbox() error = %v, want mount reestablish failure", err)
		}
	})

	t.Run("passivated wasm mount load failure", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&recordingRuntime{})
		svc.cipher = &secrets.Cipher{}
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-wasm-mount-fail",
			Image:        "hello.wasm",
			Status:       models.SandboxStatusPassivated,
			Runtime:      models.RuntimeWasm,
			ContainerID:  "ctr-wasm-mount-fail",
			ContainerIP:  "",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			Durability:   models.DurabilityPassivatable,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if err := st.PutMounts(ctx, "sb-wasm-mount-fail", []byte("not-a-ciphertext")); err != nil {
			t.Fatalf("PutMounts: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-wasm-mount-fail"); err == nil || !strings.Contains(err.Error(), "cipher not initialized") {
			t.Fatalf("StartSandbox() error = %v, want mount load failure", err)
		}
	})

	t.Run("passivated wasm reestablish failure", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&recordingRuntime{})
		svc.cipher = newTestCipher(t)
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-wasm-reestablish",
			Image:        "hello.wasm",
			Status:       models.SandboxStatusPassivated,
			Runtime:      models.RuntimeWasm,
			ContainerID:  "ctr-wasm-reestablish",
			ContainerIP:  "",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			Durability:   models.DurabilityPassivatable,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		sealed, err := svc.sealMounts([]models.MountSpec{{
			Type:   "bogus",
			Target: "/data",
			Source: "bucket",
		}})
		if err != nil {
			t.Fatalf("sealMounts: %v", err)
		}
		if err := st.PutMounts(ctx, "sb-wasm-reestablish", sealed); err != nil {
			t.Fatalf("PutMounts: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-wasm-reestablish"); err == nil || !strings.Contains(err.Error(), "reestablish mounts") {
			t.Fatalf("StartSandbox() error = %v, want wasm mount reestablish failure", err)
		}
	})

	t.Run("passivated wasm checkpoint missing", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-wasm-checkpoint",
			Image:        "hello.wasm",
			Status:       models.SandboxStatusPassivated,
			Runtime:      models.RuntimeWasm,
			ContainerID:  "ctr-wasm-checkpoint",
			ContainerIP:  "",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			Durability:   models.DurabilityPassivatable,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-wasm-checkpoint"); err == nil || !strings.Contains(err.Error(), "checkpoint missing locally") {
			t.Fatalf("StartSandbox() error = %v, want missing checkpoint", err)
		}
	})

	t.Run("wasm host start error", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		rt := &wasmStartHostRuntime{
			recordingRuntime: &recordingRuntime{},
			hostErr:          errors.New("host start failed"),
		}
		svc.SetWasmRuntime(rt)
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-wasm-host",
			Image:        "hello.wasm",
			Status:       models.SandboxStatusStopped,
			Runtime:      models.RuntimeWasm,
			ContainerID:  "ctr-wasm-host",
			ContainerIP:  "",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			Durability:   models.DurabilityPassivatable,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-wasm-host"); err == nil || !strings.Contains(err.Error(), "host start failed") {
			t.Fatalf("StartSandbox() error = %v, want host start failure", err)
		}
		if rt.hostCalls != 1 {
			t.Fatalf("host StartSandbox calls = %d, want 1", rt.hostCalls)
		}
	})

	t.Run("missing firecracker driver", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-fire-start",
			Image:        "alpine:3.20",
			Status:       models.SandboxStatusStopped,
			Runtime:      models.RuntimeFirecracker,
			ContainerID:  "ctr-fire-start",
			ContainerIP:  "10.0.0.25",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-fire-start"); err == nil || !strings.Contains(err.Error(), "driver not registered") {
			t.Fatalf("StartSandbox() error = %v, want missing firecracker driver", err)
		}
	})

	t.Run("network block unsupported runtime", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.docker = noContainerRuntime{}
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:              "sb-netblock",
			Image:           "alpine:3.20",
			Status:          models.SandboxStatusStopped,
			Runtime:         models.RuntimeDocker,
			ContainerID:     "ctr-netblock",
			ContainerIP:     "10.0.0.26",
			CPU:             1,
			MemoryMB:        256,
			DiskGB:          5,
			NetworkBlockAll: true,
			CreatedAt:       now,
			UpdatedAt:       now,
			LastActiveAt:    now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if _, err := svc.StartSandbox(ctx, "sb-netblock"); err == nil || !strings.Contains(err.Error(), "network_block_all") {
			t.Fatalf("StartSandbox() error = %v, want network block unsupported", err)
		}
	})
}
