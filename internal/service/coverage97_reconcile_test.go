package service

import (
	"context"
	"errors"
	"testing"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// cov97NetRT fails the heal calls reconcile makes for a live container, so
// those warn branches run without a netfilter backend.
type cov97NetRT struct{ *recordingRuntime }

func (cov97NetRT) ApplyNetworkBlockAll(string) error { return errors.New("block") }
func (cov97NetRT) ApplyEgressPolicy(string, []string, []string) error {
	return errors.New("egress")
}

func TestCoverage97ReconcileHealsFail(t *testing.T) {
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-net": {Status: models.SandboxStatusStarted, ContainerID: "ctr-net"},
	}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.docker = &cov97NetRT{rt}
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-net", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, ContainerIP: "10.0.0.8",
		NetworkBlockAll: true, NetworkAllowOut: []string{"10.0.0.0/8"},
		NetworkQuotaExceeded: true,
		CPU:                  1, MemoryMB: 128, DiskGB: 1,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile = %v", err)
	}
}

// cov97WasmRT is a Runtime that is not a ContainerRuntime, so reconcile's
// network-heal calls for a live WASM row take the skip branch.
type cov97WasmRT struct {
	managed map[string]*models.SandboxRuntimeState
}

func (cov97WasmRT) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, errors.New("create")
}
func (cov97WasmRT) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, errors.New("start")
}
func (cov97WasmRT) Stop(context.Context, string) error             { return nil }
func (cov97WasmRT) Destroy(context.Context, *models.Sandbox) error { return nil }
func (cov97WasmRT) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", errors.New("snapshot")
}
func (cov97WasmRT) Resize(context.Context, string, models.ResizeSandboxRequest) error { return nil }
func (cov97WasmRT) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return &models.SandboxRuntimeState{}, nil
}
func (w cov97WasmRT) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return w.managed, nil
}
func (cov97WasmRT) Ping(context.Context) error                { return nil }
func (cov97WasmRT) RemoveImage(context.Context, string) error { return nil }
func (cov97WasmRT) StartSandbox(context.Context, *models.Sandbox, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, errors.New("start sandbox")
}

var _ wasmruntime.StartHost = cov97WasmRT{}

func TestCoverage97WasmHealAndRegistryAuth(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rt := cov97WasmRT{managed: map[string]*models.SandboxRuntimeState{
		"sb-wasm": {Status: models.SandboxStatusStarted, ContainerID: "wasm-1"},
	}}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.wasm = rt
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm", Image: "mod.wasm", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeWasm, ContainerIP: "10.0.0.9",
		NetworkBlockAll: true, NetworkAllowOut: []string{"10.0.0.0/8"},
		CPU: 1, MemoryMB: 128, DiskGB: 1,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile = %v", err)
	}

	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-auth", Image: "mod.wasm", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeWasm, RegistryAuthSealed: []byte("not-a-seal"),
		CPU: 1, MemoryMB: 128, DiskGB: 1,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, "sb-auth"); err == nil {
		t.Fatal("start accepted a sealed registry blob the cipher cannot open")
	}
}
