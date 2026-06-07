package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type wasmModuleAPINoopRuntime struct{}

func (wasmModuleAPINoopRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (wasmModuleAPINoopRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (wasmModuleAPINoopRuntime) Stop(context.Context, string) error { return nil }
func (wasmModuleAPINoopRuntime) Destroy(context.Context, *models.Sandbox) error {
	return nil
}
func (wasmModuleAPINoopRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}
func (wasmModuleAPINoopRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}
func (wasmModuleAPINoopRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (wasmModuleAPINoopRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (wasmModuleAPINoopRuntime) Ping(context.Context) error { return nil }
func (wasmModuleAPINoopRuntime) RemoveImage(context.Context, string) error {
	return nil
}

type stubWasmModuleResolver struct {
	path   string
	digest string
}

func (s stubWasmModuleResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	return &wasmmod.ResolvedModule{
		Ref:       ref,
		Path:      s.path,
		Digest:    s.digest,
		SizeBytes: 4,
	}, nil
}

func TestCreateWasmModule_HappyPath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	modPath := filepath.Join(dir, "mod.wasm")
	if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: dir}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: modPath, digest: "abc123"})

	mod, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file://" + modPath})
	if err != nil {
		t.Fatalf("CreateWasmModule: %v", err)
	}
	if mod.Status != models.WasmModuleStatusReady {
		t.Fatalf("status = %s", mod.Status)
	}
	if mod.ID != "abc123" {
		t.Fatalf("id = %q, want digest", mod.ID)
	}

	got, err := svc.GetWasmModule(ctx, mod.ID)
	if err != nil {
		t.Fatalf("GetWasmModule: %v", err)
	}
	if got.ModuleRef != mod.ModuleRef {
		t.Fatalf("round-trip module_ref mismatch")
	}
}

func TestCreateWasmModule_IdempotentExplicitID(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	modPath := filepath.Join(dir, "mod.wasm")
	_ = os.WriteFile(modPath, []byte("wasm"), 0o600)
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{EnableWasm: true}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: modPath, digest: "d1"})

	req := models.CreateWasmModuleRequest{ID: "my-mod", ModuleRef: "file://x"}
	if _, err := svc.CreateWasmModule(ctx, req); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := svc.CreateWasmModule(ctx, req); err != nil {
		t.Fatalf("retry create: %v", err)
	}
}

func TestDeleteWasmModule_InUseRejected(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-1", ModuleRef: "file://a", Status: "ready", CreatedAt: now, UpdatedAt: now,
	})
	sb := &models.Sandbox{
		ID: "sb-1", Runtime: models.RuntimeWasm, ModuleRef: "file://a",
		Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{EnableWasm: true}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
	if err := svc.DeleteWasmModule(ctx, "mod-1"); !errors.Is(err, store.ErrWasmModuleInUse) {
		t.Fatalf("DeleteWasmModule error = %v, want ErrWasmModuleInUse", err)
	}
}
