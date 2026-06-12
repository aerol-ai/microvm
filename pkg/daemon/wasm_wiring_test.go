package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestWireWasmRuntime_Basic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	modulesDir := t.TempDir()
	runDir := t.TempDir()
	pool := wireWasmRuntime(ctx, config.Config{
		WasmRunDir:     runDir,
		WasmModulesDir: modulesDir,
		WasmEngine:     "wazero",
	}, testLogger(), svc, st)
	if pool != nil {
		t.Fatalf("wireWasmRuntime without pool enabled = %v, want nil", pool)
	}
}

func TestWireWasmRuntime_CatalogueLookupCallback(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	modulesDir := t.TempDir()
	modPath := filepath.Join(modulesDir, "mod.wasm")
	if err := os.WriteFile(modPath, []byte("wasm"), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "catalogue-1", Status: "ready", ModulePath: modPath, Digest: "sha256:abc",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	var resolver *wasmmod.ModuleResolver
	wasmWiringTestHook = func(r *wasmmod.ModuleResolver) { resolver = r }
	t.Cleanup(func() { wasmWiringTestHook = nil })

	_ = wireWasmRuntime(ctx, config.Config{
		WasmRunDir:              t.TempDir(),
		WasmModulesDir:          modulesDir,
		WasmEngine:              "wasmtime",
		WasmStateKVWritesPerSec: 5,
		WasmStateKVBurst:        10,
	}, testLogger(), svc, st)
	if resolver == nil || resolver.CatalogueLookup == nil {
		t.Fatal("expected wired catalogue lookup callback")
	}
	path, digest, ok := resolver.CatalogueLookup(ctx, "catalogue-1")
	if !ok || path != modPath || digest != "sha256:abc" {
		t.Fatalf("lookup = (%q, %q, %v), want ready module", path, digest, ok)
	}
	if _, _, ok := resolver.CatalogueLookup(ctx, "missing"); ok {
		t.Fatal("expected missing catalogue id to miss")
	}
}

func TestWireWasmRuntime_CatalogueLookupNotReady(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	now := time.Now().UTC()
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "pending-1", Status: "pending", ModulePath: "", Digest: "",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	var resolver *wasmmod.ModuleResolver
	wasmWiringTestHook = func(r *wasmmod.ModuleResolver) { resolver = r }
	t.Cleanup(func() { wasmWiringTestHook = nil })

	_ = wireWasmRuntime(ctx, config.Config{
		WasmRunDir: t.TempDir(), WasmModulesDir: t.TempDir(),
	}, testLogger(), svc, st)
	if _, _, ok := resolver.CatalogueLookup(ctx, "pending-1"); ok {
		t.Fatal("pending catalogue row must not resolve")
	}
}

func TestWireWasmRuntime_WithPoolAndCatalogue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	modulesDir := t.TempDir()
	runDir := t.TempDir()
	cacheDir := t.TempDir()

	// Stage a minimal module file the resolver can hash.
	modPath := filepath.Join(modulesDir, "python.wasm")
	if err := os.WriteFile(modPath, []byte("fake-wasm-module"), 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}

	cfg := config.Config{
		WasmRunDir:             runDir,
		WasmModulesDir:         modulesDir,
		WasmCacheDir:           cacheDir,
		WasmEngine:             "wasmtime",
		WasmPoolEnabled:        true,
		WasmPoolDepthDefault:   1,
		WasmPoolRefillInterval: 50 * time.Millisecond,
		WasmStandardModules: map[string]string{
			"python": modPath,
		},
		WasmRegistryAllowlist:   []string{"ghcr.io"},
		WasmStateKVWritesPerSec: 10,
		WasmStateKVBurst:        20,
	}

	pool := wireWasmRuntime(ctx, cfg, testLogger(), svc, st)
	if pool == nil {
		t.Fatal("wireWasmRuntime with pool enabled = nil, want pool")
	}
	t.Cleanup(func() { _ = pool.Close() })

	// Let seedStandardModules and the refill loop run briefly.
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestWireWasmRuntime_NilStoreSkipsCatalogue(t *testing.T) {
	ctx := context.Background()
	svc := service.New(config.Config{}, testLogger(), nil, nil, nil, nil, nil, nil, nil)

	pool := wireWasmRuntime(ctx, config.Config{
		WasmRunDir:             t.TempDir(),
		WasmModulesDir:         t.TempDir(),
		WasmPoolEnabled:        true,
		WasmPoolDepthDefault:   1,
		WasmPoolRefillInterval: time.Hour,
	}, testLogger(), svc, nil)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	_ = pool.Close()
}

func TestSeedStandardModules_NilGuards(t *testing.T) {
	seedStandardModules(context.Background(), nil, nil, map[string]string{"x": "y"}, testLogger())
	seedStandardModules(context.Background(), &wasmmod.ModuleResolver{}, nil, nil, testLogger())
}

func TestSeedStandardModules_ResolveErrorAndSuccess(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	modulesDir := t.TempDir()
	resolver := wasmmod.NewModuleResolver(modulesDir, t.TempDir())
	resolver.Reserved = map[string]string{
		"missing": "does-not-exist",
	}
	pool := wasmpool.New(t.TempDir(), logger)

	// Missing module → warn + continue.
	seedStandardModules(ctx, resolver, pool, resolver.Reserved, logger)

	// Valid staged file → NoteModule path.
	goodPath := filepath.Join(modulesDir, "hello.wasm")
	if err := os.WriteFile(goodPath, []byte("wasm-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolver.Reserved = map[string]string{"hello": goodPath}
	seedStandardModules(ctx, resolver, pool, resolver.Reserved, logger)

	// Cancelled ctx → early return.
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	seedStandardModules(cancelCtx, resolver, pool, resolver.Reserved, logger)
}
