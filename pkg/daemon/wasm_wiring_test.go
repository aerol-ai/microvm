package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
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

// T0b through the wired resolver: a catalogue id resolves in the booting
// owner's namespace first, then to the operator-published row, and never to
// another owner's row; a pinned sandbox owner wins on a caller-less context.
func TestWireWasmRuntime_CatalogueLookupPerOwner(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	modulesDir := t.TempDir()
	now := time.Now().UTC()
	for _, rec := range []store.WasmModuleRecord{
		{OwnerRef: "", ID: "shared", Digest: "d-op"},
		{OwnerRef: "acct-a", ID: "shared", Digest: "d-a"},
		{OwnerRef: "acct-b", ID: "b-only", Digest: "d-b"},
	} {
		rec.Status, rec.CreatedAt, rec.UpdatedAt = "ready", now, now
		rec.ModulePath = wasmmod.WriteMinimalWasm(t, modulesDir, rec.Digest+".wasm")
		if err := st.UpsertWasmModule(ctx, rec); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
	}
	var resolver *wasmmod.ModuleResolver
	wasmWiringTestHook = func(r *wasmmod.ModuleResolver) { resolver = r }
	t.Cleanup(func() { wasmWiringTestHook = nil })
	_ = wireWasmRuntime(ctx, config.Config{WasmRunDir: t.TempDir(), WasmModulesDir: t.TempDir()}, testLogger(), svc, st)

	tenant := func(owner string) context.Context {
		return controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}})
	}
	tests := []struct {
		name       string
		ctx        context.Context
		id         string
		wantDigest string // "" means not found
	}{
		{"own row first", tenant("acct-a"), "shared", "d-a"},
		{"operator row fallback", tenant("acct-b"), "shared", "d-op"},
		{"other owner's row", tenant("acct-a"), "b-only", ""},
		{"pinned sandbox owner", wasmmod.WithCatalogueOwner(ctx, "acct-b"), "b-only", "d-b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.Resolve(tc.ctx, tc.id)
			if tc.wantDigest == "" {
				if !errors.Is(err, wasmmod.ErrModuleNotFound) {
					t.Fatalf("Resolve = %+v, %v; want ErrModuleNotFound", got, err)
				}
				return
			}
			if err != nil || got.Digest != tc.wantDigest {
				t.Fatalf("Resolve = %+v, %v; want digest %s", got, err, tc.wantDigest)
			}
		})
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

type wiringStubResolver struct {
	path   string
	digest string
}

func (r wiringStubResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	return &wasmmod.ResolvedModule{Ref: ref, Path: r.path, Digest: r.digest, SizeBytes: 4}, nil
}

// Registering a module through the service must land it in the wired pool's
// refill targets — the registration-time NoteModule seam, so the first create
// of a registered module hits a warm slot instead of a cold compile.
func TestWireWasmRuntime_RegistrationNotesWarmPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	st := openTestStore(t)
	svc := service.New(config.Config{EnableWasm: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	modulesDir := t.TempDir()
	modPath := filepath.Join(modulesDir, "mod.wasm")
	if err := os.WriteFile(modPath, []byte("fake-wasm"), 0o644); err != nil {
		t.Fatal(err)
	}

	pool := wireWasmRuntime(ctx, config.Config{
		WasmRunDir:             t.TempDir(),
		WasmModulesDir:         modulesDir,
		WasmPoolEnabled:        true,
		WasmPoolDepthDefault:   1,
		WasmPoolRefillInterval: time.Hour, // keep the refill loop quiet
	}, testLogger(), svc, st)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	t.Cleanup(func() { _ = pool.Close() })

	// Swap in a stub resolver: this test asserts the pool wiring, not
	// resolution; the setter is the same one wireWasmRuntime used.
	svc.SetWasmModuleResolver(wiringStubResolver{path: modPath, digest: "d-wired"})
	if _, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file://" + modPath}); err != nil {
		t.Fatalf("CreateWasmModule: %v", err)
	}

	for _, target := range pool.ListTargets() {
		if target.Digest == "d-wired" && target.Path == modPath {
			return
		}
	}
	t.Fatalf("registered module missing from pool targets %v", pool.ListTargets())
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

func TestEffectiveWasmCompileCacheDir_DefaultAndExplicit(t *testing.T) {
	modules := "/var/lib/wasm/modules"
	got := effectiveWasmCompileCacheDir(config.Config{WasmModulesDir: modules})
	want := filepath.Join(modules, "cache", "wazero-compile")
	if got != want {
		t.Fatalf("default dir = %q, want %q", got, want)
	}
	t.Setenv("SB_WASM_COMPILE_CACHE_DIR", "")
	got = effectiveWasmCompileCacheDir(config.Config{WasmCompileCacheDir: ""})
	if got != "" {
		t.Fatalf("explicit empty = %q, want disabled", got)
	}
}

// TestWarmPoolEffectivelyEnabled guards the resident/warm-pool redundancy fix:
// the warm pool is wired only when enabled AND the resident host is off (with
// resident on, every non-listen create goes resident and the pool would just
// double the memory). See plans/wasm-resident-module-host.md Validation.
func TestWarmPoolEffectivelyEnabled(t *testing.T) {
	cases := []struct {
		name     string
		pool     bool
		resident bool
		want     bool
	}{
		{"pool-off", false, false, false},
		{"pool-on-resident-off", true, false, true},
		{"pool-on-resident-on", true, true, false}, // redundant → skip
		{"pool-off-resident-on", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := warmPoolEffectivelyEnabled(config.Config{
				WasmPoolEnabled:         c.pool,
				WasmResidentHostEnabled: c.resident,
			})
			if got != c.want {
				t.Fatalf("warmPoolEffectivelyEnabled(pool=%v,resident=%v)=%v, want %v", c.pool, c.resident, got, c.want)
			}
		})
	}
}
