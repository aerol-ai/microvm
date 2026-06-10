package service

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

type wasmModuleAPIRemoveErrorRuntime struct {
	wasmModuleAPINoopRuntime
	err error
}

func (r wasmModuleAPIRemoveErrorRuntime) RemoveImage(context.Context, string) error {
	return r.err
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

func TestListWasmModules(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-1", ModuleRef: "file://a", Status: "ready", CreatedAt: now, UpdatedAt: now,
	})
	_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-2", ModuleRef: "file://b", Status: "ready", CreatedAt: now, UpdatedAt: now,
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{EnableWasm: true}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)

	mods, err := svc.ListWasmModules(ctx)
	if err != nil {
		t.Fatalf("ListWasmModules: %v", err)
	}
	if len(mods) != 2 {
		t.Fatalf("Expected 2 modules, got %d", len(mods))
	}
}

func TestDeleteWasmModule(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-1", ModuleRef: "file://a", Status: "ready", CreatedAt: now, UpdatedAt: now,
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{EnableWasm: true}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)

	err := svc.DeleteWasmModule(ctx, "mod-1")
	if err != nil {
		t.Fatalf("DeleteWasmModule: %v", err)
	}

	_, err = svc.GetWasmModule(ctx, "mod-1")
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestWasmModuleAPIEdgeBranches(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	disabled := New(config.Config{}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
	if _, err := disabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/x.wasm"}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("disabled CreateWasmModule = %v, want ErrRuntimeNotImplemented", err)
	}
	if _, err := disabled.ListWasmModules(ctx); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("disabled ListWasmModules = %v, want ErrRuntimeNotImplemented", err)
	}
	if _, err := disabled.GetWasmModule(ctx, "x"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("disabled GetWasmModule = %v, want ErrRuntimeNotImplemented", err)
	}
	if err := disabled.DeleteWasmModule(ctx, "x"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("disabled DeleteWasmModule = %v, want ErrRuntimeNotImplemented", err)
	}

	enabled := New(config.Config{EnableWasm: true}, logger, st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
	if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/x.wasm"}); err == nil || !strings.Contains(err.Error(), "resolver is not configured") {
		t.Fatalf("missing resolver = %v", err)
	}
	enabled.SetWasmModuleResolver(stubWasmModuleResolver{path: filepath.Join(dir, "mod.wasm"), digest: "sha256:abc"})
	if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{}); err == nil || !strings.Contains(err.Error(), "module_ref is required") {
		t.Fatalf("empty module_ref = %v", err)
	}
	now := time.Now().UTC()
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{ID: "conflict", ModuleRef: "file:///tmp/different.wasm", Status: string(models.WasmModuleStatusReady), CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ID: "conflict", ModuleRef: "file:///tmp/x.wasm"}); !errors.Is(err, store.ErrWasmModuleIDConflict) {
		t.Fatalf("explicit ID conflict = %v", err)
	}
	enabled.SetWasmModuleResolver(erroringWasmModuleResolver{err: errors.New("resolve failed")})
	if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ID: "failed", ModuleRef: "file:///tmp/fail.wasm"}); err == nil || !strings.Contains(err.Error(), "resolve wasm module") {
		t.Fatalf("resolver failure = %v", err)
	}
	failed, err := st.GetWasmModule(ctx, "failed")
	if err != nil {
		t.Fatalf("GetWasmModule failed row: %v", err)
	}
	if failed.Status != string(models.WasmModuleStatusFailed) || !strings.Contains(failed.LastError, "resolve failed") {
		t.Fatalf("failed row = %+v", failed)
	}
	enabled.SetWasmModuleResolver(stubWasmModuleResolver{path: filepath.Join(dir, "mod.wasm"), digest: ""})
	if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/empty-digest.wasm"}); err == nil || !strings.Contains(err.Error(), "empty digest") {
		t.Fatalf("empty digest = %v", err)
	}

	remover := New(config.Config{EnableWasm: true}, logger, st, nil, nil, nil, nil, nil, nil)
	remover.SetWasmRuntime(wasmModuleAPIRemoveErrorRuntime{err: errors.New("remove failed")})
	_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{ID: "mod-remove", ModuleRef: "file:///tmp/remove.wasm", Status: string(models.WasmModuleStatusReady), CreatedAt: now, UpdatedAt: now})
	if err := remover.DeleteWasmModule(ctx, "mod-remove"); err == nil || !strings.Contains(err.Error(), "remove failed") {
		t.Fatalf("DeleteWasmModule remove failure = %v", err)
	}
}

func dropSQLiteTable(t *testing.T, dbPath, table string) {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatalf("PRAGMA foreign_keys OFF: %v", err)
	}
	if _, err := db.Exec("DROP TABLE IF EXISTS " + table); err != nil {
		t.Fatalf("DROP TABLE %s: %v", table, err)
	}
}

type wasmModuleAPIDropTableRuntime struct {
	wasmModuleAPINoopRuntime
	dbPath string
}

func (r wasmModuleAPIDropTableRuntime) RemoveImage(context.Context, string) error {
	db, err := sql.Open("sqlite3", r.dbPath+"?_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	_, err = db.Exec("DROP TABLE IF EXISTS wasm_modules")
	return err
}

func TestWasmModuleAPIStoreErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("create explicit-id store error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc := New(config.Config{EnableWasm: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
		svc.SetWasmModuleResolver(stubWasmModuleResolver{path: filepath.Join(dir, "mod.wasm"), digest: "abc"})
		if _, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ID: "mod", ModuleRef: "file:///tmp/mod.wasm"}); err == nil {
			t.Fatal("expected store error from closed DB")
		}
	})

	t.Run("list store error", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc := New(config.Config{EnableWasm: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
		if _, err := svc.ListWasmModules(ctx); err == nil {
			t.Fatal("expected list error from closed DB")
		}
	})

	t.Run("delete reference check error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		now := time.Now().UTC()
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID: "mod-ref", ModuleRef: "file:///tmp/ref.wasm", Status: "ready", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		dropSQLiteTable(t, dbPath, "sandboxes")
		svc := New(config.Config{EnableWasm: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, wasmModuleAPINoopRuntime{}, nil, nil, nil, nil, nil)
		if err := svc.DeleteWasmModule(ctx, "mod-ref"); err == nil {
			t.Fatal("expected reference-check error after dropping sandboxes table")
		}
	})

	t.Run("delete error after remove image", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		now := time.Now().UTC()
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID: "mod-del", ModuleRef: "file:///tmp/del.wasm", Status: "ready", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		svc := New(config.Config{EnableWasm: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil)
		svc.SetWasmRuntime(wasmModuleAPIDropTableRuntime{dbPath: dbPath})
		if err := svc.DeleteWasmModule(ctx, "mod-del"); err == nil {
			t.Fatal("expected delete error after table drop")
		}
	})
}
