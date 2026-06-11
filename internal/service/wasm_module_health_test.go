package service

import (
	"context"
	"database/sql"
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
)

func TestWasmPathUnderDir(t *testing.T) {
	tests := []struct {
		root string
		path string
		want bool
	}{
		{"/var/modules", "/var/modules/abc.wasm", true},
		{"/var/modules/", "/var/modules/abc.wasm", true},
		{"/var/modules", "/var/modules/nested/abc.wasm", true},
		{"/var/modules", "/var/other/abc.wasm", false},
		{"/var/modules", "/var/modules/../abc.wasm", false},
		{"", "/abc.wasm", false},
		{"/var/modules", "", false},
	}
	for _, tt := range tests {
		if got := wasmPathUnderDir(tt.root, tt.path); got != tt.want {
			t.Errorf("wasmPathUnderDir(%q, %q) = %v; want %v", tt.root, tt.path, got, tt.want)
		}
	}
}

func TestStartWasmModuleGC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmModuleGCEnabled = true
	svc.cfg.WasmModuleGCInterval = time.Millisecond * 10
	svc.cfg.WasmModuleGCTTL = time.Hour

	svc.StartWasmModuleGC(ctx)
	time.Sleep(time.Millisecond * 30)
}

func TestRunWasmModuleGC(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.WasmModuleGCTTL = 5 * time.Millisecond

	st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-1",
		ModuleRef:  "sha256:abc",
		ModulePath: "/tmp/abc.wasm",
	})

	time.Sleep(10 * time.Millisecond)

	svc.runWasmModuleGC(ctx, time.Now())

	_, err := st.GetWasmModule(ctx, "mod-1")
	if err == nil {
		t.Fatal("expected module to be deleted")
	}
}

func TestRunWasmModuleGCWithRuntimeRemovesImages(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.WasmModuleGCTTL = 5 * time.Millisecond

	rt := &recordingRuntime{}
	svc.SetWasmRuntime(rt)

	dir := t.TempDir()
	modPath := filepath.Join(dir, "module.wasm")
	if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
	now := time.Now().UTC().Add(-2 * time.Hour)
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-rt",
		ModuleRef:  "sha256:rt",
		Status:     "ready",
		ModulePath: modPath,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	svc.runWasmModuleGC(ctx, time.Now().UTC())
	if len(rt.removeImages) != 1 || rt.removeImages[0] != "sha256:rt" {
		t.Fatalf("removeImages = %v, want [sha256:rt]", rt.removeImages)
	}
	if _, err := st.GetWasmModule(ctx, "mod-rt"); err == nil {
		t.Fatal("module should have been deleted")
	}

	svc.cfg.WasmModuleGCTTL = 0
	svc.runWasmModuleGC(ctx, time.Now().UTC())
}

func TestRunWasmModuleGCEdgeBranches(t *testing.T) {
	ctx := context.Background()
	svc := &Service{cfg: config.Config{WasmModuleGCTTL: 0}}

	// TTL <= 0 is a fast no-op.
	svc.runWasmModuleGC(ctx, time.Now().UTC())

	root := t.TempDir()
	nested := filepath.Join(root, "nested", "module.wasm")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(nested, []byte("wasm"), 0o600); err != nil {
		t.Fatalf("write nested module: %v", err)
	}
	if !wasmPathUnderDir(root, nested) {
		t.Fatalf("wasmPathUnderDir(%q, %q) = false, want true", root, nested)
	}
	if wasmPathUnderDir(root, filepath.Join(root, "..", "outside.wasm")) {
		t.Fatalf("wasmPathUnderDir should reject path outside root")
	}
	bad := string([]byte{'a', 0, 'b'})
	if wasmPathUnderDir(bad, nested) {
		t.Fatalf("wasmPathUnderDir should reject invalid root %q", bad)
	}
	if wasmPathUnderDir(root, bad) {
		t.Fatalf("wasmPathUnderDir should reject invalid path %q", bad)
	}
}

type wasmModuleGCRuntime struct {
	wasmModuleAPINoopRuntime
	removeErr error
	dbPath    string
}

func (r wasmModuleGCRuntime) RemoveImage(context.Context, string) error {
	if r.removeErr != nil {
		return r.removeErr
	}
	return nil
}

type wasmModuleGCDropRuntime struct {
	wasmModuleAPINoopRuntime
	dbPath string
}

func (r wasmModuleGCDropRuntime) RemoveImage(context.Context, string) error {
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

func TestWasmModuleGCEdgeBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("start no-op branches", func(t *testing.T) {
		var nilSvc *Service
		nilSvc.StartWasmModuleGC(ctx)
		disabled := &Service{cfg: config.Config{EnableWasm: false, WasmModuleGCEnabled: true, WasmModuleGCInterval: time.Millisecond}}
		disabled.StartWasmModuleGC(ctx)
		svc := &Service{cfg: config.Config{EnableWasm: true, WasmModuleGCEnabled: true, WasmModuleGCInterval: 0}}
		svc.StartWasmModuleGC(ctx)
	})

	t.Run("list error", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Hour},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.runWasmModuleGC(ctx, time.Now())
	})

	t.Run("reference check error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID: "mod-ref", ModuleRef: "file:///tmp/ref.wasm", Status: "ready", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		freshDB, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-ref"); err != nil {
			_ = freshDB.Close()
			t.Fatalf("update wasm_modules updated_at: %v", err)
		}
		if err := freshDB.Close(); err != nil {
			t.Fatalf("freshDB.Close: %v", err)
		}
		dropSQLiteTable(t, dbPath, "sandboxes")
		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Hour},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		svc.runWasmModuleGC(ctx, time.Now())
		if _, err := st.GetWasmModule(ctx, "mod-ref"); err != nil {
			t.Fatalf("module should remain after reference-check error: %v", err)
		}
	})

	t.Run("remove image error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID: "mod-rm", ModuleRef: "file:///tmp/rm.wasm", Status: "ready", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		freshDB, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-rm"); err != nil {
			_ = freshDB.Close()
			t.Fatalf("update wasm_modules updated_at: %v", err)
		}
		if err := freshDB.Close(); err != nil {
			t.Fatalf("freshDB.Close: %v", err)
		}
		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Hour},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			wasm:   wasmModuleGCRuntime{removeErr: errors.New("remove failed")},
		}
		svc.runWasmModuleGC(ctx, time.Now())
		if _, err := st.GetWasmModule(ctx, "mod-rm"); err != nil {
			t.Fatalf("module should remain after remove failure: %v", err)
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
		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID: "mod-del", ModuleRef: "file:///tmp/del.wasm", Status: "ready", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		freshDB, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-del"); err != nil {
			_ = freshDB.Close()
			t.Fatalf("update wasm_modules updated_at: %v", err)
		}
		if err := freshDB.Close(); err != nil {
			t.Fatalf("freshDB.Close: %v", err)
		}
		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Hour},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			wasm:   wasmModuleGCDropRuntime{dbPath: dbPath},
		}
		svc.runWasmModuleGC(ctx, time.Now())
	})
}

func TestWasmModuleGCBranchCoverage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC().Add(-2 * time.Hour)
	referencedRef := "file:///tmp/referenced.wasm"
	unreferencedPath := filepath.Join(dir, "orphan.wasm")
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-ref",
		ModuleRef:  referencedRef,
		ModulePath: filepath.Join(dir, "referenced.wasm"),
		Status:     "ready",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule(ref): %v", err)
	}
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-orphan",
		ModuleRef:  "",
		ModulePath: unreferencedPath,
		Status:     "ready",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule(orphan): %v", err)
	}
	if err := st.Create(ctx, &models.Sandbox{
		ID:        "sb-ref",
		Runtime:   models.RuntimeWasm,
		ModuleRef: referencedRef,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	freshDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id IN (?, ?)`, now.Add(-2*time.Hour), "mod-ref", "mod-orphan"); err != nil {
		_ = freshDB.Close()
		t.Fatalf("update wasm_modules updated_at: %v", err)
	}
	if err := freshDB.Close(); err != nil {
		t.Fatalf("freshDB.Close: %v", err)
	}

	svc := &Service{
		cfg:    config.Config{WasmModuleGCTTL: time.Minute, WasmModulesDir: dir},
		store:  st,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		wasm:   wasmModuleGCRuntime{},
	}
	svc.runWasmModuleGC(ctx, time.Now())

	if _, err := st.GetWasmModule(ctx, "mod-ref"); err != nil {
		t.Fatalf("referenced module should remain: %v", err)
	}
	if _, err := st.GetWasmModule(ctx, "mod-orphan"); err == nil {
		t.Fatal("unreferenced module should be deleted")
	}
	if !wasmPathUnderDir(dir, dir) {
		t.Fatalf("wasmPathUnderDir should accept identical paths")
	}
}

func TestRunWasmModuleGCAdditionalBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("nil runtime removes stale on-disk module", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		modPath := filepath.Join(dir, "orphan.wasm")
		if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
			t.Fatalf("write module: %v", err)
		}
		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:         "mod-file",
			ModuleRef:  "",
			ModulePath: modPath,
			Status:     "ready",
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		freshDB, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-file"); err != nil {
			_ = freshDB.Close()
			t.Fatalf("update wasm_modules updated_at: %v", err)
		}
		if err := freshDB.Close(); err != nil {
			t.Fatalf("freshDB.Close: %v", err)
		}

		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Minute, WasmModulesDir: dir},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		svc.runWasmModuleGC(ctx, time.Now())

		if _, err := os.Stat(modPath); !os.IsNotExist(err) {
			t.Fatalf("module file should be deleted, stat err=%v", err)
		}
		if _, err := st.GetWasmModule(ctx, "mod-file"); err == nil {
			t.Fatal("module row should be deleted")
		}
	})

	t.Run("blank module ref falls back to module id for image removal", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:         "mod-blank-ref",
			ModuleRef:  "",
			ModulePath: filepath.Join(dir, "blank-ref.wasm"),
			Status:     "ready",
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		freshDB, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-blank-ref"); err != nil {
			_ = freshDB.Close()
			t.Fatalf("update wasm_modules updated_at: %v", err)
		}
		if err := freshDB.Close(); err != nil {
			t.Fatalf("freshDB.Close: %v", err)
		}

		rt := &recordingRuntime{}
		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Minute, WasmModulesDir: dir},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			wasm:   rt,
		}
		svc.runWasmModuleGC(ctx, time.Now())

		if len(rt.removeImages) != 1 || rt.removeImages[0] != "mod-blank-ref" {
			t.Fatalf("removeImages = %v, want [mod-blank-ref]", rt.removeImages)
		}
		if _, err := st.GetWasmModule(ctx, "mod-blank-ref"); err == nil {
			t.Fatal("blank-ref module row should be deleted")
		}
	})

	t.Run("nil runtime leaves out-of-tree file alone but deletes row", func(t *testing.T) {
		root := t.TempDir()
		other := t.TempDir()
		dbPath := filepath.Join(root, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		modPath := filepath.Join(other, "orphan-outside.wasm")
		if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
			t.Fatalf("write module: %v", err)
		}
		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:         "mod-outside",
			ModuleRef:  "",
			ModulePath: modPath,
			Status:     "ready",
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}
		freshDB, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-outside"); err != nil {
			_ = freshDB.Close()
			t.Fatalf("update wasm_modules updated_at: %v", err)
		}
		if err := freshDB.Close(); err != nil {
			t.Fatalf("freshDB.Close: %v", err)
		}

		svc := &Service{
			cfg:    config.Config{WasmModuleGCTTL: time.Minute, WasmModulesDir: root},
			store:  st,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		svc.runWasmModuleGC(ctx, time.Now())

		if _, err := os.Stat(modPath); err != nil {
			t.Fatalf("out-of-tree module file should remain, stat err=%v", err)
		}
		if _, err := st.GetWasmModule(ctx, "mod-outside"); err == nil {
			t.Fatal("out-of-tree module row should be deleted")
		}
	})
}
