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

// writeCacheFile drops a fake <digest>.wasm into dir with the given mtime.
func writeCacheFile(t *testing.T, dir, digest string, size int, mod time.Time) string {
	t.Helper()
	p := filepath.Join(dir, digest+".wasm")
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatalf("write cache file: %v", err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	return p
}

func TestRunWasmCacheGCTTLEvictsUnreferenced(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	svc.cfg.WasmCacheGCTTL = time.Hour

	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()
	stale := writeCacheFile(t, cacheDir, "deadbeefstale", 10, old)
	young := writeCacheFile(t, cacheDir, "deadbeefyoung", 10, fresh)

	// A catalogued digest must survive eviction even though it's old.
	pinned := writeCacheFile(t, cacheDir, "deadbeefpinned", 10, old)
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "mod-pinned", ModuleRef: "oci://h/r:t", Digest: "deadbeefpinned", ModulePath: pinned,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	svc.runWasmCacheGC(ctx, time.Now())

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("expected stale unreferenced file evicted, stat err=%v", err)
	}
	if _, err := os.Stat(young); err != nil {
		t.Errorf("expected fresh file kept: %v", err)
	}
	if _, err := os.Stat(pinned); err != nil {
		t.Errorf("expected catalogued digest kept: %v", err)
	}
}

func TestRunWasmCacheGCSizeCapEvictsOldestFirst(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	svc.cfg.WasmCacheMaxBytes = 150 // room for one 100-byte file, not two

	now := time.Now()
	oldest := writeCacheFile(t, cacheDir, "aaa", 100, now.Add(-2*time.Hour))
	newest := writeCacheFile(t, cacheDir, "bbb", 100, now)

	svc.runWasmCacheGC(ctx, now)

	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Errorf("expected oldest file evicted under cap, stat err=%v", err)
	}
	if _, err := os.Stat(newest); err != nil {
		t.Errorf("expected newest file kept under cap: %v", err)
	}
}

func TestEvictReasonBranches(t *testing.T) {
	if evictReason(true, true) != "ttl+cap" {
		t.Fatal("ttl+cap")
	}
	if evictReason(true, false) != "ttl" {
		t.Fatal("ttl")
	}
	if evictReason(false, true) != "cap" {
		t.Fatal("cap")
	}
	if evictReason(false, false) != "cap" {
		t.Fatal("default cap branch")
	}
}

// P1: sandbox module_digest pins must protect cache files even when the
// digest is absent from wasm_modules.
func TestRunWasmCacheGCKeepsSandboxReferencedDigest(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	svc.cfg.WasmCacheGCTTL = time.Hour

	old := time.Now().Add(-2 * time.Hour)
	pinned := writeCacheFile(t, cacheDir, "sandboxonly", 10, old)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-pin",
		Runtime:      models.RuntimeWasm,
		ModuleDigest: "sandboxonly",
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	svc.runWasmCacheGC(ctx, time.Now())
	if _, err := os.Stat(pinned); err != nil {
		t.Fatalf("sandbox-referenced digest should survive gc: %v", err)
	}
}

func TestRunWasmCacheGCInUseQueryError(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	cacheDir := t.TempDir()
	writeCacheFile(t, cacheDir, "gone", 10, time.Now().Add(-2*time.Hour))
	svc := &Service{
		cfg:    config.Config{WasmCacheDir: cacheDir, WasmCacheGCTTL: time.Hour},
		store:  st,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}
	svc.runWasmCacheGC(ctx, time.Now())
	if _, err := os.Stat(filepath.Join(cacheDir, "gone.wasm")); err != nil {
		t.Fatalf("file should remain when in-use query fails: %v", err)
	}
}

func TestRunWasmCacheGCReaddirFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(cacheFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.cfg.WasmCacheDir = cacheFile
	svc.cfg.WasmCacheGCTTL = time.Hour
	svc.runWasmCacheGC(ctx, time.Now())
}

func TestRunWasmCacheGCEvictsTTLAndCapTogether(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	svc.cfg.WasmCacheGCTTL = time.Hour
	svc.cfg.WasmCacheMaxBytes = 50

	old := time.Now().Add(-2 * time.Hour)
	writeCacheFile(t, cacheDir, "evictme", 100, old)

	svc.runWasmCacheGC(ctx, time.Now())
	if _, err := os.Stat(filepath.Join(cacheDir, "evictme.wasm")); !os.IsNotExist(err) {
		t.Fatalf("expected eviction under ttl+cap, stat err=%v", err)
	}
}

func TestRunWasmCacheGCStopsAtYoungUnreferencedFiles(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	svc.cfg.WasmCacheGCTTL = time.Hour

	now := time.Now()
	old := writeCacheFile(t, cacheDir, "oldfile", 10, now.Add(-2*time.Hour))
	young := writeCacheFile(t, cacheDir, "youngfile", 10, now)

	svc.runWasmCacheGC(ctx, now)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old file should be evicted")
	}
	if _, err := os.Stat(young); err != nil {
		t.Fatalf("young file should remain: %v", err)
	}
}

func TestRunWasmCacheGCSkipsDirectories(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	svc.cfg.WasmCacheGCTTL = time.Hour
	if err := os.Mkdir(filepath.Join(cacheDir, ".manifest"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := writeCacheFile(t, cacheDir, "onlywasm", 10, time.Now().Add(-2*time.Hour))
	svc.runWasmCacheGC(ctx, time.Now())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale wasm evicted")
	}
}

func TestRunWasmCacheGCDisabledNoop(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cacheDir := t.TempDir()
	svc.cfg.WasmCacheDir = cacheDir
	// both knobs zero => disabled
	f := writeCacheFile(t, cacheDir, "ccc", 10, time.Now().Add(-100*time.Hour))
	svc.runWasmCacheGC(ctx, time.Now())
	if _, err := os.Stat(f); err != nil {
		t.Errorf("expected file untouched when cache gc disabled: %v", err)
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
	// GC reclaims by the recorded content digest (a local-only RemoveImage
	// path), never by the ref — an oci:// ref would re-pull during cleanup.
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:         "mod-rt",
		ModuleRef:  "oci://h/r:t",
		Digest:     "rtdigest",
		Status:     "ready",
		ModulePath: modPath,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	svc.runWasmModuleGC(ctx, time.Now().UTC())
	if len(rt.removeImages) != 1 || rt.removeImages[0] != "rtdigest" {
		t.Fatalf("removeImages = %v, want [rtdigest]", rt.removeImages)
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

	t.Run("remove image error does not strand row", func(t *testing.T) {
		// A failed best-effort artifact delete must NOT strand the catalogue row:
		// the row is the source of placement inventory, so leaving it behind on a
		// transient remove error accumulates vacuum (codex P1). GC ignores the
		// error and still deletes the row; cache GC reclaims the bytes later.
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID: "mod-rm", ModuleRef: "oci://h/r:t", Digest: "rmdigest", Status: "ready", CreatedAt: now, UpdatedAt: now,
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
		if _, err := st.GetWasmModule(ctx, "mod-rm"); err == nil {
			t.Fatal("row should be deleted despite remove failure")
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

	t.Run("digest row reclaims by content digest", func(t *testing.T) {
		// A row carrying a content digest reclaims via the local-only,
		// digest-keyed RemoveImage path (which also drops the warm-pool entry),
		// never via the ref.
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		now := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:         "mod-digest",
			ModuleRef:  "oci://h/r:t",
			Digest:     "blankdigest",
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
		if _, err := freshDB.ExecContext(ctx, `UPDATE wasm_modules SET updated_at = ? WHERE id = ?`, now.Add(-2*time.Hour), "mod-digest"); err != nil {
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

		if len(rt.removeImages) != 1 || rt.removeImages[0] != "blankdigest" {
			t.Fatalf("removeImages = %v, want [blankdigest]", rt.removeImages)
		}
		if _, err := st.GetWasmModule(ctx, "mod-digest"); err == nil {
			t.Fatal("digest module row should be deleted")
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
