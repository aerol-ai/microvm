package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestWasmModuleOwnerNamespaces pins the (owner_ref, id) identity: the same id
// lives once per namespace, exact reads and deletes never cross namespaces,
// and ResolveWasmModule prefers the owner's row over the operator's.
func TestWasmModuleOwnerNamespaces(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for _, rec := range []WasmModuleRecord{
		{OwnerRef: "", ID: "d1", ModuleRef: "oci://r/op:1", Digest: "d1"},
		{OwnerRef: "acct-a", ID: "d1", ModuleRef: "oci://r/a:1", Digest: "d1"},
		{OwnerRef: " acct-b ", ID: " d1 ", ModuleRef: "oci://r/b:1", Digest: "d1"},
		{OwnerRef: "acct-b", ID: "b-only", ModuleRef: "oci://r/b:1", Digest: "d2"},
	} {
		rec.Status = "ready"
		if err := st.UpsertWasmModule(ctx, rec); err != nil {
			t.Fatalf("Upsert %s/%s: %v", rec.OwnerRef, rec.ID, err)
		}
	}
	// A re-upsert rewrites only its own namespace's row.
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{OwnerRef: "acct-a", ID: "d1", ModuleRef: "oci://r/a:2", Digest: "d1", Status: "ready"}); err != nil {
		t.Fatal(err)
	}

	gets := []struct {
		owner, id, wantRef string
	}{
		{"", "d1", "oci://r/op:1"},
		{"acct-a", "d1", "oci://r/a:2"},
		{"acct-b", "d1", "oci://r/b:1"},
		{"acct-c", "d1", ""},
		{"acct-a", "b-only", ""},
	}
	for _, tc := range gets {
		got, err := st.GetWasmModule(ctx, tc.owner, tc.id)
		if tc.wantRef == "" {
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(%q,%q) = %+v, %v; want ErrNotFound", tc.owner, tc.id, got, err)
			}
			continue
		}
		if err != nil || got.ModuleRef != tc.wantRef || got.OwnerRef != tc.owner {
			t.Errorf("Get(%q,%q) = %+v, %v; want ref %s", tc.owner, tc.id, got, err, tc.wantRef)
		}
	}

	resolves := []struct {
		name, owner, id, wantOwner string
	}{
		{"own row wins", "acct-a", "d1", "acct-a"},
		{"falls back to operator row", "acct-c", "d1", ""},
		{"operator namespace", "", "d1", ""},
		{"never another owner's row", "acct-a", "b-only", "-"},
		{"unknown id", "acct-a", "nope", "-"},
	}
	for _, tc := range resolves {
		got, err := st.ResolveWasmModule(ctx, tc.owner, tc.id)
		if tc.wantOwner == "-" {
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: Resolve = %+v, %v; want ErrNotFound", tc.name, got, err)
			}
			continue
		}
		if err != nil || got.OwnerRef != tc.wantOwner {
			t.Errorf("%s: Resolve = %+v, %v; want owner %q", tc.name, got, err, tc.wantOwner)
		}
	}
	if _, err := st.ResolveWasmModule(ctx, "acct-a", " "); err == nil {
		t.Fatal("Resolve with blank id should error")
	}

	all, err := st.ListWasmModules(ctx)
	if err != nil || len(all) != 4 {
		t.Fatalf("ListWasmModules = %d rows, %v; want 4", len(all), err)
	}
	refs, err := st.ListReadyWasmModuleRefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"oci://r/a:2", "oci://r/b:1", "oci://r/op:1"}; strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Fatalf("ListReadyWasmModuleRefs = %v, want %v (distinct across owners)", refs, want)
	}

	elsewhere := []struct {
		owner, id, digest string
		want              bool
	}{
		{"acct-a", "d1", "d1", true}, // operator and acct-b rows pin d1 too
		{"acct-b", "b-only", "d2", false},
		{"acct-b", "b-only", "", false},
	}
	for _, tc := range elsewhere {
		got, err := st.IsWasmDigestCataloguedElsewhere(ctx, tc.owner, tc.id, tc.digest)
		if err != nil || got != tc.want {
			t.Errorf("CataloguedElsewhere(%q,%q,%q) = %v, %v; want %v", tc.owner, tc.id, tc.digest, got, err, tc.want)
		}
	}

	// Delete reaches only the named namespace.
	if err := st.DeleteWasmModule(ctx, "acct-a", "d1"); err != nil {
		t.Fatalf("Delete acct-a/d1: %v", err)
	}
	if err := st.DeleteWasmModule(ctx, "acct-a", "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete acct-a/d1 = %v, want ErrNotFound", err)
	}
	for _, owner := range []string{"", "acct-b"} {
		if _, err := st.GetWasmModule(ctx, owner, "d1"); err != nil {
			t.Fatalf("%q/d1 gone after acct-a delete: %v", owner, err)
		}
	}
}

// The create-time resolve and the delete-time shared-bytes probe must seek
// their index: the resolve runs on the boot path for every catalogue-id
// create, and neither may walk every owner's rows.
func TestWasmModuleOwnerQueriesSeekTheirIndex(t *testing.T) {
	st := newTestStore(t)
	for _, tc := range []struct {
		name, query, wantIndex string
		args                   []any
	}{
		{"resolve own then operator", wasmModuleResolveSQL, "sqlite_autoindex_wasm_modules", []any{"acct-a", "d1"}},
		{"digest catalogued elsewhere", wasmDigestCataloguedElsewhereSQL, "idx_wasm_modules_digest", []any{"d1", "acct-a", "d1"}},
	} {
		plan := queryPlan(t, st, tc.query, tc.args)
		if !strings.Contains(plan, tc.wantIndex) || strings.Contains(plan, "SCAN wasm_modules") {
			t.Errorf("%s plan = %q, want a seek on %s", tc.name, plan, tc.wantIndex)
		}
	}
}

// Closed-store reads surface the driver error rather than a false "absent".
func TestWasmModuleOwnerQueriesClosedStore(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	_ = st.Close()
	if _, err := st.ResolveWasmModule(ctx, "acct-a", "d1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("ResolveWasmModule on closed store = %v", err)
	}
	if _, err := st.IsWasmDigestCataloguedElsewhere(ctx, "acct-a", "d1", "d1"); err == nil {
		t.Error("IsWasmDigestCataloguedElsewhere on closed store should error")
	}
	if _, err := st.IsWasmModuleReferencedByOwner(ctx, "acct-a", "d1", "r", "d1"); err == nil {
		t.Error("IsWasmModuleReferencedByOwner on closed store should error")
	}
}

// TestIsWasmModuleReferencedByOwner narrows the sandbox reference check to one
// owner's sandboxes; the fleet-wide check still sees every owner.
func TestIsWasmModuleReferencedByOwner(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := ownedSandbox("sb-b", "acct-b")
	sb.Runtime = models.RuntimeWasm
	sb.ModuleRef = "oci://r/b:1"
	sb.ModuleDigest = "d-shared"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		owner string
		any   bool
		want  bool
	}{
		{"fleet-wide sees acct-b", "", true, true},
		{"acct-b sees its own", "acct-b", false, true},
		{"acct-a does not see acct-b", "acct-a", false, false},
		{"operator namespace does not see acct-b", "", false, false},
	}
	for _, tc := range tests {
		var (
			got bool
			err error
		)
		if tc.any {
			got, err = st.IsWasmModuleReferenced(ctx, "mod", "oci://r/a:1", "d-shared")
		} else {
			got, err = st.IsWasmModuleReferencedByOwner(ctx, tc.owner, "mod", "oci://r/a:1", "d-shared")
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: referenced = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
}

// legacyWasmModulesDDL is wasm_modules as it stood before T0b: id alone is the
// primary key. withOwner selects the post-#724 shape (owner_ref as an ordinary
// column) over the pre-#724 one (no owner_ref at all).
func legacyWasmModulesDDL(withOwner bool) string {
	owner := ""
	if withOwner {
		owner = "owner_ref TEXT NOT NULL DEFAULT '',"
	}
	return `CREATE TABLE wasm_modules (
		id TEXT PRIMARY KEY,
		module_ref TEXT NOT NULL,
		status TEXT NOT NULL,
		module_path TEXT NOT NULL DEFAULT '',
		module_size_bytes INTEGER NOT NULL DEFAULT 0,
		digest TEXT NOT NULL DEFAULT '',
		entrypoint TEXT NOT NULL DEFAULT '_start',
		has_warm INTEGER NOT NULL DEFAULT 0,
		last_error TEXT NOT NULL DEFAULT '',
		` + owner + `
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		ready_at DATETIME
	);`
}

func wasmModuleIndexNames(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'wasm_modules' AND name LIKE 'idx_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	return names
}

func countWasmModules(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM wasm_modules`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestWasmModuleOwnerPKWarmUpgrade opens a database whose wasm_modules is keyed
// by id alone, in both shapes a live host can hold (with and without the #724
// owner_ref column). Open must rebuild the key to (owner_ref, id) with every
// row and column intact (backfilled rows stay in the operator namespace,
// tenant rows keep their tenant), recreate the indexes, and be a no-op on
// every later open.
func TestWasmModuleOwnerPKWarmUpgrade(t *testing.T) {
	type seed struct {
		id, owner, ref, status, path, digest, entry, lastErr string
		size                                                 int64
		warm                                                 bool
		ready                                                bool
	}
	seeds := []seed{
		{id: "d-std", owner: "", ref: "python", status: "ready", path: "/m/python.wasm", digest: "d-std", entry: "_start", size: 4096, warm: true, ready: true},
		{id: "d-tenant", owner: "acct-a", ref: "oci://r/a:1", status: "ready", path: "/m/cache/d-tenant.wasm", digest: "d-tenant", entry: "run", size: 128, ready: true},
		{id: "failed-id", owner: "", ref: "oci://r/bad:1", status: "failed", lastErr: "pull failed", entry: "_start"},
	}
	for _, withOwner := range []bool{true, false} {
		name := "pre-724 no owner_ref"
		if withOwner {
			name = "post-724 owner_ref column"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			st, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
			raw, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec(`DROP TABLE wasm_modules;`); err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec(legacyWasmModulesDDL(withOwner)); err != nil {
				t.Fatal(err)
			}
			for _, s := range seeds {
				var readyAt any
				if s.ready {
					readyAt = created.Add(time.Minute)
				}
				cols := `id, module_ref, status, module_path, module_size_bytes, digest, entrypoint, has_warm, last_error, created_at, updated_at, ready_at`
				args := []any{s.id, s.ref, s.status, s.path, s.size, s.digest, s.entry, boolToInt(s.warm), s.lastErr, created, created, readyAt}
				ph := "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
				if withOwner {
					cols += `, owner_ref`
					args = append(args, s.owner)
					ph += ", ?"
				}
				if _, err := raw.Exec(`INSERT INTO wasm_modules (`+cols+`) VALUES (`+ph+`)`, args...); err != nil {
					t.Fatalf("seed %s: %v", s.id, err)
				}
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}

			st, err = Open(path)
			if err != nil {
				t.Fatalf("warm-upgrade Open: %v", err)
			}
			t.Cleanup(func() { _ = st.Close() })
			for _, col := range []string{"owner_ref", "id"} {
				inKey, err := columnInPrimaryKey(st.db, "wasm_modules", col)
				if err != nil || !inKey {
					t.Fatalf("%s in primary key = %v, %v; want true", col, inKey, err)
				}
			}
			if got, want := wasmModuleIndexNames(t, st.db), []string{"idx_wasm_modules_digest", "idx_wasm_modules_status_ref", "idx_wasm_modules_updated_at"}; strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("indexes after rebuild = %v, want %v", got, want)
			}
			for _, s := range seeds {
				// Without the #724 column there is no owner to keep: the ALTER
				// backfills every row to the operator namespace.
				owner := s.owner
				if !withOwner {
					owner = ""
				}
				got, err := st.GetWasmModule(ctx, owner, s.id)
				if err != nil {
					t.Fatalf("row %q/%q lost: %v", owner, s.id, err)
				}
				if got.ModuleRef != s.ref || got.Status != s.status || got.ModulePath != s.path ||
					got.ModuleSizeBytes != s.size || got.Digest != s.digest || got.Entrypoint != s.entry ||
					got.HasWarm != s.warm || got.LastError != s.lastErr || got.OwnerRef != owner ||
					!got.CreatedAt.Equal(created) || (got.ReadyAt != nil) != s.ready {
					t.Fatalf("row %q changed by migration: %+v", s.id, got)
				}
			}
			// The rebuilt key admits a second owner's row for a migrated id.
			if err := st.UpsertWasmModule(ctx, WasmModuleRecord{OwnerRef: "acct-b", ID: "d-std", ModuleRef: "python", Status: "ready", Digest: "d-std"}); err != nil {
				t.Fatalf("second owner row for migrated id: %v", err)
			}
			want := len(seeds) + 1
			if n := countWasmModules(t, st); n != want {
				t.Fatalf("rows = %d, want %d", n, want)
			}

			// Idempotent: a direct rerun and a full reopen change nothing.
			if err := migrateWasmModuleOwnerPK(st.db); err != nil {
				t.Fatalf("rerun migration: %v", err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = Open(path)
			if err != nil {
				t.Fatalf("second reopen: %v", err)
			}
			if n := countWasmModules(t, st); n != want {
				t.Fatalf("rows after reopen = %d, want %d", n, want)
			}
			if got, err := st.GetWasmModule(ctx, "acct-b", "d-std"); err != nil || got.OwnerRef != "acct-b" {
				t.Fatalf("post-migration row lost on reopen: %+v, %v", got, err)
			}
		})
	}
}

// TestMigrateWasmModuleOwnerPKFailureKeepsOldTable: a rebuild that fails part
// way rolls back, leaving the legacy table and its rows in place for the next
// open to retry; an unreadable schema surfaces as an error, not a silent skip.
func TestMigrateWasmModuleOwnerPKFailureKeepsOldTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	for _, stmt := range []string{
		legacyWasmModulesDDL(true),
		// A stray table under the rekeyed name makes the CREATE inside the
		// migration transaction fail.
		`CREATE TABLE wasm_modules_rekeyed (x INTEGER);`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO wasm_modules (id, module_ref, status, created_at, updated_at) VALUES ('keep', 'python', 'ready', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := migrateWasmModuleOwnerPK(db); err == nil || !strings.Contains(err.Error(), "wasm module PK migration") {
		t.Fatalf("migrate with stray table = %v, want a migration error", err)
	}
	inKey, err := columnInPrimaryKey(db, "wasm_modules", "owner_ref")
	if err != nil || inKey {
		t.Fatalf("owner_ref in key after failed migration = %v, %v; want old key", inKey, err)
	}
	var id string
	if err := db.QueryRow(`SELECT id FROM wasm_modules`).Scan(&id); err != nil || id != "keep" {
		t.Fatalf("legacy row after failed migration = %q, %v", id, err)
	}

	closed, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if err := migrateWasmModuleOwnerPK(closed); err == nil {
		t.Fatal("migrate on a closed db should error")
	}
}
