package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// legacyGlobalSandboxNameIndex is the statement every release before
// per-owner names ran on open. CF7's rollback proof runs it verbatim.
const legacyGlobalSandboxNameIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_sandboxes_name ON sandboxes(name) WHERE name <> '';`

func sandboxNameIndexColumns(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`PRAGMA index_info(idx_sandboxes_name)`)
	if err != nil {
		t.Fatalf("PRAGMA index_info: %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var seqno, cid int
		var name sql.NullString
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			t.Fatalf("scan index_info: %v", err)
		}
		cols = append(cols, name.String)
	}
	return cols
}

func TestSandboxNamesAreUniquePerOwner(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	create := func(id, ownerRef string) error {
		sb := sampleSandbox(id)
		sb.Name = "agent"
		sb.OwnerRef = ownerRef
		return st.Create(ctx, sb)
	}
	tests := []struct {
		id, ownerRef string
		wantConflict bool
	}{
		{id: "sb-a1", ownerRef: "acct-a"},
		{id: "sb-b1", ownerRef: "acct-b"},
		{id: "sb-op1", ownerRef: ""},
		{id: "sb-a2", ownerRef: "acct-a", wantConflict: true},
		{id: "sb-op2", ownerRef: "", wantConflict: true},
	}
	for _, tt := range tests {
		err := create(tt.id, tt.ownerRef)
		if tt.wantConflict && !errors.Is(err, ErrSandboxNameConflict) {
			t.Fatalf("create %s (owner %q) = %v, want ErrSandboxNameConflict", tt.id, tt.ownerRef, err)
		}
		if !tt.wantConflict && err != nil {
			t.Fatalf("create %s (owner %q) = %v", tt.id, tt.ownerRef, err)
		}
	}
	for ownerRef, want := range map[string]string{"acct-a": "sb-a1", "acct-b": "sb-b1", "": "sb-op1"} {
		got, err := st.ResolveSandboxIDByName(ctx, ownerRef, " agent ")
		if err != nil || got != want {
			t.Fatalf("ResolveSandboxIDByName(%q) = (%q, %v), want %q", ownerRef, got, err, want)
		}
	}
	if _, err := st.ResolveSandboxIDByName(ctx, "acct-c", "agent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner must not resolve the name, got %v", err)
	}
	if cols := sandboxNameIndexColumns(t, st.db); len(cols) != 2 || cols[0] != "owner_ref" || cols[1] != "name" {
		t.Fatalf("idx_sandboxes_name columns = %v, want [owner_ref name]", cols)
	}
}

// TestSandboxNameIndexMigratesFromGlobal opens a database that still carries
// the pre-upgrade global index and checks the open rebuilds it per owner
// under the same name, keeping every row.
func TestSandboxNameIndexMigratesFromGlobal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	legacy := sampleSandbox("sb-legacy")
	legacy.Name = "agent"
	legacy.OwnerRef = "acct-a"
	if err := st.Create(ctx, legacy); err != nil {
		t.Fatalf("Create legacy: %v", err)
	}
	// Recreate the old shape: the global index under the same name.
	if _, err := st.db.Exec(`DROP INDEX idx_sandboxes_name;`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := st.db.Exec(legacyGlobalSandboxNameIndex); err != nil {
		t.Fatalf("create global index: %v", err)
	}
	if cols := sandboxNameIndexColumns(t, st.db); len(cols) != 1 || cols[0] != "name" {
		t.Fatalf("precondition: index columns = %v, want [name]", cols)
	}
	other := sampleSandbox("sb-other")
	other.Name = "agent"
	other.OwnerRef = "acct-b"
	if err := st.Create(ctx, other); !errors.Is(err, ErrSandboxNameConflict) {
		t.Fatalf("precondition: the global index must reject a cross-owner duplicate, got %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()
	if cols := sandboxNameIndexColumns(t, st.db); len(cols) != 2 || cols[0] != "owner_ref" {
		t.Fatalf("migrated index columns = %v, want [owner_ref name]", cols)
	}
	if got, err := st.ResolveSandboxIDByName(ctx, "acct-a", "agent"); err != nil || got != "sb-legacy" {
		t.Fatalf("legacy row lost in migration: (%q, %v)", got, err)
	}
	if err := st.Create(ctx, other); err != nil {
		t.Fatalf("cross-owner duplicate after migration: %v", err)
	}
	// A second open is a no-op on the per-owner form.
	if err := migrateSandboxNameIndex(st.db); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
}

// TestSandboxNameIndexRollbackBoots is the CEO review CF7 proof: after the
// migration, the database holds names that are duplicated across owners. A
// rolled-back binary runs the OLD global index statement on open; because
// SQLite's IF NOT EXISTS matches only the index name, the statement is a
// no-op and the open succeeds instead of failing on the duplicates.
func TestSandboxNameIndexRollbackBoots(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for _, tc := range []struct{ id, ownerRef string }{{"sb-a", "acct-a"}, {"sb-b", "acct-b"}, {"sb-op", ""}} {
		sb := sampleSandbox(tc.id)
		sb.Name = "agent"
		sb.OwnerRef = tc.ownerRef
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create %s: %v", tc.id, err)
		}
	}
	if _, err := st.db.Exec(legacyGlobalSandboxNameIndex); err != nil {
		t.Fatalf("old binary's schema statement failed against a migrated database: %v", err)
	}
	if cols := sandboxNameIndexColumns(t, st.db); len(cols) != 2 || cols[0] != "owner_ref" {
		t.Fatalf("index after the old statement = %v, want the per-owner form untouched", cols)
	}
}

func TestMigrateSandboxNameIndexCreatesMissingIndex(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.db.Exec(`DROP INDEX idx_sandboxes_name;`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := migrateSandboxNameIndex(st.db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if cols := sandboxNameIndexColumns(t, st.db); len(cols) != 2 {
		t.Fatalf("index columns = %v, want per-owner index", cols)
	}
}

func TestMigrateSandboxNameIndexReportsErrors(t *testing.T) {
	st := newTestStore(t)
	db := st.db
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := migrateSandboxNameIndex(db); err == nil {
		t.Fatal("migrate on a closed database must fail")
	}
}
