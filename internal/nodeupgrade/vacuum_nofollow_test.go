package nodeupgrade

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeWALDB(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES (?)", value); err != nil {
		t.Fatal(err)
	}
}

// VacuumIntoNoFollow copies the database's own file, and refuses one a link
// stands in for: by its look before the open (Lstat), and by the file
// SQLite says it opened, for a link swapped in between the two.
func TestVacuumIntoNoFollow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	own := filepath.Join(dir, "data", "state.db")
	makeWALDB(t, own, "own")
	dest := filepath.Join(dir, "copy.db")
	if err := VacuumIntoNoFollow(ctx, own, dest); err != nil {
		t.Fatalf("its own file: %v", err)
	}
	if st, err := os.Stat(dest); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("copy: %v %v", st, err)
	}

	other := filepath.Join(dir, "root-only", "other.db")
	makeWALDB(t, other, "not the node's")
	link := filepath.Join(dir, "data2", "state.db")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if err := VacuumIntoNoFollow(ctx, link, dest); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a link at the database: %v, want a refusal", err)
	}
	// The swap that lands after the look: SQLite's own answer refuses it,
	// before VACUUM INTO writes a byte.
	_ = os.Remove(dest)
	if err := vacuumIntoChecked(ctx, link, dest); err == nil || !strings.Contains(err.Error(), "a link in its place is refused") {
		t.Fatalf("SQLite opened a link's target: %v, want a refusal", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("a refused copy left %s: %v", dest, err)
	}
	if err := VacuumIntoNoFollow(ctx, filepath.Join(dir, "none.db"), dest); !os.IsNotExist(err) {
		t.Fatalf("a missing database: %v", err)
	}
}

// The split copy opens the database read-only: a link swapped in after the
// look, naming a file that does not exist, must not make SQLite create it
// (its default mode, rwc, would).
func TestVacuumIntoNoFollowCreatesNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	target := filepath.Join(dir, "root-only", "made-by-sqlite.db")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "data", "state.db")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "copy.db")
	if err := vacuumIntoChecked(ctx, link, dest); err == nil {
		t.Fatal("copied through a link to nothing")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("the open created %s: %v", target, err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("a refused copy left %s: %v", dest, err)
	}
}
