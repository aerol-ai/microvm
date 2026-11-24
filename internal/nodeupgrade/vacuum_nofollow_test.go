package nodeupgrade

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// The copy holds what a running sandboxd has in its WAL and not yet in the
// database file: the pages are read in one read transaction, as VACUUM
// INTO reads them.
func TestVacuumIntoNoFollowCopiesTheWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	makeWALDB(t, path, "checkpointed")
	live, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	live.SetMaxOpenConns(1)
	if _, err := live.Exec("PRAGMA wal_autocheckpoint=0; INSERT INTO t VALUES ('in the wal')"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("no WAL to copy: %v %v", fi, err)
	}
	dest := filepath.Join(dir, "copy.db")
	if err := VacuumIntoNoFollow(context.Background(), path, dest); err != nil {
		t.Fatal(err)
	}
	if got := readRows(t, dest); strings.Join(got, ",") != "checkpointed,in the wal" {
		t.Fatalf("copy rows %v", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "copy.db.pages*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if st, err := os.Stat(dest); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("copy: %v %v", st, err)
	}
}

func readRows(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT v FROM t ORDER BY rowid")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// A FIFO opened for reading waits for a writer, and no context reaches a
// blocked open(2). One swapped in for the database between the backup's
// look and its own open is refused at once (that open does not wait); one
// swapped in after the checks, where SQLite opens the file by name, ends
// the copy at vacuumOpenLimit. Neither hangs the backup.
func TestVacuumIntoNoFollowDoesNotHangOnAFIFO(t *testing.T) {
	for stage, want := range map[string]string{
		"open":   "changed between the look at it and its open",
		"sqlite": "did not open the database within",
	} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.db")
			makeWALDB(t, path, "x")
			setOpenLimit(t, 200*time.Millisecond)
			testHookVacuumOpen = func(at string) {
				if at != stage {
					return
				}
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { testHookVacuumOpen = nil })
			dest := filepath.Join(dir, "copy.db")
			err := withinSeconds(t, 10, func() error { return VacuumIntoNoFollow(context.Background(), path, dest) })
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatalf("a refused copy left %s: %v", dest, err)
			}
			if stage == "sqlite" {
				releaseFIFO(t, path)
			}
		})
	}
}

// The files SQLite opens by the database's name are checked as the
// database is: a FIFO at the WAL would hold SQLite's first read.
func TestVacuumIntoNoFollowRefusesAFIFOBesideTheDatabase(t *testing.T) {
	for _, side := range []string{"-wal", "-shm", "-journal"} {
		t.Run(side, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.db")
			makeWALDB(t, path, "x")
			if err := syscall.Mkfifo(path+side, 0o600); err != nil {
				t.Fatal(err)
			}
			setOpenLimit(t, 200*time.Millisecond)
			err := withinSeconds(t, 10, func() error {
				return VacuumIntoNoFollow(context.Background(), path, filepath.Join(dir, "copy.db"))
			})
			if err == nil || !strings.Contains(err.Error(), path+side+" is not a regular file") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// Once SQLite has opened the database and holds a read transaction, the
// copy reads through the files it holds. A database in rollback-journal
// mode (whoever owns the file can set its header so) has SQLite look for a
// WAL and a hot journal by name as each transaction begins: a FIFO put
// there after the open is never opened, as no transaction begins.
func TestVacuumIntoNoFollowCopiesInTheOpenTransaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite3", path+"?_journal_mode=DELETE")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x')"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	testHookVacuumOpen = func(at string) {
		if at != "copy" {
			return
		}
		for _, side := range []string{"-wal", "-journal"} {
			if err := syscall.Mkfifo(path+side, 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { testHookVacuumOpen = nil })
	dest := filepath.Join(dir, "copy.db")
	if err := withinSeconds(t, 10, func() error { return VacuumIntoNoFollow(context.Background(), path, dest) }); err != nil {
		t.Fatal(err)
	}
	if got := readRows(t, dest); strings.Join(got, ",") != "x" {
		t.Fatalf("copy rows %v", got)
	}
}

// The caller's context ends the wait for SQLite's open too.
func TestVacuumIntoNoFollowStopsAtItsContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	makeWALDB(t, path, "x")
	ctx, cancel := context.WithCancel(context.Background())
	testHookVacuumOpen = func(at string) {
		if at == "sqlite" {
			_ = os.Remove(path)
			_ = syscall.Mkfifo(path, 0o600)
			time.AfterFunc(50*time.Millisecond, cancel)
		}
	}
	t.Cleanup(func() { testHookVacuumOpen = nil })
	err := withinSeconds(t, 10, func() error { return VacuumIntoNoFollow(ctx, path, filepath.Join(dir, "copy.db")) })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the context's", err)
	}
	releaseFIFO(t, path)
}

func setOpenLimit(t *testing.T, d time.Duration) {
	t.Helper()
	old := vacuumOpenLimit
	vacuumOpenLimit = d
	t.Cleanup(func() { vacuumOpenLimit = old })
}

// withinSeconds runs f and fails the test if it has not returned in n
// seconds: what a hang looks like in a test.
func withinSeconds(t *testing.T, n int, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Duration(n) * time.Second):
		t.Fatalf("still waiting after %ds: a FIFO held the backup", n)
		return nil
	}
}

// releaseFIFO opens a FIFO for writing, which lets an open left waiting
// on it (SQLite's, given up on) return, so the test leaves no thread
// blocked.
func releaseFIFO(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = f.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
