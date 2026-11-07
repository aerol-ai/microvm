package nodeupgrade

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func removeFile(path string) error { return os.Remove(path) }

// The node's other tools (internal/nodeops) take state.db copies and read
// env files through these, so they must be the upgrader's own.
func TestExportedHelpersAreTheUpgradersOwn(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('a')"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	dest := filepath.Join(dir, "copy.db")
	if err := VacuumInto(context.Background(), dbPath, dest); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dest); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("copy: %v %v", st, err)
	}
	env := filepath.Join(dir, "sandboxd.env")
	writeFile(t, env, []byte("# c\nSB_A = 'x'\nSB_A=y\n"))
	got, err := ReadEnvFile(env)
	if err != nil || got["SB_A"] != "y" {
		t.Fatalf("ReadEnvFile = %v %v", got, err)
	}
	if _, err := ReadEnvFile(filepath.Join(dir, "none")); !os.IsNotExist(err) {
		t.Fatalf("missing env file: %v", err)
	}
}

func TestSwapInKeepsThePreviousFileAndPutBackChecksIt(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "sandboxd")
	staged := filepath.Join(dir, "staged")
	writeFile(t, dst, []byte("old"))
	writeFile(t, dst+".prev", []byte("older"))
	writeFile(t, staged, []byte("new"))
	if err := swapIn(staged, dst); err != nil {
		t.Fatal(err)
	}
	if readFile(t, dst) != "new" || readFile(t, dst+".prev") != "old" {
		t.Fatalf("after swap: %q / %q", readFile(t, dst), readFile(t, dst+".prev"))
	}
	if st, _ := os.Stat(dst); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := putBack(dst, sum([]byte("not old"))); !errors.Is(err, errPrevMismatch) {
		t.Fatalf("put back a .prev with the wrong hash: %v", err)
	}
	if err := putBack(dst, sum([]byte("old"))); err != nil {
		t.Fatal(err)
	}
	if readFile(t, dst) != "old" {
		t.Fatalf("after put back: %q", readFile(t, dst))
	}
	// Nothing installed before: the swap installs, and putting back removes.
	fresh := filepath.Join(dir, "caddy")
	if err := swapIn(staged, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh + ".prev"); !os.IsNotExist(err) {
		t.Fatal("a .prev for a file that did not exist")
	}
	if err := putBack(fresh, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("put back did not remove a file the op added")
	}
	if err := putBack(fresh, ""); err != nil {
		t.Fatalf("put back twice: %v", err)
	}
	// A staged file that is gone fails without touching dst.
	if err := swapIn(filepath.Join(dir, "missing"), dst); err == nil || readFile(t, dst) != "old" {
		t.Fatalf("swap of a missing file: %v, dst %q", err, readFile(t, dst))
	}
}

func TestStreamToFileHashesAndCaps(t *testing.T) {
	dir := t.TempDir()
	n, h, err := streamToFile(strings.NewReader("hello"), filepath.Join(dir, "a"), 0o644)
	if err != nil || n != 5 || h != sum([]byte("hello")) {
		t.Fatalf("%d %s %v", n, h, err)
	}
	old := maxFileBytes
	maxFileBytes = 4
	defer func() { maxFileBytes = old }()
	if _, _, err := streamToFile(strings.NewReader("hello"), filepath.Join(dir, "b"), 0o644); err == nil {
		t.Fatal("a file over the cap was kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); !os.IsNotExist(err) {
		t.Fatal("the oversize file was left on disk")
	}
	if _, _, err := streamToFile(strings.NewReader("x"), filepath.Join(dir, "no", "dir"), 0o644); err == nil {
		t.Fatal("wrote into a missing directory")
	}
}

// containsMarker finds a marker that straddles two reads.
func TestContainsMarkerAcrossChunks(t *testing.T) {
	dir := t.TempDir()
	marker := []byte(UpgradeCommandMarker)
	body := append(bytes.Repeat([]byte{'x'}, (1<<20)-5), marker...)
	writeFile(t, filepath.Join(dir, "bin"), body)
	if !containsMarker(filepath.Join(dir, "bin"), marker) {
		t.Fatal("missed a marker across the chunk boundary")
	}
	writeFile(t, filepath.Join(dir, "other"), bytes.Repeat([]byte{'y'}, 3<<20))
	if containsMarker(filepath.Join(dir, "other"), marker) {
		t.Fatal("found a marker that is not there")
	}
	if containsMarker(filepath.Join(dir, "missing"), marker) {
		t.Fatal("found a marker in a missing file")
	}
}

// The real backup: VACUUM INTO of a WAL database, then restore over a
// changed one with stale WAL files beside it.
func TestSQLiteBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('a'), ('b')"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	backup := filepath.Join(dir, "op.state.db")
	writeFile(t, backup, []byte("stale backup"))
	if err := sqliteBackup(context.Background(), dbPath, backup); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(backup); st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", st.Mode())
	}
	count := func(path string) int {
		t.Helper()
		db, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var n int
		if err := db.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(backup); n != 2 {
		t.Fatalf("backup has %d rows", n)
	}
	db, _ = sql.Open("sqlite3", dbPath)
	if _, err := db.Exec("INSERT INTO t VALUES ('c')"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	writeFile(t, dbPath+"-wal", []byte("frames of the failed boot"))
	if err := restoreBackup(backup, dbPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dbPath + "-wal"); !os.IsNotExist(err) {
		t.Fatal("the stale WAL survived the restore")
	}
	if n := count(dbPath); n != 2 {
		t.Fatalf("restored database has %d rows, want 2", n)
	}
	if err := sqliteBackup(context.Background(), filepath.Join(dir, "missing", "x.db"), filepath.Join(dir, "y")); err == nil {
		t.Fatal("backed up a database that does not exist")
	}
	if err := restoreBackup(filepath.Join(dir, "missing"), dbPath); err == nil {
		t.Fatal("restored a backup that does not exist")
	}
	if got := dbBytes(dbPath); got == 0 {
		t.Fatal("dbBytes of a real database is 0")
	}
}

func TestPruneBackupsKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	base := time.Now()
	for i, name := range []string{"a", "b", "c", "d"} {
		p := filepath.Join(dir, name+backupSuffix)
		writeFile(t, p, []byte(name))
		mt := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(dir, "keep.json"), []byte("{}"))
	pruneBackups(dir)
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	var names []string
	for _, l := range left {
		names = append(names, filepath.Base(l))
	}
	if strings.Join(names, ",") != "c.state.db,d.state.db,keep.json" {
		t.Fatalf("left %v", names)
	}
	pruneBackups(filepath.Join(dir, "missing"))
}

func TestStoreOpenedMarker(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	if err := WriteStoreOpenedMarker(db, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	raw := readFile(t, StoreOpenedMarkerPath(db))
	if !strings.Contains(raw, `"version":"v1.2.3"`) {
		t.Fatalf("marker = %s", raw)
	}
	if StateDirFor(db) != filepath.Join(dir, "upgrade") {
		t.Fatal(StateDirFor(db))
	}
	if err := WriteStoreOpenedMarker(filepath.Join(dir, "missing", "state.db"), "v"); err == nil {
		t.Fatal("wrote a marker into a missing directory")
	}
}

func TestStateRecords(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadState(dir, "../x"); err == nil {
		t.Fatal("loaded a path that is not an op ID")
	}
	writeFile(t, statePath(dir, "bad"), []byte("{"))
	if _, err := LoadState(dir, "bad"); err == nil {
		t.Fatal("loaded a broken record")
	}
	writeFile(t, statePath(dir, "future"), []byte(`{"format": 2}`))
	if _, err := LoadState(dir, "future"); err == nil || !strings.Contains(err.Error(), "format 2") {
		t.Fatalf("a newer format: %v", err)
	}
	if states, err := listStates(filepath.Join(dir, "missing")); err != nil || states != nil {
		t.Fatalf("missing dir: %v %v", states, err)
	}
	if err := RecordHostSetup(dir, "nope"); err == nil {
		t.Fatal("recorded a host setup that is not a hash")
	}
	writeFile(t, filepath.Join(dir, hostSetupName), []byte("garbage\n"))
	if got := InstalledHostSetup(dir, "fallback"); got != "fallback" {
		t.Fatalf("a garbage record was trusted: %q", got)
	}
	if _, err := acquireLock(filepath.Join(dir, "missing"), ""); err == nil {
		t.Fatal("locked in a missing directory")
	}
	var nilLock *lock
	nilLock.release()
}

func TestCheckOrder(t *testing.T) {
	cases := []struct {
		installed, target string
		req               Request
		want              string
	}{
		{"v0.6.11", "v0.6.12", Request{}, ""},
		{"v0.6.12", "v0.6.12", Request{}, ""},
		{"v0.6.12", "v0.6.11", Request{}, "pass --rollback"},
		{"v0.6.12", "v0.6.11", Request{Rollback: true}, ""},
		{"v0.7.0-rc.1", "v0.7.0", Request{}, ""},
		{"v0.7.0", "v0.7.0-rc.1", Request{}, "pass --rollback"},
		{"", "v0.6.12", Request{}, "cannot tell which version"},
		{"dev", "v0.6.12", Request{}, "--allow-unversioned"},
		{"dev", "v0.6.12", Request{AllowUnversioned: true}, ""},
	}
	for _, tc := range cases {
		tc.req.Version = tc.target
		err := checkOrder(tc.installed, tc.req)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("checkOrder(%q, %q, %+v) = %v, want %q", tc.installed, tc.target, tc.req, err, tc.want)
		}
	}
}
