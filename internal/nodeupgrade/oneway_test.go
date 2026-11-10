package nodeupgrade

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The one-way migration a fake newer build knows. A fake binary whose file
// says knowsOneWay runs it when it opens its store with cluster mode off,
// as sandboxd does (pkg/daemon); one that does not know it refuses a
// database that has it, as store.Open does (ErrSchemaFromNewerRelease).
const (
	fakeOneWay  = 13
	knowsOneWay = "KNOWS-ONE-WAY-13"
)

// singleNodeDB makes the rig's database a real SQLite file with the
// schema history table, a notes table for writes, and cluster mode as
// given in the env file ("" writes no env file).
func singleNodeDB(t *testing.T, r *rig, clusterEnv string) {
	t.Helper()
	_ = os.Remove(r.paths.DBPath)
	db := openTestDB(t, r.paths.DBPath)
	for _, stmt := range []string{
		`CREATE TABLE schema_migrations (number INTEGER PRIMARY KEY, name TEXT NOT NULL, n1_safe INTEGER NOT NULL, applied_at DATETIME NOT NULL)`,
		`INSERT INTO schema_migrations VALUES (1, 'base_schema', 1, CURRENT_TIMESTAMP)`,
		`CREATE TABLE notes (body TEXT)`,
		`INSERT INTO notes VALUES ('written by v0.6.11')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	if clusterEnv != "" {
		writeFile(t, r.paths.EnvFile, []byte(clusterEnv))
	}
	r.host.openStore = func(content string) bool {
		db, err := sql.Open("sqlite3", r.paths.DBPath)
		if err != nil {
			return false
		}
		defer db.Close()
		has := slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay)
		if !strings.Contains(content, knowsOneWay) {
			return !has
		}
		if !has {
			_, err = db.Exec(`INSERT INTO schema_migrations VALUES (?, 'rebuild', 0, CURRENT_TIMESTAMP)`, fakeOneWay)
		}
		return err == nil
	}
}

func openTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func oneWayOf(t *testing.T, path string) []int {
	t.Helper()
	got, err := appliedOneWay(context.Background(), path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return got
}

func addNote(t *testing.T, path, body string) {
	t.Helper()
	db := openTestDB(t, path)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO notes VALUES (?)`, body); err != nil {
		t.Fatal(err)
	}
}

func hasNote(t *testing.T, path, body string) bool {
	t.Helper()
	db := openTestDB(t, path)
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notes WHERE body = ?`, body).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func newWithOneWay(extra ...string) releaseFiles {
	next := newRelease("v0.6.12")
	next.sandboxd = fakeBinary("v0.6.12", true, append([]string{knowsOneWay}, extra...)...)
	return next
}

// J6: on a single node the new binary runs its one-way migrations at
// boot, before the store-opened marker. When it then fails, the old
// binary would refuse the database and crash-loop, so the revert puts the
// backup back even though the marker is there. In a cluster, or when the
// mode is unknown, the old rule stands: never restore after the marker.
func TestRevertAfterOneWayMigrations(t *testing.T) {
	cases := []struct {
		name        string
		env         string
		wantRestore bool
	}{
		{name: "single node restores the backup", env: "SB_ENABLE_CLUSTER=false\n", wantRestore: true},
		{name: "single node, no cluster key, restores", env: "SB_API_PORT=21212\n", wantRestore: true},
		{name: "cluster keeps the database", env: "SB_ENABLE_CLUSTER=true\n"},
		{name: "unknown mode keeps the database"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newRelease("v0.6.11")
			r := newRig(t, old)
			singleNodeDB(t, r, tc.env)
			if !tc.wantRestore {
				// Let the old binary open whatever it finds, to see that
				// the database was left alone.
				r.host.openStore = func(content string) bool {
					if strings.Contains(content, knowsOneWay) {
						db := openTestDB(t, r.paths.DBPath)
						defer db.Close()
						_, _ = db.Exec(`INSERT INTO schema_migrations VALUES (?, 'rebuild', 0, CURRENT_TIMESTAMP)`, fakeOneWay)
					}
					return true
				}
			}
			st, err := r.u.Run(context.Background(), r.from(newWithOneWay("UNHEALTHY")))
			if err == nil {
				t.Fatal("an unhealthy upgrade succeeded")
			}
			r.assertInstalled(old, old.caddy)
			if st.BackupRestored != tc.wantRestore || st.SingleNode != tc.wantRestore {
				t.Fatalf("restored %v single-node %v, want %v\n%s", st.BackupRestored, st.SingleNode, tc.wantRestore, r.out)
			}
			if got := slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay); got == tc.wantRestore {
				t.Fatalf("migration %d present = %v after the revert", fakeOneWay, got)
			}
			if v, _ := r.host.HealthVersion(context.Background(), ""); v != "v0.6.11" {
				t.Fatalf("running %q after the revert: %v\n%s", v, err, r.out)
			}
			if tc.wantRestore && !strings.Contains(r.out.String(), "one-way schema migrations [13] ran since it was taken") {
				t.Fatalf("no reason logged:\n%s", r.out)
			}
		})
	}
}

// A single-node failure where no one-way migration ran keeps the old
// rule: the marker is there, so the database stays.
func TestSingleNodeRevertWithoutOneWayKeepsTheDatabase(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	next := newRelease("v0.6.12")
	next.sandboxd = fakeBinary("v0.6.12", true, "UNHEALTHY")
	st, err := r.u.Run(context.Background(), r.from(next))
	if err == nil || st.BackupRestored || !st.SingleNode {
		t.Fatalf("revert = %+v, %v", st, err)
	}
}

// J6, rollback: `--rollback` on a single node puts back the backup the
// rolled-back upgrade took when one-way migrations ran since, so the older
// binary can open the database. Writes made since are lost, and the log
// says so.
func TestSingleNodeRollbackRestoresTheBackupAfterOneWayMigrations(t *testing.T) {
	old := newRelease("v0.6.11")
	r := newRig(t, old)
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	up, err := r.u.Run(context.Background(), r.from(newWithOneWay()))
	if err != nil {
		t.Fatalf("upgrade: %v\n%s", err, r.out)
	}
	addNote(t, r.paths.DBPath, "written by v0.6.12")
	if !slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) {
		t.Fatal("the new binary ran no one-way migration")
	}

	st, err := r.u.Run(context.Background(), Request{Version: "v0.6.11", Rollback: true, HealthTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("rollback: %v\n%s", err, r.out)
	}
	r.assertInstalled(old, old.caddy)
	if st.RestoreBackup != up.BackupPath || st.RestoreStarted {
		t.Fatalf("record = %+v", st)
	}
	if slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) || hasNote(t, r.paths.DBPath, "written by v0.6.12") || !hasNote(t, r.paths.DBPath, "written by v0.6.11") {
		t.Fatal("the database is not the backup from before the upgrade")
	}
	if v, _ := r.host.HealthVersion(context.Background(), ""); v != "v0.6.11" {
		t.Fatalf("running %q", v)
	}
	if !strings.Contains(r.out.String(), "writes made since are lost") {
		t.Fatalf("log does not say writes are lost:\n%s", r.out)
	}
	// The rollback's own backup still holds what v0.6.12 wrote.
	if !hasNote(t, st.BackupPath, "written by v0.6.12") {
		t.Fatal("the rollback did not back up the database it replaced")
	}
}

// A rollback given the older version's files (no *.prev to use) finds the
// upgrade that moved the node off that version and uses its backup.
func TestSingleNodeRollbackWithFilesFindsTheBackup(t *testing.T) {
	old := newRelease("v0.6.11")
	r := newRig(t, old)
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	up, err := r.u.Run(context.Background(), r.from(newWithOneWay()))
	if err != nil {
		t.Fatalf("upgrade: %v\n%s", err, r.out)
	}
	req := r.from(old)
	req.Rollback = true
	st, err := r.u.Run(context.Background(), req)
	if err != nil || st.RestoreBackup != up.BackupPath {
		t.Fatalf("rollback with files = %+v, %v\n%s", st, err, r.out)
	}
	if slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) {
		t.Fatal("the one-way migration is still there")
	}
}

// Without the backup the older binary can never open the database: the
// rollback is refused before anything stops.
func TestSingleNodeRollbackRefusedWhenTheBackupIsGone(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	up, err := r.u.Run(context.Background(), r.from(newWithOneWay()))
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if err := os.Remove(up.BackupPath); err != nil {
		t.Fatal(err)
	}
	before := r.host.callLog()
	st, err := r.u.Run(context.Background(), Request{Version: "v0.6.11", Rollback: true})
	if err == nil || !strings.Contains(err.Error(), "database backup") || !strings.Contains(err.Error(), "is gone") {
		t.Fatalf("rollback = %v", err)
	}
	if st.Phase != PhaseFailed || strings.Contains(strings.TrimPrefix(r.host.callLog(), before), "stop sandboxd") {
		t.Fatalf("the refused rollback stopped sandboxd: %+v\n%s", st, r.host.callLog())
	}
	r.assertInstalled(newWithOneWay(), newWithOneWay().caddy)
}

// A rollback whose older binary then fails puts the newer files back and
// the database as the rollback found it, so nothing the newer version
// wrote is lost and it opens its own database again.
func TestSingleNodeRollbackRevertPutsTheNewerDatabaseBack(t *testing.T) {
	old := newRelease("v0.6.11")
	old.sandboxd = fakeBinary("v0.6.11", true, "UNHEALTHY")
	r := newRig(t, old)
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	next := newWithOneWay()
	if _, err := r.u.Run(context.Background(), r.from(next)); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, r.out)
	}
	addNote(t, r.paths.DBPath, "written by v0.6.12")
	st, err := r.u.Run(context.Background(), Request{Version: "v0.6.11", Rollback: true, HealthTimeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("the rollback to an unhealthy binary succeeded")
	}
	r.assertInstalled(next, next.caddy)
	if !st.BackupRestored || st.RestoreStarted {
		t.Fatalf("record = %+v\n%s", st, r.out)
	}
	if !slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) || !hasNote(t, r.paths.DBPath, "written by v0.6.12") {
		t.Fatal("the newer database did not come back")
	}
	if v, _ := r.host.HealthVersion(context.Background(), ""); v != "v0.6.12" {
		t.Fatalf("running %q\n%s", v, r.out)
	}
}

// A crash during a single-node rollback that put the older backup in
// place: boot recovery, run by the newer binary still on disk, puts the
// database as the rollback found it back with the files. Once the older
// sandboxd is in place the rollback is complete and the older database
// stays.
func TestBootRecoveryOfASingleNodeRollbackRestore(t *testing.T) {
	cases := []struct {
		name          string
		point         string
		wantCompleted bool
	}{
		{name: "right after the restore", point: "restored"},
		{name: "after toolboxd", point: "swapped:toolboxd"},
		{name: "after sandboxd", point: "swapped:sandboxd", wantCompleted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newRelease("v0.6.11")
			r := newRig(t, old)
			singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
			next := newWithOneWay()
			if _, err := r.u.Run(context.Background(), r.from(next)); err != nil {
				t.Fatalf("upgrade: %v", err)
			}
			addNote(t, r.paths.DBPath, "written by v0.6.12")
			crashAt(t, r, Request{Version: "v0.6.11", Rollback: true}, tc.point, "")
			results, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
			if err != nil || len(results) != 1 || results[0].Err != nil {
				t.Fatalf("recover = %+v, %v\n%s", results, err, r.out)
			}
			newer := hasNote(t, r.paths.DBPath, "written by v0.6.12")
			if tc.wantCompleted {
				if results[0].Result != ResultCompletedAtBoot || newer {
					t.Fatalf("result %s, newer database %v", results[0].Result, newer)
				}
				r.assertInstalled(old, old.caddy)
				return
			}
			if results[0].Result != ResultRevertedAtBoot || !newer || !slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) {
				t.Fatalf("result %s, newer database %v\n%s", results[0].Result, newer, r.out)
			}
			st, _ := LoadState(r.paths.StateDir, results[0].Op)
			if !st.BackupRestored || st.RestoreStarted {
				t.Fatalf("record = %+v", st)
			}
			r.assertInstalled(next, next.caddy)
		})
	}
}

// An upgrader killed while reverting a single-node upgrade whose new
// binary ran one-way migrations: boot recovery puts the old files and the
// backup back, so the old binary can open its database. In a cluster it
// leaves the database alone.
func TestBootRecoveryAfterOneWayMigrationsOnASingleNode(t *testing.T) {
	for _, tc := range []struct {
		env         string
		wantRestore bool
	}{
		{env: "SB_ENABLE_CLUSTER=false\n", wantRestore: true},
		{env: "SB_ENABLE_CLUSTER=true\n"},
	} {
		t.Run(strings.TrimSpace(tc.env), func(t *testing.T) {
			old := newRelease("v0.6.11")
			r := newRig(t, old)
			singleNodeDB(t, r, tc.env)
			crashAt(t, r, r.from(newWithOneWay("UNHEALTHY")), "reverting", "")
			results, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
			if err != nil || len(results) != 1 || results[0].Err != nil || results[0].Result != ResultRevertedAtBoot {
				t.Fatalf("recover = %+v, %v\n%s", results, err, r.out)
			}
			r.assertInstalled(old, old.caddy)
			st, _ := LoadState(r.paths.StateDir, results[0].Op)
			if st.BackupRestored != tc.wantRestore || slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) == tc.wantRestore {
				t.Fatalf("restored %v, one-way present %v\n%s", st.BackupRestored, oneWayOf(t, r.paths.DBPath), r.out)
			}
		})
	}
}

func TestClusterModeOn(t *testing.T) {
	cases := []struct {
		name         string
		main, extra  string
		on, known    bool
		noMainEnvVar bool
	}{
		{name: "no env file", noMainEnvVar: true},
		{name: "no key: off", main: "SB_API_PORT=1\n", known: true},
		{name: "true", main: "SB_ENABLE_CLUSTER=true\n", on: true, known: true},
		{name: "1", main: "SB_ENABLE_CLUSTER=1\n", on: true, known: true},
		{name: "cluster.env wins", main: "SB_ENABLE_CLUSTER=false\n", extra: "SB_ENABLE_CLUSTER=true\n", on: true, known: true},
		{name: "unparsable falls back to off", main: "SB_ENABLE_CLUSTER=maybe\n", known: true},
		{name: "a cluster.env without the switch cannot tell", main: "SB_API_PORT=1\n", extra: "SB_NODE_ID=n1\n"},
		{name: "cluster settings without the switch cannot tell", main: "SB_CLUSTER_GOSSIP_SECRET_KEY=x\n"},
		{name: "an explicit off beside cluster.env is off", main: "SB_API_PORT=1\n", extra: "SB_ENABLE_CLUSTER=false\n", known: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := filepath.Join(dir, "sandboxd.env")
			if !tc.noMainEnvVar {
				writeFile(t, env, []byte(tc.main))
			}
			if tc.extra != "" {
				writeFile(t, filepath.Join(dir, "cluster.env"), []byte(tc.extra))
			}
			if on, known := clusterModeOn(env); on != tc.on || known != tc.known {
				t.Fatalf("= %v %v, want %v %v", on, known, tc.on, tc.known)
			}
		})
	}
	if _, known := clusterModeOn(""); known {
		t.Fatal("no path is known")
	}
}

// A database that is not SQLite cannot be compared: the cluster rule
// stands and a warning says why.
func TestOneWayCompareFailureKeepsTheClusterRule(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	st := &State{SingleNode: true}
	if got := r.u.singleNodeOneWaySince(context.Background(), st, "", r.paths.DBPath); got != nil {
		t.Fatalf("a text file compared: %v", got)
	}
	if !strings.Contains(r.out.String(), "could not compare the database") {
		t.Fatalf("no warning:\n%s", r.out)
	}
	if _, err := oneWaySince(context.Background(), r.paths.DBPath, filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("a text backup compared")
	}
	if got := r.u.singleNodeOneWaySince(context.Background(), &State{}, "", r.paths.DBPath); got != nil {
		t.Fatal("a cluster op compared")
	}
}
