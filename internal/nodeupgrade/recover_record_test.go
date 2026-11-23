package nodeupgrade

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A record in the upgrade folder is a file on disk, and boot recovery runs
// as root. The paths in it are never taken at their word (hardening, M1 PR
// 10 review): the database restored is the node's own (Paths.DBPath), a
// backup must be one of the upgrade folder's own, and a record that names
// a file anywhere but where this node installs it is left alone. These are
// the reviewer's two cases: a record asking recovery to copy a file from
// outside the upgrade folder over a path outside every sandboxd folder,
// and one naming a file outside the node's layout.

// plantRecord writes an unfinished op straight into the upgrade folder, as
// anything that could write that folder could.
func plantRecord(t *testing.T, r *rig, st *State) {
	t.Helper()
	if err := os.MkdirAll(r.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.save(r.paths.StateDir, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverTakesNoPathFromARecord(t *testing.T) {
	r := newRig(t, newRelease("v0.7.7"))
	binSum, _ := fileSHA256(r.paths.Sandboxd)
	payload := filepath.Join(r.dir, "payload")
	writeFile(t, payload, []byte("written by whoever wrote the record\n"))
	target := filepath.Join(r.dir, "etc", "elsewhere")
	writeFile(t, target, []byte("root's own file\n"))
	dbBefore := readFile(t, r.paths.DBPath)
	plantRecord(t, r, &State{
		Format: stateFormat, Op: "planted", Version: "v9.9.9", Phase: PhaseSwapping, StartedAt: time.Now(),
		Files: []FileState{{Role: roleSandboxd, Asset: "sandboxd", Path: r.paths.Sandboxd, SHA256: strings.Repeat("0", 64),
			PrevSHA256: binSum, Changed: true}},
		BackupPath: payload, DBPath: target, RestoreStarted: true, SingleNode: true,
	})
	res, err := Recover(context.Background(), r.paths, r.host, r.out)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "root's own file\n" {
		t.Fatalf("recovery wrote %s, a path a record named: %q", target, got)
	}
	if got := readFile(t, r.paths.DBPath); got != dbBefore {
		t.Fatalf("recovery restored the database from a backup outside the upgrade folder: %q", got)
	}
	if len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "is not a database backup in the upgrade folder") {
		t.Fatalf("results %+v\n%s", res, r.out)
	}
}

func TestRecoverLeavesARecordForAnotherLayout(t *testing.T) {
	r := newRig(t, newRelease("v0.7.7"))
	// A file outside the node's layout, with a *.prev beside it: settling
	// the op would copy the .prev over it.
	target := filepath.Join(r.dir, "etc", "elsewhere")
	writeFile(t, target, []byte("root's own file\n"))
	writeFile(t, target+".prev", []byte("chosen content\n"))
	prevSum, _ := fileSHA256(target + ".prev")
	curSum, _ := fileSHA256(target)
	// The record says the file now there is the new one, so settling it
	// would put the .prev back.
	plantRecord(t, r, &State{
		Format: stateFormat, Op: "elsewhere", Version: "v9.9.9", Phase: PhaseRevert, StartedAt: time.Now(),
		Files: []FileState{{Role: roleSandboxd, Asset: "sandboxd", Path: target, SHA256: curSum,
			PrevSHA256: prevSum, Changed: true, Swapped: true}},
	})
	res, err := Recover(context.Background(), r.paths, r.host, r.out)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "root's own file\n" {
		t.Fatalf("recovery put a file back at %s, a path outside this node's layout: %q", target, got)
	}
	if len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "this node installs sandboxd at") {
		t.Fatalf("results %+v", res)
	}
	st, err := LoadState(r.paths.StateDir, "elsewhere")
	if err != nil || st.Phase != PhaseFailed || !strings.Contains(st.Error, "left as it is") {
		t.Fatalf("record %+v, %v", st, err)
	}
}

// A backup the upgrade folder holds under its own name is still restored:
// the check refuses only what is not the upgrade's own.
func TestCheckBackupPath(t *testing.T) {
	dir := realDir(t)
	good := filepath.Join(dir, "op.state.db")
	writeFile(t, good, []byte("db"))
	if err := checkBackupPath(dir, good); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, filepath.Join(dir, "link.state.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		filepath.Join(dir, "link.state.db"),                  // a link
		filepath.Join(dir, "sub", "op.state.db"),             // not directly in the folder
		filepath.Join(dir, "..", filepath.Base(dir), "x.db"), // another name
		filepath.Join(dir, "sub"),                            // a folder
		"op.state.db",                                        // relative
	} {
		if err := checkBackupPath(dir, bad); err == nil {
			t.Errorf("%s passed", bad)
		}
	}
	if err := restoreBackup(dir, good, ""); err == nil {
		t.Error("a restore with no database path passed")
	}
}
