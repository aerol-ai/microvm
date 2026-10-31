package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The backup-restore runbook restores onto a replacement node, which has
// already run a fresh install: it holds a database of its own, maybe its
// WAL, and a Raft log. sandboxd-restore.sh must replace those, not merge
// the archive into them: SQLite would replay the leftover WAL onto the
// restored database, and two Raft logs in one directory are not one log.
// What it replaces is moved aside, not deleted.
func TestRestoreReplacesTheDatabaseAndRaftLog(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	scripts, err := filepath.Abs(filepath.Join("..", "..", "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(script string, args ...string) {
		t.Helper()
		out, err := exec.Command("bash", append([]string{filepath.Join(scripts, script)}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}

	// The node the backup comes from.
	src := t.TempDir()
	write(filepath.Join(src, "state.db"), "restored-db")
	write(filepath.Join(src, "raft", "log-old-node"), "old")
	write(filepath.Join(src, "etc", "sandboxd.env"), "SB_NODE_ID=node-a\n")
	archive := filepath.Join(t.TempDir(), "backup.tgz")
	run("sandboxd-backup.sh", "--state-db", filepath.Join(src, "state.db"), "--raft-dir", filepath.Join(src, "raft"),
		"--config-dir", filepath.Join(src, "etc"), "--wrapped-key", filepath.Join(src, "none"), "--key-ring", filepath.Join(src, "none"),
		"--output", archive)

	// The replacement, after its own fresh install.
	dst := t.TempDir()
	lib := filepath.Join(dst, "var", "lib", "sandboxd")
	write(filepath.Join(lib, "state.db"), "fresh-db")
	write(filepath.Join(lib, "state.db-wal"), "fresh-wal")
	write(filepath.Join(lib, "state.db-shm"), "fresh-shm")
	write(filepath.Join(lib, "raft", "log-fresh-install"), "fresh")
	run("sandboxd-restore.sh", "--input", archive, "--target-root", dst, "--force")

	if b, err := os.ReadFile(filepath.Join(lib, "state.db")); err != nil || string(b) != "restored-db" {
		t.Fatalf("state.db = %q %v, want the archive's", b, err)
	}
	for _, gone := range []string{"state.db-wal", "state.db-shm", filepath.Join("raft", "log-fresh-install")} {
		if _, err := os.Stat(filepath.Join(lib, gone)); !os.IsNotExist(err) {
			t.Errorf("%s is still beside the restored state: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(lib, "raft", "log-old-node")); err != nil {
		t.Errorf("the archive's Raft log was not restored: %v", err)
	}
	aside, _ := filepath.Glob(filepath.Join(lib, "*.pre-restore-*"))
	var names []string
	for _, a := range aside {
		names = append(names, strings.SplitN(filepath.Base(a), ".pre-restore-", 2)[0])
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "raft,state.db,state.db-shm,state.db-wal" {
		t.Errorf("moved aside: %q, want the replaced database, its WAL and SHM, and the Raft log", got)
	}
}
