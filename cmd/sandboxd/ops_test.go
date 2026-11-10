package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeops"
	"github.com/aerol-ai/microvm/pkg/daemon"
)

// opsHost is a stopped node for the backup, restore and recover-quorum
// command lines.
type opsHost struct{ active bool }

func (h *opsHost) UnitActive(context.Context, string) bool { return h.active }
func (h *opsHost) StopUnit(context.Context, string) error  { h.active = false; return nil }
func (h *opsHost) StartUnit(context.Context, string) error { h.active = true; return nil }
func (h *opsHost) HealthVersion(context.Context, string) (string, error) {
	return "", errors.New("connection refused")
}

// opsNode is a server's config and state directories in a temp dir, with
// the command seams pointed at a stopped sandboxd.
func opsNode(t *testing.T) (etc, lib string, h *opsHost) {
	t.Helper()
	dir := t.TempDir()
	etc, lib = filepath.Join(dir, "etc"), filepath.Join(dir, "lib")
	for _, d := range []string{etc, filepath.Join(lib, "raft")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := "SB_DB_PATH=" + filepath.Join(lib, "state.db") + "\nSB_NODE_ID=server-1\nSB_RAFT_ADVERTISE_ADDR=10.0.0.5:7000\n" +
		"SB_CREDENTIAL_ENCRYPTION_KEY_PATH=" + filepath.Join(lib, "key") + "\n"
	if err := os.WriteFile(filepath.Join(etc, "sandboxd.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "raft", "raft-stable.bolt"), []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(lib, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('a')"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	h = &opsHost{}
	origHost, origSig := newOpsHost, upgradeSignalContext
	t.Cleanup(func() { newOpsHost, upgradeSignalContext = origHost, origSig })
	newOpsHost = func() nodeops.Host { return h }
	upgradeSignalContext = func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), time.Minute)
	}
	return etc, lib, h
}

func TestOpsCommands(t *testing.T) {
	etc, lib, h := opsNode(t)
	archive := filepath.Join(t.TempDir(), "b.tgz")
	var stdout, stderr bytes.Buffer
	if code := runBackupCLI([]string{"--config-dir", etc, "--output", archive}, &stdout, &stderr); code != 0 {
		t.Fatalf("backup exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "with VACUUM INTO in") || !strings.Contains(stdout.String(), "wrote "+archive) {
		t.Fatalf("backup output:\n%s", stdout.String())
	}

	root := t.TempDir()
	stdout.Reset()
	if code := runRestoreCLI([]string{"--input", archive, "--target-root", root, "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("restore exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "var", "lib", "sandboxd", "raft", "raft-stable.bolt")); err != nil {
		t.Fatalf("restore: %v\n%s", err, stdout.String())
	}

	stdout.Reset()
	if code := runRecoverQuorumCLI([]string{"--config-dir", etc, "--no-backup"}, &stdout, &stderr); code != 0 {
		t.Fatalf("recover-quorum exit %d: %s", code, stderr.String())
	}
	if b, err := os.ReadFile(filepath.Join(lib, "raft", "peers.json")); err != nil || !strings.Contains(string(b), `"id": "server-1"`) {
		t.Fatalf("peers.json %q %v", b, err)
	}
	// Run again on a running node: refused, exit 1.
	h.active = true
	stderr.Reset()
	if code := runRecoverQuorumCLI([]string{"--config-dir", etc, "--force", "--no-backup"}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "stop sandboxd") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	h.active = false
	if code := runRecoverQuorumCLI([]string{"--config-dir", etc, "--rejoin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("rejoin exit %d: %s", code, stderr.String())
	}
	if m, _ := filepath.Glob(filepath.Join(lib, "raft.pre-rejoin.*")); len(m) != 1 {
		t.Fatalf("rejoin moved %v", m)
	}
}

func TestOpsCLIErrors(t *testing.T) {
	etc, _, _ := opsNode(t)
	for _, tc := range []struct {
		run  func([]string, io.Writer, io.Writer) int
		args []string
		code int
		want string
	}{
		{runBackupCLI, nil, 2, "--output is required"},
		{runBackupCLI, []string{"--bogus"}, 2, "flag provided but not defined"},
		{runBackupCLI, []string{"--output", "x", "extra"}, 2, `unexpected argument "extra"`},
		{runBackupCLI, []string{"--config-dir", etc, "--output", etc + "/x.tgz"}, 2, "which the backup copies"},
		{runRestoreCLI, []string{"--input", "x"}, 2, "refusing to restore without --force"},
		{runRestoreCLI, []string{"--input", "/nonexistent.tgz", "--force"}, 1, "backup archive not found"},
		{runRecoverQuorumCLI, []string{"--config-dir", etc, "--node-id", "server-2"}, 2, "is not this node"},
		{runRecoverQuorumCLI, []string{"--config-dir", etc, "--raft-dir", t.TempDir()}, 1, "no Raft data"},
	} {
		var stderr bytes.Buffer
		if code := tc.run(tc.args, io.Discard, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: exit %d, want %d with %q:\n%s", tc.args, code, tc.code, tc.want, stderr.String())
		}
	}
	for cmd, usage := range map[string]string{backupSubcommand: backupUsage, restoreSubcommand: restoreUsage, recoverQuorumSubcommand: recoverQuorumUsage} {
		var stdout bytes.Buffer
		if code := opsCommands[cmd]([]string{"--help"}, &stdout, io.Discard); code != 0 || stdout.String() != usage {
			t.Errorf("%s --help: exit %d\n%s", cmd, code, stdout.String())
		}
	}
}

// The wrapper scripts run the installed sandboxd only when it carries the
// command's usage text: an older sandboxd would read the command as no
// argument and boot a second daemon on the live state directory.
func TestOpsUsageCarriesTheCommandMarkers(t *testing.T) {
	for cmd, tc := range map[string]struct{ usage, script string }{
		backupSubcommand:        {backupUsage, "sandboxd-backup.sh"},
		restoreSubcommand:       {restoreUsage, "sandboxd-restore.sh"},
		recoverQuorumSubcommand: {recoverQuorumUsage, "raft-lost-quorum-recover.sh"},
	} {
		marker := "usage: sandboxd " + cmd
		if !strings.HasPrefix(tc.usage, marker) {
			t.Errorf("%s usage does not start with %q", cmd, marker)
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", tc.script))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "grep -aqF '"+marker+"' \"$bin\"") {
			t.Errorf("%s does not probe the binary for %q", tc.script, marker)
		}
		if !strings.Contains(string(raw), `exec "$bin" `+cmd+` "$@"`) {
			t.Errorf("%s does not hand its arguments to sandboxd %s", tc.script, cmd)
		}
	}
}

func TestMainRoutesOpsCommands(t *testing.T) {
	origArgs, origExit := os.Args, osExit
	t.Cleanup(func() { os.Args, osExit = origArgs, origExit })
	origDaemon := runDaemon
	t.Cleanup(func() { runDaemon = origDaemon })
	booted := false
	runDaemon = func(context.Context, *slog.Logger, daemon.ProviderFactory) error { booted = true; return nil }
	code := -1
	osExit = func(c int) { code = c }

	os.Args = []string{"sandboxd", "backup", "--help"}
	main()
	if code != -1 || booted {
		t.Fatalf("backup --help: exit %d, daemon booted %v", code, booted)
	}
	os.Args = []string{"sandboxd", "restore"}
	main()
	if code != 2 || booted {
		t.Fatalf("restore with no input: exit %d, daemon booted %v", code, booted)
	}
}
