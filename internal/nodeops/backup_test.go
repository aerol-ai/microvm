package nodeops

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/raftlogdir"
)

// node is a fake node's tree: <dir>/etc holds the env files, <dir>/lib the
// state directory.
type node struct {
	dir, etc, lib string
}

func newNode(t *testing.T, env string) node {
	t.Helper()
	dir := t.TempDir()
	n := node{dir: dir, etc: filepath.Join(dir, "etc"), lib: filepath.Join(dir, "lib")}
	write(t, filepath.Join(n.etc, "sandboxd.env"), "SB_DB_PATH="+filepath.Join(n.lib, "state.db")+"\n"+
		"SB_CREDENTIAL_ENCRYPTION_KEY_PATH="+filepath.Join(n.lib, keyName)+"\n"+env)
	return n
}

func (n node) backup(t *testing.T, o BackupOptions) BackupResult {
	t.Helper()
	o.ConfigDir = n.etc
	if o.Output == "" {
		o.Output = filepath.Join(n.dir, "out", "backup.tgz")
	}
	if o.Host == nil {
		o.Host = &fakeHost{}
	}
	o.hostname = func() (string, error) { return "node-a.example", nil }
	res, err := Backup(context.Background(), o)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	return res
}

// The archive carries the database with the writes still in its WAL (the
// script's cp of state.db missed them), the Raft tree, the config
// directory and the file-custody key, under the script's fixed names, with
// each file's mode, and a manifest in the script's order.
func TestBackupArchivesTheNode(t *testing.T) {
	n := newNode(t, "SB_NODE_ID=node-a\n")
	makeDB(t, filepath.Join(n.lib, "state.db"), "a", "b", "c")
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
	write(t, filepath.Join(n.lib, "raft", "snapshots", "1-2-3", "state.bin"), "snap")
	write(t, filepath.Join(n.lib, keyName), "plain-key")
	write(t, filepath.Join(n.etc, "tls", "node.crt"), "cert")
	if err := os.Chmod(filepath.Join(n.etc, "tls", "node.crt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("node.crt", filepath.Join(n.etc, "tls", "current.crt")); err != nil {
		t.Fatal(err)
	}
	// A FIFO has no place in a backup and must not stop one.
	if err := syscall.Mkfifo(filepath.Join(n.etc, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	clock := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	res := n.backup(t, BackupOptions{Out: &out, Version: "v0.6.12", now: func() time.Time { clock = clock.Add(time.Second); return clock }})

	st, err := os.Stat(res.Output)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("archive %s: %v %v, want mode 0600", res.Output, st, err)
	}
	if res.Bytes != st.Size() || res.DBBytes == 0 || res.DBTook != time.Second || res.Custody != "file" {
		t.Fatalf("result %+v", res)
	}
	files, hdrs := readArchive(t, res.Output)
	db := filepath.Join(t.TempDir(), "state.db")
	write(t, db, files[archiveDB])
	if got := dbRows(t, db); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("the archived database has rows %v, want a,b,c (the WAL's too)", got)
	}
	for name, want := range map[string]string{
		archiveRaft + "/raft-stable.bolt":          "stable",
		archiveRaft + "/snapshots/1-2-3/state.bin": "snap",
		archiveConfig + "/tls/node.crt":            "cert",
		archiveLib + "/" + keyName:                 "plain-key",
		archiveConfig + "/sandboxd.env":            read(t, filepath.Join(n.etc, "sandboxd.env")),
	} {
		if files[name] != want {
			t.Errorf("%s = %q, want %q", name, files[name], want)
		}
	}
	if h := hdrs[archiveConfig+"/tls/node.crt"]; h == nil || h.Mode&0o777 != 0o644 {
		t.Errorf("node.crt header %+v, want its mode 0644", h)
	}
	if h := hdrs[archiveConfig+"/tls/current.crt"]; h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != "node.crt" {
		t.Errorf("current.crt header %+v, want a link to node.crt", h)
	}
	if _, ok := hdrs[archiveConfig+"/fifo"]; ok {
		t.Error("the FIFO was archived")
	}
	for _, d := range []string{"", "var", "var/lib", archiveLib, archiveRaft, archiveConfig} {
		if h := hdrs[d]; h == nil || h.Typeflag != tar.TypeDir {
			t.Errorf("directory %q: %+v", d, h)
		}
	}
	wantManifest := strings.Join([]string{
		"created_utc=2026-11-07T10:00:01Z",
		"hostname=node-a.example",
		"state_db=" + filepath.Join(n.lib, "state.db"),
		"raft_dir=" + filepath.Join(n.lib, "raft"),
		"config_dir=" + n.etc,
		"included=" + filepath.Join(n.lib, "state.db"),
		"included=" + filepath.Join(n.lib, "raft"),
		"included=" + n.etc,
		"key_custody=file",
		"included=" + filepath.Join(n.lib, keyName),
		"sandboxd_version=v0.6.12",
		"state_db_copy=vacuum_into",
	}, "\n") + "\n"
	if !strings.HasPrefix(files[manifestName], wantManifest) || !strings.Contains(files[manifestName], "state_db_copy_ms=1000\n") {
		t.Errorf("manifest:\n%s\nwant it to start with:\n%s", files[manifestName], wantManifest)
	}
	for _, want := range []string{"backed up " + filepath.Join(n.lib, "state.db"), "with VACUUM INTO in 1s", "wrote " + res.Output} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	// No temporary file is left beside the archive.
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(res.Output), ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

// The backup decides from the key custody setting whether the archive must
// carry the wrapped server key, and it reads that setting as sandboxd does:
// systemd strips the quotes and whitespace around a value, and the cluster
// drop-in's cluster.env overrides sandboxd.env. Misread, a wrapped node's
// backup leaves out its only copy of the server key. With wrapped custody
// no plaintext key line leaves the node.
func TestBackupReadsKeyCustodyAsSandboxdDoes(t *testing.T) {
	const wrappedPath = archiveLib + "/" + wrappedName
	for name, tc := range map[string]struct {
		env         map[string]string
		wantWrapped bool
	}{
		"quoted, spaced, CRLF": {
			env:         map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY = \"wrapped\"\r\n  SB_CREDENTIAL_ENCRYPTION_KEY=plain\n"},
			wantWrapped: true,
		},
		"single quotes": {
			env:         map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY='wrapped'\n"},
			wantWrapped: true,
		},
		"cluster.env wins": {
			env:         map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY=file\n", "cluster.env": "SB_CREDENTIAL_KEY_CUSTODY=wrapped\nSB_CREDENTIAL_ENCRYPTION_KEY=x\n"},
			wantWrapped: true,
		},
		"cluster.env wins, the other way": {
			env: map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n", "cluster.env": "SB_CREDENTIAL_KEY_CUSTODY=file\n"},
		},
		"a commented-out line": {
			env: map[string]string{"sandboxd.env": "# SB_CREDENTIAL_KEY_CUSTODY=wrapped\n"},
		},
		"no env files": {},
	} {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			etc := filepath.Join(src, "etc")
			if err := os.MkdirAll(filepath.Join(etc, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			for f, body := range tc.env {
				write(t, filepath.Join(etc, f), body)
			}
			// Only the env files directly in the config directory are
			// scrubbed, as the script's glob did.
			write(t, filepath.Join(etc, "sub", "x.env"), "SB_CREDENTIAL_ENCRYPTION_KEY=nested\n")
			wrapped := filepath.Join(src, "wrapped")
			write(t, wrapped, `{"format":1}`)
			none := filepath.Join(src, "none")
			res, err := Backup(context.Background(), BackupOptions{StateDB: none, RaftDir: none, ConfigDir: etc,
				WrappedKey: wrapped, KeyRing: none, KeyFile: none, Output: filepath.Join(src, "out", "b.tgz"), Host: &fakeHost{}})
			if err != nil {
				t.Fatal(err)
			}
			files, _ := readArchive(t, res.Output)
			if _, got := files[wrappedPath]; got != tc.wantWrapped {
				t.Fatalf("wrapped key in the archive = %v, want %v (manifest:\n%s)", got, tc.wantWrapped, files[manifestName])
			}
			for f, body := range files {
				if tc.wantWrapped && isTopLevelEnv(f) && strings.Contains(body, "SB_CREDENTIAL_ENCRYPTION_KEY") {
					t.Fatalf("%s carries a plaintext key line beside the wrapped key:\n%s", f, body)
				}
			}
			if !strings.Contains(files[archiveConfig+"/sub/x.env"], "nested") {
				t.Error("a nested env file was changed")
			}
			wantCustody := "key_custody=file\n"
			if tc.wantWrapped {
				wantCustody = "key_custody=wrapped\n"
			}
			if !strings.Contains(files[manifestName], wantCustody) {
				t.Errorf("manifest lacks %q:\n%s", wantCustody, files[manifestName])
			}
		})
	}
}

// A node without a database, Raft data or key still gets an archive: the
// manifest says what was missing, as the script's did. A wrapped node
// whose wrapped file is gone is listed as missing too.
func TestBackupOfAnEmptyNode(t *testing.T) {
	n := newNode(t, "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n")
	res := n.backup(t, BackupOptions{})
	files, _ := readArchive(t, res.Output)
	for _, want := range []string{
		"missing=" + filepath.Join(n.lib, "state.db"),
		"missing=" + filepath.Join(n.lib, "raft"),
		"included=" + n.etc,
		"key_custody=wrapped",
		"missing=" + defaultWrappedKey,
	} {
		if !strings.Contains(files[manifestName], want+"\n") {
			t.Errorf("manifest lacks %q:\n%s", want, files[manifestName])
		}
	}
	if strings.Contains(files[manifestName], "state_db_copy") || res.DBBytes != 0 {
		t.Errorf("a missing database reports a copy: %+v\n%s", res, files[manifestName])
	}
}

// A config directory on another disk, reached through a link, is backed up
// as what it holds, not as a link that would restore empty.
func TestBackupFollowsALinkedTree(t *testing.T) {
	n := newNode(t, "")
	real := filepath.Join(n.dir, "real-raft")
	write(t, filepath.Join(real, "raft-stable.bolt"), "stable")
	if err := os.Symlink(real, filepath.Join(n.dir, "raft-link")); err != nil {
		t.Fatal(err)
	}
	res := n.backup(t, BackupOptions{RaftDir: filepath.Join(n.dir, "raft-link")})
	files, hdrs := readArchive(t, res.Output)
	if files[archiveRaft+"/raft-stable.bolt"] != "stable" || hdrs[archiveRaft].Typeflag != tar.TypeDir {
		t.Fatalf("raft through a link: %v %+v", files, hdrs[archiveRaft])
	}
}

// --stop takes sandboxd down for the copy and always brings it back, also
// when the backup fails; a node that was not running stays down. Without
// --stop a running node's Raft files are copied live, and the output says
// so.
func TestBackupStop(t *testing.T) {
	t.Run("running", func(t *testing.T) {
		n := newNode(t, "")
		write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "x")
		h := &fakeHost{active: true}
		var out bytes.Buffer
		n.backup(t, BackupOptions{Stop: true, Host: h, Out: &out})
		if !h.called("stop") || !h.called("start") || !h.active {
			t.Fatalf("calls %v", h.calls)
		}
		if strings.Contains(out.String(), "copied while sandboxd runs") {
			t.Errorf("a stopped node's Raft copy was called live:\n%s", out.String())
		}
	})
	t.Run("not running", func(t *testing.T) {
		n := newNode(t, "")
		h := &fakeHost{}
		n.backup(t, BackupOptions{Stop: true, Host: h})
		if h.called("stop") || h.called("start") {
			t.Fatalf("calls %v", h.calls)
		}
	})
	t.Run("live raft copy is called out", func(t *testing.T) {
		n := newNode(t, "")
		write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "x")
		var out bytes.Buffer
		n.backup(t, BackupOptions{Host: &fakeHost{active: true}, Out: &out})
		if !strings.Contains(out.String(), "pass --stop") {
			t.Errorf("no note on a live Raft copy:\n%s", out.String())
		}
	})
	t.Run("a failed backup still starts sandboxd", func(t *testing.T) {
		n := newNode(t, "")
		write(t, filepath.Join(n.lib, "state.db"), "this is not a database")
		h := &fakeHost{active: true}
		_, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: filepath.Join(n.dir, "b.tgz"), Stop: true, Host: h})
		if err == nil || !strings.Contains(err.Error(), "state.db") {
			t.Fatalf("err = %v", err)
		}
		if !h.called("start") {
			t.Fatalf("sandboxd left stopped: %v", h.calls)
		}
		if _, err := os.Stat(filepath.Join(n.dir, "b.tgz")); !os.IsNotExist(err) {
			t.Fatalf("a failed backup left an archive: %v", err)
		}
	})
	t.Run("stop fails", func(t *testing.T) {
		n := newNode(t, "")
		h := &fakeHost{active: true, stopErr: errors.New("denied")}
		if _, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: filepath.Join(n.dir, "b.tgz"), Stop: true, Host: h}); err == nil {
			t.Fatal("backed up with sandboxd still running after a failed stop")
		}
	})
	t.Run("start fails", func(t *testing.T) {
		n := newNode(t, "")
		h := &fakeHost{active: true, startErr: errors.New("unit failed")}
		if _, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: filepath.Join(n.dir, "b.tgz"), Stop: true, Host: h}); err == nil || !strings.Contains(err.Error(), "unit failed") {
			t.Fatalf("err = %v, want the failed start", err)
		}
	})
}

func TestBackupRefusals(t *testing.T) {
	n := newNode(t, "")
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "x")
	for name, tc := range map[string]struct {
		o     BackupOptions
		usage bool
		want  string
	}{
		"no output":        {o: BackupOptions{}, usage: true, want: "--output is required"},
		"output in raft":   {o: BackupOptions{Output: filepath.Join(n.lib, "raft", "b.tgz")}, usage: true, want: "which the backup copies"},
		"output in config": {o: BackupOptions{Output: filepath.Join(n.etc, "b.tgz")}, usage: true, want: "which the backup copies"},
		"output dir is a file": {
			o: BackupOptions{Output: filepath.Join(n.etc, "sandboxd.env", "b.tgz"), ConfigDir: filepath.Join(n.dir, "none")}, want: "not a directory",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.o.ConfigDir == "" {
				tc.o.ConfigDir = n.etc
			}
			tc.o.Host = &fakeHost{}
			_, err := Backup(context.Background(), tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrUsage) != tc.usage {
				t.Fatalf("err = %v, want %q (usage %v)", err, tc.want, tc.usage)
			}
		})
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sandboxd.env"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Backup(context.Background(), BackupOptions{ConfigDir: dir, Output: filepath.Join(dir, "x.tgz"), Host: &fakeHost{}}); err == nil {
		t.Fatal("an unreadable env file was ignored")
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{12: "12 B", 2048: "2.0 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.00 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// A log SB_RAFT_WAL_DIR put on a disk of its own is archived where it is by
// default, raft/raft-wal, without the record naming that disk, so a restore
// lands the default layout. A restore onto a node still configured for its
// own log disk says sandboxd will refuse to start until that is removed.
func TestBackupTakesALogOnItsOwnDisk(t *testing.T) {
	own := filepath.Join(t.TempDir(), "disk", "raft-wal")
	n := newNode(t, "SB_RAFT_WAL_DIR="+own+"\n")
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
	write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), own+"\n")
	write(t, filepath.Join(own, "wal-meta.db"), "meta")
	write(t, filepath.Join(own, "00000000000000000001-0000000000000000.wal"), "segment")

	res := n.backup(t, BackupOptions{})
	files, _ := readArchive(t, res.Output)
	for name, want := range map[string]string{
		archiveRaft + "/raft-stable.bolt":                                   "stable",
		archiveRaft + "/raft-wal/wal-meta.db":                               "meta",
		archiveRaft + "/raft-wal/00000000000000000001-0000000000000000.wal": "segment",
	} {
		if files[name] != want {
			t.Errorf("%s = %q, want %q", name, files[name], want)
		}
	}
	if _, ok := files[archiveRaft+"/"+raftlogdir.LocationFile]; ok {
		t.Error("the record naming the log disk was archived")
	}
	if !strings.Contains(files[manifestName], "raft_wal_dir="+own+"\n") {
		t.Errorf("manifest lacks the log directory:\n%s", files[manifestName])
	}

	// An archive inside the log directory would copy itself.
	o := BackupOptions{ConfigDir: n.etc, Output: filepath.Join(own, "b.tgz"), Host: &fakeHost{}}
	if _, err := Backup(context.Background(), o); !errors.Is(err, ErrUsage) {
		t.Fatalf("backup into the log directory: %v", err)
	}

	dst := t.TempDir()
	write(t, filepath.Join(dst, "etc", "sandboxd", "sandboxd.env"), "SB_RAFT_WAL_DIR="+own+"\n")
	_, out, err := restore(t, RestoreOptions{Input: res.Output, TargetRoot: dst})
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	lib := filepath.Join(dst, "var", "lib", "sandboxd")
	if read(t, filepath.Join(lib, "raft", "raft-wal", "wal-meta.db")) != "meta" {
		t.Fatal("the log did not land in raft/raft-wal")
	}
	if !strings.Contains(out, "WARNING: the restored Raft log is in") || !strings.Contains(out, "SB_RAFT_WAL_DIR="+own) {
		t.Fatalf("no warning about SB_RAFT_WAL_DIR:\n%s", out)
	}
}

// A node whose Raft directory records an unreadable location is not backed
// up with its log missing.
func TestBackupRefusesABadLogRecord(t *testing.T) {
	n := newNode(t, "")
	write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), "relative/dir\n")
	o := BackupOptions{ConfigDir: n.etc, Output: filepath.Join(n.dir, "out", "b.tgz"), Host: &fakeHost{}}
	if _, err := Backup(context.Background(), o); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("backup = %v; want the record refused", err)
	}
}
