package nodeops

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func restore(t *testing.T, o RestoreOptions) (RestoreResult, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	o.Out, o.Err, o.Force = &out, &errOut, true
	if o.Host == nil {
		o.Host = &fakeHost{}
	}
	if o.now == nil {
		o.now = func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) }
	}
	res, err := Restore(context.Background(), o)
	return res, out.String() + errOut.String(), err
}

// The backup-restore runbook restores onto a replacement node, which has
// already run a fresh install: it holds a database of its own, maybe its
// WAL, and a Raft log. Restore must replace those, not merge the archive
// into them: SQLite would replay the leftover WAL onto the restored
// database, and two Raft logs in one directory are not one log. What it
// replaces is moved aside, not deleted.
func TestRestoreReplacesTheDatabaseAndRaftLog(t *testing.T) {
	src := newNode(t, "SB_NODE_ID=node-a\n")
	makeDB(t, filepath.Join(src.lib, "state.db"), "restored")
	write(t, filepath.Join(src.lib, "raft", "log-old-node"), "old")
	archive := src.backup(t, BackupOptions{}).Output

	dst := t.TempDir()
	lib := filepath.Join(dst, "var", "lib", "sandboxd")
	write(t, filepath.Join(lib, "state.db"), "fresh-db")
	write(t, filepath.Join(lib, "state.db-wal"), "fresh-wal")
	write(t, filepath.Join(lib, "state.db-shm"), "fresh-shm")
	write(t, filepath.Join(lib, "raft", "log-fresh-install"), "fresh")
	res, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst})
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if got := dbRows(t, filepath.Join(lib, "state.db")); strings.Join(got, ",") != "restored" {
		t.Fatalf("state.db rows %v, want the archive's", got)
	}
	for _, gone := range []string{"state.db-wal", "state.db-shm", filepath.Join("raft", "log-fresh-install")} {
		if _, err := os.Stat(filepath.Join(lib, gone)); !os.IsNotExist(err) {
			t.Errorf("%s is still beside the restored state: %v", gone, err)
		}
	}
	if read(t, filepath.Join(lib, "raft", "log-old-node")) != "old" {
		t.Error("the archive's Raft log was not restored")
	}
	if read(t, filepath.Join(dst, "etc", "sandboxd", "sandboxd.env")) != read(t, filepath.Join(src.etc, "sandboxd.env")) {
		t.Error("the config directory was not restored")
	}
	if _, err := os.Stat(filepath.Join(dst, manifestName)); !os.IsNotExist(err) {
		t.Error("the manifest was written onto the node")
	}
	var names []string
	for _, a := range res.MovedAside {
		names = append(names, strings.SplitN(filepath.Base(a), ".pre-restore-", 2)[0])
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "raft,state.db,state.db-shm,state.db-wal" {
		t.Errorf("moved aside: %q, want the replaced database, its WAL and SHM, and the Raft log", got)
	}
	if !strings.Contains(out, "verify ownership/modes, then start sandboxd") || !strings.Contains(out, "restored "+archive) {
		t.Errorf("output:\n%s", out)
	}
}

// A restored node must come back with the archive's server-key files and
// none of the node it replaces: sandboxd refuses wrapped custody beside a
// plaintext key or ring, and a fresh install's own key beside a restored
// ring or env key is the wrong key. What goes is moved aside, not deleted.
// A file-custody backup carries its plaintext key file, so a fresh machine
// can open the restored data.
func TestRestoreBringsTheArchivesKeySet(t *testing.T) {
	const (
		key     = keyName
		ring    = ringName
		wrapped = wrappedName
	)
	for name, tc := range map[string]struct {
		srcEnv  string            // the backed-up node's sandboxd.env
		srcKeys map[string]string // the backed-up node's key files
		dstKeys map[string]string // the replacement's, before the restore
		want    map[string]string // key files after the restore ("" = absent)
		aside   []string          // the replacement's files moved aside
		warn    bool
	}{
		"wrapped over a default install": {
			srcEnv: "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n", srcKeys: map[string]string{wrapped: "src-wrapped"},
			dstKeys: map[string]string{key: "fresh-key"},
			want:    map[string]string{wrapped: "src-wrapped", key: "", ring: ""}, aside: []string{key},
		},
		"wrapped over a rotated plaintext ring": {
			srcEnv: "SB_CREDENTIAL_KEY_CUSTODY='wrapped'\n", srcKeys: map[string]string{wrapped: "src-wrapped"},
			dstKeys: map[string]string{key: "fresh-key", ring: "fresh-ring"},
			want:    map[string]string{wrapped: "src-wrapped", key: "", ring: ""}, aside: []string{key, ring},
		},
		"wrapped over a wrapped install": {
			srcEnv: "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n", srcKeys: map[string]string{wrapped: "src-wrapped"},
			dstKeys: map[string]string{wrapped: "fresh-wrapped"},
			want:    map[string]string{wrapped: "src-wrapped"}, aside: []string{wrapped},
		},
		"file over a wrapped install": {
			srcKeys: map[string]string{key: "src-key"},
			dstKeys: map[string]string{wrapped: "fresh-wrapped"},
			want:    map[string]string{key: "src-key", wrapped: ""}, aside: []string{wrapped},
		},
		"file with a ring over a default install": {
			srcKeys: map[string]string{key: "src-key", ring: "src-ring"},
			dstKeys: map[string]string{key: "fresh-key"},
			want:    map[string]string{key: "src-key", ring: "src-ring"}, aside: []string{key},
		},
		"file over a rotated ring": {
			srcKeys: map[string]string{key: "src-key"},
			dstKeys: map[string]string{key: "fresh-key", ring: "fresh-ring"},
			want:    map[string]string{key: "src-key", ring: ""}, aside: []string{key, ring},
		},
		"env key over a default install": {
			srcEnv:  "SB_CREDENTIAL_ENCRYPTION_KEY=c3JjLWtleQ==\n",
			dstKeys: map[string]string{key: "fresh-key"},
			want:    map[string]string{key: ""}, aside: []string{key},
		},
		"a ring with no key file over a default install": {
			srcKeys: map[string]string{ring: "src-ring"},
			dstKeys: map[string]string{key: "fresh-key"},
			want:    map[string]string{key: "", ring: "src-ring"}, aside: []string{key},
		},
		"a legacy archive with no key restored in place": {
			dstKeys: map[string]string{key: "own-key"},
			want:    map[string]string{key: "own-key"}, warn: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			src := newNode(t, tc.srcEnv)
			makeDB(t, filepath.Join(src.lib, "state.db"), "x")
			for f, body := range tc.srcKeys {
				write(t, filepath.Join(src.lib, "keys", f), body)
			}
			k := filepath.Join(src.lib, "keys")
			archive := src.backup(t, BackupOptions{WrappedKey: filepath.Join(k, wrapped), KeyRing: filepath.Join(k, ring), KeyFile: filepath.Join(k, key)}).Output
			dst := t.TempDir()
			lib := filepath.Join(dst, "var", "lib", "sandboxd")
			write(t, filepath.Join(lib, "state.db"), "fresh-db")
			for f, body := range tc.dstKeys {
				write(t, filepath.Join(lib, f), body)
			}
			_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst})
			if err != nil {
				t.Fatalf("restore: %v\n%s", err, out)
			}
			for f, want := range tc.want {
				b, err := os.ReadFile(filepath.Join(lib, f))
				switch {
				case want == "" && err == nil:
					t.Errorf("%s is still there (%q)", f, b)
				case want != "" && (err != nil || string(b) != want):
					t.Errorf("%s = %q %v, want %q", f, b, err, want)
				}
			}
			for _, f := range tc.aside {
				if m, _ := filepath.Glob(filepath.Join(lib, f+".pre-restore-*")); len(m) != 1 {
					t.Errorf("%s was not moved aside (found %v)", f, m)
				}
			}
			if got := strings.Contains(out, "WARNING: the archive carries no server key"); got != tc.warn {
				t.Errorf("warning shown = %v, want %v\n%s", got, tc.warn, out)
			}
			for _, f := range []string{wrapped, ring} {
				if st, err := os.Stat(filepath.Join(lib, f)); err == nil && st.Mode().Perm() != 0o600 {
					t.Errorf("%s mode %v, want 0600", f, st.Mode())
				}
			}
		})
	}
}

// An archive made by the old sandboxd-backup.sh (`tar -C root -czf out .`)
// restores: its names start with "./", it has the mkdir -p directories, and
// its MANIFEST.txt is not node data.
func TestRestoreReadsTheScriptsArchive(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "old.tgz")
	writeTar(t, archive,
		tarEntry{name: "./._."}, // macOS tar's extended attributes
		tarEntry{name: "./"}, tarEntry{name: "./MANIFEST.txt", body: "created_utc=x\n"},
		tarEntry{name: "./etc/sandboxd/._sandboxd.env", body: "xattrs"},
		tarEntry{name: "./var/"}, tarEntry{name: "./var/lib/"}, tarEntry{name: "./var/lib/sandboxd/"},
		tarEntry{name: "./var/lib/sandboxd/state.db", body: "db", mode: 0o640},
		tarEntry{name: "./var/lib/sandboxd/raft/", mode: 0o700},
		tarEntry{name: "./var/lib/sandboxd/raft/raft-stable.bolt", body: "s"},
		tarEntry{name: "./var/lib/sandboxd/raft/same.bolt", typ: tar.TypeLink, link: "./var/lib/sandboxd/raft/raft-stable.bolt"},
		tarEntry{name: "./etc/"}, tarEntry{name: "./etc/sandboxd/", mode: 0o750},
		tarEntry{name: "./etc/sandboxd/sandboxd.env", body: "SB_NODE_ID=a\n"},
		tarEntry{name: "./etc/sandboxd/tls/", mode: 0o700},
		tarEntry{name: "./etc/sandboxd/tls/current.crt", typ: tar.TypeSymlink, link: "node.crt"},
	)
	dst := t.TempDir()
	// The replacement's own file where the archive has a link: replaced.
	write(t, filepath.Join(dst, "etc", "sandboxd", "tls", "current.crt"), "fresh")
	var chowned []string
	_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst, euid: func() int { return 0 },
		lchown: func(p string, _, _ int) error { chowned = append(chowned, p); return nil }})
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	lib := filepath.Join(dst, "var", "lib", "sandboxd")
	if read(t, filepath.Join(lib, "state.db")) != "db" || read(t, filepath.Join(lib, "raft", "same.bolt")) != "s" {
		t.Fatal("files not restored")
	}
	if st, _ := os.Stat(filepath.Join(lib, "state.db")); st.Mode().Perm() != 0o640 {
		t.Errorf("state.db mode %v, want the archive's 0640", st.Mode())
	}
	if st, _ := os.Stat(filepath.Join(dst, "etc", "sandboxd")); st.Mode().Perm() != 0o750 {
		t.Errorf("etc/sandboxd mode %v, want the archive's 0750", st.Mode())
	}
	if l, err := os.Readlink(filepath.Join(dst, "etc", "sandboxd", "tls", "current.crt")); err != nil || l != "node.crt" {
		t.Errorf("current.crt = %q %v, want a link to node.crt", l, err)
	}
	if len(chowned) == 0 {
		t.Error("as root, nothing got the archive's owner back")
	}
	for _, p := range chowned {
		if strings.HasSuffix(p, filepath.Join("var", "lib")) {
			t.Errorf("chowned the mkdir -p directory %s", p)
		}
	}
}

// A bad archive is refused before anything on the node changes.
func TestRestoreRefusesABadArchiveBeforeAnyChange(t *testing.T) {
	ok := []tarEntry{{name: "./"}, {name: "./var/lib/sandboxd/state.db", body: "db"}}
	for name, tc := range map[string]struct {
		entries []tarEntry
		raw     string
		want    string
	}{
		"not gzip":          {raw: "plain text", want: "not a gzipped backup archive"},
		"truncated":         {raw: "truncate", want: "read archive"},
		"climbs out":        {entries: append(ok, tarEntry{name: "./etc/sandboxd/../../../x", body: "x"}), want: "leaves the target root"},
		"absolute":          {entries: append(ok, tarEntry{name: "/etc/passwd", body: "x"}), want: "absolute path"},
		"foreign file":      {entries: append(ok, tarEntry{name: "./etc/cron.d/x", body: "x"}), want: "not part of a sandboxd backup"},
		"foreign state":     {entries: append(ok, tarEntry{name: "./var/lib/sandboxd/other", body: "x"}), want: "not part of a sandboxd backup"},
		"database as a dir": {entries: []tarEntry{{name: "./var/lib/sandboxd/state.db/"}}, want: "wrong type"},
		"parent as a file":  {entries: []tarEntry{{name: "./var", body: "x"}}, want: "wrong type"},
		"a device":          {entries: append(ok, tarEntry{name: "./etc/sandboxd/dev", typ: tar.TypeChar}), want: "never has"},
		"through a link": {entries: append(ok, tarEntry{name: "./etc/sandboxd/l", typ: tar.TypeSymlink, link: "/etc"},
			tarEntry{name: "./etc/sandboxd/l/cron", body: "x"}), want: "below the link"},
		"hard link out": {entries: append(ok, tarEntry{name: "./etc/sandboxd/x", typ: tar.TypeLink, link: "../../etc/shadow"}), want: "links to"},
		"hard link to a later file": {entries: append(ok, tarEntry{name: "./etc/sandboxd/x", typ: tar.TypeLink, link: "./etc/sandboxd/y"},
			tarEntry{name: "./etc/sandboxd/y", body: "y"}), want: "links to"},
	} {
		t.Run(name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			switch tc.raw {
			case "":
				writeTar(t, archive, tc.entries...)
			case "truncate":
				writeTar(t, archive, append(ok, tarEntry{name: "./etc/sandboxd/big", body: strings.Repeat("z", 64<<10)})...)
				b := []byte(read(t, archive))
				write(t, archive, string(b[:len(b)/2]))
			default:
				write(t, archive, tc.raw)
			}
			dst := t.TempDir()
			lib := filepath.Join(dst, "var", "lib", "sandboxd")
			write(t, filepath.Join(lib, "state.db"), "keep")
			_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.want, out)
			}
			if read(t, filepath.Join(lib, "state.db")) != "keep" {
				t.Fatal("the node changed before the archive was refused")
			}
			if m, _ := filepath.Glob(filepath.Join(lib, "*.pre-restore-*")); len(m) != 0 {
				t.Fatalf("moved aside before the archive was refused: %v", m)
			}
		})
	}
}

// If writing fails part way, what was moved aside comes back, so the node
// is left as it was rather than half restored.
func TestRestorePutsBackWhatItMovedOnFailure(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive,
		tarEntry{name: "./var/lib/sandboxd/state.db", body: "new"},
		tarEntry{name: "./var/lib/sandboxd/raft/raft-stable.bolt", body: "new"},
		tarEntry{name: "./etc/sandboxd/tls", body: "a file where the node has a directory"},
	)
	dst := t.TempDir()
	lib := filepath.Join(dst, "var", "lib", "sandboxd")
	write(t, filepath.Join(lib, "state.db"), "old")
	write(t, filepath.Join(lib, "raft", "raft-stable.bolt"), "old")
	write(t, filepath.Join(dst, "etc", "sandboxd", "tls", "node.crt"), "cert")
	_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst})
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if read(t, filepath.Join(lib, "state.db")) != "old" || read(t, filepath.Join(lib, "raft", "raft-stable.bolt")) != "old" {
		t.Fatal("the moved files were not put back")
	}
	if m, _ := filepath.Glob(filepath.Join(lib, "*.pre-restore-*")); len(m) != 0 {
		t.Fatalf("left aside: %v", m)
	}
	if !strings.Contains(out, "put back: "+filepath.Join(lib, "state.db")) {
		t.Errorf("output:\n%s", out)
	}
}

// A link already on the node inside the config directory is never written
// through; the config directory itself may be a link (another disk).
func TestRestoreNeverWritesThroughANodeLink(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive, tarEntry{name: "./etc/sandboxd/"}, tarEntry{name: "./etc/sandboxd/tls/node.crt", body: "x"})
	dst := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dst, "etc", "sandboxd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dst, "etc", "sandboxd", "tls")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "node.crt")); !os.IsNotExist(err) {
		t.Fatal("wrote through the link")
	}

	// The config directory as a link to another disk is followed.
	dst = t.TempDir()
	disk := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dst, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(disk, filepath.Join(dst, "etc", "sandboxd")); err != nil {
		t.Fatal(err)
	}
	if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if read(t, filepath.Join(disk, "tls", "node.crt")) != "x" {
		t.Fatal("the linked config directory was not followed")
	}
}

// Into the node itself: refused while sandboxd runs; with --start, sandboxd
// is started and waited on.
func TestRestoreIntoTheLiveNode(t *testing.T) {
	src := newNode(t, "SB_API_PORT=9999\n")
	makeDB(t, filepath.Join(src.lib, "state.db"), "x")
	archive := src.backup(t, BackupOptions{}).Output

	root := t.TempDir()
	h := &fakeHost{active: true}
	if _, _, err := restore(t, RestoreOptions{Input: archive, TargetRoot: root, Host: h, liveRoot: root}); err == nil || !strings.Contains(err.Error(), "sandboxd is running") {
		t.Fatalf("err = %v", err)
	}
	if exists(filepath.Join(root, "var")) {
		t.Fatal("restored under a running sandboxd")
	}
	// A restore elsewhere does not care whether sandboxd runs (a staging
	// directory on a live node).
	if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: t.TempDir(), Host: h, liveRoot: root}); err != nil {
		t.Fatalf("staging restore: %v\n%s", err, out)
	}

	h = &fakeHost{healthFails: 2}
	res, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: root, Host: h, liveRoot: root, Start: true, healthPoll: time.Millisecond})
	if err != nil {
		t.Fatalf("restore --start: %v\n%s", err, out)
	}
	if !h.called("start") || res.Version != "v-test" || h.healthURL != "http://127.0.0.1:9999/health" {
		t.Fatalf("calls %v, version %q, health %q", h.calls, res.Version, h.healthURL)
	}
	if strings.Contains(out, "then start sandboxd") || !strings.Contains(out, "sandboxd is up") {
		t.Errorf("output:\n%s", out)
	}

	h = &fakeHost{healthFails: -1}
	if _, _, err := restore(t, RestoreOptions{Input: archive, TargetRoot: root, Host: h, liveRoot: root, Start: true,
		HealthTimeout: 5 * time.Millisecond, healthPoll: time.Millisecond}); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("err = %v", err)
	}
	h = &fakeHost{startErr: errors.New("unit failed")}
	if _, _, err := restore(t, RestoreOptions{Input: archive, TargetRoot: root, Host: h, liveRoot: root, Start: true}); err == nil || !strings.Contains(err.Error(), "unit failed") {
		t.Fatalf("err = %v", err)
	}
	// The same archive twice in one second: the second set-aside gets its
	// own name.
	if m, _ := filepath.Glob(filepath.Join(root, "var", "lib", "sandboxd", "state.db.pre-restore-*")); len(m) < 2 {
		t.Fatalf("set-asides %v", m)
	}
}

func TestRestoreRefusals(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive, tarEntry{name: "./var/lib/sandboxd/state.db", body: "db"})
	for name, tc := range map[string]struct {
		o     RestoreOptions
		usage bool
		want  string
	}{
		"no input":     {o: RestoreOptions{Force: true}, usage: true, want: "--input is required"},
		"no force":     {o: RestoreOptions{Input: archive}, usage: true, want: "refusing to restore without --force"},
		"missing file": {o: RestoreOptions{Input: archive + ".none", Force: true}, want: "backup archive not found"},
		"a directory":  {o: RestoreOptions{Input: filepath.Dir(archive), Force: true}, want: "backup archive not found"},
	} {
		t.Run(name, func(t *testing.T) {
			tc.o.Host, tc.o.TargetRoot = &fakeHost{}, t.TempDir()
			_, err := Restore(context.Background(), tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrUsage) != tc.usage {
				t.Fatalf("err = %v, want %q (usage %v)", err, tc.want, tc.usage)
			}
		})
	}
}

func TestEntryName(t *testing.T) {
	for raw, want := range map[string]string{
		"./": "", ".": "", "./etc/sandboxd/": "etc/sandboxd", "etc//sandboxd/./x": "etc/sandboxd/x", "MANIFEST.txt": "MANIFEST.txt",
	} {
		if got, err := entryName(raw); err != nil || got != want {
			t.Errorf("entryName(%q) = %q %v, want %q", raw, got, err, want)
		}
	}
}
