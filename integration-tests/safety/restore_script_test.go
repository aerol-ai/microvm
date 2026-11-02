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

// A restored node must come back with the archive's server-key files and
// none of the node it replaces: sandboxd refuses wrapped custody beside a
// plaintext key or ring, and a fresh install's own key beside a restored
// ring or env key is the wrong key. What goes is moved aside, not deleted.
// A file-custody backup carries its plaintext key file, so a fresh machine
// can open the restored data.
func TestRestoreBringsTheArchivesKeySet(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	scripts, err := filepath.Abs(filepath.Join("..", "..", "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	const (
		key     = "credential_encryption.key"
		ring    = "credential_encryption.key.ring"
		wrapped = "credential_encryption.key.wrapped"
	)
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
		"a legacy archive with no key restored in place": {
			dstKeys: map[string]string{key: "own-key"},
			want:    map[string]string{key: "own-key"}, warn: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			write(filepath.Join(src, "state.db"), "restored-db")
			write(filepath.Join(src, "etc", "sandboxd.env"), "SB_NODE_ID=node-a\n"+tc.srcEnv)
			for f, body := range tc.srcKeys {
				write(filepath.Join(src, "keys", f), body)
			}
			archive := filepath.Join(t.TempDir(), "backup.tgz")
			if out, err := exec.Command("bash", filepath.Join(scripts, "sandboxd-backup.sh"),
				"--state-db", filepath.Join(src, "state.db"), "--raft-dir", filepath.Join(src, "none"),
				"--config-dir", filepath.Join(src, "etc"), "--wrapped-key", filepath.Join(src, "keys", wrapped),
				"--key-ring", filepath.Join(src, "keys", ring), "--key-file", filepath.Join(src, "keys", key),
				"--output", archive).CombinedOutput(); err != nil {
				t.Fatalf("backup: %v\n%s", err, out)
			}
			if name == "a legacy archive with no key restored in place" {
				// Made before backups carried the key file: strip it.
				files := readArchive(t, archive)
				if _, ok := files["var/lib/sandboxd/"+key]; ok {
					t.Fatal("no key file was given, yet the archive has one")
				}
			}
			dst := t.TempDir()
			lib := filepath.Join(dst, "var", "lib", "sandboxd")
			write(filepath.Join(lib, "state.db"), "fresh-db")
			for f, body := range tc.dstKeys {
				write(filepath.Join(lib, f), body)
			}
			out, err := exec.Command("bash", filepath.Join(scripts, "sandboxd-restore.sh"), "--input", archive, "--target-root", dst, "--force").CombinedOutput()
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
			if got := strings.Contains(string(out), "WARNING: the archive carries no server key"); got != tc.warn {
				t.Errorf("warning shown = %v, want %v\n%s", got, tc.warn, out)
			}
		})
	}
}
