package nodeops

import (
	"archive/tar"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// setRestoreHook sets testHookRestore for one test.
func setRestoreHook(t *testing.T, f func(stage, path string)) {
	t.Helper()
	testHookRestore = f
	t.Cleanup(func() { testHookRestore = nil })
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func chmod(t *testing.T, path string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, m); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, at string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, at); err != nil {
		t.Fatal(err)
	}
}

func rename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Error(err)
	}
}

// splitTarget writes a target's own sandboxd.env, in privilege mode split.
func splitTarget(t *testing.T, dst string) {
	t.Helper()
	write(t, filepath.Join(dst, "etc", "sandboxd", "sandboxd.env"), "SB_PRIVILEGE_MODE=split\n")
}

// In privilege mode split sandboxd's user owns /etc/sandboxd/tls. It can
// keep a real 0777 folder there, which a backup records, then put a link
// to /etc in its place. A restore must not set the archive's mode (or
// owner) on what the link points to: a link where the backup has a folder
// is refused, in both modes, as a link above an entry always was.
func TestRestoreRefusesALinkWhereTheBackupHasAFolder(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "split"}[split], func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive, tarEntry{name: "./etc/sandboxd/"}, tarEntry{name: "./etc/sandboxd/tls/", mode: 0o777})
			dst := t.TempDir()
			if split {
				splitTarget(t, dst)
			}
			etc := t.TempDir() // stands in for /etc
			chmod(t, etc, 0o755)
			symlink(t, etc, filepath.Join(dst, "etc", "sandboxd", "tls"))
			_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst, euid: func() int { return 0 },
				chown: func(p string, _, _ int) error {
					if strings.Contains(p, "tls") {
						t.Errorf("changed the owner of %s", p)
					}
					return nil
				}})
			if err == nil || !strings.Contains(err.Error(), "is a link where the backup has a folder") {
				t.Fatalf("err = %v\n%s", err, out)
			}
			if m := mode(t, etc); m != 0o755 {
				t.Fatalf("the folder the link points to is now %v", m)
			}
		})
	}
}

// A link that points at no folder is replaced by the folder, as it always
// was: nothing is changed through it.
func TestRestoreReplacesALinkToNoFolder(t *testing.T) {
	for name, target := range map[string]string{"dangling": "/nonexistent/x", "to a file": "file"} {
		t.Run(name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive, tarEntry{name: "./etc/sandboxd/tls/", mode: 0o700}, tarEntry{name: "./etc/sandboxd/tls/node.crt", body: "c"})
			dst := t.TempDir()
			sb := filepath.Join(dst, "etc", "sandboxd")
			if target == "file" {
				target = filepath.Join(sb, "file")
				write(t, target, "keep")
			}
			symlink(t, target, filepath.Join(sb, "tls"))
			if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
				t.Fatalf("restore: %v\n%s", err, out)
			}
			if fi, err := os.Lstat(filepath.Join(sb, "tls")); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
				t.Fatalf("tls = %v %v, want a 0700 folder", fi, err)
			}
			if read(t, filepath.Join(sb, "tls", "node.crt")) != "c" {
				t.Fatal("node.crt not restored")
			}
			if strings.HasSuffix(target, "file") && read(t, target) != "keep" {
				t.Fatal("wrote through the link")
			}
		})
	}
}

// Each entry is written through the folder the restore opened, so a
// folder above it swapped for a link afterwards sends nothing elsewhere.
// A look for links and then a write by path would follow it.
func TestRestoreWritesThroughTheFolderItOpened(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive, tarEntry{name: "./etc/sandboxd/tls/"}, tarEntry{name: "./etc/sandboxd/tls/node.crt", body: "cert"})
	dst := t.TempDir()
	splitTarget(t, dst)
	tls := filepath.Join(dst, "etc", "sandboxd", "tls")
	elsewhere := t.TempDir()
	setRestoreHook(t, func(stage, p string) {
		if stage == "write" && p == filepath.Join(tls, "node.crt") {
			rename(t, tls, tls+".moved")
			symlink(t, elsewhere, tls)
		}
	})
	if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "node.crt")); !os.IsNotExist(err) {
		t.Fatalf("wrote through the link: %v", err)
	}
	if read(t, filepath.Join(tls+".moved", "node.crt")) != "cert" {
		t.Fatal("the file is not in the folder the restore opened")
	}
}

// A file's mode, owner and time are set through the open file, so its
// temporary name swapped for a link before then changes nothing it
// points to.
func TestRestoreSetsAFilesTimeThroughTheFile(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive, tarEntry{name: "./etc/sandboxd/tls/node.crt", body: "cert", mode: 0o600})
	dst := t.TempDir()
	splitTarget(t, dst)
	outside := filepath.Join(t.TempDir(), "root-only")
	write(t, outside, "x")
	chmod(t, outside, 0o644)
	was := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(outside, was, was); err != nil {
		t.Fatal(err)
	}
	var tmp string
	setRestoreHook(t, func(stage, p string) {
		if stage == "temp" {
			tmp = p
			rename(t, p, p+".moved")
			symlink(t, outside, p)
		}
	})
	if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if tmp == "" {
		t.Fatal("the hook never ran")
	}
	fi, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(was) || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the link's target changed: mode %v, time %v", fi.Mode(), fi.ModTime())
	}
	if moved, err := os.Stat(tmp + ".moved"); err != nil || moved.Mode().Perm() != 0o600 || !moved.ModTime().Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("the file written: %v %v", moved, err)
	}
}

// A hard link's target is reached as every entry is, with no link
// followed: its folder swapped for a link makes the restore refuse, not
// link a file of root's into the backup's place.
func TestRestoreHardLinkFollowsNoLink(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "split"}[split], func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive,
				tarEntry{name: "./var/lib/sandboxd/raft/a", body: "a"},
				tarEntry{name: "./var/lib/sandboxd/raft/b", typ: tar.TypeLink, link: "./var/lib/sandboxd/raft/a"})
			dst := t.TempDir()
			if split {
				splitTarget(t, dst)
			}
			raft := filepath.Join(dst, "var", "lib", "sandboxd", "raft")
			elsewhere := t.TempDir()
			write(t, filepath.Join(elsewhere, "a"), "root-only")
			setRestoreHook(t, func(stage, p string) {
				if stage == "write" && p == filepath.Join(raft, "b") {
					rename(t, raft, raft+".moved")
					symlink(t, elsewhere, raft)
				}
			})
			_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst})
			if err == nil || !strings.Contains(err.Error(), "is a link") {
				t.Fatalf("err = %v\n%s", err, out)
			}
			if _, err := os.Lstat(filepath.Join(elsewhere, "b")); !os.IsNotExist(err) {
				t.Fatalf("linked through the link: %v", err)
			}
			if fi, err := os.Stat(filepath.Join(elsewhere, "a")); err != nil || fi.Sys().(*syscall.Stat_t).Nlink != 1 {
				t.Fatalf("root's file got another name: %v %v", fi, err)
			}
		})
	}
}

// In privilege mode split a hard link in sandboxd's user's folders is
// written as a copy: the root helper would leave a file with two names
// root's. Elsewhere, and in single, it stays a hard link.
func TestRestoreHardLinkInSplitIsACopy(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive,
		tarEntry{name: "./var/lib/sandboxd/raft/a", body: "a"},
		tarEntry{name: "./var/lib/sandboxd/raft/b", typ: tar.TypeLink, link: "./var/lib/sandboxd/raft/a", mode: 0o640},
		tarEntry{name: "./etc/sandboxd/x", body: "x"},
		tarEntry{name: "./etc/sandboxd/y", typ: tar.TypeLink, link: "./etc/sandboxd/x"})
	dst := t.TempDir()
	splitTarget(t, dst)
	if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	raft := filepath.Join(dst, "var", "lib", "sandboxd", "raft")
	a, _ := os.Stat(filepath.Join(raft, "a"))
	b, err := os.Stat(filepath.Join(raft, "b"))
	if err != nil || os.SameFile(a, b) || read(t, filepath.Join(raft, "b")) != "a" || b.Mode().Perm() != 0o600 {
		t.Fatalf("raft/b = %v %v, want a 0600 copy of raft/a", b, err)
	}
	x, _ := os.Stat(filepath.Join(dst, "etc", "sandboxd", "x"))
	y, _ := os.Stat(filepath.Join(dst, "etc", "sandboxd", "y"))
	if !os.SameFile(x, y) {
		t.Fatal("a hard link in root's config folder was not kept")
	}
}

// The wrapped key and the ring are written 0600, so nothing changes their
// mode by name after the archive is written: a link put in their place
// would carry that change to whatever it points to.
func TestRestoreSetsTheKeyModesAsItWritesThem(t *testing.T) {
	for k, env := range map[string]string{wrappedName: "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n", ringName: ""} {
		t.Run(k, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive,
				tarEntry{name: "./etc/sandboxd/sandboxd.env", body: env},
				tarEntry{name: "./var/lib/sandboxd/" + k, body: "k", mode: 0o644})
			dst := t.TempDir()
			outside := filepath.Join(t.TempDir(), "root-only")
			write(t, outside, "x")
			chmod(t, outside, 0o644)
			setRestoreHook(t, func(stage, lib string) {
				if stage != "keys" {
					return
				}
				if m := mode(t, filepath.Join(lib, k)); m != 0o600 {
					t.Errorf("%s written %v, want 0600", k, m)
				}
				if err := os.Remove(filepath.Join(lib, k)); err != nil {
					t.Error(err)
				}
				symlink(t, outside, filepath.Join(lib, k))
			})
			if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
				t.Fatalf("restore: %v\n%s", err, out)
			}
			if m := mode(t, outside); m != 0o644 {
				t.Fatalf("the link's target is now %v", m)
			}
		})
	}
}

// In privilege mode split, on this node or on the backed-up one, what
// lands in sandboxd's user's folders (the data folder, the certificate
// folders) gets no group or other bits, whatever the archive recorded
// (that user chose those modes), and stays root's for `aerolvm-rootd
// agent-folders` to give to this node's sandboxd user at its next start.
// Root's own files and folders in the config folder keep the archive's
// mode and owner. In single nothing changes.
func TestRestoreInSplitCapsModesAndLeavesOwnersToTheHelper(t *testing.T) {
	const agentUID = 4242
	entries := func(archiveSplit bool) []tarEntry {
		env := "SB_CLUSTER_TLS_DIR=/etc/sandboxd/tls\nSB_CLUSTER_CA_DIR=/etc/sandboxd/cluster-ca\n"
		if archiveSplit {
			env += "SB_PRIVILEGE_MODE=split\n"
		}
		return []tarEntry{
			{name: "./etc/sandboxd/"},
			{name: "./etc/sandboxd/sandboxd.env", body: env, mode: 0o600},
			{name: "./etc/sandboxd/tls/", mode: 0o777, uid: agentUID},
			{name: "./etc/sandboxd/tls/node.key", body: "k", mode: 0o666, uid: agentUID},
			{name: "./etc/sandboxd/tls/current.crt", typ: tar.TypeSymlink, link: "node.crt", uid: agentUID},
			{name: "./etc/sandboxd/cluster-ca/", mode: 0o755, uid: agentUID},
			{name: "./etc/sandboxd/secrets/", mode: 0o750},
			{name: "./etc/sandboxd/secrets/token", body: "t", mode: 0o640},
			{name: "./var/lib/sandboxd/state.db", body: "db", mode: 0o644, uid: agentUID},
			{name: "./var/lib/sandboxd/raft/", mode: 0o755, uid: agentUID},
			{name: "./var/lib/sandboxd/raft/snapshots/1/meta.json", body: "{}", mode: 0o644, uid: agentUID},
		}
	}
	type want struct {
		modes map[string]os.FileMode
		owned []string // given the archive's owner
	}
	splitWant := want{
		modes: map[string]os.FileMode{
			"etc/sandboxd/tls": 0o700, "etc/sandboxd/tls/node.key": 0o600, "etc/sandboxd/cluster-ca": 0o700,
			"etc/sandboxd/secrets": 0o750, "etc/sandboxd/secrets/token": 0o640, "etc/sandboxd/sandboxd.env": 0o600,
			"var/lib/sandboxd/state.db": 0o600, "var/lib/sandboxd/raft": 0o700,
			"var/lib/sandboxd/raft/snapshots": 0o700, "var/lib/sandboxd/raft/snapshots/1/meta.json": 0o600,
		},
		owned: []string{"etc/sandboxd", "etc/sandboxd/sandboxd.env", "etc/sandboxd/secrets", "etc/sandboxd/secrets/token"},
	}
	for name, tc := range map[string]struct {
		nodeSplit, archiveSplit bool
		want                    want
	}{
		"split node":    {nodeSplit: true, want: splitWant},
		"split archive": {archiveSplit: true, want: splitWant},
		"single": {want: want{
			modes: map[string]os.FileMode{
				"etc/sandboxd/tls": 0o777, "etc/sandboxd/tls/node.key": 0o666, "etc/sandboxd/cluster-ca": 0o755,
				"etc/sandboxd/secrets": 0o750, "etc/sandboxd/secrets/token": 0o640,
				"var/lib/sandboxd/state.db": 0o644, "var/lib/sandboxd/raft": 0o755,
				"var/lib/sandboxd/raft/snapshots": 0o755, "var/lib/sandboxd/raft/snapshots/1/meta.json": 0o644,
			},
			owned: []string{"etc/sandboxd", "etc/sandboxd/sandboxd.env", "etc/sandboxd/tls", "etc/sandboxd/tls/node.key",
				"etc/sandboxd/tls/current.crt", "etc/sandboxd/cluster-ca", "etc/sandboxd/secrets", "etc/sandboxd/secrets/token",
				"var/lib/sandboxd/state.db", "var/lib/sandboxd/raft", "var/lib/sandboxd/raft/snapshots/1/meta.json"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive, entries(tc.archiveSplit)...)
			dst := t.TempDir()
			if tc.nodeSplit {
				splitTarget(t, dst)
			}
			var owned []string
			_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst, euid: func() int { return 0 },
				chown: func(p string, _, _ int) error {
					rel, _ := filepath.Rel(dst, p)
					owned = append(owned, filepath.ToSlash(rel))
					return nil
				}})
			if err != nil {
				t.Fatalf("restore: %v\n%s", err, out)
			}
			for rel, m := range tc.want.modes {
				if got := mode(t, filepath.Join(dst, filepath.FromSlash(rel))); got != m {
					t.Errorf("%s mode %v, want %v", rel, got, m)
				}
			}
			slices.Sort(owned)
			wantOwned := slices.Clone(tc.want.owned)
			slices.Sort(wantOwned)
			if !slices.Equal(owned, wantOwned) {
				t.Errorf("given the archive's owner:\n%v\nwant\n%v", owned, wantOwned)
			}
		})
	}
}

// The certificate folders are the agent's where the settings put them in
// the config folder; elsewhere the restore writes nothing of theirs.
func TestAgentTrees(t *testing.T) {
	got := agentTrees(
		Node{ClusterTLSDir: "/etc/sandboxd/certs/node", ClusterCADir: "/etc/sandboxd/cluster-ca"},
		Node{ClusterTLSDir: "relative", ClusterCADir: "/etc/sandboxd/../ca"},
		Node{ClusterTLSDir: "/srv/tls", ClusterCADir: "/etc/sandboxd"},
	)
	want := []string{archiveLib, archiveConfig + "/tls", archiveConfig + "/certs/node", archiveConfig + "/cluster-ca"}
	if !slices.Equal(got, want) {
		t.Fatalf("agentTrees = %v, want %v", got, want)
	}
	r := &restorer{split: true, agent: got}
	for name, owned := range map[string]bool{
		archiveConfig + "/tls/x": true, archiveConfig + "/tlsx": false, archiveConfig + "/sandboxd.env": false,
		archiveDB: true, archiveConfig: false,
	} {
		if r.agentOwned(name) != owned {
			t.Errorf("agentOwned(%s) = %v", name, !owned)
		}
	}
	r.split = false
	if r.agentOwned(archiveDB) {
		t.Error("single: agentOwned")
	}
}

// The archive's env files are read for its privilege mode; one no env
// file could be is refused before anything changes.
func TestRestoreRefusesAnArchiveEnvFileItCannotRead(t *testing.T) {
	for name, body := range map[string]string{
		"too large":     strings.Repeat("x", maxEnvBytes+1),
		"one long line": strings.Repeat("x", maxEnvBytes),
	} {
		t.Run(name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive, tarEntry{name: "./etc/sandboxd/cluster.env", body: body}, tarEntry{name: "./var/lib/sandboxd/state.db", body: "new"})
			dst := t.TempDir()
			write(t, filepath.Join(dst, "var", "lib", "sandboxd", "state.db"), "keep")
			if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err == nil || !strings.Contains(err.Error(), "cluster.env") {
				t.Fatalf("err = %v\n%s", err, out)
			}
			if read(t, filepath.Join(dst, "var", "lib", "sandboxd", "state.db")) != "keep" {
				t.Fatal("the node changed")
			}
		})
	}
}

// A link or a hard link where the node has a folder is refused, as a file
// there is.
func TestRestoreRefusesALinkOverAFolder(t *testing.T) {
	for _, e := range []tarEntry{
		{name: "./etc/sandboxd/tls", typ: tar.TypeSymlink, link: "x"},
		{name: "./etc/sandboxd/tls", typ: tar.TypeLink, link: "./etc/sandboxd/x"},
	} {
		archive := filepath.Join(t.TempDir(), "a.tgz")
		writeTar(t, archive, tarEntry{name: "./etc/sandboxd/x", body: "x"}, e)
		dst := t.TempDir()
		write(t, filepath.Join(dst, "etc", "sandboxd", "tls", "node.crt"), "c")
		if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Fatalf("%c: err = %v\n%s", e.typ, err, out)
		}
	}
}

// The config folder's own entry is handled as it always was: root's in
// both modes, a link to another disk followed, a file in its place
// replaced.
func TestRestoreReplacesAFileWhereTheConfigFolderGoes(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive, tarEntry{name: "./etc/sandboxd/", mode: 0o750}, tarEntry{name: "./etc/sandboxd/sandboxd.env", body: "SB_NODE_ID=a\n"})
	dst := t.TempDir()
	write(t, filepath.Join(dst, "etc", "sandboxd"), "a file")
	if _, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst}); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if m := mode(t, filepath.Join(dst, "etc", "sandboxd")); m != 0o750 {
		t.Fatalf("etc/sandboxd mode %v", m)
	}
	if read(t, filepath.Join(dst, "etc", "sandboxd", "sandboxd.env")) != "SB_NODE_ID=a\n" {
		t.Fatal("not restored")
	}
}

// A file where the restore needs a folder on the way is refused, as
// mkdir -p refused it, and what was moved aside comes back.
func TestRestoreRefusesAFileOnTheWay(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "a.tgz")
	writeTar(t, archive, tarEntry{name: "./var/lib/sandboxd/state.db", body: "new"}, tarEntry{name: "./etc/sandboxd/tls/node.crt", body: "c"})
	dst := t.TempDir()
	write(t, filepath.Join(dst, "var", "lib", "sandboxd", "state.db"), "old")
	write(t, filepath.Join(dst, "etc", "sandboxd", "tls"), "a file")
	_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if read(t, filepath.Join(dst, "var", "lib", "sandboxd", "state.db")) != "old" {
		t.Fatal("the moved database was not put back")
	}
}

// A folder's mode is set through the handle the restore opened on it,
// never by its path. In privilege mode split sandboxd's user owns these
// folders and can put a link in a folder's place between its open and its
// chmod: the mode must land on the folder that was opened, and the folder
// the link points to (a stand-in for /etc) keeps its own. A chmod by path
// would follow the link.
func TestRestoreSetsAFoldersModeThroughTheFolderItOpened(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "split"}[split], func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "a.tgz")
			writeTar(t, archive, tarEntry{name: "./etc/sandboxd/"}, tarEntry{name: "./etc/sandboxd/tls/", mode: 0o750})
			dst := t.TempDir()
			if split {
				splitTarget(t, dst)
			}
			tls := filepath.Join(dst, "etc", "sandboxd", "tls")
			if err := os.MkdirAll(tls, 0o700); err != nil {
				t.Fatal(err)
			}
			chmod(t, tls, 0o700)
			etc := t.TempDir()
			chmod(t, etc, 0o755)
			swapped := false
			setRestoreHook(t, func(stage, p string) {
				if stage != "folder" || p != tls || swapped {
					return
				}
				swapped = true
				rename(t, tls, tls+".opened")
				symlink(t, etc, tls)
			})
			_, out, err := restore(t, RestoreOptions{Input: archive, TargetRoot: dst, euid: func() int { return 0 },
				chown: func(string, int, int) error { return nil }})
			if err != nil {
				t.Fatalf("restore: %v\n%s", err, out)
			}
			if !swapped {
				t.Fatal("the restore never reached the folder's chmod")
			}
			if m := mode(t, etc); m != 0o755 {
				t.Fatalf("the folder the link points to is now %v, want 0755", m)
			}
			want := os.FileMode(0o750)
			if split {
				want = 0o700 // sandboxd's user's folder: no group or other bits
			}
			if m := mode(t, tls+".opened"); m != want {
				t.Fatalf("the folder the restore opened is %v, want %v", m, want)
			}
		})
	}
}
