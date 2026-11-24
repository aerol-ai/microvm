package nodeops

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/raftlogdir"
)

// In privilege mode split sandboxd's user owns the data folder and the
// certificate folders, and could swap any name in them for a link. The
// backup, run as root, must never read through such a link: a tree root, a
// file, a folder inside a tree, or the database.

const outsideSecret = "root's secret, outside sandboxd's folders"

// splitNode is a split node whose agent left links to a root-only folder
// where the backup reads.
func splitNode(t *testing.T) (node, string) {
	t.Helper()
	n := newNode(t, "SB_PRIVILEGE_MODE=split\nSB_NODE_ID=node-a\n")
	outside := filepath.Join(n.dir, "root-only")
	write(t, filepath.Join(outside, "secret"), outsideSecret)
	write(t, filepath.Join(outside, "tree", "secret"), outsideSecret)
	makeDB(t, filepath.Join(n.lib, "state.db"), "a")
	link := func(target, at string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
	}
	// The Raft folder itself, a file and a folder inside the certificates,
	// and the key file.
	link(filepath.Join(outside, "tree"), filepath.Join(n.lib, "raft"))
	write(t, filepath.Join(n.etc, "tls", "node.crt"), "cert")
	link(filepath.Join(outside, "secret"), filepath.Join(n.etc, "tls", "node.key"))
	link(filepath.Join(outside, "tree"), filepath.Join(n.etc, "cluster-ca", "old"))
	link(filepath.Join(outside, "secret"), filepath.Join(n.lib, keyName))
	return n, outside
}

func TestBackupInSplitReadsNothingThroughALink(t *testing.T) {
	n, outside := splitNode(t)
	res := n.backup(t, BackupOptions{})
	files, hdrs := readArchive(t, res.Output)
	for name, body := range files {
		if strings.Contains(body, outsideSecret) {
			t.Errorf("the archive's %s holds what a link names: %q", name, body)
		}
	}
	// Each link is kept as a link, as single keeps a link inside a tree.
	for _, c := range []struct{ name, target string }{
		{archiveRaft, filepath.Join(outside, "tree")},
		{archiveConfig + "/tls/node.key", filepath.Join(outside, "secret")},
		{archiveConfig + "/cluster-ca/old", filepath.Join(outside, "tree")},
		{archiveLib + "/" + keyName, filepath.Join(outside, "secret")},
	} {
		h := hdrs[c.name]
		if h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != c.target {
			t.Errorf("%s: %+v, want a link to %s", c.name, h, c.target)
		}
	}
	if files[archiveConfig+"/tls/node.crt"] != "cert" || files[archiveDB] == "" {
		t.Errorf("the archive lost the node's own files: %v", keys(files))
	}
}

// The database is copied with SQLite's nofollow: a link in its place is
// refused, where single copies what it names.
func TestBackupInSplitRefusesALinkedDatabase(t *testing.T) {
	for _, split := range []bool{true, false} {
		env := ""
		if split {
			env = "SB_PRIVILEGE_MODE=split\n"
		}
		n := newNode(t, env)
		real := filepath.Join(n.dir, "elsewhere", "other.db")
		makeDB(t, real, "x")
		if err := os.MkdirAll(n.lib, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(n.lib, "state.db")); err != nil {
			t.Fatal(err)
		}
		_, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: filepath.Join(n.dir, "out", "b.tgz"), Host: &fakeHost{}})
		if split && err == nil {
			t.Error("split copied the database a link names")
		}
		if !split && err != nil {
			t.Errorf("single refused its linked database: %v", err)
		}
	}
}

// With no link anywhere, split writes the archive single writes.
func TestBackupInSplitMatchesSingleWithoutLinks(t *testing.T) {
	archives := map[bool]map[string]string{}
	for _, split := range []bool{false, true} {
		env := "SB_NODE_ID=node-a\n"
		if split {
			env += "SB_PRIVILEGE_MODE=split\n"
		}
		n := newNode(t, env)
		makeDB(t, filepath.Join(n.lib, "state.db"), "a", "b")
		write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
		write(t, filepath.Join(n.lib, "raft", "snapshots", "1-2-3", "state.bin"), "snap")
		write(t, filepath.Join(n.lib, keyName), "plain-key")
		write(t, filepath.Join(n.etc, "tls", "node.crt"), "cert")
		res := n.backup(t, BackupOptions{})
		files, _ := readArchive(t, res.Output)
		// The env file and the manifest name this node's own temp paths.
		delete(files, manifestName)
		delete(files, archiveConfig+"/sandboxd.env")
		delete(files, archiveDB)
		archives[split] = files
	}
	single, split := archives[false], archives[true]
	if len(single) == 0 || len(single) != len(split) {
		t.Fatalf("single wrote %v, split %v", keys(single), keys(split))
	}
	for name, body := range single {
		if split[name] != body {
			t.Errorf("%s: split %q, single %q", name, split[name], body)
		}
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A Raft log on a disk of its own is read in split through the folder that
// holds it, with the location record still skipped; a link the agent left
// inside it stays a link.
func TestBackupInSplitTakesALogOnItsOwnDisk(t *testing.T) {
	own := filepath.Join(t.TempDir(), "disk", "raft-wal")
	n := newNode(t, "SB_PRIVILEGE_MODE=split\nSB_RAFT_WAL_DIR="+own+"\n")
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
	write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), own+"\n")
	write(t, filepath.Join(own, "wal-meta.db"), "meta")
	outside := filepath.Join(n.dir, "root-only")
	write(t, filepath.Join(outside, "secret"), outsideSecret)
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(own, "old.wal")); err != nil {
		t.Fatal(err)
	}
	res := n.backup(t, BackupOptions{})
	files, hdrs := readArchive(t, res.Output)
	if files[archiveRaft+"/raft-stable.bolt"] != "stable" || files[archiveRaft+"/raft-wal/wal-meta.db"] != "meta" {
		t.Fatalf("the log or the Raft folder is missing: %v", keys(files))
	}
	if _, ok := files[archiveRaft+"/"+raftlogdir.LocationFile]; ok {
		t.Error("the record naming the log disk was archived")
	}
	if h := hdrs[archiveRaft+"/raft-wal/old.wal"]; h == nil || h.Typeflag != tar.TypeSymlink {
		t.Errorf("the agent's link in the log folder: %+v, want a link", h)
	}
	for name, body := range files {
		if strings.Contains(body, outsideSecret) {
			t.Errorf("%s holds what a link names", name)
		}
	}
}

// In split the Raft log record is written by sandboxd's user, in its own
// folder. A record naming a root-only folder, with no SB_RAFT_WAL_DIR in
// the env files, must not make root archive that folder (a restore would
// put it in the agent's folder): the backup refuses, and writes nothing.
func TestBackupInSplitTakesTheLogOnlyFromTheEnv(t *testing.T) {
	n := newNode(t, "SB_PRIVILEGE_MODE=split\nSB_NODE_ID=node-a\n")
	makeDB(t, filepath.Join(n.lib, "state.db"), "a")
	outside := filepath.Join(n.dir, "root-only")
	write(t, filepath.Join(outside, "shadow"), outsideSecret)
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
	write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), outside+"\n")
	out := filepath.Join(n.dir, "out", "backup.tgz")
	_, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: out, Host: &fakeHost{}})
	if err == nil || !strings.Contains(err.Error(), "SB_RAFT_WAL_DIR") {
		t.Fatalf("backup with the agent's record naming %s: %v, want a refusal naming SB_RAFT_WAL_DIR", outside, err)
	}
	if exists(out) {
		t.Fatal("a refused backup left an archive")
	}
	// Single follows the record, as before: there, sandboxd is root.
	single := newNode(t, "SB_NODE_ID=node-a\n")
	makeDB(t, filepath.Join(single.lib, "state.db"), "a")
	write(t, filepath.Join(outside, "wal-meta.db"), "meta")
	write(t, filepath.Join(single.lib, "raft", "raft-stable.bolt"), "stable")
	write(t, filepath.Join(single.lib, "raft", raftlogdir.LocationFile), outside+"\n")
	res := single.backup(t, BackupOptions{})
	if files, _ := readArchive(t, res.Output); files[archiveRaft+"/raft-wal/wal-meta.db"] != "meta" {
		t.Fatal("single no longer takes the recorded log")
	}
}

// A file swapped for a link between the backup's look at it and its read
// must not land in the archive under the first file's name: inside the
// config folder (os.Root follows a link that stays in it; the open file is
// then not the one looked at) or out of it (os.Root refuses the escape).
func TestBackupInSplitRefusesASwapBetweenLookAndRead(t *testing.T) {
	const otherSecret = "another file in the config folder"
	for _, c := range []struct {
		name   string
		target func(n node, outside string) string
	}{
		// Relative: os.Root follows a link that stays inside (it refuses an
		// absolute one), so only the same-file check stops this one.
		{"to a file in the folder", func(_ node, _ string) string { return filepath.Join("..", "other.key") }},
		{"to a file outside it", func(_ node, outside string) string { return filepath.Join(outside, "secret") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newNode(t, "SB_PRIVILEGE_MODE=split\nSB_NODE_ID=node-a\n")
			makeDB(t, filepath.Join(n.lib, "state.db"), "a")
			outside := filepath.Join(n.dir, "root-only")
			write(t, filepath.Join(outside, "secret"), outsideSecret)
			write(t, filepath.Join(n.etc, "other.key"), otherSecret)
			cert := filepath.Join(n.etc, "tls", "node.crt")
			write(t, cert, "cert")
			swapped := false
			testHookBeforeOpen = func(name string) {
				if name != archiveConfig+"/tls/node.crt" || swapped {
					return
				}
				swapped = true
				if err := os.Remove(cert); err != nil {
					t.Error(err)
				}
				if err := os.Symlink(c.target(n, outside), cert); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { testHookBeforeOpen = nil })
			out := filepath.Join(n.dir, "out", "backup.tgz")
			_, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: out, Host: &fakeHost{}})
			if !swapped {
				t.Fatal("the hook never ran: the test no longer reaches the read")
			}
			if err == nil {
				files, _ := readArchive(t, out)
				body := files[archiveConfig+"/tls/node.crt"]
				t.Fatalf("the backup read the swapped file into node.crt (%q); want a refusal", body)
			}
		})
	}
}

// A folder swapped for a link after the walk listed it, and before the walk
// went into it, must not lead the walk out of sandboxd's folders: the walk
// goes through an os.Root, which refuses the escape. (A file's open is
// checked against its look as well, but a folder is read, not opened.)
func TestBackupInSplitRefusesAFolderSwappedDuringTheWalk(t *testing.T) {
	n := newNode(t, "SB_PRIVILEGE_MODE=split\nSB_NODE_ID=node-a\n")
	makeDB(t, filepath.Join(n.lib, "state.db"), "a")
	outside := filepath.Join(n.dir, "root-only")
	write(t, filepath.Join(outside, "secret"), outsideSecret)
	raft := filepath.Join(n.lib, "raft")
	write(t, filepath.Join(raft, "a-first"), "listed before snapshots")
	write(t, filepath.Join(raft, "snapshots", "1-2-3", "state.bin"), "snap")
	swapped := false
	testHookBeforeOpen = func(name string) {
		if name != archiveRaft+"/a-first" || swapped {
			return
		}
		swapped = true
		snaps := filepath.Join(raft, "snapshots")
		if err := os.RemoveAll(snaps); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(outside, snaps); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookBeforeOpen = nil })
	out := filepath.Join(n.dir, "out", "backup.tgz")
	_, err := Backup(context.Background(), BackupOptions{ConfigDir: n.etc, Output: out, Host: &fakeHost{}})
	if !swapped {
		t.Fatal("the hook never ran: the test no longer reaches the walk")
	}
	if err != nil {
		return
	}
	files, _ := readArchive(t, out)
	for name, body := range files {
		if strings.Contains(body, outsideSecret) {
			t.Errorf("the walk followed the swapped folder out: %s", name)
		}
	}
}
