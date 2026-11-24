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
