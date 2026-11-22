package rootd

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The ownership move (agentfolders.go, M1 PR 10). A test cannot make
// root's files without root, so these move the test user's own files
// (movedFromUID) to the test user: the counts say what the walk chose.
// agentfolders_linux_test.go moves root's files for real, as root.

func TestAgentFoldersFromEnv(t *testing.T) {
	lookupUserName = func(name string) (*user.User, error) {
		if name == "sandboxd" {
			return &user.User{Uid: "65531", Gid: "65530", Username: name}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	lookupUserID = func(id string) (*user.User, error) {
		if id == "65531" {
			return &user.User{Uid: "65531", Gid: "65530"}, nil
		}
		return nil, user.UnknownUserIdError(0)
	}
	t.Cleanup(func() { lookupUserName, lookupUserID = user.Lookup, user.LookupId })

	for _, tc := range []struct {
		name     string
		env      map[string]string
		who      string
		want     []string
		uid, gid uint32
		err      string
	}{
		{name: "sandboxd's defaults", who: "sandboxd", want: []string{"/etc/sandboxd/cluster-ca", "/run/sandboxd", "/var/lib/sandboxd"}, uid: 65531, gid: 65530},
		{name: "a uid with a name", who: "65531", want: []string{"/etc/sandboxd/cluster-ca", "/run/sandboxd", "/var/lib/sandboxd"}, uid: 65531, gid: 65530},
		{name: "a uid with no name: its own group", who: "70000", want: []string{"/etc/sandboxd/cluster-ca", "/run/sandboxd", "/var/lib/sandboxd"}, uid: 70000, gid: 70000},
		{name: "cluster files and a Raft disk", who: "sandboxd", env: map[string]string{
			"SB_CLUSTER_TLS_DIR": "/etc/sandboxd/tls", "SB_CLUSTER_CA_DIR": "/etc/sandboxd/cluster-ca/",
			"SB_RAFT_DATA_DIR": "/var/lib/sandboxd/raft", "SB_RAFT_WAL_DIR": "/srv/raft-wal",
		}, want: []string{"/etc/sandboxd/cluster-ca", "/etc/sandboxd/tls", "/run/sandboxd", "/srv/raft-wal", "/var/lib/sandboxd"}, uid: 65531, gid: 65530},
		{name: "moved folders", who: "sandboxd", env: map[string]string{
			"SB_DB_PATH": "/data/sb/state.db", "SB_MOUNTS_ROOT": "/data/mounts", "SB_CONTAINERD_RUN_DIR": "/data/sb/ctr",
			"SB_MOUNTS_CRED_DIR": "/run/sb",
			"SB_CLUSTER_CA_DIR":  "/data/ca",
		}, want: []string{"/data/ca", "/data/mounts", "/data/sb", "/run/sb"}, uid: 65531, gid: 65530},
		{name: "the data folder would be /", who: "sandboxd", env: map[string]string{"SB_DB_PATH": "/state.db"}, err: "holds more than sandboxd's files"},
		{name: "a system folder", who: "sandboxd", env: map[string]string{"SB_RAFT_WAL_DIR": "/var/lib"}, err: "holds more than"},
		{name: "the node's settings", who: "sandboxd", env: map[string]string{"SB_CLUSTER_TLS_DIR": "/etc/sandboxd"}, err: "holds more than"},
		{name: "the helper's state", who: "sandboxd", env: map[string]string{"SB_CLUSTER_CA_DIR": "/var/lib/aerolvm-rootd/ca"}, err: "root helper's"},
		{name: "above the helper's", who: "sandboxd", env: map[string]string{"SB_RAFT_WAL_DIR": "/run/aerolvm-rootd/.."}, err: "holds more than"},
		{name: "the upgrader's", who: "sandboxd", env: map[string]string{"SB_RAFT_WAL_DIR": "/var/lib/aerolvm-upgrade"}, err: "root helper's"},
		{name: "a relative path", who: "sandboxd", env: map[string]string{"SB_MOUNTS_ROOT": "mounts"}, err: "want an absolute path"},
		{name: "root", who: "0", err: "must not be root"},
		{name: "a uid past MaxInt32", who: "2147483648", err: "is past 2147483647"},
		{name: "no user", who: " ", err: "name the agent's user"},
		{name: "an unknown user", who: "nobody-here", err: "user nobody-here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := AgentFoldersFromEnv(func(k string) string { return tc.env[k] }, tc.who)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(f.Dirs, tc.want) || f.UID != tc.uid || f.GID != tc.gid {
				t.Fatalf("got %v %d:%d, want %v %d:%d", f.Dirs, f.UID, f.GID, tc.want, tc.uid, tc.gid)
			}
		})
	}
}

// A cluster server keeps its CA store where sandboxd's settings default it,
// /etc/sandboxd/cluster-ca, when they leave SB_CLUSTER_CA_DIR unset, as
// nodejoin does: `sandboxd init` writes ca.key there as root, and the
// agent signs joins and renewals with it, so the move must give it over
// (M1 PR 10 review).
func TestAgentFoldersIncludeTheDefaultCAStore(t *testing.T) {
	env := map[string]string{"SB_ENABLE_CLUSTER": "true", "SB_CLUSTER_TLS_DIR": "/etc/sandboxd/tls"}
	f, err := AgentFoldersFromEnv(func(k string) string { return env[k] }, "65531")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.Dirs, "/etc/sandboxd/cluster-ca") || !slices.Contains(f.Dirs, "/etc/sandboxd/tls") {
		t.Fatalf("folders moved: %v", f.Dirs)
	}
}

func TestOutermost(t *testing.T) {
	got := outermost([]string{"/a/b", "/a", "/ab", "/a/b/c", "/a", "/c"})
	if want := []string{"/a", "/ab", "/c"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// selfMove points the walk at the test user's own files, given to the test
// user: every chown succeeds without root.
func selfMove(t *testing.T) AgentFolders {
	t.Helper()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	oldUID, oldGID := movedFromUID, movedFromGID
	movedFromUID, movedFromGID = uid, gid
	t.Cleanup(func() { movedFromUID, movedFromGID = oldUID, oldGID })
	return AgentFolders{UID: uid, GID: gid}
}

// realTemp is a temp folder reached without a link (macOS: /var is one).
func realTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGiveToAgent(t *testing.T) {
	f := selfMove(t)
	base := realTemp(t)
	data := filepath.Join(base, "data")
	write(t, filepath.Join(data, "state.db"), "db")
	write(t, filepath.Join(data, "raft", "snapshots", "1", "meta.json"), "{}")
	write(t, filepath.Join(data, "containerd", "sb-1", "hosts"), "127.0.0.1")
	// A link out of the folder is never followed.
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(outside, "a"), "a")
	write(t, filepath.Join(outside, "b"), "b")
	if err := os.Symlink(outside, filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	// A file with a second name elsewhere is left as it is.
	write(t, filepath.Join(outside, "shared"), "x")
	if err := os.Link(filepath.Join(outside, "shared"), filepath.Join(data, "shared")); err != nil {
		t.Fatal(err)
	}
	f.Dirs = []string{data, filepath.Join(base, "missing")}
	res, err := GiveToAgent(f)
	if err != nil {
		t.Fatal(err)
	}
	// data, state.db, raft, snapshots, 1, meta.json, containerd, sb-1,
	// hosts: 9; the link and the shared file are looked at, not moved.
	if res.Changed != 9 || res.Walked != 11 || res.SkippedLinks != 1 {
		t.Fatalf("result %+v, want 9 changed of 11 walked and 1 skipped link", res)
	}
	if !slices.Equal(res.Missing, []string{filepath.Join(base, "missing")}) {
		t.Fatalf("missing %v", res.Missing)
	}

	// Run again: the same walk (a test cannot tell its own files from
	// moved ones), never an error.
	if _, err := GiveToAgent(f); err != nil {
		t.Fatal(err)
	}
}

func TestGiveToAgentLeavesOthersFiles(t *testing.T) {
	f := selfMove(t)
	// The walk moves files of movedFromUID only: pretend root is a uid
	// that owns nothing here.
	movedFromUID = f.UID + 1
	data := filepath.Join(realTemp(t), "data")
	write(t, filepath.Join(data, "x"), "x")
	f.Dirs = []string{data}
	res, err := GiveToAgent(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != 0 || res.Walked != 2 {
		t.Fatalf("result %+v, want nothing changed", res)
	}
}

func TestGiveToAgentRefuses(t *testing.T) {
	f := selfMove(t)
	base := realTemp(t)

	// A folder above that anyone can write: the agent could have renamed
	// another folder into its place.
	open := filepath.Join(base, "open")
	write(t, filepath.Join(open, "data", "x"), "x")
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	f.Dirs = []string{filepath.Join(open, "data")}
	if _, err := GiveToAgent(f); err == nil || !strings.Contains(err.Error(), "written by others") {
		t.Fatalf("err = %v, want a folder written by others", err)
	}

	// A link on the way.
	real := filepath.Join(base, "real")
	write(t, filepath.Join(real, "x"), "x")
	if err := os.Symlink(real, filepath.Join(base, "via")); err != nil {
		t.Fatal(err)
	}
	f.Dirs = []string{filepath.Join(base, "via")}
	if _, err := GiveToAgent(f); err == nil || !strings.Contains(err.Error(), "without following a link") {
		t.Fatalf("err = %v, want a link refused", err)
	}

	// A file where the folder should be.
	write(t, filepath.Join(base, "file"), "x")
	f.Dirs = []string{filepath.Join(base, "file")}
	if _, err := GiveToAgent(f); err == nil {
		t.Fatal("a file named as a folder was walked")
	}

	// Deeper than sandboxd makes.
	deep := filepath.Join(base, "deep")
	p := deep
	for i := 0; i <= maxAgentFolderDepth; i++ {
		p = filepath.Join(p, strconv.Itoa(i))
	}
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	f.Dirs = []string{deep}
	if _, err := GiveToAgent(f); err == nil || !strings.Contains(err.Error(), "folders deep") {
		t.Fatalf("err = %v, want the depth bound", err)
	}
}

func TestOwnerIDs(t *testing.T) {
	if u, g, err := ownerIDs(65531, 61000); err != nil || u != 65531 || g != 61000 {
		t.Fatalf("%d %d %v", u, g, err)
	}
	for _, ids := range [][2]uint32{{1 << 31, 1}, {1, 1 << 31}, {^uint32(0), 0}} {
		if _, _, err := ownerIDs(ids[0], ids[1]); err == nil {
			t.Errorf("%v passed", ids)
		}
	}
}

func TestGroupFor(t *testing.T) {
	if got := groupFor(0, 65531); got != 65531 {
		t.Fatalf("root's group: %d", got)
	}
	if got := groupFor(61000, 65531); got != 61000 {
		t.Fatalf("another group: %d", got)
	}
}

func TestAgentIDs(t *testing.T) {
	lookupUserName = func(string) (*user.User, error) { return &user.User{Uid: "x", Gid: "1"}, nil }
	t.Cleanup(func() { lookupUserName = user.Lookup })
	if _, _, err := agentIDs("bad"); err == nil || !strings.Contains(err.Error(), "has uid") {
		t.Fatalf("err = %v", err)
	}
	lookupUserName = func(string) (*user.User, error) { return &user.User{Uid: "5", Gid: "y"}, nil }
	if _, _, err := agentIDs("bad"); err == nil || !strings.Contains(err.Error(), "has gid") {
		t.Fatalf("err = %v", err)
	}
	// fchown takes an int: an id past MaxInt32 is refused, not wrapped.
	lookupUserName = func(string) (*user.User, error) { return &user.User{Uid: "4294967295", Gid: "1"}, nil }
	if _, _, err := agentIDs("big"); err == nil || !strings.Contains(err.Error(), "not one from 1 to 2147483647") {
		t.Fatalf("err = %v", err)
	}
	lookupUserName = func(string) (*user.User, error) { return &user.User{Uid: "5", Gid: "2147483648"}, nil }
	if _, _, err := agentIDs("big"); err == nil || !strings.Contains(err.Error(), "not one from 0 to 2147483647") {
		t.Fatalf("err = %v", err)
	}
	lookupUserName = func(string) (*user.User, error) { return nil, errors.New("no") }
	if _, err := AgentFoldersFromEnv(func(string) string { return "" }, "x"); err == nil {
		t.Fatal("an unknown user passed")
	}
}
