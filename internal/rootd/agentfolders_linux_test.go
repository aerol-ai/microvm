//go:build linux

package rootd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestKernelGiveToAgent moves root's files for real, as root: a node that
// ran in privilege mode single, switched to split (M1 PR 10). Root's files
// become the agent's, a WASM worker's file keeps its owner, a file with a
// second name outside is left as it is, and an external storage mount (a
// tmpfs here) is never entered. Run as root:
//
//	go test -run TestKernelGiveToAgent -v ./internal/rootd/
func TestKernelGiveToAgent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: it makes root's files and gives them away")
	}
	const agent, agentGroup, worker = 65531, 65531, 61000
	base := realTemp(t)
	data := filepath.Join(base, "var-lib-sandboxd")
	write(t, filepath.Join(data, "state.db"), "db")
	write(t, filepath.Join(data, "raft", "raft.db"), "raft")
	write(t, filepath.Join(data, "wasm", "work", "guest.txt"), "guest")
	if err := os.Chown(filepath.Join(data, "wasm", "work", "guest.txt"), worker, worker); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(base, "shadow"), "secret")
	if err := os.Link(filepath.Join(base, "shadow"), filepath.Join(data, "link-to-shadow")); err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(data, "mounts", "sb-1", "0")
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("cannot mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	write(t, filepath.Join(mnt, "remote.txt"), "remote")
	// A bind mount from the same disk: the same device number, so only
	// the kernel's mount-root attribute shows it is a mount (review).
	elsewhere := filepath.Join(base, "elsewhere")
	write(t, filepath.Join(elsewhere, "root-only.txt"), "root's")
	bind := filepath.Join(data, "mounts", "sb-2", "0")
	if err := os.MkdirAll(bind, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(elsewhere, bind, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(bind, unix.MNT_DETACH) })

	res, err := GiveToAgent(AgentFolders{Dirs: []string{data}, UID: agent, GID: agentGroup})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("result %+v", res)
	owner := func(p string) (uint32, uint32) {
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st.Uid, st.Gid
	}
	for _, p := range []string{data, filepath.Join(data, "state.db"), filepath.Join(data, "raft"), filepath.Join(data, "raft", "raft.db"),
		filepath.Join(data, "mounts", "sb-1")} {
		if u, g := owner(p); u != agent || g != agentGroup {
			t.Errorf("%s is %d:%d, want the agent's", p, u, g)
		}
	}
	for p, want := range map[string]uint32{
		filepath.Join(data, "wasm", "work", "guest.txt"): worker,
		filepath.Join(base, "shadow"):                    0,
		filepath.Join(mnt, "remote.txt"):                 0,
		mnt:                                              0,
		elsewhere:                                        0,
		filepath.Join(elsewhere, "root-only.txt"):        0,
	} {
		if u, _ := owner(p); u != want {
			t.Errorf("%s is uid %d, want %d", p, u, want)
		}
	}
	if res.SkippedLinks != 1 || res.SkippedMounts != 2 {
		t.Errorf("result %+v, want 1 skipped link and 2 skipped mounts", res)
	}
	// Again: nothing of root's is left to move.
	again, err := GiveToAgent(AgentFolders{Dirs: []string{data}, UID: agent, GID: agentGroup})
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed != 0 {
		t.Errorf("second walk changed %d", again.Changed)
	}
}

// TestKernelForgetsSingleWasmCaches removes, as root, the WASM compile
// caches privilege mode single gave the worker's uid, on a node switched
// to split: the worker's caches go, split's own (the agent's) stay, a link
// in a cache is removed and what it names is not, and a bind mount inside
// a cache stops that cache's removal without anything in the mount being
// touched. Run as root:
//
//	go test -run TestKernelForgetsSingleWasmCaches -v ./internal/rootd/
func TestKernelForgetsSingleWasmCaches(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: it makes the worker's files and removes them")
	}
	const agent, worker = 65531, 61000
	base := realTemp(t)
	data := filepath.Join(base, "var-lib-sandboxd")
	root := filepath.Join(data, "wasm", "modules", "cache", "wazero-compile")
	chownAll := func(dir string, uid int) {
		t.Helper()
		if err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, uid)
		}); err != nil {
			t.Fatal(err)
		}
	}
	single := filepath.Join(root, "owners", "owner-0123456789abcdef")
	write(t, filepath.Join(single, "wazero-v1", "abc"), "compiled")
	outside := filepath.Join(base, "root-only.txt")
	write(t, outside, "root's")
	if err := os.Symlink(outside, filepath.Join(single, "wazero-v1", "link")); err != nil {
		t.Fatal(err)
	}
	chownAll(single, worker)
	slotCache := filepath.Join(root, "slots", "fedcba9876543210", "cache")
	write(t, filepath.Join(slotCache, "wazero-v1", "ghi"), "compiled")
	chownAll(slotCache, worker)
	split := filepath.Join(root, "owners", "operator")
	write(t, filepath.Join(split, "wazero-v1", "def"), "compiled")
	chownAll(split, agent)
	// A bind mount inside a cache from single: the removal stops there.
	mounted := filepath.Join(root, "owners", "owner-fedcba9876543210")
	bind := filepath.Join(mounted, "bind")
	if err := os.MkdirAll(bind, 0o700); err != nil {
		t.Fatal(err)
	}
	chownAll(mounted, worker)
	elsewhere := filepath.Join(base, "elsewhere")
	write(t, filepath.Join(elsewhere, "keep.txt"), "keep")
	if err := unix.Mount(elsewhere, bind, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(bind, unix.MNT_DETACH) })

	res, err := GiveToAgent(AgentFolders{Dirs: []string{data}, UID: agent, GID: agent, WasmCacheRoot: root, WasmWorkerUID: worker})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("result %+v", res)
	if res.ForgottenCaches != 2 || len(res.CacheErrors) != 1 || !strings.Contains(res.CacheErrors[0], "another file system") {
		t.Fatalf("result %+v, want 2 caches removed and the mounted one left", res)
	}
	for p, want := range map[string]bool{
		single:                                   false,
		slotCache:                                false,
		filepath.Join(split, "wazero-v1", "def"): true,
		outside:                                  true,
		filepath.Join(bind, "keep.txt"):          true,
		filepath.Join(elsewhere, "keep.txt"):     true,
	} {
		if _, err := os.Lstat(p); (err == nil) != want {
			t.Errorf("%s there: %v, want %v", p, err == nil, want)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(root, "slots", "fedcba9876543210"), &st); err != nil || st.Uid != agent {
		t.Errorf("the slot's folder: uid %d, %v; want the agent's", st.Uid, err)
	}
}
