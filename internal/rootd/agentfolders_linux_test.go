//go:build linux

package rootd

import (
	"os"
	"path/filepath"
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
	} {
		if u, _ := owner(p); u != want {
			t.Errorf("%s is uid %d, want %d", p, u, want)
		}
	}
	if res.SkippedLinks != 1 || res.SkippedMounts != 1 {
		t.Errorf("result %+v, want 1 skipped link and 1 skipped mount", res)
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
