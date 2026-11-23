//go:build linux

package rootd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestFirecrackerFilesOnTheKernel (M1 PR 14b), as root: a file the jailer's
// user made in the chroot is handed to the agent's group with its owner
// kept; a file of the agent's is shared in with the jailer's group and its
// owner kept; and what is not one of those, as the kernel sees it, is
// refused.
func TestFirecrackerFilesOnTheKernel(t *testing.T) {
	f := kernelFirecracker(t)
	if _, err := f.prepare("sb-f", false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-f")
	root, stage := dir+"/root", dir+"/stage"
	// What firecracker writes for a snapshot: the jailer's user's.
	for _, n := range []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState} {
		p := filepath.Join(root, n)
		if err := os.WriteFile(p, []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, kJailerUID, kJailerGID); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.handOut("sb-f", []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState} {
		uid, gid, mode := statOwner(t, filepath.Join(root, n))
		if uid != kJailerUID || gid != kAgentGID || mode != 0o640 {
			t.Errorf("%s handed out: %d:%d %v, want %d:%d 0640", n, uid, gid, mode, kJailerUID, kAgentGID)
		}
	}
	// The agent's snapshot file, shared in: still the agent's, the jailer's
	// group reads it.
	saved := filepath.Join(stage, rootpolicy.FirecrackerMemory)
	if err := os.WriteFile(saved, []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(saved, kAgentUID, kAgentGID); err != nil {
		t.Fatal(err)
	}
	// The VM's own memory file is in the way: a share replaces the name.
	if err := f.share("sb-f", []string{rootpolicy.FirecrackerMemory}); err != nil {
		t.Fatal(err)
	}
	uid, gid, mode := statOwner(t, filepath.Join(root, rootpolicy.FirecrackerMemory))
	if uid != kAgentUID || gid != kJailerGID || mode != 0o640 {
		t.Errorf("shared in: %d:%d %v, want %d:%d 0640", uid, gid, mode, kAgentUID, kJailerGID)
	}
	if b, _ := os.ReadFile(filepath.Join(root, rootpolicy.FirecrackerMemory)); string(b) != "saved" {
		t.Errorf("the chroot's memory file holds %q, want the agent's", b)
	}
	// A shared file is handed out as it is.
	if err := f.handOut("sb-f", []string{rootpolicy.FirecrackerMemory}); err != nil {
		t.Fatal(err)
	}
	if uid, gid, _ := statOwner(t, filepath.Join(root, rootpolicy.FirecrackerMemory)); uid != kAgentUID || gid != kJailerGID {
		t.Errorf("a shared file changed on hand-out: %d:%d", uid, gid)
	}

	// Refused, as the kernel sees each file:
	// a root file the VM hard-linked under a snapshot's name;
	secret := filepath.Join(f.cfg.ChrootBase, "secret")
	if err := os.WriteFile(secret, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(root, rootpolicy.FirecrackerRootfs)); err != nil {
		t.Fatal(err)
	}
	if err := f.handOut("sb-f", []string{rootpolicy.FirecrackerRootfs}); err == nil {
		t.Error("handed out root's file")
	}
	if _, gid, mode := statOwner(t, secret); gid != 0 || mode != 0o600 {
		t.Errorf("root's file changed: gid %d %v", gid, mode)
	}
	// the jailer's own file with a second name;
	_ = os.Remove(filepath.Join(root, rootpolicy.FirecrackerRootfs))
	disk := filepath.Join(root, rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(disk, []byte("d"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(disk, kJailerUID, kJailerGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(disk, filepath.Join(root, "again")); err != nil {
		t.Fatal(err)
	}
	if err := f.handOut("sb-f", []string{rootpolicy.FirecrackerOverlay}); err == nil || !strings.Contains(err.Error(), "names") {
		t.Errorf("handed out a file with two names: %v", err)
	}
	// a file of root's the agent put in its stage folder to share.
	if err := os.WriteFile(filepath.Join(stage, rootpolicy.FirecrackerState), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.share("sb-f", []string{rootpolicy.FirecrackerState}); err == nil || !strings.Contains(err.Error(), "not the agent") {
		t.Errorf("shared root's file: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(stage, rootpolicy.FirecrackerState)); err != nil || fi.Sys().(*syscall.Stat_t).Gid != 0 {
		t.Errorf("a refused share changed the file: %v %v", fi, err)
	}
}
