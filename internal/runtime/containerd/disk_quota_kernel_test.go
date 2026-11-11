//go:build linux && kerneltest

package containerd

// The disk limit on a real XFS filesystem with project quotas, as root:
//
//	sudo go test -tags kerneltest ./internal/runtime/containerd/ -run KernelDiskQuota -v
//
// It makes a 512 MiB XFS image, mounts it with prjquota on a loop device,
// and lays out snapshots/<n>/fs as the overlay snapshotter does. Or, to use
// a filesystem that is already there (the worker's NVMe on Kubernetes,
// where a pod may have no loop devices), set AEROL_XFS_QUOTA_DIR to a
// directory on an XFS mount with prjquota.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func kernelQuotaRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if dir := os.Getenv("AEROL_XFS_QUOTA_DIR"); dir != "" {
		root, err := os.MkdirTemp(dir, "quota-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(root) })
		return root
	}
	if _, err := exec.LookPath("mkfs.xfs"); err != nil {
		t.Skip("needs mkfs.xfs (xfsprogs)")
	}
	tmp := t.TempDir()
	img, mnt := filepath.Join(tmp, "xfs.img"), filepath.Join(tmp, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if f, err := os.Create(img); err == nil {
		_ = f.Truncate(512 << 20)
		_ = f.Close()
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Skipf("%v: %v: %s", args, err, out)
		}
	}
	run("mkfs.xfs", "-q", img)
	run("mount", "-o", "loop,prjquota", img, mnt)
	t.Cleanup(func() { _ = exec.Command("umount", mnt).Run() })
	return mnt
}

func TestKernelDiskQuota(t *testing.T) {
	root := kernelQuotaRoot(t)
	const id = 4242
	// The project goes on the snapshot's directory (fs and work), as
	// limitWritableLayer does; writes land in fs.
	snap := filepath.Join(root, "snapshots", fmt.Sprint(id))
	dir := filepath.Join(snap, "fs")
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snap, "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file from before the limit, as a parked slot's layer has.
	if err := os.WriteFile(filepath.Join(dir, "tmp", "before"), make([]byte, 8<<20), 0o644); err != nil {
		t.Fatal(err)
	}

	q := xfsProjectQuota{}
	if err := q.Enforced(snap); err != nil {
		t.Fatalf("Enforced: %v", err)
	}
	if err := q.Assign(snap, id); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	for _, d := range []string{snap, dir, filepath.Join(snap, "work")} {
		if done, err := inProject(d, id); err != nil || !done {
			t.Fatalf("inProject(%s) = %v %v", d, done, err)
		}
	}
	if err := q.Assign(snap, id); err != nil { // the second time is a no-op
		t.Fatalf("Assign again: %v", err)
	}
	if err := q.Limit(snap, id, 64<<20); err != nil {
		t.Fatalf("Limit: %v", err)
	}

	// A directory made after the limit inherits it; writing there stops at
	// the limit, counting the 8 MiB written before.
	later := filepath.Join(dir, "later")
	if err := os.Mkdir(later, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(later, "fill"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	chunk := make([]byte, 1<<20)
	written := 0
	for written < 256<<20 {
		n, err := f.Write(chunk)
		written += n
		if err != nil {
			if !errors.Is(err, syscall.ENOSPC) && !errors.Is(err, syscall.EDQUOT) {
				t.Fatalf("write stopped with %v, want ENOSPC or EDQUOT", err)
			}
			break
		}
		if err := f.Sync(); err != nil {
			if !errors.Is(err, syscall.ENOSPC) && !errors.Is(err, syscall.EDQUOT) {
				t.Fatalf("sync: %v", err)
			}
			break
		}
	}
	t.Logf("wrote %d MiB before the limit stopped it", written>>20)
	if written >= 64<<20 || written < 40<<20 {
		t.Fatalf("wrote %d MiB, want under the 64 MiB limit less the 8 MiB already there", written>>20)
	}

	// A sibling with no limit is not held to it.
	free := filepath.Join(root, "snapshots", "4243", "fs")
	if err := os.MkdirAll(free, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(free, "big"), make([]byte, 96<<20), 0o644); err != nil {
		t.Fatalf("unlimited sibling: %v", err)
	}
}

// A mount without prjquota accepts limits and enforces none; Enforced must
// say so, or the setting would silently do nothing.
func TestKernelDiskQuotaNotEnforced(t *testing.T) {
	if os.Getenv("AEROL_XFS_QUOTA_DIR") != "" {
		t.Skip("uses its own loop mount")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("mkfs.xfs"); err != nil {
		t.Skip("needs mkfs.xfs (xfsprogs)")
	}
	tmp := t.TempDir()
	img, mnt := filepath.Join(tmp, "xfs.img"), filepath.Join(tmp, "mnt")
	_ = os.Mkdir(mnt, 0o755)
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Truncate(512 << 20)
	_ = f.Close()
	for _, args := range [][]string{{"mkfs.xfs", "-q", img}, {"mount", "-o", "loop", img, mnt}} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Skipf("%v: %v: %s", args, err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command("umount", mnt).Run() })
	if err := (xfsProjectQuota{}).Enforced(mnt); err == nil {
		t.Fatal("Enforced passed on a mount without prjquota")
	}
}

// overlayfs copies a lower file up by making it in work and renaming it into
// the upper directory. With the whole snapshot directory in the project the
// rename stays inside one project; with only the upper directory in it, XFS
// refuses the rename (EXDEV), which is how runsc failed to set up a bind
// mount in a limited gVisor sandbox (C27 live run, 2026-11-11).
func TestKernelDiskQuotaOverlayCopyUp(t *testing.T) {
	root := kernelQuotaRoot(t)
	lower := filepath.Join(root, "lower")
	if err := os.MkdirAll(filepath.Join(lower, "usr", "local", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lower, "usr", "local", "bin", "tool"), []byte("lower"), 0o755); err != nil {
		t.Fatal(err)
	}
	q := xfsProjectQuota{}
	copyUp := func(id int, tagged func(snap string) string) error {
		snap := filepath.Join(root, "snapshots", fmt.Sprint(id))
		upper, work, merged := filepath.Join(snap, "fs"), filepath.Join(snap, "work"), filepath.Join(root, fmt.Sprint("merged-", id))
		for _, d := range []string{upper, work, merged} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		target := tagged(snap)
		if err := q.Assign(target, uint32(id)); err != nil {
			t.Fatalf("Assign(%s): %v", target, err)
		}
		if err := q.Limit(target, uint32(id), 64<<20); err != nil {
			t.Fatalf("Limit: %v", err)
		}
		opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
		if out, err := exec.Command("mount", "-t", "overlay", "overlay", "-o", opts, merged).CombinedOutput(); err != nil {
			t.Skipf("overlay mount: %v: %s", err, out)
		}
		defer func() { _ = exec.Command("umount", merged).Run() }()
		return os.WriteFile(filepath.Join(merged, "usr", "local", "bin", "tool"), []byte("upper"), 0o755)
	}
	if err := copyUp(5101, func(snap string) string { return snap }); err != nil {
		t.Fatalf("copy-up with the whole snapshot in the project: %v", err)
	}
	if err := copyUp(5102, func(snap string) string { return filepath.Join(snap, "fs") }); !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("copy-up with only the upper directory in the project: %v, want EXDEV (the reason the snapshot directory is tagged)", err)
	}
}
