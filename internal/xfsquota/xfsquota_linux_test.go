//go:build linux

package xfsquota

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

// The quota structs are copied from the kernel's uapi headers by hand; a
// wrong size or offset would hand the kernel garbage limits.
func TestDiskQuotaABI(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof(struct fsxattr)", unsafe.Sizeof(fsxattr{}), 28},
		{"sizeof(struct fs_disk_quota)", unsafe.Sizeof(fsDiskQuota{}), 112},
		{"offsetof(d_blk_hardlimit)", unsafe.Offsetof(fsDiskQuota{}.BlkHardlimit), 8},
		{"offsetof(d_itimer)", unsafe.Offsetof(fsDiskQuota{}.Itimer), 56},
		{"offsetof(d_rtb_hardlimit)", unsafe.Offsetof(fsDiskQuota{}.RtbHardlimit), 72},
		{"offsetof(d_rtbtimer)", unsafe.Offsetof(fsDiskQuota{}.Rtbtimer), 96},
		{"sizeof(struct fs_quota_statv)", unsafe.Sizeof(fsQuotaStatv{}), 160},
		{"offsetof(qs_flags)", unsafe.Offsetof(fsQuotaStatv{}.Flags), 2},
		{"offsetof(qs_pquota)", unsafe.Offsetof(fsQuotaStatv{}.Pquota), 56},
		{"offsetof(qs_pad2)", unsafe.Offsetof(fsQuotaStatv{}.Pad2), 104},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	// _IOR('X', 31, struct fsxattr) and _IOW('X', 32, ...), built the way
	// asm-generic/ioctl.h builds them (amd64 and arm64 share it).
	ioc := func(dir, nr, size uintptr) uintptr { return dir<<30 | size<<16 | 'X'<<8 | nr }
	if got := ioc(2, 31, unsafe.Sizeof(fsxattr{})); got != fsIocFsgetxattr {
		t.Errorf("FS_IOC_FSGETXATTR = %#x, want %#x", fsIocFsgetxattr, got)
	}
	if got := ioc(1, 32, unsafe.Sizeof(fsxattr{})); got != fsIocFssetxattr {
		t.Errorf("FS_IOC_FSSETXATTR = %#x, want %#x", fsIocFssetxattr, got)
	}
	if got := qcmd(qXSetQLim, prjQuota); got != 0x580402 {
		t.Errorf("QCMD(Q_XSETQLIM, PRJQUOTA) = %#x, want 0x580402", got)
	}
}

func TestDiskQuotaMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	q := Ops{}
	if err := q.Enforced(missing); err == nil {
		t.Error("Enforced on a missing directory: no error")
	}
	if err := q.Assign(missing, 9); err == nil {
		t.Error("Assign on a missing directory: no error")
	}
	if err := q.Limit(missing, 9, 1<<30); err == nil {
		t.Error("Limit on a missing directory: no error")
	}
}

// On an ordinary test machine (not root, or no XFS with project quotas) the
// calls fail; the point is that the walk skips what it must not open (a
// fifo would block, a symlink must not be followed) and that nothing passes
// silently. On an XFS volume with enforced project quotas, as root, the
// tree really joins the project.
func TestDiskQuotaOnThisMachine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshots", "7", "fs")
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "hosts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	q := Ops{}
	enforced := q.Enforced(dir) == nil
	err := q.Assign(dir, 7)
	switch {
	case err == nil:
		if done, err := InProject(dir, 7); err != nil || !done {
			t.Fatalf("Assign passed but the root is not in the project: %v %v", done, err)
		}
		if err := q.Assign(dir, 7); err != nil {
			t.Fatalf("a second Assign: %v", err)
		}
	default:
		t.Logf("Assign on this machine: %v", err)
	}
	// Root may set a limit where it is only counted, not enforced; anyone
	// else must be refused.
	if err := q.Limit(dir, 7, 1<<30); err == nil && !enforced && os.Geteuid() != 0 {
		t.Fatal("a limit was accepted from a user who may not set one")
	}
}

// fakeKernel stands in for the XFS kernel calls: a project and inherit
// flag per inode, quota state, and the limits set.
type fakeKernel struct {
	attrs    map[uint64]fsxattr
	enforced bool
	limits   map[uint32]uint64
	setErr   error
}

func (k *fakeKernel) install(t *testing.T) {
	origQ, origI := sysQuotactlFd, sysIoctlFsxattr
	t.Cleanup(func() { sysQuotactlFd, sysIoctlFsxattr = origQ, origI })
	sysQuotactlFd = func(_ int, cmd, id uint32, addr unsafe.Pointer) error {
		switch cmd {
		case qcmd(qXGetQStatV, prjQuota):
			st := (*fsQuotaStatv)(addr)
			if k.enforced {
				st.Flags |= fsQuotaPDQEnfd
			}
		case qcmd(qXSetQLim, prjQuota):
			q := (*fsDiskQuota)(addr)
			if q.ID != id || q.Fieldmask != fsDqBHard {
				return syscall.EINVAL
			}
			k.limits[id] = q.BlkHardlimit * xfsBasicBlockSize
		default:
			return syscall.EINVAL
		}
		return nil
	}
	sysIoctlFsxattr = func(fd int, req uintptr, x *fsxattr) error {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return err
		}
		switch req {
		case fsIocFsgetxattr:
			*x = k.attrs[st.Ino]
		case fsIocFssetxattr:
			if k.setErr != nil {
				return k.setErr
			}
			k.attrs[st.Ino] = *x
		}
		return nil
	}
}

// TestOpsOnAFakeKernel (M1 PR 7, the package's own tests since the code
// moved here): Assign puts every folder and regular file in the project,
// folders passing it on, skips links and FIFOs, and skips a tree already
// done; Limit sets the hard block limit in 512-byte blocks; Enforced reads
// the quota state.
func TestOpsOnAFakeKernel(t *testing.T) {
	k := &fakeKernel{attrs: map[uint64]fsxattr{}, limits: map[uint32]uint64{}}
	k.install(t)
	dir := filepath.Join(t.TempDir(), "snapshots", "7")
	if err := os.MkdirAll(filepath.Join(dir, "fs", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fs", "etc", "hosts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fs", "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "fs", "link")); err != nil {
		t.Fatal(err)
	}
	q := Ops{}
	if err := q.Enforced(dir); err == nil {
		t.Fatal("a volume that enforces nothing passed")
	}
	k.enforced = true
	if err := q.Enforced(dir); err != nil {
		t.Fatal(err)
	}
	if err := q.Assign(dir, 1<<30+7); err != nil {
		t.Fatal(err)
	}
	ino := func(p string) uint64 {
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	for p, inherit := range map[string]bool{dir: true, filepath.Join(dir, "fs"): true, filepath.Join(dir, "fs", "etc"): true, filepath.Join(dir, "fs", "etc", "hosts"): false} {
		a := k.attrs[ino(p)]
		if a.Projid != 1<<30+7 || (a.Xflags&fsXflagProjinherit != 0) != inherit {
			t.Fatalf("%s: %+v", p, a)
		}
	}
	for _, p := range []string{filepath.Join(dir, "fs", "pipe"), filepath.Join(dir, "fs", "link")} {
		if _, ok := k.attrs[ino(p)]; ok {
			t.Fatalf("%s was opened", p)
		}
	}
	if done, err := InProject(dir, 1<<30+7); err != nil || !done {
		t.Fatalf("InProject = %v, %v", done, err)
	}
	k.setErr = syscall.EPERM
	if err := q.Assign(dir, 1<<30+7); err != nil {
		t.Fatalf("a tree already done was walked again: %v", err)
	}
	if err := q.Assign(dir, 1<<30+8); err == nil {
		t.Fatal("a failed set passed")
	}
	if err := q.Limit(dir, 1<<30+7, 3<<30); err != nil || k.limits[1<<30+7] != 3<<30 {
		t.Fatalf("Limit = %v, %v", err, k.limits)
	}
}
