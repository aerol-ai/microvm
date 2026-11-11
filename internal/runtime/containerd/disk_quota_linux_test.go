//go:build linux

package containerd

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
	q := xfsProjectQuota{}
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
	q := xfsProjectQuota{}
	enforced := q.Enforced(dir) == nil
	err := q.Assign(dir, 7)
	switch {
	case err == nil:
		if done, err := inProject(dir, 7); err != nil || !done {
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
