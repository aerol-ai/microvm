//go:build linux

package containerd

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// golang.org/x/sys has the quotactl_fd number but none of the XFS quota
// types or the fsxattr ioctls, so they are spelled out here from
// include/uapi/linux/fs.h and include/uapi/linux/dqblk_xfs.h. The struct
// sizes are checked in disk_quota_linux_test.go. quotactl_fd (Linux 5.14)
// takes any open file on the filesystem instead of its block device, so
// there is no device to find, and no mount table to misread (the trap S8
// hit with xfs_quota and a path).
const (
	fsIocFsgetxattr    = 0x801c581f // _IOR('X', 31, struct fsxattr)
	fsIocFssetxattr    = 0x401c5820 // _IOW('X', 32, struct fsxattr)
	fsXflagProjinherit = 0x00000200

	prjQuota          = 2
	qXSetQLim         = 0x5804 // XQM_CMD(4)
	qXGetQStatV       = 0x5808 // XQM_CMD(8)
	fsQuotaPDQEnfd    = 1 << 5
	fsDquotVersion    = 1
	fsQStatVVersion1  = 1
	fsProjQuotaFlag   = 1 << 1
	fsDqBHard         = 1 << 3
	xfsBasicBlockSize = 512
)

type fsxattr struct {
	Xflags     uint32
	Extsize    uint32
	Nextents   uint32
	Projid     uint32
	Cowextsize uint32
	Pad        [8]byte
}

// fsDiskQuota is struct fs_disk_quota; block counts are 512-byte units.
type fsDiskQuota struct {
	Version      int8
	Flags        int8
	Fieldmask    uint16
	ID           uint32
	BlkHardlimit uint64
	BlkSoftlimit uint64
	InoHardlimit uint64
	InoSoftlimit uint64
	Bcount       uint64
	Icount       uint64
	Itimer       int32
	Btimer       int32
	Iwarns       uint16
	Bwarns       uint16
	ItimerHi     int8
	BtimerHi     int8
	RtbtimerHi   int8
	Padding2     int8
	RtbHardlimit uint64
	RtbSoftlimit uint64
	Rtbcount     uint64
	Rtbtimer     int32
	Rtbwarns     uint16
	Padding3     int16
	Padding4     [8]byte
}

type fsQfilestatv struct {
	Ino      uint64
	Nblks    uint64
	Nextents uint32
	Pad      uint32
}

// fsQuotaStatv is struct fs_quota_statv; only its flags are read.
type fsQuotaStatv struct {
	Version      int8
	Pad1         uint8
	Flags        uint16
	Incoredqs    uint32
	Uquota       fsQfilestatv
	Gquota       fsQfilestatv
	Pquota       fsQfilestatv
	Btimelimit   int32
	Itimelimit   int32
	Rtbtimelimit int32
	Bwarnlimit   uint16
	Iwarnlimit   uint16
	Rtbwarnlimit uint16
	Pad3         uint16
	Pad4         uint32
	Pad2         [7]uint64
}

func qcmd(cmd, typ uint32) uint32 { return cmd<<8 | typ&0xff }

type xfsProjectQuota struct{}

// quotactlFd runs one quotactl_fd command on the filesystem holding dir.
func quotactlFd(dir string, cmd, id uint32, addr unsafe.Pointer) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL_FD, uintptr(fd), uintptr(cmd), uintptr(id), uintptr(addr), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (xfsProjectQuota) Enforced(dir string) error {
	st := fsQuotaStatv{Version: fsQStatVVersion1}
	err := quotactlFd(dir, qcmd(qXGetQStatV, prjQuota), 0, unsafe.Pointer(&st))
	runtime.KeepAlive(&st)
	if err != nil {
		return fmt.Errorf("quota state: %w", err)
	}
	if st.Flags&fsQuotaPDQEnfd == 0 {
		return errors.New("project quotas are not enforced on this filesystem")
	}
	return nil
}

func (xfsProjectQuota) Limit(dir string, id uint32, bytes uint64) error {
	q := fsDiskQuota{
		Version:      fsDquotVersion,
		Flags:        fsProjQuotaFlag,
		Fieldmask:    fsDqBHard,
		ID:           id,
		BlkHardlimit: bytes / xfsBasicBlockSize,
	}
	err := quotactlFd(dir, qcmd(qXSetQLim, prjQuota), id, unsafe.Pointer(&q))
	runtime.KeepAlive(&q)
	return err
}

// Assign walks dir parent-first, so a directory is in the project (and
// inheriting) before its entries are listed: a file created during the walk
// either inherits or is listed. Only directories and regular files are
// opened; a symlink is never followed, and a fifo or device is skipped
// rather than opened (a fifo open would block).
//
// A root already in id and inheriting is skipped: Assign is the only thing
// that sets it, after the walk below has covered the files before it (a
// retry, or a resize of a sandbox created with its limit).
func (xfsProjectQuota) Assign(dir string, id uint32) error {
	if done, err := inProject(dir, id); err != nil || done {
		return err
	}
	return filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed during the walk
			}
			return err
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		switch {
		case e.IsDir():
			flags |= unix.O_DIRECTORY
		case e.Type().IsRegular():
		default:
			return nil
		}
		fd, err := unix.Open(path, flags, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return err
		}
		defer unix.Close(fd)
		return setProject(fd, id, e.IsDir())
	})
}

// inProject reports whether dir is in project id and passes it on.
func inProject(dir string, id uint32) (bool, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	var x fsxattr
	if err := ioctlFsxattr(fd, fsIocFsgetxattr, &x); err != nil {
		return false, fmt.Errorf("get fsxattr: %w", err)
	}
	return x.Projid == id && x.Xflags&fsXflagProjinherit != 0, nil
}

func setProject(fd int, id uint32, dir bool) error {
	var x fsxattr
	if err := ioctlFsxattr(fd, fsIocFsgetxattr, &x); err != nil {
		return fmt.Errorf("get fsxattr: %w", err)
	}
	x.Projid = id
	if dir {
		x.Xflags |= fsXflagProjinherit
	}
	if err := ioctlFsxattr(fd, fsIocFssetxattr, &x); err != nil {
		return fmt.Errorf("set fsxattr: %w", err)
	}
	return nil
}

func ioctlFsxattr(fd int, req uintptr, x *fsxattr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(x)))
	runtime.KeepAlive(x)
	if errno != 0 {
		return errno
	}
	return nil
}
