//go:build linux

package xfsquota

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// golang.org/x/sys has the quotactl_fd number but none of the XFS quota
// types or the fsxattr ioctls, so they are spelled out here from
// include/uapi/linux/fs.h and include/uapi/linux/dqblk_xfs.h. The struct
// sizes are checked in xfsquota_linux_test.go. quotactl_fd (Linux 5.14)
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

// Ops drives XFS project quotas through quotactl_fd and the fsxattr
// ioctls (package doc).
type Ops struct{}

// quotactlFd runs one quotactl_fd command on the filesystem holding dir.
func quotactlFd(dir string, cmd, id uint32, addr unsafe.Pointer) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return sysQuotactlFd(fd, cmd, id, addr)
}

// The two kernel calls, which tests replace to drive the code without an
// XFS volume.
var (
	sysQuotactlFd = func(fd int, cmd, id uint32, addr unsafe.Pointer) error {
		_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL_FD, uintptr(fd), uintptr(cmd), uintptr(id), uintptr(addr), 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}
	sysIoctlFsxattr = func(fd int, req uintptr, x *fsxattr) error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(x)))
		runtime.KeepAlive(x)
		if errno != 0 {
			return errno
		}
		return nil
	}
)

func (Ops) Enforced(dir string) error {
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

func (Ops) Limit(dir string, id uint32, bytes uint64) error {
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
// either inherits or is listed.
//
// The walk never looks a path up twice. Each entry is opened by its name
// in its parent's open directory without following a link (O_PATH,
// O_NOFOLLOW), and its type is read from that open file, so what is
// listed, checked and changed is the one inode the name led to, even if
// the tree changes during the walk. Only directories and regular files are
// then opened for the ioctl, through the descriptor; a symlink, FIFO or
// device is never opened (a FIFO open would block, a device's could act).
//
// A root already in id and inheriting is skipped: Assign is the only thing
// that sets it, after the walk below has covered the files before it (a
// retry, or a resize of a sandbox created with its limit).
func (Ops) Assign(dir string, id uint32) error {
	if done, err := InProject(dir, id); err != nil || done {
		return err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := setProject(fd, id, true); err != nil {
		return err
	}
	return assignBelow(fd, id, 0)
}

// maxDepth bounds how many levels of folders below its root Assign walks,
// holding one open directory per level. A walk by path stopped near here
// too: PATH_MAX, 4096 bytes, holds about 2,000 one-letter folders. A
// variable for tests.
var maxDepth = 2048

// assignBelow puts every entry of the open directory dfd, depth levels
// below the root, in project id, and walks the directories among them.
func assignBelow(dfd int, id uint32, depth int) error {
	names, err := readNames(dfd)
	if err != nil {
		return err
	}
	for _, name := range names {
		fd, isDir, err := openEntry(dfd, name)
		if err != nil {
			return err
		}
		if fd < 0 {
			continue // gone, or not a directory or regular file
		}
		if isDir && depth+1 > maxDepth {
			unix.Close(fd)
			return fmt.Errorf("folders nested deeper than %d", maxDepth)
		}
		err = setProject(fd, id, isDir)
		if err == nil && isDir {
			err = assignBelow(fd, id, depth+1)
		}
		unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}

// readNames lists the open directory dfd, without "." and "..".
func readNames(dfd int) ([]string, error) {
	var names []string
	buf := make([]byte, 32<<10)
	for {
		n, err := unix.Getdents(dfd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("list a folder: %w", err)
		}
		if n <= 0 {
			return names, nil
		}
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
	}
}

// openEntry opens name in the open directory dfd for the fsxattr ioctls:
// first as O_PATH with no link followed, which opens nothing but a handle
// on the inode, then, if that inode is a directory or regular file, for
// reading, through the handle. It returns -1 for an entry gone since the
// listing, a link, or any other kind of file.
func openEntry(dfd int, name string) (int, bool, error) {
	pfd, err := unix.Openat(dfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, false, nil // removed during the walk
	}
	if err != nil {
		return -1, false, fmt.Errorf("open %s: %w", name, err)
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return -1, false, fmt.Errorf("stat %s: %w", name, err)
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		flags |= unix.O_DIRECTORY
	case unix.S_IFREG:
	default:
		return -1, false, nil
	}
	// The handle's own inode, reopened: /proc/self/fd/N names the open
	// file, not a path, so a rename since cannot swap it.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pfd), flags, 0)
	if err != nil {
		return -1, false, fmt.Errorf("open %s: %w", name, err)
	}
	return fd, st.Mode&unix.S_IFMT == unix.S_IFDIR, nil
}

// InProject reports whether dir is in project id and passes it on.
func InProject(dir string, id uint32) (bool, error) {
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

func ioctlFsxattr(fd int, req uintptr, x *fsxattr) error { return sysIoctlFsxattr(fd, req, x) }
