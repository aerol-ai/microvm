package rootd

import (
	"fmt"
	"math"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// pathHandle opens name in dir as an O_PATH handle, following no link: a
// handle on whatever is at the name, a socket included, that reads and
// writes nothing.
func pathHandle(dir int, name string) (int, error) {
	return unix.Openat(dir, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

// chmodPath sets an O_PATH handle's group and mode: the group through the
// handle itself (AT_EMPTY_PATH), the mode through its /proc link, which
// names that inode and no other.
func chmodPath(fd, gid int, mode uint32) error {
	if err := unix.Fchownat(fd, "", -1, gid, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	return unix.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), mode)
}

// makeFilesystemAttr runs cmd as the agent's own user and group, seen as
// root in a user namespace of its own: uid and gid 0 there are the agent's
// and nothing else is mapped. On the node it is the agent, with no
// supplementary group, so it reads and writes only what the agent can;
// what it stats it sees as root's, so mkfs.ext4 -d writes the agent's
// files as root's.
func makeFilesystemAttr(cmd *exec.Cmd, uid uint32, gid int) error {
	host := int64(uid)
	if host > math.MaxInt32 || host < 1 {
		return fmt.Errorf("root helper: agent uid %d: want 1 to %d", host, math.MaxInt32)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(host), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: true,
		Credential:                 &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}},
		Pdeathsig:                  syscall.SIGKILL,
		Setsid:                     true,
	}
	return nil
}

// fchownAny and fchmodAny set a file's owner and mode through any handle,
// an O_PATH one (rootfolder.FolderFlags) included: the owner through the
// handle itself (AT_EMPTY_PATH), the mode through its /proc link.
func fchownAny(fd, uid, gid int) error { return unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH) }

func fchmodAny(fd int, mode uint32) error {
	return unix.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), mode)
}
