package rootd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
)

// The toolbox binary every sandbox's spec binds in (toolboxd, the
// sandbox's first process). The gate binds a file only from a folder only
// root can write (gate.BindChecker): runc follows links in a bind's
// source, so an agent that could rename the file could swap it for a link
// to any host file between the gate's check and runc's mount.
//
// On a VM the operator installs toolboxd in such a folder, and the policy
// names it (SB_TOOLBOX_BINARY_PATH). On Kubernetes the agent's image
// carries toolboxd, which matches the agent's version, and the agent
// copies it to a folder the runtime container sees, which the agent can
// write. There the helper is given that copy (SB_ROOTD_TOOLBOX_SOURCE) and
// keeps a copy of its own, root's, in its state folder; the policy names
// that one, and specs bind it.
//
// The helper copies bytes, never the agent's file: it opens the source one
// name at a time with no link followed, and takes it only when it is a
// regular file the agent owns, of at most maxToolboxBytes. With
// fs.protected_hardlinks (the default) the agent cannot make a link to a
// file it does not own, and the owner check stops one made otherwise. The
// bytes are the agent's either way: it chooses toolboxd today, and it runs
// inside the sandbox (plan R9).
//
// The copy is replaced by rename, so a sandbox already running keeps the
// copy it started with, as with the agent's own rename today. It is made
// again only when the source changed (another inode, size, or change
// time), so a create pays one stat walk.

// maxToolboxBytes bounds the copy (toolboxd is about 20 MiB).
const maxToolboxBytes = 256 << 20

// toolboxFile is the helper's copy's name in its toolbox folder.
const toolboxFile = "toolboxd"

// toolboxStamp is what the helper last copied: the source's identity and
// the times that change with its content.
type toolboxStamp struct {
	dev, ino     uint64
	size         int64
	mtime, ctime unix.Timespec
}

func stampOf(st *unix.Stat_t) toolboxStamp {
	return toolboxStamp{dev: uint64(st.Dev), ino: st.Ino, size: st.Size, mtime: st.Mtim, ctime: st.Ctim}
}

// toolboxPath is the toolbox binary specs bind: the operator's, or the
// helper's copy of the agent's, made fresh when the agent's changed.
func (f *files) toolboxPath() (string, error) {
	if f.dirs.ToolboxSource == "" {
		return f.dirs.Toolbox, nil
	}
	f.toolboxMu.Lock()
	defer f.toolboxMu.Unlock()
	src, st, err := f.openToolboxSource()
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()
	stamp := stampOf(st)
	var have unix.Stat_t
	if f.toolboxCopied && stamp == f.toolboxLast &&
		unix.Fstatat(f.toolbox, toolboxFile, &have, unix.AT_SYMLINK_NOFOLLOW) == nil && have.Size == st.Size {
		return f.dirs.Toolbox, nil
	}
	if err := f.copyToolbox(src, st.Size); err != nil {
		return "", err
	}
	f.toolboxLast, f.toolboxCopied = stamp, true
	return f.dirs.Toolbox, nil
}

// openToolboxSource opens the agent's toolbox copy and checks it.
func (f *files) openToolboxSource() (*os.File, *unix.Stat_t, error) {
	dir, name := filepath.Split(f.dirs.ToolboxSource)
	dfd, err := openPath(filepath.Clean(dir))
	if err != nil {
		return nil, nil, &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf("root helper: the agent's toolbox folder: %v", err)}
	}
	defer func() { _ = unix.Close(dfd) }()
	// O_NONBLOCK: a FIFO there must not hold the call; it is refused below.
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil, &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf("root helper: no toolbox binary at %s", f.dirs.ToolboxSource)}
		}
		// ELOOP: a link, which the agent's copy never is.
		return nil, nil, &fileError{code: codes.PermissionDenied, reason: ReasonBadToolbox,
			msg: fmt.Sprintf("root helper: the toolbox binary %s cannot be opened as a file: %v", f.dirs.ToolboxSource, err)}
	}
	file := os.NewFile(uintptr(fd), f.dirs.ToolboxSource)
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	switch {
	case err != nil:
	case uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG:
		err = fmt.Errorf("%s is not a regular file (mode %o)", f.dirs.ToolboxSource, st.Mode)
	case st.Uid != f.agentUID:
		err = fmt.Errorf("%s belongs to uid %d, not the agent's %d", f.dirs.ToolboxSource, st.Uid, f.agentUID)
	case st.Size <= 0 || st.Size > maxToolboxBytes:
		err = fmt.Errorf("%s is %d bytes; want 1 to %d", f.dirs.ToolboxSource, st.Size, maxToolboxBytes)
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, &fileError{code: codes.PermissionDenied, reason: ReasonBadToolbox, msg: "root helper: " + err.Error()}
	}
	return file, &st, nil
}

// copyToolbox writes size bytes of src to the helper's copy: a temporary
// name in the helper's own folder, mode 0755, renamed over the copy.
func (f *files) copyToolbox(src *os.File, size int64) error {
	tmp, err := tmpName(toolboxFile)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(f.toolbox, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("root helper: copy the toolbox binary: %w", err)
	}
	dst := os.NewFile(uintptr(fd), tmp)
	// One byte more than the stat said: a file that grew since is not the
	// one checked, and is refused rather than cut short.
	n, err := io.Copy(dst, io.LimitReader(src, size+1))
	if err == nil && n != size {
		err = fmt.Errorf("the toolbox binary changed while it was copied (%d bytes, %d at the check)", n, size)
	}
	if err == nil {
		err = dst.Chmod(0o755)
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(f.toolbox, tmp, f.toolbox, toolboxFile)
	}
	if err != nil {
		_ = unix.Unlinkat(f.toolbox, tmp, 0)
		return fmt.Errorf("root helper: copy the toolbox binary: %w", err)
	}
	return nil
}
