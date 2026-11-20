package rootd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// listen makes the helper's socket at path, mode 0660, group gid.
//
// The socket's folder must be root's alone, and every folder above it
// root's and closed to others or sticky (openFolder, the gate's own rule).
// Then no one else can rename, replace or link anything in the socket's
// folder, and the names below are what this function left there. Without
// that, an agent that can write the folder swaps the fresh socket for a
// link between bind and chmod, and root chgrps and chmods any file it
// names (review H1: on Kubernetes /run/aerolvm is an emptyDir every worker
// container can write). A plain file the agent left at the socket's name
// cannot happen either, so it cannot stop the helper starting.
//
// The folder is opened once, one name at a time with no link followed, and
// made where missing through the folder above it, never by path. The
// chown, chmod and rename go through that open folder too. The rename
// replaces a socket left by a run that died, in one step.
func listen(path string, gid int) (*net.UnixListener, os.FileInfo, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	dfd, err := openFolder(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: socket folder: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	switch err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return nil, nil, fmt.Errorf("root helper: socket: %w", err)
	case st.Mode&unix.S_IFMT != unix.S_IFSOCK:
		// Only root can have put it there; never replace it.
		return nil, nil, fmt.Errorf("root helper: %s exists and is not a socket", path)
	}
	tmp, err := tmpName(name)
	if err != nil {
		return nil, nil, err
	}
	// Bound by path, as bind takes no folder handle: every folder on the
	// path is closed to others, so it names the folder opened above, which
	// the Fstatat below confirms.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, tmp), Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: listen: %w", err)
	}
	// The name it was bound under is gone after the rename; Shutdown
	// removes the real one.
	ln.SetUnlinkOnClose(false)
	fail := func(err error) (*net.UnixListener, os.FileInfo, error) {
		_ = ln.Close()
		_ = unix.Unlinkat(dfd, tmp, 0)
		return nil, nil, fmt.Errorf("root helper: socket: %w", err)
	}
	if err := unix.Fstatat(dfd, tmp, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fail(fmt.Errorf("%s is not the socket just made (mode %o)", tmp, st.Mode))
	}
	if err := unix.Fchownat(dfd, tmp, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	// Linux's fchmodat cannot refuse a link, and needs not here: tmp is the
	// socket just checked, in a folder no one else can change.
	if err := unix.Fchmodat(dfd, tmp, 0o660, 0); err != nil {
		return fail(err)
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		return fail(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	return ln, fi, nil
}

// openFolder opens dir from / one name at a time, following no link, and
// checks each folder through the handle it opened (rootpolicy.CheckFolder):
// dir itself must be root's, or this process's user's in tests, and closed
// to everyone else; a folder above it may instead be sticky (/tmp), where
// no one else can rename what root put in it.
//
// A missing folder is made through the open, checked folder above it
// (mkdirat), then opened and checked like the rest. Making the path first
// and checking after would follow a link someone put on the way, and root
// would make folders wherever it points before refusing (review N2).
func openFolder(dir string) (int, error) {
	owner := uint32(os.Geteuid())
	return walkFolder(dir, true, func(at string, st *unix.Stat_t, last bool) error {
		return rootpolicy.CheckFolder(at, uint32(st.Mode), st.Uid, owner, !last)
	})
}

// walkFolder opens dir from / one name at a time, following no link, and
// calls check on each folder it opened (last: dir itself). mk makes a
// missing folder through the checked folder above it; without mk a
// missing folder is an error, for a folder root must not make (the
// agent's own).
func walkFolder(dir string, mk bool, check func(at string, st *unix.Stat_t, last bool) error) (int, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return -1, fmt.Errorf("%s: want a clean absolute path", dir)
	}
	fd, err := unix.Open("/", folderFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("open /: %w", err)
	}
	var parts []string
	if dir != "/" {
		parts = strings.Split(dir[1:], "/")
	}
	checkAt := func(at string, last bool) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		return check(at, &st, last)
	}
	if err := checkAt("/", len(parts) == 0); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	at := ""
	for i, name := range parts {
		at += "/" + name
		next, err := unix.Openat(fd, name, folderFlags, 0)
		if mk && errors.Is(err, unix.ENOENT) {
			// EEXIST is fine: the open below judges whatever is there.
			if merr := unix.Mkdirat(fd, name, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("make %s: %w", at, merr)
			}
			next, err = unix.Openat(fd, name, folderFlags, 0)
		}
		_ = unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open %s without following a link: %w", at, err)
		}
		fd = next
		if err := checkAt(at, i == len(parts)-1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// tmpName is a name for a file before it is ready (a socket before its
// mode is set, a file before its content is written): no one else can
// write the folder, so it only has to differ from what root left there.
func tmpName(name string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "." + name + "." + hex.EncodeToString(b[:]), nil
}
