// Package rootfolder holds the rules root follows for a folder it trusts
// and for the root helper's socket (plans/security-gaps-m1-m4.md §3.3):
// open a folder one name at a time with no link followed, check each
// folder through the handle it opened, make a missing one through the
// checked folder above it, and make the socket so no one else can swap it
// for a link.
//
// Two root processes need these rules: the helper (internal/rootd) for its
// own folders, and the runtime supervisor (internal/supervisor), which
// makes the helper's socket and keeps the helper's verified copies when it
// runs the signed helper (eng review D4). The supervisor is fixed in the
// runtime image and must not link the helper's gRPC and containerd code,
// so the rules live here, with no imports beyond the standard library and
// x/sys.
package rootfolder

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
)

// POSIX file mode bits, the same on Linux and macOS.
const (
	modeType   = 0o170000
	modeFolder = 0o040000
	modeSticky = 0o1000
	// modeOthersWrite is write for the group and for others.
	modeOthersWrite = 0o022
)

// CheckFolder is the rule for each folder on the way to a host path root
// acts on (a bind source, a stdio FIFO, a runsc config, the helper's own
// socket, the supervisor's copy of the helper): it belongs to root, or to
// owner (a test's own user in place of root), and no one else can write
// it. With sticky allowed, a sticky folder anyone can write passes too:
// there no one else can rename or remove what root put in it. Then a name
// below means what root left there, between the check and root's use of
// it.
//
// mode and uid come from the caller's stat of the open folder; this does
// no I/O itself.
func CheckFolder(at string, mode, uid, owner uint32, sticky bool) error {
	switch {
	case mode&modeType != modeFolder:
		return fmt.Errorf("%s is not a folder", at)
	case uid != 0 && uid != owner:
		return fmt.Errorf("folder %s belongs to uid %d", at, uid)
	case mode&modeOthersWrite != 0 && !(sticky && mode&modeSticky != 0):
		return fmt.Errorf("folder %s can be written by others (mode %o)", at, mode&0o7777)
	}
	return nil
}

// Listen makes a socket at path, mode 0660, group gid.
//
// The socket's folder must be root's alone, and every folder above it
// root's and closed to others or sticky (OpenFolder, the gate's own rule).
// Then no one else can rename, replace or link anything in the socket's
// folder, and the names below are what this function left there. Without
// that, an agent that can write the folder swaps the fresh socket for a
// link between bind and chmod, and root chgrps and chmods any file it
// names (review H1: on Kubernetes /run/aerolvm is an emptyDir every worker
// container can write). A plain file the agent left at the socket's name
// cannot happen either, so it cannot stop the socket being made.
//
// The folder is opened once, one name at a time with no link followed, and
// made where missing through the folder above it, never by path. The
// chown, chmod and rename go through that open folder too. The rename
// replaces a socket left by a run that died, in one step.
//
// The listener does not remove the socket when closed: the name it was
// bound under is gone after the rename, and the caller decides when the
// socket goes (the helper on its way out, or the supervisor, which keeps
// one socket for every helper it runs).
func Listen(path string, gid int) (*net.UnixListener, os.FileInfo, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	dfd, err := OpenFolder(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("socket folder: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	switch err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return nil, nil, fmt.Errorf("socket: %w", err)
	case st.Mode&unix.S_IFMT != unix.S_IFSOCK:
		// Only root can have put it there; never replace it.
		return nil, nil, fmt.Errorf("%s exists and is not a socket", path)
	}
	tmp, err := TmpName(name)
	if err != nil {
		return nil, nil, err
	}
	// Bound by path, as bind takes no folder handle: every folder on the
	// path is closed to others, so it names the folder opened above, which
	// the Fstatat below confirms.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, tmp), Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("listen: %w", err)
	}
	ln.SetUnlinkOnClose(false)
	fail := func(err error) (*net.UnixListener, os.FileInfo, error) {
		_ = ln.Close()
		_ = unix.Unlinkat(dfd, tmp, 0)
		return nil, nil, fmt.Errorf("socket: %w", err)
	}
	if afterBind != nil {
		afterBind(dfd, tmp)
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

// afterBind, when set, runs between bind and the checks after it: tests
// put something else at the new name there, as only root could here.
var afterBind func(dfd int, tmp string)

// OpenFolder opens dir from / one name at a time, following no link, and
// checks each folder through the handle it opened (CheckFolder): dir
// itself must be root's, or this process's user's in tests, and closed to
// everyone else; a folder above it may instead be sticky (/tmp), where no
// one else can rename what root put in it.
//
// A missing folder is made through the open, checked folder above it
// (mkdirat), then opened and checked like the rest. Making the path first
// and checking after would follow a link someone put on the way, and root
// would make folders wherever it points before refusing (review N2).
func OpenFolder(dir string) (int, error) {
	owner := uint32(os.Geteuid())
	return WalkFolder(dir, true, func(at string, st *unix.Stat_t, last bool) error {
		return CheckFolder(at, uint32(st.Mode), st.Uid, owner, !last)
	})
}

// WalkFolder opens dir from / one name at a time, following no link, and
// calls check on each folder it opened (last: dir itself). mk makes a
// missing folder through the checked folder above it; without mk a
// missing folder is an error, for a folder root must not make (the
// agent's own).
func WalkFolder(dir string, mk bool, check func(at string, st *unix.Stat_t, last bool) error) (int, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return -1, fmt.Errorf("%s: want a clean absolute path", dir)
	}
	fd, err := unix.Open("/", FolderFlags, 0)
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
		next, err := unix.Openat(fd, name, FolderFlags, 0)
		if mk && errors.Is(err, unix.ENOENT) {
			// EEXIST is fine: the open below judges whatever is there.
			if merr := unix.Mkdirat(fd, name, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("make %s: %w", at, merr)
			}
			next, err = unix.Openat(fd, name, FolderFlags, 0)
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

// TmpName is a name for a file before it is ready (a socket before its
// mode is set, a file before its content is written): no one else can
// write the folder, so it only has to differ from what root left there.
func TmpName(name string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "." + name + "." + hex.EncodeToString(b[:]), nil
}

// IsTmpName reports whether n is a name TmpName gives name.
func IsTmpName(n, name string) bool {
	h, ok := strings.CutPrefix(n, "."+name+".")
	if !ok || len(h) != 16 || strings.ToLower(h) != h {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}
