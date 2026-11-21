//go:build linux

package gate

import (
	"fmt"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

func defaultStdioChecker() StdioChecker { return hostPaths{owner: 0} }
func defaultBindChecker() BindChecker   { return hostPaths{owner: 0} }
func defaultReadChecker() ReadChecker   { return hostPaths{owner: 0} }

// hostPaths checks the host paths the shim and runc will open as root.
// It walks each path from / one name at a time with openat2, refusing any
// symlink on the way, and judges each folder and the leaf through the
// handle it opened, so what it judges is what the path names. owner is
// root, or the test's own user.
type hostPaths struct{ owner uint32 }

const resolveStrict = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// walkHostPath opens p from / and calls folder for / and every folder on the way
// (with the path so far) and leaf for the last name.
func walkHostPath(p string, folder func(at string, st *unix.Stat_t) error, leaf func(st *unix.Stat_t) error) error {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return fmt.Errorf("not a clean absolute path")
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if err := folder("/", &st); err != nil {
		return err
	}
	parts := strings.Split(p[1:], "/")
	at := ""
	for i, name := range parts {
		next, err := unix.Openat2(fd, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: resolveStrict})
		if err != nil {
			return fmt.Errorf("open %s: %w", name, err)
		}
		_ = unix.Close(fd)
		fd = next
		at += "/" + name
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if i < len(parts)-1 {
			err = folder(at, &st)
		} else {
			err = leaf(&st)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// folderOK: a folder owned by root (or owner) that no one else can write,
// or a sticky one, where no one else can rename what root put there. The
// rule is rootpolicy.CheckFolder, which the helper's socket uses too.
func (h hostPaths) folderOK(at string, st *unix.Stat_t, sticky bool) error {
	return rootpolicy.CheckFolder(at, st.Mode, st.Uid, h.owner, sticky)
}

// CheckStdio accepts a FIFO owned by root, reached through folders only
// root can change.
func (h hostPaths) CheckStdio(p string) error {
	err := walkHostPath(p, func(at string, st *unix.Stat_t) error { return h.folderOK(at, st, true) },
		func(st *unix.Stat_t) error {
			if st.Mode&unix.S_IFMT != unix.S_IFIFO {
				return fmt.Errorf("not a FIFO (mode %o)", st.Mode)
			}
			if st.Uid != h.owner {
				return fmt.Errorf("the FIFO belongs to uid %d, not %d", st.Uid, h.owner)
			}
			return nil
		})
	if err != nil {
		return stdioViolation(p, "%v", err)
	}
	return nil
}

// CheckBind accepts a bind source that is a regular file with one link, a
// socket (a sandbox's ready socket), or, where folder allows it, a folder,
// reached with no link on the way. Every folder from root down to the
// source must be owned by root and writable by no one else, sticky or
// not: then the agent cannot swap the source for a link between this check
// and runc's mount. Folders above root follow the FIFO rule.
//
// A folder is refused unless folder says so (rootpolicy.BindRootFor: only
// the external mounts). A folder bound into a sandbox, which runs as uid 0,
// is one it can write, and so swap names in, unless it is bound read-only;
// the helper's folders must stay root's alone.
func (h hostPaths) CheckBind(root, src string, folder bool) error {
	err := walkHostPath(src, func(at string, st *unix.Stat_t) error {
		return h.folderOK(at, st, !(at == root || strings.HasPrefix(at, root+"/")))
	}, func(st *unix.Stat_t) error {
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if !folder {
				return fmt.Errorf("a folder, where only a file may be bound")
			}
			return nil
		case unix.S_IFSOCK:
			return nil
		case unix.S_IFREG:
			if st.Nlink > 1 {
				return fmt.Errorf("the file has %d hard links", st.Nlink)
			}
			return nil
		default:
			return fmt.Errorf("not a regular file, folder or socket (mode %o)", st.Mode)
		}
	})
	if err != nil {
		return bindViolation(src, "%v", err)
	}
	return nil
}

// CheckRead accepts a file or folder root will read because the agent
// named it (a runsc config, a restore image): reached with no link on the
// way, through folders only root can change, and itself root's and
// writable by no one else. A runsc config the agent could write names the
// binary runsc runs as root (review H2), so the name being on the policy's
// list is not enough.
func (h hostPaths) CheckRead(r rootpolicy.RootRead) error {
	err := walkHostPath(r.Path, func(at string, st *unix.Stat_t) error { return h.folderOK(at, st, true) },
		func(st *unix.Stat_t) error {
			switch kind := st.Mode & unix.S_IFMT; {
			case r.Folder && kind != unix.S_IFDIR:
				return fmt.Errorf("not a folder (mode %o)", st.Mode)
			case !r.Folder && kind != unix.S_IFREG:
				return fmt.Errorf("not a regular file (mode %o)", st.Mode)
			case !r.Folder && st.Nlink > 1:
				return fmt.Errorf("the file has %d hard links", st.Nlink)
			case st.Uid != 0 && st.Uid != h.owner:
				return fmt.Errorf("it belongs to uid %d", st.Uid)
			case st.Mode&0o022 != 0:
				return fmt.Errorf("others can write it (mode %o)", st.Mode&0o7777)
			}
			return nil
		})
	if err != nil {
		return readViolation(r, "%v", err)
	}
	return nil
}
