package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// How sandboxd opens a path it passes to a worker (openGrant). sandboxd is
// root, so a plain open would follow any link on the path: a worker that
// can write one folder on it (its /work, its checkpoint staging folder)
// could put a link there and have root open another tenant's /work or a
// root-only file, then hand it the descriptor. So, when workers drop their
// privileges, a passed path is opened one name at a time from the trusted
// folder it belongs to (GrantPolicy.Roots), never following a link, and
// refused when any folder on the way is one the worker could write: only
// the last name may be the worker's (its /work, a staging folder, a mount's
// root). A regular file must have one name and not be the worker's to
// write; a snapshot file must also be root's.

// GrantPolicy is how passed paths are opened.
type GrantPolicy struct {
	// Roots are the trusted folders passed paths live under: the run dir,
	// the modules dir, the pull cache, the mounts root. The walk starts at
	// the nearest one (followed as configured: it is the operator's); a
	// path under none starts at /.
	Roots []string
	// Worker is the uid/gid workers drop to. Without it, workers run as
	// sandboxd and paths are opened as they always were.
	Worker Confinement
}

var grantPolicy atomic.Pointer[GrantPolicy]

// SetGrantPolicy sets how this sandboxd opens the paths it passes.
func SetGrantPolicy(p GrantPolicy) {
	var roots []string
	for _, r := range p.Roots {
		r = strings.TrimSpace(r)
		if r == "" || !filepath.IsAbs(r) {
			continue
		}
		roots = append(roots, filepath.Clean(r))
		if real, err := filepath.EvalSymlinks(r); err == nil && filepath.Clean(real) != filepath.Clean(r) {
			roots = append(roots, filepath.Clean(real))
		}
	}
	p.Roots = roots
	grantPolicy.Store(&p)
}

var errGrantRefused = errors.New("refused")

// openGrantPath opens path for a grant. strict asks for a file root owns.
func openGrantPath(path string, strict bool) (*os.File, error) {
	p := grantPolicy.Load()
	if p == nil || !p.Worker.Enabled() {
		f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		if st, err := f.Stat(); err != nil || !(st.IsDir() || st.Mode().IsRegular()) {
			_ = f.Close()
			return nil, fmt.Errorf("%s: not a directory or a regular file", path)
		}
		return f, nil
	}
	return walkOpen(path, *p, strict)
}

// walkOpen is the confined open described above.
func walkOpen(path string, p GrantPolicy, strict bool) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("%s: %w: not absolute", path, errGrantRefused)
	}
	root, rel := "/", strings.TrimPrefix(clean, "/")
	for _, r := range p.Roots {
		if r == clean {
			root, rel = r, ""
			break
		}
		if strings.HasPrefix(clean, r+"/") && len(r) > len(root) {
			root, rel = r, strings.TrimPrefix(clean, r+"/")
		}
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	name := root
	if err := checkFolder(fd, root, p.Worker); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	var parts []string
	if rel != "" {
		parts = strings.Split(rel, "/")
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("%s: %w: bad name %q", path, errGrantRefused, part)
		}
		name = filepath.Join(name, part)
		last := i == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if last {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		fd = next
		if !last {
			if err := checkFolder(fd, name, p.Worker); err != nil {
				_ = unix.Close(fd)
				return nil, err
			}
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		// The last name may be the worker's own folder.
	case unix.S_IFREG:
		if uint64(st.Nlink) != 1 || workerWritable(st, p.Worker) || strict && int(st.Uid) != os.Geteuid() {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("%s: %w: a file the worker may change, or one with another name", path, errGrantRefused)
		}
	default:
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s: %w: not a directory or a regular file", path, errGrantRefused)
	}
	return os.NewFile(uintptr(fd), clean), nil
}

// checkFolder refuses a folder on the way that the worker could write: it
// could swap the next name in it.
func checkFolder(fd int, name string, c Confinement) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: name, Err: err}
	}
	if workerWritable(st, c) {
		return fmt.Errorf("%s: %w: a folder the worker can write", name, errGrantRefused)
	}
	return nil
}

// workerWritable reports whether the worker uid (with only its own group)
// may write what st describes.
func workerWritable(st unix.Stat_t, c Confinement) bool {
	mode := uint32(st.Mode)
	return int(st.Uid) == c.UID && mode&0o200 != 0 ||
		int(st.Gid) == c.GID && mode&0o020 != 0 ||
		mode&0o002 != 0
}
