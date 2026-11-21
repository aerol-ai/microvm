//go:build linux

package containerd

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// unpackInChild reports whether build contexts unpack in a child with no
// rights. Only a root sandboxd does it: one that is not root has no root to
// lose, so unpacking in process already runs without it, and it could not
// switch to another uid anyway. A var so tests can force either path.
var unpackInChild = func() bool { return os.Geteuid() == 0 }

// contextUnpackExe is the binary re-exec'd as the unpacker: sandboxd itself,
// which cmd/sandboxd dispatches on ContextUnpackFlag. A var so a test running
// as root can point it at a copy the unpack ids can run.
var contextUnpackExe = os.Executable

// contextUnpackWaitDelay bounds how long Wait waits for the child's stdin and
// stderr pipes once the child has exited or been killed. Inside its PID
// namespace nothing the child started outlives it, so this is the backstop
// for when there is no namespace (a test that is not root). A var so tests
// can shorten it.
var contextUnpackWaitDelay = 5 * time.Second

// contextFD is the descriptor the child finds its folder on: the first of
// exec.Cmd.ExtraFiles.
const contextFD = 3

// contextUnpackStderrMax caps what the parent keeps of the child's stderr.
// The child writes one line on failure; the cap only matters if it misbehaves.
const contextUnpackStderrMax = 4096

// unpackContextInChild unpacks data into dir (which must not exist yet) in a
// child process: sandboxd re-exec'd with ContextUnpackFlag, running as
// uid:gid (ids no other process on the host has, see contextIDPool) with no
// supplementary groups, no capabilities, an empty environment, in a PID
// namespace of its own, with the tar on stdin. The child sets no-new-privs
// and turns dumping off before it reads a byte (RunContextUnpack). dir is
// made 0700 here and handed to uid:gid; the child gets it as an open
// descriptor, not a path, because its parent is root's 0700 temp folder.
//
// The child is PID 1 of its namespace, so when it exits the kernel kills
// anything it started before the parent's wait returns. lockDownContext then
// checks the tree and takes it back for root, on every path. A failed unpack
// removes dir, so the ids own nothing when they go back to the pool.
func unpackContextInChild(ctx context.Context, data []byte, dir string, uid, gid int) error {
	if uid <= 0 || gid <= 0 || int64(uid) > math.MaxUint32 || int64(gid) > math.MaxUint32 {
		return fmt.Errorf("build context unpacker: uid %d / gid %d must be a non-root id", uid, gid)
	}
	exe, err := contextUnpackExe()
	if err != nil {
		return fmt.Errorf("build context unpacker: find the sandboxd binary: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	// O_NOFOLLOW: dir was just made inside a folder only root can enter, but
	// the open that the child will write through must not follow a link.
	folder, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer folder.Close()
	if err := folder.Chown(uid, gid); err != nil {
		return fmt.Errorf("build context unpacker: hand the folder to uid %d: %w", uid, err)
	}

	cmd := exec.CommandContext(ctx, exe, ContextUnpackFlag,
		"--max-entries", strconv.Itoa(maxContextEntries),
		"--max-bytes", strconv.FormatInt(maxContextTotalBytes, 10))
	cmd.Stdin = bytes.NewReader(data)
	stderr := &cappedBuffer{max: contextUnpackStderrMax}
	cmd.Stderr = stderr
	cmd.Env = []string{} // not the daemon's: no token, key or credential reaches the child
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{folder}
	cmd.WaitDelay = contextUnpackWaitDelay
	// A sandboxd that is not root never takes this path outside tests. Such
	// a test can neither call setgroups nor make a PID namespace, and its
	// own groups grant the child nothing it lacks.
	privileged := os.Geteuid() == 0
	attr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
			// Root's supplementary groups are dropped (setgroups with an
			// empty list).
			NoSetGroups: !privileged,
		},
	}
	if privileged {
		attr.Cloneflags = syscall.CLONE_NEWPID
	}
	cmd.SysProcAttr = attr
	runErr := cmd.Run()
	// On every path: the child is gone either way.
	lockErr := lockDownContext(ctx, dir)
	if runErr != nil || lockErr != nil {
		// Not os.RemoveAll: it holds a descriptor per level, and a broken
		// child can leave a chain far deeper than the depth cap.
		_ = removeBuildDir(dir)
	}
	if runErr != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s (%w)", msg, runErr)
		}
		return fmt.Errorf("build context unpacker: %w", runErr)
	}
	if lockErr != nil {
		return fmt.Errorf("build context unpacker: take the folder back: %w", lockErr)
	}
	return nil
}

// lockDownContext checks the unpacked tree and gives it to this process
// (root) before root reads it: buildctl, run by root, sends every file in it
// to buildkitd. It is one pass over folder descriptors (openat, fstatat,
// fchown, fchmod, never a path from the top and never following a link), so
// its cost is linear in entries, and it stops when ctx ends.
//
// Every entry is looked at before anything changes it. extractTarStream only
// makes folders and regular files, so anything else means the child did what
// its code does not, and the walk stops with that entry untouched: a link, a
// pipe (it would hang buildctl), a device, a folder deeper than the cap, or a
// file with a second name (a hard link can name a host file; changing its
// owner or mode here would change the host's).
//
// Each folder is made root's, without group or other write, before it is
// listed, so a descriptor that outlived the child can no longer add, remove
// or rename anything in it, and what is listed is what stays. Each file is
// changed through a descriptor opened without following links and checked to
// be the inode that was looked at. The top folder is 0700; other modes stay
// as the tar set them less group and other write, because COPY carries modes
// into the image. Root owned the tree before unpacking left the daemon, so
// ownership is what builds always saw (RUN --mount=type=bind shows it).
func lockDownContext(ctx context.Context, dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(fd)
	w := &contextWalk{ctx: ctx, uid: os.Geteuid(), gid: os.Getegid()}
	return w.folder(fd, ".", 0, 0o700)
}

// contextWalk is one lockDownContext pass.
type contextWalk struct {
	ctx      context.Context
	uid, gid int
	buf      []byte // getdents, shared: a folder is listed in full before the walk goes down
}

// folder takes the folder open on fd, path levels down, to mode, then walks
// what it holds. It holds one descriptor per level, so depth is capped.
func (w *contextWalk) folder(fd int, path string, depth int, mode uint32) error {
	if depth > maxContextDepth {
		return fmt.Errorf("build context: %q is nested deeper than %d folders", path, maxContextDepth)
	}
	// Owner first: once the unpack uid no longer owns the folder it cannot
	// chmod it back open.
	if err := unix.Fchown(fd, w.uid, w.gid); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	names, err := w.list(fd)
	if err != nil {
		return &os.PathError{Op: "readdir", Path: path, Err: err}
	}
	for _, name := range names {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		sub := name
		if path != "." {
			sub = path + "/" + name
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return &os.PathError{Op: "lstat", Path: sub, Err: err}
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := w.subfolder(fd, name, sub, depth+1, &st); err != nil {
				return err
			}
		case unix.S_IFREG:
			if err := w.file(fd, name, sub, &st); err != nil {
				return err
			}
		default:
			return fmt.Errorf("build context: %q is a %s, not a file or folder", sub, fileKind(st.Mode))
		}
	}
	return nil
}

func (w *contextWalk) subfolder(parent int, name, path string, depth int, st *unix.Stat_t) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	if err := sameEntry(fd, st, path); err != nil {
		return err
	}
	return w.folder(fd, path, depth, (st.Mode&0o777)&^0o022)
}

func (w *contextWalk) file(parent int, name, path string, st *unix.Stat_t) error {
	if st.Nlink > 1 {
		return fmt.Errorf("build context: %q is a hard link", path)
	}
	// O_NONBLOCK and O_NOCTTY: should the entry be swapped for a pipe or a
	// terminal, the open neither hangs nor takes it over; sameEntry refuses it.
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	if err := sameEntry(fd, st, path); err != nil {
		return err
	}
	if err := unix.Fchown(fd, w.uid, w.gid); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}
	if err := unix.Fchmod(fd, (st.Mode&0o777)&^0o022); err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	return nil
}

// sameEntry checks that fd is the entry fstatat looked at, still with one
// name if it is a file.
func sameEntry(fd int, want *unix.Stat_t, path string) error {
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if got.Dev != want.Dev || got.Ino != want.Ino || got.Mode&unix.S_IFMT != want.Mode&unix.S_IFMT {
		return fmt.Errorf("build context: %q changed while it was checked", path)
	}
	if got.Mode&unix.S_IFMT == unix.S_IFREG && got.Nlink > 1 {
		return fmt.Errorf("build context: %q is a hard link", path)
	}
	return nil
}

// list reads every name in the folder open on fd ("." and ".." left out).
func (w *contextWalk) list(fd int) ([]string, error) {
	if w.buf == nil {
		w.buf = make([]byte, 64<<10)
	}
	var names []string
	for {
		n, err := unix.ReadDirent(fd, w.buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return names, nil
		}
		_, _, names = unix.ParseDirent(w.buf[:n], -1, names)
	}
}

// removeBuildDir removes a build's temp folder and everything under it.
var removeBuildDir = func(dir string) error { return removeTreeBounded(dir, removeTreeWindow) }

// removeTreeWindow is how many folder descriptors removeTreeBounded holds at
// most, below the top one.
const removeTreeWindow = 32

// removeTreeBounded removes dir and everything under it, however deep, while
// holding at most window+1 descriptors. os.RemoveAll holds one per level, so
// a chain a broken child made 100,000 levels deep needs 100,000 at once:
// past the daemon's limit the cleanup fails and the tree stays, and well
// below it the daemon runs out of descriptors for everything else. Here a
// folder met at the bottom of the window is moved (renamed, within the tree)
// up into dir itself, and the walk of dir comes back to it later from depth
// one. Each entry is still visited about once, so the cost stays linear. It
// never follows a link: a link is removed as a name.
func removeTreeBounded(dir string, window int) error {
	top, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil
	case errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
		return os.Remove(dir)
	case err != nil:
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	r := &treeRemover{top: top, window: window}
	err = r.empty(top, 0)
	unix.Close(top)
	if err != nil {
		return &os.PathError{Op: "remove", Path: dir, Err: err}
	}
	return os.Remove(dir)
}

type treeRemover struct {
	top, window int
	hoisted     int
	buf         []byte
}

// empty removes everything in the folder open on fd, depth levels below the
// top. It lists the folder again until nothing is left, because folders
// hoisted into the top land there while it is being emptied.
func (r *treeRemover) empty(fd, depth int) error {
	for {
		if _, err := unix.Seek(fd, 0, 0); err != nil {
			return err
		}
		names, err := r.list(fd)
		if err != nil || len(names) == 0 {
			return err
		}
		for _, name := range names {
			err := unix.Unlinkat(fd, name, 0)
			if err == nil || errors.Is(err, unix.ENOENT) {
				continue
			}
			if !errors.Is(err, unix.EISDIR) && !errors.Is(err, unix.EPERM) {
				return err
			}
			if err := r.folder(fd, name, depth+1); err != nil {
				return err
			}
		}
	}
}

// folder removes the folder name inside parent, depth levels below the top,
// or hoists it into the top when the window is full.
func (r *treeRemover) folder(parent int, name string, depth int) error {
	if depth > r.window {
		return r.hoist(parent, name)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = r.empty(fd, depth)
	unix.Close(fd)
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// hoist moves the folder name from parent up into the top folder under a
// name nothing else there has.
func (r *treeRemover) hoist(parent int, name string) error {
	for {
		r.hoisted++
		to := fmt.Sprintf(".aerolvm-rm-%d", r.hoisted)
		err := unix.Renameat2(parent, name, r.top, to, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EINVAL) {
			// A filesystem without RENAME_NOREPLACE. Everything in the top
			// is being removed anyway, so replacing an entry costs nothing.
			err = unix.Renameat(parent, name, r.top, to)
		}
		if !errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.ENOTDIR) {
			return err
		}
	}
}

func (r *treeRemover) list(fd int) ([]string, error) {
	if r.buf == nil {
		r.buf = make([]byte, 64<<10)
	}
	var names []string
	for {
		n, err := unix.ReadDirent(fd, r.buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return names, nil
		}
		_, _, names = unix.ParseDirent(r.buf[:n], -1, names)
	}
}

// staleBuildDirs lists the build temp folders in tmp that this process could
// have made: folders, not links, owned by this euid. /tmp is shared, so
// anything else with the name (another user's folder, a link planted to lure
// root) is left alone.
func staleBuildDirs(tmp string) []string {
	ents, err := os.ReadDir(tmp)
	if err != nil {
		return nil
	}
	var stale []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), buildDirPrefix) || !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Geteuid() {
			stale = append(stale, filepath.Join(tmp, e.Name()))
		}
	}
	return stale
}

// SweepBuildDirs removes the build temp folders a previous run left behind
// (sandboxd stopped mid-build, or a cleanup failed). It lists them now,
// before this run starts any build, and removes them in the background, so
// it adds a directory read to start-up and nothing more. The channel closes
// when it is done.
func (b *BuildKitBuilder) SweepBuildDirs() <-chan struct{} {
	stale := staleBuildDirs(os.TempDir())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, dir := range stale {
			// sticky /tmp: no other user can swap a folder root owns, and the
			// remover opens it without following links anyway.
			if err := removeBuildDir(dir); err != nil {
				b.logger.Warn("could not remove a leftover image-build folder", "dir", dir, "error", err)
				continue
			}
			b.logger.Info("removed a leftover image-build folder", "dir", dir)
		}
	}()
	return done
}

func fileKind(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFIFO:
		return "named pipe"
	case unix.S_IFSOCK:
		return "socket"
	case unix.S_IFCHR, unix.S_IFBLK:
		return "device"
	}
	return fmt.Sprintf("file of type %#o", mode&unix.S_IFMT)
}

// checkContextUnpacker checks what every unpack needs: CAP_SYS_ADMIN, for the
// child's PID namespace (without it the child does not start, by design: a
// process that outlived its unpack would share the next one's id), and a
// sandboxd binary the unpack ids can run. Each error says what to change.
func checkContextUnpacker() error {
	if !pidNamespaceAllowed() {
		return errors.New("sandboxd lacks CAP_SYS_ADMIN, which each unpack's PID namespace needs: run sandboxd as full root, as the systemd unit install.sh writes does")
	}
	exe, err := contextUnpackExe()
	if err != nil {
		return fmt.Errorf("find the sandboxd binary: %w", err)
	}
	if err := checkRunnableByOthers(exe); err != nil {
		return fmt.Errorf("%w; install sandboxd where every user can enter each folder above it and run it (install.sh --install-prefix, default /usr/local/bin), or chmod o+x it", err)
	}
	return nil
}

// pidNamespaceAllowed reports whether clone(CLONE_NEWPID) can work here. A
// var so tests can answer either way.
var pidNamespaceAllowed = haveCapSysAdmin

func haveCapSysAdmin() bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	return data[0].Effective&(1<<unix.CAP_SYS_ADMIN) != 0
}

// checkRunnableByOthers checks the "other" bits, the only ones the unpack ids
// get: they own nothing and are in no group. Execute on the binary, and on
// every folder above it.
func checkRunnableByOthers(exe string) error {
	info, err := os.Stat(exe)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o001 == 0 {
		return fmt.Errorf("%s is mode %v: other users cannot run it", exe, info.Mode())
	}
	for dir := filepath.Dir(exe); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("%s is mode %v: other users cannot enter it to reach %s", dir, info.Mode(), exe)
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

// RunContextUnpack is the child half: `sandboxd --build-context-unpack
// --max-entries N --max-bytes N`, started by unpackContextInChild already
// running as the build-context uid. It reads the context tar on stdin and
// unpacks it into the folder open on contextFD, then exits.
func RunContextUnpack(args []string) error {
	// Not dumpable first. The uid is this child's alone (contextIDPool), so
	// no other non-root process can ptrace it or open its /proc fd and cwd
	// links anyway; this keeps that so should an id ever be shared.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("build context unpacker: set not dumpable: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("build context unpacker: no_new_privs: %w", err)
	}
	// The parent set the uid; check it took. A child that is root is the
	// bug this mode exists to prevent, so it refuses rather than unpack.
	if err := refuseRootIDs(unix.Getuid(), unix.Geteuid(), unix.Getgid(), unix.Getegid()); err != nil {
		return err
	}
	if err := unix.Setresuid(0, 0, 0); err == nil {
		return errors.New("build context unpacker: could regain root after the drop")
	}
	maxEntries, maxBytes, err := parseContextUnpackArgs(args)
	if err != nil {
		return err
	}
	folder := os.NewFile(contextFD, "build-context")
	if err := folder.Chdir(); err != nil {
		return fmt.Errorf("build context unpacker: enter the context folder: %w", err)
	}
	_ = folder.Close()
	return extractTarStream(os.Stdin, ".", maxEntries, maxBytes)
}

// refuseRootIDs fails if any of the ids is root's.
func refuseRootIDs(uid, euid, gid, egid int) error {
	if uid == 0 || euid == 0 || gid == 0 || egid == 0 {
		return fmt.Errorf("build context unpacker: refusing to run as root (uid %d euid %d gid %d egid %d)", uid, euid, gid, egid)
	}
	return nil
}

// parseContextUnpackArgs reads the bounds the parent passes. Both are
// required: the child has no defaults of its own to fall back on.
func parseContextUnpackArgs(args []string) (int, int64, error) {
	set := flag.NewFlagSet(ContextUnpackFlag, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	maxEntries := set.Int("max-entries", 0, "")
	maxBytes := set.Int64("max-bytes", 0, "")
	if err := set.Parse(args); err != nil {
		return 0, 0, fmt.Errorf("build context unpacker: %w", err)
	}
	if set.NArg() != 0 {
		return 0, 0, fmt.Errorf("build context unpacker: unexpected arguments %q", set.Args())
	}
	if *maxEntries <= 0 || *maxBytes <= 0 {
		return 0, 0, errors.New("build context unpacker: --max-entries and --max-bytes must both be > 0")
	}
	return *maxEntries, *maxBytes, nil
}

// cappedBuffer keeps the first max bytes written to it and drops the rest,
// so a child that writes without end cannot grow the daemon's memory.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }
