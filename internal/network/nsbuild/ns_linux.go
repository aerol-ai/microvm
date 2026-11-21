//go:build linux

package nsbuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The namespace steps of a build and a teardown, done in this process. Each
// one repeats what iproute2 does (ip/ipnetns.c: netns_add, on_netns_del;
// ip link set), so the node ends up the same as it did with `ip`: the same
// file at the same path, the same shared mount under it, lo up. Anything
// that reads it (CNI plugins, the containerd shim, `ip netns list`, an
// operator's `ip -n`) sees no difference.

// The calls below that need CAP_SYS_ADMIN, as seams: unit tests run the
// steps' own logic (the share, the bind, the way back, the cleanup) with
// stand-ins and no rights; the root tests run the real calls.
var (
	mount   = unix.Mount
	unshare = unix.Unshare
	nsGet   = netns.Get
	nsSet   = netns.Set
)

// CreateNamed is `ip netns add <name>` with <root> for /run/netns:
// share the root, create the file, bind a new netns onto it. An existing
// file is success, as the "File exists" the old exec wrapper ignored was.
func CreateNamed(root, name string) error {
	return createNamed(nil, root, name, nil)
}

// Mark is how the root helper (privilege mode split) marks what it makes,
// so that it can tell its own from anything else in its netns folder
// whatever state a build was cut short in. Both run before the namespace
// is in the folder: a build cut short leaves nothing unmarked.
type Mark struct {
	// File runs on the new, empty file before it gets its name.
	File func(fd int) error
	// Netns runs on the building thread, inside the new namespace, before
	// the namespace is bound to the file.
	Netns func() error
}

// CreateNamedMarked is CreateNamed for the root helper, with two
// differences. The file and the namespace carry m's marks from the moment
// each is in the folder: the file is made unnamed (O_TMPFILE), marked, and
// only then linked to its name. And the wait for the netns folder's flock
// ends with ctx: it polls a non-blocking lock instead of sleeping in
// flock(2), which would hold an OS thread for as long as another process
// held the lock.
func CreateNamedMarked(ctx context.Context, root, name string, m Mark) error {
	return createNamed(ctx, root, name, &m)
}

// createNamed is both; a nil ctx is CreateNamed's blocking flock, a nil m
// its unmarked file.
func createNamed(ctx context.Context, root, name string, m *Mark) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create netns dir %s: %w", root, err)
	}
	if err := shareNetnsRoot(ctx, root); err != nil {
		return err
	}
	path := filepath.Join(root, name)
	made, err := createFile(root, path, m)
	if !made || err != nil {
		return err
	}
	var inside func() error
	if m != nil {
		inside = m.Netns
	}
	if err := bindNewNetns(path, inside); err != nil {
		// Never leave the empty file behind (iproute2 deletes it too): the
		// next add of this name would take it for a live netns.
		_ = unix.Unmount(path, unix.MNT_DETACH)
		_ = unix.Unlink(path)
		return err
	}
	return nil
}

// createFile makes the empty file a namespace is bound to. made is false
// when a file by that name is there already.
func createFile(root, path string, m *Mark) (made bool, err error) {
	if m == nil || m.File == nil {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("create netns file %s: %w", path, err)
		}
		_ = unix.Close(fd)
		return true, nil
	}
	if _, err := os.Lstat(path); err == nil {
		return false, nil
	}
	fd, err := openUnnamed(root)
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EISDIR) {
		// A filesystem without unnamed files (overlayfs before Linux 6.6).
		return createMarkedNamed(root, path, m)
	}
	if err != nil {
		return false, fmt.Errorf("create netns file in %s: %w", root, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := m.File(fd); err != nil {
		return false, fmt.Errorf("mark netns file %s: %w", path, err)
	}
	// Linking through /proc needs no capability beyond the folder's write
	// right; AT_EMPTY_PATH would need CAP_DAC_READ_SEARCH.
	return linkNew(fmt.Sprintf("/proc/self/fd/%d", fd), path, unix.AT_SYMLINK_FOLLOW)
}

// openUnnamed opens a new file in dir with no name (O_TMPFILE); a seam, so
// tests take the way without it on any filesystem.
var openUnnamed = func(dir string) (int, error) {
	return unix.Open(dir, unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0)
}

// createMarkedNamed is createFile's way without O_TMPFILE: the file is
// made and marked under a name no namespace has (a dot first, which a
// namespace name may not hold), then linked to its own. A build cut short
// in between leaves that marked, empty file, which no call ever names.
func createMarkedNamed(root, path string, m *Mark) (bool, error) {
	tmp := filepath.Join(root, fmt.Sprintf(".%s.%d.new", filepath.Base(path), unix.Gettid()))
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EEXIST) {
		// One a build cut short left: the folder is root's alone.
		_ = unix.Unlink(tmp)
		fd, err = unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return false, fmt.Errorf("create netns file %s: %w", tmp, err)
	}
	defer func() { _ = unix.Unlink(tmp) }()
	merr := m.File(fd)
	_ = unix.Close(fd)
	if merr != nil {
		return false, fmt.Errorf("mark netns file %s: %w", path, merr)
	}
	return linkNew(tmp, path, 0)
}

// linkNew gives the marked file its name; a name already there is no
// error, and nothing is made.
func linkNew(from, path string, flags int) (bool, error) {
	err := unix.Linkat(unix.AT_FDCWD, from, unix.AT_FDCWD, path, flags)
	if errors.Is(err, unix.EEXIST) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create netns file %s: %w", path, err)
	}
	return true, nil
}

// shareNetnsRoot makes root a shared mount, so a netns bound under it shows
// in other mount namespaces (a containerd shim's) and its unmount reaches
// them, which lets the kernel free it. iproute2 does this before every add,
// under an flock on the dir: two adds that both find root not yet a mount
// point would otherwise each bind it onto itself, stacking mounts
// (https://bugs.debian.org/949235). flock locks belong to the open file, so
// it also orders this daemon's own concurrent builds (a refill and a
// create's miss) and any `ip netns add` run beside them.
//
// With ctx (the root helper) the lock is polled without blocking, and the
// wait gives up when ctx ends.
func shareNetnsRoot(ctx context.Context, root string) error {
	lock, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open netns dir %s: %w", root, err)
	}
	defer func() { _ = unix.Close(lock) }()
	if ctx == nil {
		// iproute2 warns and goes on when the lock fails; so does this.
		if unix.Flock(lock, unix.LOCK_EX) == nil {
			defer func() { _ = unix.Flock(lock, unix.LOCK_UN) }()
		}
	} else {
		if err := flockPolling(ctx, lock); err != nil {
			return fmt.Errorf("lock netns dir %s: %w", root, err)
		}
		defer func() { _ = unix.Flock(lock, unix.LOCK_UN) }()
	}
	madeMount := false
	for {
		err := mount("", root, "none", unix.MS_SHARED|unix.MS_REC, "")
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EINVAL) || madeMount {
			return fmt.Errorf("mount --make-shared %s: %w", root, err)
		}
		// EINVAL: root is not a mount point yet. Make it one, then share it.
		if err := mount(root, root, "none", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("mount --bind %s %s: %w", root, root, err)
		}
		madeMount = true
	}
}

// flockPoll paces the polling lock; tests shorten it.
var flockPoll = 2 * time.Millisecond

// flockPolling takes an exclusive flock on fd without ever sleeping in the
// kernel: a held lock is tried again every flockPoll until ctx ends.
func flockPolling(ctx context.Context, fd int) error {
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		t := time.NewTimer(flockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// bindNewNetns creates a network namespace and binds it at path. The
// unshare moves the calling OS thread into the new namespace, so it runs on
// a locked thread of a goroutine of its own, and that thread goes back to
// the namespace it came from before it is unlocked.
//
// Letting the goroutine end while locked, and the runtime take the thread
// with it, is not enough: Go never ends the process's main thread. A locked
// goroutine that ends there wedges it instead, and it stays in the new
// namespace for the life of the process. /proc/<pid>/ns/net names the main
// thread's namespace, so sandboxd then looked, from outside, as if it ran
// in one sandbox's network; and the gVisor address probe, whose task pid 1
// is sandboxd itself in a worker pod, gave every later sandbox on that node
// the wedged sandbox's address, and every create there failed (found on
// kind: "sandbox came up at 10.88.0.6, not at its prepaid address").
//
// Only when the way back fails does the thread stay locked and end with
// the goroutine: no other goroutine may run on a thread in a sandbox's
// namespace.
func bindNewNetns(path string, inside func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		home, err := bindNewNetnsOnThread(path, inside)
		if home {
			runtime.UnlockOSThread()
		}
		errc <- err
	}()
	return <-errc
}

// bindNewNetnsOnThread is bindNewNetns on the calling thread, which the
// caller has locked. home reports that the thread is back in the namespace
// it started in (or never left it), so it may be unlocked. inside, when
// set, runs in the new namespace before the bind; its failure binds
// nothing.
func bindNewNetnsOnThread(path string, inside func() error) (home bool, err error) {
	orig, err := nsGet()
	if err != nil {
		return true, fmt.Errorf("open this thread's netns: %w", err)
	}
	defer func() { _ = orig.Close() }()
	if err := unshare(unix.CLONE_NEWNET); err != nil {
		return true, fmt.Errorf("unshare a new netns: %w", err)
	}
	// This thread's namespace. /proc/self/ns/net would name the main
	// thread's.
	self := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
	var bindErr error
	if inside != nil {
		if ierr := inside(); ierr != nil {
			bindErr = fmt.Errorf("mark the new netns for %s: %w", path, ierr)
		}
	}
	if bindErr == nil {
		if merr := mount(self, path, "none", unix.MS_BIND, ""); merr != nil {
			bindErr = fmt.Errorf("bind %s -> %s: %w", self, path, merr)
		}
	}
	if serr := nsSet(orig); serr != nil {
		return false, errors.Join(bindErr, fmt.Errorf("return to the original netns after binding %s: %w", path, serr))
	}
	return true, bindErr
}

// LoopbackUp is `ip -n <name> link set lo up` for the netns at path, over
// one netlink socket opened inside it. NewHandleAt enters the namespace on
// a locked thread only to open the socket and puts the thread back
// (hostnet's address read works the same way).
func LoopbackUp(path string) error {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", path, err)
	}
	defer func() { _ = ns.Close() }()
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket in %s: %w", path, err)
	}
	defer h.Close()
	lo, err := h.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find lo in %s: %w", path, err)
	}
	if err := h.LinkSetUp(lo); err != nil {
		return fmt.Errorf("set lo up in %s: %w", path, err)
	}
	return nil
}

// DeleteNamed is `ip netns del <name>`: detach the bind mount (its
// error ignored, as in iproute2: the file may not be a mount at all), then
// remove the file. A missing file is success, so delete stays idempotent.
// Any other failure is returned. The old exec wrapper swallowed every
// "Cannot remove namespace file" message, which iproute2 prints for a
// missing file but also for one it could not remove; the pool parks a slot
// whose teardown failed instead of reusing it, so a file still on the node
// is now reported rather than silently handed to the next build.
func DeleteNamed(root, name string) error {
	path := filepath.Join(root, name)
	_ = unix.Unmount(path, unix.MNT_DETACH)
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove netns file %s: %w", path, err)
	}
	return nil
}
