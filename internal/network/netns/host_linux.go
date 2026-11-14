//go:build linux

package netns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

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

// createNamedNetns is `ip netns add <name>` with <root> for /run/netns:
// share the root, create the file, bind a new netns onto it. An existing
// file is success, as the "File exists" the old exec wrapper ignored was.
func createNamedNetns(root, name string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create netns dir %s: %w", root, err)
	}
	if err := shareNetnsRoot(root); err != nil {
		return err
	}
	path := filepath.Join(root, name)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create netns file %s: %w", path, err)
	}
	_ = unix.Close(fd)
	if err := bindNewNetns(path); err != nil {
		// Never leave the empty file behind (iproute2 deletes it too): the
		// next add of this name would take it for a live netns.
		_ = unix.Unmount(path, unix.MNT_DETACH)
		_ = unix.Unlink(path)
		return err
	}
	return nil
}

// shareNetnsRoot makes root a shared mount, so a netns bound under it shows
// in other mount namespaces (a containerd shim's) and its unmount reaches
// them, which lets the kernel free it. iproute2 does this before every add,
// under an flock on the dir: two adds that both find root not yet a mount
// point would otherwise each bind it onto itself, stacking mounts
// (https://bugs.debian.org/949235). flock locks belong to the open file, so
// it also orders this daemon's own concurrent builds (a refill and a
// create's miss) and any `ip netns add` run beside them.
func shareNetnsRoot(root string) error {
	lock, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open netns dir %s: %w", root, err)
	}
	defer func() { _ = unix.Close(lock) }()
	// iproute2 warns and goes on when the lock fails; so does this.
	if unix.Flock(lock, unix.LOCK_EX) == nil {
		defer func() { _ = unix.Flock(lock, unix.LOCK_UN) }()
	}
	madeMount := false
	for {
		err := unix.Mount("", root, "none", unix.MS_SHARED|unix.MS_REC, "")
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EINVAL) || madeMount {
			return fmt.Errorf("mount --make-shared %s: %w", root, err)
		}
		// EINVAL: root is not a mount point yet. Make it one, then share it.
		if err := unix.Mount(root, root, "none", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("mount --bind %s %s: %w", root, root, err)
		}
		madeMount = true
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
func bindNewNetns(path string) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		home, err := bindNewNetnsOnThread(path)
		if home {
			runtime.UnlockOSThread()
		}
		errc <- err
	}()
	return <-errc
}

// bindNewNetnsOnThread is bindNewNetns on the calling thread, which the
// caller has locked. home reports that the thread is back in the namespace
// it started in (or never left it), so it may be unlocked.
func bindNewNetnsOnThread(path string) (home bool, err error) {
	orig, err := netns.Get()
	if err != nil {
		return true, fmt.Errorf("open this thread's netns: %w", err)
	}
	defer func() { _ = orig.Close() }()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return true, fmt.Errorf("unshare a new netns: %w", err)
	}
	// This thread's namespace. /proc/self/ns/net would name the main
	// thread's.
	self := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
	var bindErr error
	if merr := unix.Mount(self, path, "none", unix.MS_BIND, ""); merr != nil {
		bindErr = fmt.Errorf("bind %s -> %s: %w", self, path, merr)
	}
	if serr := netns.Set(orig); serr != nil {
		return false, errors.Join(bindErr, fmt.Errorf("return to the original netns after binding %s: %w", path, serr))
	}
	return true, bindErr
}

// loopbackUpIn is `ip -n <name> link set lo up` for the netns at path, over
// one netlink socket opened inside it. NewHandleAt enters the namespace on
// a locked thread only to open the socket and puts the thread back
// (hostnet's address read works the same way).
func loopbackUpIn(path string) error {
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

// deleteNamedNetns is `ip netns del <name>`: detach the bind mount (its
// error ignored, as in iproute2: the file may not be a mount at all), then
// remove the file. A missing file is success, so delete stays idempotent.
// Any other failure is returned. The old exec wrapper swallowed every
// "Cannot remove namespace file" message, which iproute2 prints for a
// missing file but also for one it could not remove; the pool parks a slot
// whose teardown failed instead of reusing it, so a file still on the node
// is now reported rather than silently handed to the next build.
func deleteNamedNetns(root, name string) error {
	path := filepath.Join(root, name)
	_ = unix.Unmount(path, unix.MNT_DETACH)
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove netns file %s: %w", path, err)
	}
	return nil
}
