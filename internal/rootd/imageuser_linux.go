//go:build linux

package rootd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// readImageFiles reads an image's /etc/passwd and /etc/group from its
// layer folders (top first) on a thread of its own: the thread takes a
// mount namespace of its own, mounts the layers read-only there, reads,
// and ends with the goroutine, its namespace and mount with it. A read
// that outlives ctx is left to end on its own; the call returns at once.
func readImageFiles(ctx context.Context, snapshotsDir, mountpoint string, layers []string) (UserFiles, error) {
	if len(layers) == 0 {
		// A snapshot with no parent has no image layer: no files.
		return UserFiles{}, nil
	}
	type result struct {
		f   UserFiles
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// Never unlocked: once the thread has a mount namespace of its own
		// it must not run anything else, and the runtime ends a thread
		// whose goroutine exits locked.
		runtime.LockOSThread()
		f, err := readInPrivateMounts(snapshotsDir, mountpoint, layers)
		ch <- result{f, err}
	}()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-ctx.Done():
		return UserFiles{}, ctx.Err()
	}
}

// readInPrivateMounts runs on a locked thread. unshare(CLONE_NEWNS) gives
// the thread its own copy of the mount table (and its own working folder,
// CLONE_FS), and making every mount in it private keeps the mount below
// from reaching the host's.
func readInPrivateMounts(snapshotsDir, mountpoint string, layers []string) (UserFiles, error) {
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return UserFiles{}, fmt.Errorf("a private mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return UserFiles{}, fmt.Errorf("make the private namespace's mounts private: %w", err)
	}
	const flags = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if len(layers) == 1 {
		// overlayfs wants two lower folders when it has no upper one; a
		// single layer is its own folder, bound.
		if err := unix.Mount(layers[0], mountpoint, "", unix.MS_BIND, ""); err != nil {
			return UserFiles{}, fmt.Errorf("bind the image's layer: %w", err)
		}
		defer func() { _ = unix.Unmount(mountpoint, unix.MNT_DETACH) }()
		if err := unix.Mount("", mountpoint, "", unix.MS_BIND|unix.MS_REMOUNT|flags, ""); err != nil {
			return UserFiles{}, fmt.Errorf("make the image's layer read-only: %w", err)
		}
	} else {
		// The layers by their names under the snapshots folder, from
		// there (this thread's own working folder): the kernel takes one
		// page of mount options, which an image's full paths can fill.
		rel := make([]string, len(layers))
		for i, l := range layers {
			r, err := filepath.Rel(snapshotsDir, l)
			if err != nil || strings.HasPrefix(r, "..") {
				return UserFiles{}, fmt.Errorf("layer %s is not under %s", l, snapshotsDir)
			}
			rel[i] = r
		}
		if err := unix.Chdir(snapshotsDir); err != nil {
			return UserFiles{}, err
		}
		if err := unix.Mount("overlay", mountpoint, "overlay", flags, "lowerdir="+strings.Join(rel, ":")); err != nil {
			return UserFiles{}, fmt.Errorf("mount the image's layers: %w", err)
		}
		defer func() { _ = unix.Unmount(mountpoint, unix.MNT_DETACH) }()
	}
	if imageMountedHook != nil {
		imageMountedHook()
	}
	root, err := unix.Open(mountpoint, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return UserFiles{}, err
	}
	defer func() { _ = unix.Close(root) }()
	return UserFiles{Passwd: readInRoot(root, "etc/passwd"), Group: readInRoot(root, "etc/group")}, nil
}

// imageMountedHook runs on the reading thread once the image is mounted;
// tests read the mount's flags there.
var imageMountedHook func()

// readInRoot opens name inside the root folder root, as the image sees
// it: every link, absolute ones too, resolves inside root, and never off
// its mount (openat2 RESOLVE_IN_ROOT, RESOLVE_NO_XDEV). O_NONBLOCK keeps a
// FIFO from holding the open; it is then refused as not a regular file.
func readInRoot(root int, name string) UserFile {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	}
	var fd int
	var err error
	for range 3 { // EAGAIN: a rename raced the walk; nothing renames here
		if fd, err = unix.Openat2(root, name, how); !errors.Is(err, unix.EAGAIN) {
			break
		}
	}
	switch {
	case errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR):
		return UserFile{}
	case err != nil:
		return UserFile{Present: true, Bad: err.Error()}
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return UserFile{Present: true, Bad: err.Error()}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return UserFile{Present: true, Bad: "not a regular file"}
	}
	if st.Size > maxUserFileBytes {
		return UserFile{Present: true, Bad: fmt.Sprintf("%d bytes, past %d", st.Size, maxUserFileBytes)}
	}
	body, err := io.ReadAll(io.LimitReader(f, maxUserFileBytes+1))
	switch {
	case err != nil:
		return UserFile{Present: true, Bad: err.Error()}
	case len(body) > maxUserFileBytes:
		return UserFile{Present: true, Bad: fmt.Sprintf("grew past %d bytes", maxUserFileBytes)}
	}
	return UserFile{Present: true, Body: body}
}
