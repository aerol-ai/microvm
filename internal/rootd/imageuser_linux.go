//go:build linux

package rootd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// readImageFiles reads an image's /etc/passwd and /etc/group from its
// layer folders (top first) through a detached mount: the kernel's mount
// API (fsopen, fsconfig, fsmount) builds a read-only, nosuid, nodev,
// noexec overlay of the layers and hands back a file descriptor for its
// root, attached to no folder of any mount namespace. Nothing changes
// namespace or folder: no thread, and not the process, so nothing is left
// in a private namespace afterwards, and nothing copies the helper's mount
// table (the cost grew with every sandbox's mounts, #1400 review). The
// mount goes when its descriptor closes, the helper's death included.
//
// Each layer is opened under the snapshots folder with no link followed
// and named to the overlay by its open descriptor (/proc/self/fd/N), so a
// name is never looked up twice, and an image of many layers fits the
// kernel's one page of options. emptyDir, the helper's own empty folder,
// is the bottom layer: an overlay with no upper folder wants two lower
// ones on older kernels, and an empty one changes nothing in the view.
//
// The caller bounds the time (imageUser); this runs on whatever thread.
func readImageFiles(snapshotsDir, emptyDir string, layers []string) (UserFiles, error) {
	if len(layers) == 0 {
		// A snapshot with no parent has no image layer: no files.
		return UserFiles{}, nil
	}
	mfd, err := mountImage(snapshotsDir, emptyDir, layers)
	if err != nil {
		return UserFiles{}, err
	}
	defer func() { _ = unix.Close(mfd) }()
	if imageMountedHook != nil {
		imageMountedHook(mfd)
	}
	return UserFiles{Passwd: readInRoot(mfd, "etc/passwd"), Group: readInRoot(mfd, "etc/group")}, nil
}

// imageMountAttrs are the detached mount's flags.
const imageMountAttrs = unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC

// mountImage builds the detached overlay of layers over emptyDir and
// returns its root's descriptor.
func mountImage(snapshotsDir, emptyDir string, layers []string) (int, error) {
	sfd, err := unix.Open(snapshotsDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("snapshots folder: %w", err)
	}
	defer func() { _ = unix.Close(sfd) }()
	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	beneath := &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS}
	var lower []string
	for _, l := range layers {
		rel, err := filepath.Rel(snapshotsDir, l)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return -1, fmt.Errorf("layer %s is not under %s", l, snapshotsDir)
		}
		fd, err := unix.Openat2(sfd, rel, beneath)
		if err != nil {
			return -1, fmt.Errorf("layer %s: %w", l, err)
		}
		fds = append(fds, fd)
		lower = append(lower, "/proc/self/fd/"+strconv.Itoa(fd))
	}
	efd, err := unix.Open(emptyDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("the empty bottom layer: %w", err)
	}
	fds = append(fds, efd)
	if err := isEmpty(efd); err != nil {
		return -1, fmt.Errorf("the empty bottom layer %s: %w", emptyDir, err)
	}
	lower = append(lower, "/proc/self/fd/"+strconv.Itoa(efd))

	fsfd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("fsopen overlay: %w", err)
	}
	defer func() { _ = unix.Close(fsfd) }()
	if err := unix.FsconfigSetString(fsfd, "lowerdir", strings.Join(lower, ":")); err != nil {
		return -1, fmt.Errorf("overlay lowerdir: %w%s", err, fsLog(fsfd))
	}
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return -1, fmt.Errorf("overlay: %w%s", err, fsLog(fsfd))
	}
	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, imageMountAttrs)
	if err != nil {
		return -1, fmt.Errorf("fsmount: %w%s", err, fsLog(fsfd))
	}
	return mfd, nil
}

// isEmpty checks the bottom layer holds nothing: a file there would show
// through in every image that lacks it. One getdents call.
func isEmpty(fd int) error {
	buf := make([]byte, 4096)
	n, err := unix.Getdents(fd, buf)
	if err != nil {
		return err
	}
	if _, _, names := unix.ParseDirent(buf[:n], -1, nil); len(names) > 0 {
		return fmt.Errorf("holds %s", names[0])
	}
	return nil
}

// fsLog reads what the kernel said about a failed fsconfig or fsmount,
// for the error: a few lines at most.
func fsLog(fsfd int) string {
	var msgs []string
	buf := make([]byte, 512)
	for range 4 {
		n, err := unix.Read(fsfd, buf)
		if err != nil || n <= 0 {
			break
		}
		msgs = append(msgs, strings.TrimSpace(string(buf[:n])))
	}
	if len(msgs) == 0 {
		return ""
	}
	return " (" + strings.Join(msgs, "; ") + ")"
}

// imageMountedHook runs once the image is mounted, with the mount's root;
// tests read the mount's flags there.
var imageMountedHook func(mfd int)

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
