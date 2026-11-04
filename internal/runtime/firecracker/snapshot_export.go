package firecracker

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A Firecracker snapshot is the sandbox's root filesystem as a one-layer
// container image. It goes into the node's image store (Docker or
// containerd), so everything a container snapshot gets works unchanged: the
// catalogue row, the registry push, the delete, image GC, and a create from
// it on any node, as a Firecracker or a container sandbox.
//
// It is the disk only, like a Docker commit. The memory is left out: it holds
// the sandbox's environment variables (API keys included), and a memory
// snapshot only restores on a host with a compatible CPU and the same
// Firecracker. The overlay disk (/dev/vdb) is left out too: it is a separate
// data disk the guest mounts itself, like a container volume.

// A stopped sandbox is exported from the disk Stop saved. A running one is
// exported from a copy of its live disk, made while the guest holds its root
// filesystem frozen (freeze_fs): programs keep running and only their writes
// to the disk wait, for as long as the copy takes. Docker likewise pauses a
// container while it commits it.

// snapshotExportDirName holds each export's working files under the
// templates dir, on the same filesystem as the saved disk so its copy is
// cheap.
const snapshotExportDirName = "_exports"

// snapshotExportExcluded are the files cold boot writes into every disk
// (coldBootInjectFiles). /etc/toolboxd.env holds the sandbox's toolbox token,
// its credential; the others describe this sandbox only. A Firecracker create
// from the snapshot writes fresh ones, and a container create mounts its own
// agent. /lost+found is ext4's, not the image's.
var snapshotExportExcluded = map[string]bool{
	guestEnvPath:     true,
	guestToolboxPath: true,
	guestInitPath:    true,
	guestResolvPath:  true,
	"/lost+found":    true,
}

var (
	// errSnapshotNoDisk: neither a running VM nor a disk saved by Stop.
	errSnapshotNoDisk = fmt.Errorf("this sandbox has no running VM and no saved disk to take a snapshot of; start it or stop it first: %w", models.ErrSnapshotSourceNotReady)
	// errSnapshotNotFlushed: the saved disk may miss writes that were still
	// in the guest's page cache; the agent can flush, it just did not.
	errSnapshotNotFlushed = fmt.Errorf("this sandbox's disk was not flushed when it last stopped, so a snapshot could miss files; start it and stop it again, then take the snapshot: %w", models.ErrSnapshotSourceNotReady)
	// errSnapshotAgentTooOld: the agent can neither flush nor freeze. It is
	// the agent the sandbox was created with, for life (Start restores its
	// memory), so no Stop or Start fixes it.
	errSnapshotAgentTooOld = fmt.Errorf("this sandbox was created by an older release whose agent cannot flush or pause its disk, so its snapshot could miss files; sandboxes created on this release can be snapshotted: %w", models.ErrSnapshotSourceNotReady)
	// errSnapshotSourceGone: the VM stopped or went away while the snapshot
	// waited for it.
	errSnapshotSourceGone = fmt.Errorf("the sandbox stopped while the snapshot waited for it; take the snapshot again: %w", models.ErrSnapshotSourceNotReady)
)

// guestFreezeLimit is how long the guest holds a freeze_fs before thawing on
// its own, in case this host dies mid-copy. A copy that takes longer is
// discarded: the disk may have changed under it. 10 minutes copies roughly
// 80 GB of data at a gp3 volume's 135 MB/s baseline. A var for tests.
var guestFreezeLimit = 10 * time.Minute

const (
	// guestFreezeMargin allows for the guest's timer starting before the
	// host sees the freeze ack.
	guestFreezeMargin = 15 * time.Second
	// guestThawTimeout bounds one thaw_fs attempt.
	guestThawTimeout = 10 * time.Second
)

// DiskMounter mounts an ext4 image file on a directory. The production
// implementation is the host's mount(8) with a loop device; tests use a
// plain directory.
type DiskMounter interface {
	Mount(ctx context.Context, image, dir string) (unmount func() error, err error)
}

// SetImageStore injects the node's container image store. Without one,
// CreateSnapshot answers not-implemented and a create cannot start a
// snapshot this node holds only locally.
func (d *Driver) SetImageStore(s ImageStore) { d.images = s }

// SetDiskMounter replaces the loop mounter (tests).
func (d *Driver) SetDiskMounter(m DiskMounter) { d.mounter = m }

// CreateSnapshot exports a sandbox's root filesystem as the image imageRef in
// the node's image store and returns the image's ID.
//
// A stopped sandbox is exported from the disk Stop saved, which is not
// touched (Start still restores from it). A running one is exported from a
// copy of its disk taken while the guest's root filesystem is frozen. Either
// way a sparse copy is what gets mounted, which also lets ext4 replay its
// journal into the copy.
func (d *Driver) CreateSnapshot(ctx context.Context, sandboxID, imageRef string) (string, error) {
	if err := validateSandboxID(sandboxID); err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot: %w", err)
	}
	if d.images == nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: no image store registered: %w",
			sandboxID, models.ErrRuntimeNotImplemented)
	}
	exportBase, err := d.snapshotExportDir()
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	d.mu.Lock()
	_, running := d.vmms[sandboxID]
	d.mu.Unlock()
	if running {
		return d.exportDisk(ctx, sandboxID, imageRef, exportBase, "running", func(diskCopy string) error {
			return d.copyRunningDisk(ctx, sandboxID, diskCopy)
		})
	}
	manifest, err := d.readSandboxSnapshotManifest(sandboxID)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, errSnapshotNoDisk)
	}
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	switch manifest.GuestFlush {
	case guestFlushDone:
	case guestFlushFailed:
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, errSnapshotNotFlushed)
	default:
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, errSnapshotAgentTooOld)
	}
	_, _, _, savedRootfs, _, _ := d.sandboxSnapshotPaths(sandboxID)
	return d.exportDisk(ctx, sandboxID, imageRef, exportBase, "stopped", func(diskCopy string) error {
		if err := copyFile(savedRootfs, diskCopy); err != nil {
			return fmt.Errorf("copy saved disk: %w", err)
		}
		return nil
	})
}

// exportDisk makes a working dir, has fill put a copy of the sandbox's disk
// in it, mounts the copy and streams it into the image store as a tar.
func (d *Driver) exportDisk(ctx context.Context, sandboxID, imageRef, exportBase, state string, fill func(diskCopy string) error) (string, error) {
	if err := os.MkdirAll(exportBase, 0o700); err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	work, err := os.MkdirTemp(exportBase, sandboxID+"-")
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			d.logger.Warn("firecracker snapshot: export dir not removed", "dir", work, "error", err)
		}
	}()

	diskCopy := filepath.Join(work, rootfsFileName)
	if err := fill(diskCopy); err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	mountDir := filepath.Join(work, "mnt")
	if err := os.Mkdir(mountDir, 0o700); err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	unmount, err := d.diskMounter().Mount(ctx, diskCopy, mountDir)
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: mount disk copy: %w", sandboxID, err)
	}
	defer func() {
		if err := unmount(); err != nil {
			d.logger.Warn("firecracker snapshot: export mount not removed", "dir", mountDir, "error", err)
		}
	}()

	reader, writer := io.Pipe()
	go func() { writer.CloseWithError(writeRootfsTar(writer, mountDir)) }()
	id, err := d.images.ImportRootfs(ctx, imageRef, reader)
	// Ends the tar writer if the import stopped reading early.
	_ = reader.CloseWithError(errors.New("import finished"))
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: import image %s: %w", sandboxID, imageRef, err)
	}
	d.logger.Info("firecracker snapshot: exported sandbox",
		"sandbox_id", sandboxID, "state", state, "image", imageRef, "image_id", id)
	return id, nil
}

// copyRunningDisk copies a running VM's disk to diskCopy while the guest
// holds its root filesystem frozen. It holds the VM's gate, so a Stop waits
// for the thaw instead of saving a frozen VM. The image is built from the
// copy after the thaw, so the pause is the copy alone.
func (d *Driver) copyRunningDisk(ctx context.Context, sandboxID, diskCopy string) error {
	release, err := d.gate.lock(ctx, sandboxID)
	if err != nil {
		return err
	}
	defer release()
	d.mu.Lock()
	handle, running := d.vmms[sandboxID]
	guestCID := d.guestCID[sandboxID]
	d.mu.Unlock()
	if !running {
		// A Stop that held the gate first saved and removed the VM.
		return errSnapshotSourceGone
	}
	if guestCID < 3 && d.pool != nil {
		if slot, err := d.pool.Get(ctx, sandboxID); err == nil && slot != nil {
			guestCID = slot.VsockCID
		}
	}
	if guestCID < 3 {
		return fmt.Errorf("no vsock CID recorded for the running VM")
	}
	vsockPath := filepath.Join(handle.RunDir(), hostVsockUDSName)
	if err := d.freezeGuest(ctx, sandboxID, vsockPath, guestCID); err != nil {
		return err
	}
	frozenAt := time.Now()
	copyErr := copyFile(filepath.Join(handle.RunDir(), rootfsFileName), diskCopy)
	paused := time.Since(frozenAt)
	d.thawGuest(sandboxID, vsockPath, guestCID)
	if copyErr != nil {
		return fmt.Errorf("copy running disk: %w", copyErr)
	}
	if paused > guestFreezeLimit-guestFreezeMargin {
		return fmt.Errorf("copying the disk took %s and the guest lifts a freeze after %s, so the disk may have changed while it was copied",
			paused.Round(time.Second), guestFreezeLimit)
	}
	d.logger.Info("firecracker snapshot: running sandbox's writes paused for the disk copy",
		"sandbox_id", sandboxID, "pause_ms", paused.Milliseconds())
	return nil
}

// freezeGuest asks the guest to flush and freeze its root filesystem. The
// freeze itself flushes, so it can take a while with a lot of dirty data.
func (d *Driver) freezeGuest(ctx context.Context, sandboxID, vsockPath string, guestCID uint32) error {
	err := d.sendVsockOpAckWithin(ctx, guestSyncTimeout, vsockPath, guestCID, "freeze_fs",
		map[string]int64{"thaw_after_ms": guestFreezeLimit.Milliseconds()})
	switch {
	case err == nil:
		return nil
	case isUnknownOp(err):
		return errSnapshotAgentTooOld
	default:
		// Only the ack may have been lost; thaw so a freeze that did land
		// does not last until the guest's own timer.
		d.thawGuest(sandboxID, vsockPath, guestCID)
		return fmt.Errorf("freeze the guest's filesystem: %w", err)
	}
}

// thawGuest releases a freeze, retrying, and never with the caller's
// context: a cancelled request must not leave the sandbox unable to write.
// If every attempt fails, the guest's safety timer thaws it. An agent that
// does not know thaw_fs cannot have frozen anything.
func (d *Driver) thawGuest(sandboxID, vsockPath string, guestCID uint32) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = d.sendVsockOpAckWithin(context.Background(), guestThawTimeout, vsockPath, guestCID, "thaw_fs", nil)
		if err == nil || isUnknownOp(err) {
			return
		}
	}
	d.logger.Error("firecracker snapshot: guest filesystem not thawed; the guest lifts the freeze itself",
		"sandbox_id", sandboxID, "within", guestFreezeLimit, "error", err)
}

// snapshotExportDir is where exports keep their working files: next to the
// saved sandboxes, on the same filesystem, so the disk copy stays sparse.
func (d *Driver) snapshotExportDir() (string, error) {
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(base), snapshotExportDirName), nil
}

func (d *Driver) diskMounter() DiskMounter {
	if d.mounter != nil {
		return d.mounter
	}
	return loopMounter{}
}

// loopMounter mounts with mount(8) and a loop device. Read-write, on a copy:
// a read-only loop device would refuse the journal replay a disk saved from
// a paused VM may need.
type loopMounter struct{}

func (loopMounter) Mount(ctx context.Context, image, dir string) (func() error, error) {
	if out, err := exec.CommandContext(ctx, "mount", "-o", "loop,noatime,nodev,nosuid", image, dir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("mount %s: %w: %s", image, err, strings.TrimSpace(string(out)))
	}
	return func() error {
		// Its own context: the caller's may already be cancelled, and a
		// mount left behind holds the loop device.
		uctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(uctx, "umount", dir).CombinedOutput(); err != nil {
			return fmt.Errorf("umount %s: %w: %s", dir, err, strings.TrimSpace(string(out)))
		}
		return nil
	}, nil
}

// writeRootfsTar writes the tree under root as a tar stream that keeps what
// a container image layer needs: numeric owners, modes, symlinks, hard links,
// device and fifo nodes, and extended attributes (file capabilities such as
// ping's live in security.capability). The excluded paths and sockets are
// left out.
func writeRootfsTar(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	seen := map[[2]uint64]string{} // (dev, inode) of files with several links -> first name
	xattrBuf := make([]byte, xattrMax)
	// Not os.DirFS: it refuses names that are not UTF-8, and a guest may
	// have any bytes in its file names.
	root = filepath.Clean(root)
	prefix := root + string(filepath.Separator)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, prefix))
		guestPath := "/" + rel
		if snapshotExportExcluded[guestPath] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		// A socket is only a name for a listener that died with the VM, and
		// tar cannot hold one; docker export leaves them out too.
		if info.Mode()&fs.ModeSocket != 0 {
			return nil
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("%s: %w", guestPath, err)
		}
		hdr.Name = rel
		if info.IsDir() {
			hdr.Name += "/"
		}
		// Numeric owners: the host's user names mean nothing in the image.
		hdr.Uname, hdr.Gname = "", ""
		if st, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode().IsRegular() && st.Nlink > 1 {
			key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
			if first, ok := seen[key]; ok {
				hdr.Typeflag, hdr.Linkname, hdr.Size = tar.TypeLink, first, 0
			} else {
				seen[key] = hdr.Name
			}
		}
		if xattrs := readXattrs(path, xattrBuf); len(xattrs) > 0 {
			hdr.PAXRecords = map[string]string{}
			for name, value := range xattrs {
				hdr.PAXRecords["SCHILY.xattr."+name] = value
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("%s: %w", guestPath, err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", guestPath, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// xattrMax is Linux's cap on both an attribute name list and one value
// (XATTR_LIST_MAX, XATTR_SIZE_MAX), so one buffer this size always fits.
const xattrMax = 64 << 10

// readXattrs returns path's extended attributes, or none where the
// filesystem or platform has none to give. buf is scratch space of xattrMax
// bytes, reused across calls. A missing attribute only loses what the image
// could carry, so errors are not fatal.
func readXattrs(path string, buf []byte) map[string]string {
	size, err := unix.Llistxattr(path, buf)
	if err != nil || size <= 0 {
		return nil
	}
	names := strings.Split(strings.TrimRight(string(buf[:size]), "\x00"), "\x00")
	out := map[string]string{}
	for _, name := range names {
		n, err := unix.Lgetxattr(path, name, buf)
		if err != nil {
			continue
		}
		out[name] = string(buf[:n])
	}
	return out
}

// SweepSnapshotExports removes what an export left behind when the daemon
// stopped in the middle of one: its working dirs under _exports, the disk
// copy each holds, and the loop mount on it. Run at boot, before any export
// can start. A mount left in place would hold a loop device until reboot.
func (d *Driver) SweepSnapshotExports() {
	dir, err := d.snapshotExportDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			// Not mounted is the common case; umount then just fails.
			_ = exec.Command("umount", filepath.Join(path, "mnt")).Run()
		}
		if err := os.RemoveAll(path); err != nil {
			d.logger.Warn("firecracker snapshot: stale export not removed", "path", path, "error", err)
		}
	}
}
