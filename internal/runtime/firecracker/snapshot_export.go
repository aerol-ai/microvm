package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

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

// A stopped sandbox is exported from the disk Stop saved (frozen before the
// pause, so it holds every write). A running one is exported from a copy of
// its live disk, made while the guest holds its root filesystem frozen
// (freeze_fs): programs keep running and only their writes to the disk wait,
// for as long as the copy takes. Docker likewise pauses a container while it
// commits it. Either way the copy's files are read inside a helper VM
// (snapshot_export_vm.go), never by the host kernel.

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

// SetImageStore injects the node's container image store. Without one,
// CreateSnapshot answers not-implemented and a create cannot start a
// snapshot this node holds only locally.
func (d *Driver) SetImageStore(s ImageStore) { d.images = s }

// CreateSnapshot exports a sandbox's root filesystem as the image imageRef in
// the node's image store and returns the image's ID.
//
// A stopped sandbox is exported from the disk Stop saved, which is not
// touched (Start still restores from it). A running one is exported from a
// copy of its disk taken while the guest's root filesystem is frozen. Either
// way a sparse copy is what the helper VM mounts, never the saved disk.
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

// exportDisk makes a working dir and has a helper VM export a copy of the
// sandbox's disk, which fill puts in place, into the image store.
func (d *Driver) exportDisk(ctx context.Context, sandboxID, imageRef, exportBase, state string, fill func(diskCopy string) error) (string, error) {
	if err := os.MkdirAll(exportBase, 0o700); err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	work, err := os.MkdirTemp(exportBase, sandboxID+"-")
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
	}
	// Nothing is ever mounted here (the helper VM reads the disk), so
	// removing it can only remove files.
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			d.logger.Warn("firecracker snapshot: export dir not removed; the next boot removes it", "dir", work, "error", err)
		}
	}()
	id, err := d.exportViaHelper(ctx, sandboxID, imageRef, work, fill)
	if err != nil {
		return "", fmt.Errorf("firecracker runtime: snapshot %s: %w", sandboxID, err)
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

// SweepSnapshotExports removes what an export left behind when the daemon
// stopped in the middle of one: its work dirs under _exports, and the run
// dirs (jail chroots) of its helper VMs. Run at boot after AdoptRunningVMs,
// which kills a helper VM still running, and before any export can start.
func (d *Driver) SweepSnapshotExports() {
	var leftovers []string
	if dir, err := d.snapshotExportDir(); err == nil {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				leftovers = append(leftovers, filepath.Join(dir, entry.Name()))
			}
		}
	}
	// A jailed VM's dir is <base>/<exec name>/<id>; an unjailed one's
	// <run dir>/<id>.
	pattern := filepath.Join(d.cfg.RunDir, exportHelperIDPrefix+"*")
	if d.cfg.UseJailer {
		pattern = filepath.Join(d.cfg.JailerChrootBase, "*", exportHelperIDPrefix+"*")
	}
	if d.cfg.RunDir != "" || d.cfg.UseJailer {
		matches, _ := filepath.Glob(pattern)
		leftovers = append(leftovers, matches...)
	}
	for _, path := range leftovers {
		if err := os.RemoveAll(path); err != nil {
			d.logger.Warn("firecracker snapshot: stale export not removed", "path", path, "error", err)
		}
	}
}
