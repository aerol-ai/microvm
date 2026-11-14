package containerd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/containerd/v2/core/mount"
)

// DiskGB on the containerd engine (C27, spike S8). Each sandbox's writable
// layer goes in an XFS project of its own with a hard block limit of
// DiskGB. On runc the sandbox's writes land in the overlay snapshot's upper
// directory; on gVisor the root overlay's file store is a file there. Either
// way the sandbox sees an ordinary "no space left".
//
// The project covers the whole snapshot directory, snapshots/<n>, so its
// work directory too, not only the upper one (fs): overlayfs copies a file
// up by making it in work and renaming it into fs, and XFS refuses a rename
// into a directory of another project with EXDEV ("invalid cross-device
// link"). Docker's overlay2 quota tags the layer directory for the same
// reason. Found live: runsc could not set up a bind mount in a limited
// gVisor sandbox.
//
// The project ID is the snapshot's number (snapshots/<n>/fs): containerd's
// overlay snapshotter takes it from a sequence that never repeats, so IDs are
// unique and need no table of their own, and a retry finds the same one.
// That is also why the volume must not carry anyone else's project IDs. A
// sandbox's ID is not reused after it is gone, so its limit is left in
// place rather than cleared on destroy.

// projectQuota is the XFS project-quota surface the limit needs
// (disk_quota_linux.go). Tests substitute a fake.
type projectQuota interface {
	// Enforced returns nil when dir's filesystem enforces project quotas.
	Enforced(dir string) error
	// Assign puts dir and everything under it in project id, and marks each
	// directory so what is created in it later joins the project too.
	Assign(dir string, id uint32) error
	// Limit sets project id's hard block limit, in bytes, on dir's filesystem.
	Limit(dir string, id uint32, bytes uint64) error
}

var diskQuotaOps projectQuota = xfsProjectQuota{}

// snapshotMounter is the snapshotter surface that names a snapshot's
// directories. Tests inject a fake.
type snapshotMounter interface {
	Mounts(ctx context.Context, key string) ([]mount.Mount, error)
}

// snapshotMountsFn resolves the default snapshotter, the one
// cntr.WithNewSnapshot prepares every sandbox's snapshot on.
var snapshotMountsFn = func(client *Client) snapshotMounter {
	if client == nil || client.Raw() == nil {
		return nil
	}
	if s := client.Raw().SnapshotService(""); s != nil {
		return s
	}
	return nil
}

// writableLayerDir finds an active overlay snapshot's upper directory in its
// mounts, and the snapshot's number. A snapshot with layers below it mounts
// as overlay with upperdir=; one with none is a bind of the directory itself.
func writableLayerDir(mounts []mount.Mount) (string, uint32, error) {
	dir := ""
	for _, m := range mounts {
		for _, opt := range m.Options {
			if v, ok := strings.CutPrefix(opt, "upperdir="); ok {
				dir = v
			}
		}
		if dir == "" && m.Type == "bind" {
			dir = m.Source
		}
	}
	if dir == "" {
		return "", 0, errors.New("disk limit: the snapshot has no writable directory (SB_CONTAINERD_DISK_QUOTA needs the overlayfs snapshotter)")
	}
	dir = filepath.Clean(dir)
	parent := filepath.Dir(dir)
	if filepath.Base(dir) != "fs" || filepath.Base(filepath.Dir(parent)) != "snapshots" {
		return "", 0, fmt.Errorf("disk limit: %s is not an overlayfs snapshot's directory (SB_CONTAINERD_DISK_QUOTA needs the overlayfs snapshotter)", dir)
	}
	n, err := strconv.ParseUint(filepath.Base(parent), 10, 32)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("disk limit: snapshot number %q is not a usable project ID", filepath.Base(parent))
	}
	return dir, uint32(n), nil
}

// limitWritableLayer gives the snapshot named key a hard limit of diskGB. It
// runs before the sandbox gets its identity: after NewContainer on a cold
// create, before the adopt on a warm one. A parked slot's layer already
// holds files, which Assign moves into the project too. Calling it again
// for the same snapshot sets the same project and limit.
func (d *Driver) limitWritableLayer(ctx context.Context, client *Client, key string, diskGB int) error {
	if !d.cfg.DiskQuota || diskGB <= 0 {
		return nil
	}
	s := snapshotMountsFn(client)
	if s == nil {
		return errors.New("disk limit: containerd has no snapshotter")
	}
	mounts, err := s.Mounts(client.withNS(ctx), key)
	if err != nil {
		return fmt.Errorf("disk limit: snapshot %q: %w", key, err)
	}
	upper, id, err := writableLayerDir(mounts)
	if err != nil {
		return err
	}
	dir := filepath.Dir(upper) // snapshots/<n>: fs and work (see above)
	if err := d.ensureDiskQuotaReady(dir); err != nil {
		return err
	}
	if err := diskQuotaOps.Assign(dir, id); err != nil {
		return fmt.Errorf("disk limit: project %d on %s: %w", id, dir, err)
	}
	if err := diskQuotaOps.Limit(dir, id, uint64(diskGB)<<30); err != nil {
		return fmt.Errorf("disk limit: %d GB on project %d: %w", diskGB, id, err)
	}
	return nil
}

// ensureDiskQuotaReady checks once that the snapshots' filesystem enforces
// project quotas: a volume mounted without prjquota (or with pqnoenforce)
// accepts every limit and enforces none, which is the silent failure this
// setting must not have. A failed check is not latched, so a fixed mount is
// picked up by the next create without a restart. The same lazy-latch shape
// as Service.EnsureLayer4Ready.
func (d *Driver) ensureDiskQuotaReady(dir string) error {
	if d.diskQuotaReady.Load() {
		return nil
	}
	d.diskQuotaMu.Lock()
	defer d.diskQuotaMu.Unlock()
	if d.diskQuotaReady.Load() {
		return nil
	}
	if err := diskQuotaOps.Enforced(dir); err != nil {
		return fmt.Errorf("disk limit: SB_CONTAINERD_DISK_QUOTA is on, but %s does not enforce project quotas (XFS mounted with prjquota, Linux 5.14 or later): %w", dir, err)
	}
	d.diskQuotaReady.Store(true)
	return nil
}
