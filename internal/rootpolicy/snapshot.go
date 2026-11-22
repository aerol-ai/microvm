package rootpolicy

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The root helper's container parts that read a container's root
// filesystem snapshot (M1 PR 7, plan §3.3 "Images" and "Disk"). The agent
// names a container; its snapshot has the container's own key
// (cntr.WithNewSnapshot), and the helper asks containerd, in its own
// namespace and under its own snapshotter, for the snapshot's mounts. The
// rules below take those mounts, which containerd gave the helper, never
// the agent, and derive every host path from them: each one must be a
// layer's own folder under the snapshotter's root (layerDir).

const (
	// RuleSnapshot: the named snapshot is not an active one of the
	// helper's namespace and snapshotter.
	RuleSnapshot Rule = "snapshot"
	// RuleImageUser: an image's USER the helper will not resolve.
	RuleImageUser Rule = "image_user"
	// RuleDiskQuota: a disk quota the helper will not set.
	RuleDiskQuota Rule = "disk_quota"
)

// MaxImageUserLen bounds an image's USER. containerd takes "user",
// "uid", "user:group" and the like; a name is at most 32 bytes on most
// systems, so this is a bound, not a limit anyone meets.
const MaxImageUserLen = 256

// CheckImageUser allows an image config's USER as containerd reads it:
// valid UTF-8, no control characters, at most MaxImageUserLen bytes. The
// helper resolves it with containerd's own code (oci.WithUser), which
// refuses a malformed one as an image's error.
func CheckImageUser(u string) error {
	if len(u) > MaxImageUserLen || !utf8.ValidString(u) {
		return violate(RuleImageUser, "image user of %d bytes: want valid UTF-8 of at most %d", len(u), MaxImageUserLen)
	}
	for _, r := range u {
		if unicode.IsControl(r) {
			return violate(RuleImageUser, "image user %q holds a control character", u)
		}
	}
	return nil
}

// ImageLayers returns the image's layers of an active snapshot, top
// first, from the mounts containerd answers for it: an overlay whose lower
// folders are the image's layers, above which the container's writable
// layer sits. Only the lower folders are returned: the writable layer is
// the container's, and what was read from the image must be the image's
// alone. An active snapshot with no parent (a bind of its own folder) has
// no image layer, and returns none. Each folder must be exactly a layer's
// own fs folder under the snapshotter's root.
func ImageLayers(p Policy, ms []Mount) ([]string, error) {
	m, err := activeSnapshotMount(p, ms)
	if err != nil {
		return nil, err
	}
	if m.Type == "bind" {
		return nil, nil
	}
	// CheckSnapshotMounts has made sure an overlay has its lowerdir, once.
	var lower string
	for _, o := range m.Options {
		if v, ok := strings.CutPrefix(o, "lowerdir="); ok {
			lower = v
		}
	}
	return strings.Split(lower, ":"), nil
}

// WritableLayer returns an active snapshot's own folder,
// <SnapshotterRoot>/snapshots/<n>, and n, from the mounts containerd
// answers for it: the folder of its overlay's upperdir, or of the bind of
// a snapshot with no parent. The folder holds the writable layer (fs) and
// overlayfs's work folder, which a project quota must both cover.
func WritableLayer(p Policy, ms []Mount) (string, uint64, error) {
	m, err := activeSnapshotMount(p, ms)
	if err != nil {
		return "", 0, err
	}
	upper := m.Source
	for _, o := range m.Options {
		if v, ok := strings.CutPrefix(o, "upperdir="); ok {
			upper = v
		}
	}
	// CheckSnapshotMounts has made sure the folder is a layer's own; its
	// number may still be past 64 bits.
	id, ok := p.layerDir(upper, "fs")
	n, err := strconv.ParseUint(id, 10, 64)
	if !ok || err != nil {
		return "", 0, violate(RuleSnapshotMount, "writable layer %q is not a snapshot's own fs folder with a 64-bit number", upper)
	}
	return p.snapshotsDir() + "/" + id, n, nil
}

// activeSnapshotMount checks that ms is what the overlayfs snapshotter
// returns for an active snapshot: one mount, an overlay with an upper and
// a work folder, or a read-write bind of a snapshot with no parent, every
// folder a layer's own (CheckSnapshotMounts).
func activeSnapshotMount(p Policy, ms []Mount) (Mount, error) {
	if len(ms) != 1 {
		return Mount{}, violate(RuleSnapshotMount, "an active snapshot has one mount, not %d", len(ms))
	}
	if err := CheckSnapshotMounts(p, ms); err != nil {
		return Mount{}, err
	}
	m := ms[0]
	switch m.Type {
	case "bind":
		for _, o := range m.Options {
			if o == "ro" {
				return Mount{}, violate(RuleSnapshot, "a read-only bind is a view, not an active snapshot")
			}
		}
	case "overlay":
		var upper bool
		for _, o := range m.Options {
			upper = upper || strings.HasPrefix(o, "upperdir=")
		}
		if !upper {
			return Mount{}, violate(RuleSnapshot, "an overlay with no upperdir is a view, not an active snapshot")
		}
	}
	return m, nil
}

// The XFS project IDs of sandboxes' writable layers: a fixed range of
// AerolVM's own, so they never meet an operator's other projects on the
// same volume. Snapshot n's project is QuotaProjectBase + n: containerd's
// overlay snapshotter numbers snapshots from a sequence that never
// repeats, so a project is never reused, and a retry finds the same one.
// The range ends below 2^31, which every quota tool reads as positive.
const (
	QuotaProjectBase uint32 = 1 << 30
	QuotaProjectSpan uint64 = 1<<30 - 1
)

// QuotaProject is snapshot n's project, refused outside the range.
func QuotaProject(n uint64) (uint32, error) {
	if n == 0 || n > QuotaProjectSpan {
		return 0, violate(RuleDiskQuota, "snapshot %d is outside AerolVM's project range (1 to %d)", n, QuotaProjectSpan)
	}
	return QuotaProjectBase + uint32(n), nil
}

// Bounds of a disk quota: a create's DiskGB is whole gigabytes, at least
// one; 64 TiB is past any one node's disk. Zero would lift the limit.
const (
	MinQuotaBytes uint64 = 1 << 30
	MaxQuotaBytes uint64 = 1 << 46
)

// CheckQuotaBytes allows a quota of MinQuotaBytes to MaxQuotaBytes.
func CheckQuotaBytes(b uint64) error {
	if b < MinQuotaBytes || b > MaxQuotaBytes {
		return violate(RuleDiskQuota, "a disk quota of %d bytes: want %d to %d", b, MinQuotaBytes, MaxQuotaBytes)
	}
	return nil
}
