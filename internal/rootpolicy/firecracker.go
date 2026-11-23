package rootpolicy

import (
	"net/netip"
	"path"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
)

// The rules for the root helper's Firecracker calls (M1 PR 9b): the VM's
// jail, the files the agent builds for it, its TAP device, and the
// filesystems the helper makes for the agent.
//
// The agent names a VM by its sandbox ID (CheckHostID), a jail file by
// one of a few fixed names, and a TAP by its name. The helper builds every
// path and every address from its own settings: a TAP's addresses come
// from its slot index and the helper's own TAP base, so a broken agent can
// name only one of the pool's devices, never another link or address.

// The files a VM's jail holds that the agent builds: its root disk and its
// overlay disk (internal/runtime/firecracker rootfsFileName and
// overlayFileName). The kernel is the helper's own (its settings), and
// the jailer adds the rest.
const (
	FirecrackerRootfs  = "rootfs.ext4"
	FirecrackerOverlay = "overlay.ext4"
	FirecrackerKernel  = "vmlinux"
)

// CheckFirecrackerFile refuses a jail file name the agent may not stage.
func CheckFirecrackerFile(name string) error {
	if name != FirecrackerRootfs && name != FirecrackerOverlay {
		return violate(RuleHost, "Firecracker jail file %q: want %s or %s", name, FirecrackerRootfs, FirecrackerOverlay)
	}
	return nil
}

// FirecrackerJail is a VM's jail, as the jailer lays it out under its
// chroot base (internal/runtime/firecracker jailedRootDir): dir is
// <base>/firecracker/<id>, the jailer's chroot is dir/root, and the folder
// the agent builds the VM's disks in is dir/stage. id must have passed
// CheckHostID.
func FirecrackerJail(base, id string) (dir, root, stage string, err error) {
	if !cleanAbs(base) || base == "/" {
		return "", "", "", violate(RuleHost, "jailer chroot base %q: want a clean absolute folder other than /", base)
	}
	if err := CheckHostID(HostFirecracker, id); err != nil {
		return "", "", "", err
	}
	dir = path.Join(base, "firecracker", id)
	root = path.Join(dir, "root")
	if p := path.Join(root, "api.socket"); len(p) > maxSocketPath {
		return "", "", "", violate(RuleHost, "Firecracker API socket %s is longer than a socket path may be (%d)", p, maxSocketPath)
	}
	return dir, root, path.Join(dir, "stage"), nil
}

// CheckTap is the TAP slot name holds in a pool laid out from baseCIDR
// with poolSize slots: name must be the pool's (fctap<index>, the index in
// the pool). Refused with RuleTap.
func CheckTap(name, baseCIDR string, poolSize int) (taphost.Slot, error) {
	index, ok := taphost.IndexOf(name, poolSize)
	if !ok {
		return taphost.Slot{}, violate(RuleTap, "TAP %q is not one of the pool's %d (%s<index>)", name, poolSize, taphost.NamePrefix)
	}
	slot, err := taphost.SlotAt(baseCIDR, poolSize, index)
	if err != nil {
		return taphost.Slot{}, violate(RuleTap, "TAP %q: %v", name, err)
	}
	return slot, nil
}

// CheckTapBase refuses a TAP base the pool cannot be laid out from: an
// IPv4 network of at least poolSize /30s, at most the pool's cap.
func CheckTapBase(baseCIDR string, poolSize int) error {
	p, err := netip.ParsePrefix(baseCIDR)
	if err != nil || !p.Addr().Is4() || p.Masked() != p {
		return violate(RuleTap, "TAP base %q: want an IPv4 network (its first address, /bits)", baseCIDR)
	}
	if _, err := taphost.SlotAt(baseCIDR, poolSize, 0); err != nil {
		return violate(RuleTap, "TAP base %s: %v", baseCIDR, err)
	}
	return nil
}

// maxFilesystemMiB bounds a filesystem the helper makes for the agent: a
// filesystem image is a file of the agent's, as big as it asks, and this
// is a sandbox disk's cap (models: a disk of at most 1024 GiB).
const maxFilesystemMiB = 1024 << 10

// CheckFilesystemSize refuses a filesystem size the helper will not make:
// none at all (mkfs.ext4 needs one for a new file), or past a sandbox
// disk's cap.
func CheckFilesystemSize(mib uint64) error {
	if mib == 0 || mib > maxFilesystemMiB {
		return violate(RuleHost, "filesystem of %d MiB: want 1 to %d", mib, maxFilesystemMiB)
	}
	return nil
}
