package firecracker

// jailer.go is the chroot+cgroups+drop-priv wrap around the firecracker
// spawn. Production hosts always run firecracker via `jailer`, the helper
// binary that ships in the same release tarball. Dev boxes and CI without
// root run firecracker directly — that path is in vmm.go.
//
// Why a separate file: the path math here is non-trivial and read in
// isolation. The jailer is the only Firecracker component that touches
// the host filesystem outside Config.RunDir; getting it wrong leaks files
// across sandboxes or breaks the chroot. Keeping the layout decisions in
// one file makes them auditable.
//
// Jailer's canonical filesystem layout (from
// https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md):
//
//	<chroot-base>/firecracker/<id>/
//	└── root/                            # the chroot the VMM sees as "/"
//	    ├── firecracker                  # hard-linked exec-file (jailer does this)
//	    ├── api.socket                   # --api-sock is RELATIVE to root
//	    ├── (kernel, rootfs.ext4, etc.   # daemon copies these in before spawn)
//	    │   the rest of the guest's
//	    │   block/file world lives here)
//	    └── run/                         # the guest's /run
//
// `--api-sock api.socket` becomes <chroot-base>/firecracker/<id>/root/api.socket
// on the host. The runtime driver talks to that absolute host path; the
// guest sees `/api.socket`.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
)

// jailerAPISocketName is the path the jailed firecracker binds inside its
// chroot. The host-visible absolute path is computed by jailedRootDir.
// Hardcoded because operators never need to override it: changing the
// socket name buys nothing and breaks every assumption in this file.
const jailerAPISocketName = "api.socket"

// jailerExpectsBase returns the chroot base the daemon would manage if
// jailer mode were active, or an error if the config is incomplete. Phase
// 1 keeps this validation here rather than in newVMM so the non-jailer
// path stays cheap — direct-spawn doesn't need any of these knobs.
func (c Config) jailerExpectsBase() (string, error) {
	if !c.UseJailer {
		return "", errors.New("jailer not enabled in config")
	}
	if c.JailerBinary == "" {
		return "", errors.New("JailerBinary is empty")
	}
	if c.JailerChrootBase == "" {
		return "", errors.New("JailerChrootBase is empty")
	}
	return c.JailerChrootBase, nil
}

// jailedRootDir returns the host path of the chroot's root directory for
// a given sandbox. The jailer creates this; the daemon writes the
// kernel/rootfs/etc. into it before spawn.
//
// Format mirrors the jailer docs verbatim — do not "simplify" the trailing
// /root; the jailer's own argument parsing assumes that layout and
// changing it breaks chroot setup.
func jailedRootDir(base, sandboxID string) string {
	return filepath.Join(base, "firecracker", sandboxID, "root")
}

// jailedAPISocketHostPath returns the absolute host path the API socket
// will appear at once jailer creates the chroot and firecracker binds
// inside it. The runtime driver dials this path; the in-chroot
// firecracker writes to it.
func jailedAPISocketHostPath(base, sandboxID string) string {
	return filepath.Join(jailedRootDir(base, sandboxID), jailerAPISocketName)
}

// jailerArgv returns the full argv for invoking `jailer` to spawn this
// VMM's firecracker. The double-dash separates jailer's own flags from
// the firecracker flags that follow; firecracker arguments are passed
// through verbatim and are interpreted INSIDE the chroot (so paths must
// be chroot-relative).
//
// Notably absent: --netns. Phase 1 of the plan runs sandboxes in the host
// network namespace with TAP-side iptables/eBPF for isolation; netns
// isolation is a future axis (see plans/snapshot-clone-fast-boot.md §3
// "Network namespace per sandbox"). When that lands, append
// "--netns", "/var/run/netns/<id>" before the double-dash.
//
// The trailing args after "--" are firecracker's, not jailer's. Keep them
// in sync with vmm.buildArgs (the non-jailer path) so the shape doesn't
// silently drift.
func (v *vmm) jailerArgv() []string {
	return []string{
		"--id", v.sandboxID,
		"--exec-file", v.cfg.FirecrackerBinary,
		"--uid", strconv.Itoa(v.cfg.JailerUID),
		"--gid", strconv.Itoa(v.cfg.JailerGID),
		"--chroot-base-dir", v.cfg.JailerChrootBase,
		// Hold the firecracker stderr/stdout in the host process group
		// rather than detaching to a daemon; we want the cappedBuffer in
		// vmm.go to see the lines. Without --daemonize jailer keeps the
		// child attached to our stdio fds, which is what we need.
		"--",
		"--api-sock", jailerAPISocketName,
	}
}

// applyJailerLayout rewires a vmm's paths to the chroot-aware locations
// when Config.UseJailer is true. Called from newVMM after the direct-mode
// defaults are set; in non-jailer mode it returns nil and changes
// nothing.
//
// Two effects:
//
//  1. runDir flips from <Config.RunDir>/<id> to the chroot root path,
//     because that's where the daemon copies the kernel/rootfs and where
//     jailer expects to find them.
//  2. apiSocket flips to the host-visible chroot path the jailed
//     firecracker will bind.
func (v *vmm) applyJailerLayout() error {
	if !v.cfg.UseJailer {
		return nil
	}
	base, err := v.cfg.jailerExpectsBase()
	if err != nil {
		return fmt.Errorf("vmm: jailer layout: %w", err)
	}
	v.runDir = jailedRootDir(base, v.sandboxID)
	v.apiSocket = jailedAPISocketHostPath(base, v.sandboxID)
	v.logPath = filepath.Join(v.runDir, "firecracker.log")
	return nil
}
