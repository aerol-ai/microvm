package rootpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Mount is a containerd mount as a request carries it: a task's root
// filesystem, or the layers a Diff call reads and writes.
type Mount struct {
	Type    string
	Source  string
	Target  string
	Options []string
}

// TaskCreate is the part of a Tasks.Create request the envelope reads.
type TaskCreate struct {
	ContainerID string
	Rootfs      []Mount
	Stdin       string
	Stdout      string
	Stderr      string
	Terminal    bool
	// Checkpoint is the digest of a checkpoint to restore from. The agent
	// restores through the runsc config and RestoreAnnotation instead, so
	// it is always empty.
	Checkpoint string
	// OptionsTypeURL is the task options' type. The agent sends none, and
	// containerd then uses the container's own, checked runtime options.
	OptionsTypeURL string
	// RuntimePath names a shim binary for containerd to run, as root.
	RuntimePath    string
	TaskAPIAddress string
	TaskAPIVersion uint32
}

// CheckTaskCreate checks a task create: its root filesystem mounts, its
// stdio paths, and that every field that would let the request choose what
// root runs is empty.
func CheckTaskCreate(p Policy, t TaskCreate) error {
	if err := ValidateID(t.ContainerID); err != nil {
		return err
	}
	switch {
	case t.Terminal:
		return violate(RuleTask, "task create asks for a terminal; the agent never does")
	case t.Checkpoint != "":
		return violate(RuleCheckpoint, "task create restores checkpoint %s; restores go through the runsc config", t.Checkpoint)
	case t.OptionsTypeURL != "":
		return violate(RuleRuntimeOptions, "task create carries its own runtime options (%s)", t.OptionsTypeURL)
	case t.RuntimePath != "":
		return violate(RuleRuntime, "task create names shim binary %q", t.RuntimePath)
	case t.TaskAPIAddress != "" || t.TaskAPIVersion != 0:
		return violate(RuleTask, "task create names a task API address %q", t.TaskAPIAddress)
	}
	if err := CheckSnapshotMounts(p, t.Rootfs); err != nil {
		return err
	}
	return CheckTaskIO(p, t.Stdin, t.Stdout, t.Stderr)
}

// overlayFlags are the only option-less overlay options: the ones the
// overlayfs snapshotter adds by itself.
var overlayFlags = []string{"index=off", "userxattr"}

// snapshotBindOptions are the options of the bind mount the snapshotter
// returns for a layer with no parent.
var snapshotBindOptions = []string{"ro", "rw", "rbind"}

// layerDir returns the snapshot ID when dir is exactly a layer's own
// folder, <SnapshotterRoot>/snapshots/<id>/<leaf>, with id all digits. Not
// a path below it: inside fs is the sandbox's writable layer, where the
// agent's sandbox could have left a symlink to anywhere. And nothing but
// digits, so no comma, colon or equals sign can ride in: containerd joins a
// mount's options with commas into the kernel's mount data, where
// "lowerdir=<layer>,upperdir=/etc" would be two options.
func (p Policy) layerDir(dir, leaf string) (string, bool) {
	rest, ok := strings.CutPrefix(dir, p.snapshotsDir()+"/")
	if !ok {
		return "", false
	}
	id, l, ok := strings.Cut(rest, "/")
	if !ok || l != leaf || id == "" || len(id) > 20 || strings.Trim(id, "0123456789") != "" {
		return "", false
	}
	return id, true
}

// CheckSnapshotMounts checks mounts that should have come from the
// snapshotter: a task's root filesystem, and a Diff call's layers, which
// containerd mounts as root and reads (Diff) or writes into (Apply). The
// type must be one the overlayfs snapshotter returns, every host path in it
// exactly a layer's own folder (layerDir), and every option one the
// snapshotter sets, each at most once. The destination alone is not enough
// (Kata CVE-2026-77176); here there is none, so the source is everything.
func CheckSnapshotMounts(p Policy, ms []Mount) error {
	for i, m := range ms {
		if m.Target != "" {
			return violate(RuleSnapshotMount, "mount %d has target %q; snapshotter mounts have none", i, m.Target)
		}
		switch m.Type {
		case "bind":
			if _, ok := p.layerDir(m.Source, "fs"); !ok {
				return violate(RuleSnapshotMount, "bind source %q is not a snapshot's own fs folder", m.Source)
			}
			for _, o := range m.Options {
				if !slices.Contains(snapshotBindOptions, o) {
					return violate(RuleSnapshotMount, "bind option %q is not one the snapshotter sets", o)
				}
			}
		case "overlay":
			if m.Source != "overlay" {
				return violate(RuleSnapshotMount, "overlay source %q is not \"overlay\"", m.Source)
			}
			if err := checkOverlayOptions(p, m.Options); err != nil {
				return err
			}
		default:
			return violate(RuleSnapshotMount, "mount type %q is not one the overlayfs snapshotter returns", m.Type)
		}
	}
	return nil
}

func checkOverlayOptions(p Policy, options []string) error {
	seen := map[string]bool{}
	var lower bool
	var upperID, workID string
	for _, o := range options {
		key, value, _ := strings.Cut(o, "=")
		if seen[key] {
			return violate(RuleSnapshotMount, "overlay option %s appears twice; the kernel keeps the last", key)
		}
		seen[key] = true
		var ok bool
		switch key {
		case "lowerdir":
			for _, dir := range strings.Split(value, ":") {
				if _, ok = p.layerDir(dir, "fs"); !ok {
					return violate(RuleSnapshotMount, "overlay lowerdir %q is not a snapshot's own fs folder", dir)
				}
			}
			lower = true
		case "upperdir":
			if upperID, ok = p.layerDir(value, "fs"); !ok {
				return violate(RuleSnapshotMount, "overlay upperdir %q is not a snapshot's own fs folder", value)
			}
		case "workdir":
			if workID, ok = p.layerDir(value, "work"); !ok {
				return violate(RuleSnapshotMount, "overlay workdir %q is not a snapshot's own work folder", value)
			}
		default:
			if !slices.Contains(overlayFlags, o) {
				return violate(RuleSnapshotMount, "overlay option %q is not one the snapshotter sets", o)
			}
		}
	}
	if !lower {
		return violate(RuleSnapshotMount, "overlay mount has no lowerdir")
	}
	if upperID != workID {
		return violate(RuleSnapshotMount, "overlay upperdir and workdir are not the same snapshot's (%q, %q)", upperID, workID)
	}
	return nil
}

// CheckTaskIO allows a task's stdio only as plain FIFO paths in the FIFO
// folder. The runc shim opens each one as root, and reads a URI scheme:
// binary:///path runs that program as root, and file:///path opens any
// file for writing. This check is on the text alone; the shim also follows
// links, so the gate checks on disk too (gate.StdioChecker).
func CheckTaskIO(p Policy, paths ...string) error {
	for _, stdio := range paths {
		if stdio == "" {
			continue
		}
		if !cleanAbs(stdio) || strings.ContainsAny(stdio, ":?#%") || !within(stdio, p.FIFODir) {
			return violate(RuleTaskIO, "task stdio %q is not a FIFO under %s", stdio, p.FIFODir)
		}
	}
	return nil
}

// CheckCheckpointPath allows a checkpoint or restore image only inside the
// moves folder: runsc (as root) reads and writes it whole.
func CheckCheckpointPath(p Policy, dir string) error {
	if !cleanAbs(dir) || !within(dir, p.MovesDir) {
		return violate(RuleCheckpoint, "checkpoint path %q is not under %s", dir, p.MovesDir)
	}
	return nil
}

// CheckTaskUpdate checks a live resize: memory, CPU and pids limits only,
// each a real limit (not zero, negative or -1 for unlimited) within the
// policy's bounds, and no annotations. A device rule here would open the
// host's devices to a running sandbox that has CAP_MKNOD.
func CheckTaskUpdate(p Policy, resourcesTypeURL string, resources []byte, annotations map[string]string) error {
	if len(annotations) > 0 {
		return violate(RuleResources, "task update sets annotations %v", sortedKeys(annotations))
	}
	if resourcesTypeURL == "" && len(resources) == 0 {
		return nil
	}
	if resourcesTypeURL != ResourcesTypeURL {
		return violate(RuleResources, "task update resources have type %q, not %s", resourcesTypeURL, ResourcesTypeURL)
	}
	dec := json.NewDecoder(bytes.NewReader(resources))
	dec.DisallowUnknownFields()
	var r specs.LinuxResources
	if err := dec.Decode(&r); err != nil {
		return violate(RuleResources, "task update resources do not decode: %v", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return violate(RuleResources, "task update resources have bytes after their JSON object")
	}
	// A resize names only what it changes, so a bound limit may be absent.
	return checkResources(&r, "task update resources", false, p.Limits, false)
}
