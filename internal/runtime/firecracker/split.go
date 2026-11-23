package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// Privilege mode split (M1 PR 9b): sandboxd has no rights, so the root
// helper does the Firecracker work single mode does as root. It makes each
// VM's jail and runs the jailer (a host of kind firecracker), makes its TAP
// and the guests' NAT and isolation, and makes its filesystems as
// sandboxd's own user seen as root, so their files come out root's.
//
// sandboxd builds a VM's disks in the jail's stage folder, which is its
// own, and the helper moves each into the chroot for the jailer's user;
// sandboxd never writes in the chroot, where the jailer works as root. The
// helper gives the VM's API and vsock sockets to sandboxd's group, so the
// cold boot otherwise runs as in single mode: the same machine config,
// drives, network, vsock handshake, guest env and adoption.
//
// What split mode does not do yet answers 501 with a reason
// (errSplitSnapshots): every path that saves or loads a VM's memory and
// state (stop, start, a snapshot, a move, an export, a template's
// snapshot, a snapshot load, the warm VM pool). Firecracker writes those
// files as the jailer's user, in the chroot, and sandboxd could not take
// them back. The ownership lease cannot freeze a VM (its group is root's):
// Freeze answers ErrCannotFreeze, and the lease stops the VM instead.

// SplitHelper is the root helper's Firecracker calls, as
// internal/rootclient makes them (pkg/daemon adapts the client).
type SplitHelper interface {
	// PrepareFirecracker makes the VM's jail and moves the stage folder's
	// disks named by stage into the chroot; on a running VM it also gives
	// its sockets to sandboxd's group again. It answers the chroot and the
	// stage folder.
	PrepareFirecracker(ctx context.Context, id string, stage ...string) (root, stageDir string, err error)
	// SpawnFirecracker runs the VM's jailer and answers once firecracker
	// has bound its API socket.
	SpawnFirecracker(ctx context.Context, id string) (SplitProcess, error)
	// OpenFirecracker holds a VM a previous sandboxd started, if it still
	// runs.
	OpenFirecracker(ctx context.Context, id string, pid int, startTicks uint64) (SplitProcess, error)
	// StopFirecracker kills the VM and removes its jail.
	StopFirecracker(ctx context.Context, id string) error
	// EnsureTap and RemoveTap make sure one of the pool's TAPs is up, or
	// gone. EnsureTap answers the slot the helper worked out.
	EnsureTap(ctx context.Context, name string) (TapSlot, error)
	RemoveTap(ctx context.Context, name string) error
	// MakeFilesystem makes an ext4 filesystem in the VM's stage file name:
	// from the folder source, with sizeMiB, or empty with no source.
	MakeFilesystem(ctx context.Context, id, name, source string, sizeMiB uint64) error
}

// SplitProcess is a VM the helper holds: a signal ends it through the
// helper, and Done closes once it is gone (rootclient.HostProcess).
type SplitProcess interface {
	liveProcess
	Pid() int
	StartTicks() uint64
}

// errSplitSnapshots is what split mode refuses for Firecracker.
var errSplitSnapshots = privmode.NotYet("save or load a Firecracker VM's memory and state (stop, start, a snapshot, a move, an export, a template's snapshot, the warm VM pool)",
	privmode.StepFirecrackerSnapshots)

// SetSplit makes the driver run its VMs through the root helper h:
// privilege mode split. It replaces the spawner and the TAP host. Call it
// after the other setters.
func (d *Driver) SetSplit(h SplitHelper) {
	d.split = h
	d.spawn = d.splitSpawn
	d.tapHost = splitTapHost{h: h}
}

// splitGap refuses, in split mode, what saves or loads a VM's state.
func (d *Driver) splitGap() error {
	if d.split != nil {
		return errSplitSnapshots
	}
	return nil
}

// splitSpawn is the spawner in split mode: the helper makes the jail
// first, so the stage folder is there for the disks.
func (d *Driver) splitSpawn(_ Config, sandboxID string) (VMMHandle, error) {
	if err := validateSandboxID(sandboxID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), splitCallWait)
	defer cancel()
	root, stage, err := d.split.PrepareFirecracker(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("root helper: Firecracker jail: %w", err)
	}
	return &splitVMM{h: d.split, id: sandboxID, root: root, stage: stage}, nil
}

// splitCallWait bounds a helper call the driver makes with no context of
// its own (a stage, a cleanup).
const splitCallWait = 2 * time.Minute

// splitVMM is a VM the helper runs. RunDir is the jailer's chroot, where
// firecracker binds its sockets; StageDir is the folder sandboxd builds the
// VM's disks in.
type splitVMM struct {
	h     SplitHelper
	id    string
	root  string
	stage string

	mu   sync.Mutex
	proc SplitProcess
}

func (v *splitVMM) APISocket() string { return filepath.Join(v.root, jailerAPISocketName) }
func (v *splitVMM) RunDir() string    { return v.root }

// StageDir is where sandboxd builds the VM's disks (stageDirOf).
func (v *splitVMM) StageDir() string { return v.stage }

func (v *splitVMM) Start(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.proc != nil {
		return errors.New("vmm: Start called twice")
	}
	p, err := v.h.SpawnFirecracker(ctx, v.id)
	if err != nil {
		return err
	}
	v.proc = p
	return nil
}

// WaitSocket: the helper answered SpawnFirecracker once firecracker had
// bound its API socket; this sees it from sandboxd's side.
func (v *splitVMM) WaitSocket(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultSocketWait
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(v.APISocket()); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return fmt.Errorf("vmm: API socket %s: %w", v.APISocket(), err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ShareSockets has the helper give the VM's sockets to sandboxd's group
// again, once firecracker has bound its vsock socket (at InstanceStart).
func (v *splitVMM) ShareSockets(ctx context.Context) error {
	_, _, err := v.h.PrepareFirecracker(ctx, v.id)
	return err
}

// Shutdown, Kill and Cleanup all end the VM through the helper, which kills
// its group and removes its jail: in split mode a VM never restarts from
// its jail (errSplitSnapshots).
func (v *splitVMM) Shutdown(ctx context.Context, _ time.Duration) error {
	return v.stop(ctx)
}

func (v *splitVMM) Kill() error {
	ctx, cancel := context.WithTimeout(context.Background(), splitCallWait)
	defer cancel()
	return v.stop(ctx)
}

func (v *splitVMM) Cleanup() error { return v.Kill() }

func (v *splitVMM) stop(ctx context.Context) error {
	err := v.h.StopFirecracker(ctx, v.id)
	v.mu.Lock()
	if v.proc != nil && err == nil {
		_ = v.proc.Close()
	}
	v.mu.Unlock()
	return err
}

// StderrTail: the VM's output goes to the helper's hosts' log.
func (v *splitVMM) StderrTail() string { return "" }

func (v *splitVMM) Pid() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.proc == nil {
		return 0
	}
	select {
	case <-v.proc.Done():
		return 0
	default:
		return v.proc.Pid()
	}
}

// stageDirOf is where a VM's disks are built: the stage folder in split
// mode, the run folder (the chroot itself) in single mode.
func stageDirOf(h VMMHandle) string {
	if s, ok := h.(interface{ StageDir() string }); ok {
		return s.StageDir()
	}
	return h.RunDir()
}

// splitJailID answers the sandbox ID of a VM whose stage folder holds path,
// and the file's name, checking path is <chroot base>/firecracker/<id>/
// stage/<name> as the helper lays it out.
func (d *Driver) splitJailID(path string) (id, name string, err error) {
	stage := filepath.Dir(path)
	id, name = filepath.Base(filepath.Dir(stage)), filepath.Base(path)
	_, _, want, err := rootpolicy.FirecrackerJail(d.cfg.JailerChrootBase, id)
	if err != nil || want != stage {
		return "", "", fmt.Errorf("firecracker runtime: %s is not in a VM's stage folder", path)
	}
	return id, name, nil
}

// splitStage moves a disk the driver built in a VM's stage folder into its
// chroot, through the helper (chrootFilePath in split mode). A shared file
// is the kernel, which the helper puts in every jail itself.
func (d *Driver) splitStage(srcAbs, destName string, shared bool) (string, error) {
	if shared {
		if srcAbs != d.cfg.KernelImage || destName != kernelFileName {
			return "", fmt.Errorf("firecracker runtime: %w", errSplitSnapshots)
		}
		return destName, nil
	}
	id, name, err := d.splitJailID(srcAbs)
	if err != nil {
		return "", err
	}
	if name != destName {
		return "", fmt.Errorf("firecracker runtime: %s is staged as %s, not %s", srcAbs, name, destName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), splitCallWait)
	defer cancel()
	if _, _, err := d.split.PrepareFirecracker(ctx, id, name); err != nil {
		return "", fmt.Errorf("root helper: stage %s: %w", name, err)
	}
	return destName, nil
}

// SplitMkfs is the OCI builder's mkfs in split mode (pkg/oci Config.Mkfs):
// the helper makes the VM's root disk in its stage folder, from the
// unpacked image, as sandboxd's own user seen as root.
func (d *Driver) SplitMkfs(ctx context.Context, source, out string, sizeMiB int) error {
	if d.split == nil {
		return errors.New("firecracker runtime: SplitMkfs outside privilege mode split")
	}
	id, name, err := d.splitJailID(out)
	if err != nil {
		return err
	}
	if sizeMiB <= 0 {
		return fmt.Errorf("firecracker runtime: a root disk of %d MiB", sizeMiB)
	}
	return d.split.MakeFilesystem(ctx, id, name, source, uint64(sizeMiB))
}

// makeOverlayFS formats a VM's overlay file as ext4: mkfs.ext4 as root in
// single mode, through the helper in split mode.
func (d *Driver) makeOverlayFS(ctx context.Context, overlayPath string) error {
	if d.split != nil {
		id, name, err := d.splitJailID(overlayPath)
		if err != nil {
			return err
		}
		return d.split.MakeFilesystem(ctx, id, name, "", 0)
	}
	return runOverlayMkfs(ctx, d.cfg.Mkfs4Bin, overlayPath)
}

// shareSockets has the helper give a split VM's sockets to sandboxd's
// group once it has started; a no-op in single mode.
func shareSockets(ctx context.Context, h VMMHandle) error {
	if s, ok := h.(interface{ ShareSockets(context.Context) error }); ok {
		return s.ShareSockets(ctx)
	}
	return nil
}

// splitTapHost makes a VM's TAP through the helper. The helper works the
// slot out from the name and its own TAP base; one that differs from
// sandboxd's pool (the two settings disagree) is refused.
type splitTapHost struct{ h SplitHelper }

func (t splitTapHost) Ensure(ctx context.Context, slot TapSlot) error {
	if slot.GuestMAC != "" {
		return fmt.Errorf("firecracker runtime: TAP %s: %w", slot.TapName, errSplitSnapshots)
	}
	got, err := t.h.EnsureTap(ctx, slot.TapName)
	if err != nil {
		return err
	}
	if got.CIDR != slot.CIDR || got.HostIP != slot.HostIP || got.GuestIP != slot.GuestIP || got.VsockCID != slot.VsockCID {
		_ = t.h.RemoveTap(context.WithoutCancel(ctx), slot.TapName)
		return fmt.Errorf("firecracker runtime: TAP %s is %s %s->%s cid %d in the root helper's pool and %s %s->%s cid %d in sandboxd's; "+
			"SB_FIRECRACKER_TAP_BASE_CIDR and SB_FIRECRACKER_TAP_POOL_SIZE must be the same for both",
			slot.TapName, got.CIDR, got.HostIP, got.GuestIP, got.VsockCID, slot.CIDR, slot.HostIP, slot.GuestIP, slot.VsockCID)
	}
	return nil
}

func (t splitTapHost) Remove(ctx context.Context, name string) error { return t.h.RemoveTap(ctx, name) }

// splitOpenProcess holds a VM a previous sandboxd started, through the
// helper (adoptVM in split mode).
func (d *Driver) splitOpenProcess(ctx context.Context, id string, pid int, startTicks uint64) (liveProcess, error) {
	return d.split.OpenFirecracker(ctx, id, pid, startTicks)
}

// splitKillStray ends a VM no sandbox owns, through the helper, by the group
// the helper started it in.
func (d *Driver) splitKillStray(ctx context.Context, pid int) error {
	group, in, err := vmmGroupOfPID(pid)
	if err != nil {
		return err
	}
	if !in || rootpolicy.CheckHostID(rootpolicy.HostFirecracker, group) != nil {
		return fmt.Errorf("pid %d is in no VM's group of its own", pid)
	}
	return d.split.StopFirecracker(ctx, group)
}
