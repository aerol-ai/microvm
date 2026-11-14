package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/firecracker"
)

// A running VM outlives the sandboxd that started it, as a Docker container
// outlives dockerd. Three parts make that work:
//
//   - vmm.Start moves each VM into a cgroup of its own (vmmCgroupName), out
//     of sandboxd's unit, so a restart or upgrade does not kill it.
//   - register writes a record of each running VM under the run dir: its
//     process (pid, start time, boot), API socket and vsock CID.
//   - At boot, AdoptRunningVMs reads the records back, takes over the VMs
//     whose sandboxes should still run, and kills every other process in
//     the VMs' cgroup: nothing would ever manage it.
//
// The run dir is on tmpfs (/run), so a reboot, which ends every VM, also
// ends every record.

const (
	// vmmCgroupName is the cgroup, under the cgroup v2 root or the
	// configured parent (Config.VMMCgroupParent), every VM runs in.
	vmmCgroupName = "aerolvm-vmm"
	// vmmRecordDirName holds one record per running VM, under the run dir.
	vmmRecordDirName = "vmms"
)

// vmmCgroupParent is Config.VMMCgroupParent of the driver this process
// runs. There is one driver per sandboxd, and the host seams below read it
// without a driver at hand, so New sets it once.
var vmmCgroupParent atomic.Pointer[string]

func currentVMMCgroupParent() string {
	if p := vmmCgroupParent.Load(); p != nil {
		return *p
	}
	return ""
}

var (
	// errProcessGone: the process exited, or its pid now names another.
	errProcessGone = errors.New("process is gone")
	// errVMMAdoptionUnsupported: this host cannot hand a VM to the next
	// sandboxd (not Linux).
	errVMMAdoptionUnsupported = errors.New("VMs do not outlive sandboxd on this host")
)

// liveProcess is a running process held so that a signal reaches it and no
// other process that later reuses its pid.
type liveProcess interface {
	Signal(sig syscall.Signal) error
	// Done is closed once the process has exited.
	Done() <-chan struct{}
	Close() error
}

// Host seams, replaced in tests.
var (
	moveVMMToCgroup = moveToVMMCgroup
	listVMMCgroup   = vmmCgroupPIDs
	processStart    = procStartTicks
	hostBootID      = currentBootID
	openProcess     = openLiveProcess
	killStrayVMM    = killCgroupStray
	processCmdline  = procCmdline
	sweepVMMGroups  = removeEmptyVMMGroups
)

// vmmRecord is what a running VM leaves for the next sandboxd.
type vmmRecord struct {
	SandboxID string `json:"sandbox_id"`
	PID       int    `json:"pid"`
	// StartTicks and BootID tell this process from a later one with the
	// same pid.
	StartTicks uint64 `json:"start_ticks"`
	BootID     string `json:"boot_id"`
	APISocket  string `json:"api_socket"`
	RunDir     string `json:"run_dir"`
	VsockCID   uint32 `json:"vsock_cid"`
	// OwnsRunDir: Destroy removes the run dir. A VM taken from the warm
	// pool leaves its run dir to the pool, as warmDestroyHandle does.
	OwnsRunDir bool `json:"owns_run_dir"`
}

func (d *Driver) vmmRecordDir() string {
	if d.cfg.RunDir == "" {
		return ""
	}
	return filepath.Join(d.cfg.RunDir, vmmRecordDirName)
}

// register makes a running VM the driver's: the maps every lifecycle call
// reads, the RSS sampler, and the record a restarted sandboxd adopts it
// from. The maps come first, so a sampler tick never sees a pid the rest of
// the driver does not know.
func (d *Driver) register(sandboxID string, client VMMClient, handle VMMHandle, guestCID uint32, ownsRunDir bool) {
	d.mu.Lock()
	d.clients[sandboxID] = client
	d.vmms[sandboxID] = handle
	d.guestCID[sandboxID] = guestCID
	d.mu.Unlock()
	d.rssRegister(sandboxID, handle.Pid())
	d.placeVMM(sandboxID, handle.Pid())
	if err := d.writeVMMRecord(sandboxID, handle, guestCID, ownsRunDir); err != nil {
		d.logger.Warn("firecracker: running VM not recorded; a sandboxd restart will stop it",
			"sandbox_id", sandboxID, "error", err)
	}
}

// unregister forgets a VM: the maps, the sampler and its record. The
// record goes before the VM does, so a sandboxd that dies in between finds
// an unrecorded VM at boot and kills it rather than adopting one that is
// being stopped or destroyed.
// placeVMM puts a sandbox's VM in a group of its own (moveToVMMCgroup): a
// warm VM taken for a sandbox, or one adopted from a release that started
// VMs in the shared group. A VM already there moves nowhere. Without one,
// the ownership lease cannot freeze it: logged, and Freeze answers
// ErrCannotFreeze for it.
func (d *Driver) placeVMM(sandboxID string, pid int) {
	if pid <= 0 {
		return
	}
	if err := moveVMMToCgroup(pid, sandboxID); err != nil && !errors.Is(err, errVMMAdoptionUnsupported) {
		d.logger.Warn("firecracker: VM not in a group of its own; the ownership lease cannot freeze it",
			"sandbox_id", sandboxID, "error", err)
	}
}

// Freeze stops a sandbox's VM where it stands: its own cgroup frozen. The
// cluster ownership fence calls it when sandboxd's lease runs out
// (internal/service/ownership_lease.go); the runtime supervisor freezes the
// same group with sandboxd down (FenceGroup). A VM with no group of its own
// answers sbruntime.ErrCannotFreeze.
func (d *Driver) Freeze(_ context.Context, sandboxID string) error {
	return setVMMGroupFrozen(sandboxID, true)
}

// Thaw lets a frozen VM run on.
func (d *Driver) Thaw(_ context.Context, sandboxID string) error {
	return setVMMGroupFrozen(sandboxID, false)
}

// FenceGroup is the group the runtime supervisor freezes for a sandbox's
// VM, under the sandboxes' cgroup parent: aerolvm-vmm/<sandbox>
// (ownerlease.HostGroups). It is under that parent when the VMs' cgroup
// parent is the containerd one, the default (config
// SB_HOST_PROCESS_CGROUP_PARENT); the service checks that before it relies
// on it.
func (d *Driver) FenceGroup(sandboxID string) string {
	return vmmCgroupName + "/" + sandboxID
}

var (
	_ sbruntime.Freezer      = (*Driver)(nil)
	_ sbruntime.FenceGrouper = (*Driver)(nil)
)

func (d *Driver) unregister(sandboxID string) (VMMHandle, bool) {
	d.mu.Lock()
	handle, ok := d.vmms[sandboxID]
	delete(d.clients, sandboxID)
	delete(d.vmms, sandboxID)
	delete(d.guestCID, sandboxID)
	d.mu.Unlock()
	d.rssUnregister(sandboxID)
	d.removeVMMRecord(sandboxID)
	return handle, ok
}

func (d *Driver) writeVMMRecord(sandboxID string, handle VMMHandle, guestCID uint32, ownsRunDir bool) error {
	dir := d.vmmRecordDir()
	pid := handle.Pid()
	if dir == "" || pid <= 0 {
		return nil
	}
	ticks, err := processStart(pid)
	if errors.Is(err, errVMMAdoptionUnsupported) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read start time of pid %d: %w", pid, err)
	}
	boot, err := hostBootID()
	if err != nil {
		return fmt.Errorf("read boot id: %w", err)
	}
	return writeRecordFile(dir, vmmRecord{
		SandboxID: sandboxID, PID: pid, StartTicks: ticks, BootID: boot,
		APISocket: handle.APISocket(), RunDir: handle.RunDir(), VsockCID: guestCID,
		OwnsRunDir: ownsRunDir,
	})
}

// writeRecordFile writes rec under dir, whole or not at all.
func writeRecordFile(dir string, rec vmmRecord) error {
	if dir == "" {
		return nil
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), filepath.Join(dir, rec.SandboxID+".json"))
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
	}
	return werr
}

func (d *Driver) removeVMMRecord(sandboxID string) {
	dir := d.vmmRecordDir()
	if dir == "" {
		return
	}
	if err := os.Remove(filepath.Join(dir, sandboxID+".json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		d.logger.Warn("firecracker: VM record not removed", "sandbox_id", sandboxID, "error", err)
	}
}

// readVMMRecords returns the records under the record dir, dropping files
// that are not one (a write cut short leaves only a .record-* temp file).
func (d *Driver) readVMMRecords() []vmmRecord {
	dir := d.vmmRecordDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			d.logger.Warn("firecracker adopt: VM records unreadable", "dir", dir, "error", err)
		}
		return nil
	}
	var records []vmmRecord
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		id, isRecord := strings.CutSuffix(entry.Name(), ".json")
		var rec vmmRecord
		raw, err := os.ReadFile(path)
		if err == nil && isRecord {
			err = json.Unmarshal(raw, &rec)
		}
		if err != nil || !isRecord || rec.SandboxID != id || validateSandboxID(id) != nil || rec.PID <= 0 {
			_ = os.Remove(path)
			continue
		}
		records = append(records, rec)
	}
	return records
}

// VMMKeeper reports whether a sandbox's VM should still be running on this
// node. An error means the answer is unknown.
type VMMKeeper func(ctx context.Context, sandboxID string) (bool, error)

// AdoptRunningVMs takes over the VMs a previous sandboxd left running. A VM
// whose sandbox should still run is registered as if this sandboxd had
// started it; any other VM in the VMs' cgroup (a warm-pool VM, a template's
// snapshot VM, a create the restart cut short, a stopped sandbox's) is
// killed. Call it once at boot, before anything creates, starts or
// reconciles a sandbox: reconcile reaps a started sandbox whose VM the
// driver does not know.
//
// A VM is found by its record, or, without one, by its command line: a
// release before records started its VMs in sandboxd's cgroup, and the
// installer moves them out before it restarts sandboxd onto this one.
func (d *Driver) AdoptRunningVMs(ctx context.Context, keep VMMKeeper) int {
	boot, bootErr := hostBootID()
	adopted := map[int]bool{}
	recorded := map[string]bool{}
	for _, rec := range d.readVMMRecords() {
		recorded[rec.SandboxID] = true
		if bootErr != nil || rec.BootID != boot {
			d.removeVMMRecord(rec.SandboxID)
			continue
		}
		if d.adoptVM(ctx, rec, keep) {
			adopted[rec.PID] = true
		}
	}
	pids, err := listVMMCgroup()
	if err != nil {
		d.logger.Warn("firecracker adopt: VM cgroup unreadable; leftover VMs may still run", "error", err)
	}
	for _, pid := range pids {
		if adopted[pid] {
			continue
		}
		if rec, ok := d.discoverVM(ctx, pid, boot); ok && !recorded[rec.SandboxID] {
			recorded[rec.SandboxID] = true
			if d.adoptVM(ctx, rec, keep) {
				adopted[pid] = true
				if err := writeRecordFile(d.vmmRecordDir(), rec); err != nil {
					d.logger.Warn("firecracker adopt: VM not recorded", "sandbox_id", rec.SandboxID, "error", err)
				}
				continue
			}
		}
		// Only a VM is a stray. The installer also puts here the reader it
		// starts for each VM an older release left writing into a pipe
		// (keep_firecracker_vms_running); it exits with its VM.
		if args, err := processCmdline(pid); err != nil || len(args) == 0 || filepath.Base(args[0]) != "firecracker" {
			continue
		}
		if err := killStrayVMM(pid); err != nil {
			d.logger.Warn("firecracker adopt: leftover VM not killed", "pid", pid, "error", err)
			continue
		}
		d.logger.Info("firecracker adopt: killed a VM no sandbox owns", "pid", pid)
	}
	// The groups of VMs that are gone (adoptVM moved each adopted VM
	// into its own group already).
	sweepVMMGroups()
	return len(adopted)
}

// adoptVM registers the VM rec describes if its sandbox should run, and
// kills it otherwise. It reports whether the VM was adopted.
func (d *Driver) adoptVM(ctx context.Context, rec vmmRecord, keep VMMKeeper) bool {
	proc, err := openProcess(rec.PID, rec.StartTicks)
	if err != nil {
		// The VM ended while sandboxd was down; reconcile handles its
		// sandbox like any other whose VM is gone.
		d.logger.Info("firecracker adopt: recorded VM is gone", "sandbox_id", rec.SandboxID, "error", err)
		d.removeVMMRecord(rec.SandboxID)
		return false
	}
	handle := &adoptedVMM{rec: rec, proc: proc, cleanupRoot: d.runDirRoot()}
	want, err := keep(ctx, rec.SandboxID)
	if err != nil {
		// Unknown is not "stopped": keep the VM, and reconcile decides
		// once the store answers.
		d.logger.Warn("firecracker adopt: cannot tell whether a VM should run; keeping it",
			"sandbox_id", rec.SandboxID, "error", err)
		want = true
	}
	if !want {
		d.logger.Info("firecracker adopt: stopping a VM whose sandbox is not running", "sandbox_id", rec.SandboxID)
		_ = handle.Kill()
		if err := handle.Cleanup(); err != nil {
			d.logger.Warn("firecracker adopt: run dir not removed", "sandbox_id", rec.SandboxID, "error", err)
		}
		d.removeVMMRecord(rec.SandboxID)
		return false
	}
	if rec.RunDir != "" {
		go boundVMMOutput(filepath.Join(rec.RunDir, vmmOutputName), proc.Done())
	}
	client := d.newClient(rec.APISocket)
	d.resumeIfPaused(ctx, rec.SandboxID, client)
	d.mu.Lock()
	d.clients[rec.SandboxID] = client
	d.vmms[rec.SandboxID] = handle
	d.guestCID[rec.SandboxID] = rec.VsockCID
	d.mu.Unlock()
	d.rssRegister(rec.SandboxID, rec.PID)
	// A release before this one started every VM in the VMs' shared
	// cgroup: a group of its own lets the ownership lease freeze it alone.
	d.placeVMM(rec.SandboxID, rec.PID)
	// The sandboxd that died may have frozen the guest's disk (a snapshot's
	// copy, or a Stop it never finished), and no one else will ever thaw
	// it. Not waited for: an unresponsive guest must not hold up the boot,
	// and its own timer thaws it in the end.
	if d.vsockDial != nil {
		go d.thawGuest(rec.SandboxID, filepath.Join(rec.RunDir, hostVsockUDSName), rec.VsockCID)
	}
	d.logger.Info("firecracker adopt: running VM taken over", "sandbox_id", rec.SandboxID, "pid", rec.PID)
	return true
}

// discoverVM builds the record a VM with none would have had, from its
// command line: the jailer starts firecracker with --id <sandbox>, and an
// unjailed one's --api-sock is in its sandbox's run dir. The paths are the
// ones this driver would give that sandbox, and the vsock CID is its TAP
// slot's.
func (d *Driver) discoverVM(ctx context.Context, pid int, boot string) (vmmRecord, bool) {
	args, err := processCmdline(pid)
	if err != nil {
		return vmmRecord{}, false
	}
	id, ok := vmSandboxFromArgs(args, d.cfg.RunDir)
	if !ok {
		return vmmRecord{}, false
	}
	layout, err := newVMM(d.cfg, id, d.logger)
	if err != nil {
		return vmmRecord{}, false
	}
	ticks, err := processStart(pid)
	if err != nil {
		return vmmRecord{}, false
	}
	rec := vmmRecord{SandboxID: id, PID: pid, StartTicks: ticks, BootID: boot,
		APISocket: layout.apiSocket, RunDir: layout.runDir, OwnsRunDir: true}
	if d.pool != nil {
		if slot, err := d.pool.Get(ctx, id); err == nil && slot != nil {
			rec.VsockCID = slot.VsockCID
		}
	}
	return rec, true
}

// vmSandboxFromArgs reads the sandbox ID off a firecracker command line.
func vmSandboxFromArgs(args []string, runDir string) (string, bool) {
	if len(args) == 0 || filepath.Base(args[0]) != "firecracker" {
		return "", false
	}
	for i := 1; i+1 < len(args); i++ {
		switch args[i] {
		case "--id":
			if validateSandboxID(args[i+1]) == nil {
				return args[i+1], true
			}
		case "--api-sock":
			dir := filepath.Dir(args[i+1])
			if runDir != "" && filepath.Dir(dir) == filepath.Clean(runDir) && validateSandboxID(filepath.Base(dir)) == nil {
				return filepath.Base(dir), true
			}
		}
	}
	return "", false
}

// resumeIfPaused resumes a VM a Stop paused and then never finished: the
// sandboxd stopping it died first. Its sandbox is still running, so the VM
// must be too; the next Stop saves it again.
func (d *Driver) resumeIfPaused(ctx context.Context, sandboxID string, client VMMClient) {
	ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := client.InstanceInfo(ictx)
	if err != nil {
		d.logger.Warn("firecracker adopt: VM state unknown", "sandbox_id", sandboxID, "error", err)
		return
	}
	if info.State != "Paused" {
		return
	}
	if err := client.PatchVM(ictx, firecracker.VM{State: firecracker.VMStateResumed}); err != nil {
		d.logger.Warn("firecracker adopt: paused VM not resumed", "sandbox_id", sandboxID, "error", err)
		return
	}
	d.logger.Info("firecracker adopt: resumed a VM an interrupted stop left paused", "sandbox_id", sandboxID)
}

// runDirRoot is the directory every VM's run dir is under.
func (d *Driver) runDirRoot() string {
	if d.cfg.UseJailer {
		return d.cfg.JailerChrootBase
	}
	return d.cfg.RunDir
}

// adoptedVMM is a VM a previous sandboxd started. It has no exec.Cmd and
// no output pipe; it is driven by signals through its pidfd.
type adoptedVMM struct {
	rec         vmmRecord
	proc        liveProcess
	cleanupRoot string
	closeOnce   sync.Once
}

func (h *adoptedVMM) APISocket() string { return h.rec.APISocket }
func (h *adoptedVMM) RunDir() string    { return h.rec.RunDir }

func (h *adoptedVMM) Start(context.Context) error {
	return errors.New("vmm: an adopted VM is already running")
}

func (h *adoptedVMM) WaitSocket(context.Context, time.Duration) error { return nil }

// StderrTail is the head of the VM's output file, as for a VM this sandboxd
// started. A VM a release before the file started has none.
func (h *adoptedVMM) StderrTail() string {
	if h.rec.RunDir == "" {
		return ""
	}
	return readOutputHead(filepath.Join(h.rec.RunDir, vmmOutputName))
}

func (h *adoptedVMM) Pid() int {
	select {
	case <-h.proc.Done():
		return 0
	default:
		return h.rec.PID
	}
}

// Shutdown sends SIGTERM, then SIGKILL after grace, as vmm.Shutdown does.
func (h *adoptedVMM) Shutdown(ctx context.Context, grace time.Duration) error {
	select {
	case <-h.proc.Done():
		h.close()
		return nil
	default:
	}
	_ = h.proc.Signal(syscall.SIGTERM)
	if grace <= 0 {
		grace = 3 * time.Second
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-h.proc.Done():
	case <-timer.C:
		_ = h.proc.Signal(syscall.SIGKILL)
		<-h.proc.Done()
	case <-ctx.Done():
		return ctx.Err()
	}
	h.close()
	return nil
}

func (h *adoptedVMM) Kill() error {
	_ = h.proc.Signal(syscall.SIGKILL)
	<-h.proc.Done()
	h.close()
	return nil
}

func (h *adoptedVMM) close() {
	h.closeOnce.Do(func() { _ = h.proc.Close() })
}

// Cleanup removes the run dir, with vmm.Cleanup's guard against a path
// outside the run dir root.
func (h *adoptedVMM) Cleanup() error {
	if !h.rec.OwnsRunDir || h.rec.RunDir == "" {
		return nil
	}
	if h.cleanupRoot == "" || !strings.HasPrefix(h.rec.RunDir, h.cleanupRoot+string(filepath.Separator)) {
		return fmt.Errorf("vmm: refusing to clean up path outside %q: %s", h.cleanupRoot, h.rec.RunDir)
	}
	if err := os.RemoveAll(h.rec.RunDir); err != nil {
		return err
	}
	removeJailDir(h.rec.RunDir, h.rec.SandboxID)
	return nil
}
