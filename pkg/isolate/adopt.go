package isolate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// A group host outlives the sandboxd that started it, so a sandboxd restart
// (every node upgrade) keeps the isolates it runs, with their in-memory
// state. workerd is the process that must survive; the Go side of the host
// (the bundle server, the egress servers) lives in sandboxd and is started
// again on the same sockets by the next one. Three parts:
//
//   - workerd runs outside sandboxd's unit: a jailed one in its group's
//     cgroup (applyJail), an unjailed one in the hosts' cgroup
//     (HostConfig.Cgroup).
//   - A running host keeps a record (HostConfig.RecordDir/<key>.json): its
//     workerd (pid, start time, boot), its run dir and jail, which sandboxes
//     it holds and which egress slot each one has. The slot must be the
//     same after the restart: the controller caches each isolate by id and
//     slot, so a sandbox given another slot would get a fresh isolate and
//     lose its state. Records name no secrets.
//   - At boot AdoptHosts reads the records back and takes each host over
//     whose workerd still runs; SweepLeftovers then removes every jail and
//     process no record kept.
//
// The record dir is on tmpfs (/run), so a reboot, which ends every workerd,
// also ends every record.

// hostRecord is what a running host leaves for the next sandboxd.
type hostRecord struct {
	GroupKey       string `json:"group_key"`
	PID            int    `json:"pid"`
	StartTicks     uint64 `json:"start_ticks"`
	BootID         string `json:"boot_id"`
	RunDir         string `json:"run_dir"`
	EgressPoolSize int    `json:"egress_pool_size"`
	Jailed         bool   `json:"jailed,omitempty"`
	ChrootDir      string `json:"chroot_dir,omitempty"`
	CgroupDir      string `json:"cgroup_dir,omitempty"`
	UID            int    `json:"uid,omitempty"`
	GID            int    `json:"gid,omitempty"`
	// Slots is each egressing sandbox's slot; Loaded every sandbox with a
	// pinned bundle.
	Slots  map[string]int `json:"slots,omitempty"`
	Loaded []string       `json:"loaded,omitempty"`
}

// Host seams, replaced in tests.
var (
	openHostProcess = hostproc.Open
	hostStartTicks  = hostproc.StartTicks
	hostBootID      = hostproc.BootID
)

// PID is workerd's process id, or 0 when it is not known.
func (h *Host) PID() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pid
}

// GroupKey is the host's own key: its run dir, chroot and cgroup are named
// after it.
func (h *Host) GroupKey() string { return h.cfg.GroupKey }

func (h *Host) recordPath() string {
	if h.cfg.RecordDir == "" {
		return ""
	}
	return filepath.Join(h.cfg.RecordDir, h.cfg.GroupKey+".json")
}

// writeRecord writes the host's record as it is now, whole or not at all.
// recordMu spans the snapshot and the write, so the last writer always
// writes the newest state. Best-effort: a host without a record still runs,
// but a sandboxd restart stops it instead of taking it over. The record dir
// is on tmpfs, so this is one small in-memory write.
func (h *Host) writeRecord() {
	path := h.recordPath()
	if path == "" || !h.started.Load() {
		return
	}
	h.recordMu.Lock()
	defer h.recordMu.Unlock()
	h.mu.RLock()
	rec := hostRecord{
		GroupKey: h.cfg.GroupKey, PID: h.pid, StartTicks: h.startTicks, BootID: h.bootID,
		RunDir: h.cfg.RunDir, EgressPoolSize: h.cfg.EgressPoolSize,
		Jailed: h.cfg.Jail.Require, ChrootDir: h.cfg.Jail.ChrootDir, UID: h.cfg.Jail.UID, GID: h.cfg.Jail.GID,
	}
	if h.jail != nil {
		rec.CgroupDir = h.jail.cgroupDir
	}
	if len(h.slotByID) > 0 {
		rec.Slots = make(map[string]int, len(h.slotByID))
		for id, slot := range h.slotByID {
			rec.Slots[id] = slot
		}
	}
	for id := range h.bundles {
		rec.Loaded = append(rec.Loaded, id)
	}
	h.mu.RUnlock()
	sort.Strings(rec.Loaded)
	if err := writeRecordFile(path, rec); err != nil && h.logger != nil {
		h.logger.Warn("isolate: running group host not recorded; a sandboxd restart will stop it",
			"group", h.cfg.GroupKey, "error", err)
	}
}

func (h *Host) removeRecord() {
	if path := h.recordPath(); path != "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) && h.logger != nil {
			h.logger.Warn("isolate: group host record not removed", "group", h.cfg.GroupKey, "error", err)
		}
	}
}

// noteProcess remembers who workerd is, for the record.
func (h *Host) noteProcess(pid int) {
	ticks, err := hostStartTicks(pid)
	if err != nil {
		return // not Linux, or gone already: no record can name it
	}
	boot, err := hostBootID()
	if err != nil {
		return
	}
	h.mu.Lock()
	h.pid, h.startTicks, h.bootID = pid, ticks, boot
	h.mu.Unlock()
}

func writeRecordFile(path string, rec hostRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".record-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(raw)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
	}
	return werr
}

// readHostRecords returns the records under dir, removing files that are
// not one (a write cut short leaves only a .record-* temp file).
func readHostRecords(dir string) []hostRecord {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []hostRecord
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		key, isRecord := strings.CutSuffix(e.Name(), ".json")
		var rec hostRecord
		raw, err := os.ReadFile(path)
		if err == nil && isRecord {
			err = json.Unmarshal(raw, &rec)
		}
		if err != nil || !isRecord || rec.GroupKey != key || validateLoaderID(key) != nil || rec.PID <= 0 || rec.RunDir == "" {
			_ = os.Remove(path)
			continue
		}
		out = append(out, rec)
	}
	return out
}

// AdoptedHost is a group host a previous sandboxd left running, taken over.
// Loaded are the sandboxes it holds; their bundles are pinned again with
// Load, their egress policies set again with SetEgressPolicy (their slots
// are already held).
type AdoptedHost struct {
	Host   *Host
	Loaded []string
}

// AdoptHosts takes over every group host recorded under base.RecordDir
// whose workerd still runs and still answers. base carries what a record
// does not (logger, the hosts' cgroup, the start timeout); the rest comes
// from the record. A host that cannot be taken over is stopped and its
// jail torn down. Call it once at boot, before any group is spawned.
func AdoptHosts(ctx context.Context, base HostConfig) []AdoptedHost {
	if base.RecordDir == "" {
		return nil
	}
	boot, bootErr := hostBootID()
	var out []AdoptedHost
	for _, rec := range readHostRecords(base.RecordDir) {
		h, err := adoptHost(ctx, base, rec, boot, bootErr)
		if err != nil {
			if base.Logger != nil {
				base.Logger.Info("isolate adopt: group host not taken over", "group", rec.GroupKey, "pid", rec.PID, "reason", err)
			}
			continue
		}
		out = append(out, AdoptedHost{Host: h, Loaded: append([]string(nil), rec.Loaded...)})
	}
	return out
}

// adoptHost takes one recorded host over, or tears down what is left of it.
func adoptHost(ctx context.Context, base HostConfig, rec hostRecord, boot string, bootErr error) (*Host, error) {
	cfg := base
	cfg.GroupKey = rec.GroupKey
	cfg.RunDir = rec.RunDir
	cfg.EgressPoolSize = rec.EgressPoolSize
	cfg.Jail = JailConfig{Require: rec.Jailed, ChrootDir: rec.ChrootDir, UID: rec.UID, GID: rec.GID}
	if cfg.WorkerdPath == "" {
		cfg.WorkerdPath = "workerd" // an adopted host never starts workerd
	}
	h, err := NewHost(cfg)
	if err != nil {
		removeRecordAt(base.RecordDir, rec.GroupKey)
		return nil, err
	}
	if rec.Jailed {
		h.jail = recordedJail(rec)
	}
	fail := func(err error) (*Host, error) {
		h.removeRecord()
		_ = h.stopServers()
		if terr := h.jail.teardown(); terr != nil && h.logger != nil {
			h.logger.Warn("isolate adopt: leftover jail not removed", "group", rec.GroupKey, "error", terr)
		}
		return nil, err
	}
	if bootErr != nil || rec.BootID != boot {
		return fail(fmt.Errorf("recorded on another boot"))
	}
	proc, err := openHostProcess(rec.PID, rec.StartTicks)
	if err != nil {
		return fail(err)
	}
	kill := func(err error) (*Host, error) {
		_ = proc.Signal(syscall.SIGKILL)
		<-proc.Done()
		_ = proc.Close()
		return fail(err)
	}
	// The previous sandboxd's listeners died with it; their socket files
	// are still there. Start them again on the same paths: workerd dials
	// them by path on each request.
	for _, s := range append([]string{h.hostSock, h.egressDenySock}, h.egressSocks...) {
		_ = os.Remove(s)
	}
	if err := h.startBundleServer(); err != nil {
		return kill(err)
	}
	if err := h.startEgressDenyServer(); err != nil {
		return kill(err)
	}
	if err := h.grantJailAccess(h.hostSock, h.egressDenySock); err != nil {
		return kill(err)
	}
	h.mu.Lock()
	for id, slot := range rec.Slots {
		if slot < 0 || slot >= len(h.idBySlot) || h.idBySlot[slot] != "" {
			continue
		}
		if err := h.startSlotServerLocked(slot); err != nil {
			continue // its sandbox egresses through EGRESS_DENY until a policy update
		}
		h.slotByID[id] = slot
		h.idBySlot[slot] = id
	}
	exited := make(chan struct{})
	client := unixHTTPClient(h.controlSock)
	h.proc = proc
	h.exited = exited
	h.ctrlClient = client
	h.pid, h.startTicks, h.bootID = rec.PID, rec.StartTicks, rec.BootID
	h.mu.Unlock()
	go func() {
		<-proc.Done()
		close(exited)
	}()
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	err = probeControl(probeCtx, client)
	cancel()
	if err != nil {
		h.mu.Lock()
		h.proc = nil
		h.mu.Unlock()
		return kill(fmt.Errorf("workerd does not answer: %w", err))
	}
	h.started.Store(true)
	h.writeRecord()
	if h.logger != nil {
		h.logger.Info("isolate adopt: running group host taken over", "group", rec.GroupKey, "pid", rec.PID, "sandboxes", len(rec.Loaded))
	}
	return h, nil
}

// recordedJail is the jail a record describes, for teardown.
func recordedJail(rec hostRecord) *jailRealized {
	r := &jailRealized{chrootBase: filepath.Dir(rec.ChrootDir), chrootDir: rec.ChrootDir}
	if rec.CgroupDir != "" {
		r.cgroup, r.cgroupDir = cgroupFS{root: filepath.Dir(rec.CgroupDir)}, rec.CgroupDir
	}
	if rec.ChrootDir != "" {
		r.noexecMounts = []string{filepath.Join(rec.ChrootDir, "tmp"), filepath.Join(rec.ChrootDir, JailRunDirName)}
	}
	return r
}

func removeRecordAt(dir, key string) {
	_ = os.Remove(filepath.Join(dir, key+".json"))
}

// Leftovers names where a previous sandboxd's group hosts could have left
// processes or jails that no record kept.
type Leftovers struct {
	// HostsCgroup is the unjailed hosts' cgroup.
	HostsCgroup *hostproc.Cgroup
	// JailCgroupRoot and JailChrootBase hold one cgroup and one chroot per
	// jailed group (aerolvm-isolate-<key> and <key>).
	JailCgroupRoot string
	JailChrootBase string
	// Keep are the group keys of the hosts AdoptHosts took over, and
	// KeepPIDs their workerd processes.
	Keep     map[string]bool
	KeepPIDs map[int]bool
}

// Host seams for the sweep, replaced in tests.
var (
	sweepOpenPID = func(pid int) (hostproc.Process, error) {
		p, _, err := hostproc.OpenPID(pid)
		return p, err
	}
	sweepUnmount = unmountNoexecMounts
)

// SweepLeftovers kills every group-host process and removes every jail a
// previous sandboxd left that no adopted host owns: a host whose record was
// lost or refused, a create cut short, a warm-pool blank. Nothing would
// ever manage them, and a jailed one holds a cgroup and a chroot tree. Call
// it once at boot, after AdoptHosts and before any group is spawned: a key
// reused by a new group must find nothing in its way. It returns how many
// processes it killed.
func SweepLeftovers(l Leftovers) int {
	killed := 0
	if l.HostsCgroup != nil {
		pids, _ := l.HostsCgroup.PIDs()
		killed += killPIDs(pids, l.KeepPIDs)
	}
	if l.JailCgroupRoot != "" {
		entries, _ := os.ReadDir(l.JailCgroupRoot)
		for _, e := range entries {
			key, ok := strings.CutPrefix(e.Name(), jailCgroupPrefix)
			if !e.IsDir() || !ok || l.Keep[key] {
				continue
			}
			dir := filepath.Join(l.JailCgroupRoot, e.Name())
			pids, _ := hostproc.ReadPIDs(filepath.Join(dir, "cgroup.procs"))
			killed += killPIDs(pids, nil)
			_ = (cgroupFS{root: l.JailCgroupRoot}).remove(dir)
		}
	}
	if l.JailChrootBase != "" {
		entries, _ := os.ReadDir(l.JailChrootBase)
		for _, e := range entries {
			if !e.IsDir() || e.Name() == jailBaseName || l.Keep[e.Name()] || validateLoaderID(e.Name()) != nil {
				continue
			}
			dir := filepath.Join(l.JailChrootBase, e.Name())
			sweepUnmount([]string{filepath.Join(dir, "tmp"), filepath.Join(dir, JailRunDirName)})
			_ = removeGroupJail(l.JailChrootBase, dir)
		}
	}
	return killed
}

// jailCgroupPrefix starts every jailed group's cgroup name
// (internal/runtime/isolate.BuildJailSpec).
const jailCgroupPrefix = "aerolvm-isolate-"

// killPIDs SIGKILLs each pid not in keep, through a pidfd so a pid reused
// since the listing is left alone.
func killPIDs(pids []int, keep map[int]bool) int {
	n := 0
	for _, pid := range pids {
		if keep[pid] {
			continue
		}
		p, err := sweepOpenPID(pid)
		if err != nil {
			continue
		}
		_ = p.Signal(syscall.SIGKILL)
		<-p.Done()
		_ = p.Close()
		n++
	}
	return n
}
