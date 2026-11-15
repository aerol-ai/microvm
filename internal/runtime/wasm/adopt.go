package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/pkg/hostproc"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// A WASM sandbox outlives the sandboxd that started it, as a container
// outlives dockerd. Every node upgrade restarts sandboxd, so this is what
// keeps WASM sandboxes running through one. Four parts:
//
//   - Workers start in the workers' cgroup (SetWorkerCgroup), outside
//     sandboxd's unit, so systemd's stop of the unit does not reach them.
//   - Each running instance keeps a record in the driver's records dir
//     (recordsDirName): which worker holds it and on which socket. It names
//     no secrets; the sandbox row has the rest. Releases before this kept
//     it in the sandbox's work dir, the guest's /work; such a record is
//     read once, checked, and moved (readInstanceRecord, AdoptSandbox).
//   - At boot AdoptWorkers takes over the workers left in the cgroup: the
//     resident hosts at once (they are shared), the per-sandbox workers
//     only once a sandbox claims them.
//   - The service then calls AdoptSandbox for each started WASM row: an
//     instance its worker still holds, and says it holds for that sandbox,
//     is registered as if this sandboxd had made it. RestoreSandbox brings
//     back one whose worker did not survive (an upgrade from a release
//     before this, a crash), with its /work files, and FinishAdoption stops
//     every worker nobody claimed.
//
// The run dir is on tmpfs (/run), so a reboot, which ends every worker,
// also ends every record and every /work dir.

// legacyInstanceRecordName is the record a running instance kept in its
// work dir before records moved to recordsDirName.
const legacyInstanceRecordName = "instance.json"

// maxRecordBytes caps a record read. A record is a few hundred bytes; the
// cap is for the one read from a guest's /work.
const maxRecordBytes = 64 << 10

// instanceRecord is what a running instance leaves for the next sandboxd.
type instanceRecord struct {
	SandboxID    string `json:"sandbox_id"`
	Socket       string `json:"socket"`
	WorkerKey    string `json:"worker_key"`
	Resident     bool   `json:"resident,omitempty"`
	WarmPool     bool   `json:"warm_pool,omitempty"`
	ModuleRef    string `json:"module_ref,omitempty"`
	ModulePath   string `json:"module_path,omitempty"`
	ModuleDigest string `json:"module_digest,omitempty"`
	ModuleSize   int64  `json:"module_size,omitempty"`
	EntryExport  string `json:"entry_export,omitempty"`
	MemoryMB     int    `json:"memory_mb,omitempty"`
	// ListenPort is the host port a serving guest listens on (expose_port).
	ListenPort int `json:"listen_port,omitempty"`
}

// ErrNotAdopted: no running instance of the sandbox survived to adopt.
var ErrNotAdopted = errors.New("wasm: no running instance to adopt")

// Host seams, replaced in tests.
var (
	findWorkers = worker.FindWorkers
	stopProcess = func(p hostproc.Process) { hostproc.Stop(p, 3*time.Second) }
)

// workerAdopter is the supervisor half of adoption (worker.Supervisor).
type workerAdopter interface {
	Adopt(key, socketPath string, proc hostproc.Process) bool
}

// workerSurvivor reports whether a supervisor's workers outlive sandboxd
// (worker.Supervisor).
type workerSurvivor interface {
	Survives() bool
}

// SetWorkerCgroup names the cgroup the workers run in, which AdoptWorkers
// lists at boot. The supervisors start their workers there themselves.
func (d *Driver) SetWorkerCgroup(cg *hostproc.Cgroup) {
	d.workerCgroup = cg
}

// instanceRecordPath is a sandbox's record in the driver's records dir. ""
// without a run dir or for an id that is not a sandbox id.
func (d *Driver) instanceRecordPath(sandboxID string) string {
	if d.cfg.RunDir == "" || models.ValidateSandboxID(sandboxID) != nil {
		return ""
	}
	return filepath.Join(d.cfg.RunDir, recordsDirName, sandboxID+".json")
}

// legacyInstanceRecordPath is where releases before recordsDirName kept a
// sandbox's record: in its work dir ("" as for instanceRecordPath).
func (d *Driver) legacyInstanceRecordPath(sandboxID string) string {
	if d.cfg.RunDir == "" || models.ValidateSandboxID(sandboxID) != nil {
		return ""
	}
	return filepath.Join(d.sandboxDir(sandboxID), legacyInstanceRecordName)
}

// recordInstance writes inst's record, whole or not at all. Best-effort: a
// sandbox without a record is restored fresh after a restart instead of
// taken over, and says so in the log. The run dir is on tmpfs, so this is
// one small in-memory write.
func (d *Driver) recordInstance(inst *sandboxInstance) {
	if inst == nil || d.cfg.RunDir == "" {
		return
	}
	path := d.instanceRecordPath(inst.sandboxID)
	err := d.ensureHostDirs()
	if err == nil && path == "" {
		err = fmt.Errorf("not a sandbox id")
	}
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("wasm: running instance not recorded; a sandboxd restart will restart it fresh",
				"sandbox_id", inst.sandboxID, "error", err)
		}
		return
	}
	d.mu.Lock()
	rec := instanceRecord{
		SandboxID: inst.sandboxID, Socket: inst.socketPath, WorkerKey: inst.workerKey,
		Resident: inst.fromResidentHost, WarmPool: inst.fromWarmPool,
		ModuleRef: inst.moduleRef, ModulePath: inst.modulePath, ModuleDigest: inst.moduleDigest,
		ModuleSize: inst.moduleSize, EntryExport: inst.entryExport, MemoryMB: inst.memoryMB,
		ListenPort: inst.resolvedListenPort,
	}
	d.mu.Unlock()
	if err := writeFileAtomic(path, rec); err != nil && d.logger != nil {
		d.logger.Warn("wasm: running instance not recorded; a sandboxd restart will restart it fresh",
			"sandbox_id", inst.sandboxID, "error", err)
	}
}

// readInstanceRecord reads a sandbox's record. ok is false when it has
// none, or none that names a worker this driver gives the sandbox
// (recordRoutesValid). legacy marks a record read from the sandbox's work
// dir, where releases before this kept it: the guest could have written
// that file, so only its routing fields are kept (which worker, on which
// socket), and AdoptSandbox takes the rest from the sandbox row and the
// worker.
func (d *Driver) readInstanceRecord(sandboxID string) (rec instanceRecord, legacy, ok bool) {
	path := d.instanceRecordPath(sandboxID)
	if path == "" {
		return instanceRecord{}, false, false
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return d.readLegacyInstanceRecord(sandboxID)
	}
	if err == nil && json.Unmarshal(raw, &rec) == nil && rec.SandboxID == sandboxID && d.recordRoutesValid(sandboxID, rec, false) {
		return rec, false, true
	}
	if d.logger != nil {
		d.logger.Warn("wasm adopt: unusable instance record; the sandbox is restored instead",
			"sandbox_id", sandboxID, "path", path, "error", err)
	}
	return instanceRecord{}, false, false
}

func (d *Driver) readLegacyInstanceRecord(sandboxID string) (instanceRecord, bool, bool) {
	raw, err := readGuestFile(d.legacyInstanceRecordPath(sandboxID), maxRecordBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return instanceRecord{}, false, false
	}
	var rec instanceRecord
	if err != nil || json.Unmarshal(raw, &rec) != nil || rec.SandboxID != sandboxID || !d.recordRoutesValid(sandboxID, rec, true) {
		if d.logger != nil {
			d.logger.Warn("wasm adopt: the record in the sandbox's work dir names no worker this driver gives it; the sandbox is restored instead",
				"sandbox_id", sandboxID, "error", err)
		}
		return instanceRecord{}, false, false
	}
	return instanceRecord{SandboxID: rec.SandboxID, Socket: rec.Socket, WorkerKey: rec.WorkerKey,
		Resident: rec.Resident, WarmPool: rec.WarmPool}, true, true
}

// readGuestFile reads a small file from a dir the guest can write: not
// through a symlink at its name, which could lead anywhere on the host,
// without blocking on a FIFO, and only a regular file of at most limit
// bytes.
func readGuestFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return raw, nil
}

// recordRoutesValid reports whether a record names, consistently, a worker
// this driver would give the sandbox:
//   - its own worker: its own socket, under its id as the worker key. A
//     legacy record can name only the socket in the sandbox's dir, where
//     releases before this put it; a record of the driver's may name either
//     (an adopted worker keeps the socket it was started on).
//   - a warm-pool slot's worker: a slot socket of the pool over this run
//     dir, under the slot's id. Slot ids are random and in no path a guest
//     sees.
//   - a resident host: one of this run dir's resident sockets, under the
//     host's key. A resident host answers per sandbox whether it holds an
//     instance (HasInstance), and did before any sandboxd adopted one, so
//     naming one gets a record nothing the host does not confirm.
//
// So no record, wherever it was read, names another sandbox's own worker.
func (d *Driver) recordRoutesValid(sandboxID string, rec instanceRecord, legacy bool) bool {
	if rec.Socket == "" {
		return false
	}
	switch {
	case rec.Resident:
		bucketID, index, ok := parseResidentSocket(d.cfg.RunDir, rec.Socket)
		return ok && !rec.WarmPool && rec.WorkerKey == d.residentHostKey(bucketID, index)
	case rec.WarmPool:
		slotID, ok := wasmpool.SlotFromSocket(d.cfg.RunDir, rec.Socket)
		return ok && rec.WorkerKey == slotID
	case rec.WorkerKey != sandboxID:
		return false
	case rec.Socket == d.legacyWorkerSocketPath(sandboxID):
		return true
	default:
		return !legacy && rec.Socket == d.workerSocketPath(sandboxID)
	}
}

// writeFileAtomic writes v as JSON at path through a temp file and a
// rename, so a reader never sees half a record.
func writeFileAtomic(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
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

// AdoptReport counts what AdoptWorkers found.
type AdoptReport struct {
	ResidentHosts int // resident hosts taken over
	Workers       int // per-sandbox workers held for a sandbox to claim
	Stopped       int // processes stopped: not a worker, unhealthy, or unusable
}

// AdoptWorkers takes over the workers a previous sandboxd left running in
// the workers' cgroup. Call it once at boot, after the supervisors are
// wired and before anything creates, prewarms or reconciles: the prewarm
// would start a second resident host on a socket an adopted one serves.
//
// A resident host is adopted at once when it still answers with its module
// loaded; its instances are claimed by AdoptSandbox. A per-sandbox worker
// is held until a sandbox's record names its socket (FinishAdoption stops
// the rest). Anything else in the cgroup is stopped: nothing would ever
// manage it.
func (d *Driver) AdoptWorkers(ctx context.Context) AdoptReport {
	var report AdoptReport
	if d.workerCgroup == nil {
		return report
	}
	found, err := findWorkers(d.workerCgroup)
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("wasm adopt: workers' cgroup unreadable; running workers are not taken over", "error", err)
		}
		return report
	}
	stop := func(f worker.FoundWorker, why string) {
		if d.logger != nil {
			d.logger.Info("wasm adopt: stopping a leftover worker", "pid", f.PID, "socket", f.Socket, "reason", why)
		}
		stopProcess(f.Proc)
		report.Stopped++
	}
	for _, f := range found {
		switch {
		case f.Socket == "":
			stop(f, "not a worker")
		case f.Resident:
			if why := d.adoptResidentHost(ctx, f); why != "" {
				stop(f, why)
				continue
			}
			report.ResidentHosts++
		default:
			if !strings.HasPrefix(f.Socket, filepath.Clean(d.cfg.RunDir)+string(filepath.Separator)) {
				stop(f, "socket outside the run dir")
				continue
			}
			d.residentMu.Lock()
			if d.pendingWorkers == nil {
				d.pendingWorkers = make(map[string]worker.FoundWorker)
			}
			d.pendingWorkers[f.Socket] = f
			d.residentMu.Unlock()
			report.Workers++
		}
	}
	if d.logger != nil && (report.ResidentHosts+report.Workers+report.Stopped) > 0 {
		d.logger.Info("wasm adopt: workers from the previous sandboxd", "resident_hosts", report.ResidentHosts,
			"workers", report.Workers, "stopped", report.Stopped)
	}
	return report
}

// adoptResidentHost registers a running resident host in its bucket. It
// returns why it could not, or "".
func (d *Driver) adoptResidentHost(ctx context.Context, f worker.FoundWorker) string {
	if !d.residentHostEnabled() {
		return "resident hosts are off"
	}
	bucketID, index, ok := parseResidentSocket(d.cfg.RunDir, f.Socket)
	if !ok {
		return "not a resident host socket"
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	loaded, err := d.newWorkerClient(f.Socket).InstanceLoaded(checkCtx, "")
	cancel()
	if err != nil || !loaded {
		return fmt.Sprintf("does not answer with its module loaded (loaded=%v, err=%v)", loaded, err)
	}
	adopter, ok := d.residentSupervisor.(workerAdopter)
	if !ok || !adopter.Adopt(d.residentHostKey(bucketID, index), f.Socket, f.Proc) {
		return "resident supervisor cannot adopt it"
	}
	now := time.Now()
	d.residentMu.Lock()
	if d.residentBuckets == nil {
		d.residentBuckets = make(map[string]*residentBucket)
	}
	b := d.residentBuckets[bucketID]
	if b == nil {
		b = &residentBucket{id: bucketID}
		d.residentBuckets[bucketID] = b
	}
	d.residentMu.Unlock()
	b.mu.Lock()
	b.hosts = append(b.hosts, &residentHost{socket: f.Socket, index: index, ready: true, lastCheck: now, idleSince: now})
	if index >= b.nextIndex {
		// A spill host started later must not reuse a surviving host's
		// socket.
		b.nextIndex = index + 1
	}
	b.mu.Unlock()
	return ""
}

// residentSocketName is <bucket>.sock or <bucket>-<n>.sock (n >= 2), with a
// bucket id from residentBucketID.
var residentSocketName = regexp.MustCompile(`^((?:o[0-9a-f]{16}-)?[0-9a-f]{16}-[0-9]+mb)(?:-([0-9]+))?\.sock$`)

// parseResidentSocket reads the bucket id and host index back off a
// resident host's socket path (residentSocketPath).
func parseResidentSocket(runDir, socket string) (string, int, bool) {
	if filepath.Dir(socket) != filepath.Join(runDir, "resident") {
		return "", 0, false
	}
	m := residentSocketName.FindStringSubmatch(filepath.Base(socket))
	if m == nil {
		return "", 0, false
	}
	if m[2] == "" {
		return m[1], 0, true
	}
	n, err := strconv.Atoi(m[2])
	if err != nil || n < 2 {
		return "", 0, false
	}
	return m[1], n - 1, true
}

// AdoptSandbox takes over the running instance of a started sandbox, found
// through its record: on its resident host, or on its own worker. The
// instance must still answer; anything else is ErrNotAdopted, and the
// caller restores the sandbox instead. hostMounts are the sandbox's mount
// binds, as for StartSandbox.
func (d *Driver) AdoptSandbox(ctx context.Context, sb *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if sb == nil {
		return nil, ErrNotAdopted
	}
	d.mu.Lock()
	if inst := d.byID[sb.ID]; inst != nil {
		state := d.runtimeState(inst)
		d.mu.Unlock()
		return state, nil
	}
	d.mu.Unlock()
	rec, legacy, ok := d.readInstanceRecord(sb.ID)
	if !ok {
		return nil, ErrNotAdopted
	}
	modulePath, moduleSize, moduleDigest := rec.ModulePath, rec.ModuleSize, firstNonEmpty(rec.ModuleDigest, sb.ModuleDigest)
	if legacy {
		// It passed the checks, so it is one an older sandboxd wrote. It
		// does not stay where the guest can write it: an adoption below
		// records the instance in the driver's dir, and so does a restore.
		_ = os.Remove(d.legacyInstanceRecordPath(sb.ID))
		// The module comes from the row, as for a restore, never from a
		// path the guest could have written. Before the worker is claimed:
		// a failure leaves the worker to FinishAdoption and the sandbox to
		// a restore, which resolves the same way.
		resolved, err := d.moduleFromRow(ctx, sb)
		if err != nil {
			if d.logger != nil {
				d.logger.Warn("wasm adopt: module of a pre-upgrade sandbox not resolved; it is restored instead",
					"sandbox_id", sb.ID, "error", err)
			}
			return nil, ErrNotAdopted
		}
		modulePath, moduleSize = resolved.Path, resolved.SizeBytes
		moduleDigest = firstNonEmpty(sb.ModuleDigest, resolved.Digest)
	}
	var host *residentHost
	var bucket *residentBucket
	if rec.Resident {
		if bucket, host = d.residentHostBySocket(rec.Socket); host == nil {
			return nil, ErrNotAdopted
		}
		st, err := d.instanceStatus(ctx, rec.Socket, sb.ID)
		if err != nil || !st.Loaded || st.Foreign(sb.ID) {
			return nil, ErrNotAdopted
		}
	} else if !d.adoptOwnWorker(ctx, sb.ID, rec) {
		return nil, ErrNotAdopted
	}
	listenPort := rec.ListenPort
	if legacy && !rec.Resident {
		// The worker's own answer, not a number the guest could have
		// written: the guest HTTP proxy dials the port it is given.
		listenPort = d.workerListenPort(rec.Socket, sb.ID)
	}

	workDir := d.sandboxDir(sb.ID)
	inst := &sandboxInstance{
		sandboxID:          sb.ID,
		moduleRef:          firstNonEmpty(rec.ModuleRef, sb.ModuleRef, sb.Image),
		modulePath:         modulePath,
		moduleSize:         moduleSize,
		moduleDigest:       moduleDigest,
		socketPath:         rec.Socket,
		workDir:            workDir,
		workerKey:          rec.WorkerKey,
		fromWarmPool:       rec.WarmPool,
		fromResidentHost:   rec.Resident,
		status:             models.SandboxStatusStarted,
		entryExport:        firstNonEmpty(rec.EntryExport, "_start"),
		baseEnv:            copyStringMap(sb.Env),
		baseArgs:           wasmArgsFromSandbox(sb),
		preopens:           preopensFromBinds(workDir, hostMounts),
		cpu:                sb.CPU,
		memoryMB:           rec.MemoryMB,
		diskGB:             sb.DiskGB,
		durability:         sb.Durability,
		resolvedListenPort: listenPort,
	}
	if inst.memoryMB <= 0 {
		inst.memoryMB = sb.MemoryMB
	}
	if inst.memoryMB <= 0 {
		inst.memoryMB = d.cfg.DefaultMemoryMB
	}
	// The worker still enforces the network state it had; the driver's own
	// copy, which every later instantiation carries, comes from the row.
	blockIn, blockOut := sandboxNetworkBlocks(sb)
	d.seedNetworkBlocks(sb.ID, blockIn, blockOut)
	d.seedNetworkPolicy(sb.ID, sb.NetworkAllowOut, sb.NetworkDenyOut, sb.NetworkEgressMode == models.NetworkEgressModeLearn)
	if host != nil {
		bucket.mu.Lock()
		host.live++
		host.idleSince = time.Time{}
		bucket.mu.Unlock()
		inst.residentSlotHeld = true
	} else {
		d.noteWorkerSpawnCount(inst)
	}
	d.mu.Lock()
	d.byID[sb.ID] = inst
	d.mu.Unlock()
	if legacy {
		d.recordInstance(inst)
	}
	if d.logger != nil {
		d.logger.Info("wasm adopt: running sandbox taken over", "sandbox_id", sb.ID, "resident", rec.Resident,
			"socket", rec.Socket, "record_moved", legacy)
	}
	return d.runtimeState(inst), nil
}

// moduleFromRow resolves the module a stored sandbox runs, pinned to the
// digest it was created with, as StartSandbox does.
func (d *Driver) moduleFromRow(ctx context.Context, sb *models.Sandbox) (*wasmmod.ResolvedModule, error) {
	if d.resolver == nil {
		return nil, fmt.Errorf("module resolver not configured")
	}
	ref := firstNonEmpty(strings.TrimSpace(sb.ModuleRef), strings.TrimSpace(sb.Image))
	if ref == "" {
		return nil, fmt.Errorf("module_ref is required")
	}
	return d.resolvePinned(wasmmod.WithCatalogueOwner(ctx, sb.OwnerRef), ref, sb.ModuleDigest, moduleAuthFromSandbox(sb))
}

// instanceStatusReader is the status question that also says whose
// instance a worker holds (workerClientAdapter). A client without it
// answers as a worker from before that would.
type instanceStatusReader interface {
	InstanceStatus(ctx context.Context, sandboxID string) (worker.InstanceStatus, error)
}

// instanceStatus asks the worker on socket about sandboxID's instance.
func (d *Driver) instanceStatus(ctx context.Context, socket, sandboxID string) (worker.InstanceStatus, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := d.newWorkerClient(socket)
	if r, ok := client.(instanceStatusReader); ok {
		return r.InstanceStatus(checkCtx, sandboxID)
	}
	loaded, err := client.InstanceLoaded(checkCtx, sandboxID)
	return worker.InstanceStatus{Loaded: loaded}, err
}

// adoptOwnWorker takes over the per-sandbox (or warm-slot) worker rec
// names, once that worker answers for sandboxID.
func (d *Driver) adoptOwnWorker(ctx context.Context, sandboxID string, rec instanceRecord) bool {
	if !d.hasPendingWorker(rec.Socket) {
		return false
	}
	// Asked before the claim: a worker that holds another sandbox's
	// instance stays pending for that sandbox's own adoption, unclaimed and
	// running.
	st, err := d.instanceStatus(ctx, rec.Socket, sandboxID)
	if err == nil && st.Foreign(sandboxID) {
		if d.logger != nil {
			d.logger.Warn("wasm adopt: the worker a record names holds another sandbox; not taken over",
				"sandbox_id", sandboxID, "socket", rec.Socket)
		}
		return false
	}
	if !d.claimWorker(rec) {
		return false
	}
	if err != nil || !st.Loaded {
		_ = d.supervisor.Stop(rec.WorkerKey)
		return false
	}
	// A worker from before identity answers (!st.Checked) cannot say whose
	// instance it holds. It is taken on the record's word, and that word
	// can only name this sandbox's own socket or a warm slot's
	// (recordRoutesValid).
	return true
}

// hasPendingWorker reports whether AdoptWorkers holds a worker on socket
// that no sandbox has claimed yet.
func (d *Driver) hasPendingWorker(socket string) bool {
	d.residentMu.Lock()
	defer d.residentMu.Unlock()
	_, ok := d.pendingWorkers[socket]
	return ok
}

// workerListenPort asks a worker which host port its guest listens on; 0
// for none or no answer (the next port sync then starts the listener
// again).
func (d *Driver) workerListenPort(socket, sandboxID string) int {
	port, err := d.newWorkerClient(socket).ResolvedListenPort(sandboxID)
	if err != nil || port < 0 {
		return 0
	}
	return port
}

// residentHostBySocket finds an adopted (or live) resident host.
func (d *Driver) residentHostBySocket(socket string) (*residentBucket, *residentHost) {
	d.residentMu.Lock()
	buckets := make([]*residentBucket, 0, len(d.residentBuckets))
	for _, b := range d.residentBuckets {
		buckets = append(buckets, b)
	}
	d.residentMu.Unlock()
	for _, b := range buckets {
		b.mu.Lock()
		for _, h := range b.hosts {
			if h.socket == socket && h.ready {
				b.mu.Unlock()
				return b, h
			}
		}
		b.mu.Unlock()
	}
	return nil, nil
}

// claimWorker hands the per-sandbox worker a record names to the
// supervisor, under the record's key.
func (d *Driver) claimWorker(rec instanceRecord) bool {
	d.residentMu.Lock()
	f, ok := d.pendingWorkers[rec.Socket]
	if ok {
		delete(d.pendingWorkers, rec.Socket)
	}
	d.residentMu.Unlock()
	if !ok {
		return false
	}
	adopter, isAdopter := d.supervisor.(workerAdopter)
	if !isAdopter || rec.WorkerKey == "" || !adopter.Adopt(rec.WorkerKey, rec.Socket, f.Proc) {
		stopProcess(f.Proc)
		return false
	}
	return true
}

// FinishAdoption stops the per-sandbox workers no sandbox claimed: a
// stopped or destroyed sandbox's, or a warm-pool slot's (the pool starts
// empty at boot). It returns how many it stopped.
func (d *Driver) FinishAdoption() int {
	d.residentMu.Lock()
	left := d.pendingWorkers
	d.pendingWorkers = nil
	d.residentMu.Unlock()
	for _, f := range left {
		if d.logger != nil {
			d.logger.Info("wasm adopt: stopping a worker no running sandbox claims", "pid", f.PID, "socket", f.Socket)
		}
		stopProcess(f.Proc)
	}
	return len(left)
}

// HasWorkDir reports whether the sandbox's work dir (its /work) is still
// there: after a sandboxd restart it is, after a reboot it is not.
func (d *Driver) HasWorkDir(sandboxID string) bool {
	if d.cfg.RunDir == "" || models.ValidateSandboxID(sandboxID) != nil {
		return false
	}
	st, err := os.Stat(d.sandboxDir(sandboxID))
	return err == nil && st.IsDir()
}

// RestoreSandbox brings back a started sandbox whose instance did not
// survive a sandboxd restart: a new instance over the same work dir, so
// its /work files are kept. It goes where a create would put it: the
// resident host, unless the sandbox has public traffic or exposed ports.
// Memory of the old instance is gone; a serving guest is started again by
// the next port sync.
func (d *Driver) RestoreSandbox(ctx context.Context, sb *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if sb == nil {
		return nil, fmt.Errorf("restore: nil sandbox")
	}
	public := sb.AllowPublicTraffic != nil && *sb.AllowPublicTraffic
	if !d.residentHostEnabled() || public || len(sb.ExposedPorts) > 0 || d.resolver == nil {
		return d.StartSandbox(ctx, sb, hostMounts)
	}
	ref := firstNonEmpty(strings.TrimSpace(sb.ModuleRef), strings.TrimSpace(sb.Image))
	if ref == "" {
		return nil, fmt.Errorf("restore sandbox %s: module_ref is required", sb.ID)
	}
	ownerCtx := wasmmod.WithCatalogueOwner(ctx, sb.OwnerRef)
	resolved, err := d.resolvePinned(ownerCtx, ref, sb.ModuleDigest, moduleAuthFromSandbox(sb))
	if err != nil {
		return nil, err
	}
	if resolved.Digest == "" {
		return d.StartSandbox(ctx, sb, hostMounts)
	}
	memoryMB := sb.MemoryMB
	if memoryMB <= 0 {
		memoryMB = d.cfg.DefaultMemoryMB
	}
	return d.createOnResidentHost(ownerCtx, requestFromSandbox(sb), sb.ID, ref, resolved, memoryMB, hostMounts, nil)
}

// requestFromSandbox is the create request a stored sandbox was made from,
// as far as an instantiation needs it.
func requestFromSandbox(sb *models.Sandbox) models.CreateSandboxRequest {
	return models.CreateSandboxRequest{
		Runtime:            models.RuntimeWasm,
		ModuleRef:          sb.ModuleRef,
		Image:              sb.Image,
		Env:                copyStringMap(sb.Env),
		ContainerCommand:   append([]string(nil), sb.ContainerCommand...),
		CPU:                sb.CPU,
		MemoryMB:           sb.MemoryMB,
		DiskGB:             sb.DiskGB,
		Durability:         sb.Durability,
		AllowPublicTraffic: sb.AllowPublicTraffic,
		NetworkBlockAll:    sb.NetworkBlockAll,
		NetworkAllowOut:    sb.NetworkAllowOut,
		NetworkDenyOut:     sb.NetworkDenyOut,
		NetworkEgressMode:  sb.NetworkEgressMode,
	}
}

// KeepOnShutdown reports whether the shutdown drain must leave a sandbox's
// instance alone instead of checkpointing it: its worker outlives
// sandboxd, or it is on a resident host, which serves no checkpoint (its
// instance keeps no memory between execs; its state is the /work files,
// which outlive the restart either way). Checkpointing such an instance
// failed on the resident host and tore down a worker that would have
// survived (T14: passivate_failed for good).
func (d *Driver) KeepOnShutdown(sandboxID string) bool {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		return false
	}
	if inst.fromResidentHost {
		return true
	}
	s, ok := d.supervisor.(workerSurvivor)
	return ok && s.Survives()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
