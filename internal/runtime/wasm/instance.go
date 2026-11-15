package wasm

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

const wasmLoopbackIP = "127.0.0.1"

type sandboxInstance struct {
	sandboxID    string
	moduleRef    string
	modulePath   string
	moduleSize   int64
	moduleDigest string
	socketPath   string
	workDir      string
	workerKey    string
	// workerSpawnCount is sampled from the supervisor when this instance is
	// loaded. If the slot respawns later, the new worker is empty and the
	// driver must not keep reporting the sandbox as live.
	workerSpawnCount int
	fromWarmPool     bool
	// fromResidentHost marks a sandbox instantiated into a shared resident host
	// process (compile-once/instantiate-many). Its socketPath is the bucket host
	// socket and workerKey is the bucket id — destroy must StopInstance, NOT kill
	// the shared process, and the per-sandbox supervisor spawn-count tracking does
	// not apply.
	fromResidentHost bool
	// residentSlotHeld is true once this instance has reserved a live slot on its
	// resident host; releaseResidentSlotFor clears it so the slot is freed exactly
	// once (Finding P1-2). Meaningless unless fromResidentHost.
	residentSlotHeld bool
	status           models.SandboxStatus
	entryExport      string
	baseEnv          map[string]string
	baseArgs         []string
	preopens         []wasmengine.Preopen
	cpu              float64
	memoryMB         int
	diskGB           int
	durability       string

	// Guest HTTP: resolved host port after ephemeral wasip1 bind (0 in caps).
	resolvedListenPort int
	runGeneration      uint64
	guestServeGen      uint64
	guestServeMu       sync.Mutex

	// streams are the sandbox's live streaming runs (stream.go), created on
	// first use under Driver.mu. Stop, Destroy and a passivating checkpoint
	// end them.
	streams *streamSet
}

func (d *Driver) sandboxDir(sandboxID string) string {
	return filepath.Join(d.cfg.RunDir, sandboxID)
}

// The driver keeps its host-side state in dirs of its own under the run
// dir, never in a sandbox's dir: that dir is the guest's /work, preopened to
// the guest and open to the toolbox files API, so the guest can rewrite,
// delete or swap for a symlink anything in it. The names start with a dot,
// which no sandbox id can (models.ValidateSandboxID), so neither is ever a
// sandbox's dir.
const (
	recordsDirName = ".records" // instance records, <sandbox id>.json
	socketsDirName = ".sockets" // per-sandbox worker sockets, <sandbox id>.sock
)

// legacyWorkerSocketName is the socket a per-sandbox worker listened on in
// the sandbox's dir before sockets moved to socketsDirName. Workers outlive
// sandboxd, so an upgraded sandboxd still adopts workers there and talks to
// them on it until they stop. Until then the socket is in the guest's
// /work: deleting it or swapping it for a link cuts sandboxd off from that
// sandbox's own worker, and a worker of this release that the link leads to
// refuses requests for any sandbox but the one it holds
// (worker.Server.refuseForeign).
const legacyWorkerSocketName = "worker.sock"

// workerSocketPath is the socket of a new worker of the sandbox's own. ""
// without a run dir or for an id that is not a sandbox id, which could name
// a path outside the dir.
func (d *Driver) workerSocketPath(sandboxID string) string {
	if d.cfg.RunDir == "" || models.ValidateSandboxID(sandboxID) != nil {
		return ""
	}
	return filepath.Join(d.cfg.RunDir, socketsDirName, sandboxID+".sock")
}

// legacyWorkerSocketPath is where a per-sandbox worker from before
// socketsDirName listens ("" as for workerSocketPath).
func (d *Driver) legacyWorkerSocketPath(sandboxID string) string {
	if d.cfg.RunDir == "" || models.ValidateSandboxID(sandboxID) != nil {
		return ""
	}
	return filepath.Join(d.sandboxDir(sandboxID), legacyWorkerSocketName)
}

// ensureHostDirs makes the driver's own dirs under the run dir, once per
// process: after the first call a create pays one atomic load for it.
func (d *Driver) ensureHostDirs() error {
	if d.hostDirsReady.Load() {
		return nil
	}
	d.hostDirsMu.Lock()
	defer d.hostDirsMu.Unlock()
	if d.hostDirsReady.Load() {
		return nil
	}
	if d.cfg.RunDir == "" {
		return fmt.Errorf("wasm runtime: run dir not configured")
	}
	for _, name := range []string{recordsDirName, socketsDirName} {
		if err := os.MkdirAll(filepath.Join(d.cfg.RunDir, name), 0o700); err != nil {
			return fmt.Errorf("wasm runtime: %w", err)
		}
	}
	d.hostDirsReady.Store(true)
	return nil
}

// ownWorkerSocket is the socket for a new worker of the sandbox's own, with
// its dir in place.
func (d *Driver) ownWorkerSocket(sandboxID string) (string, error) {
	if err := d.ensureHostDirs(); err != nil {
		return "", err
	}
	socket := d.workerSocketPath(sandboxID)
	if socket == "" {
		return "", fmt.Errorf("wasm runtime: no worker socket for sandbox id %q", sandboxID)
	}
	return socket, nil
}

func (d *Driver) socketPath(sandboxID string) string {
	// sun_path is capped at 104 bytes on macOS — nest sockets directly under /tmp.
	return filepath.Join(os.TempDir(), "aerol-wasm-"+sandboxID+".sock")
}

func moduleRefFromRequest(req models.CreateSandboxRequest) string {
	return models.ModuleRefForCreate(req)
}

func entryExportFromRequest(req models.CreateSandboxRequest) string {
	// WASI modules export _start; ContainerCommand is argv (see wasmArgs), not the export name.
	return "_start"
}
