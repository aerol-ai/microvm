package wasm

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
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
	sessions         *sessions.Manager

	// Guest HTTP: resolved host port after ephemeral wasip1 bind (0 in caps).
	resolvedListenPort int
	runGeneration      uint64
	guestServeGen      uint64
	guestServeMu       sync.Mutex
}

func (d *Driver) sandboxDir(sandboxID string) string {
	return filepath.Join(d.cfg.RunDir, sandboxID)
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
