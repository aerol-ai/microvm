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
	moduleDigest string
	socketPath   string
	workDir      string
	workerKey    string
	fromWarmPool bool
	status       models.SandboxStatus
	entryExport  string
	baseEnv      map[string]string
	baseArgs     []string
	preopens     []wasmengine.Preopen
	cpu          float64
	memoryMB     int
	diskGB       int
	durability   string
	sessions     *sessions.Manager

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
