package wasm

import (
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/pkg/models"
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
	cpu          float64
	memoryMB     int
	diskGB       int
	durability   string
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
	if len(req.ContainerCommand) > 0 {
		return req.ContainerCommand[0]
	}
	return "_start"
}
