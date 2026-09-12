package v1

import (
	"context"
	"os"
	"path/filepath"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
)

type v1WasmMigrateHost struct {
	noopRuntime
	snapDir  string
	cloneGen string
}

func (h v1WasmMigrateHost) MigrateSandbox(_ context.Context, sandbox *models.Sandbox, destDir string) (string, string, error) {
	id := "sandbox"
	if sandbox != nil && sandbox.ID != "" {
		id = sandbox.ID
	}
	dst := filepath.Join(destDir, id, "mem.snap")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", "", err
	}
	entries, err := os.ReadDir(h.snapDir)
	if err != nil {
		return "", "", err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.snapDir, ent.Name()))
		if err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(dst, ent.Name()), data, 0o600); err != nil {
			return "", "", err
		}
	}
	return dst, h.cloneGen, nil
}

var _ wasmruntime.MigrationHost = v1WasmMigrateHost{}
