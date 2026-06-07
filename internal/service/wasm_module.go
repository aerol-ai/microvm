package service

import (
	"context"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// registerWasmModuleCatalogue upserts a wasm_modules row after a successful create.
func (s *Service) registerWasmModuleCatalogue(ctx context.Context, sandbox *models.Sandbox, modulePath string, sizeBytes int64) {
	if sandbox == nil || !s.isWasmSandbox(sandbox) {
		return
	}
	ref := strings.TrimSpace(sandbox.ModuleRef)
	if ref == "" {
		return
	}
	id := ref
	if strings.Contains(ref, "://") {
		id = sandbox.ModuleDigest
	}
	if id == "" {
		id = ref
	}
	now := time.Now().UTC()
	_ = s.store.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:              id,
		ModuleRef:       ref,
		Status:          "ready",
		ModulePath:      modulePath,
		ModuleSizeBytes: sizeBytes,
		Digest:          sandbox.ModuleDigest,
		Entrypoint:      entryExportFromSandbox(sandbox),
		HasWarm:         s.cfg.WasmPoolEnabled,
		CreatedAt:       now,
		ReadyAt:         &now,
	})
}

func entryExportFromSandbox(sb *models.Sandbox) string {
	if sb == nil || len(sb.ContainerCommand) == 0 {
		return "_start"
	}
	return sb.ContainerCommand[0]
}
