package service

import (
	"context"
	"fmt"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
)

// MigrateWasmSandbox packages a boundary checkpoint for handoff to a sibling node.
func (s *Service) MigrateWasmSandbox(ctx context.Context, sandboxID, destDir string) (string, string, error) {
	if s.wasm == nil {
		return "", "", fmt.Errorf("wasm runtime not configured")
	}
	host, ok := s.wasm.(wasmruntime.MigrationHost)
	if !ok {
		return "", "", fmt.Errorf("wasm runtime does not implement migration")
	}
	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return "", "", err
	}
	if !s.isWasmSandbox(sandbox) {
		return "", "", fmt.Errorf("sandbox %s is not wasm runtime", sandboxID)
	}
	return host.MigrateSandbox(ctx, sandbox, destDir)
}
