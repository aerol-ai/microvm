package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) cleanupWasmSandboxArtifacts(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || sandbox == nil || !s.isWasmSandbox(sandbox) {
		return nil
	}
	if s.store != nil {
		if err := s.store.DeleteAllWasmStateKV(ctx, sandbox.ID); err != nil {
			return err
		}
		if err := s.store.DeleteAllWasmCheckpointPushes(ctx, sandbox.ID); err != nil {
			return err
		}
	}
	if s.wasmCheckpointPusher != nil {
		if registryRef := strings.TrimSpace(sandbox.WasmRegistryRef); registryRef != "" {
			if err := s.wasmCheckpointPusher.DeleteRef(ctx, registryRef); err != nil {
				s.logger.Warn("delete wasm checkpoint AOCR ref failed",
					"sandbox_id", sandbox.ID,
					"registry_ref", registryRef,
					"error", err,
				)
			}
		}
	}
	return nil
}
