package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// WasmCheckpointPushResult is persisted on the sandbox row after a successful AOCR push.
type WasmCheckpointPushResult struct {
	RegistryRef string
	Digest      string
}

// WasmCheckpointPusher uploads durable WASM checkpoints to AOCR via ORAS.
type WasmCheckpointPusher struct {
	cfg    SnapshotPushConfig
	logger *slog.Logger
}

// NewWasmCheckpointPusher builds a pusher. Returns nil when cfg.Enabled is false.
func NewWasmCheckpointPusher(cfg SnapshotPushConfig, logger *slog.Logger) (*WasmCheckpointPusher, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &WasmCheckpointPusher{cfg: cfg, logger: logger}, nil
}

// DestRefFor returns the AOCR ref for sandboxID without pushing.
func (p *WasmCheckpointPusher) DestRefFor(sandboxID string) string {
	if p == nil {
		return ""
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return ""
	}
	return wasmmod.WasmCheckpointRef(p.cfg.Host, p.cfg.ClusterID, sandboxID)
}

// PushOnce uploads memSnapDir to AOCR for sandboxID.
func (p *WasmCheckpointPusher) PushOnce(ctx context.Context, sandboxID, memSnapDir string) (WasmCheckpointPushResult, error) {
	if p == nil {
		return WasmCheckpointPushResult{}, errors.New("wasm checkpoint push disabled (pusher is nil)")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	memSnapDir = strings.TrimSpace(memSnapDir)
	if sandboxID == "" || memSnapDir == "" {
		return WasmCheckpointPushResult{}, fmt.Errorf("wasm checkpoint push: sandbox id and mem.snap dir required")
	}

	dest := p.DestRefFor(sandboxID)
	orasCfg := wasmmod.ORASPushConfig{
		Host:      p.cfg.Host,
		ClusterID: p.cfg.ClusterID,
		PATPath:   p.cfg.PATPath,
	}
	digest, err := wasmmod.PushSnapshotArtifact(ctx, orasCfg, memSnapDir, dest)
	if err != nil {
		return WasmCheckpointPushResult{}, fmt.Errorf("wasm checkpoint push %s -> %s: %w", sandboxID, dest, err)
	}
	if p.logger != nil {
		p.logger.Info("wasm checkpoint pushed to AOCR",
			"sandbox_id", sandboxID,
			"dest", dest,
			"digest", digest,
		)
	}
	return WasmCheckpointPushResult{RegistryRef: dest, Digest: digest}, nil
}
