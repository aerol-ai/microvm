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

// DestRefFor returns the AOCR :latest ref for sandboxID without pushing.
func (p *WasmCheckpointPusher) DestRefFor(sandboxID string) string {
	return p.DestRefTagged(sandboxID, "latest")
}

// DestRefTagged returns an AOCR ref with an explicit tag.
func (p *WasmCheckpointPusher) DestRefTagged(sandboxID, tag string) string {
	if p == nil {
		return ""
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return ""
	}
	return wasmmod.WasmCheckpointRefTagged(p.cfg.Host, p.cfg.ClusterID, sandboxID, tag)
}

// PushOnce uploads memSnapDir to AOCR :latest for sandboxID.
func (p *WasmCheckpointPusher) PushOnce(ctx context.Context, sandboxID, memSnapDir string) (WasmCheckpointPushResult, error) {
	return p.PushOnceTo(ctx, sandboxID, memSnapDir, p.DestRefFor(sandboxID))
}

// PushOnceTo uploads memSnapDir to an explicit AOCR ref.
func (p *WasmCheckpointPusher) PushOnceTo(ctx context.Context, sandboxID, memSnapDir, dest string) (WasmCheckpointPushResult, error) {
	if p == nil {
		return WasmCheckpointPushResult{}, errors.New("wasm checkpoint push disabled (pusher is nil)")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	memSnapDir = strings.TrimSpace(memSnapDir)
	if sandboxID == "" || memSnapDir == "" {
		return WasmCheckpointPushResult{}, fmt.Errorf("wasm checkpoint push: sandbox id and mem.snap dir required")
	}
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return WasmCheckpointPushResult{}, fmt.Errorf("wasm checkpoint push: destination ref required")
	}
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

// PullOnce downloads a durable checkpoint from AOCR into dstDir (§4.8 failover).
func (p *WasmCheckpointPusher) PullOnce(ctx context.Context, registryRef, dstDir string) error {
	if p == nil {
		return errors.New("wasm checkpoint pull disabled (pusher is nil)")
	}
	registryRef = strings.TrimSpace(registryRef)
	dstDir = strings.TrimSpace(dstDir)
	if registryRef == "" || dstDir == "" {
		return fmt.Errorf("wasm checkpoint pull: registry ref and destination dir required")
	}
	return wasmmod.PullSnapshotArtifact(ctx, p.orasPullConfig(), registryRef, dstDir)
}

func (p *WasmCheckpointPusher) orasPullConfig() wasmmod.ORASPullConfig {
	return wasmmod.ORASPullConfig{
		Host:      p.cfg.Host,
		ClusterID: p.cfg.ClusterID,
		PATPath:   p.cfg.PATPath,
	}
}

// DeleteRef removes a tagged WASM checkpoint manifest from AOCR.
func (p *WasmCheckpointPusher) DeleteRef(ctx context.Context, registryRef string) error {
	if p == nil {
		return errors.New("wasm checkpoint push disabled (pusher is nil)")
	}
	return wasmmod.DeleteSnapshotRef(ctx, p.orasPushConfig(), registryRef)
}

func (p *WasmCheckpointPusher) orasPushConfig() wasmmod.ORASPushConfig {
	return wasmmod.ORASPushConfig{
		Host:      p.cfg.Host,
		ClusterID: p.cfg.ClusterID,
		PATPath:   p.cfg.PATPath,
	}
}
