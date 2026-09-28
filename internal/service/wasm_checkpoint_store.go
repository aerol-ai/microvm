package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// WasmCheckpointStore abstracts AOCR push/pull for durable WASM checkpoints.
// Production uses *WasmCheckpointPusher; tests inject fakes.
//
// Every operation is bound to a sandbox LIFETIME (its incarnation), not just
// its id. A sandbox id outlives its lifetimes, and pushes run detached for
// minutes, so an id-keyed artifact let a dead lifetime's late push replace
// what the live one — or a failover owner restoring it — would read.
type WasmCheckpointStore interface {
	DestRefTagged(sandboxID, tag string) string
	PushOnceTo(ctx context.Context, sandboxID, incarnationID, memSnapDir, dest string) (WasmCheckpointPushResult, error)
	// PullOnce restores registryRef into dstDir, refusing a checkpoint that a
	// different lifetime than incarnationID published.
	PullOnce(ctx context.Context, registryRef, incarnationID, dstDir string) error
	DeleteRef(ctx context.Context, registryRef string) error
}

// wasmCheckpointLatestRef is one lifetime's rolling pointer to its most recent
// checkpoint. Only that lifetime's pushes write it, so it is the authoritative
// thing for a failover owner to read when all it knows is the lifetime.
func (s *Service) wasmCheckpointLatestRef(sandboxID, incarnationID string) string {
	if s.wasmCheckpointPusher == nil || strings.TrimSpace(incarnationID) == "" {
		return ""
	}
	return s.wasmCheckpointPusher.DestRefTagged(sandboxID, wasmmod.WasmCheckpointLatestTag(incarnationID))
}

// wasmCheckpointDigestRef is one lifetime's immutable ref to one checkpoint.
func (s *Service) wasmCheckpointDigestRef(sandboxID, incarnationID, digest string) string {
	if s.wasmCheckpointPusher == nil || strings.TrimSpace(incarnationID) == "" {
		return ""
	}
	return s.wasmCheckpointPusher.DestRefTagged(sandboxID, wasmmod.WasmCheckpointLifetimeDigestTag(incarnationID, digest))
}
