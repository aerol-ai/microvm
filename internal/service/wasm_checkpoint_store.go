package service

import "context"

// WasmCheckpointStore abstracts AOCR push/pull for durable WASM checkpoints.
// Production uses *WasmCheckpointPusher; tests inject fakes.
type WasmCheckpointStore interface {
	DestRefFor(sandboxID string) string
	DestRefTagged(sandboxID, tag string) string
	PushOnceTo(ctx context.Context, sandboxID, memSnapDir, dest string) (WasmCheckpointPushResult, error)
	PullOnce(ctx context.Context, registryRef, dstDir string) error
	DeleteRef(ctx context.Context, registryRef string) error
}
