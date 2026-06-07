// Package wasmmod — AOCR push for §4.8.1 WASM snapshot artifacts (D2).
package wasmmod

import (
	"context"
	"errors"
	"fmt"
)

// ErrORASPushNotWired is returned until AOCR push is implemented.
var ErrORASPushNotWired = errors.New("wasm snapshot oras push not wired")

// PushSnapshotArtifact uploads a local mem.snap directory to an OCI registry.
// Phase 6 lands the seam; ORAS wiring ships when AOCR endpoints are configured.
func PushSnapshotArtifact(ctx context.Context, memSnapDir, registryRef string) (digest string, err error) {
	_ = ctx
	if memSnapDir == "" || registryRef == "" {
		return "", fmt.Errorf("oras push: mem.snap dir and registry ref required")
	}
	return "", fmt.Errorf("oras push not wired yet (see plans/wasm-runtime.md Phase 6): %w", ErrORASPushNotWired)
}
