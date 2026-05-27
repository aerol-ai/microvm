package vmm

// spawner.go declares the seam PR 4-B's refill goroutine uses to turn
// a 'spawning' row into a 'loaded' one. The contract is intentionally
// narrow: given a slot id, a template id, and the snapshot artifacts
// the snapshot-load path needs, the spawner must produce a paused
// firecracker process whose API socket the pool can hand to the
// runtime driver on Acquire.
//
// PR 4-A ships the interface only. PR 4-B's runtime adapter will
// satisfy it from inside the firecracker package by wrapping
// *firecracker.Driver — that's the package that already owns the VMM
// supervisor + REST client, and PR 4-A's import-cycle wall (vmm →
// store, runtime → vmm) means the adapter must live on the runtime
// side, not here.
//
// Tests in this package inject a fake Spawner that records call
// sequences and returns a stub Handle — proves the state machine
// works without spawning real firecracker processes.

import (
	"context"
	"time"
)

// SnapshotInputs is the per-template artifact reference the spawner
// needs to issue LoadSnapshot against. Mirrors the fields
// configureVMMForLoad in internal/runtime/firecracker/driver.go reads
// from a TemplateResolution; declared locally so this package keeps
// its zero-imports-from-runtime contract.
//
// VsockCID is the GUEST CID baked into the snapshot state at template
// build time. The pool's Slot row will pick it up via RecordLoaded so
// the runtime driver dials the right CID when it claims the slot for
// a sandbox.
type SnapshotInputs struct {
	TemplateID         string
	SnapshotMemoryPath string
	SnapshotStatePath  string
	SnapshotChecksum   string
	VsockCID           uint32
}

// SpawnedHandle is the subset of a *firecracker.vmm the pool consumes
// after a successful Spawn. Interface form lets the refill goroutine
// hold the handle without dragging the firecracker package into this
// one. PR 4-B's runtime adapter satisfies it with the same VMMHandle
// shape internal/runtime/firecracker/seams.go already declares.
//
// Shutdown is the only mutation the pool ever issues directly: when
// a slot moves from 'loaded' to 'released' (because the GC ages it
// out, or because the spawner attempted a refill that the daemon is
// now backing out of), the pool calls Shutdown to bring the VMM
// process down before deleting the row. Acquire's caller (PR 4-B's
// Driver.Create change) is responsible for the post-Resume
// lifecycle — the pool never resumes a slot itself.
type SpawnedHandle interface {
	APISocket() string
	RunDir() string
	Shutdown(ctx context.Context, grace time.Duration) error
	// Pid returns the host PID of the spawned firecracker process, or
	// 0 if the supervisor doesn't track one (test fakes, or a handle
	// whose process has exited). Phase 5 (PR 5-C) consumes this on the
	// Acquire side so the runtime can re-key the RSS sampler from
	// slotID to sandboxID without crossing the import-cycle wall to
	// inspect the underlying *firecracker.vmm directly.
	Pid() int
}

// Spawner is the seam the pool depends on for producing
// loaded-but-paused firecracker processes. PR 4-A ships the interface
// only; the concrete impl lands in PR 4-B's runtime adapter.
//
// Spawn semantics:
//
//   - On success: the returned handle's firecracker process MUST be
//     in the 'Paused' state, with the snapshot at inputs.SnapshotMemoryPath
//     / inputs.SnapshotStatePath loaded and EnableDiffSnapshots=true.
//     The pool will subsequently call RecordLoaded with the handle's
//     APISocket / RunDir / inputs.VsockCID.
//
//   - On error: the spawner MUST leave no leaked process. The pool's
//     caller then issues RecordFailed and the row goes to 'released'
//     for the GC sweep to clean up the (now-empty) on-disk runDir.
//
//   - ctx cancellation is the timeout mechanism. The refill goroutine
//     enforces a per-spawn deadline; the spawner must honor it and
//     return ctx.Err() rather than spinning.
type Spawner interface {
	Spawn(ctx context.Context, slotID string, inputs SnapshotInputs) (SpawnedHandle, error)
}
