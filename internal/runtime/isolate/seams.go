package isolate

import "context"

// This file declares the seams the Phase-2+ engine work plugs into, mirroring
// internal/runtime/wasm/seams.go: the driver depends on small interfaces so
// tests inject fakes and production wires pkg/jsbundle / pkg/isolate without
// the driver importing either. Method sets here are deliberately minimal —
// the HostSupervisor surface in particular is finalized by the §2.2 bundle-
// injection spike (inject into a running workerd vs per-sandbox process vs
// config regeneration), so nothing beyond the spike-invariant calls is
// promised yet.

// ResolvedBundle is a JS/TS bundle resolved to a local, validated artifact.
// Digest is the sha256 of the bundle bytes — content-addressing is what makes
// create retries idempotent (a retry resolves to the same digest and joins
// the existing sandbox).
type ResolvedBundle struct {
	Ref       string
	Digest    string
	Path      string
	SizeBytes int64
}

// BundleResolver resolves a bundle reference (path, file://, uploaded name,
// digest) to a local artifact. Production implementation: pkg/jsbundle
// (Phase 2), the analog of pkg/wasmmod for .wasm modules.
type BundleResolver interface {
	Resolve(ctx context.Context, ref string) (ResolvedBundle, error)
}

// WarmHost is a pre-spawned blank workerd process a tenant's FIRST create
// claims (the group router runs before the pool: subsequent creates join the
// tenant's existing group and never touch the pool).
type WarmHost struct {
	SocketPath string
	PID        int
}

// WarmPool hands out blank workerd hosts. Production implementation:
// internal/pool/isolate (Phase 3). ok=false means empty or disabled — the
// caller cold-spawns.
type WarmPool interface {
	Acquire(ctx context.Context) (WarmHost, bool)
}

// HostSupervisor owns workerd group processes: one per isolate-group key
// (§2.1). Spawning realizes the group's JailSpec (chroot + cgroups +
// drop-priv + seccomp); stopping is the last-member teardown and the hostile-
// teardown path.
type HostSupervisor interface {
	SpawnGroup(ctx context.Context, spec JailSpec) (socketPath string, pid int, err error)
	StopGroup(ctx context.Context, groupKey string) error
}
