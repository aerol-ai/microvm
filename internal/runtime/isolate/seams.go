package isolate

import (
	"context"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// This file declares the seams the engine work plugs into, mirroring
// internal/runtime/wasm/seams.go: the driver depends on small interfaces so
// tests inject fakes and production wires pkg/jsbundle / pkg/isolate without
// the driver importing their concrete types at call sites. The HostSupervisor
// / GroupHost surface was finalized by the §2.2 bundle-injection spike (GREEN
// 2026-07-17): the winning path is one workerd process per group running a
// controller worker that dynamically loads sandbox isolates by id, so a group
// host exposes Load/Unload/Invoke over that process.

// BundleResolver resolves a bundle reference (path, file://, uploaded name,
// digest) for a tenant to the concrete bundle code the group host injects.
// Production implementation: pkg/jsbundle (adapted in bundleresolver.go), the
// analog of pkg/wasmmod for .wasm modules. tenant scopes uploaded-name lookups.
type BundleResolver interface {
	Resolve(ctx context.Context, tenant, ref string) (*jsbundle.Bundle, error)
}

// GroupHost is a running workerd group process the driver loads sandboxes into
// and routes requests to. One host backs one isolate-group key (§2.1).
// Production implementation: *pkg/isolate.Host.
type GroupHost interface {
	// Load pins a sandbox's bundle so the host can serve it; idempotent.
	Load(id string, b *jsbundle.Bundle) error
	// Unload drops a sandbox and returns the number still loaded (for
	// last-member teardown).
	Unload(id string) int
	// LoadedCount is the number of sandboxes currently on this host.
	LoadedCount() int
	// Invoke proxies an HTTP request to the sandbox identified by id.
	Invoke(ctx context.Context, id string, r *http.Request) (*http.Response, error)
	// Stop kills the group process and releases its resources.
	Stop() error
}

// HostSupervisor spawns group hosts, one per isolate-group key (§2.1).
// SpawnGroup realizes the group's JailSpec (chroot + cgroups + drop-priv +
// seccomp) and starts the workerd process. Production implementation:
// pkg/isolate via hostsupervisor.go.
type HostSupervisor interface {
	SpawnGroup(ctx context.Context, spec JailSpec) (GroupHost, error)
}

// WarmPool hands out blank workerd group hosts. Production implementation:
// internal/pool/isolate (Phase 3). ok=false means empty or disabled — the
// caller cold-spawns. The group router runs before the pool: only a tenant's
// FIRST create claims; subsequent creates join the existing group.
type WarmPool interface {
	Acquire(ctx context.Context) (GroupHost, bool)
}
