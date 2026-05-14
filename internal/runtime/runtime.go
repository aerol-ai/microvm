// Package runtime defines the abstraction the service layer uses to drive a
// sandbox container, regardless of which OCI runtime executes it. The first
// implementation is pkg/docker.Client, which talks to the local Docker daemon
// and can drive either runc or runsc (gVisor) depending on per-sandbox /
// host-default selection. Future implementations (e.g. native runsc without
// Docker) plug in behind the same interface.
//
// Methods that are intrinsically Docker-API-shaped — exec hijacking, the
// /events stream — intentionally stay off this interface and on the concrete
// *docker.Client. Pulling them through the abstraction would only buy
// clutter; gVisor under Docker uses the same exec/event paths anyway.
package runtime

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Runtime is the contract the service layer requires of any container runtime
// driver. Implementations must be safe for concurrent use; the service serializes
// per-sandbox operations but issues calls for different sandboxes in parallel.
type Runtime interface {
	// Create provisions and starts a managed container. The caller owns the
	// sandbox ID. The runtime sets it as the container's canonical name so
	// the sandbox ID is the end-to-end identifier (the container ID is an
	// internal detail). The chosen OCI runtime is read from
	// req.Runtime; the implementation is expected to substitute its own
	// default when req.Runtime is empty.
	Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error)

	// Start boots a previously created container and waits for the in-container
	// toolbox to become reachable.
	Start(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error)

	// Stop sends a graceful stop with a default timeout.
	Stop(ctx context.Context, containerRef string) error

	// Destroy removes the container and clears any per-IP network rules.
	// Passing nil is a no-op — convenient for cleanup paths that may not yet
	// have a sandbox record.
	Destroy(ctx context.Context, sandbox *models.Sandbox) error

	// CreateSnapshot commits a managed container into a reusable local image
	// reference and returns the resulting image ID.
	CreateSnapshot(ctx context.Context, containerRef, imageRef string) (string, error)

	// Resize updates CPU/memory caps on a running container. DiskGB is not
	// resizable on a live container; resize-up at create time is honored
	// per-runtime.
	Resize(ctx context.Context, containerRef string, req models.ResizeSandboxRequest) error

	// Inspect returns the current runtime state for a single container.
	Inspect(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error)

	// ListManaged returns the runtime state of every container managed by
	// this sandboxd, keyed by sandbox ID. Used by reconcile.
	ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error)

	// Ping verifies the underlying runtime daemon is reachable.
	Ping(ctx context.Context) error

	// RemoveImage GCs an image from the runtime's local store. 404/409 are
	// treated as success — see implementation notes.
	RemoveImage(ctx context.Context, imageRef string) error

	// PushAllowedPorts updates the in-container toolbox's allowlist of ports
	// reachable through its proxy. Best-effort; callers log on failure.
	PushAllowedPorts(ctx context.Context, containerIP, toolboxToken string, ports []int) error

	// ClearNetworkRules releases any per-IP network rules previously attached
	// to a sandbox. Used by the event-driven path when a container exits or
	// is destroyed out-of-band; Destroy() handles this during normal teardown.
	ClearNetworkRules(containerIP string) error

	// ApplyNetworkBlockAll installs the per-IP egress DROP rule for sandboxes
	// created with NetworkBlockAll=true. Idempotent — safe to call on every
	// Start and reconcile pass. Used to reapply the rule after Stop+Start
	// cycles (which clear it on the stop event) and after host-side state
	// loss (iptables flush, daemon restart that rebuilds chains).
	ApplyNetworkBlockAll(containerIP string) error

	// ApplyNetworkBlockIngress installs the per-IP ingress DROP rule. Used
	// by the network-quota enforcer when net_bytes_in_limit is crossed.
	// Idempotent at the netrules layer. Distinct from the egress block so
	// quota enforcement composes with NetworkBlockAll independently on each
	// direction.
	ApplyNetworkBlockIngress(containerIP string) error

	// ClearNetworkBlockIngress removes the per-IP ingress DROP rule. The
	// caller is responsible for not racing this against quota state — the
	// service layer only clears when limits are raised above current usage.
	ClearNetworkBlockIngress(containerIP string) error

	// ClearNetworkBlockEgress removes the per-IP egress DROP rule. Symmetric
	// to ApplyNetworkBlockAll for callers that need to walk back a quota-
	// driven block without also undoing NetworkBlockAll. Today the underlying
	// rule is shared, so the service must consult NetworkBlockAll before
	// invoking this on a quota-clear path.
	ClearNetworkBlockEgress(containerIP string) error
}
