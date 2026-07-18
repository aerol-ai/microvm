package isolate

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Create is the cold path (plans/isolate-runtime.md §10): resolve the
// sandbox's bundle, route it to its isolate group (spawning the group's workerd
// process under single-flight on the first create — or claiming a warm blank
// host when the pool is enabled), and load the bundle onto that host. The
// sandbox is "running" the moment its bundle is pinned — the isolate itself is
// compiled lazily on first invoke (the §2.2 warm path). No per-IP networking,
// no container: this is host-mediated like WASM.
//
// Failure rule (LIFO): if load fails after the group was acquired, the sandbox
// is released from the group, which tears the group's process down when this
// create had spawned it and no other member joined — so a failed first-create
// never leaks an empty workerd process (§11 empty-group rule).
func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	_ = toolboxToken
	_ = hostMounts
	if d.resolver == nil {
		return nil, fmt.Errorf("isolate: bundle resolver not registered: %w", models.ErrRuntimeNotImplemented)
	}
	ref := models.ModuleRefForCreate(req)
	if ref == "" {
		return nil, fmt.Errorf("isolate: module_ref (bundle reference) is required")
	}

	bundle, err := d.resolver.Resolve(ctx, req.TenantID, ref)
	if err != nil {
		return nil, fmt.Errorf("isolate: resolve bundle %q: %w", ref, err)
	}

	groupKey, err := d.groupKeyForCreate(req.TenantID, sandboxID)
	if err != nil {
		return nil, err
	}

	host, err := d.acquireGroup(ctx, groupKey, req.CPU, req.MemoryMB)
	if err != nil {
		return nil, err
	}

	if err := host.Load(sandboxID, bundle); err != nil {
		d.releaseFromGroup(groupKey, sandboxID)
		return nil, fmt.Errorf("isolate: load bundle onto group %q: %w", groupKey, err)
	}

	egress := policyFromCreate(req.NetworkBlockAll, req.NetworkAllowOut, req.NetworkDenyOut)
	if setter, ok := host.(EgressPolicySetter); ok {
		setter.SetEgressPolicy(sandboxID, egress)
	}
	// Mirror WASM: host-mediated sandboxes advertise loopback so
	// syncAllowedPorts / expose_port probe gating still run.
	state := &models.SandboxRuntimeState{
		SandboxID:    sandboxID,
		Status:       models.SandboxStatusStarted,
		ModuleRef:    ref,
		ModuleDigest: bundle.Digest,
		ModulePath:   bundle.Digest,
		ContainerIP:  "127.0.0.1",
	}
	d.mu.Lock()
	d.byID[sandboxID] = &sandboxRecord{
		state:     state,
		groupKey:  groupKey,
		tenantID:  req.TenantID,
		bundleRef: "sha256:" + bundle.Digest,
		egress:    egress,
	}
	d.mu.Unlock()
	d.touchGroup(groupKey)
	return state, nil
}
