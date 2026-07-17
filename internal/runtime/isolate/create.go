package isolate

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Create is the Phase-2 cold path (plans/isolate-runtime.md §10): resolve the
// sandbox's bundle, route it to its isolate group (spawning the group's workerd
// process under single-flight on the first create), and load the bundle onto
// that host. The sandbox is "running" the moment its bundle is pinned — the
// isolate itself is compiled lazily on first invoke (the §2.2 warm path). No
// per-IP networking, no container: this is host-mediated like WASM.
//
// Failure rule (LIFO): if load fails after the group was acquired, the sandbox
// is released from the group, which tears the group's process down when this
// create had spawned it and no other member joined — so a failed first-create
// never leaks an empty workerd process (§11 empty-group rule).
func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
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
		// Undo: drop this sandbox and reap the group if we just spawned it and
		// it is now empty.
		d.releaseFromGroup(groupKey, sandboxID)
		return nil, fmt.Errorf("isolate: load bundle onto group %q: %w", groupKey, err)
	}

	state := &models.SandboxRuntimeState{
		SandboxID:    sandboxID,
		Status:       models.SandboxStatusStarted,
		ModuleRef:    ref,
		ModuleDigest: bundle.Digest,
		ModulePath:   bundle.Digest, // content-addressed; the digest IS the locator
	}
	d.mu.Lock()
	d.byID[sandboxID] = &sandboxRecord{state: state, groupKey: groupKey}
	d.mu.Unlock()
	return state, nil
}
