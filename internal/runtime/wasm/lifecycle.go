package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// digestResolver is the optional capability a ModuleResolver exposes to boot a
// sandbox from its content-addressed frozen copy. Type-asserted so test fakes
// that only implement Resolve keep working.
type digestResolver interface {
	ResolveByDigest(digest string) (*wasmmod.ResolvedModule, bool)
}

// authResolver is the optional capability to resolve under caller-supplied
// per-tenant registry credentials. Type-asserted so simple fakes still work.
type authResolver interface {
	ResolveWithAuth(ctx context.Context, ref string, authOverride *wasmmod.ModuleAuth) (*wasmmod.ResolvedModule, error)
}

// resolveWithRequestAuth resolves ref, passing the request's registry
// credentials (per-tenant) through to an oci:// pull when present. When the
// request carries no creds, or the resolver predates the auth seam, it falls
// back to the plain Resolve (system identity).
func resolveWithRequestAuth(ctx context.Context, r ModuleResolver, ref string, reg *models.RegistryAuth) (*wasmmod.ResolvedModule, error) {
	if reg != nil && (strings.TrimSpace(reg.Username) != "" || strings.TrimSpace(reg.Password) != "") {
		if ar, ok := r.(authResolver); ok {
			return ar.ResolveWithAuth(ctx, ref, &wasmmod.ModuleAuth{
				Username: reg.Username,
				PAT:      reg.Password,
			})
		}
	}
	return r.Resolve(ctx, ref)
}

// moduleAuthFromSandbox builds the per-tenant registry credential from a
// sandbox's transient (unsealed) RegistryAuth, used so a failover peer pulls a
// private oci:// module under the tenant's identity (codex C4). Nil when the
// sandbox carries no creds (public/standard module).
func moduleAuthFromSandbox(sandbox *models.Sandbox) *wasmmod.ModuleAuth {
	if sandbox == nil || sandbox.RegistryAuth == nil {
		return nil
	}
	ra := sandbox.RegistryAuth
	if strings.TrimSpace(ra.Username) == "" && strings.TrimSpace(ra.Password) == "" {
		return nil
	}
	return &wasmmod.ModuleAuth{Username: ra.Username, PAT: ra.Password}
}

// resolvePinned resolves a sandbox's module preferring the digest pinned at
// create over the (mutable) ref. On a frozen-copy cache hit it boots the exact
// original bytes; on a miss it re-resolves the ref (under authOverride creds
// when set) but REFUSES to boot if the bytes drifted from the pin — turning
// codex C2's silent code-swap into a loud, recoverable error.
func (d *Driver) resolvePinned(ctx context.Context, ref, pinnedDigest string, authOverride *wasmmod.ModuleAuth) (*wasmmod.ResolvedModule, error) {
	pinnedDigest = strings.TrimSpace(pinnedDigest)
	if pinnedDigest != "" {
		if dr, ok := d.resolver.(digestResolver); ok {
			if resolved, hit := dr.ResolveByDigest(pinnedDigest); hit {
				return resolved, nil
			}
		}
	}
	resolved, err := d.resolveRef(ctx, ref, authOverride)
	if err != nil {
		return nil, fmt.Errorf("resolve module %q: %w", ref, err)
	}
	if pinnedDigest != "" && resolved.Digest != "" && resolved.Digest != pinnedDigest {
		return nil, fmt.Errorf("module %q pinned %s but now resolves to %s: %w",
			ref, pinnedDigest, resolved.Digest, wasmmod.ErrModuleDigestMismatch)
	}
	return resolved, nil
}

// resolveRef resolves under authOverride creds when set and the resolver
// supports the auth seam, else plain Resolve.
func (d *Driver) resolveRef(ctx context.Context, ref string, authOverride *wasmmod.ModuleAuth) (*wasmmod.ResolvedModule, error) {
	if authOverride != nil {
		if ar, ok := d.resolver.(authResolver); ok {
			return ar.ResolveWithAuth(ctx, ref, authOverride)
		}
	}
	return d.resolver.Resolve(ctx, ref)
}

func (d *Driver) Start(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return nil, err
	}
	if inst.status == models.SandboxStatusStarted {
		return d.runtimeState(inst), nil
	}

	workerKey := inst.workerKey
	if workerKey == "" {
		workerKey = sandboxID
	}
	if err := d.supervisor.Ensure(ctx, workerKey, inst.socketPath); err != nil {
		return nil, fmt.Errorf("start worker: %w", err)
	}
	client := d.newWorkerClient(inst.socketPath)
	if err := d.waitWorker(ctx, client, sandboxID); err != nil {
		return nil, err
	}
	d.noteWorkerSpawnCount(inst)
	if err := client.LoadModule(sandboxID, inst.modulePath); err != nil {
		return nil, fmt.Errorf("load module: %w", err)
	}
	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:            copyStringMap(inst.baseEnv),
		Preopens:       append([]wasmengine.Preopen(nil), inst.preopens...),
		Args:           append([]string(nil), inst.baseArgs...),
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}, inst.memoryMB, d.cfg.DefaultWallTimeout)
	if err := client.Instantiate(sandboxID, caps); err != nil {
		return nil, fmt.Errorf("instantiate module: %w", err)
	}
	inst.status = models.SandboxStatusStarted
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()
	return d.runtimeState(inst), nil
}

// StartSandbox reconstructs a stopped sandbox from its persisted row and mounts.
func (d *Driver) StartSandbox(ctx context.Context, sandbox *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if sandbox == nil {
		return nil, fmt.Errorf("start sandbox: nil sandbox")
	}
	if inst, err := d.instance(sandbox.ID); err == nil {
		return d.Start(ctx, inst.sandboxID)
	}

	ref := strings.TrimSpace(sandbox.ModuleRef)
	if ref == "" {
		ref = strings.TrimSpace(sandbox.Image)
	}
	if ref == "" {
		return nil, fmt.Errorf("start sandbox %s: module_ref is required", sandbox.ID)
	}
	if d.resolver == nil {
		return nil, fmt.Errorf("wasm runtime: module resolver not configured: %w", models.ErrRuntimeNotImplemented)
	}
	// Boot the digest pinned at create, not whatever the alias/tag points at
	// now (codex C2). On drift with no frozen copy this fails loudly.
	resolved, err := d.resolvePinned(ctx, ref, sandbox.ModuleDigest, moduleAuthFromSandbox(sandbox))
	if err != nil {
		return nil, err
	}

	workDir := d.sandboxDir(sandbox.ID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir sandbox dir: %w", err)
	}
	inst := &sandboxInstance{
		sandboxID:    sandbox.ID,
		moduleRef:    ref,
		modulePath:   resolved.Path,
		moduleDigest: resolved.Digest,
		socketPath:   filepath.Join(workDir, "worker.sock"),
		workDir:      workDir,
		workerKey:    sandbox.ID,
		status:       models.SandboxStatusStopped,
		entryExport:  "_start",
		baseEnv:      copyStringMap(sandbox.Env),
		baseArgs:     wasmArgsFromSandbox(sandbox),
		preopens:     preopensFromBinds(workDir, hostMounts),
		cpu:          sandbox.CPU,
		memoryMB:     sandbox.MemoryMB,
		diskGB:       sandbox.DiskGB,
		durability:   sandbox.Durability,
	}
	if inst.memoryMB <= 0 {
		inst.memoryMB = d.cfg.DefaultMemoryMB
	}
	d.mu.Lock()
	d.byID[sandbox.ID] = inst
	d.mu.Unlock()

	return d.Start(ctx, sandbox.ID)
}

func (d *Driver) Stop(ctx context.Context, sandboxID string) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	client := d.newWorkerClient(inst.socketPath)
	if err := client.StopInstance(sandboxID); err != nil {
		return fmt.Errorf("stop instance: %w", err)
	}
	inst.status = models.SandboxStatusStopped
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()
	return nil
}

func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	sandboxID := sandbox.ID

	d.mu.Lock()
	inst := d.byID[sandboxID]
	delete(d.byID, sandboxID)
	d.mu.Unlock()

	if d.net != nil {
		d.net.ReleaseSandbox(sandboxID)
	}
	if d.supervisor != nil {
		workerKey := sandboxID
		if inst != nil && inst.workerKey != "" {
			workerKey = inst.workerKey
		}
		_ = d.supervisor.Stop(workerKey)
	}
	if inst != nil && inst.fromWarmPool && inst.socketPath != "" {
		_ = os.RemoveAll(filepath.Dir(inst.socketPath))
	}
	workDir := d.sandboxDir(sandboxID)
	if inst != nil && inst.workDir != "" {
		workDir = inst.workDir
	}
	_ = os.RemoveAll(workDir)
	_ = os.RemoveAll(d.checkpointDir(sandboxID))
	return nil
}

func (d *Driver) Resize(ctx context.Context, sandboxID string, req models.ResizeSandboxRequest) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	if req.DiskGB > 0 && req.DiskGB != inst.diskGB {
		return fmt.Errorf("wasm runtime: disk resize not supported on a live instance")
	}
	if req.CPU > 0 {
		inst.cpu = req.CPU
	}
	if req.MemoryMB > 0 {
		inst.memoryMB = req.MemoryMB
	}
	if inst.status == models.SandboxStatusStarted && req.MemoryMB > 0 {
		client := d.newWorkerClient(inst.socketPath)
		caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{}, inst.memoryMB, d.cfg.DefaultWallTimeout)
		if err := client.SetCapability(sandboxID, caps); err != nil {
			return fmt.Errorf("resize worker caps: %w", err)
		}
	}
	_ = ctx
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()
	return nil
}

func (d *Driver) instance(sandboxID string) (*sandboxInstance, error) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		return nil, fmt.Errorf("wasm sandbox %q not found", sandboxID)
	}
	return inst, nil
}

func ctxDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(5 * time.Second)
}

func ctxDone(ctx context.Context, deadline time.Time) bool {
	if err := ctx.Err(); err != nil {
		return true
	}
	return time.Now().After(deadline)
}

func sleepBrief(ctx context.Context) {
	t := time.NewTimer(25 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
