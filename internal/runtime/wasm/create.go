package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if d.resolver == nil {
		return nil, fmt.Errorf("wasm runtime: module resolver not configured: %w", models.ErrRuntimeNotImplemented)
	}
	if d.supervisor == nil {
		return nil, fmt.Errorf("wasm runtime: worker supervisor not configured: %w", models.ErrRuntimeNotImplemented)
	}
	if d.cfg.RunDir == "" {
		return nil, fmt.Errorf("wasm runtime: run dir not configured")
	}

	ref := moduleRefFromRequest(req)
	if ref == "" {
		return nil, fmt.Errorf("wasm runtime: module_ref or image is required")
	}

	resolved, err := d.resolver.Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve module %q: %w", ref, err)
	}

	warmSlot, err := d.tryAcquireWarm(ctx, resolved.Digest, resolved.Path)
	if err != nil {
		return nil, fmt.Errorf("warm pool acquire: %w", err)
	}

	workDir := d.sandboxDir(sandboxID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir sandbox dir: %w", err)
	}

	socketPath := filepath.Join(workDir, "worker.sock")
	workerKey := sandboxID
	if warmSlot != nil {
		socketPath = warmSlot.SocketPath
		workerKey = warmSlot.WorkerKey
	}

	memoryMB := req.MemoryMB
	if memoryMB <= 0 {
		memoryMB = d.cfg.DefaultMemoryMB
	}

	inst := &sandboxInstance{
		sandboxID:    sandboxID,
		moduleRef:    ref,
		modulePath:   resolved.Path,
		moduleDigest: resolved.Digest,
		socketPath:   socketPath,
		workDir:      workDir,
		workerKey:    workerKey,
		fromWarmPool: warmSlot != nil,
		status:       models.SandboxStatusCreating,
		entryExport:  entryExportFromRequest(req),
		baseEnv:      copyStringMap(req.Env),
		baseArgs:     wasmArgs(req),
		cpu:          req.CPU,
		memoryMB:     memoryMB,
		diskGB:       req.DiskGB,
	}

	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()

	cleanup := func() {
		_ = d.supervisor.Stop(workerKey)
		if warmSlot != nil {
			_ = os.RemoveAll(filepath.Dir(warmSlot.SocketPath))
		}
		_ = os.RemoveAll(workDir)
		d.mu.Lock()
		delete(d.byID, sandboxID)
		d.mu.Unlock()
	}

	client := d.newWorkerClient(socketPath)
	if warmSlot == nil {
		if err := d.supervisor.Ensure(ctx, sandboxID, socketPath); err != nil {
			cleanup()
			return nil, fmt.Errorf("start worker: %w", err)
		}
	}
	if err := d.waitWorker(ctx, client, sandboxID); err != nil {
		cleanup()
		return nil, err
	}
	if warmSlot == nil {
		if err := client.LoadModule(sandboxID, resolved.Path); err != nil {
			cleanup()
			return nil, fmt.Errorf("load module: %w", err)
		}
	}

	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:  req.Env,
		Args: wasmArgs(req),
		Preopens: []wasmengine.Preopen{{
			GuestPath: "/",
			HostPath:  workDir,
		}},
	}, memoryMB, d.cfg.DefaultWallTimeout)

	if err := client.Instantiate(sandboxID, caps); err != nil {
		cleanup()
		return nil, fmt.Errorf("instantiate module: %w", err)
	}
	if err := client.Invoke(sandboxID, inst.entryExport); err != nil {
		cleanup()
		return nil, fmt.Errorf("invoke %q: %w", inst.entryExport, err)
	}

	inst.status = models.SandboxStatusStarted
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()

	return d.runtimeState(inst), nil
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func wasmArgs(req models.CreateSandboxRequest) []string {
	if len(req.ContainerCommand) > 1 {
		return append([]string{req.ContainerCommand[0]}, req.ContainerCommand[1:]...)
	}
	if len(req.ContainerCommand) == 1 {
		return []string{req.ContainerCommand[0]}
	}
	return []string{"wasm"}
}

func (d *Driver) runtimeState(inst *sandboxInstance) *models.SandboxRuntimeState {
	if inst == nil {
		return nil
	}
	return &models.SandboxRuntimeState{
		SandboxID:    inst.sandboxID,
		ContainerID:  "wasm:" + inst.sandboxID,
		ContainerIP:  wasmLoopbackIP,
		Status:       inst.status,
		ModuleRef:    inst.moduleRef,
		ModuleDigest: inst.moduleDigest,
	}
}

func (d *Driver) waitWorker(ctx context.Context, client WorkerClient, sandboxID string) error {
	deadline := ctxDeadline(ctx)
	for {
		if err := client.Ping(sandboxID); err == nil {
			return nil
		}
		if ctxDone(ctx, deadline) {
			return fmt.Errorf("worker not ready: %w", ctx.Err())
		}
		sleepBrief(ctx)
	}
}
