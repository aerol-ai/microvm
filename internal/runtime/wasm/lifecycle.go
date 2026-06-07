package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

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
	if err := client.LoadModule(sandboxID, inst.modulePath); err != nil {
		return nil, fmt.Errorf("load module: %w", err)
	}
	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Preopens:       []wasmengine.Preopen{{GuestPath: "/", HostPath: inst.workDir}},
		Args:           []string{"wasm"},
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}, inst.memoryMB, d.cfg.DefaultWallTimeout)
	if err := client.Instantiate(sandboxID, caps); err != nil {
		return nil, fmt.Errorf("instantiate module: %w", err)
	}
	if err := client.Invoke(sandboxID, inst.entryExport); err != nil {
		return nil, fmt.Errorf("invoke %q: %w", inst.entryExport, err)
	}

	inst.status = models.SandboxStatusStarted
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()
	return d.runtimeState(inst), nil
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
