package wasm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// RehydrateSandbox reloads a passivated sandbox from mem.snap (§4.3).
func (d *Driver) RehydrateSandbox(ctx context.Context, sandbox *models.Sandbox) (*models.SandboxRuntimeState, error) {
	if sandbox == nil {
		return nil, fmt.Errorf("rehydrate: nil sandbox")
	}
	mu := d.rehydrateGate(sandbox.ID)
	mu.Lock()
	defer mu.Unlock()

	d.mu.Lock()
	if inst := d.byID[sandbox.ID]; inst != nil && inst.status == models.SandboxStatusStarted {
		state := d.runtimeState(inst)
		d.mu.Unlock()
		return state, nil
	}
	d.mu.Unlock()

	checkpointPath := strings.TrimSpace(sandbox.CheckpointPath)
	if checkpointPath == "" {
		checkpointPath = d.checkpointDir(sandbox.ID)
	}
	if !wasmengine.DirExists(checkpointPath) {
		return nil, fmt.Errorf("rehydrate %s: %w", sandbox.ID, wasmengine.ErrEmptySnapshotDir)
	}
	snap, err := wasmengine.ReadSnapshotDir(checkpointPath, wasmengine.EngineNameWazero())
	if err != nil {
		return nil, err
	}
	if err := wasmengine.FenceCloneGeneration(sandbox.CloneGeneration, snap.Config.CloneGeneration); err != nil {
		return nil, err
	}

	modulePath := ""
	moduleDigest := sandbox.ModuleDigest
	moduleRef := sandbox.ModuleRef
	if d.resolver != nil && moduleRef != "" {
		resolved, resolveErr := d.resolver.Resolve(ctx, moduleRef)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve module %q: %w", moduleRef, resolveErr)
		}
		modulePath = resolved.Path
		if moduleDigest == "" {
			moduleDigest = resolved.Digest
		}
	}
	if modulePath == "" {
		return nil, fmt.Errorf("rehydrate %s: module path unknown", sandbox.ID)
	}

	workDir := d.sandboxDir(sandbox.ID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(workDir, "worker.sock")
	workerKey := sandbox.ID

	if err := d.supervisor.Ensure(ctx, workerKey, socketPath); err != nil {
		return nil, fmt.Errorf("start worker: %w", err)
	}
	client := d.newWorkerClient(socketPath)
	if err := d.waitWorker(ctx, client, sandbox.ID); err != nil {
		return nil, err
	}
	if err := client.LoadModule(sandbox.ID, modulePath); err != nil {
		return nil, fmt.Errorf("load module: %w", err)
	}

	memoryMB := sandbox.MemoryMB
	if memoryMB <= 0 {
		memoryMB = d.cfg.DefaultMemoryMB
	}
	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:  sandbox.Env,
		Args: wasmArgsFromSandbox(sandbox),
		Preopens: []wasmengine.Preopen{{
			GuestPath: "/",
			HostPath:  workDir,
		}},
	}, memoryMB, d.cfg.DefaultWallTimeout)

	if err := client.Restore(sandbox.ID, checkpointPath, caps); err != nil {
		if errors.Is(err, models.ErrSnapshotCorrupt) || errors.Is(err, models.ErrSnapshotFenced) {
			return nil, err
		}
		return nil, fmt.Errorf("restore snapshot: %w", err)
	}

	inst := &sandboxInstance{
		sandboxID:    sandbox.ID,
		moduleRef:    moduleRef,
		modulePath:   modulePath,
		moduleDigest: moduleDigest,
		socketPath:   socketPath,
		workDir:      workDir,
		workerKey:    workerKey,
		status:       models.SandboxStatusStarted,
		entryExport:  snap.Config.Entrypoint,
		baseEnv:      copyStringMap(sandbox.Env),
		baseArgs:     wasmArgsFromSandbox(sandbox),
		cpu:          sandbox.CPU,
		memoryMB:     memoryMB,
		diskGB:       sandbox.DiskGB,
		durability:   sandbox.Durability,
	}
	if inst.entryExport == "" {
		inst.entryExport = "_start"
	}

	d.mu.Lock()
	d.byID[sandbox.ID] = inst
	d.mu.Unlock()
	return d.runtimeState(inst), nil
}

func (d *Driver) rehydrateGate(sandboxID string) *sync.Mutex {
	if v, ok := d.rehydrate.Load(sandboxID); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := d.rehydrate.LoadOrStore(sandboxID, mu)
	return actual.(*sync.Mutex)
}

func wasmArgsFromSandbox(sb *models.Sandbox) []string {
	if sb == nil || len(sb.ContainerCommand) == 0 {
		return []string{"wasm"}
	}
	return append([]string(nil), sb.ContainerCommand...)
}
