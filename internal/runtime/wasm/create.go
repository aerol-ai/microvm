package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func effectiveMemoryMB(req models.CreateSandboxRequest, defaultMB int) int {
	if req.MemoryMB > 0 {
		return req.MemoryMB
	}
	return defaultMB
}

func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, _ string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	driverStart := time.Now()
	timing := createtiming.From(ctx)
	defer func() {
		if timing != nil {
			timing.RecordStage("wasm_driver", time.Since(driverStart))
		}
	}()

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

	resolveStart := time.Now()
	// Per-tenant registry creds ride the request (req.Registry), never global
	// config — so a private oci:// module pulls under the caller's own AOCR
	// identity. Falls back to the resolver's system identity when absent.
	resolved, err := resolveWithRequestAuth(ctx, d.resolver, ref, req.Registry)
	if timing != nil {
		timing.RecordStage("wasm_resolve", time.Since(resolveStart))
	}
	if err != nil {
		return nil, fmt.Errorf("resolve module %q: %w", ref, err)
	}

	memoryMB := effectiveMemoryMB(req, d.cfg.DefaultMemoryMB)

	// Resident-host fast path (opt-in, non-listen, known digest): instantiate
	// into a shared compile-once/instantiate-many host instead of spawning a
	// per-sandbox worker + compiling. Everything below is the untouched
	// per-sandbox path used when the flag is off (the default).
	if d.residentHostEnabled() && !createWantsPublicExpose(req) && resolved.Digest != "" {
		return d.createOnResidentHost(ctx, req, sandboxID, ref, resolved, memoryMB, hostMounts, timing)
	}

	warmStart := time.Now()
	warmSlot, err := d.tryAcquireWarm(ctx, resolved.Digest, resolved.Path, memoryMB)
	if timing != nil {
		if warmSlot != nil {
			timing.RecordStageDesc("wasm_warm", time.Since(warmStart), "hit")
		} else {
			timing.RecordStageDesc("wasm_warm", time.Since(warmStart), "miss")
		}
	}
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

	inst := &sandboxInstance{
		sandboxID:    sandboxID,
		moduleRef:    ref,
		modulePath:   resolved.Path,
		moduleSize:   resolved.SizeBytes,
		moduleDigest: resolved.Digest,
		socketPath:   socketPath,
		workDir:      workDir,
		workerKey:    workerKey,
		fromWarmPool: warmSlot != nil,
		status:       models.SandboxStatusCreating,
		entryExport:  entryExportFromRequest(req),
		baseEnv:      copyStringMap(req.Env),
		baseArgs:     wasmArgs(req),
		preopens:     preopensFromBinds(workDir, hostMounts),
		cpu:          req.CPU,
		memoryMB:     memoryMB,
		diskGB:       req.DiskGB,
		durability:   req.Durability,
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
		spawnStart := time.Now()
		if err := d.supervisor.Ensure(ctx, sandboxID, socketPath); err != nil {
			cleanup()
			return nil, fmt.Errorf("start worker: %w", err)
		}
		if err := d.waitWorker(ctx, client, sandboxID); err != nil {
			cleanup()
			return nil, err
		}
		if timing != nil {
			timing.RecordStage("wasm_spawn", time.Since(spawnStart))
		}
		d.noteWorkerSpawnCount(inst)
		loadStart := time.Now()
		loadTimings, err := client.LoadModule(sandboxID, resolved.Path, memoryMB)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("load module: %w", err)
		}
		if timing != nil {
			timing.RecordStage("wasm_load", time.Since(loadStart))
			// Sub-stages of wasm_load, reported by the worker, so the create-latency
			// bench can see which step owns the ~2.8s cold load (compile dominates
			// for CPython) — the measurement that gates plans/wasm-resident-module-host.md.
			recordLoadSubStages(timing, loadTimings)
		}
	} else {
		if err := d.waitWorker(ctx, client, sandboxID); err != nil {
			cleanup()
			return nil, err
		}
		d.noteWorkerSpawnCount(inst)
	}

	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:            req.Env,
		Args:           wasmArgs(req),
		Preopens:       append([]wasmengine.Preopen(nil), inst.preopens...),
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}, memoryMB, d.cfg.DefaultWallTimeout)
	if err := d.bindAuditCapability(sandboxID, &caps); err != nil {
		cleanup()
		return nil, err
	}

	instStart := time.Now()
	if err := client.Instantiate(sandboxID, caps); err != nil {
		cleanup()
		return nil, fmt.Errorf("instantiate module: %w", err)
	}
	if timing != nil {
		timing.RecordStage("wasm_instantiate", time.Since(instStart))
	}
	// _start is deferred until expose_port enables wasip1 listen (HTTP) or Exec/Invoke (one-shot).
	inst.status = models.SandboxStatusStarted
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()

	return d.runtimeState(inst), nil
}

// recordLoadSubStages emits the wasm_load breakdown as separate Server-Timing
// entries. Only non-zero stages are recorded so a warm-hit create (which never
// calls LoadModule) and engines that don't report timings stay silent.
func recordLoadSubStages(timing *createtiming.CreateTiming, t wasmengine.LoadTimings) {
	if t.NewEngine > 0 {
		timing.RecordStage("wasm_load_newengine", t.NewEngine)
	}
	if t.RuntimeInit > 0 {
		timing.RecordStage("wasm_load_runtime", t.RuntimeInit)
	}
	if t.Read > 0 {
		timing.RecordStage("wasm_load_read", t.Read)
	}
	if t.Compile > 0 {
		timing.RecordStage("wasm_load_compile", t.Compile)
	}
}

func preopensFromBinds(workDir string, binds []mounts.ContainerBind) []wasmengine.Preopen {
	preopens := []wasmengine.Preopen{{
		GuestPath: "/work",
		HostPath:  workDir,
	}}
	for _, b := range binds {
		guest := strings.TrimSpace(b.ContainerPath)
		host := strings.TrimSpace(b.HostPath)
		if guest == "" || host == "" {
			continue
		}
		preopens = append(preopens, wasmengine.Preopen{
			GuestPath: guest,
			HostPath:  host,
		})
	}
	return preopens
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
		SandboxID:       inst.sandboxID,
		ContainerID:     "wasm:" + inst.sandboxID,
		ContainerIP:     wasmLoopbackIP,
		Status:          inst.status,
		ModuleRef:       inst.moduleRef,
		ModuleDigest:    inst.moduleDigest,
		ModulePath:      inst.modulePath,
		ModuleSizeBytes: inst.moduleSize,
	}
}

func (d *Driver) waitWorker(ctx context.Context, client WorkerClient, sandboxID string) error {
	deadline := ctxDeadline(ctx)
	attempt := 0
	for {
		if err := client.Ping(sandboxID); err == nil {
			return nil
		}
		if ctxDone(ctx, deadline) {
			return fmt.Errorf("worker not ready: %w", ctx.Err())
		}
		sleepBrief(ctx, attempt)
		attempt++
	}
}
