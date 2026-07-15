package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// residentBucket tracks the shared resident-host process for one
// (module digest, memoryMB) bucket. mu single-flights host spawn + host-level
// LoadModule so concurrent creates for the same module neither spawn duplicate
// hosts nor double-compile. See plans/wasm-resident-module-host.md.
type residentBucket struct {
	id     string
	socket string
	mu     sync.Mutex
	ready  bool
}

// residentHostEnabled reports whether creates should route to a resident host.
// Requires both the opt-in config flag and a wired resident supervisor, so a
// misconfiguration degrades to the per-sandbox path rather than erroring.
func (d *Driver) residentHostEnabled() bool {
	return d.cfg.ResidentHostEnabled && d.residentSupervisor != nil
}

// createWantsPublicExpose reports whether a create signals intent to expose an
// HTTP port. wasm creates are always non-listen AT create time (the wasip1
// listener is added later by expose_port → SyncGuestListenPorts), so the only
// create-time hint is AllowPublicTraffic. Public-intent creates route to the
// per-sandbox cold path because the resident host rejects wasip1 listeners.
// (Calling expose_port later on a private, resident-hosted sandbox is
// unsupported in this cut and surfaces as an error — documented in the plan.)
func createWantsPublicExpose(req models.CreateSandboxRequest) bool {
	return req.AllowPublicTraffic != nil && *req.AllowPublicTraffic
}

// residentBucketID derives a filesystem-safe bucket id from the module digest
// and memory limit — the two dimensions that must match for instances to share
// one runtime + compiled module (wazero's memory limit is per-runtime).
func residentBucketID(digest string, memoryMB int) string {
	short := strings.ReplaceAll(digest, ":", "-")
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("%s-%dmb", short, memoryMB)
}

func (d *Driver) residentSocketPath(bucketID string) string {
	return filepath.Join(d.cfg.RunDir, "resident", bucketID+".sock")
}

// ensureResidentHost spawns (idempotently) the bucket's host process and loads
// the module into it once, returning the bucket. Single-flighted per bucket.
func (d *Driver) ensureResidentHost(ctx context.Context, digest, path string, memoryMB int) (*residentBucket, error) {
	id := residentBucketID(digest, memoryMB)

	d.residentMu.Lock()
	if d.residentBuckets == nil {
		d.residentBuckets = make(map[string]*residentBucket)
	}
	b := d.residentBuckets[id]
	if b == nil {
		b = &residentBucket{id: id, socket: d.residentSocketPath(id)}
		d.residentBuckets[id] = b
	}
	d.residentMu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ready {
		return b, nil
	}
	if err := os.MkdirAll(filepath.Dir(b.socket), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir resident dir: %w", err)
	}
	if err := d.residentSupervisor.Ensure(ctx, id, b.socket); err != nil {
		return nil, fmt.Errorf("start resident host: %w", err)
	}
	client := d.newWorkerClient(b.socket)
	if err := d.waitWorker(ctx, client, id); err != nil {
		return nil, err
	}
	// Host-level compile-once; the resident server dedups by path so a repeat
	// call across buckets is a cheap no-op.
	if _, err := client.LoadModule(id, path, memoryMB); err != nil {
		return nil, fmt.Errorf("resident load module: %w", err)
	}
	b.ready = true
	return b, nil
}

// PrewarmResidentHosts brings up the resident host and compiles each ref's
// module at daemon boot, so the FIRST create for a standard module is a ~ms
// Instantiate instead of paying the one-time ~seconds CompileModule on the
// create path. This is the fix for the lazy first-create-per-node tail measured
// in the v0.7.10 A/B (resident server p99 ~1.7s = the un-amortized first
// compile). Best-effort and meant to be backgrounded by the caller (compiling a
// ~25MB module is slow — pr-review.md §2 keeps it off the boot-blocking path);
// a ref that does not resolve or compile is logged and skipped. No-op unless
// resident hosts are enabled.
func (d *Driver) PrewarmResidentHosts(ctx context.Context, refs []string) {
	if !d.residentHostEnabled() || d.resolver == nil {
		return
	}
	for _, ref := range refs {
		if ctx.Err() != nil {
			return
		}
		resolved, err := d.resolver.Resolve(ctx, ref)
		if err != nil || resolved == nil || resolved.Digest == "" {
			if d.logger != nil {
				d.logger.Warn("resident prewarm skipped: ref did not resolve", "ref", ref, "error", err)
			}
			continue
		}
		if _, err := d.ensureResidentHost(ctx, resolved.Digest, resolved.Path, d.cfg.DefaultMemoryMB); err != nil {
			if d.logger != nil {
				d.logger.Warn("resident prewarm failed", "ref", ref, "error", err)
			}
			continue
		}
		if d.logger != nil {
			d.logger.Info("resident host prewarmed", "ref", ref, "digest", resolved.Digest, "memory_mb", d.cfg.DefaultMemoryMB)
		}
	}
}

// createOnResidentHost is the resident-host create path: it instantiates an
// isolated instance into the shared bucket host instead of spawning a
// per-sandbox worker + compiling. Reached only when residentHostEnabled() and
// the request is non-listen with a known digest. The existing per-sandbox
// create path (Driver.Create) is left completely untouched.
func (d *Driver) createOnResidentHost(ctx context.Context, req models.CreateSandboxRequest, sandboxID, ref string, resolved *wasmmod.ResolvedModule, memoryMB int, hostMounts []mounts.ContainerBind, timing *createtiming.CreateTiming) (*models.SandboxRuntimeState, error) {
	bucket, err := d.ensureResidentHost(ctx, resolved.Digest, resolved.Path, memoryMB)
	if err != nil {
		return nil, err
	}

	workDir := d.sandboxDir(sandboxID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir sandbox dir: %w", err)
	}

	inst := &sandboxInstance{
		sandboxID:        sandboxID,
		moduleRef:        ref,
		modulePath:       resolved.Path,
		moduleSize:       resolved.SizeBytes,
		moduleDigest:     resolved.Digest,
		socketPath:       bucket.socket,
		workDir:          workDir,
		workerKey:        bucket.id,
		fromResidentHost: true,
		status:           models.SandboxStatusCreating,
		entryExport:      entryExportFromRequest(req),
		baseEnv:          copyStringMap(req.Env),
		baseArgs:         wasmArgs(req),
		preopens:         preopensFromBinds(workDir, hostMounts),
		cpu:              req.CPU,
		memoryMB:         memoryMB,
		diskGB:           req.DiskGB,
		durability:       req.Durability,
	}

	d.mu.Lock()
	_, retry := d.byID[sandboxID]
	d.byID[sandboxID] = inst
	d.mu.Unlock()

	client := d.newWorkerClient(bucket.socket)
	// Idempotency (pr-review.md §1): a retried create for the same sandboxID must
	// not trip the resident engine's duplicate-instance guard. On a retry, drop
	// any instance left by a prior attempt first (no-op if absent). Only on the
	// retry path, so a first create pays no extra round-trip.
	if retry {
		_ = client.StopInstance(sandboxID)
	}

	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:            req.Env,
		Args:           wasmArgs(req),
		Preopens:       append([]wasmengine.Preopen(nil), inst.preopens...),
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}, memoryMB, d.cfg.DefaultWallTimeout)

	instStart := time.Now()
	if err := client.Instantiate(sandboxID, caps); err != nil {
		// The host may have respawned empty (module dropped) — force a reload on
		// the next create for this bucket, and roll this create back.
		bucket.mu.Lock()
		bucket.ready = false
		bucket.mu.Unlock()
		d.mu.Lock()
		delete(d.byID, sandboxID)
		d.mu.Unlock()
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("instantiate module: %w", err)
	}
	if timing != nil {
		timing.RecordStage("wasm_instantiate", time.Since(instStart))
	}
	inst.status = models.SandboxStatusStarted
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()
	return d.runtimeState(inst), nil
}
