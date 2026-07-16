package wasm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// residentBucket is one logical (ownerRef, digest, memoryMB) group. It may span
// multiple host processes when MaxInstances is hit (spill to <bucket>-2.sock).
type residentBucket struct {
	id    string
	mu    sync.Mutex
	hosts []*residentHost
}

// residentHealthTTL bounds how stale a host's liveness proof may be before a
// reuse re-probes it. Keeping the Ping+Loaded round-trips OFF the per-create hot
// path (Finding B, eng-review 2026-07-17) protects the ~21ms warm-create win; a
// host that dies inside the window is still caught reactively by the
// Instantiate-failure rollback in createOnResidentHost (host.ready=false).
const residentHealthTTL = 5 * time.Second

// residentHost is one shared worker process inside a bucket.
type residentHost struct {
	socket string
	index  int
	ready  bool
	// live is Creating+Started instances routed here. Updated under the parent
	// bucket's mu so MaxInstances is a hard cap under concurrent creates.
	live int
	// lastCheck is when readiness was last proven (bring-up or health-check).
	lastCheck time.Time
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
func createWantsPublicExpose(req models.CreateSandboxRequest) bool {
	return req.AllowPublicTraffic != nil && *req.AllowPublicTraffic
}

// ownerRefFromCreateCtx mirrors service.ownerRefForCreate without importing
// internal/service: non-operator Access → OwnerRef; operator/empty → "".
func ownerRefFromCreateCtx(ctx context.Context) string {
	access, ok := controlplane.AccessFromContext(ctx)
	if !ok || access.Operator {
		return ""
	}
	return strings.TrimSpace(access.Identity.OwnerRef)
}

// residentBucketID derives a collision-free, filesystem-safe bucket id from
// owner, digest, and memory limit. Owner and digest are HASHED, not truncated or
// character-sanitized: truncation/sanitization could map two distinct owners
// (long shared prefix) or `a/b` vs `a-b` to the same bucket, co-locating two
// SaaS tenants in one process and breaking the isolation D7 exists for
// (Finding P0-1). A non-empty ownerRef is mixed in per D7; empty/operator keeps
// the global (owner-less) bucket for self-hosted compile amortization.
func residentBucketID(ownerRef, digest string, memoryMB int) string {
	modHash := shortHash(digest)
	ownerRef = strings.TrimSpace(ownerRef)
	if ownerRef == "" {
		return fmt.Sprintf("%s-%dmb", modHash, memoryMB)
	}
	return fmt.Sprintf("o%s-%s-%dmb", shortHash(ownerRef), modHash, memoryMB)
}

// shortHash is the first 16 hex chars (64 bits) of sha256(s) — a collision-free,
// filesystem-safe fixed-width slug for bucket ids.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func (d *Driver) residentSocketPath(bucketID string, index int) string {
	if index <= 0 {
		return filepath.Join(d.cfg.RunDir, "resident", bucketID+".sock")
	}
	// Second host is <bucket>-2.sock (1-based display index = index+1).
	return filepath.Join(d.cfg.RunDir, "resident", fmt.Sprintf("%s-%d.sock", bucketID, index+1))
}

func (d *Driver) residentHostKey(bucketID string, index int) string {
	if index <= 0 {
		return bucketID
	}
	return fmt.Sprintf("%s-%d", bucketID, index+1)
}

func (d *Driver) maxResidentInstances() int {
	if d.cfg.ResidentHostMaxInstances > 0 {
		return d.cfg.ResidentHostMaxInstances
	}
	// 0 / unset = unbounded (single host grows). Tests leave this at 0; prod
	// config defaults to 32 via FromDaemonConfig.
	return 0
}

// releaseResidentSlotFor decrements the host live count for a committed resident
// instance exactly once, guarding against double release (e.g. Destroy after a
// retry already cleaned up the old instance) via the inst.residentSlotHeld flag.
func (d *Driver) releaseResidentSlotFor(inst *sandboxInstance) {
	if inst == nil || !inst.fromResidentHost {
		return
	}
	d.mu.Lock()
	held := inst.residentSlotHeld
	inst.residentSlotHeld = false
	d.mu.Unlock()
	if held {
		d.releaseResidentSlot(inst.socketPath)
	}
}

// releaseResidentSlot decrements the host live count after Destroy or a failed
// create. Best-effort: looks up the host by socket under residentMu.
func (d *Driver) releaseResidentSlot(socket string) {
	if socket == "" {
		return
	}
	d.residentMu.Lock()
	buckets := d.residentBuckets
	d.residentMu.Unlock()
	for _, b := range buckets {
		b.mu.Lock()
		for _, h := range b.hosts {
			if h.socket == socket {
				if h.live > 0 {
					h.live--
				}
				b.mu.Unlock()
				return
			}
		}
		b.mu.Unlock()
	}
}

// ensureResidentHost picks (or spawns) a host under MaxInstances for the
// (owner, digest, memoryMB) bucket, loads the module once, and returns it.
// Single-flighted per bucket. Re-validates readiness (InstanceLoaded) on reuse
// when the last proof is older than residentHealthTTL so a supervisor respawn
// behind the same socket is detected (D8). When reserve is true the chosen
// host's live count is incremented (caller releases it on failure/Destroy);
// prewarm passes false since it brings up + compiles but instantiates nothing.
func (d *Driver) ensureResidentHost(ctx context.Context, ownerRef, digest, path string, memoryMB int, reserve bool) (*residentBucket, *residentHost, error) {
	id := residentBucketID(ownerRef, digest, memoryMB)

	d.residentMu.Lock()
	if d.residentBuckets == nil {
		d.residentBuckets = make(map[string]*residentBucket)
	}
	b := d.residentBuckets[id]
	if b == nil {
		b = &residentBucket{id: id}
		d.residentBuckets[id] = b
	}
	d.residentMu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	max := d.maxResidentInstances()
	take := func(h *residentHost) (*residentBucket, *residentHost, error) {
		if reserve {
			h.live++
		}
		return b, h, nil
	}
	for _, h := range b.hosts {
		if max > 0 && h.live >= max {
			continue
		}
		if h.ready {
			// Lazy health-check (Finding B): skip the RPC when readiness was proven
			// within residentHealthTTL so the common warm-create path stays RPC-free.
			if time.Since(h.lastCheck) <= residentHealthTTL {
				return take(h)
			}
			if err := d.healthCheckResidentHost(ctx, h, id); err != nil {
				h.ready = false
			} else {
				h.lastCheck = time.Now()
				return take(h)
			}
		}
		if err := d.bringUpResidentHost(ctx, b, h, path, memoryMB); err != nil {
			return nil, nil, err
		}
		return take(h)
	}

	// All hosts full (or none yet) — spawn the next index.
	index := len(b.hosts)
	h := &residentHost{
		socket: d.residentSocketPath(id, index),
		index:  index,
	}
	b.hosts = append(b.hosts, h)
	if err := d.bringUpResidentHost(ctx, b, h, path, memoryMB); err != nil {
		return nil, nil, err
	}
	return take(h)
}

func (d *Driver) healthCheckResidentHost(ctx context.Context, h *residentHost, _ string) error {
	client := d.newWorkerClient(h.socket)
	pingCtx := ctx
	if _, ok := pingCtx.Deadline(); !ok {
		var cancel context.CancelFunc
		pingCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	// InstanceLoaded is a context-bounded round-trip that proves BOTH liveness and
	// that the module is compiled, so it subsumes a Ping. A separate contextless
	// client.Ping could block forever on a wedged host while bucket.mu is held
	// (Finding P2), so it is intentionally not called here.
	loaded, err := client.InstanceLoaded(pingCtx, "")
	if err != nil {
		return err
	}
	if !loaded {
		return fmt.Errorf("resident host module not loaded")
	}
	return nil
}

func (d *Driver) bringUpResidentHost(ctx context.Context, b *residentBucket, h *residentHost, path string, memoryMB int) error {
	if err := os.MkdirAll(filepath.Dir(h.socket), 0o700); err != nil {
		return fmt.Errorf("mkdir resident dir: %w", err)
	}
	key := d.residentHostKey(b.id, h.index)
	if err := d.residentSupervisor.Ensure(ctx, key, h.socket); err != nil {
		return fmt.Errorf("start resident host: %w", err)
	}
	client := d.newWorkerClient(h.socket)
	if err := d.waitWorker(ctx, client, key); err != nil {
		return err
	}
	if _, err := client.LoadModule(key, path, memoryMB); err != nil {
		return fmt.Errorf("resident load module: %w", err)
	}
	h.ready = true
	h.lastCheck = time.Now()
	return nil
}

// PrewarmResidentHosts brings up the resident host and compiles each ref's
// module at daemon boot, so the FIRST create for a standard module is a ~ms
// Instantiate instead of paying the one-time ~seconds CompileModule on the
// create path. Best-effort and meant to be backgrounded by the caller.
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
		// Prewarm the operator/global bucket (empty owner) at default memory.
		// reserve=false: prewarm compiles the module on the host but instantiates
		// no sandbox, so it must NOT hold a live slot (Finding P1-2).
		if _, _, err := d.ensureResidentHost(ctx, "", resolved.Digest, resolved.Path, d.cfg.DefaultMemoryMB, false); err != nil {
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
// the request is non-listen with a known digest.
func (d *Driver) createOnResidentHost(ctx context.Context, req models.CreateSandboxRequest, sandboxID, ref string, resolved *wasmmod.ResolvedModule, memoryMB int, hostMounts []mounts.ContainerBind, timing *createtiming.CreateTiming) (*models.SandboxRuntimeState, error) {
	ownerRef := ownerRefFromCreateCtx(ctx)

	// Idempotent retry (pr-review.md §1): if a prior attempt left an instance for
	// this sandboxID, tear it down on ITS OWN host and release that slot BEFORE we
	// reserve a fresh one. Doing it here (not after ensureResidentHost) means a
	// retry that spills to a different host cannot orphan the old instance on the
	// original host (Findings A + P0-2).
	d.mu.Lock()
	old := d.byID[sandboxID]
	d.mu.Unlock()
	if old != nil && old.fromResidentHost && old.socketPath != "" {
		_ = d.newWorkerClient(old.socketPath).StopInstance(sandboxID)
		d.releaseResidentSlotFor(old)
	}

	bucket, host, err := d.ensureResidentHost(ctx, ownerRef, resolved.Digest, resolved.Path, memoryMB, true)
	if err != nil {
		return nil, err
	}

	workDir := d.sandboxDir(sandboxID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		// Release the slot ensureResidentHost just reserved (Finding P1-2).
		d.releaseResidentSlot(host.socket)
		return nil, fmt.Errorf("mkdir sandbox dir: %w", err)
	}

	workerKey := d.residentHostKey(bucket.id, host.index)
	inst := &sandboxInstance{
		sandboxID:        sandboxID,
		moduleRef:        ref,
		modulePath:       resolved.Path,
		moduleSize:       resolved.SizeBytes,
		moduleDigest:     resolved.Digest,
		socketPath:       host.socket,
		workDir:          workDir,
		workerKey:        workerKey,
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

	// Commit the Creating instance (any prior attempt was already torn down +
	// slot-released above, so no in-band retry handling is needed here).
	d.mu.Lock()
	d.byID[sandboxID] = inst
	d.mu.Unlock()

	client := d.newWorkerClient(host.socket)
	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:            req.Env,
		Args:           wasmArgs(req),
		Preopens:       append([]wasmengine.Preopen(nil), inst.preopens...),
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}, memoryMB, d.cfg.DefaultWallTimeout)

	instStart := time.Now()
	if err := client.Instantiate(sandboxID, caps); err != nil {
		// The host may have respawned empty — force a reload on the next create
		// for this host, and roll this create back.
		bucket.mu.Lock()
		host.ready = false
		if host.live > 0 {
			host.live--
		}
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
	// The reserved slot is now owned by this committed instance; Destroy releases
	// it exactly once via releaseResidentSlotFor (Finding P1-2).
	inst.residentSlotHeld = true
	d.byID[sandboxID] = inst
	d.mu.Unlock()
	return d.runtimeState(inst), nil
}
