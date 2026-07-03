// Package vmm is the policy layer of the Firecracker warm-VMM pool
// described in plans/snapshot-clone-fast-boot.md Phase 4. It sits on
// top of the firecracker_vmm_pool table primitives in
// internal/store/store.go and exposes a typed API the runtime driver
// (PR 4-B) and metrics exporter (PR 4-C) consume.
//
// What lives here vs. internal/store:
//
//   - internal/store: schema, raw CRUD, partial unique index, the
//     SELECT-then-UPDATE idempotent allocator under SQLite's single
//     writer. The load-bearing transactional substrate. Touching this
//     triggers pr-review.md §5 — the indexes are the contract.
//
//   - this package: policy on top of those primitives. Per-template
//     depth knobs, the Slot value type callers depend on (decoupled
//     from store.FirecrackerVMMSlot so re-exports don't leak the
//     store layer), and the future home for the refill goroutine
//     (PR 4-B) and metrics aggregation (PR 4-C). No SQL of its own —
//     the store is the boundary.
//
// What does NOT live here in PR 4-A:
//
//   - The concrete VMM spawner. spawner.go declares the seam (the
//     Spawner and Handle interfaces); PR 4-B's runtime adapter
//     (wrapping *firecracker.Driver) plugs in the real
//     spawn-and-LoadSnapshot implementation. PR 4-A's tests inject a
//     fake to exercise the state machine without touching real
//     processes or root.
//
//   - The refill background goroutine. This package's primitives —
//     Acquire / Release / Stats — are the substrate the loop sits on;
//     the loop itself lands in refill.go alongside PR 4-B's
//     integration.
//
//   - Any Driver.Create change. The pool is an inert substrate until
//     PR 4-B wires it.
//
// Import discipline: this package depends only on internal/store and
// the Go standard library. It MUST NOT import internal/runtime/...,
// internal/service, or any package above the store layer — those will
// import this one (via the runtime adapter in PR 4-B), and we keep
// the cycle wall up by being strict here.
package vmm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// Pool is the per-host warm-VMM pool's policy layer. The zero value is
// not usable; callers must go through New. Safe for concurrent use:
// per-template depth state is guarded by a small mutex, and all SQLite
// writes flow through store's single-writer connection.
type Pool struct {
	st     *store.Store
	logger *slog.Logger

	// depthMu guards depthByTemplate. The map is read on every refill
	// tick (PR 4-B) and written only when main.go calls SetDepth at
	// boot or via a future reload path; a RWMutex would buy nothing
	// because writes are rare and the read path is already cheap.
	depthMu         sync.Mutex
	depthByTemplate map[string]int
	defaultDepth    int

	// handlesMu guards handles. The handles map holds the live
	// SpawnedHandle for every slot that the refill loop has loaded but
	// the Acquire path has not yet claimed. Ownership transfers to the
	// caller on AcquireWithHandle; until then the pool is responsible
	// for Shutting the handle down on daemon-stop or GC drain. The
	// SQLite row is the authoritative status; this map is the
	// in-process complement (firecracker processes don't survive a
	// daemon restart, so reloading the map from disk is meaningless).
	handlesMu sync.Mutex
	handles   map[string]SpawnedHandle
}

// Slot is the policy-level view of one warm-VMM pool entry. Mirrors
// store.FirecrackerVMMSlot but lives in this package so the runtime
// driver and the future metrics exporter depend on a policy type, not
// on the store's row shape. The split is identical to the TAP pool's
// Slot / store.FirecrackerTapSlot pair.
//
// SandboxID is non-empty only when Status == StatusAllocated. APISocket
// and RunDir are non-empty from StatusLoaded onward. The zero time on
// LoadedAt / AllocatedAt / ReleasedAt means "transition not yet
// happened" (the store layer maps SQL NULL to time.Time{} for us).
type Slot struct {
	ID          string
	TemplateID  string
	Status      Status
	SandboxID   string
	APISocket   string
	RunDir      string
	VsockCID    uint32
	CreatedAt   time.Time
	LoadedAt    time.Time
	AllocatedAt time.Time
	ReleasedAt  time.Time
	LastError   string
}

// Status is the typed wrapper over the store's bare-string status
// column. Local to this package so callers depend on the typed
// constants rather than free-form strings; the store layer's bare
// constants stay because they're directly used in SQL literals there.
type Status string

const (
	StatusSpawning  Status = Status(store.FirecrackerVMMSlotStatusSpawning)
	StatusLoaded    Status = Status(store.FirecrackerVMMSlotStatusLoaded)
	StatusAllocated Status = Status(store.FirecrackerVMMSlotStatusAllocated)
	StatusReleased  Status = Status(store.FirecrackerVMMSlotStatusReleased)
)

// Stats is the per-template occupancy snapshot Pool.Stats returns. The
// fields mirror store.FirecrackerVMMPoolStats by name; re-declared in
// this package for the same store-decoupling reason as Slot.
type Stats struct {
	Total     int
	Spawning  int
	Loaded    int
	Allocated int
	Released  int
}

// ErrNoLoadedSlot is the policy-layer mirror of
// store.ErrNoFreeFirecrackerVMMSlot. PR 4-B's runtime adapter
// translates this into "fall back to cold spawn" rather than treating
// it as an error state — an empty pool is the expected behavior between
// refill ticks.
var ErrNoLoadedSlot = errors.New("vmm pool: no loaded slot for this template")

// New returns a Pool. logger may be nil; the package logs nothing in
// PR 4-A but the spawn/refill paths in PR 4-B will use it heavily, so
// the field is wired now to avoid a constructor change later.
func New(st *store.Store, logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{
		st:              st,
		logger:          logger,
		depthByTemplate: make(map[string]int),
		handles:         make(map[string]SpawnedHandle),
	}
}

// SetDefaultDepth is the boot-time hook for the daemon-wide depth
// floor. PR 4-B's refill goroutine reads DepthFor(templateID) on every
// tick; when no per-template override is set the default is what it
// gets. Zero is allowed and means "do not warm this template" —
// makes the per-template opt-in trivial.
func (p *Pool) SetDefaultDepth(depth int) {
	if depth < 0 {
		depth = 0
	}
	p.depthMu.Lock()
	defer p.depthMu.Unlock()
	p.defaultDepth = depth
}

// SetDepth records a per-template depth override. Idempotent: a repeat
// SetDepth with the same depth is a no-op. Passing depth=0 explicitly
// is the "stop warming this template" signal; the refill loop in
// PR 4-B will let existing loaded slots drain and not refill.
func (p *Pool) SetDepth(templateID string, depth int) {
	if templateID == "" {
		return
	}
	if depth < 0 {
		depth = 0
	}
	p.depthMu.Lock()
	defer p.depthMu.Unlock()
	p.depthByTemplate[templateID] = depth
}

// DepthFor returns the configured warm-slot depth for templateID:
// per-template override if set, otherwise the default. Used by PR 4-B's
// refill tick to compute the spawn budget for this iteration.
func (p *Pool) DepthFor(templateID string) int {
	p.depthMu.Lock()
	defer p.depthMu.Unlock()
	if d, ok := p.depthByTemplate[templateID]; ok {
		return d
	}
	return p.defaultDepth
}

// Acquire claims one 'loaded' slot for the (templateID, sandboxID)
// pair. Returns ErrNoLoadedSlot when no claimable slot exists for the
// template — PR 4-B's caller treats that as the cold-spawn fallback
// signal, not as a failed create.
//
// Idempotency mirrors the store layer's: a second Acquire for the
// same sandbox returns the slot already claimed, not a new one. The
// partial unique index on sandbox_id is the load-bearing guarantee;
// the store's idempotency pre-check makes the happy path observable.
//
// now is injected so tests can pin allocated_at. Pass time.Now() in
// production callers.
func (p *Pool) Acquire(ctx context.Context, templateID, sandboxID string, now time.Time) (*Slot, error) {
	raw, err := p.st.AllocateFirecrackerVMMSlot(ctx, templateID, sandboxID, now)
	if err != nil {
		if errors.Is(err, store.ErrNoFreeFirecrackerVMMSlot) {
			return nil, ErrNoLoadedSlot
		}
		return nil, fmt.Errorf("vmm pool acquire: %w", err)
	}
	return slotFromStore(raw), nil
}

// AcquireWithHandle is Acquire plus the in-memory SpawnedHandle the
// refill loop registered after RecordLoaded. The runtime driver's
// pool-hit branch needs the handle to PATCH per-sandbox state onto
// the paused VMM before Resume; the SQLite row alone is insufficient
// because the host PID and process supervision live on the handle.
//
// On hit: returns the slot row, the handle, and a nil error. The
// handle is removed from the pool's internal map at the same time —
// ownership transfers to the caller, whose Destroy path is now
// responsible for the final Shutdown.
//
// On miss: returns (nil, nil, ErrNoLoadedSlot), same as Acquire.
//
// Edge case — slot row exists but handle does not: the SQLite row says
// 'loaded' but the in-memory map has no entry. This happens after a
// daemon restart (the firecracker processes that were warm before the
// restart are orphans on the host, and the rows still say 'loaded'
// because the daemon never got to mark them released). The Acquire
// transaction succeeds at the row level but the handle is missing.
// We treat this as a miss + mark the row released so the GC sweep
// drops it (and the operator's reaper will clean up the orphan
// firecracker process via the next daemon-restart scan). Returns
// ErrNoLoadedSlot.
func (p *Pool) AcquireWithHandle(ctx context.Context, templateID, sandboxID string, now time.Time) (*Slot, SpawnedHandle, error) {
	start := time.Now()
	slot, err := p.Acquire(ctx, templateID, sandboxID, now)
	if err != nil {
		if errors.Is(err, ErrNoLoadedSlot) {
			recordAcquireOutcome(acquireOutcomeMiss, time.Since(start))
		} else {
			recordAcquireOutcome(metricsClassifyAcquireError(err), time.Since(start))
		}
		return nil, nil, err
	}
	p.handlesMu.Lock()
	handle, ok := p.handles[slot.ID]
	if ok {
		delete(p.handles, slot.ID)
		handlesInMemory.Add(-1)
	}
	p.handlesMu.Unlock()
	if !ok {
		// Row says 'loaded' but the handle is gone — orphan from a
		// previous daemon. Release the slot so the row doesn't stay
		// 'allocated' against a sandbox that won't actually own a
		// VMM. Best-effort: the row is now in an inconsistent state
		// vs. the caller's expectations, but ErrNoLoadedSlot is the
		// right signal to fall back to cold spawn.
		if relErr := p.Release(ctx, sandboxID, now); relErr != nil {
			p.logger.Warn("vmm pool: orphan release failed",
				"slot_id", slot.ID, "sandbox_id", sandboxID, "error", relErr)
		}
		recordAcquireOutcome(acquireOutcomeOrphan, time.Since(start))
		return nil, nil, ErrNoLoadedSlot
	}
	recordAcquireOutcome(acquireOutcomeHit, time.Since(start))
	return slot, handle, nil
}

// registerHandle is the refill loop's hook for parking the live
// SpawnedHandle alongside the SQLite row. Called after RecordLoaded
// has committed the 'loaded' status — registering earlier could
// expose a handle that the Acquire path's RowsAffected race would
// then claim before the row was loaded.
func (p *Pool) registerHandle(slotID string, h SpawnedHandle) {
	if h == nil {
		return
	}
	p.handlesMu.Lock()
	if _, dup := p.handles[slotID]; !dup {
		handlesInMemory.Add(1)
	}
	p.handles[slotID] = h
	p.handlesMu.Unlock()
}

// takeHandle removes and returns the in-memory handle for slotID.
// Returns (nil, false) when no handle is registered (already taken
// by Acquire, never registered, or already dropped by Close).
func (p *Pool) takeHandle(slotID string) (SpawnedHandle, bool) {
	p.handlesMu.Lock()
	defer p.handlesMu.Unlock()
	h, ok := p.handles[slotID]
	if ok {
		delete(p.handles, slotID)
		handlesInMemory.Add(-1)
	}
	return h, ok
}

// Close shuts down every still-registered warm VMM. Called by the
// daemon on graceful shutdown so the host doesn't get left with
// orphan firecracker processes. Best-effort: a per-handle Shutdown
// failure is logged and the loop continues — partial cleanup beats no
// cleanup. The grace duration is shared across all handles; pass
// something like 5s in production.
//
// Returns the number of handles drained. The SQLite rows are not
// touched here — Release-then-Reap is the row lifecycle, and the
// next daemon start will release any leftover warm rows before the
// refill loop runs.
func (p *Pool) Close(ctx context.Context, grace time.Duration) int {
	p.handlesMu.Lock()
	handles := p.handles
	p.handles = make(map[string]SpawnedHandle)
	handlesInMemory.Add(-int64(len(handles)))
	p.handlesMu.Unlock()
	drained := 0
	for slotID, h := range handles {
		if err := h.Shutdown(ctx, grace); err != nil {
			p.logger.Warn("vmm pool: close shutdown failed",
				"slot_id", slotID, "error", err)
			continue
		}
		drained++
	}
	return drained
}

// releaseOrphanedRowsAtStart moves warm-pool rows stranded in
// 'spawning'/'loaded' with no claimant into 'released' before the
// daemon begins refilling again. Without this startup repair, a clean
// or crashed restart can strand warm rows forever because no handle
// survives to transition them later.
func (p *Pool) releaseOrphanedRowsAtStart(ctx context.Context, now time.Time) (int, error) {
	released, err := p.st.ReleaseOrphanedFirecrackerVMMSlots(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("vmm pool release orphaned startup rows: %w", err)
	}
	return released, nil
}

// Get returns the slot currently claimed by sandboxID, or nil if it
// has none. PR 4-B's destroy path uses this to find the VMM process
// whose Shutdown needs to be issued.
func (p *Pool) Get(ctx context.Context, sandboxID string) (*Slot, error) {
	raw, err := p.st.GetFirecrackerVMMSlotBySandbox(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("vmm pool get: %w", err)
	}
	if raw == nil {
		return nil, nil
	}
	return slotFromStore(raw), nil
}

// Release moves the sandbox's slot to 'released' so the GC sweep
// (PR 4-B) tears the VMM process down. Idempotent in both the
// "sandbox never claimed a slot" and "slot already released" senses
// — the store-layer WHERE filters cover both cases.
//
// now is injected for the same reason as Acquire.
func (p *Pool) Release(ctx context.Context, sandboxID string, now time.Time) error {
	if err := p.st.ReleaseFirecrackerVMMSlot(ctx, sandboxID, now); err != nil {
		return fmt.Errorf("vmm pool release: %w", err)
	}
	return nil
}

// Stats returns the per-template breakdown by status. Cheap — a single
// GROUP BY scan covered by idx_firecracker_vmm_pool_template_status.
func (p *Pool) Stats(ctx context.Context, templateID string) (Stats, error) {
	raw, err := p.st.GetFirecrackerVMMPoolStats(ctx, templateID)
	if err != nil {
		return Stats{}, fmt.Errorf("vmm pool stats: %w", err)
	}
	return Stats{
		Total:     raw.Total,
		Spawning:  raw.Spawning,
		Loaded:    raw.Loaded,
		Allocated: raw.Allocated,
		Released:  raw.Released,
	}, nil
}

// RecordSpawning is the refill-loop entry point: reserve a new row in
// 'spawning' for the given (slotID, templateID) so the spawner can
// proceed without racing a parallel refill tick on the same row id.
// Exposed in PR 4-A so PR 4-A's tests can drive the state machine,
// and so PR 4-B's refill goroutine has a typed boundary rather than
// reaching into the store layer.
//
// slotID generation is the caller's job — PR 4-B's refill loop uses
// uuid-style "vmms-<16 hex>" mirroring generateTemplateID.
func (p *Pool) RecordSpawning(ctx context.Context, slotID, templateID string, now time.Time) error {
	return p.st.InsertFirecrackerVMMSlot(ctx, store.FirecrackerVMMSlot{
		ID:         slotID,
		TemplateID: templateID,
	}, now)
}

// RecordLoaded is the spawner-success entry point: the spawner has
// produced a paused, snapshot-loaded firecracker process whose API
// socket lives at apiSocket and whose chroot/runDir is runDir, and
// the guest snapshot bakes vsockCID. Promotes the row to 'loaded' so
// subsequent Acquire calls can pick it up.
func (p *Pool) RecordLoaded(ctx context.Context, slotID, apiSocket, runDir string, vsockCID uint32, now time.Time) error {
	return p.st.MarkFirecrackerVMMSlotLoaded(ctx, slotID, apiSocket, runDir, vsockCID, now)
}

// RecordFailed is the spawner-failure entry point: the spawner could
// not produce a usable loaded VMM (process refused to boot, snapshot
// integrity mismatch, etc.). Drops the row straight to 'released' so
// the GC sweep cleans it up after the TTL, with errMsg preserved for
// operator triage.
func (p *Pool) RecordFailed(ctx context.Context, slotID, errMsg string, now time.Time) error {
	return p.st.MarkFirecrackerVMMSlotFailed(ctx, slotID, errMsg, now)
}

// ListNonReleased returns every slot for templateID that is in
// 'spawning', 'loaded', or 'allocated'. PR 4-B's refill tick uses this
// to compute the spawn budget: desired = DepthFor(templateID),
// current = len(ListNonReleased(templateID)), spawn the delta.
func (p *Pool) ListNonReleased(ctx context.Context, templateID string) ([]Slot, error) {
	raw, err := p.st.ListFirecrackerVMMSlotsForRefill(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("vmm pool list non-released: %w", err)
	}
	out := make([]Slot, len(raw))
	for i, r := range raw {
		s := slotFromStore(&r)
		out[i] = *s
	}
	return out, nil
}

// ReapReleased deletes 'released' rows whose released_at is older than
// cutoff. Returns the number of rows actually deleted. PR 4-B's GC
// sweep calls this once it has confirmed the underlying firecracker
// process for each released row is gone — the order matters: row
// deletion is the LAST step, never the first, so a crash mid-sweep
// leaves the row pointing at the dead process for the next pass to
// find and clean up.
//
// Per-row handle drain: when the in-memory map still has a handle for
// a row being reaped, it means the slot was released without ever
// being Acquire'd (e.g. a synthetic test, a future drain path, or a
// partial cleanup that released the row before the process stopped).
// Shutdown must succeed before delete so the row remains the durable
// breadcrumb for a retry if teardown fails.
func (p *Pool) ReapReleased(ctx context.Context, cutoff time.Time) (int, error) {
	released, err := p.st.ListReleasedFirecrackerVMMSlots(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("vmm pool reap (list): %w", err)
	}
	var deleted int
	for _, sl := range released {
		if h, ok := p.takeHandle(sl.ID); ok {
			if sErr := h.Shutdown(ctx, 3*time.Second); sErr != nil {
				p.logger.Warn("vmm pool reap: shutdown failed",
					"slot_id", sl.ID, "error", sErr)
				p.registerHandle(sl.ID, h)
				continue
			}
		}
		// WarmSpawn allocates a Firecracker TAP slot under the warm VMM
		// slot id before LoadSnapshot. The handle's Shutdown releases it on
		// the normal in-memory path; this store-level release covers daemon
		// restart/orphan cases where the VMM row survived but the handle map
		// did not. Idempotent for slots already transferred to a sandbox or
		// already released.
		if err := p.st.ReleaseFirecrackerTapSlot(ctx, sl.ID); err != nil {
			return deleted, fmt.Errorf("vmm pool reap (release tap %s): %w", sl.ID, err)
		}
		if err := p.st.DeleteFirecrackerVMMSlot(ctx, sl.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Someone else (a racing reap, the GC tests) dropped
				// the row between the list and the delete; not an
				// error, just an idempotency win.
				continue
			}
			return deleted, fmt.Errorf("vmm pool reap (delete %s): %w", sl.ID, err)
		}
		deleted++
	}
	recordReaped(deleted)
	return deleted, nil
}

// slotFromStore copies a store.FirecrackerVMMSlot into the policy
// Slot shape. Centralized so callers see a single conversion point;
// adding a field to either shape forces an edit here and the resulting
// build break catches any drift.
func slotFromStore(s *store.FirecrackerVMMSlot) *Slot {
	if s == nil {
		return nil
	}
	return &Slot{
		ID:          s.ID,
		TemplateID:  s.TemplateID,
		Status:      Status(s.Status),
		SandboxID:   s.SandboxID,
		APISocket:   s.APISocket,
		RunDir:      s.RunDir,
		VsockCID:    s.VsockCID,
		CreatedAt:   s.CreatedAt,
		LoadedAt:    s.LoadedAt,
		AllocatedAt: s.AllocatedAt,
		ReleasedAt:  s.ReleasedAt,
		LastError:   s.LastError,
	}
}
