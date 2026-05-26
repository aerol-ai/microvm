package service

// template_health_test.go covers the Phase 6 PR-A service-layer
// snapshot-corruption recovery:
//
//   - MarkSnapshotCorrupt is idempotent under concurrent invocation —
//     N goroutines hitting the same ready template produce exactly
//     one state transition and one rebuild kick.
//   - RebuildTemplateSnapshot rehydrates an unhealthy template back to
//     ready when the snapshotter succeeds, and degrades to
//     ready_no_snapshot when the rootfs (or the snapshotter itself)
//     is also broken.
//   - The notifier surface is best-effort: store/rebuild errors after
//     logging do not propagate user-visibly.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newHealthHarness sets up a Service with a real sqlite store + the
// fake snapshotter/CID-allocator from template_test.go. The template
// row is seeded in status=ready with snapshot artifacts populated so
// it's a valid MarkSnapshotCorrupt target.
func newHealthHarness(t *testing.T) (*Service, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	templatesDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatalf("mkdir templates dir: %v", err)
	}
	svc := &Service{
		cfg: config.Config{
			EnableFirecracker:               true,
			FirecrackerTemplatesDir:         templatesDir,
			FirecrackerTemplateMemoryMB:     512,
			FirecrackerTemplateVCPU:         1,
			FirecrackerTemplateBuildTimeout: 5 * time.Second,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
	}
	return svc, st, templatesDir
}

// seedReadyTemplate inserts a row that satisfies MarkSnapshotCorrupt's
// preconditions: status=ready, has_snapshot=true, snapshot paths point
// at real (writable) on-disk files. The rootfs file is also touched so
// the rebuild path's RootfsPath check passes.
func seedReadyTemplate(t *testing.T, st *store.Store, templatesDir, id string) *models.Template {
	t.Helper()
	tplDir := filepath.Join(templatesDir, id)
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatalf("mkdir tpl dir: %v", err)
	}
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("ROOTFS"), 0o600); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	memPath := filepath.Join(tplDir, snapshotMemoryFilename)
	statePath := filepath.Join(tplDir, snapshotStateFilename)
	if err := os.WriteFile(memPath, []byte("MEM"), 0o600); err != nil {
		t.Fatalf("write mem: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("STATE"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	now := time.Now().UTC()
	tpl := &models.Template{
		ID:                 id,
		Image:              "docker://alpine:3.19",
		Status:             models.TemplateStatusReady,
		RootfsPath:         rootfs,
		RootfsSizeBytes:    6,
		SnapshotMemoryPath: memPath,
		SnapshotStatePath:  statePath,
		SnapshotSizeBytes:  8,
		SnapshotChecksum:   "sha256:dead|sha256:beef",
		SnapshotVsockCID:   42,
		HasSnapshot:        true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	return tpl
}

// TestMarkSnapshotCorrupt_IdempotentUnderConcurrency is the
// concurrency primitive contract: N parallel observers of the same
// corruption event produce exactly one state transition and exactly
// one rebuild attempt. Without this property the refill loop + cold-
// load paths would each fire a rebuild on every retry — N rebuilds
// for one corruption.
func TestMarkSnapshotCorrupt_IdempotentUnderConcurrency(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-conc")

	// Stub the snapshotter so RebuildTemplateSnapshot completes
	// synchronously and we can count rebuild invocations through it.
	snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 16)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	const N = 16
	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			_ = svc.MarkSnapshotCorrupt(context.Background(), tpl.ID, "checksum mismatch")
		}()
	}
	wg.Wait()

	// Wait for at most one rebuild to complete. A deterministic deadline
	// rather than a fixed sleep so the test doesn't slow the suite.
	deadline := time.After(3 * time.Second)
waitRebuild:
	for {
		select {
		case <-snap.done:
			break waitRebuild
		case <-deadline:
			t.Fatal("rebuild never fired; MarkSnapshotCorrupt's first observer must kick a rebuild")
		}
	}

	// Drain any *additional* rebuilds with a short grace window. There
	// should be none — the UPDATE WHERE status='ready' guard means only
	// the first observer transitions the row, and the kick is gated on
	// that transition succeeding.
	time.Sleep(50 * time.Millisecond)
	snap.mu.Lock()
	calls := snap.calls
	snap.mu.Unlock()
	if calls != 1 {
		t.Errorf("snapshotter calls = %d, want exactly 1 (one rebuild per corruption event)", calls)
	}

	// After the rebuild succeeds the row is back in ready.
	got, err := st.GetTemplate(context.Background(), tpl.ID)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got.Status != models.TemplateStatusReady {
		t.Errorf("post-rebuild status = %s, want ready", got.Status)
	}
	if !got.HasSnapshot {
		t.Errorf("HasSnapshot = false after successful rebuild")
	}
}

// TestMarkSnapshotCorrupt_NoOpWhenAlreadyUnhealthy proves the second
// arm of idempotency: a template that's already unhealthy (e.g. a
// previous observer transitioned it but the rebuild hasn't completed
// yet) does NOT kick a second rebuild on the next MarkSnapshotCorrupt
// call. The store's UPDATE WHERE status='ready' clause is the gate.
func TestMarkSnapshotCorrupt_NoOpWhenAlreadyUnhealthy(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-already")

	// Force the row into unhealthy before any MarkSnapshotCorrupt call.
	changed, err := st.MarkTemplateUnhealthy(context.Background(), tpl.ID, "preexisting")
	if err != nil {
		t.Fatalf("pre-MarkTemplateUnhealthy: %v", err)
	}
	if !changed {
		t.Fatal("pre-MarkTemplateUnhealthy did not change row; harness misconfigured")
	}

	// Snapshotter that records calls but never returns — if a rebuild
	// is kicked we'll catch it via the channel.
	snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 4)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	if err := svc.MarkSnapshotCorrupt(context.Background(), tpl.ID, "another observer"); err != nil {
		t.Fatalf("MarkSnapshotCorrupt on already-unhealthy: %v", err)
	}

	select {
	case <-snap.done:
		t.Fatal("rebuild was kicked despite row already being unhealthy; idempotency broken")
	case <-time.After(100 * time.Millisecond):
		// no rebuild — expected
	}
}

// TestMarkSnapshotCorrupt_MissingTemplateIsNoop guards the race where
// the template is deleted between the corrupt-load observation and the
// MarkSnapshotCorrupt call. Returning an error would surface a noisy
// log at a call site that's already returning its own user-facing
// error; nil is the correct response.
func TestMarkSnapshotCorrupt_MissingTemplateIsNoop(t *testing.T) {
	svc, _, _ := newHealthHarness(t)
	// Empty store — template "tpl-gone" doesn't exist.
	if err := svc.MarkSnapshotCorrupt(context.Background(), "tpl-gone", "checksum"); err != nil {
		t.Errorf("MarkSnapshotCorrupt on missing template = %v, want nil (treated as no-op)", err)
	}
}

// TestRebuildTemplateSnapshot_SnapshotterFailFlipsToReadyNoSnapshot is
// the degraded recovery arm: the rootfs is fine but the snapshotter
// itself fails (VMM boot timeout, etc.). The terminal state must be
// ready_no_snapshot — the cold-build path still works and the operator
// sees a distinct "snapshot broken, fallback engaged" signal rather
// than a stuck unhealthy row.
func TestRebuildTemplateSnapshot_SnapshotterFailFlipsToReadyNoSnapshot(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-rebuild-fail")

	// Move the row into unhealthy directly (skip MarkSnapshotCorrupt so
	// this test isolates the rebuild arm).
	if _, err := st.MarkTemplateUnhealthy(context.Background(), tpl.ID, "test setup"); err != nil {
		t.Fatalf("MarkTemplateUnhealthy: %v", err)
	}

	snap := &fakeTemplateSnapshotter{err: errors.New("vmm wedged on rebuild")}
	svc.SetTemplateSnapshotter(snap)
	alloc := &fakeCIDAllocator{cid: 42}
	svc.SetTemplateCIDAllocator(alloc)

	err := svc.RebuildTemplateSnapshot(context.Background(), tpl.ID)
	if err == nil {
		t.Fatal("RebuildTemplateSnapshot returned nil error despite snapshotter failure")
	}

	got, gerr := st.GetTemplate(context.Background(), tpl.ID)
	if gerr != nil {
		t.Fatalf("GetTemplate: %v", gerr)
	}
	if got.Status != models.TemplateStatusReadyNoSnapshot {
		t.Errorf("status = %s, want ready_no_snapshot after snapshotter failure", got.Status)
	}
	if got.SnapshotError == "" {
		t.Errorf("SnapshotError empty after rebuild failure")
	}
	// CID released so the next rebuild attempt gets a clean slot.
	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	if len(alloc.releaseIDs) != 1 || alloc.releaseIDs[0] != tpl.ID {
		t.Errorf("releaseIDs = %v, want [%q]", alloc.releaseIDs, tpl.ID)
	}
}

// TestRebuildTemplateSnapshot_RejectsNonUnhealthyState guards the
// state-machine precondition: someone else (operator action, a
// completed concurrent rebuild) may have moved the row out of
// unhealthy between the kick and the rebuild goroutine starting.
// Re-rebuilding would race with whoever's driving the new state.
func TestRebuildTemplateSnapshot_RejectsNonUnhealthyState(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-still-ready")
	// Leave row in ready (skip MarkTemplateUnhealthy).

	snap := &fakeTemplateSnapshotter{}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	err := svc.RebuildTemplateSnapshot(context.Background(), tpl.ID)
	if err == nil {
		t.Fatal("RebuildTemplateSnapshot on a ready row returned nil; must refuse")
	}
	snap.mu.Lock()
	defer snap.mu.Unlock()
	if snap.calls != 0 {
		t.Errorf("snapshotter calls = %d, want 0 on precondition failure", snap.calls)
	}
}

// TestRebuildTemplateSnapshot_RequiresWiring asserts the configuration
// guard: a daemon without snapshotter+CID allocator wiring (e.g.
// templates feature disabled or partially configured) must surface a
// clear error rather than nil-pointer-deref on the snapshot call.
func TestRebuildTemplateSnapshot_RequiresWiring(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-no-wiring")
	if _, err := st.MarkTemplateUnhealthy(context.Background(), tpl.ID, "test"); err != nil {
		t.Fatalf("MarkTemplateUnhealthy: %v", err)
	}
	// templateSnapshotter and templateCIDAllocator left nil.
	if err := svc.RebuildTemplateSnapshot(context.Background(), tpl.ID); err == nil {
		t.Error("RebuildTemplateSnapshot without wiring returned nil error")
	}
}

// TestRekickUnhealthyTemplatesAtStart_RekicksEachUnhealthyRow simulates
// the crash-mid-rebuild scenario the scanner exists to recover from:
// two templates were marked unhealthy before a daemon restart and no
// in-process rebuild ever fired. After RekickUnhealthyTemplatesAtStart
// both rows should return to ready via the same RebuildTemplateSnapshot
// path the in-process notifier uses.
func TestRekickUnhealthyTemplatesAtStart_RekicksEachUnhealthyRow(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tplA := seedReadyTemplate(t, st, templatesDir, "tpl-rekick-a")
	tplB := seedReadyTemplate(t, st, templatesDir, "tpl-rekick-b")
	healthy := seedReadyTemplate(t, st, templatesDir, "tpl-healthy")
	// Drive both targets into unhealthy directly (skip MarkSnapshotCorrupt
	// so this isolates the scanner's rekick semantics from the notifier's
	// CAS gate).
	if _, err := st.MarkTemplateUnhealthy(context.Background(), tplA.ID, "prior crash"); err != nil {
		t.Fatalf("seed unhealthy A: %v", err)
	}
	if _, err := st.MarkTemplateUnhealthy(context.Background(), tplB.ID, "prior crash"); err != nil {
		t.Fatalf("seed unhealthy B: %v", err)
	}

	snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 4)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 99})

	svc.RekickUnhealthyTemplatesAtStart(context.Background())

	// Two rebuilds should complete before the deadline. The scanner
	// fires kicks synchronously but the rebuild runs in a detached
	// goroutine — wait for both via the snapshotter's done channel.
	deadline := time.After(3 * time.Second)
	for i := range 2 {
		select {
		case <-snap.done:
		case <-deadline:
			t.Fatalf("only %d/2 rebuilds completed within deadline", i)
		}
	}

	// Healthy row was never touched — no extra rebuild beyond the two
	// unhealthy ones.
	time.Sleep(50 * time.Millisecond)
	snap.mu.Lock()
	calls := snap.calls
	snap.mu.Unlock()
	if calls != 2 {
		t.Errorf("snapshotter calls = %d, want 2 (one per unhealthy row)", calls)
	}

	// Both targets recovered; healthy row untouched.
	for _, id := range []string{tplA.ID, tplB.ID} {
		got, err := st.GetTemplate(context.Background(), id)
		if err != nil {
			t.Fatalf("GetTemplate %s: %v", id, err)
		}
		if got.Status != models.TemplateStatusReady {
			t.Errorf("template %s post-rebuild status = %s, want ready", id, got.Status)
		}
	}
	gotHealthy, err := st.GetTemplate(context.Background(), healthy.ID)
	if err != nil {
		t.Fatalf("GetTemplate healthy: %v", err)
	}
	if gotHealthy.Status != models.TemplateStatusReady {
		t.Errorf("healthy template status = %s, want ready (untouched)", gotHealthy.Status)
	}
}

// TestRekickUnhealthyTemplatesAtStart_EmptyStoreIsNoop is the
// boring-but-load-bearing case: most daemon starts have no unhealthy
// templates and the scanner must not log noise or block startup.
func TestRekickUnhealthyTemplatesAtStart_EmptyStoreIsNoop(t *testing.T) {
	svc, _, _ := newHealthHarness(t)
	snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 1)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 1})

	svc.RekickUnhealthyTemplatesAtStart(context.Background())

	select {
	case <-snap.done:
		t.Fatal("snapshotter fired on empty store; scanner should be no-op")
	case <-time.After(75 * time.Millisecond):
	}
	snap.mu.Lock()
	defer snap.mu.Unlock()
	if snap.calls != 0 {
		t.Errorf("snapshotter calls = %d, want 0 on empty store", snap.calls)
	}
}

// TestRequestTemplateRebuild_ReadyTransitionsAndKicks proves the happy
// path: an operator-triggered rebuild against a ready template flips it
// to unhealthy and kicks exactly one rebuild via the existing
// MarkSnapshotCorrupt path. The returned row reflects the
// post-transition state so the SDK can poll-until-ready against the
// 202 response directly.
func TestRequestTemplateRebuild_ReadyTransitionsAndKicks(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-op-rebuild")

	snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 4)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	got, err := svc.RequestTemplateRebuild(context.Background(), tpl.ID)
	if err != nil {
		t.Fatalf("RequestTemplateRebuild: %v", err)
	}
	if got == nil {
		t.Fatal("RequestTemplateRebuild returned nil template")
	}
	// MarkSnapshotCorrupt may have already been overtaken by the
	// rebuild goroutine flipping the row to snapshotting/ready by the
	// time we re-read. The contract is "row is no longer ready" — the
	// rebuild is in flight.
	if got.Status == models.TemplateStatusReady {
		t.Errorf("status = ready after rebuild request; expected unhealthy/snapshotting/ready_no_snapshot or post-rebuild ready")
	}

	select {
	case <-snap.done:
	case <-time.After(3 * time.Second):
		t.Fatal("rebuild did not fire; operator request must trigger snapshotter")
	}
	snap.mu.Lock()
	calls := snap.calls
	snap.mu.Unlock()
	if calls != 1 {
		t.Errorf("snapshotter calls = %d, want 1 (operator request fires one rebuild)", calls)
	}
}

// TestRequestTemplateRebuild_ConcurrentCallersCollapseToOneRebuild pins
// the idempotency contract: while a rebuild is in flight, N concurrent
// operator retries produce exactly one rebuild kick. The CAS in
// MarkTemplateUnhealthy is the gating primitive — the losers of the
// race see unhealthy/snapshotting on their re-read and either return
// 202 (unhealthy arm) or ErrTemplateNotRebuildable (snapshotting arm).
// Either is correct UX; none of the losers may trigger a second kick.
//
// We block the snapshotter via `snap.block` so the rebuild stays in
// flight until the test releases it — without that, a fast rebuild
// would complete between racing callers and each cycle would
// legitimately kick a fresh rebuild, breaking the determinism we want
// to assert here.
func TestRequestTemplateRebuild_ConcurrentCallersCollapseToOneRebuild(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-op-conc")

	snap := &fakeTemplateSnapshotter{
		done:  make(chan struct{}, 16),
		block: make(chan struct{}),
	}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	const N = 16
	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			// All callers must complete without panic; success or
			// ErrTemplateNotRebuildable (race against snapshotting
			// transition) are both correct outcomes.
			_, _ = svc.RequestTemplateRebuild(context.Background(), tpl.ID)
		}()
	}
	wg.Wait()

	// Snapshotter is now blocked inside its first call. Confirm no
	// additional kicks land within a brief grace window — the row is
	// either unhealthy or snapshotting, so any further RequestTemplateRebuild
	// would fail the CAS or fall into the snapshotting/not-rebuildable arm.
	time.Sleep(75 * time.Millisecond)
	snap.mu.Lock()
	calls := snap.calls
	snap.mu.Unlock()
	if calls != 1 {
		t.Errorf("snapshotter calls = %d, want 1 (N operator requests collapse to one rebuild while in flight)", calls)
	}

	// Release the blocked snapshotter and drain.
	close(snap.block)
	select {
	case <-snap.done:
	case <-time.After(3 * time.Second):
		t.Fatal("rebuild never drained after release")
	}
}

// TestRequestTemplateRebuild_UnhealthyIsNoopReturnsRow proves the
// already-unhealthy arm. A second operator request against an
// already-unhealthy template must NOT kick a second rebuild — the first
// rebuild is in flight (or will be re-kicked by the startup scanner) —
// and must return the row so the operator's UI can keep polling.
func TestRequestTemplateRebuild_UnhealthyIsNoopReturnsRow(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-op-unhealthy")
	if _, err := st.MarkTemplateUnhealthy(context.Background(), tpl.ID, "test setup"); err != nil {
		t.Fatalf("MarkTemplateUnhealthy: %v", err)
	}

	snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 4)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

	got, err := svc.RequestTemplateRebuild(context.Background(), tpl.ID)
	if err != nil {
		t.Fatalf("RequestTemplateRebuild on unhealthy: %v", err)
	}
	if got == nil || got.Status != models.TemplateStatusUnhealthy {
		t.Errorf("got status = %v, want unhealthy", got)
	}
	select {
	case <-snap.done:
		t.Fatal("rebuild was kicked despite row already unhealthy; should defer to existing in-flight rebuild")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestRequestTemplateRebuild_RejectsNonRebuildableStates pins the
// 412 contract: states where rebuild is unsafe (build in flight) or
// unsupported (ready_no_snapshot — needs source-image access; failed —
// needs delete+recreate) must surface ErrTemplateNotRebuildable so
// the operator's tooling can distinguish them from 404.
func TestRequestTemplateRebuild_RejectsNonRebuildableStates(t *testing.T) {
	for _, status := range []models.TemplateStatus{
		models.TemplateStatusPending,
		models.TemplateStatusBuildingRootfs,
		models.TemplateStatusSnapshotting,
		models.TemplateStatusReadyNoSnapshot,
		models.TemplateStatusFailed,
	} {
		t.Run(string(status), func(t *testing.T) {
			svc, st, templatesDir := newHealthHarness(t)
			tpl := seedReadyTemplate(t, st, templatesDir, "tpl-state-"+string(status))
			// Force the row into the test's target state. Use
			// UpdateTemplateStatus rather than MarkTemplateUnhealthy so
			// each subtest is isolated.
			if err := st.UpdateTemplateStatus(context.Background(), tpl.ID,
				status, tpl.RootfsPath, "", tpl.RootfsSizeBytes); err != nil {
				t.Fatalf("force status %s: %v", status, err)
			}

			snap := &fakeTemplateSnapshotter{done: make(chan struct{}, 1)}
			svc.SetTemplateSnapshotter(snap)
			svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

			_, err := svc.RequestTemplateRebuild(context.Background(), tpl.ID)
			if err == nil {
				t.Fatalf("status=%s: RequestTemplateRebuild returned nil err; must refuse", status)
			}
			if !errors.Is(err, models.ErrTemplateNotRebuildable) {
				t.Errorf("status=%s: err = %v, want errors.Is(_, ErrTemplateNotRebuildable)", status, err)
			}
			select {
			case <-snap.done:
				t.Errorf("status=%s: snapshotter fired despite refusal", status)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// TestRequestTemplateRebuild_MissingTemplatePropagatesNotFound proves
// the 404 mapping: a missing template ID returns a store.ErrNotFound
// that apihttp.WriteStoreAwareError maps to 404. Without this the
// handler would return 400 and operator tooling couldn't tell missing
// from malformed.
func TestRequestTemplateRebuild_MissingTemplatePropagatesNotFound(t *testing.T) {
	svc, _, _ := newHealthHarness(t)
	_, err := svc.RequestTemplateRebuild(context.Background(), "tpl-missing")
	if err == nil {
		t.Fatal("RequestTemplateRebuild on missing template returned nil; must error")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is(_, store.ErrNotFound) so the handler maps to 404", err)
	}
}

// TestRequestTemplateRebuild_EmptyIDRejected guards the API surface:
// a missing path value (would happen only on a malformed router
// registration) must not nil-deref into the store.
func TestRequestTemplateRebuild_EmptyIDRejected(t *testing.T) {
	svc, _, _ := newHealthHarness(t)
	if _, err := svc.RequestTemplateRebuild(context.Background(), ""); err == nil {
		t.Error("RequestTemplateRebuild with empty id returned nil; must reject")
	}
}

// TestRekickUnhealthyTemplatesAtStart_NoOpWithoutWiring proves the
// guard: if the daemon hasn't attached a snapshotter (e.g.
// EnableFirecracker true but template subsystem partially wired) the
// scanner short-circuits without touching the store. Important because
// kickSnapshotRebuild would just log "rebuild requires wiring" forever
// otherwise.
func TestRekickUnhealthyTemplatesAtStart_NoOpWithoutWiring(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-no-wire")
	if _, err := st.MarkTemplateUnhealthy(context.Background(), tpl.ID, "test"); err != nil {
		t.Fatalf("MarkTemplateUnhealthy: %v", err)
	}
	// snapshotter + allocator deliberately left nil.

	svc.RekickUnhealthyTemplatesAtStart(context.Background())

	got, err := st.GetTemplate(context.Background(), tpl.ID)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got.Status != models.TemplateStatusUnhealthy {
		t.Errorf("template status = %s, want unhealthy (scanner must not touch)", got.Status)
	}
}
