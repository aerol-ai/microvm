package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeWarmPool is the test double for the WarmPool seam. Records
// every Acquire/Release call so tests can assert the Create flow
// reached the right pool method without exercising real SQLite.
type fakeWarmPool struct {
	mu sync.Mutex

	// preload is the slot+handle to hand back on the next
	// AcquireWithHandle. Set to (nil, nil, ErrNoLoadedSlot) for a miss.
	slot      *vmmpool.Slot
	handle    vmmpool.SpawnedHandle
	acquireEr error

	acquireCalls []acquireCall
	releaseCalls []string
	releaseErr   error
}

type acquireCall struct {
	TemplateID string
	SandboxID  string
}

func (p *fakeWarmPool) AcquireWithHandle(_ context.Context, templateID, sandboxID string, _ time.Time) (*vmmpool.Slot, vmmpool.SpawnedHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acquireCalls = append(p.acquireCalls, acquireCall{TemplateID: templateID, SandboxID: sandboxID})
	if p.acquireEr != nil {
		return nil, nil, p.acquireEr
	}
	return p.slot, p.handle, nil
}

func (p *fakeWarmPool) Release(_ context.Context, sandboxID string, _ time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseCalls = append(p.releaseCalls, sandboxID)
	return p.releaseErr
}

// fakeSpawnedHandle satisfies vmmpool.SpawnedHandle. The runtime's
// Acquire path uses APISocket to build a REST client and RunDir to
// place the per-sandbox overlay file. Shutdown is invoked on the
// rollback paths.
type fakeSpawnedHandle struct {
	mu          sync.Mutex
	apiSocket   string
	runDir      string
	pid         int
	shutdowns   int
	shutdownErr error
}

func (h *fakeSpawnedHandle) APISocket() string { return h.apiSocket }
func (h *fakeSpawnedHandle) RunDir() string    { return h.runDir }
func (h *fakeSpawnedHandle) Pid() int          { return h.pid }
func (h *fakeSpawnedHandle) Shutdown(_ context.Context, _ time.Duration) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shutdowns++
	return h.shutdownErr
}

// stageWarmFixture preloads a warm-pool fixture into the driverFixture
// and returns the fake pool + the (slot, handle) it will hand back on
// the first AcquireWithHandle. Tests that want a miss should overwrite
// pool.acquireEr after this returns.
func stageWarmFixture(t *testing.T, f *driverFixture) (*fakeWarmPool, *fakeSpawnedHandle) {
	t.Helper()
	runDir := t.TempDir()
	apiSocket := filepath.Join(runDir, "api.sock")
	if err := os.WriteFile(apiSocket, []byte{}, 0o600); err != nil {
		t.Fatalf("write fake api socket: %v", err)
	}
	handle := &fakeSpawnedHandle{apiSocket: apiSocket, runDir: runDir}
	slot := &vmmpool.Slot{
		ID:         "vmms-warm-fixture",
		TemplateID: "tpl-warm",
		Status:     vmmpool.StatusAllocated,
		APISocket:  apiSocket,
		RunDir:     runDir,
		VsockCID:   200,
	}
	pool := &fakeWarmPool{slot: slot, handle: handle}
	f.driver.SetWarmPool(pool)
	// Make the REST client factory route warm-path Resume/PATCH calls
	// to the same fake client the test fixture already inspects.
	f.driver.SetClientFactory(func(_ string) VMMClient { return f.client })
	return pool, handle
}

// stageWarmTemplate wires the resolver to surface a snapshot-bearing
// template so Create's eligibility check chooses the warm path.
func stageWarmTemplate(t *testing.T, f *driverFixture, hasOverlay bool) {
	t.Helper()
	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("MEM"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath:         rootfs,
		hasSnapshot:        true,
		hasOverlay:         hasOverlay,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotVsockCID:   200,
	})
}

// TestCreate_WarmHit asserts that a Create against a snapshot-bearing
// template with a warm pool slot ready skips cold-spawn entirely:
// no spawn handle is allocated (the warm slot's API socket is used),
// PatchNetworkInterface PATCHes the per-sandbox TAP onto the loaded
// snapshot, and Action(Resume) is the only Action call (no
// InstanceStart, which would mean the driver mistakenly cold-booted).
//
// This is the headline boot-path-latency win the Phase 4 plan calls
// for: a warm hit should not visit the cold-spawn path's expensive
// steps (process spawn, WaitSocket, LoadSnapshot, configureVMM).
func TestCreate_WarmHit(t *testing.T) {
	f := newDriverFixture(t)
	pool, handle := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-warm",
	}, "sb-warm-hit", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v, want SandboxStatusStarted", state)
	}

	// Pool was consulted exactly once with the right keys.
	pool.mu.Lock()
	if len(pool.acquireCalls) != 1 {
		t.Fatalf("warm pool Acquire calls = %d, want 1", len(pool.acquireCalls))
	}
	if pool.acquireCalls[0].TemplateID != "tpl-warm" || pool.acquireCalls[0].SandboxID != "sb-warm-hit" {
		t.Errorf("warm pool Acquire = %+v, want {tpl-warm sb-warm-hit}", pool.acquireCalls[0])
	}
	if len(pool.releaseCalls) != 0 {
		t.Errorf("warm pool Release calls = %d on happy path, want 0 (release happens at Destroy)", len(pool.releaseCalls))
	}
	pool.mu.Unlock()

	// Warm-hit MUST NOT have shut down the handle on the happy path —
	// the sandbox now owns the firecracker process.
	handle.mu.Lock()
	if handle.shutdowns != 0 {
		t.Errorf("warm handle shutdowns = %d on happy path, want 0", handle.shutdowns)
	}
	handle.mu.Unlock()

	// Cold-spawn fingerprints MUST be absent: the fixture's fake VMM
	// records Start/WaitSocket on cold-boot — they should be untouched.
	if f.vmm.started || f.vmm.waited {
		t.Errorf("cold-spawn VMM started=%v waited=%v on warm-hit path; want false/false", f.vmm.started, f.vmm.waited)
	}

	// LoadSnapshot MUST NOT have been called on Create's path — the
	// pool's refill goroutine already issued it (the test's fake
	// client never sees that call because it's on a separate paused
	// VMM).
	if f.client.snapshotLoad != nil {
		t.Errorf("LoadSnapshot was called on warm-hit Create path: %+v", f.client.snapshotLoad)
	}

	// The per-sandbox host TAP MUST have been realized on the warm-hit
	// path — WarmSpawn skips it, so the Acquire side owns it. Without
	// this Ensure, Action(Resume) would point the guest's eth0 at a
	// host_dev_name that does not exist. Exactly one Ensure, no Remove
	// (the sandbox now owns the device; Destroy removes it later).
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 0 {
		t.Errorf("warm-hit tap ensure=%d remove=%d, want 1/0", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}

	// PATCH NetworkInterface MUST have been called with the per-sandbox
	// TAP name (mapped from the pool's preloaded slot.TapName via the
	// fake tap pool's Allocate).
	nic, ok := f.client.networkPatches[primaryIfaceID]
	if !ok {
		t.Fatal("PATCH NetworkInterface was not called on warm-hit path")
	}
	if nic.HostDevName == "" {
		t.Errorf("PATCH NetworkInterface had empty HostDevName")
	}

	// Action(Resume) was the lone Action call — no InstanceStart.
	if len(f.client.actions) != 1 || f.client.actions[0] != firecracker.ActionResume {
		t.Errorf("actions = %v, want [Resume]", f.client.actions)
	}
}

// TestCreate_WarmMissFallsBackToColdSpawn asserts the contract: when
// the pool returns ErrNoLoadedSlot, Create proceeds with the existing
// snapshot-load path and the user-visible outcome is unchanged. A
// regression here would surface "warm pool empty" as a Create error
// to the user — the pool is supposed to be transparent.
func TestCreate_WarmMissFallsBackToColdSpawn(t *testing.T) {
	f := newDriverFixture(t)
	pool, _ := stageWarmFixture(t, f)
	pool.acquireEr = vmmpool.ErrNoLoadedSlot
	stageWarmTemplate(t, f, false)

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-warm",
	}, "sb-warm-miss", "tok", nil)
	if err != nil {
		t.Fatalf("Create on miss: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v, want SandboxStatusStarted", state)
	}

	// Cold-spawn ran (the snapshot-load path's existing
	// configureVMMForLoad → LoadSnapshot + Resume).
	if !f.vmm.started || !f.vmm.waited {
		t.Errorf("cold-spawn VMM started=%v waited=%v on warm-miss path; want true/true", f.vmm.started, f.vmm.waited)
	}
	if f.client.snapshotLoad == nil {
		t.Error("LoadSnapshot was not called on warm-miss fall-through")
	}

	// Pool was consulted but no Release on the miss path — there was
	// no slot to release.
	pool.mu.Lock()
	if len(pool.acquireCalls) != 1 {
		t.Errorf("warm pool Acquire calls = %d, want 1", len(pool.acquireCalls))
	}
	if len(pool.releaseCalls) != 0 {
		t.Errorf("warm pool Release calls = %d on miss, want 0", len(pool.releaseCalls))
	}
	pool.mu.Unlock()
}

// TestCreate_WarmRollbackOnPatchFailure asserts the cleanup contract
// (pr-review.md §4) on the warm path: if PATCH NetworkInterface fails
// after AcquireWithHandle succeeded, the pool slot MUST be released
// (row → 'released') and the handle MUST be Shutdown so the daemon
// doesn't end up holding a slot the sandbox never claimed.
func TestCreate_WarmRollbackOnPatchFailure(t *testing.T) {
	f := newDriverFixture(t)
	pool, handle := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	f.client.networkPatchErr = errors.New("synthetic PATCH NIC failure")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-warm",
	}, "sb-warm-rollback", "tok", nil)
	if err == nil {
		t.Fatal("Create returned nil on injected PATCH NIC failure")
	}

	pool.mu.Lock()
	if len(pool.releaseCalls) == 0 {
		t.Error("warm pool Release was not called on PATCH failure; slot would leak as 'allocated'")
	}
	pool.mu.Unlock()

	handle.mu.Lock()
	if handle.shutdowns == 0 {
		t.Error("warm handle Shutdown was not called on PATCH failure; firecracker process would leak")
	}
	handle.mu.Unlock()

	// The host TAP was Ensured just before the PATCH, so the rollback
	// MUST Remove it — otherwise a `ip link` device leaks on every
	// failed warm create. ensure=1/remove=1 is the matched pair.
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 1 {
		t.Errorf("warm rollback tap ensure=%d remove=%d, want 1/1", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}
}

// TestCreate_WarmRollbackOnTapEnsureFailure asserts the rollback when
// the host-TAP realization itself fails on the warm path: the create
// must surface the error, tear down the warm handle + pool slot, and
// MUST NOT call Remove (there is no device to delete — mirrors the
// cold path's "no Remove when Ensure failed" discipline).
func TestCreate_WarmRollbackOnTapEnsureFailure(t *testing.T) {
	f := newDriverFixture(t)
	pool, handle := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	f.tapHost.ensureErr = errors.New("synthetic tap ensure failure")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-warm",
	}, "sb-warm-tap-fail", "tok", nil)
	if err == nil {
		t.Fatal("Create returned nil on injected tap Ensure failure")
	}

	// Pool slot released + handle shut down so the warm VMM doesn't leak.
	pool.mu.Lock()
	if len(pool.releaseCalls) == 0 {
		t.Error("warm pool Release was not called on tap Ensure failure; slot would leak as 'allocated'")
	}
	pool.mu.Unlock()
	handle.mu.Lock()
	if handle.shutdowns == 0 {
		t.Error("warm handle Shutdown was not called on tap Ensure failure; firecracker process would leak")
	}
	handle.mu.Unlock()

	// Ensure was attempted once and failed; Remove MUST be skipped.
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 0 {
		t.Errorf("warm tap-ensure-failure ensure=%d remove=%d, want 1/0", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}
}

// TestCreate_WarmEligibilityNoTemplate asserts the warm path is
// skipped when req.TemplateID is empty — ad-hoc creates (Phase 1) MUST
// never consult the warm pool. The pool is per-template; there is no
// "default" warm slot to claim.
func TestCreate_WarmEligibilityNoTemplate(t *testing.T) {
	f := newDriverFixture(t)
	pool, _ := stageWarmFixture(t, f)

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 128,
		DiskGB:   1,
	}, "sb-no-template", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	pool.mu.Lock()
	if len(pool.acquireCalls) != 0 {
		t.Errorf("warm pool Acquire called on ad-hoc create: %v", pool.acquireCalls)
	}
	pool.mu.Unlock()
}

// TestCreate_WarmEligibilityNoSnapshot asserts the warm path is
// skipped when the template has no snapshot (HasSnapshot=false). Such
// templates can only be cold-booted; consulting the pool would always
// miss and waste a SQLite roundtrip on every Create.
func TestCreate_WarmEligibilityNoSnapshot(t *testing.T) {
	f := newDriverFixture(t)
	pool, _ := stageWarmFixture(t, f)
	// Template without snapshot — must short-circuit warm consult.
	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath:  rootfs,
		hasSnapshot: false,
	})

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-no-snap",
	}, "sb-no-snap", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	pool.mu.Lock()
	if len(pool.acquireCalls) != 0 {
		t.Errorf("warm pool Acquire called on no-snapshot template: %v", pool.acquireCalls)
	}
	pool.mu.Unlock()
}

// TestDestroy_ReleasesWarmPoolSlot proves the symmetry: a sandbox
// created via the warm path is teared down by Destroy, which MUST
// call WarmPool.Release on the sandbox id. Without this, the SQLite
// row stays 'allocated' against a deleted sandbox and the GC sweep
// won't reap it (Reap only touches 'released' rows).
func TestDestroy_ReleasesWarmPoolSlot(t *testing.T) {
	f := newDriverFixture(t)
	pool, _ := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-warm",
	}, "sb-destroy-warm", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-destroy-warm"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.releaseCalls) != 1 || pool.releaseCalls[0] != "sb-destroy-warm" {
		t.Errorf("warm pool Release on Destroy = %v, want [sb-destroy-warm]", pool.releaseCalls)
	}
}
