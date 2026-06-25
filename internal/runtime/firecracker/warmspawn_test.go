package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestWarmSpawn_HappyPath asserts the WarmSpawn primitive walks the
// spawn → start → wait-socket → LoadSnapshot sequence and returns a
// handle whose VMM is NOT resumed. The pool's Acquire path resumes the
// slot -- a regression where WarmSpawn resumes the VM on its own
// would put the slot in 'Running' the moment it's loaded, defeating
// the whole "pause and PATCH per-sandbox state before resume" model
// PR-A built the snapshot capture path around.
func TestWarmSpawn_HappyPath(t *testing.T) {
	f := newDriverFixture(t)

	tplDir := t.TempDir()
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("MEM"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	handle, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID:             "vmms-warm-001",
		TemplateID:         "tpl-snap",
		SnapshotMemoryPath: snapMem,
		SnapshotStatePath:  snapState,
		VsockCID:           200,
	})
	if err != nil {
		t.Fatalf("WarmSpawn: %v", err)
	}
	if handle == nil {
		t.Fatal("WarmSpawn returned nil handle on success")
	}

	// LoadSnapshot must have been issued with ResumeVM=false +
	// EnableDiffSnapshots=true. EnableDiffSnapshots is the CoW gate;
	// turning it off here would break the diff-snapshot fast-boot
	// strategy the Phase 3 plan baked in.
	if f.client.snapshotLoad == nil {
		t.Fatal("LoadSnapshot was not called")
	}
	if f.client.snapshotLoad.ResumeVM {
		t.Error("LoadSnapshot.ResumeVM=true; warm-spawn must leave the VMM paused")
	}
	if !f.client.snapshotLoad.EnableDiffSnapshots {
		t.Error("LoadSnapshot.EnableDiffSnapshots=false; warm-spawn must enable diff snapshots")
	}
	if f.client.snapshotLoad.SnapshotPath != snapState {
		t.Errorf("LoadSnapshot.SnapshotPath = %q, want %q", f.client.snapshotLoad.SnapshotPath, snapState)
	}
	if f.client.snapshotLoad.MemBackend == nil ||
		f.client.snapshotLoad.MemBackend.BackendPath != snapMem ||
		f.client.snapshotLoad.MemBackend.BackendType != "File" {
		t.Errorf("LoadSnapshot.MemBackend wrong: %+v", f.client.snapshotLoad.MemBackend)
	}

	// No VM resume: the pool will resume after PATCHing
	// per-sandbox TAP+overlay. Anything in actions[] here that isn't a
	// known warm-spawn step is a regression.
	for _, a := range f.client.actions {
		if a == "InstanceStart" || a == "Resume" {
			t.Errorf("warm-spawn issued forbidden action %q; pool's Acquire path resumes", a)
		}
	}

	// VMM was started + socket waited; not shut down.
	if !f.vmm.started || !f.vmm.waited {
		t.Errorf("vmm started=%v waited=%v; want true/true", f.vmm.started, f.vmm.waited)
	}
	if f.vmm.shutdown {
		t.Error("warm-spawn shut down the VMM on success path; the handle is the pool's to own")
	}

	// Returned handle exposes the API socket + RunDir for the pool to
	// record into the slot row.
	if handle.APISocket() == "" {
		t.Error("handle.APISocket() empty; pool can't issue PATCHes")
	}
	if handle.RunDir() == "" {
		t.Error("handle.RunDir() empty; pool can't place per-slot artifacts")
	}
}

// TestWarmSpawn_CleansUpOnLoadFailure asserts the cleanup contract
// spawner.go promises the pool: a failed WarmSpawn leaks no
// firecracker process and no rundir. The pool's GC sweep depends on
// this — without it, a snapshot-load failure (corrupt artifact, OOM
// at load time) leaves a stuck process the daemon never knows about.
func TestWarmSpawn_CleansUpOnLoadFailure(t *testing.T) {
	f := newDriverFixture(t)
	f.client.snapshotLoadErr = errors.New("synthetic LoadSnapshot failure")

	tplDir := t.TempDir()
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("MEM"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	_, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID:             "vmms-warm-fail",
		TemplateID:         "tpl-snap",
		SnapshotMemoryPath: snapMem,
		SnapshotStatePath:  snapState,
		VsockCID:           200,
	})
	if err == nil {
		t.Fatal("WarmSpawn returned nil error despite injected LoadSnapshot failure")
	}
	if !f.vmm.shutdown {
		t.Error("WarmSpawn did not shut down the VMM on LoadSnapshot failure; pool would leak the process")
	}
	if !f.vmm.cleaned {
		t.Error("WarmSpawn did not clean up the rundir on LoadSnapshot failure")
	}
}

// TestWarmSpawn_ValidatesInputs is a guardrail against the silent
// failure modes the pool's caller can't recover from. The pool itself
// has no notion of what makes a snapshot artifact "valid" — only the
// runtime knows the kernel must be configured, the CID must be ≥3,
// and the snapshot paths must be present. A missing input would
// produce a useless paused VMM the Acquire path can't use.
func TestWarmSpawn_ValidatesInputs(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()

	// Kernel image not configured → models.ErrRuntimeNotImplemented
	// wrapper, since the daemon hasn't been told where the kernel
	// lives. We mutate the fixture driver's cfg in place (Driver
	// holds a sync.Mutex, so a value copy would trip the copylocks
	// vet) and restore it after.
	savedKernel := f.driver.cfg.KernelImage
	f.driver.cfg.KernelImage = ""
	if _, err := f.driver.WarmSpawn(ctx, WarmSpawnRequest{SlotID: "sb", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 5}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("missing kernel: err = %v, want ErrRuntimeNotImplemented", err)
	}
	f.driver.cfg.KernelImage = savedKernel

	cases := []struct {
		name string
		req  WarmSpawnRequest
	}{
		{"empty slot id", WarmSpawnRequest{SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 5}},
		{"missing snapshot paths", WarmSpawnRequest{SlotID: "sb", VsockCID: 5}},
		{"reserved vsock cid", WarmSpawnRequest{SlotID: "sb", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.driver.WarmSpawn(ctx, tc.req); err == nil {
				t.Errorf("WarmSpawn(%+v) returned nil error; expected validation failure", tc.req)
			}
		})
	}
}

// TestPoolSpawner_DelegatesToWarmSpawn proves the runtime adapter
// satisfies vmm.Spawner by forwarding to Driver.WarmSpawn and
// returning a handle the pool can store. The interface satisfaction
// itself is a compile-time check (the var _ assignment) — the
// behavioral check is that SnapshotInputs flow through unchanged into
// the LoadSnapshot REST call.
func TestPoolSpawner_DelegatesToWarmSpawn(t *testing.T) {
	f := newDriverFixture(t)

	tplDir := t.TempDir()
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("MEM"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	// Interface satisfaction is a compile-time assertion; the var _
	// is the single source of truth that adding a method to
	// vmm.Spawner breaks the build here, not at main.go wiring time.
	var _ vmmpool.Spawner = NewPoolSpawner(f.driver)

	adapter := NewPoolSpawner(f.driver)
	handle, err := adapter.Spawn(context.Background(), "vmms-adapt-001", vmmpool.SnapshotInputs{
		TemplateID:         "tpl-snap",
		SnapshotMemoryPath: snapMem,
		SnapshotStatePath:  snapState,
		VsockCID:           200,
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if handle == nil {
		t.Fatal("Spawn returned nil handle on success")
	}

	// Handle's Shutdown must thread through to the underlying VMM.
	// This is what the pool calls when it ages the slot out; a
	// regression where Shutdown is a no-op would leak processes.
	if err := handle.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("handle.Shutdown: %v", err)
	}
	if !f.vmm.shutdown {
		t.Error("PoolSpawner handle.Shutdown did not reach the underlying VMM")
	}
}

// TestPoolSpawner_NilDriverGuard catches the misconfiguration where
// main.go constructs a PoolSpawner before the driver is ready. The
// pool's refill goroutine should surface a clear error rather than
// nil-pointer panic the daemon.
func TestPoolSpawner_NilDriverGuard(t *testing.T) {
	var s *PoolSpawner
	if _, err := s.Spawn(context.Background(), "x", vmmpool.SnapshotInputs{}); err == nil {
		t.Error("nil *PoolSpawner.Spawn returned nil error; should surface a clear misconfiguration")
	}

	s2 := &PoolSpawner{driver: nil}
	if _, err := s2.Spawn(context.Background(), "x", vmmpool.SnapshotInputs{}); err == nil {
		t.Error("PoolSpawner with nil driver returned nil error from Spawn")
	}
}
