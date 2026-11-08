package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// adoptingWasmRuntime is a WASM driver that adopts, restores and keeps by
// sandbox id, as a test sets.
type adoptingWasmRuntime struct {
	fakeCheckpointRuntime
	mu        sync.Mutex
	adoptable map[string]bool
	workDirs  map[string]bool
	restoreOK map[string]bool
	keep      map[string]bool
	adopted   []string
	restored  []string
	envSeen   map[string]map[string]string
	finished  int
}

func (r *adoptingWasmRuntime) AdoptSandbox(_ context.Context, sb *models.Sandbox, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.envSeen == nil {
		r.envSeen = map[string]map[string]string{}
	}
	r.envSeen[sb.ID] = sb.Env
	if !r.adoptable[sb.ID] {
		return nil, wasmruntime.ErrNotAdopted
	}
	r.adopted = append(r.adopted, sb.ID)
	return &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}, nil
}

func (r *adoptingWasmRuntime) RestoreSandbox(_ context.Context, sb *models.Sandbox, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.restoreOK[sb.ID] {
		return nil, errors.New("instantiate failed")
	}
	r.restored = append(r.restored, sb.ID)
	return &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}, nil
}

func (r *adoptingWasmRuntime) HasWorkDir(id string) bool { return r.workDirs[id] }
func (r *adoptingWasmRuntime) FinishAdoption() int       { r.finished++; return 0 }
func (r *adoptingWasmRuntime) KeepOnShutdown(id string) bool {
	return r.keep[id]
}

// TestAdoptWasmSandboxesAtBoot: each started WASM row is taken over,
// restored over its kept work dir, or recorded as lost (stopped, or
// passivated when it has a checkpoint), and never reaped.
func TestAdoptWasmSandboxesAtBoot(t *testing.T) {
	ctx := context.Background()
	checkpoint := filepath.Join(t.TempDir(), "mem.snap")
	if err := os.MkdirAll(checkpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := &adoptingWasmRuntime{
		adoptable: map[string]bool{"sb-adopt": true},
		workDirs:  map[string]bool{"sb-restore": true, "sb-restore-fail": true, "sb-pfailed": true},
		restoreOK: map[string]bool{"sb-restore": true, "sb-pfailed": true},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)
	now := time.Now().UTC()
	rows := []*models.Sandbox{
		{ID: "sb-adopt", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, AuditIncarnationID: "inc-sb-adopt"},
		{ID: "sb-restore", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted},
		{ID: "sb-restore-fail", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted},
		{ID: "sb-lost", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityEphemeral},
		{ID: "sb-passive", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityPassivatable, CheckpointPath: checkpoint},
		{ID: "sb-passive-nockpt", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityPassivatable},
		{ID: "sb-stopped", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped},
		{ID: "sb-pfailed", Runtime: models.RuntimeWasm, Status: models.SandboxStatusPassivateFailed, Durability: models.DurabilityPassivatable},
		{ID: "sb-docker", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted},
	}
	for _, sb := range rows {
		sb.CreatedAt, sb.UpdatedAt = now, now
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("create %s: %v", sb.ID, err)
		}
	}
	sealed, err := svc.sealEnv("sb-adopt", "inc-sb-adopt", map[string]string{"K": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-adopt", sealed); err != nil {
		t.Fatal(err)
	}
	// A sandbox whose sealed env cannot be read is left to reconcile, never
	// adopted without its credentials.
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-badenv", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-badenv", []byte("not-a-seal")); err != nil {
		t.Fatal(err)
	}
	rt.adoptable["sb-badenv"] = true
	report := svc.AdoptWasmSandboxes(ctx)
	if report.Adopted != 1 || report.Restored != 2 || report.Lost != 4 {
		t.Fatalf("report = %+v", report)
	}
	if rt.finished != 1 {
		t.Fatalf("FinishAdoption called %d times", rt.finished)
	}
	if got := rt.envSeen["sb-adopt"]["K"]; got != "v" {
		t.Fatalf("adopt saw env %v; the sealed env must reach the driver", rt.envSeen["sb-adopt"])
	}
	if _, seen := rt.envSeen["sb-stopped"]; seen {
		t.Fatal("a stopped row was adopted")
	}
	if _, seen := rt.envSeen["sb-badenv"]; seen {
		t.Fatal("a sandbox with an unreadable env reached the driver")
	}
	want := map[string]models.SandboxStatus{
		"sb-adopt":          models.SandboxStatusStarted,
		"sb-restore":        models.SandboxStatusStarted,
		"sb-restore-fail":   models.SandboxStatusStopped,
		"sb-lost":           models.SandboxStatusStopped,
		"sb-passive":        models.SandboxStatusPassivated,
		"sb-passive-nockpt": models.SandboxStatusStopped,
		"sb-stopped":        models.SandboxStatusStopped,
		"sb-pfailed":        models.SandboxStatusStarted,
		"sb-docker":         models.SandboxStatusStarted,
	}
	for id, status := range want {
		got, err := st.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v (a lost sandbox must not be reaped)", id, err)
		}
		if got.Status != status {
			t.Errorf("%s status = %s, want %s", id, got.Status, status)
		}
	}
	lost, _ := st.Get(ctx, "sb-lost")
	if lost.StatusReason != models.StatusReasonReconcile {
		t.Fatalf("lost reason = %q", lost.StatusReason)
	}
}

func TestAdoptWasmSandboxesNoop(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if r := svc.AdoptWasmSandboxes(context.Background()); r != (WasmAdoptReport{}) {
		t.Fatalf("no wasm runtime: %+v", r)
	}
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeCheckpointRuntime{})
	if r := svc.AdoptWasmSandboxes(context.Background()); r != (WasmAdoptReport{}) {
		t.Fatalf("runtime without adoption: %+v", r)
	}
}

// TestDrainSkipsWhatSurvives: the shutdown drain leaves alone a sandbox
// whose instance outlives sandboxd, and still checkpoints one that does not.
func TestDrainSkipsWhatSurvives(t *testing.T) {
	ctx := context.Background()
	rt := &adoptingWasmRuntime{keep: map[string]bool{"sb-keep": true}}
	rt.checkpointPath, rt.cloneGen = "/tmp/ckpt", "gen"
	rt.managed = map[string]*models.SandboxRuntimeState{"sb-keep": {SandboxID: "sb-keep"}, "sb-drain": {SandboxID: "sb-drain"}}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)
	now := time.Now().UTC()
	for _, id := range []string{"sb-keep", "sb-drain"} {
		if err := st.Create(ctx, &models.Sandbox{ID: id, Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
			Durability: models.DurabilityPassivatable, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.DrainWasmSandboxes(ctx); err != nil {
		t.Fatal(err)
	}
	if rt.checkpointCalls != 1 {
		t.Fatalf("checkpoints = %d, want 1 (only the one that dies with sandboxd)", rt.checkpointCalls)
	}
	keep, _ := st.Get(ctx, "sb-keep")
	drained, _ := st.Get(ctx, "sb-drain")
	if keep.Status != models.SandboxStatusStarted || drained.Status != models.SandboxStatusPassivated {
		t.Fatalf("kept = %s, drained = %s", keep.Status, drained.Status)
	}
}
