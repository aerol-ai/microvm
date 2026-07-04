package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Phase 0 instrumentation tests (plans/firecracker-create-latency.md):
// Driver.Create must attribute its boot stages onto the context-carried
// createtiming recorder so the v1 handler can surface them as
// Server-Timing entries. Stage presence is the contract — the bench's
// per-stage breakdown can only sum to the create total if every visited
// stage records, and only visited stages record.

// stageMap folds the recorder into name→Stage for assertion convenience.
func stageMap(timing *createtiming.CreateTiming) map[string]createtiming.Stage {
	out := map[string]createtiming.Stage{}
	for _, st := range timing.Stages() {
		out[st.Name] = st
	}
	return out
}

func requireStages(t *testing.T, stages map[string]createtiming.Stage, names ...string) {
	t.Helper()
	for _, name := range names {
		st, ok := stages[name]
		if !ok {
			t.Errorf("stage %q not recorded (have %v)", name, stageNames(stages))
			continue
		}
		if st.DurMS < 0 {
			t.Errorf("stage %q duration = %v, want >= 0", name, st.DurMS)
		}
	}
}

func forbidStages(t *testing.T, stages map[string]createtiming.Stage, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, ok := stages[name]; ok {
			t.Errorf("stage %q recorded but must be absent on this path (have %v)", name, stageNames(stages))
		}
	}
}

func stageNames(stages map[string]createtiming.Stage) []string {
	names := make([]string, 0, len(stages))
	for name := range stages {
		names = append(names, name)
	}
	return names
}

// TestCreate_SnapshotLoad_RecordsStages: a successful snapshot-load
// Create populates every boot stage, including fc_verify (checksum on)
// and fc_load, and never the cold-boot fc_configure or warm fc_warm.
func TestCreate_SnapshotLoad_RecordsStages(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = true
	f.driver.snapshotVerifier = func(_, _, _ string) error { return nil }

	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	for _, p := range []string{templateRootfs, snapMem, snapState} {
		if err := os.WriteFile(p, []byte("X"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotChecksum:   "deadbeef",
		snapshotVsockCID:   200,
	})

	ctx, timing := createtiming.With(context.Background())
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-snap",
	}, "sb-stage-load", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stages := stageMap(timing)
	requireStages(t, stages,
		"fc_tap_alloc", "fc_rootfs", "fc_tap_ensure", "fc_spawn",
		"fc_verify", "fc_load", "fc_resume", "fc_handshake",
		"fc_post_resume", "fc_driver")
	forbidStages(t, stages, "fc_configure", "fc_warm")
}

// TestCreate_ColdBoot_OmitsVerifyLoadStages: a cold-boot Create (no
// template → OCI rootfs + configureVMM + InstanceStart) records the
// shared stages plus fc_configure, and never fc_verify/fc_load — those
// belong exclusively to the snapshot-load branch.
func TestCreate_ColdBoot_OmitsVerifyLoadStages(t *testing.T) {
	f := newDriverFixture(t)

	ctx, timing := createtiming.With(context.Background())
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}, "sb-stage-cold", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stages := stageMap(timing)
	requireStages(t, stages,
		"fc_tap_alloc", "fc_rootfs", "fc_tap_ensure", "fc_spawn",
		"fc_configure", "fc_resume", "fc_handshake", "fc_post_resume",
		"fc_driver")
	forbidStages(t, stages, "fc_verify", "fc_load", "fc_warm")
}

// TestCreate_WarmHit_RecordsWarmMarker: a warm-pool hit records the
// fc_warm;desc=hit marker (UC-98's split key) plus the resume/handshake
// stages the warm path still runs, and none of the cold-spawn stages it
// skipped.
func TestCreate_WarmHit_RecordsWarmMarker(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)

	ctx, timing := createtiming.With(context.Background())
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-warm",
	}, "sb-stage-warm", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stages := stageMap(timing)
	requireStages(t, stages, "fc_warm", "fc_resume", "fc_handshake", "fc_post_resume", "fc_driver")
	if st := stages["fc_warm"]; st.Desc != "hit" {
		t.Errorf("fc_warm desc = %q, want hit", st.Desc)
	}
	forbidStages(t, stages, "fc_tap_alloc", "fc_rootfs", "fc_tap_ensure", "fc_spawn", "fc_configure", "fc_verify", "fc_load")
}

// TestCreate_ErrorStillRecordsDriverTotal: fc_driver is recorded on the
// failure path too — a failed create's cost is exactly what an operator
// debugging latency needs, and the handler sets Server-Timing on error
// responses as well.
func TestCreate_ErrorStillRecordsDriverTotal(t *testing.T) {
	f := newDriverFixture(t)
	f.rootfs.nextErr = os.ErrPermission

	ctx, timing := createtiming.With(context.Background())
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}, "sb-stage-err", "tok", nil); err == nil {
		t.Fatal("Create succeeded, want rootfs build error")
	}

	stages := stageMap(timing)
	requireStages(t, stages, "fc_tap_alloc", "fc_driver")
	forbidStages(t, stages, "fc_spawn", "fc_resume")
}
