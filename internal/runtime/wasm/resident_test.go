package wasm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// residentTestDriver builds a driver wired for both the per-sandbox and the
// resident-host paths, sharing one recording client, so a test can assert which
// path a create took.
func residentTestDriver(t *testing.T, enabled bool) (*Driver, *fakeSupervisor, *fakeSupervisor, *recordingWorkerClient) {
	t.Helper()
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	runDir := filepath.Join(dir, "run")

	perSandbox := &fakeSupervisor{}
	resident := &fakeSupervisor{}
	client := &recordingWorkerClient{}
	d := New(Config{RunDir: runDir, ModulesDir: dir, ResidentHostEnabled: enabled}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(perSandbox)
	d.SetResidentHostSupervisor(resident)
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	return d, perSandbox, resident, client
}

// TestCreateRoutesToResidentHost is the Phase 3b routing guard: with the flag on
// and a non-public create, the sandbox instantiates into the shared resident
// host (resident supervisor ensured, per-sandbox supervisor untouched), and
// Destroy removes just the instance without killing the shared host.
func TestCreateRoutesToResidentHost(t *testing.T) {
	d, perSandbox, resident, client := residentTestDriver(t, true)

	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-res", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if resident.ensureCalls != 1 {
		t.Fatalf("resident ensure calls = %d, want 1", resident.ensureCalls)
	}
	if perSandbox.ensureCalls != 0 {
		t.Fatalf("per-sandbox ensure calls = %d, want 0 (routed to resident host)", perSandbox.ensureCalls)
	}
	if client.loadPath == "" {
		t.Fatal("expected host-level LoadModule on the resident path")
	}
	if len(client.instantiateCaps) != 1 {
		t.Fatalf("Instantiate calls = %d, want 1", len(client.instantiateCaps))
	}
	inst, err := d.instance("sb-res")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if !inst.fromResidentHost {
		t.Fatal("instance not marked fromResidentHost")
	}
	if inst.workerKey != residentBucketID("deadbeef", 0) {
		t.Fatalf("workerKey=%q, want bucket %q", inst.workerKey, residentBucketID("deadbeef", 0))
	}

	// Destroy must StopInstance (per-sandbox), NOT kill the shared host.
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-res"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !client.stopped {
		t.Fatal("Destroy did not StopInstance on the resident host")
	}
	if resident.stopCalls != 0 {
		t.Fatalf("resident supervisor Stop called %d times — must never kill the shared host", resident.stopCalls)
	}
	if perSandbox.stopCalls != 0 {
		t.Fatalf("per-sandbox supervisor Stop called %d times for a resident instance", perSandbox.stopCalls)
	}
}

// TestCreateResidentRetryIsIdempotent guards pr-review.md §1: re-creating the
// same sandboxID on the resident path drops the prior instance first
// (StopInstance) so it does not trip the engine's duplicate-instance guard.
func TestCreateResidentRetryIsIdempotent(t *testing.T) {
	d, _, _, client := residentTestDriver(t, true)
	req := models.CreateSandboxRequest{Image: "demo.wasm"}
	if _, err := d.Create(context.Background(), req, "sb-retry", "tok", nil); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	client.stopped = false
	if _, err := d.Create(context.Background(), req, "sb-retry", "tok", nil); err != nil {
		t.Fatalf("Create #2 (retry): %v", err)
	}
	if !client.stopped {
		t.Fatal("retry did not StopInstance the prior instance before re-instantiating")
	}
	if len(client.instantiateCaps) != 2 {
		t.Fatalf("Instantiate calls = %d, want 2 (one per create)", len(client.instantiateCaps))
	}
}

// TestPrewarmResidentHostsSkipsFirstCreateBringup guards the boot-time pre-warm:
// after PrewarmResidentHosts brings up + compiles a module's host, the first
// create for that module must NOT re-spawn or re-compile — it's a cached
// (ready) bucket, so the create is instantiate-only. This is what moves the
// one-time compile off the create path (the v0.7.10 tail fix).
func TestPrewarmResidentHostsSkipsFirstCreateBringup(t *testing.T) {
	d, _, resident, client := residentTestDriver(t, true)

	d.PrewarmResidentHosts(context.Background(), []string{"demo.wasm"})
	if resident.ensureCalls != 1 {
		t.Fatalf("prewarm resident ensure calls = %d, want 1", resident.ensureCalls)
	}
	if client.loadPath == "" {
		t.Fatal("prewarm did not LoadModule (compile) the resident host")
	}

	// First create for the same (digest, memoryMB) bucket must reuse the
	// pre-warmed host: no additional Ensure, no additional LoadModule.
	client.loadPath = ""
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-pw", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resident.ensureCalls != 1 {
		t.Fatalf("create re-brought-up the host: resident ensure calls = %d, want 1 (reuse pre-warmed)", resident.ensureCalls)
	}
	if client.loadPath != "" {
		t.Fatalf("create re-compiled (LoadModule) despite pre-warm: loadPath=%q", client.loadPath)
	}
	inst, err := d.instance("sb-pw")
	if err != nil || !inst.fromResidentHost {
		t.Fatalf("create did not use the resident host (inst=%v err=%v)", inst, err)
	}
}

// TestPrewarmResidentHostsDisabledNoop confirms pre-warm does nothing when the
// flag is off (no resident supervisor consulted).
func TestPrewarmResidentHostsDisabledNoop(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, false)
	d.PrewarmResidentHosts(context.Background(), []string{"demo.wasm"})
	if resident.ensureCalls != 0 {
		t.Fatalf("prewarm ran with flag off: resident ensure calls = %d, want 0", resident.ensureCalls)
	}
}

// TestCreateResidentDisabledUsesColdPath confirms the flag-off default is
// untouched: creates take the per-sandbox worker path.
func TestCreateResidentDisabledUsesColdPath(t *testing.T) {
	d, perSandbox, resident, _ := residentTestDriver(t, false)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-cold", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if perSandbox.ensureCalls != 1 {
		t.Fatalf("per-sandbox ensure calls = %d, want 1 with resident disabled", perSandbox.ensureCalls)
	}
	if resident.ensureCalls != 0 {
		t.Fatalf("resident ensure calls = %d, want 0 with flag off", resident.ensureCalls)
	}
	inst, err := d.instance("sb-cold")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if inst.fromResidentHost {
		t.Fatal("instance wrongly marked fromResidentHost with flag off")
	}
}

// TestCreatePublicExposeUsesColdPath confirms a public-intent create bypasses
// the resident host (which cannot serve wasip1 listeners) even when enabled.
func TestCreatePublicExposeUsesColdPath(t *testing.T) {
	d, perSandbox, resident, _ := residentTestDriver(t, true)
	pub := true
	req := models.CreateSandboxRequest{Image: "demo.wasm", AllowPublicTraffic: &pub}
	if _, err := d.Create(context.Background(), req, "sb-pub", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resident.ensureCalls != 0 {
		t.Fatalf("resident ensure calls = %d, want 0 for a public-expose create", resident.ensureCalls)
	}
	if perSandbox.ensureCalls != 1 {
		t.Fatalf("per-sandbox ensure calls = %d, want 1 (cold path for public expose)", perSandbox.ensureCalls)
	}
	inst, err := d.instance("sb-pub")
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if inst.fromResidentHost {
		t.Fatal("public-expose create wrongly routed to resident host")
	}
}
