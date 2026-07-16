package wasm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
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
	if inst.workerKey != residentBucketID("", "deadbeef", 0) {
		t.Fatalf("workerKey=%q, want bucket %q", inst.workerKey, residentBucketID("", "deadbeef", 0))
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
	// Finding A: an idempotent retry must not inflate the host live count — the
	// sandbox occupies exactly one slot no matter how many times create is retried.
	var totalLive int
	d.residentMu.Lock()
	for _, b := range d.residentBuckets {
		b.mu.Lock()
		for _, h := range b.hosts {
			totalLive += h.live
		}
		b.mu.Unlock()
	}
	d.residentMu.Unlock()
	if totalLive != 1 {
		t.Fatalf("host live count = %d after idempotent retry, want 1 (retry leaked a slot)", totalLive)
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

// TestResidentBucketIDIncludesOwnerRef guards D7: a non-operator OwnerRef gets
// its own bucket so SaaS tenants never co-locate; empty/operator stays global.
func TestResidentBucketIDIncludesOwnerRef(t *testing.T) {
	global := residentBucketID("", "deadbeef", 256)
	tenant := residentBucketID("acme", "deadbeef", 256)
	if global == tenant {
		t.Fatalf("owner bucket collided with global: %q", global)
	}
	if residentBucketID("acme", "deadbeef", 256) != tenant {
		t.Fatal("owner bucket not stable")
	}
	other := residentBucketID("globex", "deadbeef", 256)
	if other == tenant {
		t.Fatal("different owners share a bucket")
	}
}

func TestCreateWithOwnerRefUsesDistinctResidentHost(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, true)
	opCtx := context.Background()
	userCtx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})

	if _, err := d.Create(opCtx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-op", "tok", nil); err != nil {
		t.Fatalf("operator Create: %v", err)
	}
	if _, err := d.Create(userCtx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-user", "tok", nil); err != nil {
		t.Fatalf("user Create: %v", err)
	}
	if resident.ensureCalls != 2 {
		t.Fatalf("resident ensure calls = %d, want 2 (distinct owner buckets)", resident.ensureCalls)
	}
	opInst, _ := d.instance("sb-op")
	userInst, _ := d.instance("sb-user")
	if opInst.workerKey == userInst.workerKey {
		t.Fatalf("owner create reused operator bucket key %q", opInst.workerKey)
	}
}

func TestResidentMaxInstancesSpillsToSecondHost(t *testing.T) {
	d, _, resident, _ := residentTestDriver(t, true)
	d.cfg.ResidentHostMaxInstances = 1

	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-1", "tok", nil); err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-2", "tok", nil); err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	if resident.ensureCalls != 2 {
		t.Fatalf("resident ensure calls = %d, want 2 (spill to second host)", resident.ensureCalls)
	}
	a, _ := d.instance("sb-1")
	b, _ := d.instance("sb-2")
	if a.socketPath == b.socketPath {
		t.Fatalf("both instances on same socket %q under MaxInstances=1", a.socketPath)
	}
}

func TestInspectMarksDeadResidentHostStopped(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	client := &unloadedWorkerClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	d.mu.Lock()
	d.byID["sb-dead"] = &sandboxInstance{
		sandboxID:        "sb-dead",
		socketPath:       "/tmp/fake-resident.sock",
		fromResidentHost: true,
		status:           models.SandboxStatusStarted,
	}
	d.mu.Unlock()

	state, err := d.Inspect(context.Background(), "sb-dead")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStopped {
		t.Fatalf("state = %+v, want stopped after resident host gone", state)
	}
}

func TestSetNetworkBlocksReachesResidentHost(t *testing.T) {
	d, _, _, client := residentTestDriver(t, true)
	netClient := &networkRecordingClient{recordingWorkerClient: *client}
	d.SetWorkerClientFactory(func(string) WorkerClient { return netClient })

	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-blocks", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d.SetNetworkBlocks("sb-blocks", false, true)
	if !netClient.blocksSet {
		t.Fatal("SetNetworkBlocks did not reach the resident host socket")
	}
}

type networkRecordingClient struct {
	recordingWorkerClient
	blocksSet bool
}

func (c *networkRecordingClient) SetNetworkBlocks(string, bool, bool) error {
	c.blocksSet = true
	return nil
}

// totalResidentLive sums the live slot count across every resident host so tests
// can assert MAX_INSTANCES accounting (Findings A / P0-2 / P1-2).
func totalResidentLive(d *Driver) int {
	var total int
	d.residentMu.Lock()
	buckets := d.residentBuckets
	d.residentMu.Unlock()
	for _, b := range buckets {
		b.mu.Lock()
		for _, h := range b.hosts {
			total += h.live
		}
		b.mu.Unlock()
	}
	return total
}

// TestResidentBucketIDNoCollision proves the hashed bucket id (P0-1) does not
// co-locate distinct owners/modules that the old truncate+sanitize scheme would
// have collided into one shared host process.
func TestResidentBucketIDNoCollision(t *testing.T) {
	// Long owners sharing a >24-char prefix (old code truncated to 24).
	if residentBucketID("customer-aaaaaaaaaaaaaaaaaaaaaaaaaaaa-1", "sha256:deadbeef", 256) ==
		residentBucketID("customer-aaaaaaaaaaaaaaaaaaaaaaaaaaaa-2", "sha256:deadbeef", 256) {
		t.Fatal("distinct long owners collided to one bucket")
	}
	// Sanitization collision: a/b vs a-b (old code mapped '/' -> '-').
	if residentBucketID("a/b", "sha256:deadbeef", 256) == residentBucketID("a-b", "sha256:deadbeef", 256) {
		t.Fatal("owners a/b and a-b collided")
	}
	// Modules sharing a 16-char digest prefix (old code truncated to 16).
	if residentBucketID("", "sha256:0000000000000000aaaa", 256) ==
		residentBucketID("", "sha256:0000000000000000bbbb", 256) {
		t.Fatal("modules sharing a 16-char digest prefix collided")
	}
	// Operator/empty owner must not collide with any real owner.
	if residentBucketID("", "sha256:deadbeef", 256) == residentBucketID("owner1", "sha256:deadbeef", 256) {
		t.Fatal("operator (empty owner) and owner1 collided")
	}
}

// TestResidentRetryNoOrphanOrLeak proves an idempotent retry under MAX_INSTANCES
// tears down the prior instance on its own host and keeps the live count at 1 —
// no orphaned instance on a spilled host, no slot leak (P0-2 + Finding A).
func TestResidentRetryNoOrphanOrLeak(t *testing.T) {
	d, _, _, client := residentTestDriver(t, true)
	d.cfg.ResidentHostMaxInstances = 1
	req := models.CreateSandboxRequest{Image: "demo.wasm"}
	if _, err := d.Create(context.Background(), req, "sb-x", "tok", nil); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	client.stopped = false
	if _, err := d.Create(context.Background(), req, "sb-x", "tok", nil); err != nil {
		t.Fatalf("Create #2 (retry): %v", err)
	}
	if !client.stopped {
		t.Fatal("retry did not StopInstance the prior instance on its host")
	}
	if got := totalResidentLive(d); got != 1 {
		t.Fatalf("total resident live = %d after idempotent retry under MAX=1, want 1", got)
	}
}

// TestPrewarmResidentHostDoesNotReserveSlot proves boot pre-warm brings up +
// compiles a host without holding a live slot (P1-2) — otherwise every prewarmed
// module would permanently inflate the bucket's occupancy.
func TestPrewarmResidentHostDoesNotReserveSlot(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.PrewarmResidentHosts(context.Background(), []string{"demo.wasm"})
	if got := totalResidentLive(d); got != 0 {
		t.Fatalf("prewarm reserved %d live slots, want 0", got)
	}
}
