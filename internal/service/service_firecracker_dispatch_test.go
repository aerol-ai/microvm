package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// fireRecordingRuntime is a minimal runtime.Runtime test double for the
// firecracker dispatch. It records Create invocations and returns a
// fixed error — that's all the dispatch test needs to verify routing.
//
// We avoid reusing the docker-shaped recordingRuntime in this file
// because (a) it has fields we don't need (admission counters, snapshot
// stubs) and (b) explicitly modeling the firecracker double's contract
// keeps the test description honest about what's being asserted.
type fireRecordingRuntime struct {
	calls         int
	err           error
	lastCreateReq models.CreateSandboxRequest
	// ok, when non-nil, is the SandboxRuntimeState the fake returns
	// (with state.SandboxID overwritten by the per-call sandboxID so
	// the service layer's row build sees the right id). Lets one fake
	// type cover both the "driver errored" and "driver succeeded"
	// paths.
	ok           *models.SandboxRuntimeState
	destroyCalls int
}

func (r *fireRecordingRuntime) Create(_ context.Context, req models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.calls++
	r.lastCreateReq = req
	if r.ok != nil {
		out := *r.ok
		out.SandboxID = sandboxID
		return &out, nil
	}
	return nil, r.err
}

// Every other method on the runtime interface is unreachable from the
// firecracker dispatch path today; stubs keep the type satisfying
// runtime.Runtime so it can be plugged into Service.firecracker.
func (r *fireRecordingRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, errors.New("not used")
}

func (r *fireRecordingRuntime) Stop(context.Context, string) error { return nil }
func (r *fireRecordingRuntime) Destroy(context.Context, *models.Sandbox) error {
	r.destroyCalls++
	return nil
}
func (r *fireRecordingRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}
func (r *fireRecordingRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}
func (r *fireRecordingRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (r *fireRecordingRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (r *fireRecordingRuntime) Ping(context.Context) error                { return nil }
func (r *fireRecordingRuntime) RemoveImage(context.Context, string) error { return nil }
func (r *fireRecordingRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}
func (r *fireRecordingRuntime) ClearNetworkRules(string) error        { return nil }
func (r *fireRecordingRuntime) ApplyNetworkBlockAll(string) error     { return nil }
func (r *fireRecordingRuntime) ApplyNetworkBlockIngress(string) error { return nil }
func (r *fireRecordingRuntime) ClearNetworkBlockIngress(string) error { return nil }
func (r *fireRecordingRuntime) ClearNetworkBlockEgress(string) error  { return nil }

// TestFirecrackerDispatch_NotEnabled covers the operator-facing failure
// mode: SB_ENABLE_FIRECRACKER is off and a sandbox arrives with
// runtime="firecracker". The error must name the env var so the
// operator knows what to flip.
func TestFirecrackerDispatch_NotEnabled(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			Runtime:           models.RuntimeDocker,
			EnableFirecracker: false,
		},
	}
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeFirecracker,
	})
	if err == nil {
		t.Fatal("expected error when firecracker is not enabled")
	}
	if !strings.Contains(err.Error(), "SB_ENABLE_FIRECRACKER=true") {
		t.Errorf("error should name the env var; got %v", err)
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("error should wrap ErrRuntimeNotImplemented; got %v", err)
	}
}

// TestFirecrackerDispatch_EnabledNoDriver covers the daemon-config bug:
// SB_ENABLE_FIRECRACKER=true but main.go failed to call
// SetFirecrackerRuntime (the driver constructor errored out, for
// example). The error must distinguish this from the "not enabled"
// case so the operator can tell config vs. wiring apart.
func TestFirecrackerDispatch_EnabledNoDriver(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			Runtime:           models.RuntimeDocker,
			EnableFirecracker: true,
		},
	}
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeFirecracker,
	})
	if err == nil {
		t.Fatal("expected error when firecracker driver is not registered")
	}
	if !strings.Contains(err.Error(), "driver not registered") {
		t.Errorf("error should say driver not registered; got %v", err)
	}
}

// TestFirecrackerDispatch_RoutesToDriver confirms the happy path of the
// dispatch: when SetFirecrackerRuntime has been called, runtime=
// "firecracker" creates land in the registered driver, not the docker
// path. The driver returns ErrRuntimeNotImplemented today; the test
// asserts the driver was called AT ALL and that the error surfaces.
// When the full Create lands, this test becomes the seam for asserting
// the response shape too.
func TestFirecrackerDispatch_RoutesToDriver(t *testing.T) {
	rt := &fireRecordingRuntime{err: errors.New("phase 1 placeholder")}
	svc := &Service{
		cfg: config.Config{
			Runtime:           models.RuntimeDocker,
			EnableFirecracker: true,
		},
	}
	svc.SetFirecrackerRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeFirecracker,
	})
	if err == nil || !strings.Contains(err.Error(), "phase 1 placeholder") {
		t.Fatalf("expected error from driver, got %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("driver Create calls = %d, want 1", rt.calls)
	}
}

// Note on "docker bypasses registry" coverage: a regression where the
// firecracker registry incorrectly intercepted docker requests would
// surface as failures in the existing TestServiceCreateWithIDAndAccessors
// and TestCreateSandboxValidationAndRollbackPaths suites (those exercise
// runtime="docker"/empty-runtime and assert their own recordingRuntime
// gets called). Adding a dedicated test here would require constructing
// a full mounts+docker+store harness only to assert a no-call counter;
// the existing coverage is the cheaper signal.

// TestFirecrackerDispatch_HappyPathBuildsResponse exercises the
// createFirecrackerSandbox flow end-to-end against a real store /
// caddy stub / no-op mounts manager, with the firecracker driver
// mocked to return a populated SandboxRuntimeState. Asserts that the
// returned CreateSandboxResponse carries the runtime + IP + status
// the driver reported and that a row was persisted.
func TestFirecrackerDispatch_HappyPathBuildsResponse(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fctest/api.sock",
			ContainerIP: "172.16.0.2",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	// The harness's admitter only declares docker as supported; for
	// the firecracker test we don't care about admission shape, so we
	// drop it. (A separate admitter test would assert the placement
	// integration; that's not what this dispatch test covers.)
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)

	resp, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		Runtime:  models.RuntimeFirecracker,
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   1,
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Sandbox.Runtime != models.RuntimeFirecracker {
		t.Errorf("Sandbox.Runtime = %q, want firecracker", resp.Sandbox.Runtime)
	}
	if resp.Sandbox.ContainerIP != "172.16.0.2" {
		t.Errorf("Sandbox.ContainerIP = %q, want 172.16.0.2", resp.Sandbox.ContainerIP)
	}
	if resp.Sandbox.Status != models.SandboxStatusStarted {
		t.Errorf("Sandbox.Status = %q, want started", resp.Sandbox.Status)
	}
	if resp.SSHPrivateKey == "" {
		t.Error("expected SSHPrivateKey to be populated")
	}
	if rt.calls != 1 {
		t.Errorf("driver.Create calls = %d, want 1", rt.calls)
	}
	// Row must be persisted with the firecracker runtime so subsequent
	// inspect / list / destroy land on the right driver.
	stored, err := st.Get(context.Background(), resp.Sandbox.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.Runtime != models.RuntimeFirecracker {
		t.Errorf("persisted runtime = %q, want firecracker", stored.Runtime)
	}
}

func TestFirecrackerDispatch_TemplateIDImpliesRuntimeAndPersistsOptions(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fctpl/api.sock",
			ContainerIP: "172.16.0.3",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)

	resp, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		TemplateID:    " tpl-fast ",
		OverlaySizeGB: 12,
		CPU:           1,
		MemoryMB:      256,
		DiskGB:        1,
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("driver.Create calls = %d, want 1", rt.calls)
	}
	if rt.lastCreateReq.Runtime != models.RuntimeFirecracker {
		t.Fatalf("driver request runtime = %q, want firecracker", rt.lastCreateReq.Runtime)
	}
	if rt.lastCreateReq.TemplateID != "tpl-fast" {
		t.Fatalf("driver request template_id = %q, want tpl-fast", rt.lastCreateReq.TemplateID)
	}
	if resp.Sandbox.Runtime != models.RuntimeFirecracker {
		t.Fatalf("response runtime = %q, want firecracker", resp.Sandbox.Runtime)
	}
	if resp.Sandbox.TemplateID != "tpl-fast" {
		t.Fatalf("response template_id = %q, want tpl-fast", resp.Sandbox.TemplateID)
	}
	if resp.Sandbox.OverlaySizeGB != 12 {
		t.Fatalf("response overlay_size_gb = %d, want 12", resp.Sandbox.OverlaySizeGB)
	}

	stored, err := st.Get(context.Background(), resp.Sandbox.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.Runtime != models.RuntimeFirecracker {
		t.Fatalf("stored runtime = %q, want firecracker", stored.Runtime)
	}
	if stored.TemplateID != "tpl-fast" {
		t.Fatalf("stored template_id = %q, want tpl-fast", stored.TemplateID)
	}
	if stored.OverlaySizeGB != 12 {
		t.Fatalf("stored overlay_size_gb = %d, want 12", stored.OverlaySizeGB)
	}
}

func TestFirecrackerDispatch_TemplateIDRejectsExplicitDockerRuntime(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fctpl/api.sock",
			ContainerIP: "172.16.0.3",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		Runtime:    models.RuntimeDocker,
		TemplateID: "tpl-fast",
	})
	if err == nil {
		t.Fatal("expected template_id + runtime=docker rejection")
	}
	if !strings.Contains(err.Error(), "template_id requires runtime") {
		t.Fatalf("error = %v, want template_id runtime guidance", err)
	}
	if rt.calls != 0 {
		t.Fatalf("driver.Create calls = %d, want 0", rt.calls)
	}
}

func TestFirecrackerDispatch_RegistrySealFailureRollsBackRuntime(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fcreg/api.sock",
			ContainerIP: "172.16.0.8",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.cipher = &secrets.Cipher{}
	svc.SetFirecrackerRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		Runtime:  models.RuntimeFirecracker,
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   1,
		Registry: &models.RegistryAuth{
			Server:   "ghcr.io",
			Username: "alice",
			Password: "top-secret",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "encrypt registry auth") {
		t.Fatalf("CreateSandbox() error = %v, want registry sealing failure", err)
	}
	if rt.calls != 1 {
		t.Fatalf("driver.Create calls = %d, want 1", rt.calls)
	}
	if rt.destroyCalls != 1 {
		t.Fatalf("driver.Destroy calls = %d, want 1 rollback", rt.destroyCalls)
	}
	if rows, err := st.List(context.Background()); err != nil || len(rows) != 0 {
		t.Fatalf("store rows after failed create = %v, err=%v, want empty", rows, err)
	}
}

func TestFirecrackerDispatch_CustomDomainsPersistOnCreate(t *testing.T) {
	ctx := context.Background()
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fc-custom-domains/api.sock",
			ContainerIP: "172.16.0.9",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.test"
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		Runtime:       models.RuntimeFirecracker,
		CustomDomains: []string{"api.external.test", "www.external.test"},
	})
	if err != nil {
		t.Fatalf("CreateSandbox() error = %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("driver.Create calls = %d, want 1", rt.calls)
	}
	if resp.Runtime != models.RuntimeFirecracker {
		t.Fatalf("response runtime = %q, want firecracker", resp.Runtime)
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if len(stored.CustomDomains) != 2 {
		t.Fatalf("stored custom domains = %+v, want 2 rows", stored.CustomDomains)
	}
}

// TestFirecrackerDispatch_RejectsMountsForNow confirms the explicit
// Phase 1 rejection of mounts on the firecracker path. Once virtio-fs
// support lands, this test becomes a positive coverage point.
func TestFirecrackerDispatch_RejectsMountsForNow(t *testing.T) {
	rt := &fireRecordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeFirecracker,
		Mounts:  []models.MountSpec{{Source: "s3://bucket/key", Target: "/data"}},
	})
	if err == nil {
		t.Fatal("expected mounts rejection")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("error should wrap ErrRuntimeNotImplemented; got %v", err)
	}
	if rt.calls != 0 {
		t.Errorf("driver should not be called when mounts are rejected; calls=%d", rt.calls)
	}
}

func TestFirecrackerDispatch_RollsBackWhenCaddyUpsertFails(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fc-route/api.sock",
			ContainerIP: "172.16.0.5",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		HTTPClientTimeout: time.Second,
	})

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeFirecracker,
	})
	if err == nil || !strings.Contains(err.Error(), "patch caddy route failed") {
		t.Fatalf("expected caddy failure, got %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("driver Create calls = %d, want 1", rt.calls)
	}
	if rt.destroyCalls != 1 {
		t.Fatalf("driver Destroy calls = %d, want 1 rollback", rt.destroyCalls)
	}
}

func TestFirecrackerDispatch_RollsBackWhenCustomDomainPersistenceFails(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fc-domains/api.sock",
			ContainerIP: "172.16.0.6",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.test"
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)
	svc.AttachCluster(&customDomainConflictCluster{
		Noop: cluster.NewNoop("self", "http://self", "sandbox.test"),
	})

	resp, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		Runtime:       models.RuntimeFirecracker,
		CustomDomains: []string{"api.example.com", "www.example.com"},
	}, "sb-fc-domains")
	t.Logf("custom-domain create error: %v", err)
	if err == nil {
		t.Fatalf("expected custom-domain conflict, got response %+v", resp)
	}
	if rt.calls != 1 {
		t.Fatalf("driver Create calls = %d, want 1", rt.calls)
	}
	if rt.destroyCalls != 1 {
		t.Fatalf("driver Destroy calls = %d, want 1 rollback", rt.destroyCalls)
	}
	if _, err := st.Get(context.Background(), "sb-fc-domains"); err == nil {
		t.Fatal("failed create should not leave a sandbox row")
	}
}

func TestFirecrackerDispatch_RejectsUnsupportedNetworkControlsForNow(t *testing.T) {
	cases := []struct {
		name string
		req  models.CreateSandboxRequest
	}{
		{
			name: "network block all",
			req: models.CreateSandboxRequest{
				Image:           "alpine:3.20",
				Runtime:         models.RuntimeFirecracker,
				NetworkBlockAll: true,
			},
		},
		{
			name: "network byte limit",
			req: models.CreateSandboxRequest{
				Image:                "alpine:3.20",
				Runtime:              models.RuntimeFirecracker,
				NetworkBytesOutLimit: 1024,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &fireRecordingRuntime{}
			svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.cfg.EnableFirecracker = true
			svc.SetFirecrackerRuntime(rt)

			_, err := svc.CreateSandbox(context.Background(), tc.req)
			if err == nil {
				t.Fatal("expected unsupported network control rejection")
			}
			if !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("error should wrap ErrRuntimeNotImplemented; got %v", err)
			}
			if rt.calls != 0 {
				t.Fatalf("driver should not be called when network controls are rejected; calls=%d", rt.calls)
			}
		})
	}
}

func TestFirecrackerDispatch_AllowsStopLifecycle(t *testing.T) {
	rt := &fireRecordingRuntime{
		ok: &models.SandboxRuntimeState{
			ContainerID: "/var/run/sb/fclife/api.sock",
			ContainerIP: "172.16.0.4",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)

	resp, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeFirecracker,
		Lifecycle: &models.Lifecycle{
			StopIfIdleFor: time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if resp.Sandbox.Lifecycle.StopIfIdleFor != time.Minute {
		t.Fatalf("lifecycle = %+v, want stop timer persisted", resp.Sandbox.Lifecycle)
	}
	if rt.calls != 1 {
		t.Fatalf("driver calls = %d, want 1", rt.calls)
	}
}

func TestFirecrackerLifecycle_StartStopAndDestroyRouteToFirecracker(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	fireRT := &recordingRuntime{
		startState: &models.SandboxRuntimeState{
			SandboxID:   "sb-fc-start",
			ContainerID: "/var/run/sb/sb-fc-start/new.sock",
			ContainerIP: "172.16.0.10",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(fireRT)

	starting := firecrackerSandboxForTest("sb-fc-start")
	starting.Status = models.SandboxStatusStopped
	if err := st.Create(ctx, starting); err != nil {
		t.Fatalf("Create start sandbox: %v", err)
	}
	started, err := svc.StartSandbox(ctx, starting.ID)
	if err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if started.Status != models.SandboxStatusStarted || started.ContainerIP != "172.16.0.10" {
		t.Fatalf("started = %+v, want firecracker started state", started)
	}
	if len(fireRT.startRefs) != 1 || fireRT.startRefs[0] != starting.ID {
		t.Fatalf("firecracker start refs = %v, want [%s]", fireRT.startRefs, starting.ID)
	}
	if len(dockerRT.startRefs) != 0 {
		t.Fatalf("docker start refs = %v, want none", dockerRT.startRefs)
	}

	stopping := firecrackerSandboxForTest("sb-fc-stop")
	if err := st.Create(ctx, stopping); err != nil {
		t.Fatalf("Create stop sandbox: %v", err)
	}
	stopped, err := svc.StopSandbox(ctx, stopping.ID)
	if err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	if stopped.Status != models.SandboxStatusStopped || stopped.ContainerID != "" || stopped.ContainerIP != "" {
		t.Fatalf("stopped = %+v, want stopped with runtime identity cleared", stopped)
	}
	if len(fireRT.stopRefs) != 1 || fireRT.stopRefs[0] != stopping.ID {
		t.Fatalf("firecracker stop refs = %v, want [%s]", fireRT.stopRefs, stopping.ID)
	}
	if len(dockerRT.stopRefs) != 0 {
		t.Fatalf("docker stop refs = %v, want none", dockerRT.stopRefs)
	}

	destroying := firecrackerSandboxForTest("sb-fc-destroy")
	if err := st.Create(ctx, destroying); err != nil {
		t.Fatalf("Create destroy sandbox: %v", err)
	}
	if err := svc.DestroySandbox(ctx, destroying.ID); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	if len(fireRT.destroyIDs) != 1 || fireRT.destroyIDs[0] != destroying.ID {
		t.Fatalf("firecracker destroy IDs = %v, want [%s]", fireRT.destroyIDs, destroying.ID)
	}
	if len(dockerRT.destroyIDs) != 0 {
		t.Fatalf("docker destroy IDs = %v, want none", dockerRT.destroyIDs)
	}
	if _, err := st.Get(ctx, destroying.ID); err == nil {
		t.Fatalf("destroyed sandbox row still exists")
	}
}

func TestFirecrackerUpdateLifecycleAllowsStopTimers(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(&recordingRuntime{})

	sb := firecrackerSandboxForTest("sb-fc-lifecycle")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	updated, err := svc.UpdateLifecycle(ctx, sb.ID, models.Lifecycle{StopAtAge: time.Hour})
	if err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}
	if updated.Lifecycle.StopAtAge != time.Hour {
		t.Fatalf("lifecycle = %+v, want stop_at_age persisted", updated.Lifecycle)
	}
}

func TestFirecrackerSetNetworkLimitsRejectsPositiveLimitsForNow(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(&recordingRuntime{})

	sb := firecrackerSandboxForTest("sb-fc-netlimit")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	_, err := svc.SetNetworkLimits(ctx, sb.ID, 1, 0)
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("SetNetworkLimits error = %v, want ErrRuntimeNotImplemented", err)
	}
}

func TestFirecrackerReconcile_MissingRuntimeStateDestroysViaFirecracker(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	fireRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	svc, st, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(fireRT)

	sb := firecrackerSandboxForTest("sb-fc-missing")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(fireRT.destroyIDs) != 1 || fireRT.destroyIDs[0] != sb.ID {
		t.Fatalf("firecracker destroy IDs = %v, want [%s]", fireRT.destroyIDs, sb.ID)
	}
	if len(dockerRT.destroyIDs) != 0 {
		t.Fatalf("docker destroy IDs = %v, want none", dockerRT.destroyIDs)
	}
	if _, err := st.Get(ctx, sb.ID); err == nil {
		t.Fatalf("reconciled missing sandbox row still exists")
	}
}

func TestFirecrackerReconcile_StoppedMissingRuntimeStateIsKept(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	fireRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	svc, st, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(fireRT)

	sb := firecrackerSandboxForTest("sb-fc-stopped-missing")
	sb.Status = models.SandboxStatusStopped
	sb.ContainerID = ""
	sb.ContainerIP = ""
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(fireRT.destroyIDs) != 0 {
		t.Fatalf("firecracker destroy IDs = %v, want none for stopped snapshot row", fireRT.destroyIDs)
	}
	if _, err := st.Get(ctx, sb.ID); err != nil {
		t.Fatalf("stopped firecracker row was not preserved: %v", err)
	}
}

type snapshotRecordingRuntime struct {
	recordingRuntime
	snapshotRefs  []string
	snapshotNames []string
}

func (r *snapshotRecordingRuntime) CreateSnapshot(_ context.Context, ref, name string) (string, error) {
	r.snapshotRefs = append(r.snapshotRefs, ref)
	r.snapshotNames = append(r.snapshotNames, name)
	return "image-" + name, nil
}

func TestFirecrackerSnapshot_RoutesCommitToFirecrackerRuntime(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	fireRT := &snapshotRecordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(fireRT)

	sb := firecrackerSandboxForTest("sb-fc-snapshot")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	snapshot, created, err := svc.CreateSnapshotWithOwnership(ctx, sb.ID, models.CreateSandboxSnapshotRequest{Name: "e2b/fc:default"})
	if err != nil {
		t.Fatalf("CreateSnapshotWithOwnership: %v", err)
	}
	if !created {
		t.Fatal("snapshot should be newly created")
	}
	if snapshot.SourceSandboxID != sb.ID {
		t.Fatalf("snapshot source = %q, want %q", snapshot.SourceSandboxID, sb.ID)
	}
	if len(fireRT.snapshotRefs) != 1 || fireRT.snapshotRefs[0] != sb.ID {
		t.Fatalf("firecracker snapshot refs = %v, want [%s]", fireRT.snapshotRefs, sb.ID)
	}
	if len(fireRT.snapshotNames) != 1 || fireRT.snapshotNames[0] != "e2b/fc:default" {
		t.Fatalf("firecracker snapshot names = %v, want [e2b/fc:default]", fireRT.snapshotNames)
	}
}

type resizeRecordingRuntime struct {
	recordingRuntime
	resizeRefs []string
	resizes    []models.ResizeSandboxRequest
}

func (r *resizeRecordingRuntime) Resize(_ context.Context, ref string, req models.ResizeSandboxRequest) error {
	r.resizeRefs = append(r.resizeRefs, ref)
	r.resizes = append(r.resizes, req)
	return nil
}

func TestFirecrackerResize_RoutesToFirecrackerRuntime(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	fireRT := &resizeRecordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(fireRT)

	sb := firecrackerSandboxForTest("sb-fc-resize")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	got, err := svc.ResizeSandbox(ctx, sb.ID, models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512, DiskGB: 2})
	if err != nil {
		t.Fatalf("ResizeSandbox: %v", err)
	}
	if len(fireRT.resizeRefs) != 1 || fireRT.resizeRefs[0] != sb.ID {
		t.Fatalf("firecracker resize refs = %v, want [%s]", fireRT.resizeRefs, sb.ID)
	}
	if got.CPU != 2 || got.MemoryMB != 512 || got.DiskGB != 2 {
		t.Fatalf("resized sandbox resources = cpu:%v mem:%d disk:%d, want 2/512/2", got.CPU, got.MemoryMB, got.DiskGB)
	}
}

func firecrackerSandboxForTest(id string) *models.Sandbox {
	now := time.Now().UTC()
	return &models.Sandbox{
		ID:              id,
		Image:           "alpine:3.20",
		Status:          models.SandboxStatusStarted,
		ContainerID:     "/var/run/sb/" + id + "/api.sock",
		ContainerIP:     "172.16.0.9",
		CPU:             1,
		MemoryMB:        256,
		DiskGB:          1,
		OSUser:          "root",
		Env:             map[string]string{},
		ToolboxEnabled:  true,
		ToolboxToken:    "token",
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
		Runtime:         models.RuntimeFirecracker,
		TemplateID:      "tpl-fast",
		OverlaySizeGB:   4,
		NetworkBlockAll: false,
	}
}
