package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
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
	calls int
	err   error
	// ok, when non-nil, is the SandboxRuntimeState the fake returns
	// (with state.SandboxID overwritten by the per-call sandboxID so
	// the service layer's row build sees the right id). Lets one fake
	// type cover both the "driver errored" and "driver succeeded"
	// paths.
	ok *models.SandboxRuntimeState
}

func (r *fireRecordingRuntime) Create(_ context.Context, req models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.calls++
	_ = req
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

func (r *fireRecordingRuntime) Stop(context.Context, string) error             { return nil }
func (r *fireRecordingRuntime) Destroy(context.Context, *models.Sandbox) error { return nil }
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
