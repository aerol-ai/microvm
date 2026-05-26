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
}

func (r *fireRecordingRuntime) Create(_ context.Context, req models.CreateSandboxRequest, _, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.calls++
	// Confirm the dispatch is passing the request through unchanged.
	// (The service layer normalises req.Runtime to chosenRuntime before
	// dispatch; we don't re-assert that here because the docker tests
	// already cover it.)
	_ = req
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
