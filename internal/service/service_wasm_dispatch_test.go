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

type wasmRecordingRuntime struct {
	calls         int
	err           error
	lastCreateReq models.CreateSandboxRequest
}

func (r *wasmRecordingRuntime) Create(_ context.Context, req models.CreateSandboxRequest, _, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.calls++
	r.lastCreateReq = req
	return nil, r.err
}

func (r *wasmRecordingRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, errors.New("not used")
}
func (r *wasmRecordingRuntime) Stop(context.Context, string) error             { return nil }
func (r *wasmRecordingRuntime) Destroy(context.Context, *models.Sandbox) error { return nil }
func (r *wasmRecordingRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}
func (r *wasmRecordingRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}
func (r *wasmRecordingRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (r *wasmRecordingRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return nil, nil
}
func (r *wasmRecordingRuntime) Ping(context.Context) error                { return nil }
func (r *wasmRecordingRuntime) RemoveImage(context.Context, string) error { return nil }

func TestWasmDispatch_NotEnabled(t *testing.T) {
	svc := &Service{cfg: config.Config{Runtime: models.RuntimeDocker, EnableWasm: false}}
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "demo.wasm",
		Runtime: models.RuntimeWasm,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "SB_ENABLE_WASM=true") {
		t.Fatalf("error should name env var: %v", err)
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("expected ErrRuntimeNotImplemented: %v", err)
	}
}

func TestWasmDispatch_EnabledNoDriver(t *testing.T) {
	svc := &Service{cfg: config.Config{Runtime: models.RuntimeDocker, EnableWasm: true}}
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "demo.wasm",
		Runtime: models.RuntimeWasm,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "driver not registered") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWasmDispatch_RoutesToDriver(t *testing.T) {
	rt := &wasmRecordingRuntime{err: errors.New("phase 1 placeholder")}
	svc := &Service{cfg: config.Config{Runtime: models.RuntimeDocker, EnableWasm: true}}
	svc.SetWasmRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "demo.wasm",
		Runtime: models.RuntimeWasm,
	})
	if err == nil || !strings.Contains(err.Error(), "phase 1 placeholder") {
		t.Fatalf("expected driver error, got %v", err)
	}
	if rt.calls != 1 {
		t.Fatalf("expected one driver Create call, got %d", rt.calls)
	}
	if rt.lastCreateReq.Runtime != models.RuntimeWasm {
		t.Fatalf("runtime = %q", rt.lastCreateReq.Runtime)
	}
}

func TestWasmDispatch_RejectsMounts(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableWasm: true}}
	svc.SetWasmRuntime(&wasmRecordingRuntime{})
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "demo.wasm",
		Runtime: models.RuntimeWasm,
		Mounts:  []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b/k", Target: "/data"}},
	})
	if err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("expected mount rejection, got %v", err)
	}
}
