package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type wasmRecordingRuntime struct {
	calls         int
	err           error
	lastCreateReq models.CreateSandboxRequest

	createCalls   int
	createState   *models.SandboxRuntimeState
	createErr     error
	lastSandboxID string
	lastToken     string
	lastBinds     []mounts.ContainerBind
	destroyCalls  int
	managed       map[string]*models.SandboxRuntimeState
}

func (r *wasmRecordingRuntime) Create(_ context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.calls++
	r.createCalls++
	r.lastCreateReq = req
	r.lastSandboxID = id
	r.lastToken = token
	r.lastBinds = binds

	if r.err != nil {
		return nil, r.err
	}
	if r.createErr != nil {
		return nil, r.createErr
	}
	if r.createState != nil {
		state := *r.createState
		return &state, nil
	}
	return &models.SandboxRuntimeState{
		SandboxID:    id,
		ContainerID:  "wasm-" + id,
		ContainerIP:  "10.0.0.100",
		Status:       models.SandboxStatusStarted,
		ModuleDigest: "sha256:fake",
	}, nil
}

func (r *wasmRecordingRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, errors.New("not used")
}
func (r *wasmRecordingRuntime) Stop(context.Context, string) error { return nil }
func (r *wasmRecordingRuntime) Destroy(context.Context, *models.Sandbox) error {
	r.destroyCalls++
	return nil
}
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
	out := make(map[string]*models.SandboxRuntimeState, len(r.managed))
	for id, state := range r.managed {
		copy := *state
		out[id] = &copy
	}
	return out, nil
}
func (r *wasmRecordingRuntime) Ping(context.Context) error                { return nil }
func (r *wasmRecordingRuntime) RemoveImage(context.Context, string) error { return nil }
func (r *wasmRecordingRuntime) RuntimeHealth(context.Context) string      { return "ok" }

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

func TestWasmDispatch_OmittedMemoryUsesWasmDefault(t *testing.T) {
	rt := &wasmRecordingRuntime{err: errors.New("driver stub")}
	svc := &Service{cfg: config.Config{
		Runtime:             models.RuntimeDocker,
		EnableWasm:          true,
		WasmDefaultMemoryMB: 256,
	}}
	svc.SetWasmRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "demo.wasm",
		Runtime: models.RuntimeWasm,
	})
	if err == nil || !strings.Contains(err.Error(), "driver stub") {
		t.Fatalf("expected driver error, got %v", err)
	}
	if rt.lastCreateReq.MemoryMB != 256 {
		t.Fatalf("memory_mb = %d, want wasm default 256", rt.lastCreateReq.MemoryMB)
	}
}

func TestWasmDispatch_ModuleRefWithoutImage(t *testing.T) {
	rt := &wasmRecordingRuntime{err: errors.New("driver stub")}
	svc := &Service{cfg: config.Config{Runtime: models.RuntimeDocker, EnableWasm: true}}
	svc.SetWasmRuntime(rt)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		ModuleRef: "hello.wasm",
		Runtime:   models.RuntimeWasm,
	})
	if err == nil || !strings.Contains(err.Error(), "driver stub") {
		t.Fatalf("expected driver error, got %v", err)
	}
	if rt.lastCreateReq.ModuleRef != "hello.wasm" {
		t.Fatalf("module_ref = %q", rt.lastCreateReq.ModuleRef)
	}
	if rt.lastCreateReq.Image != "hello.wasm" {
		t.Fatalf("image normalized to %q", rt.lastCreateReq.Image)
	}
}

func TestWasmDispatch_RequiresMountManagerWhenMountsSet(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableWasm: true}}
	svc.SetWasmRuntime(&wasmRecordingRuntime{})
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:   "demo.wasm",
		Runtime: models.RuntimeWasm,
		Mounts:  []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b/k", Target: "/data"}},
	})
	if err == nil || !strings.Contains(err.Error(), "mount manager not configured") {
		t.Fatalf("expected mount manager error, got %v", err)
	}
}

func TestWasmCreateSandboxSuccess(t *testing.T) {
	ctx := context.Background()
	rt := &wasmRecordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)

	req := models.CreateSandboxRequest{
		ModuleRef: "hello.wasm",
		Runtime:   models.RuntimeWasm,
		Name:      "test-wasm",
	}

	resp, err := svc.CreateSandboxWithID(ctx, req, "sb-wasm-success")
	if err != nil {
		t.Fatalf("CreateSandboxWithID() error: %v", err)
	}

	if rt.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", rt.createCalls)
	}

	sandbox, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("failed to retrieve sandbox from store: %v", err)
	}
	if sandbox.Runtime != models.RuntimeWasm {
		t.Fatalf("expected sandbox runtime to be wasm, got %s", sandbox.Runtime)
	}
	if sandbox.ModuleDigest != "sha256:fake" {
		t.Fatalf("expected module digest sha256:fake, got %s", sandbox.ModuleDigest)
	}
}

func TestWasmCreateSandboxValidation(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true

	cases := []struct {
		name string
		req  models.CreateSandboxRequest
		want string
	}{
		{
			name: "gpus not supported",
			req:  models.CreateSandboxRequest{ModuleRef: "a", Runtime: models.RuntimeWasm, GPUs: &models.GPURequest{}},
			want: "does not yet support GPUs",
		},
		{
			name: "negative network limits",
			req:  models.CreateSandboxRequest{ModuleRef: "a", Runtime: models.RuntimeWasm, NetworkBytesInLimit: -1},
			want: "network byte limits must be >= 0",
		},
		{
			name: "template id not supported",
			req:  models.CreateSandboxRequest{ModuleRef: "a", Runtime: models.RuntimeWasm, TemplateID: "temp1"},
			want: "does not support template_id",
		},
		{
			name: "missing module ref",
			req:  models.CreateSandboxRequest{Runtime: models.RuntimeWasm},
			want: "module_ref or image is required",
		},
		{
			name: "invalid lifecycle",
			req:  models.CreateSandboxRequest{ModuleRef: "a", Runtime: models.RuntimeWasm, Lifecycle: &models.Lifecycle{StopIfIdleFor: -time.Second}},
			want: "invalid lifecycle",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.createWasmSandbox(ctx, tc.req, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestWasmCreateSandboxStoreFail(t *testing.T) {
	ctx := context.Background()
	rt := &wasmRecordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)

	req := models.CreateSandboxRequest{
		ModuleRef: "hello.wasm",
		Runtime:   models.RuntimeWasm,
		Name:      "conflict-name",
	}

	_, err := svc.CreateSandboxWithID(ctx, req, "first")
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	// This should fail due to unique constraint on Name
	_, err = svc.CreateSandboxWithID(ctx, req, "second")
	if err == nil || !strings.Contains(err.Error(), "sandbox name already in use") {
		t.Fatalf("expected sandbox name conflict error, got %v", err)
	}

	if rt.destroyCalls != 1 {
		t.Fatalf("expected 1 destroy call due to rollback, got %d", rt.destroyCalls)
	}
}

func TestWasmCreateSandboxMaxInstances(t *testing.T) {
	ctx := context.Background()
	rt := &wasmRecordingRuntime{
		managed: map[string]*models.SandboxRuntimeState{
			"sb-1": {},
			"sb-2": {},
		},
	}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.WasmMaxInstances = 2
	svc.SetWasmRuntime(rt)

	req := models.CreateSandboxRequest{
		ModuleRef: "hello.wasm",
		Runtime:   models.RuntimeWasm,
	}

	_, err := svc.CreateSandboxWithID(ctx, req, "sb-wasm-max")
	if err == nil || !strings.Contains(err.Error(), "wasm instance cap") {
		t.Fatalf("expected wasm instance cap error, got %v", err)
	}
}
