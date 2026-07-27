package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeIsolateToolboxHost struct {
	*recordingRuntime
	served int
}

func (f *fakeIsolateToolboxHost) ServeToolbox(_ context.Context, _ string, _ string, w http.ResponseWriter, _ *http.Request) {
	f.served++
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("isolate-toolbox"))
}

func TestServeToolboxReverseProxyIsolateAndSSHForwardLog(t *testing.T) {
	ctx := context.Background()
	host := &fakeIsolateToolboxHost{recordingRuntime: &recordingRuntime{}}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(host)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-iso-tb", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted,
		ToolboxToken: "tok", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/files", nil)
	req.Header.Set("X-Aerol-Ssh-Forward-Id", "fwd-1")
	rec := httptest.NewRecorder()
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-iso-tb", rec, req, "/files"); err != nil {
		t.Fatalf("ServeToolboxReverseProxy: %v", err)
	}
	if rec.Body.String() != "isolate-toolbox" || host.served != 1 {
		t.Fatalf("body=%q served=%d", rec.Body.String(), host.served)
	}

	svc.SetIsolateRuntime(&recordingRuntime{})
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-iso-tb", httptest.NewRecorder(), req, "/x"); err == nil || !strings.Contains(err.Error(), "toolbox host") {
		t.Fatalf("err = %v", err)
	}
	svc.isolate = nil
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-iso-tb", httptest.NewRecorder(), req, "/x"); err == nil || !strings.Contains(err.Error(), "driver not registered") {
		t.Fatalf("err = %v", err)
	}
}

func TestHealthIsolateStatusBranches(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	// Server-only role is not a worker → isolate health is skipped.
	svc.cfg.NodeRole = config.NodeRoleServer
	h, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !strings.Contains(h.Isolate, "skipped") {
		t.Fatalf("isolate status = %q, want skipped", h.Isolate)
	}

	svc.cfg.NodeRole = config.NodeRoleWorker
	svc.isolate = nil
	h, err = svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Status != "degraded" || !strings.Contains(h.Isolate, "not registered") {
		t.Fatalf("health = %+v", h)
	}

	svc.SetIsolateRuntime(&recordingRuntime{pingErr: errors.New("workerd missing")})
	h, err = svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Status != "degraded" || !strings.Contains(h.Isolate, "workerd missing") {
		t.Fatalf("health = %+v", h)
	}
	svc.SetIsolateRuntime(&recordingRuntime{})
	h, err = svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Isolate != "ok" {
		t.Fatalf("isolate = %q", h.Isolate)
	}
}

func TestApplyHTTPPortRouteDockerShapes(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.HTTPWakeDirectRouteRetryDuration = 200 * time.Millisecond
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})

	direct := &models.Sandbox{
		ID: "sb-http", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.5",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.applyHTTPPortRoute(ctx, direct, 8080); err != nil {
		t.Fatalf("direct bypass: %v", err)
	}
	svc.cfg.HTTPWakeDirectBypassEnabled = false
	if err := svc.applyHTTPPortRoute(ctx, direct, 8080); err != nil {
		t.Fatalf("direct no-bypass: %v", err)
	}

	wake := &models.Sandbox{
		ID: "sb-wake", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.applyHTTPPortRoute(ctx, wake, 8081); err != nil {
		t.Fatalf("wake: %v", err)
	}
	none := &models.Sandbox{ID: "sb-none", Status: models.SandboxStatusStopped}
	if err := svc.applyHTTPPortRoute(ctx, none, 8082); err != nil {
		t.Fatalf("none: %v", err)
	}

	rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc.SetIsolateRuntime(rt)
	if err := svc.applyHTTPPortRoute(ctx, &models.Sandbox{ID: "iso", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted}, 9); err != nil {
		t.Fatalf("isolate apply: %v", err)
	}
}

func TestResizeSandboxAndGPUCount(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-resize", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, ContainerID: "ctr-resize",
		CPU: 1, MemoryMB: 512, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc.docker = resizeOKRuntime{recordingRuntime: rt}
	got, err := svc.ResizeSandbox(ctx, "sb-resize", models.ResizeSandboxRequest{CPU: 2, MemoryMB: 1024})
	if err != nil {
		t.Fatalf("ResizeSandbox: %v", err)
	}
	if got.CPU != 2 || got.MemoryMB != 1024 {
		t.Fatalf("resized = %+v", got)
	}
	if n := gpuCountForCapacity(nil); n != 0 {
		t.Fatalf("nil gpu = %d", n)
	}
	if n := gpuCountForCapacity(&models.GPURequest{Count: 3}); n != 3 {
		t.Fatalf("gpu count = %d", n)
	}
	if n := gpuCountForCapacity(&models.GPURequest{}); n != 1 {
		t.Fatalf("zero count defaults to 1, got %d", n)
	}
}

type resizeOKRuntime struct{ *recordingRuntime }

func (r resizeOKRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}

func TestDestroySandboxHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-des", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-des", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroySandbox(ctx, "sb-des"); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
}

func TestSealClusterSecretEnvelopeNonceFailureAndBadDEK(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("nonce entropy")}})
	if _, err := s.sealClusterSecretEnvelope([]byte(`{"x":1}`), []string{"*"}); err == nil {
		t.Fatal("expected nonce failure")
	}
	if _, err := openClusterSecretEnvelopePayload([]byte("short"), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []string{"*"}); err == nil {
		t.Fatal("expected bad dek / short payload failure")
	}
}

func TestRunVolumeReclaimCancelAndConcurrency(t *testing.T) {
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.SetVolumeReclaimer(&fakeReclaimer{})
	s.cfg.PlatformVolumes.ReclaimConcurrency = 4
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		seedDeletedVolume(t, s, fmt.Sprintf("v%d", i), fmt.Sprintf("n%d", i), fmt.Sprintf("aerol-volumes/volumes/t-a/n%d", i))
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	s.runVolumeReclaim(cancelCtx)

	seedDeletedVolume(t, s, "vx", "nx", "aerol-volumes/volumes/t-a/nx")
	s.runVolumeReclaim(ctx)
}

func TestRegisterSnapshotAndGet(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	snap := &models.SandboxSnapshot{
		Name: "snap-1", Image: "alpine:snap", ImageID: "sha256:abc",
		SourceSandboxID: "sb-snap", CreatedAt: now,
	}
	got, err := svc.RegisterSnapshot(ctx, snap)
	if err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if got.Name != "snap-1" {
		t.Fatalf("got = %+v", got)
	}
	// Idempotent same image.
	again, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-1", Image: "alpine:snap"})
	if err != nil || again.Name != "snap-1" {
		t.Fatalf("idempotent = %+v, %v", again, err)
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-1", Image: "other"}); err == nil {
		t.Fatal("expected name conflict")
	}
	fetched, err := svc.GetSnapshot(ctx, "snap-1")
	if err != nil || fetched.Name != "snap-1" {
		t.Fatalf("GetSnapshot = %+v, %v", fetched, err)
	}
}

func TestForceReconcileHTTPWakeShape(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-force", Image: "alpine", Status: models.SandboxStatusStopped,
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForceReconcileHTTPWakeShape(ctx); err != nil {
		t.Fatalf("ForceReconcileHTTPWakeShape: %v", err)
	}
	svc.cfg.EnableServerless = false
	if err := svc.ForceReconcileHTTPWakeShape(ctx); err != nil {
		t.Fatalf("disabled: %v", err)
	}
}

func TestApplyInFluxRouteDomainMode(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second,
	})
	p := cluster.Placement{SandboxID: "sb-domain"}
	_ = svc.applyInFluxSandboxRoute(context.Background(), p)
	_ = svc.applyInFluxPortRoute(context.Background(), p, 443)
}

func TestInstallTLSPortRouteShapes(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = ":443"
	svc.cfg.L4PortRangeStart = 20000
	svc.cfg.L4PortRangeEnd = 20010
	sb := &models.Sandbox{
		ID: "sb-tls", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.8",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	_ = svc.installTLSPortRoute(ctx, sb, 8443)
	_ = svc.deleteTLSPortRoute(ctx, "sb-tls", 8443)

	wake := &models.Sandbox{
		ID: "sb-tls-wake", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	_ = svc.installTLSPortRoute(ctx, wake, 8443)
}

func TestReconcileStaleOwnershipListError(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	_ = st.Close()
	svc.reconcileStaleOwnership(context.Background())
}

func TestStartBuiltImageGCPaths(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ImageBuildGCEnabled = true
	svc.cfg.ImageBuildGCInterval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	svc.StartBuiltImageGC(ctx)
	cancel()
	svc.cfg.ImageBuildGCEnabled = false
	svc.StartBuiltImageGC(context.Background())
}

func TestOpenClusterSecretPayloadLegacyRaw(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	plain := []byte(`{"registry":{"password":"x"}}`)
	sealed, err := s.cipher.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.openClusterSecretPayload(sealed, "")
	if err != nil || string(out) != string(plain) {
		t.Fatalf("legacy open = %q, %v", out, err)
	}
}
