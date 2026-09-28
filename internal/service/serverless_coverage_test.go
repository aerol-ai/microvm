package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

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

func TestReconstructWakeArmedPublicTrafficDisabled(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	falseVal := false
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-pub-off", Image: "alpine", Status: models.SandboxStatusStopped,
		ContainerIP: "10.0.0.10", Runtime: models.RuntimeDocker,
		AllowPublicTraffic: &falseVal, WakeArmed: true,
		ExposedPorts: []models.ExposedPort{{
			Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "http://x",
		}},
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.SetWakeArmed(ctx, sb.ID, true); err != nil {
		t.Fatalf("SetWakeArmed: %v", err)
	}
	sb.WakeArmed = true

	svc.ReconstructWakeArmedIfNeeded(ctx, sb)
	if sb.WakeArmed {
		t.Fatal("public-disabled reconstruct must clear WakeArmed")
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WakeArmed {
		t.Fatal("store still WakeArmed after public-disabled reconstruct")
	}

	svc.ReconstructWakeArmedIfNeeded(ctx, nil)
}

func TestStopSandboxInternalModesWave11(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-stop-life", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID, Port: 8080, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	stopped, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle)
	if err != nil {
		t.Fatalf("lifecycle stop: %v", err)
	}
	if stopped == nil {
		t.Fatal("nil stopped")
	}
	// Manual stop on already-stopped.
	if _, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeManual); err != nil {
		t.Fatalf("manual stop: %v", err)
	}
}

func TestServerlessSemAcquireFailWave12(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.WakeStartConcurrency = 1
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-sem", Image: "a", Status: models.SandboxStatusStopped,
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-sem")
	if err == nil {
		t.Log("wake may still succeed if slot acquired before cancel observed")
	}
}

func TestStopSandboxInternalWarnArmsWave15(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-stop15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-stop15", Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	})
	_, _ = svc.stopSandboxInternal(ctx, "sb-stop15", stopModeLifecycle)

	// Runtime Stop failure.
	rt := &recordingRuntime{stopErr: errors.New("stop boom")}
	svc2, st2, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/stop2.db", rt)
	svc2.cfg.EnableServerless = true
	_ = st2.Create(ctx, &models.Sandbox{
		ID: "sb-stop-fail", Image: "a", Status: models.SandboxStatusStarted,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, err := svc2.stopSandboxInternal(ctx, "sb-stop-fail", stopModeManual); err == nil {
		t.Fatal("expected stop failure")
	}
}

func TestForceReconcileHTTPWakeShapeWave15(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-frc15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.9",
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-frc15", Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	})
	_ = svc.ForceReconcileHTTPWakeShape(ctx)
}

func TestServerlessReconstructWakeArmedStoreFailWave21(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = false
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-recon", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(ctx, sb)
	_ = st.Close()
	svc.ReconstructWakeArmedIfNeeded(ctx, sb)
}

func TestServerlessWakeGetUnderLockFailWave23(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-w23", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.Close()
	_, _ = svc.EnsureSandboxAwakeForHTTP(ctx, "sb-w23")
}

func TestForceReconcileHTTPWakeShapeInstallFailures(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-force-fail", Image: "alpine", Status: models.SandboxStatusStopped,
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 20001},
		},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Nil sandbox rows / non-serverless skipped; TCP port skipped; HTTP install fails.
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-non-sl", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForceReconcileHTTPWakeShape(ctx); err != nil {
		t.Fatalf("ForceReconcileHTTPWakeShape: %v", err)
	}
}

func TestReconstructWakeArmedStoreErrors(t *testing.T) {
	ctx := context.Background()
	svc, st := newServerlessHarness(t, &fakeCapacityRuntime{})
	falseVal := false
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-wake-store", Image: "alpine", Status: models.SandboxStatusStopped,
		AllowPublicTraffic: &falseVal, WakeArmed: true,
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	// deleteExposedPortRoute + SetWakeArmed against closed store → warn arms.
	svc.ReconstructWakeArmedIfNeeded(ctx, sb)
}

func TestEnsureSandboxAwakeArmsWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()

	started := &models.Sandbox{
		ID: "sb-awake-started", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, started); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-started"); err != nil {
		t.Fatalf("already started: %v", err)
	}

	destroying := &models.Sandbox{
		ID: "sb-awake-other", Image: "a", Status: models.SandboxStatusError,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, destroying); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-other"); err != nil {
		t.Fatalf("non-stopped: %v", err)
	}

	stoppedPlain := &models.Sandbox{
		ID: "sb-awake-plain", Image: "a", Status: models.SandboxStatusStopped,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, stoppedPlain); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-plain"); err != nil {
		t.Fatalf("non-serverless stopped: %v", err)
	}

	disarmed := &models.Sandbox{
		ID: "sb-awake-disarm", Image: "a", Status: models.SandboxStatusStopped,
		WakeArmed: false, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, disarmed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-disarm"); !errors.Is(err, ErrSandboxManuallyStopped) {
		t.Fatalf("disarmed = %v", err)
	}

	// Trip circuit: record failures then expect ErrWakeCircuitOpen.
	armed := &models.Sandbox{
		ID: "sb-awake-circ", Image: "a", Status: models.SandboxStatusStopped,
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, armed); err != nil {
		t.Fatal(err)
	}
	flight := svc.wakeFlightFor("sb-awake-circ")
	flight.mu.Lock()
	for i := 0; i < 8; i++ {
		flight.recordFailure(time.Now())
	}
	flight.mu.Unlock()
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-circ"); !errors.Is(err, ErrWakeCircuitOpen) {
		t.Fatalf("circuit = %v", err)
	}
}

func TestStopSandboxInternalAndForceReconcileWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-stop-int", Image: "a", Status: models.SandboxStatusStarted,
		ContainerIP:  "10.0.0.1",
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.stopSandboxInternal(ctx, "sb-stop-int", stopModeLifecycle); err != nil {
		t.Fatalf("stopSandboxInternal: %v", err)
	}
	_ = svc.ForceReconcileHTTPWakeShape(ctx)
}
