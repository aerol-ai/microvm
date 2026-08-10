package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestRunIngressOpsBranchesWave12(t *testing.T) {
	ctx := context.Background()
	if err := runIngressOps(ctx, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := runIngressOps(ctx, []func(context.Context) error{func(context.Context) error { return nil }}, 0); err != nil {
		t.Fatal(err)
	}
	err := runIngressOps(ctx, []func(context.Context) error{
		func(context.Context) error { return errors.New("op1") },
		func(context.Context) error { return errors.New("op2") },
		func(context.Context) error { return nil },
	}, 2)
	if err == nil {
		t.Fatal("expected first error")
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	ops := make([]func(context.Context) error, 20)
	for i := range ops {
		ops[i] = func(context.Context) error {
			time.Sleep(5 * time.Millisecond)
			return nil
		}
	}
	_ = runIngressOps(cancelCtx, ops, 4)

	_ = runIngressOpsBatched(ctx, []func(context.Context) error{
		func(context.Context) error { return errors.New("batch") },
	}, 2, 1)
}

func TestEnsureSandboxAwakeSemAndStoreWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.WakeStartConcurrency = 1
	now := time.Now().UTC()

	release, err := svc.acquireWakeStartSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-sem", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	_, err = svc.EnsureSandboxAwakeForHTTP(short, "sb-sem")
	if err == nil {
		t.Fatal("expected sem / timeout failure")
	}

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.cfg.EnableServerless = true
	if err := st2.Create(ctx, &models.Sandbox{
		ID: "sb-awake-close", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_ = st2.Close()
	_, _ = svc2.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-close")
}

func TestCustomDomainHelpersWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = false
	if err := svc.AddCustomDomain(ctx, "sb", "h.example.com", 8080); err == nil {
		t.Fatal("expected disabled")
	}
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "example.com"
	if err := svc.AddCustomDomain(ctx, "missing", "api.example.com", 8080); err == nil {
		t.Fatal("expected missing sandbox")
	}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-cd", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_ = svc.RemoveCustomDomain(ctx, "sb-cd", "nope.example.com")
}

func TestWasmMigrateImportExportWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	src := t.TempDir()
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: src, cloneGen: "gen-w12"})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-w-mig", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, gen, err := svc.MigrateWasmSandbox(ctx, "sb-w-mig", dir)
	t.Logf("MigrateWasmSandbox path=%q gen=%q err=%v", path, gen, err)
}

func TestReconcileClusterIngressDisabledWave12(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = false
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("disabled: %v", err)
	}
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = false
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("caddy off: %v", err)
	}
}

func TestDataPlaneHostAndPlacementHelpersWave12(t *testing.T) {
	_ = dataPlaneHostForPlacement(cluster.Placement{OwnerNodeID: "self", OwnerDataPlaneHost: "https://dp.example.com"})
	_ = dataPlaneHostForPlacement(cluster.Placement{OwnerNodeID: "other", OwnerAPIURL: "http://api.other:8080"})
	_ = dataPlaneHostForPlacement(cluster.Placement{})
	_ = hostFromURL("https://host.example.com:443/path")
	_ = hostFromURL("10.0.0.1")
	_ = hostFromURL("[::1]:8080")
	_ = hostFromURL("not a url")
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb", LastActiveAt: now, Tags: map[string]string{"a": "1"}}
	_ = svc.activityFloorFor(sb, false)
	_ = svc.activityFloorFor(sb, true)
	_ = svc.activityFloorFor(nil, false)
	_ = sandboxMatchesTags(sb, map[string]string{"a": "1"})
	_ = sandboxMatchesTags(sb, map[string]string{"a": "2"})
	_ = sandboxMatchesTags(&models.Sandbox{}, map[string]string{"a": "1"})
}

func TestValidateLifecycleBypassWave12(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.NetstatsPollInterval = time.Second
	svc.cfg.ReconcileInterval = time.Second
	_ = svc.validateLifecycle(models.Lifecycle{Serverless: true, StopIfIdleFor: time.Millisecond})
	if err := svc.validateLifecycle(models.Lifecycle{}); err != nil {
		t.Fatalf("empty: %v", err)
	}
}

func TestHandleDuplicateAndImageStillReferencedWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-dup", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.handleDuplicateStoreCreate(ctx, "sb-dup", models.ErrSandboxExists)
	if err != nil || resp == nil {
		t.Fatalf("dup = %v %v", resp, err)
	}
	if _, err := svc.handleDuplicateStoreCreate(ctx, "sb-dup", errors.New("other")); err == nil {
		t.Fatal("expected passthrough")
	}
	_ = imageStillReferenced([]*models.Sandbox{
		{Image: "alpine", Status: models.SandboxStatusDestroyed},
		{Image: "alpine", Status: models.SandboxStatusStarted},
	}, "alpine")
}

func TestStartClusterIngressReconcileWave12(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = false
	svc.StartClusterIngressReconcile(ctx) // no-op
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	svc.StartClusterIngressReconcile(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
}

func TestToolboxTargetWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = 4321
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-tb", Image: "a", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.2", ToolboxToken: "tok",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	ep, err := svc.ToolboxTarget(ctx, "sb-tb")
	if err != nil || !strings.Contains(ep.URL, "10.0.0.2") {
		t.Fatalf("ep=%+v err=%v", ep, err)
	}
	if _, err := svc.ToolboxTarget(ctx, "missing"); err == nil {
		t.Fatal("expected miss")
	}
}

func TestBypassEnabledForWave12(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	_ = svc.bypassEnabledFor(RouteKindHTTP)
	_ = svc.bypassEnabledFor(RouteKindL4)
	_ = svc.anyBypassEnabled()
}
