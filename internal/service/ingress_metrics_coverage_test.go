package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestReconcileSkippedAndStoppedRuntimeRows(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableWasm = true
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableServerless = true
	svc.SetWasmRuntime(rt)
	svc.SetFirecrackerRuntime(rt)

	now := time.Now().UTC()
	seed := func(sb *models.Sandbox) {
		t.Helper()
		sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("seed %s: %v", sb.ID, err)
		}
	}

	// containerd-owned row with no driver registered → skip (don't tear down).
	seed(&models.Sandbox{
		ID: "sb-ctr", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd,
		ContainerID: "ctr-sb-ctr", ContainerIP: "10.0.0.1",
	})

	// Stopped wasm without wake → delete routes path.
	seed(&models.Sandbox{
		ID: "sb-wasm-stop", Image: "mod", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeWasm, WakeArmed: false,
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	})

	// Stopped wasm with wake → ReconstructWakeArmedIfNeeded.
	seed(&models.Sandbox{
		ID: "sb-wasm-wake", Image: "mod", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeWasm, WakeArmed: true,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	})

	// Stopped firecracker without wake.
	seed(&models.Sandbox{
		ID: "sb-fc-stop", Image: "tpl", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeFirecracker, WakeArmed: false,
		ExposedPorts: []models.ExposedPort{{Port: 22, Protocol: models.ExposedPortProtocolTCP, HostPort: 22022}},
	})

	// Passivated wasm is left alone.
	seed(&models.Sandbox{
		ID: "sb-wasm-pass", Image: "mod", Status: models.SandboxStatusPassivated,
		Runtime: models.RuntimeWasm,
	})

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// containerd row must survive (driver missing → skip, not delete).
	if _, err := st.Get(ctx, "sb-ctr"); err != nil {
		t.Fatalf("containerd row deleted: %v", err)
	}
}

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
