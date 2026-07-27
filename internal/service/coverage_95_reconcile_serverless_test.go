package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

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

func TestUpdateLifecycleServerlessFlip(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-life", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, ContainerID: "ctr-life", ContainerIP: "10.0.0.9",
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	updated, err := svc.UpdateLifecycle(ctx, "sb-life", models.Lifecycle{
		Serverless: true, StopIfIdleFor: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}
	if !updated.Lifecycle.Serverless {
		t.Fatal("serverless not set")
	}
	// Flip back off.
	updated, err = svc.UpdateLifecycle(ctx, "sb-life", models.Lifecycle{})
	if err != nil {
		t.Fatalf("UpdateLifecycle clear: %v", err)
	}
	if updated.Lifecycle.Serverless {
		t.Fatal("serverless still set")
	}
}

func TestCreateSandboxEgressPolicyRejected(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:           "alpine",
		NetworkAllowOut: []string{"10.0.0.0/8"},
		NetworkDenyOut:  []string{"192.168.0.0/16"},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
	_, err = svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:          "alpine",
		NetworkDenyOut: []string{"0.0.0.0/0"},
	})
	if err == nil || !strings.Contains(err.Error(), "network_block_all") {
		t.Fatalf("deny-all err = %v", err)
	}
}
