package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateIsolateSandboxIDGenerationFailure(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(&recordingRuntime{})
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	_, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "generate sandbox id") {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateIsolateSandboxBundleResolveMiss(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(&recordingRuntime{})
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "b")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)
	_, err = svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "missing-name",
	})
	if err == nil || !strings.Contains(err.Error(), "resolve bundle") {
		t.Fatalf("err = %v, want resolve failure", err)
	}
}

func TestCreateIsolateSandboxMemoryDefaultAndNilAdmitter(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.admitter = nil
	driver := &recordingRuntime{}
	svc.SetIsolateRuntime(driver)
	resp, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b", MemoryMB: 0,
	}, "sb-mem-default")
	if err != nil {
		t.Fatalf("createIsolateSandbox: %v", err)
	}
	if resp.Sandbox.MemoryMB != models.DefaultMemoryMB {
		t.Fatalf("MemoryMB = %d, want default %d", resp.Sandbox.MemoryMB, models.DefaultMemoryMB)
	}
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
