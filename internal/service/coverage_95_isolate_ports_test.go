package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// noopIsolatePortGateway mirrors noopWasmPortGateway so a recordingRuntime-style
// stub can satisfy AsPortGateway without spawning workerd.
type noopIsolatePortGateway struct{}

func (noopIsolatePortGateway) EnsureHTTPListener(_ context.Context, _ string, guestPort int) (string, error) {
	return "127.0.0.1:39999", nil
}

func (noopIsolatePortGateway) ReleaseHTTPListener(string, int) {}

func (noopIsolatePortGateway) SyncAllowedPorts(string, []int) {}

type isolatePortsRuntime struct {
	*recordingRuntime
	noopIsolatePortGateway
	dialErr error
	dialed  []struct {
		id   string
		port int
	}
	released []struct {
		id   string
		port int
	}
	synced []struct {
		id    string
		ports []int
	}
}

func (r *isolatePortsRuntime) EnsureHTTPListener(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	r.dialed = append(r.dialed, struct {
		id   string
		port int
	}{sandboxID, guestPort})
	if r.dialErr != nil {
		return "", r.dialErr
	}
	return r.noopIsolatePortGateway.EnsureHTTPListener(ctx, sandboxID, guestPort)
}

func (r *isolatePortsRuntime) ReleaseHTTPListener(sandboxID string, guestPort int) {
	r.released = append(r.released, struct {
		id   string
		port int
	}{sandboxID, guestPort})
}

func (r *isolatePortsRuntime) SyncAllowedPorts(sandboxID string, ports []int) {
	r.synced = append(r.synced, struct {
		id    string
		ports []int
	}{sandboxID, append([]int(nil), ports...)})
}

func TestIsolatePortGatewayBranches(t *testing.T) {
	svc := &Service{}
	if _, err := svc.isolatePortGateway(); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("missing isolate driver = %v, want ErrRuntimeNotImplemented", err)
	}
	svc.SetIsolateRuntime(&recordingRuntime{})
	if _, err := svc.isolatePortGateway(); err == nil {
		t.Fatal("recordingRuntime without PortGateway should fail")
	}

	rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc.SetIsolateRuntime(rt)
	pg, err := svc.isolatePortGateway()
	if err != nil || pg == nil {
		t.Fatalf("isolatePortGateway = %v, %v", pg, err)
	}
}

func TestIsolateHTTPDialAndUpstreamURL(t *testing.T) {
	ctx := context.Background()
	rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.SetIsolateRuntime(rt)

	dial, err := svc.isolateHTTPDial(ctx, "sb-iso", 8080)
	if err != nil || dial != "127.0.0.1:39999" {
		t.Fatalf("isolateHTTPDial = %q, %v", dial, err)
	}
	url, err := svc.isolateHTTPUpstreamURL(ctx, "sb-iso", 8080)
	if err != nil || url != "http://127.0.0.1:39999" {
		t.Fatalf("isolateHTTPUpstreamURL = %q, %v", url, err)
	}

	rt.dialErr = errors.New("listener failed")
	if _, err := svc.isolateHTTPDial(ctx, "sb-iso", 8080); err == nil {
		t.Fatal("isolateHTTPDial should propagate EnsureHTTPListener error")
	}
	if _, err := svc.isolateHTTPUpstreamURL(ctx, "sb-iso", 8080); err == nil {
		t.Fatal("isolateHTTPUpstreamURL should propagate dial error")
	}
}

func TestSyncIsolateAllowedPorts(t *testing.T) {
	ctx := context.Background()
	rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.SetIsolateRuntime(rt)

	// Nil sandbox and missing gateway are best-effort no-ops.
	svc.syncIsolateAllowedPorts(ctx, nil)
	svc2 := &Service{}
	svc2.syncIsolateAllowedPorts(ctx, &models.Sandbox{ID: "x", ExposedPorts: []models.ExposedPort{{Port: 1}}})

	svc.syncIsolateAllowedPorts(ctx, &models.Sandbox{
		ID: "sb-sync",
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 9090, Protocol: models.ExposedPortProtocolHTTP},
		},
	})
	if len(rt.synced) != 1 || len(rt.synced[0].ports) != 2 {
		t.Fatalf("synced = %+v", rt.synced)
	}
}

func TestInstallIsolateHTTPPortRouteShapes(t *testing.T) {
	ctx := context.Background()
	rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(rt)

	now := time.Now().UTC()
	direct := &models.Sandbox{
		ID: "sb-iso-direct", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStarted, Durability: models.DurabilityEphemeral,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := svc.installIsolateHTTPPortRoute(ctx, direct, 8080); err != nil {
		t.Fatalf("direct: %v", err)
	}

	wake := &models.Sandbox{
		ID: "sb-iso-wake", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStopped, WakeArmed: true,
		Durability: models.DurabilityEphemeral,
		Lifecycle:  models.Lifecycle{Serverless: true},
		CreatedAt:  now, UpdatedAt: now,
	}
	svc.cfg.EnableServerless = true
	if err := svc.installIsolateHTTPPortRoute(ctx, wake, 8081); err != nil {
		t.Fatalf("wake: %v", err)
	}

	none := &models.Sandbox{
		ID: "sb-iso-none", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStopped, Durability: models.DurabilityEphemeral,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := svc.installIsolateHTTPPortRoute(ctx, none, 8082); err != nil {
		t.Fatalf("none: %v", err)
	}

	svc.isolateHTTPPortRouteCleanup(ctx, "sb-iso-clean", 8080)
	if len(rt.released) == 0 {
		t.Fatal("cleanup should release the isolate HTTP listener")
	}
}

func TestInstallIsolateHTTPPortRouteCaddyErrors(t *testing.T) {
	ctx := context.Background()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			http.NotFound(w, r)
			return
		case http.MethodPut:
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("direct upsert failure releases listener", func(t *testing.T) {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		svc.cfg.EnableServerless = true
		svc.cfg.HTTPWakeDirectBypassEnabled = true
		svc.cfg.Domain = "sandbox.example.com"
		svc.cfg.InternalIngressAddr = "127.0.0.1:1234"
		svc.caddy = caddy.New(config.Config{
			EnableCaddy: true, Domain: "sandbox.example.com",
			CaddyAdminURL: server.URL, CaddyServerID: "srv0",
			HTTPClientTimeout: time.Second,
		})
		svc.SetIsolateRuntime(rt)
		err := svc.installIsolateHTTPPortRoute(ctx, &models.Sandbox{
			ID: "sb-iso-direct-err", Runtime: models.RuntimeIsolate,
			Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
			Lifecycle: models.Lifecycle{Serverless: true},
		}, 8080)
		if err == nil {
			t.Fatal("expected caddy direct upsert error")
		}
		if len(rt.released) == 0 {
			t.Fatal("failed upsert must release the orphaned listener")
		}
	})

	t.Run("wake upsert failure releases listener", func(t *testing.T) {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		svc.cfg.EnableServerless = true
		svc.cfg.HTTPWakeDirectBypassEnabled = false
		svc.cfg.Domain = "sandbox.example.com"
		svc.cfg.InternalIngressAddr = "127.0.0.1:1234"
		svc.caddy = caddy.New(config.Config{
			EnableCaddy: true, Domain: "sandbox.example.com",
			CaddyAdminURL: server.URL, CaddyServerID: "srv0",
			HTTPClientTimeout: time.Second,
		})
		svc.SetIsolateRuntime(rt)
		err := svc.installIsolateHTTPPortRoute(ctx, &models.Sandbox{
			ID: "sb-iso-wake-err", Runtime: models.RuntimeIsolate,
			Status: models.SandboxStatusStopped, WakeArmed: true,
			Lifecycle: models.Lifecycle{Serverless: true},
		}, 8081)
		if err == nil {
			t.Fatal("expected caddy wake upsert error")
		}
		if len(rt.released) == 0 {
			t.Fatal("failed wake upsert must release the listener opened by dial")
		}
	})

	t.Run("dial failure short-circuits", func(t *testing.T) {
		rt := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}, dialErr: errors.New("no listener")}
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.SetIsolateRuntime(rt)
		if err := svc.installIsolateHTTPPortRoute(ctx, &models.Sandbox{ID: "sb-dial", Runtime: models.RuntimeIsolate}, 8080); err == nil {
			t.Fatal("expected dial failure")
		}
	})
}

func TestIsolateExposePortHTTPUsesHostMediator(t *testing.T) {
	ctx := context.Background()
	// Real isolate driver implements PortGateway with a loopback listener —
	// offline-safe (no workerd) and exercises the same dial path as production.
	driver := isolateruntime.New(isolateruntime.Config{RunDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(driver)
	// Skip the container-port probe (127.0.0.1:8080 is not a real guest).
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-iso-port", Status: models.SandboxStatusStarted, Runtime: models.RuntimeIsolate,
		ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	resp, err := svc.ExposePort(ctx, "sb-iso-port", 8080, "http")
	if err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if resp.PublicURL == "" && svc.cfg.Domain != "" {
		t.Fatal("empty public URL with domain configured")
	}
	url, err := svc.isolateHTTPUpstreamURL(ctx, "sb-iso-port", 8080)
	if err != nil {
		t.Fatalf("isolateHTTPUpstreamURL: %v", err)
	}
	ep, err := svc.WakeAwarePortTarget(ctx, "sb-iso-port", 8080)
	if err != nil {
		t.Fatalf("WakeAwarePortTarget: %v", err)
	}
	if ep.URL != url {
		t.Fatalf("upstream = %q want %q", ep.URL, url)
	}

	_, err = svc.ExposePort(ctx, "sb-iso-port", 5432, "tcp")
	if err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("tcp expose = %v, want ErrRuntimeNotImplemented", err)
	}

	svc.syncAllowedPorts(ctx, &models.Sandbox{
		ID: "sb-iso-port", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	})
}
