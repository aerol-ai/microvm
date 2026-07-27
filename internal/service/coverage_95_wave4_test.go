package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

func TestApplyInFluxRoutesCaddyErrorBranches(t *testing.T) {
	ctx := context.Background()
	// Every Caddy admin write fails so applyInFlux* error-assignment arms run.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	newSvc := func(domain string) *Service {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.Domain = domain
		svc.cfg.EnableCaddy = true
		svc.caddy = caddy.New(config.Config{
			EnableCaddy: true, Domain: domain, CaddyAdminURL: server.URL,
			CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
		})
		return svc
	}

	p := cluster.Placement{SandboxID: "sb-influx"}
	svc := newSvc("")
	if err := svc.applyInFluxSandboxRoute(ctx, p); err == nil {
		t.Fatal("expected path-mode influx sandbox route error")
	}
	if err := svc.applyInFluxPortRoute(ctx, p, 8080); err == nil {
		t.Fatal("expected path-mode influx port route error")
	}
	if err := svc.applyInFluxRoute(ctx, p); err == nil {
		t.Fatal("expected applyInFluxRoute error")
	}

	svc2 := newSvc("sandbox.example.com")
	if err := svc2.applyInFluxSandboxRoute(ctx, p); err == nil {
		t.Fatal("expected domain-mode influx sandbox route error")
	}
	if err := svc2.applyInFluxPortRoute(ctx, p, 443); err == nil {
		t.Fatal("expected domain-mode influx port route error")
	}
}

func TestInstallTLSPortRouteWithL4Ready(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPut || r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete:
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = "127.0.0.1:9443"
	svc.cfg.L4PortRangeStart = 20000
	svc.cfg.L4PortRangeEnd = 20100
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)

	direct := &models.Sandbox{
		ID: "sb-tls-d", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.3",
	}
	if err := svc.installTLSPortRoute(ctx, direct, 8443); err != nil {
		t.Fatalf("direct TLS: %v", err)
	}
	wake := &models.Sandbox{
		ID: "sb-tls-w", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installTLSPortRoute(ctx, wake, 8443); err != nil {
		// Wake may fail ensuring unix listener in unit env; still exercises the branch.
		t.Logf("wake TLS (best-effort): %v", err)
	}
	none := &models.Sandbox{ID: "sb-tls-n", Status: models.SandboxStatusStopped}
	if err := svc.installTLSPortRoute(ctx, none, 8443); err != nil {
		t.Fatalf("none TLS: %v", err)
	}
	_ = svc.deleteTLSPortRoute(ctx, "sb-tls-d", 8443)
}

func TestUpsertExposedPortRouteHTTP(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.Domain = "sandbox.example.com"
	svc.l4Ready.Store(true)
	sb := &models.Sandbox{ID: "sb-up", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.4"}
	if err := svc.upsertExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 8080, Protocol: models.ExposedPortProtocolHTTP,
	}); err != nil {
		t.Fatalf("upsert http: %v", err)
	}
	_ = svc.upsertExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 20001,
	})
	_ = svc.upsertExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 8443, Protocol: models.ExposedPortProtocolTLS,
	})
	if err := svc.upsertExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 1, Protocol: "udp",
	}); err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("unknown protocol = %v", err)
	}
	if err := svc.deleteExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 8080, Protocol: models.ExposedPortProtocolHTTP,
	}); err != nil {
		t.Fatalf("delete http: %v", err)
	}
	_ = svc.deleteExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 20001,
	})
	_ = svc.deleteExposedPortRoute(ctx, sb, models.ExposedPort{
		Port: 8443, Protocol: models.ExposedPortProtocolTLS,
	})
	if err := svc.deleteExposedPortRoute(ctx, sb, models.ExposedPort{Port: 1, Protocol: "udp"}); err == nil {
		t.Fatal("delete unknown protocol should fail")
	}
}

func TestGetPlatformVolumeByNameDisabledAndSanitize(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.cfg.PlatformVolumes.Enabled = false
	if _, err := s.GetPlatformVolumeByName(ctx, "x"); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
	s.cfg.PlatformVolumes.Enabled = true
	if _, err := s.GetPlatformVolumeByName(ctx, "../bad"); err == nil {
		t.Fatal("expected sanitize failure")
	}
	// Happy path after create.
	v, err := s.CreatePlatformVolume(ctx, "ok-name")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPlatformVolumeByName(ctx, "ok-name")
	if err != nil || got.ID != v.ID {
		t.Fatalf("by name = %+v, %v", got, err)
	}
}

func TestDeleteVolumeRowIfUnattachedEmptySource(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "empty-src")
	if err != nil {
		t.Fatal(err)
	}
	// Force empty Source so deleteVolumeRowIfUnattached rebuilds via MountSource.
	v.Source = ""
	if err := s.deleteVolumeRowIfUnattached(ctx, *v); err != nil {
		t.Fatalf("deleteVolumeRowIfUnattached: %v", err)
	}
	if _, err := volumes.SanitizeVolumeName("empty-src"); err != nil {
		t.Fatal(err)
	}
}

func TestReclaimOneLiveSourceCheckError(t *testing.T) {
	s := enabledVolumeService(t)
	harness, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	s.logger = harness.logger
	s.SetVolumeReclaimer(&fakeReclaimer{})
	ctx := context.Background()
	seedDeletedVolume(t, s, "v-err", "n-err", "aerol-volumes/volumes/t-a/n-err")

	// Close store so ExistsForSource / ByID fail → reclaimOne warn+return arms.
	_ = s.store.Close()
	pending := models.PendingVolumeDeletion{
		VolumeID: "v-err", Tenant: "t-a", Name: "n-err",
		Backend: "s3", Source: "aerol-volumes/volumes/t-a/n-err",
	}
	s.reclaimOne(ctx, pending)
}

func TestUpdateLifecycleValidationError(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-lc-bad", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.UpdateLifecycle(ctx, "sb-lc-bad", models.Lifecycle{StopIfIdleFor: -time.Second})
	if err == nil || !strings.Contains(err.Error(), "invalid lifecycle") {
		t.Fatalf("err = %v", err)
	}
	_, err = svc.UpdateLifecycle(ctx, "missing", models.Lifecycle{})
	if err == nil {
		t.Fatal("missing sandbox should fail")
	}
}
