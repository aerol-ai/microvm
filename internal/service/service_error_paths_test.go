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
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type failingExposeCluster struct {
	*cluster.Noop
	addErr error
}

func (c *failingExposeCluster) AddExposedPort(ctx context.Context, sandboxID string, port int, route cluster.ExposedPortRoute) error {
	return c.addErr
}

type networkBlockFailRuntime struct {
	*recordingRuntime
	applyErr error
}

func (r *networkBlockFailRuntime) ApplyNetworkBlockAll(containerIP string) error {
	r.applyNetworkBlockAllCalls = append(r.applyNetworkBlockAllCalls, containerIP)
	return r.applyErr
}

func TestStartSandboxRuntimeFailureMarksSandboxErrorAndReleasesAdmission(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{startErr: errors.New("start failed")}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-start-runtime-fail",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStopped,
		ContainerID:  "ctr-start-runtime-fail",
		ContainerIP:  "10.0.0.21",
		Runtime:      models.RuntimeDocker,
		CPU:          2,
		MemoryMB:     1024,
		DiskGB:       10,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.StartSandbox(ctx, "sb-start-runtime-fail")
	if err == nil || !strings.Contains(err.Error(), "start failed") {
		t.Fatalf("StartSandbox() error = %v, want runtime start failure", err)
	}
	if len(rt.startRefs) != 1 || rt.startRefs[0] != "ctr-start-runtime-fail" {
		t.Fatalf("runtime Start refs = %v, want [ctr-start-runtime-fail]", rt.startRefs)
	}
	if len(rt.stopRefs) != 0 {
		t.Fatalf("runtime Stop refs = %v, want none on direct start failure", rt.stopRefs)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 0 || cap.ReservedCPU != 0 || cap.ReservedMemoryMB != 0 {
		t.Fatalf("capacity snapshot after failed start = %+v, want released admission", cap)
	}
	got, err := st.Get(ctx, "sb-start-runtime-fail")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusError {
		t.Fatalf("sandbox status = %q, want error after failed start", got.Status)
	}
}

func TestStartSandboxNetworkBlockFailureStopsContainerAndReleasesAdmission(t *testing.T) {
	ctx := context.Background()
	baseRuntime := &recordingRuntime{
		startState: &models.SandboxRuntimeState{
			SandboxID:   "sb-start-netblock-fail",
			ContainerID: "ctr-start-netblock-new",
			ContainerIP: "10.0.0.44",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, baseRuntime)
	svc.docker = &networkBlockFailRuntime{recordingRuntime: baseRuntime, applyErr: errors.New("iptables failed")}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:              "sb-start-netblock-fail",
		Image:           "alpine:3.20",
		Status:          models.SandboxStatusStopped,
		ContainerID:     "ctr-start-netblock-old",
		ContainerIP:     "10.0.0.22",
		Runtime:         models.RuntimeDocker,
		CPU:             2,
		MemoryMB:        1024,
		DiskGB:          10,
		NetworkBlockAll: true,
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.StartSandbox(ctx, "sb-start-netblock-fail")
	if err == nil || !strings.Contains(err.Error(), "apply network block on start") {
		t.Fatalf("StartSandbox() error = %v, want network-block failure", err)
	}
	if len(baseRuntime.applyNetworkBlockAllCalls) != 1 || baseRuntime.applyNetworkBlockAllCalls[0] != "10.0.0.44" {
		t.Fatalf("ApplyNetworkBlockAll calls = %v, want [10.0.0.44]", baseRuntime.applyNetworkBlockAllCalls)
	}
	if len(baseRuntime.stopRefs) != 1 || baseRuntime.stopRefs[0] != "ctr-start-netblock-new" {
		t.Fatalf("runtime Stop refs = %v, want [ctr-start-netblock-new]", baseRuntime.stopRefs)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 0 || cap.ReservedCPU != 0 || cap.ReservedMemoryMB != 0 {
		t.Fatalf("capacity snapshot after failed start = %+v, want released admission", cap)
	}
	got, err := st.Get(ctx, "sb-start-netblock-fail")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusError {
		t.Fatalf("sandbox status = %q, want error after network-block failure", got.Status)
	}
}

func TestExposePortHTTPRollsBackOnClusterRecordFailure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	fake := newApplyInFluxCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	}
	svc.caddy = caddy.New(svc.cfg)
	svc.AttachCluster(&failingExposeCluster{
		Noop:   cluster.NewNoop("node-1", "http://node-1"),
		addErr: errors.New("cluster write failed"),
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-http-rollback",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-http-rollback",
		ContainerIP:  "10.0.0.30",
		Runtime:      models.RuntimeDocker,
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.ExposePort(ctx, "sb-http-rollback", 8080, models.ExposedPortProtocolHTTP)
	if err == nil || !strings.Contains(err.Error(), "cluster: record exposed port") {
		t.Fatalf("ExposePort() error = %v, want cluster record failure", err)
	}
	got, err := st.Get(ctx, "sb-http-rollback")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if len(got.ExposedPorts) != 0 {
		t.Fatalf("exposed ports after rollback = %+v, want none", got.ExposedPorts)
	}
	if fake.hasRoute(caddy.PortRouteID("sb-http-rollback", 8080)) {
		t.Fatal("HTTP route should have been deleted during rollback")
	}
	if len(rt.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want 0 on failed expose", len(rt.pushes))
	}
}

func TestStopSandboxIgnoresCaddyCleanupFailures(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, admitter := newServiceRuntimeHarness(t, rt)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/id/") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:          "sb-stop-cleanup",
		Image:       "alpine:3.20",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-stop-cleanup",
		ContainerIP: "10.0.0.31",
		Runtime:     models.RuntimeDocker,
		CPU:         1,
		MemoryMB:    256,
		DiskGB:      5,
		ExposedPorts: []models.ExposedPort{{
			SandboxID: "sb-stop-cleanup",
			Port:      8080,
			Protocol:  models.ExposedPortProtocolHTTP,
			PublicURL: "https://sb-stop-cleanup-8080.sandbox.example.com",
		}},
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	admitter.Reserve("sb-stop-cleanup", capacity.Request{CPU: 1, MemoryMB: 256})

	stopped, err := svc.StopSandbox(ctx, "sb-stop-cleanup")
	if err != nil {
		t.Fatalf("StopSandbox() error = %v", err)
	}
	if stopped.Status != models.SandboxStatusStopped {
		t.Fatalf("returned sandbox status = %q, want stopped", stopped.Status)
	}
	if len(rt.stopRefs) != 1 || rt.stopRefs[0] != "ctr-stop-cleanup" {
		t.Fatalf("runtime Stop refs = %v, want [ctr-stop-cleanup]", rt.stopRefs)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 0 || cap.ReservedCPU != 0 || cap.ReservedMemoryMB != 0 {
		t.Fatalf("capacity snapshot after stop = %+v, want released admission", cap)
	}
	got, err := st.Get(ctx, "sb-stop-cleanup")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("stored sandbox status = %q, want stopped", got.Status)
	}
}

func TestUnexposePortDeletesLegacyHTTPRouteWhenRowMissing(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	fake := newApplyInFluxCaddyFake(caddy.PortRouteID("sb-legacy-unexpose", 8080))
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-legacy-unexpose",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-legacy-unexpose",
		ContainerIP:  "10.0.0.32",
		Runtime:      models.RuntimeDocker,
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if err := svc.UnexposePort(ctx, "sb-legacy-unexpose", 8080); err != nil {
		t.Fatalf("UnexposePort() error = %v", err)
	}
	if fake.hasRoute(caddy.PortRouteID("sb-legacy-unexpose", 8080)) {
		t.Fatal("legacy HTTP route should have been deleted")
	}
	got, err := st.Get(ctx, "sb-legacy-unexpose")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if len(got.ExposedPorts) != 0 {
		t.Fatalf("exposed ports after legacy unexpose = %+v, want none", got.ExposedPorts)
	}
}
