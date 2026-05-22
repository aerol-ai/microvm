package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
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

type startHookRuntime struct {
	*recordingRuntime
	afterStart func()
}

func (r *networkBlockFailRuntime) ApplyNetworkBlockAll(containerIP string) error {
	r.applyNetworkBlockAllCalls = append(r.applyNetworkBlockAllCalls, containerIP)
	return r.applyErr
}

func (r *startHookRuntime) Start(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	state, err := r.recordingRuntime.Start(ctx, containerRef)
	if err == nil && r.afterStart != nil {
		r.afterStart()
	}
	return state, err
}

func testTCPServerID(hostPort int) string {
	return "tcp-port-" + strconv.Itoa(hostPort)
}

func testTLSRouteID(id string, port int) string {
	return "sandbox-" + id + "-port-" + strconv.Itoa(port) + "-tls"
}

func newServiceRuntimeHarnessAllowStoreClose(t *testing.T, rt *recordingRuntime) (*Service, *storepkg.Store, *capacity.Admitter) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	svc := &Service{
		cfg: config.Config{
			Runtime:           models.RuntimeDocker,
			ToolboxPort:       4321,
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:    st,
		docker:   rt,
		caddy:    caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts:   mgr,
		admitter: admitter,
		images:   newDefaultImageDistributionProvider(""),
	}
	return svc, st, admitter
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

func TestStartSandboxReturnsErrorWhenExposedPortRouteReupsertFails(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{startState: &models.SandboxRuntimeState{
		SandboxID:   "sb-start-route-fail",
		ContainerID: "ctr-start-route-new",
		ContainerIP: "10.0.0.55",
		Status:      models.SandboxStatusStarted,
	}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/id/"+caddy.SandboxRouteID("sb-start-route-fail"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPatch && r.URL.Path == "/id/"+caddy.PortRouteID("sb-start-route-fail", 8080):
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxPort:       4321,
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-start-route-fail",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStopped,
		ContainerID:  "ctr-start-route-old",
		ContainerIP:  "10.0.0.40",
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
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-start-route-fail",
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		PublicURL: "https://sb-start-route-fail-8080.sandbox.example.com",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort() error = %v", err)
	}

	_, err := svc.StartSandbox(ctx, "sb-start-route-fail")
	if err == nil || !strings.Contains(err.Error(), "patch caddy route failed: 500") {
		t.Fatalf("StartSandbox() error = %v, want exposed-port caddy failure", err)
	}
	if len(rt.startRefs) != 1 || rt.startRefs[0] != "ctr-start-route-old" {
		t.Fatalf("runtime Start refs = %v, want [ctr-start-route-old]", rt.startRefs)
	}
	if len(rt.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want none on failed restart", len(rt.pushes))
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 1 || cap.ReservedCPU != 1 || cap.ReservedMemoryMB != 256 {
		t.Fatalf("capacity snapshot after caddy failure = %+v, want running reservation kept", cap)
	}
	got, err := st.Get(ctx, "sb-start-route-fail")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStopped || got.ContainerID != "ctr-start-route-old" || got.ContainerIP != "10.0.0.40" {
		t.Fatalf("stored sandbox after failed restart = %+v, want original stopped row", got)
	}
}

func TestStartSandboxReturnsErrorWhenStoreUpsertFails(t *testing.T) {
	ctx := context.Background()
	baseRuntime := &recordingRuntime{startState: &models.SandboxRuntimeState{
		SandboxID:   "sb-start-store-fail",
		ContainerID: "ctr-start-store-new",
		ContainerIP: "10.0.0.56",
		Status:      models.SandboxStatusStarted,
	}}
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, baseRuntime)
	svc.docker = &startHookRuntime{
		recordingRuntime: baseRuntime,
		afterStart: func() {
			_ = st.Close()
		},
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-start-store-fail",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStopped,
		ContainerID:  "ctr-start-store-old",
		ContainerIP:  "10.0.0.41",
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

	_, err := svc.StartSandbox(ctx, "sb-start-store-fail")
	if err == nil || !strings.Contains(err.Error(), "database is closed") {
		t.Fatalf("StartSandbox() error = %v, want store upsert failure", err)
	}
	if len(baseRuntime.startRefs) != 1 || baseRuntime.startRefs[0] != "ctr-start-store-old" {
		t.Fatalf("runtime Start refs = %v, want [ctr-start-store-old]", baseRuntime.startRefs)
	}
	if len(baseRuntime.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want none on failed restart", len(baseRuntime.pushes))
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 1 || cap.ReservedCPU != 1 || cap.ReservedMemoryMB != 256 {
		t.Fatalf("capacity snapshot after store failure = %+v, want running reservation kept", cap)
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

func TestStopSandboxReturnsRuntimeStopFailureWithoutMutatingState(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{stopErr: errors.New("stop failed")}
	svc, st, admitter := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-stop-runtime-fail",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-stop-runtime-fail",
		ContainerIP:  "10.0.0.42",
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
	admitter.Reserve("sb-stop-runtime-fail", capacity.Request{CPU: 2, MemoryMB: 1024})

	_, err := svc.StopSandbox(ctx, "sb-stop-runtime-fail")
	if err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("StopSandbox() error = %v, want runtime stop failure", err)
	}
	if len(rt.stopRefs) != 1 || rt.stopRefs[0] != "ctr-stop-runtime-fail" {
		t.Fatalf("runtime Stop refs = %v, want [ctr-stop-runtime-fail]", rt.stopRefs)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 1 || cap.ReservedCPU != 2 || cap.ReservedMemoryMB != 1024 {
		t.Fatalf("capacity snapshot after failed stop = %+v, want reservation preserved", cap)
	}
	got, err := st.Get(ctx, "sb-stop-runtime-fail")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("stored sandbox status = %q, want started after failed stop", got.Status)
	}
}

func TestStopSandboxCleansUpMixedProtocolRoutes(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, admitter := newServiceRuntimeHarness(t, rt)
	fake := newGCCaddyFake()
	fake.httpRouteIDs[caddy.SandboxRouteID("sb-stop-mixed")] = struct{}{}
	fake.httpRouteIDs[caddy.PortRouteID("sb-stop-mixed", 8080)] = struct{}{}
	fake.l4TCPServerIDs[testTCPServerID(37412)] = struct{}{}
	fake.l4TLSRouteIDs[testTLSRouteID("sb-stop-mixed", 8443)] = struct{}{}
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxPort:       4321,
		EnableCaddy:       true,
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-stop-mixed",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-stop-mixed",
		ContainerIP:  "10.0.0.43",
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
	for _, exposure := range []models.ExposedPort{
		{SandboxID: "sb-stop-mixed", Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-stop-mixed-8080.sandbox.example.com", CreatedAt: now},
		{SandboxID: "sb-stop-mixed", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 37412, PublicURL: "tcp://sandbox.example.com:37412", CreatedAt: now},
		{SandboxID: "sb-stop-mixed", Port: 8443, Protocol: models.ExposedPortProtocolTLS, PublicURL: "tls://sb-stop-mixed-8443.sandbox.example.com:443", CreatedAt: now},
	} {
		if err := st.UpsertPort(ctx, exposure); err != nil {
			t.Fatalf("UpsertPort(%d) error = %v", exposure.Port, err)
		}
	}
	admitter.Reserve("sb-stop-mixed", capacity.Request{CPU: 1, MemoryMB: 256})

	stopped, err := svc.StopSandbox(ctx, "sb-stop-mixed")
	if err != nil {
		t.Fatalf("StopSandbox() error = %v", err)
	}
	if stopped.Status != models.SandboxStatusStopped {
		t.Fatalf("returned sandbox status = %q, want stopped", stopped.Status)
	}
	if len(rt.stopRefs) != 1 || rt.stopRefs[0] != "ctr-stop-mixed" {
		t.Fatalf("runtime Stop refs = %v, want [ctr-stop-mixed]", rt.stopRefs)
	}
	if got := fake.keys(fake.httpRouteIDs); len(got) != 0 {
		t.Fatalf("http routes after stop = %v, want none", got)
	}
	if got := fake.keys(fake.l4TCPServerIDs); len(got) != 0 {
		t.Fatalf("tcp servers after stop = %v, want none", got)
	}
	if got := fake.keys(fake.l4TLSRouteIDs); len(got) != 0 {
		t.Fatalf("tls routes after stop = %v, want none", got)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 0 || cap.ReservedCPU != 0 || cap.ReservedMemoryMB != 0 {
		t.Fatalf("capacity snapshot after stop = %+v, want released admission", cap)
	}
	got, err := st.Get(ctx, "sb-stop-mixed")
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
