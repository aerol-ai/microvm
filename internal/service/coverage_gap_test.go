package service

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// --- auto_import_writeback.go ---

func TestMarkImportedNoOpsAndWriteThrough(t *testing.T) {
	ctx := context.Background()
	var nilSvc *Service
	nilSvc.MarkImported(ctx, "sb", "ref") // nil receiver

	svc := &Service{}
	svc.MarkImported(ctx, "sb", "   ") // empty ref

	stub := &specWriteThroughCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{
			Image:                 "ghcr.io/aerol-ai/sandbox:v1",
			ImageDistributionMode: models.ImageDistributionAOCR,
		},
	}
	svc.AttachCluster(stub)
	svc.MarkImported(ctx, "sb-1", "aocr.aerol.ai/cluster/cl/_imported/ghcr.io/foo:v1--idle-90d")

	calls := stub.calls()
	if len(calls) != 1 {
		t.Fatalf("UpsertSpec calls = %d, want 1", len(calls))
	}
	if calls[0].ImageDistributionMode != models.ImageDistributionAOCRImported {
		t.Fatalf("mode = %q, want aocr_imported", calls[0].ImageDistributionMode)
	}
	if calls[0].ImageRegistryRef == "" {
		t.Fatal("registry ref not written through")
	}
}

// --- dns_verify.go ---

type dnsNotFoundResolver struct{}

func (dnsNotFoundResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}

type dnsGenericErrResolver struct{}

func (dnsGenericErrResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("temporary failure")
}

type dnsStringNotFoundResolver struct{}

func (dnsStringNotFoundResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("lookup _aerol-verify.example.com: no such host")
}

func TestVerifyCustomDomainOwnershipDNSErrors(t *testing.T) {
	ctx := context.Background()
	if err := verifyCustomDomainOwnership(ctx, dnsNotFoundResolver{}, "api.acme.com", "_aerol-verify", "aerol-verify="); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("not found err = %v", err)
	}
	if err := verifyCustomDomainOwnership(ctx, dnsGenericErrResolver{}, "api.acme.com", "_aerol-verify", "aerol-verify="); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("generic err = %v", err)
	}
	if err := verifyCustomDomainOwnership(ctx, dnsStringNotFoundResolver{}, "api.acme.com", "_aerol-verify", "aerol-verify="); !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("string not found err = %v", err)
	}
}

func TestIsDNSNotFound(t *testing.T) {
	if !isDNSNotFound(&net.DNSError{IsNotFound: true}) {
		t.Fatal("DNSError IsNotFound should match")
	}
	if !isDNSNotFound(errors.New("lookup foo: no such host")) {
		t.Fatal("string fallback should match")
	}
	if isDNSNotFound(errors.New("connection refused")) {
		t.Fatal("unrelated error should not match")
	}
}

// --- auto_import.go ---

func TestAutoImporterEndpointAndValidation(t *testing.T) {
	var imp *AutoImporter
	if got := imp.Endpoint(); got != "" {
		t.Fatalf("nil Endpoint = %q, want empty", got)
	}
	imp, err := NewAutoImporter(AutoImportConfig{
		Enabled:      true,
		HooksBaseURL: "://bad",
		ClusterID:    "c",
		ClusterPAT:   "p",
	})
	if err == nil {
		t.Fatal("expected invalid URL error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"imported","registry_ref":"r"}`))
	}))
	defer srv.Close()
	imp, err = NewAutoImporter(AutoImportConfig{
		Enabled:      true,
		HooksBaseURL: srv.URL,
		ClusterID:    "c",
		ClusterPAT:   "p",
	})
	if err != nil {
		t.Fatalf("NewAutoImporter: %v", err)
	}
	if !strings.HasSuffix(imp.Endpoint(), "/v1/internal/imports") {
		t.Fatalf("endpoint = %q", imp.Endpoint())
	}
}

// --- auto_import_retry.go ---

func TestAutoImportReconcilerSetSpecMutator(t *testing.T) {
	var r *AutoImportReconciler
	r.SetSpecMutator(nil) // nil receiver

	store := newFakeStore()
	store.seed("sb-1", true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(importResponse{Status: "imported", RegistryRef: "cluster/ref"})
	}))
	defer srv.Close()
	imp, _ := NewAutoImporter(validImportCfg(srv.URL))
	specs := map[string]*models.CreateSandboxRequest{
		"sb-1": {
			Image:                 "ghcr.io/aerol-ai/sandbox:v1",
			ImageRegistryRef:      "ghcr.io/aerol-ai/sandbox:v1",
			ImageDigest:           "sha256:abc",
			ImageDistributionMode: models.ImageDistributionAOCR,
			Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
		},
	}
	r = NewAutoImportReconciler(imp, store, &fakeSpecResolver{specs: specs}, slog.Default(), 1)
	mut := &markImportedSpy{}
	r.SetSpecMutator(mut)
	stats, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Succeeded != 1 || mut.calls != 1 {
		t.Fatalf("stats=%+v mut.calls=%d, want success+mutator", stats, mut.calls)
	}
}

type markImportedSpy struct{ calls int }

func (m *markImportedSpy) MarkImported(_ context.Context, _ string, _ string) { m.calls++ }

// --- cluster_ownership.go ---

func TestReplayClusterOwnershipAndReconcile(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	recorder := &recordingOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{},
	}
	svc.cfg.EnableCluster = true
	svc.AttachCluster(recorder)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-replay", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 512, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	count, err := svc.ReplayClusterOwnership(ctx)
	if err != nil {
		t.Fatalf("ReplayClusterOwnership: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	svc.reconcileLocalClusterOwnership(ctx, []*models.Sandbox{{ID: "sb-replay"}}, map[string]*models.SandboxRuntimeState{"sb-replay": {}})
}

func TestClusterOwnershipNeedsReplayVariants(t *testing.T) {
	c := cluster.NewNoop("self", "http://self", "")
	svc := &Service{cfg: config.Config{EnableCluster: true}}
	svc.AttachCluster(c)

	sb := &models.Sandbox{
		ID: "sb-x", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, HostPort: 18080}},
	}
	if !svc.clusterOwnershipNeedsReplay(c, sb) {
		t.Fatal("missing placement should need replay")
	}

	rec := &recordingOwnershipCluster{
		Noop: c,
		placements: map[string]cluster.Placement{
			"sb-x": {
				SandboxID: "sb-x", OwnerNodeID: "self", OwnerState: cluster.PlacementOwnerStateActive,
				State: cluster.PlacementStateReserved,
			},
		},
	}
	svc.AttachCluster(rec)
	if !svc.clusterOwnershipNeedsReplay(rec, sb) {
		t.Fatal("reserved placement should need replay")
	}
}

// --- ingress_delta.go ---

func TestIngressDeltaHelpersAndGC(t *testing.T) {
	_ = clusterIngressShardFilter(nil, "self")
	c := cluster.NewNoop("self", "http://self", "")
	f := clusterIngressShardFilter(c, "self")
	_ = f

	svc := &Service{
		cfg:   config.Config{EnableCluster: true, Domain: "sb.example.com", L4TLSListen: ":8443"},
		caddy: caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}
	peer := cluster.Placement{
		SandboxID: "sb-peer", OwnerNodeID: "peer-1", OwnerAPIURL: "http://10.0.0.2:8080",
		Version: 1,
		Spec:    &models.CreateSandboxRequest{AllowPublicTraffic: privateFlag(true)},
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 25432},
			8080: {Protocol: models.ExposedPortProtocolHTTP},
			8443: {Protocol: models.ExposedPortProtocolTLS},
		},
	}
	intents, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{peer}, "self")
	if !needL4 {
		t.Fatal("tcp/tls exposure should need L4")
	}
	if len(intents) == 0 {
		t.Fatal("expected intents")
	}

	inFlux := cluster.Placement{SandboxID: "sb-flux", OwnerNodeID: "", Version: 2}
	svc.addClusterIngressInFluxIntents(intents, inFlux)
	if _, ok := intents[ingressIntentKey(ingressSurfaceHTTP, caddy.InFluxSandboxRouteID("sb-flux"))]; !ok {
		t.Fatal("missing in-flux sandbox intent")
	}

	httpExp, tcpExp, tlsExp := expectedIngressRoutesFromIntents(intents)
	svc.addLocalIngressExpectedRoutes(httpExp, tcpExp, tlsExp, []*models.Sandbox{
		{ID: "local", Status: models.SandboxStatusStarted, ExposedPorts: []models.ExposedPort{
			{Port: 22, Protocol: models.ExposedPortProtocolTCP, HostPort: 10022},
			{Port: 443, Protocol: models.ExposedPortProtocolTLS},
		}},
	})
	if len(httpExp) == 0 || len(tcpExp) == 0 || len(tlsExp) == 0 {
		t.Fatalf("expected routes not populated: http=%d tcp=%d tls=%d", len(httpExp), len(tcpExp), len(tlsExp))
	}

	svc.ingressRouteCache = map[string]ingressRouteIntent{}
	ops, commit := svc.planClusterIngressDelta(intents)
	if len(ops) == 0 {
		t.Fatal("expected delta ops on cold cache")
	}
	commit()

	if !svc.shouldRunClusterIngressFullGC() {
		t.Fatal("first full GC should run")
	}
	if svc.shouldRunClusterIngressFullGC() {
		t.Fatal("second full GC within interval should skip")
	}

	defaultProtocolPlacement := cluster.Placement{
		SandboxID:   "sb-default-protocol",
		OwnerNodeID: "peer-2",
		OwnerAPIURL: "http://10.0.0.3:8080",
		Version:     2,
		Spec:        &models.CreateSandboxRequest{AllowPublicTraffic: privateFlag(true)},
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			9090: {},
		},
	}
	defaultIntents, defaultNeedL4 := svc.buildClusterIngressIntents([]cluster.Placement{defaultProtocolPlacement}, "self")
	if !defaultNeedL4 {
		t.Fatal("default protocol exposure should still need L4")
	}
	defaultKey := ingressIntentKey(ingressSurfaceTLS, caddy.IngressPortSNIRouteID("sb-default-protocol", 9090))
	if _, ok := defaultIntents[defaultKey]; !ok {
		t.Fatalf("default-protocol port intent missing: %s", defaultKey)
	}

	_ = routeShardFilterLogValue(cluster.IngressShardFilterForNode(nil, "self"))
}

func TestGCUnexpectedClusterIngressRoutes(t *testing.T) {
	ctx := context.Background()
	fake := newCountingCaddyFake(0)
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		EnableCaddy:       true,
		HTTPClientTimeout: time.Second,
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-gc", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	intents, _ := svc.buildClusterIngressIntents(nil, "self")
	if err := svc.gcUnexpectedClusterIngressRoutes(ctx, intents); err != nil {
		t.Fatalf("gcUnexpectedClusterIngressRoutes: %v", err)
	}
}

func TestBuildClusterIngressIntentsExecutesApplyAndDeleteClosures(t *testing.T) {
	ctx := context.Background()
	fake := newCountingCaddyFake(0)
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	caddyCfg := config.Config{
		EnableCaddy:       true,
		Domain:            "example.test",
		L4TLSListen:       ":8443",
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		HTTPClientTimeout: time.Second,
	}
	svc := &Service{
		cfg:    caddyCfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(caddyCfg),
	}

	desired, needL4 := svc.buildClusterIngressIntents([]cluster.Placement{
		{
			SandboxID:          "sb-live",
			OwnerNodeID:        "peer-1",
			OwnerAPIURL:        "http://10.0.0.7:21212",
			OwnerDataPlaneHost: "10.0.0.7",
			Version:            1,
			Spec:               &models.CreateSandboxRequest{AllowPublicTraffic: privateFlag(true)},
			CustomHostnames:    []string{"api.acme.com"},
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				8080: {Protocol: models.ExposedPortProtocolHTTP},
				5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 25432},
				8443: {Protocol: models.ExposedPortProtocolTLS},
				3306: {Protocol: models.ExposedPortProtocolTCP},
			},
		},
		{
			SandboxID:   "sb-flux",
			OwnerNodeID: "peer-2",
			Version:     2,
			Spec:        &models.CreateSandboxRequest{AllowPublicTraffic: privateFlag(true)},
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				9000: {Protocol: models.ExposedPortProtocolHTTP},
			},
		},
	}, "self")
	if !needL4 {
		t.Fatal("expected L4 to be required for cluster ingress intents")
	}
	ops, commit := svc.planClusterIngressDelta(desired)
	if len(ops) == 0 {
		t.Fatal("expected initial delta ops")
	}
	for i, op := range ops {
		if err := op(ctx); err != nil {
			t.Fatalf("apply op %d: %v", i, err)
		}
	}
	commit()

	if ops, _ = svc.planClusterIngressDelta(desired); len(ops) != 0 {
		t.Fatalf("identical desired state produced %d ops, want 0", len(ops))
	}

	ops, _ = svc.planClusterIngressDelta(map[string]ingressRouteIntent{})
	if len(ops) == 0 {
		t.Fatal("expected delete ops when desired state is empty")
	}
	for i, op := range ops {
		if err := op(ctx); err != nil {
			t.Fatalf("delete op %d: %v", i, err)
		}
	}
	if atomic.LoadInt64(&fake.totalCalls) == 0 {
		t.Fatal("expected caddy admin calls to be issued")
	}
}

func TestGCUnexpectedClusterIngressRoutesBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled caddy returns nil", func(t *testing.T) {
		svc := &Service{
			cfg:   config.Config{EnableCluster: true},
			caddy: caddy.New(config.Config{EnableCaddy: false}),
		}
		if err := svc.gcUnexpectedClusterIngressRoutes(ctx, nil); err != nil {
			t.Fatalf("disabled caddy: %v", err)
		}
	})

	t.Run("store list failure", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableCluster = true
		svc.caddy = caddy.New(config.Config{
			EnableCaddy:       true,
			CaddyAdminURL:     "http://127.0.0.1:1",
			CaddyServerID:     "srv0",
			HTTPClientTimeout: time.Second,
		})
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if err := svc.gcUnexpectedClusterIngressRoutes(ctx, nil); err == nil {
			t.Fatal("expected store list failure")
		}
	})

	t.Run("deletes unexpected entries", func(t *testing.T) {
		fake := newGCCaddyFake()
		fake.httpRouteIDs["sandbox-zombie"] = struct{}{}
		fake.httpRouteIDs["sandbox-zombie-port-3000"] = struct{}{}
		fake.l4TCPServerIDs["tcp-port-39999"] = struct{}{}
		fake.l4TLSRouteIDs["sandbox-zombie-port-8443-tls"] = struct{}{}
		server := httptest.NewServer(fake.handler(t))
		t.Cleanup(server.Close)

		svc := &Service{
			cfg: config.Config{EnableCluster: true},
			caddy: caddy.New(config.Config{
				EnableCaddy:       true,
				CaddyAdminURL:     server.URL,
				CaddyServerID:     "srv0",
				HTTPClientTimeout: time.Second,
			}),
		}
		if err := svc.gcUnexpectedClusterIngressRoutes(ctx, nil); err != nil {
			t.Fatalf("gcUnexpectedClusterIngressRoutes: %v", err)
		}
		if got := fake.keys(fake.httpRouteIDs); len(got) != 0 {
			t.Fatalf("unexpected HTTP routes remain: %v", got)
		}
		if got := fake.keys(fake.l4TCPServerIDs); len(got) != 0 {
			t.Fatalf("unexpected TCP servers remain: %v", got)
		}
		if got := fake.keys(fake.l4TLSRouteIDs); len(got) != 0 {
			t.Fatalf("unexpected TLS routes remain: %v", got)
		}
	})
}

// --- usage_live.go ---

func TestStartLiveUsageSamplerPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := newUsageService(&captureReporter{})
	svc.StartLiveUsageSampler(ctx) // interval 0 → no-op

	svc.cfg.FleetLiveSampleInterval = time.Millisecond
	svc.StartLiveUsageSampler(ctx) // no reporter wired in newUsageService... actually usageEnabled checks reporter

	r := &captureReporter{}
	svc = newUsageService(r)
	svc.cfg.FleetLiveSampleInterval = 10 * time.Millisecond
	svc.events = &docker.Client{}
	svc.StartLiveUsageSampler(ctx)
	time.Sleep(25 * time.Millisecond)

	svc2 := newUsageService(r)
	svc2.cfg.FleetLiveSampleInterval = time.Millisecond
	svc2.StartLiveUsageSampler(ctx) // no docker client → warn path
}

// --- template.go GC ---

func TestRunTemplateGCSweep(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newHealthHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = 24 * time.Hour
	now := time.Now().UTC()
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-gc-old", Image: "x", Status: models.TemplateStatusReady,
		CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour),
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	svc.runTemplateGC(ctx, now)

	ctx2, cancel := context.WithCancel(context.Background())
	svc.cfg.FirecrackerTemplateGCInterval = time.Millisecond
	svc.StartTemplateGC(ctx2)
	time.Sleep(5 * time.Millisecond)
	cancel()
}

// --- custom_domains.go persistCustomDomainsOnCreate ---

func TestPersistCustomDomainsOnCreate(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.example.com"))
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-cd-create", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.persistCustomDomainsOnCreate(ctx, "sb-cd-create", []string{"api.example.com", "www.example.com"}); err != nil {
		t.Fatalf("persistCustomDomainsOnCreate: %v", err)
	}
	domains, err := svc.ListCustomDomains(ctx, "sb-cd-create")
	if err != nil || len(domains) != 2 {
		t.Fatalf("ListCustomDomains = %v, %v", domains, err)
	}
	if err := svc.persistCustomDomainsOnCreate(ctx, "sb-cd-create", nil); err != nil {
		t.Fatalf("empty hostnames: %v", err)
	}
}

// --- l4wake.go ---

func TestReadProxyV1DestinationPort(t *testing.T) {
	cases := []struct {
		line    string
		want    int
		wantErr bool
	}{
		{"PROXY TCP4 1.2.3.4 5 6.7.8.9 443\n", 443, false},
		{"PROXY TCP6 ::1 12345 ::2 8080\n", 8080, false},
		{"PROXY UDP4 1.2.3.4 5 6.7.8.9 443\n", 0, true},
		{"NOTPROXY TCP4 1.2.3.4 5 6.7.8.9 443\n", 0, true},
		{"PROXY TCP4 1.2.3.4 5 6.7.8.9 99999\n", 0, true},
	}
	for _, tc := range cases {
		br := bufio.NewReaderSize(strings.NewReader(tc.line), l4WakeProxyHeaderMaxBytes)
		got, err := readProxyV1DestinationPort(br)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("line %q: expected error", tc.line)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("line %q: got (%d, %v), want %d", tc.line, got, err, tc.want)
		}
	}
	longLine := strings.Repeat("X", l4WakeProxyHeaderMaxBytes+10) + "\n"
	br := bufio.NewReaderSize(strings.NewReader(longLine), l4WakeProxyHeaderMaxBytes)
	if _, err := readProxyV1DestinationPort(br); err == nil {
		t.Fatal("expected buffer full error")
	}
}

func TestWakeAwareL4PortTargetErrors(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-l4", Image: "alpine", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.WakeAwareL4PortTarget(ctx, "sb-l4", 5432); err == nil {
		t.Fatal("stopped sandbox should fail wake")
	}
}

func TestStartL4WakeProxyDisabled(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	if err := svc.StartL4WakeProxy(context.Background()); err != nil {
		t.Fatalf("disabled: %v", err)
	}
}

func TestStartL4WakeProxyListenError(t *testing.T) {
	svc := &Service{
		cfg: config.Config{
			EnableServerless:   true,
			InternalL4WakeAddr: "not-a-real-listener-address",
		},
		caddy:  caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second}),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := svc.StartL4WakeProxy(context.Background()); err == nil {
		t.Fatal("expected listen error from invalid wake address")
	}
}

func TestHandleL4WakeTCPConnBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid header", func(t *testing.T) {
		svc := &Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			_, _ = client.Write([]byte("garbage\n"))
			_ = client.Close()
			close(done)
		}()
		svc.handleL4WakeTCPConn(server)
		<-done
	})

	t.Run("missing exposure and non-tcp exposure", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

		server, client := net.Pipe()
		go func(conn net.Conn) {
			_, _ = conn.Write([]byte("PROXY TCP4 1.2.3.4 5 6.7.8.9 40123\r\n"))
			_ = conn.Close()
		}(client)
		svc.handleL4WakeTCPConn(server)

		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:          "sb-l4-http",
			Image:       "alpine",
			Status:      models.SandboxStatusStarted,
			ContainerID: "ctr-l4-http",
			ContainerIP: "10.0.0.77",
			Runtime:     models.RuntimeDocker,
			CPU:         1,
			MemoryMB:    512,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if err := st.UpsertPort(ctx, models.ExposedPort{
			SandboxID: "sb-l4-http",
			Port:      8080,
			Protocol:  models.ExposedPortProtocolHTTP,
			HostPort:  40123,
			CreatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertPort: %v", err)
		}
		server, client = net.Pipe()
		go func(conn net.Conn) {
			_, _ = conn.Write([]byte("PROXY TCP4 1.2.3.4 5 6.7.8.9 40123\r\n"))
			_ = conn.Close()
		}(client)
		svc.handleL4WakeTCPConn(server)
	})
}

func TestProxyL4WakeConnDialError(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:          "sb-l4-proxy",
		Image:       "alpine",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-l4-proxy",
		ContainerIP: "10.0.0.88",
		Runtime:     models.RuntimeDocker,
		CPU:         1,
		MemoryMB:    512,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-l4-proxy",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  25432,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}

	setDialL4UpstreamForTest(t, func(context.Context, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("dial failed")
	})

	server, client := net.Pipe()
	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("ping"))
	}()
	svc.proxyL4WakeConn(ctx, "sb-l4-proxy", 5432, server, nil)
}

func TestTLSWakeListenerAcceptBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.InternalL4WakeDir = shortSockDir(t)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:          "sb-tls-accept",
		Image:       "alpine",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-tls-accept",
		ContainerIP: "10.0.0.99",
		Runtime:     models.RuntimeDocker,
		CPU:         1,
		MemoryMB:    512,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-tls-accept",
		Port:      8443,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  28443,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}

	setDialL4UpstreamForTest(t, func(context.Context, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("dial failed")
	})

	socketPath, err := svc.ensureTLSWakeListener("sb-tls-accept", 8443)
	if err != nil {
		t.Fatalf("ensureTLSWakeListener: %v", err)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix wake listener: %v", err)
	}
	_, _ = conn.Write([]byte("hello"))
	_ = conn.Close()
	time.Sleep(50 * time.Millisecond)
	svc.closeTLSWakeListener("sb-tls-accept", 8443)
}

// --- service.go create paths ---

func TestCreateSandboxWithIDValidationAndIdempotency(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)

	if _, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine"}, ""); err == nil {
		t.Fatal("empty id should error")
	}

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-fixed-id")
	if err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	resp2, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-fixed-id")
	if err != nil {
		t.Fatalf("idempotent CreateSandboxWithID: %v", err)
	}
	if resp2.Sandbox.ID != resp.Sandbox.ID {
		t.Fatalf("idempotent response = %q, want %q", resp2.Sandbox.ID, resp.Sandbox.ID)
	}
	if rt.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1 (second call is store hit)", rt.createCalls)
	}
}

func TestCreateSandboxValidationErrors(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{}); err == nil {
		t.Fatal("missing image should fail")
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine", Runtime: models.RuntimeKata,
	}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("kata runtime err = %v", err)
	}
	svc.cfg.EnableFirecracker = false
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine", Runtime: models.RuntimeFirecracker,
	}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("fc disabled err = %v", err)
	}
}

func TestEnsureClusterReadyWaitsForLeader(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}}
	svc.AttachCluster(&delayedLeaderCluster{Noop: cluster.NewNoop("self", "http://self", ""), delay: 10 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.EnsureClusterReady(ctx); err != nil {
		t.Fatalf("EnsureClusterReady: %v", err)
	}
	if !svc.clusterReady.Load() {
		t.Fatal("clusterReady latch not set")
	}
}

type delayedLeaderCluster struct {
	*cluster.Noop
	delay time.Duration
}

func (d *delayedLeaderCluster) Leader() string {
	time.Sleep(d.delay)
	return d.Noop.SelfNodeID()
}

func TestCapacityRequestFromSandboxGPU(t *testing.T) {
	sb := &models.Sandbox{
		CPU: 2, MemoryMB: 1024, DiskGB: 10,
		GPUs: &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 2},
	}
	req := capacityRequestFromSandbox(sb)
	if req.GPUs != 2 || req.GPUVendor != string(models.GPUVendorNVIDIA) {
		t.Fatalf("capacity req = %+v", req)
	}
	if got := capacityRequestFromSandbox(&models.Sandbox{CPU: 1, MemoryMB: 512}); got.GPUs != 0 {
		t.Fatalf("no gpu = %+v", got)
	}
}

// --- template_pull.go docker adapter ---

func TestNewTemplateArtifactPullDockerAdapter(t *testing.T) {
	adapter := NewTemplateArtifactPullDockerAdapter(&docker.Client{})
	if adapter == nil {
		t.Fatal("nil adapter")
	}
	_ = adapter // interface satisfied; PullImage/Export/Remove delegate to docker
}

func TestTemplateLocalFilesPresentAndChecksum(t *testing.T) {
	dir := t.TempDir()
	rootfs := filepath.Join(dir, templateRootfsFilename)
	mem := filepath.Join(dir, snapshotMemoryFilename)
	state := filepath.Join(dir, snapshotStateFilename)
	for _, p := range []string{rootfs, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tpl := &models.Template{RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state}
	if !templateLocalFilesPresent(dir, tpl) {
		t.Fatal("expected files present")
	}
	sum, err := computeSnapshotChecksum(mem, state)
	if err != nil || sum == "" {
		t.Fatalf("checksum = %q, %v", sum, err)
	}
	h, err := hashFileSHA256(rootfs)
	if err != nil || h == "" {
		t.Fatalf("hash = %q, %v", h, err)
	}
}

func TestWriteFileFromTar(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: "nested/file.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out.txt")
	if err := writeFileFromTar(tr, hdr.Size, dest); err != nil {
		t.Fatalf("writeFileFromTar: %v", err)
	}
}

// --- snapshot_push.go ---

func TestSnapshotPusherValidateAndReadPAT(t *testing.T) {
	if err := (SnapshotPushConfig{}).Validate(); err != nil {
		t.Fatalf("disabled config should pass validate: %v", err)
	}
	if err := (SnapshotPushConfig{Enabled: true}).Validate(); err == nil {
		t.Fatal("enabled config missing fields should fail validate")
	}
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := SnapshotPushConfig{Enabled: true, Host: "reg.example.com", ClusterID: "cl", PATPath: patFile}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	p, err := NewSnapshotPusher(cfg, &fakeSnapshotPushDocker{}, slog.Default())
	if err != nil {
		t.Fatalf("NewSnapshotPusher: %v", err)
	}
	if !SnapshotNeedsPush(&models.SandboxSnapshot{ImageDistributionMode: models.ImageDistributionLocalOnly}) {
		t.Fatal("local-only should need push")
	}
	if p.DestRefFor("snap") == "" {
		t.Fatal("DestRefFor empty")
	}
}

// --- acme_budget.go ---

func TestACMEBudgetThresholdMinimum(t *testing.T) {
	b := newBudgetForTest(1, time.Hour, 0.01, newFakeClock())
	if b.Threshold() < 1 {
		t.Fatalf("threshold = %d, want at least 1", b.Threshold())
	}
}

// --- fleet_control error aggregation ---

func TestFleetControlStopByOwnerSetFleetSuspendedError(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-fleet-err", OwnerRef: "acme", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, ContainerID: "ctr", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 512, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc.SetFleetAdmitter(stubAdmitter{deny: map[string]error{}})
	if err := svc.StopByOwner(ctx, "acme"); err != nil {
		t.Fatalf("StopByOwner: %v", err)
	}
}

// --- facade_state UpdateTags nil ---

func TestUpdateTagsNilTags(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-tags-nil", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.UpdateTags(ctx, "sb-tags-nil", nil); err != nil {
		t.Fatalf("UpdateTags nil: %v", err)
	}
}

// --- auto_import string helpers (already covered but ensure splitOnce false path) ---

func TestParseUpstreamFromRegistryRefEdgeCases(t *testing.T) {
	if h, r, _ := parseUpstreamFromRegistryRef("library/redis", ""); h != "" || r != "" {
		t.Fatalf("bare name should fail: %q %q", h, r)
	}
	if h, r, tag := parseUpstreamFromRegistryRef("ghcr.io/org/repo:tag", ""); h != "ghcr.io" || r != "org/repo" || tag != "tag" {
		t.Fatalf("got %q %q %q", h, r, tag)
	}
}

func TestAutoImportRequestFromSpecSkipsImported(t *testing.T) {
	_, ok := autoImportRequestFromSpec(&models.CreateSandboxRequest{
		ImageDigest:           "sha256:x",
		ImageDistributionMode: models.ImageDistributionAOCRImported,
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
	})
	if ok {
		t.Fatal("already imported spec should not retry")
	}
}
