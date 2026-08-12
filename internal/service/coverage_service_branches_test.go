package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type noContainerRuntime struct{}

func (noContainerRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, nil
}

func (noContainerRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return &models.SandboxRuntimeState{}, nil
}

func (noContainerRuntime) Stop(context.Context, string) error { return nil }

func (noContainerRuntime) Destroy(context.Context, *models.Sandbox) error { return nil }

func (noContainerRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}

func (noContainerRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}

func (noContainerRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return &models.SandboxRuntimeState{}, nil
}

func (noContainerRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return map[string]*models.SandboxRuntimeState{}, nil
}

func (noContainerRuntime) Ping(context.Context) error { return nil }

func (noContainerRuntime) RemoveImage(context.Context, string) error { return nil }

func (noContainerRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}

type wasmQuotaRuntime struct {
	*recordingRuntime
	networkBlocks []struct {
		sandboxID                 string
		blockIngress, blockEgress bool
	}
}

func (r *wasmQuotaRuntime) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) {
	r.networkBlocks = append(r.networkBlocks, struct {
		sandboxID                 string
		blockIngress, blockEgress bool
	}{sandboxID: sandboxID, blockIngress: blockIngress, blockEgress: blockEgress})
}

type serviceClusterStub struct {
	*cluster.Noop
	leader      string
	placements  []cluster.Placement
	specs       map[string]*models.CreateSandboxRequest
	deleteCalls []string
	members     []cluster.Member
	drained     map[string]bool
	owner       cluster.OwnerInfo
	ownerErr    error
	ownerCalls  []string
}

type failingTemplateArtifactPushStore struct {
	err error
}

func (s failingTemplateArtifactPushStore) ListTemplatesPendingPush(context.Context) ([]*models.Template, error) {
	return nil, s.err
}

func (s failingTemplateArtifactPushStore) SetTemplatePushState(context.Context, string, string, string) error {
	return nil
}

func (s failingTemplateArtifactPushStore) UpdateTemplatePushDistribution(context.Context, string, string, string) error {
	return nil
}

func (s *serviceClusterStub) Leader() string { return s.leader }

func (s *serviceClusterStub) Placements() []cluster.Placement {
	return append([]cluster.Placement(nil), s.placements...)
}

func (s *serviceClusterStub) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	byID := make(map[string]cluster.Placement, len(s.placements))
	for _, p := range s.placements {
		byID[p.SandboxID] = p
	}
	for _, id := range ids {
		if p, ok := byID[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (s *serviceClusterStub) PlacementsForShards(cluster.PlacementShardFilter) []cluster.Placement {
	return s.Placements()
}

func (s *serviceClusterStub) SpecOf(id string) *models.CreateSandboxRequest {
	if s.specs == nil {
		return nil
	}
	spec, ok := s.specs[id]
	if !ok || spec == nil {
		return nil
	}
	cp := *spec
	return &cp
}

func (s *serviceClusterStub) DeletePlacement(_ context.Context, sandboxID string) error {
	s.deleteCalls = append(s.deleteCalls, sandboxID)
	return nil
}

func (s *serviceClusterStub) OwnerOf(sandboxID string) (cluster.OwnerInfo, error) {
	s.ownerCalls = append(s.ownerCalls, sandboxID)
	if s.ownerErr != nil {
		return cluster.OwnerInfo{}, s.ownerErr
	}
	if s.owner.NodeID != "" || s.owner.APIURL != "" || s.owner.IsSelf {
		return s.owner, nil
	}
	return cluster.OwnerInfo{NodeID: s.SelfNodeID(), APIURL: s.SelfAPIURL(), IsSelf: true}, nil
}

func (s *serviceClusterStub) IsNodeDrained(nodeID string) bool {
	if s.drained == nil {
		return false
	}
	return s.drained[nodeID]
}

func (s *serviceClusterStub) Members() []cluster.Member {
	if len(s.members) > 0 {
		return append([]cluster.Member(nil), s.members...)
	}
	return s.Noop.Members()
}

func (s *serviceClusterStub) LocalMembers() []cluster.Member { return s.Members() }

func TestServiceHelperBranchesAndInventory(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	svc.AttachCluster(nil)
	if svc.Cluster() != nil {
		t.Fatal("AttachCluster(nil) should be a no-op")
	}
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	svc.ClearClusterForTest()
	if svc.Cluster() != nil {
		t.Fatal("ClearClusterForTest should detach the cluster client")
	}

	svc.docker = &recordingRuntime{}
	if rt, err := svc.runtimeForSandbox(nil); err != nil || rt != svc.docker {
		t.Fatalf("runtimeForSandbox(nil) = (%T, %v), want docker runtime", rt, err)
	}
	if rt, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeDocker}); err != nil || rt != svc.docker {
		t.Fatalf("runtimeForSandbox(docker) = (%T, %v), want docker runtime", rt, err)
	}
	if _, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeFirecracker}); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("runtimeForSandbox(firecracker without driver) = %v, want ErrRuntimeNotImplemented", err)
	}
	svc.SetFirecrackerRuntime(&recordingRuntime{})
	if rt, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeFirecracker}); err != nil || rt != svc.firecracker {
		t.Fatalf("runtimeForSandbox(firecracker) = (%T, %v), want firecracker runtime", rt, err)
	}
	if _, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeWasm}); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("runtimeForSandbox(wasm without driver) = %v, want ErrRuntimeNotImplemented", err)
	}
	svc.SetWasmRuntime(&recordingRuntime{})
	if rt, err := svc.runtimeForSandbox(&models.Sandbox{Runtime: models.RuntimeWasm}); err != nil || rt != svc.wasm {
		t.Fatalf("runtimeForSandbox(wasm) = (%T, %v), want wasm runtime", rt, err)
	}

	if _, err := svc.containerRuntimeForSandbox(&models.Sandbox{Runtime: models.RuntimeDocker}); err != nil {
		t.Fatalf("containerRuntimeForSandbox(docker) = %v, want nil", err)
	}
	svc.docker = noContainerRuntime{}
	if _, err := svc.containerRuntimeForSandbox(&models.Sandbox{Runtime: models.RuntimeDocker}); err == nil || !strings.Contains(err.Error(), "does not support container network rules") {
		t.Fatalf("containerRuntimeForSandbox without container surface = %v", err)
	}

	svc.AttachWasmCheckpointPusher(nil)
	if svc.wasmCheckpointPusher != nil {
		t.Fatal("AttachWasmCheckpointPusher(nil) should be a no-op")
	}
	ck := &recordingCheckpointStore{destRef: "test://checkpoint"}
	svc.AttachWasmCheckpointPusher(ck)
	if svc.wasmCheckpointPusher != ck {
		t.Fatal("AttachWasmCheckpointPusher should store the pusher")
	}

	if got := sandboxContainerRef(nil); got != "" {
		t.Fatalf("sandboxContainerRef(nil) = %q, want empty", got)
	}
	if got := sandboxContainerRef(&models.Sandbox{ContainerID: "ctr-123"}); got != "ctr-123" {
		t.Fatalf("sandboxContainerRef = %q, want ctr-123", got)
	}

	if got, known := (&Service{store: st}).LocalReadyWasmModuleInventory(ctx); got != nil || known {
		t.Fatalf("LocalReadyWasmModuleInventory without EnableWasm = (%v, %v), want nil/false", got, known)
	}
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID:        "mod-1",
		ModuleRef: "file:///tmp/mod-1.wasm",
		Status:    string(models.WasmModuleStatusReady),
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
	svc.cfg.EnableWasm = true
	refs, known := svc.LocalReadyWasmModuleInventory(ctx)
	if !known || len(refs) != 1 || refs[0] != "file:///tmp/mod-1.wasm" {
		t.Fatalf("LocalReadyWasmModuleInventory = (%v, %v), want one ready ref", refs, known)
	}
	refs[0] = "mutated"
	cached, known := svc.LocalReadyWasmModuleInventory(ctx)
	if !known || len(cached) != 1 || cached[0] != "file:///tmp/mod-1.wasm" {
		t.Fatalf("LocalReadyWasmModuleInventory cache returned %v, want original ref", cached)
	}
	cap := svc.Capacity()
	if !cap.LocalWasmModuleInventoryKnown || len(cap.LocalWasmModuleIDs) != 1 || cap.LocalWasmModuleIDs[0] != "file:///tmp/mod-1.wasm" {
		t.Fatalf("Capacity overlay = %+v, want wasm module inventory", cap)
	}

	svc.cfg.ImageBuildGCEnabled = false
	svc.StartBuiltImageGC(ctx)
	svc.StartPendingImageGC(ctx)
	svc.cfg.ImageBuildGCEnabled = true
	svc.cfg.ImageBuildGCInterval = time.Millisecond
	svc.events = nil
	svc.StartBuiltImageGC(ctx)
	svc.cfg.ImageBuildGCInterval = 0
	svc.StartPendingImageGC(ctx)
	svc.cfg.EnableCluster = true
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc.StartClusterIngressReconcile(ctx)
}

func TestAddClusterIngressExpectedRoutesBranches(t *testing.T) {
	t.Run("domain mode", func(t *testing.T) {
		svc := &Service{cfg: config.Config{EnableCluster: true, Domain: "sandbox.test"}}
		svc.AttachCluster(&serviceClusterStub{
			Noop: cluster.NewNoop("self", "http://self", "sandbox.test"),
			placements: []cluster.Placement{
				{
					SandboxID:   "sb-orphan",
					OwnerNodeID: "",
					ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
						8080: {Protocol: models.ExposedPortProtocolHTTP},
						8443: {Protocol: models.ExposedPortProtocolTLS},
						5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 33333},
					},
				},
				{
					SandboxID:       "sb-peer",
					OwnerNodeID:     "peer",
					CustomHostnames: []string{"api.external.test", "www.external.test"},
					ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
						8080: {Protocol: models.ExposedPortProtocolHTTP},
						8443: {Protocol: models.ExposedPortProtocolTLS},
						5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 32345},
					},
				},
			},
		})
		httpExp := map[string]struct{}{}
		tcpExp := map[string]struct{}{}
		tlsExp := map[string]struct{}{}
		svc.addClusterIngressExpectedRoutes(httpExp, tcpExp, tlsExp)
		for _, routeID := range []string{
			caddy.InFluxSandboxRouteID("sb-orphan"),
			caddy.InFluxPortRouteID("sb-orphan", 8080),
			caddy.InFluxPortRouteID("sb-orphan", 8443),
		} {
			if _, ok := httpExp[routeID]; !ok {
				t.Fatalf("missing in-flux route %q in %#v", routeID, httpExp)
			}
		}
		for _, routeID := range []string{
			caddy.IngressSandboxSNIRouteID("sb-peer"),
			caddy.IngressCustomDomainSNIRouteID("sb-peer", "api.external.test"),
			caddy.IngressCustomDomainSNIRouteID("sb-peer", "www.external.test"),
			caddy.IngressPortSNIRouteID("sb-peer", 8080),
			caddy.IngressPortSNIRouteID("sb-peer", 8443),
		} {
			if _, ok := tlsExp[routeID]; !ok {
				t.Fatalf("missing TLS route %q in %#v", routeID, tlsExp)
			}
		}
		if _, ok := tcpExp["tcp-port-32345"]; !ok {
			t.Fatalf("missing TCP server route in %#v", tcpExp)
		}
	})

	t.Run("no domain mode", func(t *testing.T) {
		svc := &Service{cfg: config.Config{EnableCluster: true}}
		svc.AttachCluster(&serviceClusterStub{
			Noop: cluster.NewNoop("self", "http://self", ""),
			placements: []cluster.Placement{
				{
					SandboxID:   "sb-direct",
					OwnerNodeID: "peer",
					ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
						8080: {Protocol: models.ExposedPortProtocolHTTP},
						8443: {Protocol: models.ExposedPortProtocolTLS},
					},
				},
			},
		})
		httpExp := map[string]struct{}{}
		tcpExp := map[string]struct{}{}
		tlsExp := map[string]struct{}{}
		svc.addClusterIngressExpectedRoutes(httpExp, tcpExp, tlsExp)
		for _, routeID := range []string{"sandbox-sb-direct", "sandbox-sb-direct-port-8080"} {
			if _, ok := httpExp[routeID]; !ok {
				t.Fatalf("missing direct HTTP route %q in %#v", routeID, httpExp)
			}
		}
		if len(tlsExp) != 0 {
			t.Fatalf("expected no TLS routes without domain mode, got %#v", tlsExp)
		}
	})
}

func TestApplyNetworkQuotaStateBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	wrt := &wasmQuotaRuntime{recordingRuntime: &recordingRuntime{}}
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(wrt)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:                   "sb-wasm-quota",
		Image:                "hello.wasm",
		Runtime:              models.RuntimeWasm,
		Status:               models.SandboxStatusStarted,
		ContainerIP:          "10.0.0.99",
		CPU:                  1,
		MemoryMB:             256,
		DiskGB:               5,
		NetworkQuotaExceeded: true,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	wasmRow, err := st.Get(ctx, "sb-wasm-quota")
	if err != nil {
		t.Fatalf("store.Get(): %v", err)
	}
	svc.applyNetworkQuotaState(ctx, wasmRow, true, true)
	if len(wrt.networkBlocks) != 1 || !wrt.networkBlocks[0].blockIngress || !wrt.networkBlocks[0].blockEgress {
		t.Fatalf("wasm network blocks = %+v, want ingress+egress block", wrt.networkBlocks)
	}
	refreshed, err := st.Get(ctx, "sb-wasm-quota")
	if err != nil {
		t.Fatalf("store.Get() after mark: %v", err)
	}
	if !refreshed.NetworkQuotaExceeded {
		t.Fatal("wasm sandbox should be marked over quota")
	}
	svc.applyNetworkQuotaState(ctx, refreshed, false, false)
	if len(wrt.networkBlocks) != 2 || wrt.networkBlocks[1].blockIngress || wrt.networkBlocks[1].blockEgress {
		t.Fatalf("wasm network blocks after clear = %+v, want clear call", wrt.networkBlocks)
	}
	cleared, err := st.Get(ctx, "sb-wasm-quota")
	if err != nil {
		t.Fatalf("store.Get() after clear: %v", err)
	}
	if cleared.NetworkQuotaExceeded {
		t.Fatal("wasm sandbox quota flag should clear")
	}

	if err := st.Create(ctx, &models.Sandbox{
		ID:                   "sb-no-ip-quota",
		Image:                "alpine",
		Runtime:              models.RuntimeDocker,
		Status:               models.SandboxStatusStopped,
		NetworkQuotaExceeded: true,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActiveAt:         now,
	}); err != nil {
		t.Fatalf("seed docker sandbox: %v", err)
	}
	dockerRow, err := st.Get(ctx, "sb-no-ip-quota")
	if err != nil {
		t.Fatalf("store.Get() docker row: %v", err)
	}
	svc.applyNetworkQuotaState(ctx, dockerRow, false, false)
	if got, err := st.Get(ctx, "sb-no-ip-quota"); err != nil {
		t.Fatalf("store.Get() after docker clear: %v", err)
	} else if got.NetworkQuotaExceeded {
		t.Fatal("docker quota flag should clear even without a container IP")
	}
}

func TestStartBuiltImageGCAndLifecycleSweepEnabledPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &Service{
		cfg: config.Config{
			ImageBuildGCEnabled:  true,
			ImageBuildGCInterval: time.Hour,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		events: &docker.Client{},
	}
	svc.StartBuiltImageGC(ctx)

	lifecycleSvc := &Service{
		cfg: config.Config{
			IdleTimeoutMinutes: 1,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	lifecycleSvc.StartLifecycleSweep(ctx)
	cancel()
	time.Sleep(10 * time.Millisecond)
}

func TestServicePureHelperBranches(t *testing.T) {
	if got := capacityRequestFromSandbox(nil); got != (capacity.Request{}) {
		t.Fatalf("capacityRequestFromSandbox(nil) = %+v, want zero value", got)
	}

	sb := &models.Sandbox{
		Runtime:       models.RuntimeFirecracker,
		CPU:           2,
		MemoryMB:      512,
		DiskGB:        4,
		OverlaySizeGB: 3,
		ModuleRef:     "module://demo",
	}
	req := capacityRequestFromSandbox(sb)
	if req.DiskGB != 7 || req.MemoryMB != 512 || req.ModuleRef != "module://demo" {
		t.Fatalf("capacityRequestFromSandbox(firecracker) = %+v", req)
	}

	failover := &models.CreateSandboxRequest{}
	if err := NormalizeCreateFailover(failover); err != nil || failover.Failover != nil {
		t.Fatalf("NormalizeCreateFailover(nil policy) = %+v, %v", failover, err)
	}
	none := &models.CreateSandboxRequest{Failover: &models.Failover{Policy: models.FailoverPolicyNone}}
	if err := NormalizeCreateFailover(none); err != nil || none.Failover != nil {
		t.Fatalf("NormalizeCreateFailover(none) = %+v, %v", none, err)
	}
	localOnly := &models.CreateSandboxRequest{
		Image:    "aerolvm-build/demo:latest",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	if err := NormalizeCreateFailover(localOnly); err == nil {
		t.Fatal("NormalizeCreateFailover(local-only recreate) should fail")
	}

	token, err := generateToolboxToken()
	if err != nil || len(token) != 64 {
		t.Fatalf("generateToolboxToken() = %q, %v", token, err)
	}
	sa, sk, err := generateSandboxSSHKeys()
	if err != nil || sa == "" || sk == "" {
		t.Fatalf("generateSandboxSSHKeys() = (%q,%q,%v)", sa, sk, err)
	}

	if got := hostFromURL("https://example.test:8443/path"); got != "example.test" {
		t.Fatalf("hostFromURL = %q", got)
	}
	if got := l4ListenPort("127.0.0.1:4444"); got != 4444 {
		t.Fatalf("l4ListenPort = %d", got)
	}
}

func TestServiceOwnershipAndHealthBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	// DeleteSelfOwnedClusterPlacement should be a no-op without cluster.
	svc.deleteSelfOwnedClusterPlacement(ctx, "sb-none", "reason")

	// And it should ignore non-self owners.
	other := &serviceClusterStub{
		Noop:  cluster.NewNoop("self", "http://self", ""),
		owner: cluster.OwnerInfo{NodeID: "peer", APIURL: "http://peer", IsSelf: false},
	}
	svc.cfg.EnableCluster = true
	svc.AttachCluster(other)
	svc.deleteSelfOwnedClusterPlacement(ctx, "sb-peer", "reason")
	if len(other.deleteCalls) != 0 {
		t.Fatalf("non-self placement should not be deleted, got %v", other.deleteCalls)
	}

	// Self-owned placement should be deleted.
	selfOwned := &serviceClusterStub{
		Noop:  cluster.NewNoop("self", "http://self", ""),
		owner: cluster.OwnerInfo{NodeID: "self", APIURL: "http://self", IsSelf: true},
	}
	svc.AttachCluster(selfOwned)
	svc.deleteSelfOwnedClusterPlacement(ctx, "sb-self", "reason")
	if len(selfOwned.deleteCalls) != 1 || selfOwned.deleteCalls[0] != "sb-self" {
		t.Fatalf("self-owned placement delete calls = %v", selfOwned.deleteCalls)
	}

	// Reconcile stale ownership should destroy local sandboxes that no
	// longer belong to this node.
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-stale",
		Image:        "alpine",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerID:  "ctr-stale",
		ContainerIP:  "10.0.0.80",
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	stale := &serviceClusterStub{
		Noop:  cluster.NewNoop("self", "http://self", ""),
		owner: cluster.OwnerInfo{NodeID: "peer", APIURL: "http://peer", IsSelf: false},
	}
	svc.AttachCluster(stale)
	svc.reconcileStaleOwnership(ctx)
	if len(stale.ownerCalls) == 0 {
		t.Fatal("reconcileStaleOwnership should consult owner mapping")
	}
	if _, err := st.Get(ctx, "sb-stale"); err == nil {
		t.Fatal("stale sandbox should have been destroyed")
	}

	// Health should surface degraded probes, including the SSH gateway.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	svc.cfg.EnableSSHGateway = true
	svc.cfg.SSHListenAddr = addr
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableWasm = true
	svc.docker = &recordingRuntime{pingErr: errors.New("docker down")}
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc.SetFirecrackerRuntime(&recordingRuntime{health: "degraded"})
	svc.SetWasmRuntime(&recordingRuntime{pingErr: errors.New("wasm down")})
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-health-degraded",
		Image:        "alpine",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerID:  "ctr-health",
		ContainerIP:  "10.0.0.81",
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	health, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health(degraded): %v", err)
	}
	if health.Docker != "docker down" || health.Firecracker != "degraded" || health.Wasm != "wasm down" || health.SSHGateway == "ok" {
		t.Fatalf("health = %+v", health)
	}
}

func TestServiceClusterAndHealthBranches(t *testing.T) {
	t.Run("ensure cluster ready waits for leader", func(t *testing.T) {
		svc := &Service{cfg: config.Config{EnableCluster: true}}
		svc.AttachCluster(&serviceClusterStub{
			Noop:   cluster.NewNoop("self", "http://self", ""),
			leader: "",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		defer cancel()
		err := svc.EnsureClusterReady(ctx)
		if err == nil || !strings.Contains(err.Error(), "no leader yet") {
			t.Fatalf("EnsureClusterReady() error = %v, want no-leader error", err)
		}
	})

	t.Run("reconcile missing self-owned placements", func(t *testing.T) {
		ctx := context.Background()
		svc := &Service{cfg: config.Config{EnableCluster: true}}
		stub := &serviceClusterStub{
			Noop: cluster.NewNoop("self", "http://self", ""),
			placements: []cluster.Placement{
				{SandboxID: "sb-delete", OwnerNodeID: "self", OwnerState: cluster.PlacementOwnerStateActive, State: cluster.PlacementStatePlaced},
				{SandboxID: "sb-skip", OwnerNodeID: "self", OwnerState: cluster.PlacementOwnerStateActive, State: cluster.PlacementStatePlaced},
				{SandboxID: "sb-peer", OwnerNodeID: "peer", OwnerState: cluster.PlacementOwnerStateActive, State: cluster.PlacementStatePlaced},
			},
			specs: map[string]*models.CreateSandboxRequest{
				"sb-skip": {Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}},
			},
		}
		svc.AttachCluster(stub)
		svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})
		if len(stub.deleteCalls) != 1 || stub.deleteCalls[0] != "sb-delete" {
			t.Fatalf("delete calls = %#v, want only sb-delete", stub.deleteCalls)
		}
	})

	t.Run("health and start hooks", func(t *testing.T) {
		ctx := context.Background()
		rt := &recordingRuntime{}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		svc.docker = &fakeCapacityRuntime{}
		svc.SetFirecrackerRuntime(&fakeCapacityRuntime{})
		svc.SetWasmRuntime(&fakeCapacityRuntime{})
		svc.cfg.EnableFirecracker = true
		svc.cfg.EnableWasm = true
		svc.cfg.EnableSSHGateway = true
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer ln.Close()
		svc.cfg.SSHListenAddr = ln.Addr().String()

		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-health",
			Image:        "alpine",
			Status:       models.SandboxStatusStarted,
			Runtime:      models.RuntimeDocker,
			ContainerID:  "ctr-health",
			ContainerIP:  "10.0.0.50",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}

		health, err := svc.Health(ctx)
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		if health.Status != "ok" || health.Docker != "ok" || health.Caddy != "ok" || health.Firecracker != "ok" || health.Wasm != "ok" || health.SSHGateway != "ok" {
			t.Fatalf("health = %+v, want fully ok", health)
		}
		if health.Sandboxes != 1 {
			t.Fatalf("health sandboxes = %d, want 1", health.Sandboxes)
		}

		svc.cfg.ImageBuildGCEnabled = false
		svc.StartBuiltImageGC(ctx)
		svc.StartPendingImageGC(ctx)
		svc.cfg.EnableCluster = true
		svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
		svc.StartClusterIngressReconcile(ctx)
	})
}

func TestServiceHelperBranchCoverageRoundTwo(t *testing.T) {
	ctx := context.Background()

	t.Run("mount and template push helpers", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-mounts",
			Image:        "alpine",
			Status:       models.SandboxStatusStarted,
			Runtime:      models.RuntimeDocker,
			ContainerID:  "ctr-mounts",
			ContainerIP:  "10.0.0.91",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if _, err := svc.ListMounts(ctx, "sb-mounts"); err == nil {
			t.Fatal("closed store should fail ListMounts")
		}

		svc = &Service{
			templateArtifactPusher: &TemplateArtifactPusher{},
			store:                  st,
			logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if svc.markTemplateForPush(ctx, "tpl-missing") {
			t.Fatal("closed store should not mark template for push")
		}

		r := &TemplateArtifactPushReconciler{
			pusher:      &TemplateArtifactPusher{},
			store:       failingTemplateArtifactPushStore{err: errors.New("push list failed")},
			logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			maxInFlight: 1,
		}
		svc.templateArtifactPushReconciler = r
		svc.kickTemplateArtifactPushReconciler("tpl-missing")
		time.Sleep(20 * time.Millisecond)
	})

	t.Run("cluster ownership and gc helpers", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableCluster = true
		svc.cfg.ImageBuildGCEnabled = true
		svc.cfg.ImageGCWhitelist = []string{"whitelisted:latest"}
		svc.admitter = nil

		svc.deleteSelfOwnedClusterPlacement(ctx, "", "empty")
		svc.deleteSelfOwnedClusterPlacement(ctx, "sb-none", "no-cluster")

		nonSelf := &serviceClusterStub{
			Noop:     cluster.NewNoop("self", "http://self", ""),
			owner:    cluster.OwnerInfo{NodeID: "peer", APIURL: "http://peer", IsSelf: false},
			ownerErr: errors.New("owner lookup failed"),
		}
		svc.AttachCluster(nonSelf)
		svc.deleteSelfOwnedClusterPlacement(ctx, "sb-peer", "peer")

		selfOwned := &serviceClusterStub{
			Noop:  cluster.NewNoop("self", "http://self", ""),
			owner: cluster.OwnerInfo{NodeID: "self", APIURL: "http://self", IsSelf: true},
		}
		svc.AttachCluster(selfOwned)
		svc.deleteSelfOwnedClusterPlacement(ctx, "sb-self", "self")
		if len(selfOwned.deleteCalls) != 1 || selfOwned.deleteCalls[0] != "sb-self" {
			t.Fatalf("delete calls = %v, want [sb-self]", selfOwned.deleteCalls)
		}

		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.ReplayReservations(ctx)
		svc.refreshPendingImageGCOnUse(ctx, "alpine:latest")
		svc.schedulePendingImageGC(ctx, "alpine:latest")
		if err := svc.gcClusterIngressRoutes(ctx); err == nil {
			t.Fatal("closed store should fail gcClusterIngressRoutes")
		}
	})

	t.Run("toolbox and wake targets", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-toolbox",
			Image:        "alpine",
			Status:       models.SandboxStatusStarted,
			Runtime:      models.RuntimeDocker,
			ContainerID:  "ctr-toolbox",
			ContainerIP:  "",
			CPU:          1,
			MemoryMB:     256,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed sandbox: %v", err)
		}
		svc.cfg.ToolboxPort = 4242
		if _, err := svc.ToolboxTarget(ctx, "sb-toolbox"); err == nil {
			t.Fatal("missing container IP should fail ToolboxTarget")
		}
		if _, err := svc.WakeAwarePortTarget(ctx, "sb-toolbox", 8080); err == nil {
			t.Fatal("missing container IP should fail WakeAwarePortTarget")
		}
	})
}

func TestFleetControllerOwnerActions(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-owner",
		Image:        "alpine",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerID:  "ctr-owner",
		ContainerIP:  "10.0.0.60",
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		OwnerRef:     "acct-1",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if err := svc.StopByOwner(ctx, "acct-1"); err != nil {
		t.Fatalf("StopByOwner: %v", err)
	}
	stopped, err := st.Get(ctx, "sb-owner")
	if err != nil {
		t.Fatalf("Get after StopByOwner: %v", err)
	}
	if stopped.Status != models.SandboxStatusStopped || !stopped.FleetSuspended {
		t.Fatalf("stopped row = %+v, want fleet-suspended stopped", stopped)
	}

	if err := svc.RestoreByOwner(ctx, "acct-1"); err != nil {
		t.Fatalf("RestoreByOwner: %v", err)
	}
	restored, err := st.Get(ctx, "sb-owner")
	if err != nil {
		t.Fatalf("Get after RestoreByOwner: %v", err)
	}
	if restored.Status != models.SandboxStatusStarted || restored.FleetSuspended {
		t.Fatalf("restored row = %+v, want fleet-suspended cleared", restored)
	}

	if err := svc.DeleteByOwner(ctx, "acct-1"); err != nil {
		t.Fatalf("DeleteByOwner: %v", err)
	}
	if _, err := st.Get(ctx, "sb-owner"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after DeleteByOwner = %v, want not found", err)
	}

	if err := svc.FireWebhook(ctx, "acct-1", "notify"); err != nil {
		t.Fatalf("FireWebhook: %v", err)
	}
}

func TestStartPendingImageGCRunsAtLeastOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	svc.cfg.ImageBuildGCTTL = time.Millisecond
	svc.cfg.ImageBuildGCInterval = time.Millisecond
	seedPending(t, st, "alpine:latest", time.Now().UTC().Add(-2*time.Hour))

	svc.StartPendingImageGC(ctx)
	time.Sleep(30 * time.Millisecond)
	cancel()

	if len(*removed) == 0 {
		t.Fatal("expected pending image GC to run at least once")
	}
}

func TestStartClusterIngressReconcileEnabledPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &Service{
		cfg:    config.Config{EnableCluster: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))

	svc.StartClusterIngressReconcile(ctx)
	time.Sleep(20 * time.Millisecond)
}
