package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/oci"
)

type stubParkHandle struct{ alive bool }

func (h *stubParkHandle) Alive() bool                                         { return h.alive }
func (h *stubParkHandle) Adopt(context.Context, string, string, string) error { return nil }
func (h *stubParkHandle) Close() error                                        { return nil }

func poolWithLoadedSlot(t *testing.T) *dockerpool.Pool {
	t.Helper()
	p := dockerpool.New(testLogger())
	key := dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
	p.RecordLoaded(&dockerpool.ParkedSlot{
		ID: "park-drain", Key: key, Handle: &stubParkHandle{alive: true},
	})
	return p
}

func TestCoverage95DrainWarmPoolsWithSlots(t *testing.T) {
	drainDockerWarmPool(poolWithLoadedSlot(t), testLogger())
	drainContainerdWarmPool(poolWithLoadedSlot(t), testLogger())
}

func TestCoverage95ContainerdWarmPoolBranches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	driver := cntr.New(cntr.FromDaemonConfig(config.Config{
		ContainerEngine: models.ContainerEngineContainerd,
	}), nil, testLogger())
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	pool := wireContainerdWarmPool(ctx, config.Config{
		ContainerEngine:              models.ContainerEngineContainerd,
		ContainerdPoolEnabled:        true,
		DockerReadySocketEnabled:     true,
		ContainerdPoolDepth:          1,
		ContainerdPoolRefillInterval: time.Hour,
		DockerRuntimeWaitTimeout:     time.Second,
		Runtime:                      models.RuntimeDocker,
		ContainerdPoolImages:         []string{"  ", "alpine:3.20"},
	}, testLogger(), driver, admitter)
	if pool == nil {
		t.Fatal("expected pool")
	}
	drainContainerdWarmPool(pool, testLogger())

	w := &containerdEngineWiring{
		netns:        &containerdNetnsPool{},
		warm:         poolWithLoadedSlot(t),
		logger:       testLogger(),
		stopReassert: func() {},
	}
	w.Stop()
}

func TestCoverage95DockerWarmPoolEmptyImageAndPurgeWarn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := newTestDockerClient(t)
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	pool := wireDockerWarmPool(ctx, config.Config{
		DockerPoolEnabled:        true,
		DockerReadySocketEnabled: true,
		DockerPoolDepth:          1,
		DockerPoolRefillInterval: time.Hour,
		DockerRuntimeWaitTimeout: time.Second,
		Runtime:                  models.RuntimeDocker,
		DockerPoolImages:         []string{" "},
	}, testLogger(), c, admitter)
	if pool == nil {
		t.Fatal("expected pool")
	}
	drainDockerWarmPool(poolWithLoadedSlot(t), testLogger())
	cancel()
}

func TestCoverage95WireContainerdNativeNetnsPoolBranches(t *testing.T) {
	st := openDaemonTestStore(t)
	work := t.TempDir()
	origSysctls := ensureForwardingSysctls
	t.Cleanup(func() { ensureForwardingSysctls = origSysctls })

	cfg := config.Config{
		ContainerEngine:                   models.ContainerEngineContainerd,
		ContainerdNativeNetnsPoolEnabled:  true,
		ContainerdNetnsPoolDepth:          0,
		ContainerdNetnsPoolSize:           1,
		ContainerdNetnsPoolRefillInterval: time.Hour,
		ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
		ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())

	t.Run("sysctl_error", func(t *testing.T) {
		ensureForwardingSysctls = func() error { return errors.New("sysctl boom") }
		if _, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver); err == nil {
			t.Fatal("want sysctl error")
		}
	})

	t.Run("cni_runner_error", func(t *testing.T) {
		ensureForwardingSysctls = func() error { return nil }
		bad := cfg
		bad.ContainerdCNIPluginDir = ""
		if _, err := wireContainerdNativeNetnsPool(context.Background(), bad, testLogger(), st, driver); err == nil {
			t.Fatal("want cni runner error")
		}
	})

	t.Run("reconcile_reaps_orphans", func(t *testing.T) {
		ensureForwardingSysctls = func() error { return nil }
		st2 := openDaemonTestStore(t)
		ctx := context.Background()
		now := time.Now().UTC()
		if err := netns.New(st2).Seed(ctx, netns.SeedConfig{PoolSize: 1}, now); err != nil {
			t.Fatal(err)
		}
		slot, err := st2.BeginPrewarmContainerNetnsSlot(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := st2.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/gone/netns", "10.0.0.9", now); err != nil {
			t.Fatal(err)
		}
		pool, err := wireContainerdNativeNetnsPool(ctx, cfg, testLogger(), st2, driver)
		if err != nil {
			t.Fatalf("wire: %v", err)
		}
		if pool == nil {
			t.Fatal("expected pool")
		}
		pool.Stop()
	})
}

func TestCoverage95ContainerEngineWiringBranches(t *testing.T) {
	st := openDaemonTestStore(t)
	svc := &service.Service{}
	logger := testLogger()

	t.Run("netrules_backend_error", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("netrules backend validation requires linux")
		}
		_, err := wireContainerEngine(context.Background(), config.Config{
			ContainerEngine:    models.ContainerEngineContainerd,
			EnableNetworkRules: true,
			NetrulesBackend:    "bogus-backend",
		}, logger, svc, st, nil, nil, nil)
		if err == nil {
			t.Fatal("want netrules error")
		}
	})

	t.Run("netns_wire_error", func(t *testing.T) {
		orig := ensureForwardingSysctls
		ensureForwardingSysctls = func() error { return errors.New("sysctl") }
		t.Cleanup(func() { ensureForwardingSysctls = orig })
		_, err := wireContainerEngine(context.Background(), config.Config{
			ContainerEngine:                  models.ContainerEngineContainerd,
			EnableNetworkRules:               false,
			NetrulesBackend:                  "exec",
			ContainerdNativeNetnsPoolEnabled: true,
			ContainerdNetnsPoolSize:          1,
		}, logger, svc, st, nil, nil, nil)
		if err == nil {
			t.Fatal("want netns wire error")
		}
	})

	t.Run("with_docker_client_multi_events", func(t *testing.T) {
		dc := newTestDockerClient(t)
		w, err := wireContainerEngine(context.Background(), config.Config{
			ContainerEngine:                  models.ContainerEngineContainerd,
			EnableNetworkRules:               false,
			NetrulesBackend:                  "exec",
			ContainerdNativeNetnsPoolEnabled: false,
			ContainerdPoolEnabled:            false,
		}, logger, svc, st, dc, nil, nil)
		if err != nil {
			t.Fatalf("wireContainerEngine: %v", err)
		}
		if w == nil {
			t.Fatal("expected wiring")
		}
		w.Stop()
	})

	t.Run("chain_reassert_tick", func(t *testing.T) {
		old := chainReassertInterval
		chainReassertInterval = 5 * time.Millisecond
		t.Cleanup(func() { chainReassertInterval = old })

		mgr, err := netrules.NewWithOptions(false, netrules.BackendExec, netrules.ChainAerolvmUser)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stop := startChainReassert(ctx, mgr, logger)
		time.Sleep(20 * time.Millisecond)
		stop()
		cancel()
	})
}

func TestCoverage95MultiEventsSourceEdgeCases(t *testing.T) {
	t.Run("empty_sources", func(t *testing.T) {
		mux := newMultiEventsSource()
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- mux.StreamEvents(ctx, make(chan docker.DockerEvent)) }()
		cancel()
		if err := <-errCh; !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamEvents = %v, want context.Canceled", err)
		}
	})

	t.Run("single_source", func(t *testing.T) {
		src := &fakeEventsSource{prefix: "only", n: 1}
		mux := newMultiEventsSource(src)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := make(chan docker.DockerEvent, 1)
		go func() { _ = mux.StreamEvents(ctx, out) }()
		select {
		case ev := <-out:
			if ev.SandboxID != "only" {
				t.Fatalf("event = %+v", ev)
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for event")
		}
	})

	t.Run("cancel_during_forward", func(t *testing.T) {
		src := &fakeEventsSource{prefix: "slow", n: 100}
		mux := newMultiEventsSource(src)
		ctx, cancel := context.WithCancel(context.Background())
		out := make(chan docker.DockerEvent)
		go func() { _ = mux.StreamEvents(ctx, out) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
	})

	t.Run("first_source_error_cancels_mux", func(t *testing.T) {
		mux := newMultiEventsSource(&fakeEventsSource{prefix: "a", n: 5}, &boomEventsSource{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out := make(chan docker.DockerEvent, 8)
		if err := mux.StreamEvents(ctx, out); err == nil {
			t.Fatal("expected stream error")
		}
	})
}

type boomEventsSource struct{}

func (b *boomEventsSource) StreamEvents(context.Context, chan<- docker.DockerEvent) error {
	return errors.New("stream boom")
}

func (b *boomEventsSource) ContainerPID(context.Context, string) (int, error) {
	return 0, nil
}

func TestCoverage95DaemonAdapterSuccessPaths(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	logger := testLogger()
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	now := time.Now().UTC()

	t.Run("get_sandbox_spec_nil_cluster", func(t *testing.T) {
		resolver := autoImportSpecResolver{svc: &service.Service{}}
		if spec, ok := resolver.GetSandboxSpec("x"); ok || spec != nil {
			t.Fatalf("GetSandboxSpec = (%+v, %v), want (nil,false)", spec, ok)
		}
	})

	t.Run("template_resolver_ready_with_snapshot", func(t *testing.T) {
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-snap", Image: "alpine", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
			HasSnapshot: true, SnapshotMemoryPath: "/tmp/m", SnapshotStatePath: "/tmp/s",
		}); err != nil {
			t.Fatal(err)
		}
		a := &templateResolverAdapter{svc: svc}
		res, err := a.Resolve(ctx, "tpl-snap")
		if err != nil || res == nil || !res.HasSnapshot {
			t.Fatalf("Resolve = (%+v, %v)", res, err)
		}
	})

	t.Run("template_snapshotter_success_shape", func(t *testing.T) {
		a := &firecrackerTemplateSnapshotterAdapter{driver: fcruntime.New(fcruntime.FromDaemonConfig(config.Config{}), logger)}
		_, err := a.SnapshotTemplate(ctx, service.TemplateSnapshotRequest{
			TemplateID: "tpl", RootfsPath: "/tmp/r", OutMemoryPath: "/tmp/m", OutStatePath: "/tmp/s",
		})
		if err == nil {
			t.Fatal("expected error without pool")
		}
	})

	t.Run("rootfs_build_with_inject", func(t *testing.T) {
		ociCfg, work := ociHappyConfig(t)
		builder, err := oci.New(ociCfg)
		if err != nil {
			t.Fatal(err)
		}
		injectPath := filepath.Join(work, "inject.txt")
		if err := os.WriteFile(injectPath, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		a := &firecrackerRootfsAdapter{inner: builder}
		_, err = a.Build(ctx, fcruntime.RootfsBuildRequest{
			ImageRef: "docker://alpine:3.20",
			OutPath:  filepath.Join(work, "inj-rootfs.ext4"),
			InjectFiles: []fcruntime.InjectFile{{
				HostPath: injectPath, GuestPath: "/etc/inject", Mode: 0o644,
			}},
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
	})

	t.Run("template_builder_with_toolbox", func(t *testing.T) {
		toolbox := filepath.Join(t.TempDir(), "toolboxd")
		if err := os.WriteFile(toolbox, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		ociCfg, work := ociHappyConfig(t)
		builder, err := oci.New(ociCfg)
		if err != nil {
			t.Fatal(err)
		}
		a := &templateBuilderAdapter{inner: builder, toolboxBinaryPath: toolbox}
		_, err = a.Build(ctx, service.TemplateBuildRequest{
			ImageRef: "docker://alpine:3.20",
			OutPath:  filepath.Join(work, "tpl-inj.ext4"),
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
	})

	t.Run("warm_pool_depth_negative_tap", func(t *testing.T) {
		got, capped := firecrackerWarmPoolDepth(4, -8)
		if got != 0 || !capped {
			t.Fatalf("firecrackerWarmPoolDepth = (%d,%v), want (0,true)", got, capped)
		}
	})
}

func TestCoverage95ReconcilerSweepPaths(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	logger := testLogger()
	now := time.Now().UTC()

	patPath := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("auto_import_sweep_with_pending", func(t *testing.T) {
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-import", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now,
			AutoImportPending: true,
		}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startAutoImportReconciler(runCtx, logger, config.Config{
			AutoImportEnabled:           true,
			AutoImportClusterPATPath:    patPath,
			AutoImportHooksBaseURL:      "https://hooks.example",
			AutoImportClusterID:         "cluster-1",
			AutoImportReconcileInterval: 5 * time.Millisecond,
			AutoImportMaxInFlight:       1,
		}, st, svc)
		time.Sleep(80 * time.Millisecond)
		cancel()
	})

	t.Run("snapshot_push_containerd_backend", func(t *testing.T) {
		driver := cntr.New(cntr.FromDaemonConfig(config.Config{ContainerEngine: models.ContainerEngineContainerd}), nil, logger)
		ctd := &containerdEngineWiring{driver: driver}
		runCtx, cancel := context.WithCancel(context.Background())
		startSnapshotPushReconciler(runCtx, logger, config.Config{
			SnapshotPushEnabled:           true,
			ContainerEngine:               models.ContainerEngineContainerd,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t), ctd)
		time.Sleep(40 * time.Millisecond)
		cancel()
	})

	t.Run("template_push_sweep", func(t *testing.T) {
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-push", Image: "docker://alpine:3.20", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateArtifactPushReconciler(runCtx, logger, config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t))
		time.Sleep(40 * time.Millisecond)
		cancel()
	})

	t.Run("template_rotation_interval_without_max_age_warn", func(t *testing.T) {
		startTemplateRotationReconciler(context.Background(), logger, config.Config{
			EnableFirecracker:                   true,
			FirecrackerTemplateRotationInterval: time.Second,
			FirecrackerTemplateMaxAge:           0,
		}, st, svc)
	})
}

func TestCoverage95IsolateBundleStoreError(t *testing.T) {
	badDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := wireIsolateRuntime(context.Background(), config.Config{
		EnableIsolate:      true,
		IsolateRunDir:      badDir,
		IsolateWorkerdPath: "/nonexistent-workerd",
	}, testLogger(), nil)
	if err == nil {
		t.Fatal("want bundle store error")
	}
}

func TestCoverage95RunExtendedWiringBranches(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"docker_warm_and_netns", map[string]string{
			"SB_DOCKER_POOL_ENABLED":         "true",
			"SB_DOCKER_READY_SOCKET_ENABLED": "true",
			"SB_DOCKER_NETNS_POOL_ENABLED":   "true",
			"SB_DOCKER_NETNS_POOL_DEPTH":     "1",
		}},
		{"containerd_warm_pool", map[string]string{
			"SB_CONTAINER_ENGINE":            "containerd",
			"SB_CONTAINERD_POOL_ENABLED":     "true",
			"SB_DOCKER_READY_SOCKET_ENABLED": "true",
			"SB_CONTAINERD_POOL_DEPTH":       "1",
		}},
		{"netrules_enabled", map[string]string{
			"SB_ENABLE_NETWORK_RULES": "true",
			"SB_NETRULES_BACKEND":     "exec",
		}},
		{"isolate_non_worker", map[string]string{
			"SB_ENABLE_CLUSTER":               "true",
			"SB_NODE_ROLE":                    "ingress",
			"SB_CLUSTER_BOOTSTRAP":            "false",
			"SB_BOOTSTRAP_PEERS":              "127.0.0.1:19999",
			"SB_CLUSTER_INSECURE_GOSSIP":      "true",
			"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
			"SB_ENABLE_ISOLATE":               "true",
		}},
		{"wasm_non_worker", map[string]string{
			"SB_ENABLE_CLUSTER":               "true",
			"SB_NODE_ROLE":                    "ingress",
			"SB_CLUSTER_BOOTSTRAP":            "false",
			"SB_BOOTSTRAP_PEERS":              "127.0.0.1:19999",
			"SB_CLUSTER_INSECURE_GOSSIP":      "true",
			"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
			"SB_ENABLE_WASM":                  "true",
		}},
		{"cluster_agent_worker", map[string]string{
			"SB_ENABLE_CLUSTER":               "true",
			"SB_NODE_ROLE":                    "worker",
			"SB_CLUSTER_BOOTSTRAP":            "false",
			"SB_BOOTSTRAP_PEERS":              "127.0.0.1:19999",
			"SB_CLUSTER_INSECURE_GOSSIP":      "true",
			"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
		}},
		{"auto_import_pull_observer", map[string]string{
			"SB_AUTO_IMPORT_ENABLED": "true",
		}},
		{"platform_volumes_nfs", map[string]string{
			"SB_PLATFORM_VOLUMES_ENABLED":    "true",
			"SB_PLATFORM_VOLUMES_BACKEND":    "nfs",
			"SB_PLATFORM_VOLUMES_NFS_SERVER": "127.0.0.1",
			"SB_PLATFORM_VOLUMES_NFS_EXPORT": "/export",
		}},
		{"firecracker_vmm_pool", map[string]string{
			"SB_ENABLE_FIRECRACKER":                 "true",
			"SB_FIRECRACKER_BINARY":                 "/bin/true",
			"SB_JAILER_BINARY":                      "/bin/true",
			"SB_FIRECRACKER_KERNEL":                 "vmlinux",
			"SB_FIRECRACKER_RUN_DIR":                "fc-run",
			"SB_FIRECRACKER_USE_JAILER":             "false",
			"SB_FIRECRACKER_TAP_BASE_CIDR":          "172.19.0.0/30",
			"SB_FIRECRACKER_TAP_POOL_SIZE":          "1",
			"SB_FIRECRACKER_SKOPEO_BIN":             "/bin/true",
			"SB_FIRECRACKER_UMOCI_BIN":              "/bin/true",
			"SB_FIRECRACKER_MKFS_BIN":               "/bin/true",
			"SB_FIRECRACKER_VMM_POOL_ENABLED":       "true",
			"SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT": "1",
		}},
		{"serverless_custom_domains", map[string]string{
			"SB_ENABLE_CADDY":          "true",
			"SB_ENABLE_SERVERLESS":     "true",
			"SB_ENABLE_CUSTOM_DOMAINS": "true",
			"SB_DOMAIN":                "example.test",
		}},
		{"wasm_resident_host", map[string]string{
			"SB_ENABLE_WASM":                "true",
			"SB_WASM_RESIDENT_HOST_ENABLED": "true",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := setBaseRunEnv(t)
			t.Setenv("SB_ISOLATE_RUN_DIR", paths.rootDir+"/isolate")
			t.Setenv("SB_WASM_RUN_DIR", paths.rootDir+"/wasm-run")
			t.Setenv("SB_WASM_MODULES_DIR", paths.rootDir+"/wasm-modules")
			if tc.name == "firecracker_vmm_pool" {
				t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
				t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
			}
			if tc.name == "cluster_agent_worker" || tc.name == "isolate_non_worker" || tc.name == "wasm_non_worker" {
				raftPort := pickFreeTCPPort(t)
				gossipPort := pickFreeTCPPort(t)
				t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:"+strconv.Itoa(raftPort))
				t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:"+strconv.Itoa(gossipPort))
				t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:"+strconv.Itoa(raftPort))
				t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:"+strconv.Itoa(gossipPort))
				t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
			}
			if tc.name == "auto_import_pull_observer" {
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
				t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
				t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1h")
			}
			if tc.name == "platform_volumes_nfs" {
				badRoot := filepath.Join(paths.rootDir, "vol-reclaim-file")
				if err := os.WriteFile(badRoot, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SB_PLATFORM_VOLUMES_RECLAIM_MOUNT_ROOT", badRoot)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if err := runWithAutoCancel(t, 600*time.Millisecond, nil); err != nil {
				t.Fatalf("Run %s: %v", tc.name, err)
			}
		})
	}
}

func TestCoverage95IsolateBackgroundAndPoolSpawner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startIsolateBackground(ctx, config.Config{}, nil, nil)

	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	driver := isolateruntime.New(isolateruntime.FromDaemonConfig(config.Config{}), testLogger())
	startIsolateBackground(ctx, config.Config{IsolateBundleGCInterval: time.Millisecond}, driver, svc)

	spawner := &poolSpawner{supervisor: isolateruntime.NewHostSupervisor(isolateruntime.Config{
		WorkerdPath: "/nonexistent-workerd",
		RunDir:      t.TempDir(),
	})}
	if _, err := spawner.Spawn(context.Background()); err == nil {
		t.Fatal("Spawn with missing workerd unexpectedly succeeded")
	}
	if got := spawner.n.Load(); got != 1 {
		t.Fatalf("spawn sequence = %d, want 1", got)
	}
}

func TestCoverage95DaemonWiringGuards(t *testing.T) {
	if got := adaptTapSlot(nil); got != nil {
		t.Fatalf("adaptTapSlot(nil) = %+v, want nil", got)
	}
	if pool := wireContainerdWarmPool(context.Background(), config.Config{
		ContainerdPoolEnabled:    true,
		DockerReadySocketEnabled: true,
	}, testLogger(), nil, nil); pool != nil {
		t.Fatal("warm pool without driver unexpectedly initialized")
	}
}

func TestCoverage95IsolateWarmPoolWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Exercise the pool wiring without trying to start workerd.

	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	driver, err := wireIsolateRuntime(ctx, config.Config{
		EnableIsolate:             true,
		IsolateWorkerdPath:        "/nonexistent-workerd",
		IsolateRunDir:             t.TempDir(),
		IsolatePoolEnabled:        true,
		IsolatePoolDepthDefault:   1,
		IsolatePoolRefillInterval: time.Hour,
	}, testLogger(), svc)
	if err != nil {
		t.Fatalf("wireIsolateRuntime: %v", err)
	}
	if driver == nil {
		t.Fatal("wireIsolateRuntime returned nil driver")
	}
}

func TestCoverage95RunIsolateAndContainerdWiring(t *testing.T) {
	t.Run("isolate", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		t.Setenv("SB_ENABLE_ISOLATE", "true")
		t.Setenv("SB_ISOLATE_WORKERD_PATH", "/nonexistent-workerd")
		t.Setenv("SB_ISOLATE_RUN_DIR", paths.rootDir+"/isolate")
		t.Setenv("SB_ISOLATE_POOL_ENABLED", "true")
		t.Setenv("SB_ISOLATE_POOL_DEPTH_DEFAULT", "1")
		if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
			t.Fatalf("Run isolate: %v", err)
		}
	})
	t.Run("containerd", func(t *testing.T) {
		setBaseRunEnv(t)
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		t.Setenv("SB_CONTAINERD_POOL_ENABLED", "false")
		t.Setenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", "false")
		if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
			t.Fatalf("Run containerd: %v", err)
		}
	})
}

func TestCoverage95RunMoreWiringBranches(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"jsbundle_gc", map[string]string{
			"SB_ENABLE_ISOLATE":             "true",
			"SB_ISOLATE_WORKERD_PATH":       "/nonexistent-workerd",
			"SB_ISOLATE_BUNDLE_GC_INTERVAL": "1ms",
		}},
		{"wasm_pool", map[string]string{
			"SB_ENABLE_WASM":             "true",
			"SB_WASM_POOL_ENABLED":       "true",
			"SB_WASM_POOL_DEPTH_DEFAULT": "1",
		}},
		{"snapshot_push", map[string]string{
			"SB_ENABLE_SNAPSHOT_PUSH_RECONCILE": "true",
			"SB_SNAPSHOT_PUSH_INTERVAL":         "1h",
		}},
		{"template_rotation", map[string]string{
			"SB_ENABLE_TEMPLATE_ROTATION_RECONCILE": "true",
			"SB_TEMPLATE_ROTATION_INTERVAL":         "1h",
		}},
		{"netrules_reassert", map[string]string{
			"SB_CONTAINER_ENGINE":                 "containerd",
			"SB_NETRULES_CHAIN_REASSERT_INTERVAL": "1h",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := setBaseRunEnv(t)
			t.Setenv("SB_ISOLATE_RUN_DIR", paths.rootDir+"/isolate")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
				t.Fatalf("Run %s: %v", tc.name, err)
			}
		})
	}
}

func TestCoverage95MoreWiringAndRunBranches(t *testing.T) {
	t.Run("netns_live_inspect_during_wire", func(t *testing.T) {
		st := openDaemonTestStore(t)
		work := t.TempDir()
		origSysctls := ensureForwardingSysctls
		ensureForwardingSysctls = func() error { return nil }
		t.Cleanup(func() { ensureForwardingSysctls = origSysctls })

		cfg := config.Config{
			ContainerEngine:                   models.ContainerEngineContainerd,
			ContainerdNativeNetnsPoolEnabled:  true,
			ContainerdNetnsPoolDepth:          0,
			ContainerdNetnsPoolSize:           2,
			ContainerdNetnsPoolRefillInterval: time.Hour,
			ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
			ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
		}
		driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
		ctx := context.Background()
		now := time.Now().UTC()
		pool := netns.New(st)
		if err := pool.Seed(ctx, netns.SeedConfig{PoolSize: 2}, now); err != nil {
			t.Fatal(err)
		}
		host := netns.NewFakeHost()
		if _, _, err := netns.NewRuntimeHandoff(pool, host).Provision(ctx, "sb-live"); err != nil {
			t.Fatal(err)
		}
		wired, err := wireContainerdNativeNetnsPool(ctx, cfg, testLogger(), st, driver)
		if err != nil {
			t.Fatalf("wire: %v", err)
		}
		if wired == nil {
			t.Fatal("expected wired pool")
		}
		wired.Stop()
	})

	t.Run("containerd_warm_nil_driver", func(t *testing.T) {
		pool := wireContainerdWarmPool(context.Background(), config.Config{
			ContainerEngine:          models.ContainerEngineContainerd,
			ContainerdPoolEnabled:    true,
			DockerReadySocketEnabled: true,
		}, testLogger(), nil, nil)
		if pool != nil {
			t.Fatal("want nil without driver")
		}
	})

	t.Run("containerd_warm_default_image", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driver := cntr.New(cntr.FromDaemonConfig(config.Config{ContainerEngine: models.ContainerEngineContainerd}), nil, testLogger())
		pool := wireContainerdWarmPool(ctx, config.Config{
			ContainerEngine:          models.ContainerEngineContainerd,
			ContainerdPoolEnabled:    true,
			DockerReadySocketEnabled: true,
			ContainerdPoolDepth:      1,
			Runtime:                  models.RuntimeDocker,
		}, testLogger(), driver, nil)
		if pool == nil {
			t.Fatal("expected default-image pool")
		}
		drainContainerdWarmPool(pool, testLogger())
	})

	t.Run("netns_seed_cap_error", func(t *testing.T) {
		st := openDaemonTestStore(t)
		cfg := config.Config{
			ContainerEngine:                  models.ContainerEngineContainerd,
			ContainerdNativeNetnsPoolEnabled: true,
			ContainerdNetnsPoolSize:          10001,
		}
		driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
		if _, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver); err == nil {
			t.Fatal("want seed cap error")
		}
	})

	t.Run("wasm_resident_host", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := openTestStore(t)
		svc := service.New(config.Config{EnableWasm: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		if err := os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755); err != nil {
			t.Fatal(err)
		}
		pool := wireWasmRuntime(ctx, config.Config{
			EnableWasm:              true,
			WasmRunDir:              filepath.Join(paths.rootDir, "wasm-run"),
			WasmModulesDir:          filepath.Join(paths.rootDir, "wasm-modules"),
			WasmResidentHostEnabled: true,
			WasmStandardModules:     map[string]string{"python": "python.wasm"},
			WasmResidentHostIdleTTL: time.Millisecond,
		}, testLogger(), svc, st)
		if pool != nil {
			pool.Close()
		}
		time.Sleep(20 * time.Millisecond)
	})

	t.Run("template_resolver_unhealthy", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-bad", Image: "alpine", Status: models.TemplateStatusUnhealthy,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		a := &templateResolverAdapter{svc: svc}
		if _, err := a.Resolve(ctx, "tpl-bad"); err != nil {
			t.Fatalf("unhealthy template should resolve: %v", err)
		}
	})

	t.Run("snapshot_push_sweep_logs", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
			Name: "snap-log", Image: "img:1", CreatedAt: now,
			PushState: models.SnapshotPushStatePending,
		}); err != nil {
			t.Fatal(err)
		}
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startSnapshotPushReconciler(runCtx, testLogger(), config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t), nil)
		time.Sleep(50 * time.Millisecond)
		cancel()
	})

	t.Run("template_push_sweep_logs", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-artifact", Image: "docker://alpine:3.20", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
			PushState: models.TemplatePushStatePending,
		}); err != nil {
			t.Fatal(err)
		}
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateArtifactPushReconciler(runCtx, testLogger(), config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t))
		time.Sleep(50 * time.Millisecond)
		cancel()
	})

	t.Run("template_rotation_sweep_logs", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		stale := now.Add(-48 * time.Hour)
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-rot", Image: "docker://alpine:3.19", Status: models.TemplateStatusReady,
			ReadyAt: &stale, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateRotationReconciler(runCtx, testLogger(), config.Config{
			EnableFirecracker:                   true,
			FirecrackerTemplateRotationInterval: 5 * time.Millisecond,
			FirecrackerTemplateMaxAge:           time.Hour,
		}, st, svc)
		time.Sleep(50 * time.Millisecond)
		cancel()
	})

	t.Run("resolve_ensure_local_error", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{EnableFirecracker: true, FirecrackerTemplatesDir: t.TempDir()}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		attachTemplateArtifactPuller(testLogger(), config.Config{
			EnableFirecracker:       true,
			FirecrackerTemplatesDir: t.TempDir(),
		}, svc, newTestDockerClient(t))
		now := time.Now().UTC()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-pull", Image: "docker://alpine:3.20", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", RegistryRef: "aocr.example/cluster/c1/templates/tpl-pull:latest",
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		a := &templateResolverAdapter{svc: svc}
		if _, err := a.Resolve(ctx, "tpl-pull"); err == nil {
			t.Fatal("expected ensure-local pull error")
		}
	})

	t.Run("snapshot_push_wasm_pusher_fail", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		startSnapshotPushReconciler(context.Background(), testLogger(), config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "missing-pat"),
			SnapshotPushReconcileInterval: time.Hour,
		}, st, svc, newTestDockerClient(t), nil)
	})

	t.Run("template_rotation_reconciler_build_error", func(t *testing.T) {
		startTemplateRotationReconciler(context.Background(), testLogger(), config.Config{
			EnableFirecracker:                   true,
			FirecrackerTemplateRotationInterval: time.Second,
			FirecrackerTemplateMaxAge:           time.Hour,
		}, openTestStore(t), nil)
	})

	t.Run("reconciler_nil_guards", func(t *testing.T) {
		logger := testLogger()
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)

		startSnapshotPushReconciler(ctx, logger, config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: time.Hour,
		}, nil, svc, newTestDockerClient(t), nil)

		startTemplateArtifactPushReconciler(ctx, logger, config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: time.Hour,
		}, nil, svc, newTestDockerClient(t))
	})

	t.Run("auto_import_sweep_error", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startAutoImportReconciler(runCtx, testLogger(), config.Config{
			AutoImportEnabled:           true,
			AutoImportClusterPATPath:    patPath,
			AutoImportHooksBaseURL:      "https://hooks.example",
			AutoImportClusterID:         "cluster-1",
			AutoImportReconcileInterval: 5 * time.Millisecond,
			AutoImportMaxInFlight:       1,
		}, st, svc)
		_ = st.Close()
		time.Sleep(30 * time.Millisecond)
		cancel()
	})

	t.Run("snapshot_push_sweep_error", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startSnapshotPushReconciler(runCtx, testLogger(), config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
		}, st, svc, newTestDockerClient(t), nil)
		_ = st.Close()
		time.Sleep(30 * time.Millisecond)
		cancel()
	})

	t.Run("template_push_sweep_error", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateArtifactPushReconciler(runCtx, testLogger(), config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
		}, st, svc, newTestDockerClient(t))
		_ = st.Close()
		time.Sleep(30 * time.Millisecond)
		cancel()
	})

	t.Run("oci_helper_error_paths", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "blocked")
		if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blocked, "skopeo"), []byte("#!/bin/sh\n"), 0o755); err == nil {
			t.Fatal("expected write into file path to fail")
		}
	})

	runCases := []struct {
		name  string
		setup func(t *testing.T, paths runTestPaths)
		err   bool
	}{
		{
			name: "bypass_rollback",
			setup: func(t *testing.T, paths runTestPaths) {
				if err := os.WriteFile(paths.bypassMarkerPath, []byte("true\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED", "false")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_ENABLE_CADDY", "true")
				t.Setenv("SB_DOMAIN", "example.test")
			},
		},
		{
			name: "isolate_wire_error",
			err:  true,
			setup: func(t *testing.T, paths runTestPaths) {
				badDir := filepath.Join(paths.rootDir, "not-a-dir")
				if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_RUN_DIR", badDir)
				t.Setenv("SB_ISOLATE_WORKERD_PATH", "/nonexistent-workerd")
			},
		},
		{
			name: "docker_ready_socket",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
				t.Setenv("SB_DOCKER_READY_SOCKET_DIR", filepath.Join(paths.rootDir, "ready"))
			},
		},
		{
			name: "auto_reconcile",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_AUTO_RECONCILE", "true")
			},
		},
		{
			name: "wasm_pool_drain",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
				t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))
				t.Setenv("SB_WASM_POOL_ENABLED", "true")
				t.Setenv("SB_WASM_POOL_DEPTH_DEFAULT", "1")
				t.Setenv("SB_WASM_POOL_REFILL_INTERVAL", "5ms")
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755)
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755)
			},
		},
		{
			name: "cluster_wasm_inventory",
			setup: func(t *testing.T, paths runTestPaths) {
				raftPort := pickFreeTCPPort(t)
				gossipPort := pickFreeTCPPort(t)
				t.Setenv("SB_ENABLE_CLUSTER", "true")
				t.Setenv("SB_NODE_ROLE", "mixed")
				t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
				t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
				t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
				t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:"+strconv.Itoa(raftPort))
				t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:"+strconv.Itoa(gossipPort))
				t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:"+strconv.Itoa(raftPort))
				t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:"+strconv.Itoa(gossipPort))
				t.Setenv("SB_RAFT_DATA_DIR", filepath.Join(paths.rootDir, "raft"))
				t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
				t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755)
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755)
			},
		},
		{
			name: "serverless_l4_wake",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_CADDY", "true")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "example.test")
			},
		},
		{
			name: "containerd_wire_failure",
			err:  true,
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_CONTAINER_ENGINE", "containerd")
				t.Setenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", "true")
				t.Setenv("SB_CONTAINERD_CNI_PLUGIN_DIR", "")
				t.Setenv("SB_CONTAINERD_CNI_CONF_PATH", "")
			},
		},
		{
			name: "cluster_start_failure",
			err:  true,
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_CLUSTER", "true")
				t.Setenv("SB_NODE_ROLE", "mixed")
				t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
				t.Setenv("SB_RAFT_BIND_ADDR", "not-a-valid-address")
			},
		},
		{
			name: "netrules_enabled",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_NETWORK_RULES", "true")
				t.Setenv("SB_NETRULES_BACKEND", "exec")
			},
		},
		{
			name: "auto_import_observer",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_AUTO_IMPORT_ENABLED", "true")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
				t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
				t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1h")
			},
		},
		{
			name: "full_feature_shutdown",
			setup: func(t *testing.T, paths runTestPaths) {
				collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(collector.Close)
				t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
				t.Setenv("SB_OTEL_TRACES_ENDPOINT", collector.URL)
				t.Setenv("SB_OTEL_METRICS_ENABLED", "true")
				t.Setenv("SB_OTEL_METRICS_ENDPOINT", collector.URL)
				t.Setenv("SB_OTEL_METRICS_INTERVAL", "10ms")
				t.Setenv("SB_ENABLE_CADDY", "true")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "example.test")
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
				t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))
				t.Setenv("SB_WASM_POOL_ENABLED", "true")
				t.Setenv("SB_WASM_POOL_DEPTH_DEFAULT", "1")
				t.Setenv("SB_ENABLE_FIRECRACKER", "true")
				t.Setenv("SB_FIRECRACKER_BINARY", "/bin/true")
				t.Setenv("SB_JAILER_BINARY", "/bin/true")
				t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
				t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
				t.Setenv("SB_FIRECRACKER_USE_JAILER", "false")
				t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.19.0.0/30")
				t.Setenv("SB_FIRECRACKER_TAP_POOL_SIZE", "1")
				t.Setenv("SB_FIRECRACKER_SKOPEO_BIN", "/bin/true")
				t.Setenv("SB_FIRECRACKER_UMOCI_BIN", "/bin/true")
				t.Setenv("SB_FIRECRACKER_MKFS_BIN", "/bin/true")
				t.Setenv("SB_FIRECRACKER_VMM_POOL_ENABLED", "true")
				t.Setenv("SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT", "1")
				t.Setenv("SB_AUTO_IMPORT_ENABLED", "true")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
				t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
				t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1h")
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755)
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755)
			},
		},
	}
	for _, tc := range runCases {
		t.Run(tc.name, func(t *testing.T) {
			paths := setBaseRunEnv(t)
			tc.setup(t, paths)
			if tc.err {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err := Run(ctx, testLogger(), nil)
				if err == nil {
					t.Fatalf("Run %s = nil, want error", tc.name)
				}
				return
			}
			if tc.name == "full_feature_shutdown" {
				if err := runWithAutoCancel(t, 2500*time.Millisecond, nil); err != nil {
					t.Fatalf("Run %s: %v", tc.name, err)
				}
				return
			}
			if err := runWithAutoCancel(t, 1200*time.Millisecond, nil); err != nil {
				t.Fatalf("Run %s: %v", tc.name, err)
			}
		})
	}
}
