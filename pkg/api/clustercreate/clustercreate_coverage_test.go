package clustercreate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage95LiftPrepareAndCapacity(t *testing.T) {
	t.Run("nil_cluster_allows_local", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil),
			svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{})
		if !ok {
			t.Fatal("nil cluster should fall through to local create")
		}
	})

	t.Run("isolate_unbound_ref_rejected", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Runtime:   models.RuntimeIsolate,
			ModuleRef: "sha256:abc",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusBadRequest {
			t.Fatalf("ok=%v status=%d, want 400 for unbound isolate ref", ok, status)
		}
	})

	t.Run("local_image_on_drained_self", func(t *testing.T) {
		stub := &clusterStub{
			Noop:    cluster.NewNoop("node-a", "http://node-a", ""),
			drained: true,
			members: []cluster.Member{{NodeID: "node-a", Role: config.NodeRoleWorker}},
		}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable {
			t.Fatalf("ok=%v status=%d, want 503 on drained local image", ok, status)
		}
	})

	t.Run("select_self_drained", func(t *testing.T) {
		// Server role cannot own; SelectPlacement still returns self + drained
		// so the local-image path rejects instead of creating on a draining node.
		stub := &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			drained:      true,
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
			members:      []cluster.Member{{NodeID: "node-a", Role: config.NodeRoleServer}},
		}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable {
			t.Fatalf("ok=%v status=%d, want 503 on drained self placement", ok, status)
		}
	})

	t.Run("local_image_no_placement", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			selectErr: cluster.ErrNoPlacementTarget,
			members:   []cluster.Member{{NodeID: "node-a", Role: config.NodeRoleServer}},
		}
		svc := testServiceWithCluster(stub)
		var status int
		rr := httptest.NewRecorder()
		_, ok := Prepare(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
			t.Fatalf("ok=%v status=%d retry=%q", ok, status, rr.Header().Get("Retry-After"))
		}
	})

	t.Run("local_image_invalid_topology", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			selectErr: cluster.ErrInvalidTopology,
			members:   []cluster.Member{{NodeID: "node-a", Role: config.NodeRoleServer}},
		}
		svc := testServiceWithCluster(stub)
		var status int
		rr := httptest.NewRecorder()
		_, ok := Prepare(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") != "300" {
			t.Fatalf("ok=%v status=%d retry=%q", ok, status, rr.Header().Get("Retry-After"))
		}
	})

	t.Run("select_self_not_drained", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
			members:      []cluster.Member{{NodeID: "node-a", Role: config.NodeRoleServer}},
		}
		svc := testServiceWithCluster(stub)
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, nil, PrepareOptions{})
		if !ok {
			t.Fatal("self + not drained should create locally")
		}
	})

	t.Run("failover_fanout_reserve_self", func(t *testing.T) {
		// Recreate failover is the only create shape that publishes secret
		// recipients at reserve time (WantsSecretRecipientFanout).
		stub := &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
			members:      []cluster.Member{{NodeID: "node-a", Role: config.NodeRoleWorker, Alive: true}},
		}
		svc := testServiceWithCluster(stub)
		dec, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image:    "alpine:3.20",
			Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		}, nil, PrepareOptions{})
		if !ok || dec.ReservationID == "" {
			t.Fatalf("ok=%v dec=%+v", ok, dec)
		}
	})
}

func TestCoverage95LiftCapacityRequestAndRollback(t *testing.T) {
	iso := CapacityRequestFromCreate(models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: models.JSBundleRefForNode("sha256:abc", "worker-b"),
	})
	if iso.RequiredNodeID == "" {
		t.Fatalf("isolate node-bound ref should set RequiredNodeID: %+v", iso)
	}
	encoded, ok := models.EncodeNodeAffinity("worker-b")
	if !ok {
		t.Fatal("EncodeNodeAffinity")
	}
	built := CapacityRequestFromCreate(models.CreateSandboxRequest{
		Image: docker.BuiltImageNamespace + "/node-" + encoded + "/abc:latest",
	})
	if built.RequiredNodeID != "worker-b" {
		t.Fatalf("built-image required node = %q", built.RequiredNodeID)
	}

	wasm := CapacityRequestFromCreate(models.CreateSandboxRequest{Runtime: models.RuntimeWasm, MemoryMB: 64})
	if wasm.MemoryMB != 72 {
		t.Fatalf("wasm memory = %d, want 72", wasm.MemoryMB)
	}

	gpus := CapacityRequestFromCreate(models.CreateSandboxRequest{
		GPUs: &models.GPURequest{Count: 0, Vendor: models.GPUVendorNVIDIA},
	})
	if gpus.GPUs != 1 || gpus.GPUVendor != string(models.GPUVendorNVIDIA) {
		t.Fatalf("gpu request = %+v", gpus)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	CancelReservationBestEffort(context.Background(), nil, logger, "sb")
	empty := testServiceWithCluster(cluster.NewNoop("node-a", "", ""))
	CancelReservationBestEffort(context.Background(), empty, logger, "")
	empty.ClearClusterForTest()
	CancelReservationBestEffort(context.Background(), empty, logger, "sb-nil-cluster")
	RollbackLocalCreate(context.Background(), nil, logger, "sb")
	RollbackLocalCreate(context.Background(), empty, logger, "  ")

	// EnableCluster stays true after ClearCluster so Overlap hits the
	// nil-client sequential CreateSandboxWithID path, not the cfg short-circuit.
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, _ := newCreateService(t, stub, true)
	svc.ClearClusterForTest()
	if _, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-overlap-nil", OverlapOptions{}); err != nil {
		t.Fatalf("nil cluster overlap: %v", err)
	}
}

func TestCoverage95LiftCreateOnSelectedNodeSealRollback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, _ := newCreateService(t, stub, false)
	_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "secret"},
	}, "", CreateOptions{})
	if err == nil {
		t.Fatal("expected seal failure without cipher to roll back")
	}

	// Reserved path resolves volumes before create; disabled platform volumes
	// cancel the reservation instead of leaving a dangling raft row.
	_, err = CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
		Image:           "alpine:3.20",
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "vol", Path: "/data"}},
	}, "sb-res-vol", CreateOptions{})
	if err == nil {
		t.Fatal("expected platform-volume resolve failure")
	}
}

func TestPrepareCoverage95Branches(t *testing.T) {
	t.Run("default_write_error_on_misdirected", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc := testServiceWithCluster(stub)
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-b")
		w := httptest.NewRecorder()
		_, ok := Prepare(w, r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{})
		if ok || w.Code != http.StatusMisdirectedRequest {
			t.Fatalf("ok=%v status=%d, want 421", ok, w.Code)
		}
	})

	t.Run("invalid_failover_with_local_image", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image:                 docker.BuiltImageNamespace + "/abc:latest",
			Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusBadRequest {
			t.Fatalf("ok=%v status=%d, want 400", ok, status)
		}
	})

	t.Run("invalid_topology_retry_after_on_standard_path", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			selectErr: cluster.ErrInvalidTopology,
		}
		svc := testServiceWithCluster(stub)
		w := httptest.NewRecorder()
		var status int
		_, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, func(_ http.ResponseWriter, code int, _ string) {
			status = code
		}, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable {
			t.Fatalf("ok=%v status=%d, want 503", ok, status)
		}
		if got := w.Header().Get("Retry-After"); got != "300" {
			t.Fatalf("Retry-After = %q, want 300", got)
		}
	})

	t.Run("recovery_payload_too_large", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
			reserveErr:   cluster.ErrRecoveryPayloadTooLarge,
		}
		svc := testServiceWithCluster(stub)
		var status int
		var message string
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, func(_ http.ResponseWriter, code int, msg string) {
			status = code
			message = msg
		}, PrepareOptions{})
		if ok || status != http.StatusBadRequest {
			t.Fatalf("ok=%v status=%d, want 400", ok, status)
		}
		if !strings.Contains(message, "too large") {
			t.Fatalf("message = %q, want too large hint", message)
		}
	})

	t.Run("foreign_arch_snapshot_normalize_error", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		foreignArch := "amd64"
		if runtime.GOARCH == "amd64" {
			foreignArch = "arm64"
		}
		foreignRef := "aocr.test/cluster/c1/snapshots/snap:latest--arch-" + foreignArch
		ctx := context.Background()
		if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
			Name:                  "foreign-snap:default",
			Image:                 foreignRef,
			CreatedAt:             time.Now(),
			ImageDistributionMode: models.ImageDistributionAOCR,
			ImageRegistryRef:      foreignRef,
		}); err != nil {
			t.Fatalf("CreateSnapshot: %v", err)
		}

		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		cfg := config.Config{EnableCaddy: false, ToolboxPort: 2280}
		svc := service.New(cfg, logger, st, newFakeRuntime(), nil, nil, nil, nil, nil)
		svc.AttachCluster(stub)

		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: "foreign-snap:default",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusBadRequest {
			t.Fatalf("ok=%v status=%d, want 400 for foreign arch", ok, status)
		}
	})
}

func TestClusterCreateSelfCanOwnSandboxWorkerAndMissingMember(t *testing.T) {
	workerStub := &clusterStub{
		Noop: cluster.NewNoop("worker-a", "", ""),
		members: []cluster.Member{
			{NodeID: "worker-a", Role: config.NodeRoleWorker},
		},
	}
	if !clusterCreateSelfCanOwnSandbox(workerStub) {
		t.Fatal("worker role should own sandboxes")
	}

	otherStub := &clusterStub{
		Noop: cluster.NewNoop("orphan-a", "", ""),
		members: []cluster.Member{
			{NodeID: "other-b", Role: config.NodeRoleWorker},
		},
	}
	if !clusterCreateSelfCanOwnSandbox(otherStub) {
		t.Fatal("self missing from members should default true")
	}
}

func TestCapacityRequestFromCreateTemplateWithoutRuntime(t *testing.T) {
	got := CapacityRequestFromCreate(models.CreateSandboxRequest{TemplateID: "tpl-1"})
	if got.Runtime != models.RuntimeFirecracker {
		t.Fatalf("runtime = %q, want firecracker", got.Runtime)
	}
	if got.TemplateID != "tpl-1" {
		t.Fatalf("template = %q", got.TemplateID)
	}
}

func TestCreateOnSelectedNodeCoverage95Branches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("normalize_failover_error", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc := testServiceWithCluster(stub)
		_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
			Image:                 docker.BuiltImageNamespace + "/abc:latest",
			Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		}, "", CreateOptions{})
		if err == nil {
			t.Fatal("expected failover normalize error")
		}
	})

	t.Run("non_reserved_record_placement_failure_rolls_back", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			recordErr: errors.New("raft write failed"),
		}
		svc, _ := newCreateService(t, stub, true)
		_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "", CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "raft write failed") {
			t.Fatalf("err = %v, want record placement failure", err)
		}
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
	})

	t.Run("non_reserved_seal_failure_without_cipher", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, _ := newCreateService(t, stub, false)
		_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
			Image:    "private.example.com/app:latest",
			Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "secret"},
		}, "", CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "cipher") {
			t.Fatalf("err = %v, want cipher failure", err)
		}
	})

	t.Run("non_reserved_resolve_platform_volumes_failure", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		cfg := config.Config{
			EnableCaddy: false,
			ToolboxPort: 2280,
			PATToken:    "operator-pat",
			PlatformVolumes: config.PlatformVolumesConfig{
				Enabled:  true,
				Backend:  config.PlatformVolumesBackendS3,
				S3Bucket: "aerol-volumes",
				S3Prefix: "volumes",
			},
		}
		svc := service.New(cfg, logger, st, newFakeRuntime(), nil, nil, nil, nil, nil)
		svc.AttachCluster(stub)

		_, err = CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
			Image:           "alpine:3.20",
			PlatformVolumes: []models.PlatformVolumeMount{{Name: "../escape", Path: "/x"}},
		}, "", CreateOptions{})
		if err == nil {
			t.Fatal("expected platform volume resolution failure")
		}
	})

	t.Run("create_sandbox_error_without_reservation", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		rt := newFakeRuntime()
		rt.createErr = errors.New("create boom")
		svc, _ := newCreateServiceWithRuntime(t, stub, rt, true)
		_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "", CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "create boom") {
			t.Fatalf("err = %v, want create boom", err)
		}
	})
}

func TestCancelReservationBestEffortNilClusterOnService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, _ := newCreateService(t, nil, true)

	CancelReservationBestEffort(context.Background(), svc, logger, "sb-1")
}

func TestCancelReservationBestEffortLogsCancelError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{
		Noop:      cluster.NewNoop("node-a", "", ""),
		cancelErr: errors.New("cancel failed"),
	}
	CancelReservationBestEffort(context.Background(), testServiceWithCluster(stub), logger, "sb-log-cancel")
	if stub.cancels != 1 {
		t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
	}
}

func TestPrepareNilServiceAndDiskGBForCapacity(t *testing.T) {
	_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil),
		nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{})
	if !ok {
		t.Fatal("nil service should allow local create")
	}
	if disk := diskGBForCapacity(10, models.RuntimeFirecracker, 5); disk != 15 {
		t.Fatalf("diskGBForCapacity = %d, want 15", disk)
	}
}

func TestCreateOnSelectedNodeReservedPlatformVolumeFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Config{
		EnableCaddy: false,
		ToolboxPort: 2280,
		PATToken:    "operator-pat",
		PlatformVolumes: config.PlatformVolumesConfig{
			Enabled:  true,
			Backend:  config.PlatformVolumesBackendS3,
			S3Bucket: "aerol-volumes",
			S3Prefix: "volumes",
		},
	}
	svc := service.New(cfg, logger, st, newFakeRuntime(), nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)

	_, err = CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
		Image:           "alpine:3.20",
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "../escape", Path: "/x"}},
	}, "sb-reserved-vol", CreateOptions{})
	if err == nil {
		t.Fatal("expected platform volume resolution failure on reserved path")
	}
	if stub.cancels != 1 {
		t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
	}
}

func TestPrepareLocalImageInvalidTopologyOnSelect(t *testing.T) {
	stub := &clusterStub{
		Noop:      cluster.NewNoop("server-a", "http://server-a", ""),
		selectErr: cluster.ErrInvalidTopology,
		members: []cluster.Member{
			{NodeID: "server-a", Role: config.NodeRoleServer},
			{NodeID: "worker-b", Role: config.NodeRoleWorker},
		},
	}
	svc := testServiceWithCluster(stub)
	w := httptest.NewRecorder()
	var status int
	_, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
		Image: docker.BuiltImageNamespace + "/abc:latest",
	}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
	if ok || status != http.StatusServiceUnavailable {
		t.Fatalf("ok=%v status=%d, want 503", ok, status)
	}
	if got := w.Header().Get("Retry-After"); got != "300" {
		t.Fatalf("Retry-After = %q, want 300", got)
	}
}

func TestCreateOnSelectedNodeNormalizeImageDistributionError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	foreignArch := "amd64"
	if runtime.GOARCH == "amd64" {
		foreignArch = "arm64"
	}
	foreignRef := "aocr.test/cluster/c1/snapshots/snap:latest--arch-" + foreignArch
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:                  "foreign-snap:default",
		Image:                 foreignRef,
		CreatedAt:             time.Now(),
		ImageDistributionMode: models.ImageDistributionAOCR,
		ImageRegistryRef:      foreignRef,
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
	cfg := config.Config{EnableCaddy: false, ToolboxPort: 2280}
	svc := service.New(cfg, logger, st, newFakeRuntime(), nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)

	_, err = CreateOnSelectedNode(ctx, svc, logger, models.CreateSandboxRequest{Image: "foreign-snap:default"}, "", CreateOptions{})
	if err == nil {
		t.Fatal("expected normalize image distribution error")
	}
}
