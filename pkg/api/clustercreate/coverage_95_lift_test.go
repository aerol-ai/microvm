package clustercreate

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
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
