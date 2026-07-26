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
		svc, _ := newCreateServiceWithRuntime(t, stub, rt, false)
		_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "", CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "create boom") {
			t.Fatalf("err = %v, want create boom", err)
		}
	})
}

func TestBestEffortHelpersNilClusterOnService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, _ := newCreateService(t, nil, false)

	DeletePlacementBestEffort(context.Background(), svc, logger, "sb-1")
	CancelReservationBestEffort(context.Background(), svc, logger, "sb-1")
}

func TestOverlapCreateAndPromoteNilClusterSequentialPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, st := newCreateService(t, nil, false)
	resp, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-seq-nil-cluster", OverlapOptions{})
	if err != nil {
		t.Fatalf("OverlapCreateAndPromote: %v", err)
	}
	if resp.Sandbox.ID != "sb-seq-nil-cluster" {
		t.Fatalf("id = %q", resp.Sandbox.ID)
	}
	if _, err := st.Get(context.Background(), "sb-seq-nil-cluster"); err != nil {
		t.Fatalf("store.Get: %v", err)
	}
}

func TestRetractFailedPromoteDeletePlacementFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		deleteErr: errors.New("raft delete failed"),
	}
	svc, _ := newCreateService(t, stub, false)
	if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-del-fail"); err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	retractFailedPromote(context.Background(), svc, stub, logger, "sb-del-fail")
	if stub.deletes != 1 {
		t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
	}
}

func TestRetractReservedCreateDeleteSecretsFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, st := newCreateService(t, stub, true)
	if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-secrets-del"); err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	_ = st.Close()
	retractReservedCreate(context.Background(), svc, stub, logger, "sb-secrets-del", nil)
	if stub.cancels != 1 {
		t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
	}
}

func TestDeletePlacementBestEffortLogsDeleteError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{
		Noop:      cluster.NewNoop("node-a", "", ""),
		deleteErr: errors.New("delete failed"),
	}
	DeletePlacementBestEffort(context.Background(), testServiceWithCluster(stub), logger, "sb-log-del")
	if stub.deletes != 1 {
		t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
	}
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

func TestDeletePlacementBestEffortDeleteErrorNilLogger(t *testing.T) {
	stub := &clusterStub{
		Noop:      cluster.NewNoop("node-a", "", ""),
		deleteErr: errors.New("delete failed"),
	}
	DeletePlacementBestEffort(context.Background(), testServiceWithCluster(stub), nil, "sb-nil-logger")
	if stub.deletes != 1 {
		t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
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

func TestRetractFailedPromoteDeleteSecretsFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, st := newCreateService(t, stub, true)
	if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-secrets-fail"); err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	_ = st.Close()
	retractFailedPromote(context.Background(), svc, stub, logger, "sb-secrets-fail")
	if stub.deletes != 1 {
		t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
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
