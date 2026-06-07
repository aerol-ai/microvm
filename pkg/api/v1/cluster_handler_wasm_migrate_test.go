package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

type ownerCluster struct {
	*cluster.Noop
	owner cluster.OwnerInfo
}

func (c *ownerCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, nil
}

func TestClusterWasmMigrateRequiresCluster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.ClearClusterForTest()
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, cluster.PublicWasmMigratePath, strings.NewReader(`{"sandbox_id":"sb-1","target_node_id":"node-b"}`))
	rr := httptest.NewRecorder()
	h.clusterWasmMigrate(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterWasmMigrateRejectsInvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, cluster.PublicWasmMigratePath, strings.NewReader(`not-json`))
	rr := httptest.NewRecorder()
	h.clusterWasmMigrate(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestClusterInternalWasmMigrateExportRequiresOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&ownerCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
		owner: cluster.OwnerInfo{NodeID: "node-b", IsSelf: false},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-1/export", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterInternalWasmMigrateExport(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}

func TestClusterInternalWasmMigrateImportMissingCloneGenAllowed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()}, logger, nil, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	body := bytes.NewReader([]byte{})
	req := httptest.NewRequest(http.MethodPut, cluster.PublicInternalWasmMigratePath+"sb-1/import", body)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterInternalWasmMigrateImport(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Fatal("expected import failure without tar body")
	}
}

func TestClusterWasmMigrateRequestShape(t *testing.T) {
	var req service.WasmMigrateRequest
	if err := json.Unmarshal([]byte(`{"sandbox_id":"sb","target_node_id":"node-b"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.SandboxID != "sb" || req.TargetNodeID != "node-b" {
		t.Fatalf("req = %+v", req)
	}
}

var _ = context.Background
