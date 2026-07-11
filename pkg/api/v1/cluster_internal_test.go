package v1

import (
	"context"
	"encoding/base64"
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
	"github.com/aerol-ai/microvm/pkg/models"
)

func newClusterInternalHandler(t *testing.T) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func TestClusterInternalHandlers_BasicCoverage(t *testing.T) {
	h := newClusterInternalHandler(t)

	t.Run("apply_empty_body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", nil)
		h.clusterInternalApply(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("placement_missing_id", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement", nil)
		req.SetPathValue("id", "")
		h.clusterInternalPlacement(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("placement_by_name_invalid_base64", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name", nil)
		req.SetPathValue("name", "%%notbase64%%")
		h.clusterInternalPlacementByName(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("placement_by_name_unknown", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("missing"))
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placement-by-name/"+encoded, nil)
		req.SetPathValue("name", encoded)
		h.clusterInternalPlacementByName(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("placements_list_ok", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/placements", nil)
		h.clusterInternalPlacements(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("placements_query_invalid_json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/query", strings.NewReader("{bad"))
		h.clusterInternalPlacementsQuery(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("placements_query_ok", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"shards": []int{0, 1}})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/query", strings.NewReader(string(body)))
		h.clusterInternalPlacementsQuery(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("placements_page_invalid_json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/page", strings.NewReader("{bad"))
		h.clusterInternalPlacementsPage(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("placements_page_ok", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/placements/page", strings.NewReader(`{"cursor":"","limit":10}`))
		h.clusterInternalPlacementsPage(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("recovery_get_unavailable", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/recovery/ref-1", nil)
		req.SetPathValue("ref", "ref-1")
		h.clusterInternalRecoveryGet(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("get status = %d, want 503", rr.Code)
		}
	})

	t.Run("select_placement_invalid_and_ok", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader("{bad"))
		h.clusterInternalSelectPlacement(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader(`{"request":{"cpu":1,"memory_mb":256,"disk_gb":1}}`))
		h.clusterInternalSelectPlacement(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("drain_state_ok", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/drain/node-a", nil)
		req.SetPathValue("id", "node-a")
		h.clusterInternalDrainState(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("volume_query_kinds", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := service.New(config.Config{EnableCluster: true, PATToken: "op"}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := cluster.NewNoop("self", "http://self", "")
		svc.AttachCluster(c)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		ctx := context.Background()
		v := models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
		if _, _, err := c.VolumeUpsert(ctx, v, 0); err != nil {
			t.Fatalf("seed volume: %v", err)
		}
		_ = c.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
			Tenant: "t-a", VolumeID: "vol-1", SandboxID: "sb-1", Target: "/data", Source: "bucket/t-a/data",
		}})

		cases := []struct {
			kind   string
			query  string
			status int
		}{
			{"id", "kind=id&tenant=t-a&id=vol-1", http.StatusOK},
			{"name", "kind=name&tenant=t-a&name=data", http.StatusOK},
			{"list", "kind=list&tenant=t-a", http.StatusOK},
			{"source", "kind=source&source=bucket/t-a/data", http.StatusOK},
			{"attachment_count", "kind=attachment_count&tenant=t-a&id=vol-1", http.StatusOK},
			{"missing id", "kind=id&tenant=t-a&id=missing", http.StatusNotFound},
			{"bad kind", "kind=unknown", http.StatusBadRequest},
		}
		for _, tc := range cases {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/volume?"+tc.query, nil)
			h.clusterInternalVolume(rr, req)
			if rr.Code != tc.status {
				t.Fatalf("%s: status = %d, want %d; body=%s", tc.kind, rr.Code, tc.status, rr.Body.String())
			}
		}
	})

	t.Run("volume_no_cluster", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/volume?kind=id&tenant=t-a&id=vol-1", nil)
		h.clusterInternalVolume(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
	})
}
