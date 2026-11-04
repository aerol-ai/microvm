package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

type snapHomeInternalStub struct {
	*cluster.Noop
	home      string
	found     bool
	lookupErr error
}

func (c *snapHomeInternalStub) SnapshotHomeNode(context.Context, string) (string, bool, error) {
	return c.home, c.found, c.lookupErr
}

func TestClusterInternalSnapshotNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("found", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&snapHomeInternalStub{Noop: cluster.NewNoop("self", "", ""), home: "node-x", found: true})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterInternalSnapshotNode(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/snapshot-node?name=snap-a", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var resp cluster.SnapshotNodeQueryResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.NodeID != "node-x" || !resp.Found {
			t.Fatalf("resp = %+v, want node-x/found", resp)
		}
	})

	t.Run("lookup error", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&snapHomeInternalStub{Noop: cluster.NewNoop("self", "", ""), lookupErr: errors.New("boom")})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterInternalSnapshotNode(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/snapshot-node?name=snap-a", nil))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 on lookup error", rr.Code)
		}
	})

	t.Run("no cluster", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterInternalSnapshotNode(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/snapshot-node?name=snap-a", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
	})
}
