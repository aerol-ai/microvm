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

// reclaimStubCluster answers the delete_with_sandbox reclaim query.
type reclaimStubCluster struct {
	*cluster.Noop
	reclaims []cluster.VolumeReclaim
	err      error
	node     string
	limit    int
}

func (c *reclaimStubCluster) VolumeReclaimsReplicated() bool { return true }
func (c *reclaimStubCluster) VolumeReclaimsFor(_ context.Context, nodeID string, limit int) ([]cluster.VolumeReclaim, error) {
	c.node, c.limit = nodeID, limit
	return c.reclaims, c.err
}
func (c *reclaimStubCluster) ClaimVolumeReclaim(context.Context, cluster.VolumeReclaim, string) error {
	return nil
}
func (c *reclaimStubCluster) AckVolumeReclaim(context.Context, cluster.VolumeReclaim) error {
	return nil
}
func (c *reclaimStubCluster) VolumeDeleteOwingBytes(context.Context, string, string, string) error {
	return nil
}

// A worker's reclaim sweep asks a server which delete_with_sandbox volumes
// it should drain; a server without the ledger says it does not know the
// kind, so the worker skips the pass.
func TestClusterInternalVolumeReclaims(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	entry := cluster.VolumeReclaim{Tenant: "t-a", VolumeID: "vol-d", Source: "b/d", NodeID: "wkr-a", RecordedUnixNano: 7}
	cases := []struct {
		name    string
		cluster cluster.Client
		status  int
	}{
		{"no ledger on this client", cluster.NewNoop("self", "http://self", ""), http.StatusBadRequest},
		{"list", &reclaimStubCluster{Noop: cluster.NewNoop("self", "http://self", ""), reclaims: []cluster.VolumeReclaim{entry}}, http.StatusOK},
		{"list fails", &reclaimStubCluster{Noop: cluster.NewNoop("self", "http://self", ""), err: errors.New("fsm away")}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
			svc.AttachCluster(tc.cluster)
			h := &handlers{deps: Deps{Service: svc, Logger: logger}}
			rr := httptest.NewRecorder()
			h.clusterInternalVolume(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/volume?kind=reclaims&node_id=wkr-a&limit=5", nil))
			if rr.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.status, rr.Body.String())
			}
			stub, ok := tc.cluster.(*reclaimStubCluster)
			if !ok || tc.status != http.StatusOK {
				return
			}
			if stub.node != "wkr-a" || stub.limit != 5 {
				t.Fatalf("asked for node %q limit %d", stub.node, stub.limit)
			}
			var resp cluster.VolumeQueryResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || len(resp.Reclaims) != 1 || resp.Reclaims[0] != entry {
				t.Fatalf("reclaims = %+v, %v", resp, err)
			}
		})
	}
}
