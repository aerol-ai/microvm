package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

type changesStubCluster struct {
	*cluster.Noop
	gotSince uint64
	gotWait  time.Duration
}

func (c *changesStubCluster) PlacementChanges(_ context.Context, since uint64, wait time.Duration) cluster.PlacementChangesResponse {
	c.gotSince, c.gotWait = since, wait
	return cluster.PlacementChangesResponse{
		Next: 42,
		Changes: []cluster.PlacementChange{
			{Index: 41, SandboxID: "sb1", Placement: &cluster.Placement{SandboxID: "sb1", SecretRef: "sealed-ref", SecretVersion: 3}},
			{Index: 42, SandboxID: "sb2", Deleted: true},
		},
	}
}

func placementChangesHandlers(t *testing.T, c cluster.Client) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	if c != nil {
		svc.AttachCluster(c)
	}
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func TestClusterInternalPlacementChangesHandler(t *testing.T) {
	stub := &changesStubCluster{Noop: cluster.NewNoop("srv", "", "")}
	h := placementChangesHandlers(t, stub)

	rr := httptest.NewRecorder()
	h.clusterInternalPlacementChanges(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementChangesPath+"?since=40&wait=5s", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if stub.gotSince != 40 || stub.gotWait != 5*time.Second {
		t.Fatalf("server got since=%d wait=%v, want 40 and 5s", stub.gotSince, stub.gotWait)
	}
	var resp cluster.PlacementChangesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Next != 42 || len(resp.Changes) != 2 || !resp.Changes[1].Deleted {
		t.Fatalf("resp = %+v", resp)
	}
	// Same redaction as the page walk it replaces.
	if p := resp.Changes[0].Placement; p == nil || p.SecretRef != "" || p.SecretVersion != 0 {
		t.Fatalf("secret handle leaked through the feed: %+v", p)
	}

	for _, bad := range []string{"?since=abc", "?since=-1", "?wait=nope", "?wait=-3s"} {
		rr := httptest.NewRecorder()
		h.clusterInternalPlacementChanges(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementChangesPath+bad, nil))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, rr.Code)
		}
	}
}

// Agents and the single-node Noop hold no change log: 503, never an empty
// "no changes" that a caller would trust.
func TestClusterInternalPlacementChangesNotServedWithoutALog(t *testing.T) {
	for name, c := range map[string]cluster.Client{
		"noop":       cluster.NewNoop("n", "", ""),
		"no cluster": nil,
	} {
		h := placementChangesHandlers(t, c)
		if c == nil {
			h.deps.Service.ClearClusterForTest()
		}
		rr := httptest.NewRecorder()
		h.clusterInternalPlacementChanges(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalPlacementChangesPath, nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503", name, rr.Code)
		}
	}
}
