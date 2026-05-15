package v1

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

type createForwardCluster struct {
	*cluster.Noop
	target             cluster.PlacementTarget
	forwardedPeer      string
	forwardedTarget    string
	selectPlacementHit int
}

func (c *createForwardCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	c.selectPlacementHit++
	return c.target, nil
}

func (c *createForwardCluster) ForwardHTTP(peerAPIURL string, w http.ResponseWriter, r *http.Request) {
	c.forwardedPeer = peerAPIURL
	c.forwardedTarget = r.Header.Get(clusterCreateTargetHeader)
	w.WriteHeader(http.StatusAccepted)
}

func TestClusterCreateWrapPinsForwardedCreateToSelectedTarget(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a"),
		target: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if fakeCluster.forwardedPeer != "http://node-b:21212" {
		t.Fatalf("forwarded peer = %q, want node-b API URL", fakeCluster.forwardedPeer)
	}
	if fakeCluster.forwardedTarget != "node-b" {
		t.Fatalf("%s = %q, want node-b", clusterCreateTargetHeader, fakeCluster.forwardedTarget)
	}
	if fakeCluster.selectPlacementHit != 1 {
		t.Fatalf("SelectPlacement calls = %d, want 1", fakeCluster.selectPlacementHit)
	}
}

func TestClusterCreateWrapRejectsCreateForwardedToWrongNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a"),
		target: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	req.Header.Set(clusterCreateTargetHeader, "node-b")
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusMisdirectedRequest)
	}
	if fakeCluster.selectPlacementHit != 0 {
		t.Fatalf("SelectPlacement calls = %d, want 0", fakeCluster.selectPlacementHit)
	}
}

var _ cluster.Client = (*createForwardCluster)(nil)
