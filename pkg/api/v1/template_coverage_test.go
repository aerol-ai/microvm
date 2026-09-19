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
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestForwardTemplateToLeaderBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	empty := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", "")},
		leader:             "",
	}
	rr := httptest.NewRecorder()
	if !h.forwardTemplateToLeader(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil), empty, clusterTemplateAggregateHeader) || rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty leader status = %d", rr.Code)
	}

	self := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", "")},
		leader:             "self",
	}
	if h.forwardTemplateToLeader(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/templates", nil), self, clusterTemplateAggregateHeader) {
		t.Fatal("self leader must not forward")
	}

	missing := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{
			Noop:    cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{{NodeID: "self", Alive: true}},
		},
		leader: "gone",
	}
	missRR := httptest.NewRecorder()
	if !h.forwardTemplateToLeader(missRR, httptest.NewRequest(http.MethodGet, "/v1/templates", nil), missing, clusterTemplateAggregateHeader) || missRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing leader status = %d", missRR.Code)
	}

	dead := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "lead", Alive: false, InternalURL: ""},
			},
		},
		leader: "lead",
	}
	deadRR := httptest.NewRecorder()
	if !h.forwardTemplateToLeader(deadRR, httptest.NewRequest(http.MethodGet, "/v1/templates", nil), dead, clusterTemplateAggregateHeader) || deadRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("dead leader status = %d", deadRR.Code)
	}

	// LookupMember miss + Members() hit is the test-client fallback.
	member, found := templateMemberByID(&membersStubCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		members: []cluster.Member{
			{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
		},
	}, "peer")
	if !found || member.NodeID != "peer" {
		t.Fatalf("Members fallback = %+v found=%v", member, found)
	}
	if _, ok := templateMemberByID(&membersStubCluster{Noop: cluster.NewNoop("self", "http://self", "")}, "nope"); ok {
		t.Fatal("expected miss")
	}
	if n := clusterRuntimeUnavailablePeerCount(nil, models.RuntimeFirecracker, nil, nil); n != 0 {
		t.Fatalf("nil cluster count = %d", n)
	}
}

func TestClusterCreateTemplateWrapPlacementErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&createForwardCluster{
		Noop:      cluster.NewNoop("server-a", "http://server-a", ""),
		selectErr: cluster.ErrInvalidTopology,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	rr := httptest.NewRecorder()
	h.clusterCreateTemplateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterListTemplatesWrapLocalErrorEmptyMerge(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	_ = env.store.Close()
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected local list error when store is closed")
	}
}

func TestClusterCreateTemplateWrapForwardedHeaderBypass(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`))
	req.Header.Set(clusterTemplateForwardedHeader, "1")
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted && rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
}
