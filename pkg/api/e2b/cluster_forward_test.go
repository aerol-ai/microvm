package e2b

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
)

type mockCluster struct {
	cluster.Client
	owner         cluster.OwnerInfo
	ownerErr      error
	forwardCalled bool
}

func (m *mockCluster) OwnerOf(sandboxID string) (cluster.OwnerInfo, error) {
	return m.owner, m.ownerErr
}

func (m *mockCluster) ForwardHTTP(ep cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	m.forwardCalled = true
	w.WriteHeader(http.StatusAccepted)
}

func TestClusterForwardWrap(t *testing.T) {
	localHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	createSvc := func(c cluster.Client) *service.Service {
		s := &service.Service{}
		s.AttachCluster(c)
		return s
	}

	cases := []struct {
		name        string
		depsService *service.Service
		pathID      string
		header      string
		wantStatus  int
		wantForward bool
	}{
		{
			name:       "nil_service",
			wantStatus: http.StatusOK,
		},
		{
			name:        "nil_cluster",
			depsService: &service.Service{},
			wantStatus:  http.StatusOK,
		},
		{
			name:        "unknown_sandbox",
			depsService: createSvc(&mockCluster{ownerErr: cluster.ErrUnknownSandbox}),
			wantStatus:  http.StatusOK,
		},
		{
			name:        "orphaned_sandbox",
			depsService: createSvc(&mockCluster{ownerErr: cluster.ErrOrphaned}),
			wantStatus:  http.StatusGone,
		},
		{
			name:        "other_error",
			depsService: createSvc(&mockCluster{ownerErr: errors.New("boom")}),
			wantStatus:  http.StatusServiceUnavailable,
		},
		{
			name:        "is_self",
			depsService: createSvc(&mockCluster{owner: cluster.OwnerInfo{IsSelf: true}}),
			wantStatus:  http.StatusOK,
		},
		{
			name:        "no_urls",
			depsService: createSvc(&mockCluster{owner: cluster.OwnerInfo{IsSelf: false, NodeID: "n1"}}),
			wantStatus:  http.StatusServiceUnavailable,
		},
		{
			name:        "forwarding_loop",
			depsService: createSvc(&mockCluster{owner: cluster.OwnerInfo{IsSelf: false, APIURL: "http://api"}}),
			header:      "1",
			wantStatus:  http.StatusMisdirectedRequest,
		},
		{
			name:        "successful_forward",
			depsService: createSvc(&mockCluster{owner: cluster.OwnerInfo{IsSelf: false, APIURL: "http://api"}}),
			wantStatus:  http.StatusAccepted,
			wantForward: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &handlers{deps: Deps{Service: tc.depsService}}
			wrapped := h.clusterForwardWrap(localHandler)

			req := httptest.NewRequest(http.MethodGet, "/sandboxes/test-id", nil)
			req.SetPathValue("id", "test-id")
			if tc.header != "" {
				req.Header.Set("X-Cluster-Forwarded", tc.header)
			}
			rr := httptest.NewRecorder()

			wrapped.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}

			if tc.depsService != nil && tc.depsService.Cluster() != nil {
				mc := tc.depsService.Cluster().(*mockCluster)
				if mc.forwardCalled != tc.wantForward {
					t.Fatalf("forwardCalled = %v, want %v", mc.forwardCalled, tc.wantForward)
				}
			}
		})
	}
}
