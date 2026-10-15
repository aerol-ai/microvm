package clusterroute

import (
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

// stubCluster is a cluster.Client (via Noop) with scriptable ownership.
type stubCluster struct {
	*cluster.Noop
	owner     cluster.OwnerInfo
	ownerErr  error
	nameOwner cluster.OwnerInfo
	nameErr   error
	forwarded bool
}

func (c *stubCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, c.ownerErr
}
func (c *stubCluster) OwnerOfName(string, string) (string, cluster.OwnerInfo, error) {
	return "", c.nameOwner, c.nameErr
}
func (c *stubCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	c.forwarded = true
	w.WriteHeader(http.StatusAccepted)
}

func svcWith(t *testing.T, c cluster.Client) *service.Service {
	t.Helper()
	svc := service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	if c != nil {
		svc.AttachCluster(c)
	}
	return svc
}

func noopStub() *stubCluster { return &stubCluster{Noop: cluster.NewNoop("self", "http://self", "")} }

func local() (http.Handler, *bool) {
	ran := new(bool)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusNoContent)
	}), ran
}

func req(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x/"+id, nil)
	r.SetPathValue("id", id)
	return r
}

// The one wrapper routes every ownership case the same way for every facade.
func TestWrap(t *testing.T) {
	peer := cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"}
	tests := []struct {
		name       string
		stub       *stubCluster
		nilSvc     bool
		id         string
		forwarded  string // X-Cluster-Forwarded header
		wantStatus int    // 0 = served locally
		wantFwd    bool
	}{
		{name: "no id", stub: noopStub(), id: "", wantStatus: 0},
		{name: "unknown sandbox", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}, id: "sb", wantStatus: 0},
		{name: "orphaned", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrOrphaned}, id: "sb", wantStatus: http.StatusGone},
		{name: "lookup error", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: errors.New("boom")}, id: "sb", wantStatus: http.StatusServiceUnavailable},
		{name: "self owns it", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{IsSelf: true}}, id: "sb", wantStatus: 0},
		{name: "route miss", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{NodeID: "worker-a"}}, id: "sb", wantStatus: http.StatusServiceUnavailable},
		{name: "forward to owner", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: peer}, id: "sb", wantStatus: http.StatusAccepted, wantFwd: true},
		{name: "loop guard", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: peer}, id: "sb", forwarded: "1", wantStatus: http.StatusMisdirectedRequest},
		{name: "nil service", nilSvc: true, id: "sb", wantStatus: 0},
		{name: "no cluster attached", stub: nil, id: "sb", wantStatus: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var svc *service.Service
			if !tc.nilSvc {
				if tc.stub == nil {
					svc = svcWith(t, nil)
					svc.ClearClusterForTest() // service present, no cluster client
				} else {
					svc = svcWith(t, tc.stub)
				}
			}
			lh, ran := local()
			h := Wrap(svc, Options{WriteError: writeErr}, lh)
			r := req(tc.id)
			if tc.forwarded != "" {
				r.Header.Set("X-Cluster-Forwarded", tc.forwarded)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if tc.wantStatus == 0 {
				if !*ran {
					t.Fatalf("expected local handler to run; status %d", rr.Code)
				}
				return
			}
			if *ran {
				t.Fatalf("local handler ran; wanted status %d", tc.wantStatus)
			}
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.stub != nil && tc.stub.forwarded != tc.wantFwd {
				t.Fatalf("forwarded = %v, want %v", tc.stub.forwarded, tc.wantFwd)
			}
		})
	}
}

// ResolveName forwards a per-owner name that is not a known id.
func TestWrapResolvesName(t *testing.T) {
	stub := &stubCluster{
		Noop:      cluster.NewNoop("self", "", ""),
		ownerErr:  cluster.ErrUnknownSandbox,
		nameOwner: cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"},
	}
	lh, ran := local()
	h := Wrap(svcWith(t, stub), Options{PathKey: "idOrName", ResolveName: true, WriteError: writeErr}, lh)
	r := httptest.NewRequest(http.MethodGet, "/x/my-name", nil)
	r.SetPathValue("idOrName", "my-name")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if *ran || rr.Code != http.StatusAccepted || !stub.forwarded {
		t.Fatalf("name route: ran=%v status=%d forwarded=%v", *ran, rr.Code, stub.forwarded)
	}
}

// The id may come from a header (plan B5: /e2b/runtime).
func TestWrapIDFromHeader(t *testing.T) {
	stub := &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"}}
	lh, ran := local()
	h := Wrap(svcWith(t, stub), Options{
		ID:         func(r *http.Request) string { return r.Header.Get("E2b-Sandbox-Id") },
		WriteError: writeErr,
	}, lh)
	r := httptest.NewRequest(http.MethodGet, "/e2b/runtime/process", nil)
	r.Header.Set("E2b-Sandbox-Id", "sb-remote")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if *ran || rr.Code != http.StatusAccepted || !stub.forwarded {
		t.Fatalf("header route: ran=%v status=%d forwarded=%v", *ran, rr.Code, stub.forwarded)
	}
}

func writeErr(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
}
