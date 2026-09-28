package ingressproxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/routedns"
)

func newRouterHandler(res PortResolver, hosts *HostRoutes) http.Handler {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Resolver:       res,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBufferBytes: 1 << 20,
		Hosts:          hosts,
	})
	return mux
}

func do(h http.Handler, host, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// An owner-table hit (wake, masked, mediator) serves through the same wake
// proxy as the path route: the original path goes upstream.
func TestHostRouterOwnerHitServesThroughTheWakeProxy(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "sandbox")
	}))
	defer upstream.Close()
	res := &fakeResolver{target: upstream.URL, started: true}
	owner := routedns.NewOwnerTable()
	owner.Set("sb1-8080.d.test", routedns.OwnerTarget{State: routedns.TargetWake, SandboxID: "sb1", GuestPort: 8080})
	h := newRouterHandler(res, &HostRoutes{Owner: owner, ClusterMode: true})

	rr := do(h, "SB1-8080.d.test:443", "/api/items")
	if rr.Code != http.StatusOK || rr.Body.String() != "sandbox" {
		t.Fatalf("owner hit: %d %q", rr.Code, rr.Body.String())
	}
	if res.lastID != "sb1" || res.lastPrt != 8080 || gotPath != "/api/items" {
		t.Fatalf("resolved %s:%d path %q, want sb1:8080 /api/items", res.lastID, res.lastPrt, gotPath)
	}
}

func TestHostRouterAnswers(t *testing.T) {
	owner := routedns.NewOwnerTable()
	owner.Set("moving.d.test", routedns.OwnerTarget{State: routedns.TargetInFlux, SandboxID: "mv", GuestPort: 2280})
	owner.Set("broken.d.test", routedns.OwnerTarget{State: routedns.TargetRouter}) // no id/port
	ingress := routedns.NewIngressIndex()
	ingress.Replace([]cluster.Placement{
		{SandboxID: "remote", OwnerNodeID: "w2", OwnerDataPlaneHost: "10.0.0.2", PublicTraffic: true},
		{SandboxID: "mine", OwnerNodeID: "self", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true},
		{SandboxID: "priv", OwnerNodeID: "w2", OwnerDataPlaneHost: "10.0.0.2"},
		{SandboxID: "orph", OwnerDataPlaneHost: "10.0.0.3", PublicTraffic: true},
	}, "d.test")

	tests := []struct {
		name  string
		hosts *HostRoutes
		host  string
		want  int
		retry bool
	}{
		{"owner in flux", &HostRoutes{Owner: owner}, "moving.d.test", http.StatusServiceUnavailable, true},
		{"owner entry without a target", &HostRoutes{Owner: owner}, "broken.d.test", http.StatusNotFound, false},
		{"ingress: owned elsewhere (coalescing)", &HostRoutes{Owner: owner, Ingress: ingress, SelfNodeID: "self"}, "remote.d.test", http.StatusMisdirectedRequest, false},
		{"ingress: owned here, no route", &HostRoutes{Owner: owner, Ingress: ingress, SelfNodeID: "self"}, "mine.d.test", http.StatusNotFound, false},
		{"ingress: private", &HostRoutes{Ingress: ingress, SelfNodeID: "self"}, "priv.d.test", http.StatusNotFound, false},
		{"ingress: in flux", &HostRoutes{Ingress: ingress, SelfNodeID: "self"}, "orph.d.test", http.StatusServiceUnavailable, true},
		{"ingress: unknown (full index)", &HostRoutes{Ingress: ingress, SelfNodeID: "self", ClusterMode: true}, "ghost.d.test", http.StatusNotFound, false},
		{"worker in a cluster: bounce", &HostRoutes{Owner: owner, ClusterMode: true}, "ghost.d.test", http.StatusMisdirectedRequest, false},
		{"single-node: not found", &HostRoutes{Owner: owner}, "ghost.d.test", http.StatusNotFound, false},
		{"empty host", &HostRoutes{Owner: owner, ClusterMode: true}, "", http.StatusNotFound, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := do(newRouterHandler(&fakeResolver{}, tc.hosts), tc.host, "/")
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.want, rr.Body.String())
			}
			if tc.retry && rr.Header().Get("Retry-After") != "2" {
				t.Fatal("503 must carry Retry-After: 2")
			}
			if tc.want == http.StatusMisdirectedRequest && rr.Header().Get("Connection") != "close" {
				t.Fatal("421 must close the connection so the client reconnects")
			}
		})
	}
}

// Flag off (Hosts nil): no catch-all is mounted, so behaviour is exactly as
// before. The wake path route and the TLS ask endpoint keep precedence when
// it IS mounted.
func TestHostRouterMountingAndPrecedence(t *testing.T) {
	off := newRouterHandler(&fakeResolver{}, nil)
	if rr := do(off, "x.d.test", "/"); rr.Code != http.StatusNotFound {
		t.Fatalf("flag off: status %d, want the mux's plain 404", rr.Code)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "wake") }))
	defer upstream.Close()
	on := newRouterHandler(&fakeResolver{target: upstream.URL, started: true}, &HostRoutes{Owner: routedns.NewOwnerTable(), ClusterMode: true})
	if rr := do(on, "anything.d.test", PathPrefix+"/sb1/8080/"); rr.Code != http.StatusOK || rr.Body.String() != "wake" {
		t.Fatalf("wake path route shadowed by the host router: %d %q", rr.Code, rr.Body.String())
	}
	var hosts *HostRoutes
	h := &handlers{deps: Deps{Hosts: hosts}}
	rr := httptest.NewRecorder()
	h.hostRoute(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("nil HostRoutes: %d", rr.Code)
	}
}

func TestRequestHost(t *testing.T) {
	for in, want := range map[string]string{
		"A.B.test:443": "a.b.test", "a.b.test.": "a.b.test", "[::1]:8080": "::1", "plain": "plain",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = in
		if got := requestHost(r); got != want {
			t.Errorf("requestHost(%q) = %q, want %q", in, got, want)
		}
	}
}
