package clusterroute

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The header names are written out (not cluster.HeaderRouteHint /
// HeaderNotOwner) on purpose: this file is the owner-side contract of the
// owner cache, and it must compile against a build without the cache to show
// that build serves or 404s a stale cache-routed forward.
const (
	routeHintHeader = "X-Cluster-Route-Hint"
	notOwnerHeader  = "X-Cluster-Not-Owner"
)

// A forward the edge routed from its owner cache is served only by a node
// whose own lookup says it owns the sandbox. Every other outcome is a 421
// that echoes the edge's token, and the local handler never runs: a stale
// cache entry must never turn into a 404 (local serve of an unknown id), a
// 410, a 503, or a serve on a node that no longer owns the sandbox.
func TestWrapCacheRoutedForwardIsServedOnlyByTheOwner(t *testing.T) {
	peer := cluster.OwnerInfo{NodeID: "worker-b", APIURL: "http://worker-b", InternalURL: "https://worker-b:7002"}
	self := cluster.OwnerInfo{NodeID: "self", IsSelf: true}
	tests := []struct {
		name      string
		stub      cluster.Client
		tenant    string // caller's OwnerRef; "" = operator
		wantLocal bool
	}{
		{name: "deleted: no placement", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}},
		{name: "orphaned", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrOrphaned}},
		{name: "moved to another node", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: peer}},
		{name: "moved, owner URL not known yet", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{NodeID: "worker-b"}}},
		{name: "lookup failed", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: errors.New("control plane unreachable")}},
		{
			name:   "another tenant's sandbox",
			stub:   &placementStub{stubCluster: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: self}, hasPlace: true, placement: cluster.Placement{OwnerRef: "acct-b"}},
			tenant: "acct-a",
		},
		{name: "owned here", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: self}, wantLocal: true},
		{
			name:      "owned here, caller's own tenant",
			stub:      &placementStub{stubCluster: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: self}, hasPlace: true, placement: cluster.Placement{OwnerRef: "acct-a"}},
			tenant:    "acct-a",
			wantLocal: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sawHint string
			ran := false
			lh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				sawHint = r.Header.Get(routeHintHeader)
				w.WriteHeader(http.StatusNoContent)
			})
			h := Wrap(svcWith(t, tc.stub), Options{WriteError: writeErr}, lh)
			r := req("sb-1")
			r.Header.Set("X-Cluster-Forwarded", "1")
			r.Header.Set(routeHintHeader, "tok-123")
			if tc.tenant != "" {
				r = r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{
					Identity: controlplane.Identity{ExternalID: "u", OwnerRef: tc.tenant},
				}))
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)

			if tc.wantLocal {
				if !ran || rr.Code != http.StatusNoContent {
					t.Fatalf("owner did not serve: ran=%v status=%d body=%q", ran, rr.Code, rr.Body.String())
				}
				if sawHint != "" {
					t.Fatalf("local handler saw the route-hint token %q; it must be dropped before any handler runs", sawHint)
				}
				if got := rr.Header().Get(notOwnerHeader); got != "" {
					t.Fatalf("served answer carries %s=%q", notOwnerHeader, got)
				}
				return
			}
			if ran {
				t.Fatalf("local handler ran on a node that does not own the sandbox (status %d)", rr.Code)
			}
			if rr.Code != http.StatusMisdirectedRequest {
				t.Fatalf("status = %d, want 421 (body %q)", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get(notOwnerHeader); got != "tok-123" {
				t.Fatalf("%s = %q, want the edge's token %q", notOwnerHeader, got, "tok-123")
			}
		})
	}
}

// Without the route hint a forwarded request keeps every answer it has
// always had: the "not here" exists only for cache-routed forwards.
func TestWrapPlainForwardKeepsItsAnswers(t *testing.T) {
	tests := []struct {
		name       string
		stub       *stubCluster
		wantStatus int // 0 = served locally
	}{
		{name: "unknown: local handler answers", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}},
		{name: "orphaned: 410", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrOrphaned}, wantStatus: http.StatusGone},
		{name: "other owner: loop 421", stub: &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{NodeID: "worker-b", APIURL: "http://worker-b"}}, wantStatus: http.StatusMisdirectedRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lh, ran := local()
			h := Wrap(svcWith(t, tc.stub), Options{WriteError: writeErr}, lh)
			r := req("sb-1")
			r.Header.Set("X-Cluster-Forwarded", "1")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if tc.wantStatus == 0 {
				if !*ran {
					t.Fatalf("local handler did not run; status %d", rr.Code)
				}
				return
			}
			if *ran || rr.Code != tc.wantStatus {
				t.Fatalf("ran=%v status=%d, want %d", *ran, rr.Code, tc.wantStatus)
			}
			if got := rr.Header().Get(notOwnerHeader); got != "" {
				t.Fatalf("plain forward answered with %s=%q", notOwnerHeader, got)
			}
		})
	}
}
