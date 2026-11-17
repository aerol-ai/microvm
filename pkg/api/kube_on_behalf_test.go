package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// A forward the edge speaks for on behalf of a Kubernetes caller (C17) gets
// that caller's access on the peer, one owner and the runner role, never
// the node's own, and only on the calls the agent-sandbox API makes;
// anything malformed, or not from a vouched-for peer, is a refusal.
func TestOnBehalfForwards(t *testing.T) {
	srv := patFreeServer(t, config.PATScopeAny)
	path := "/v1/sandboxes/sb-missing"
	method := http.MethodDelete
	call := func(headers map[string]string, peer, internal bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "10.0.0.9:7002"
		if peer {
			req.TLS = peerTLS("peer-test")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if internal {
			req = req.WithContext(cluster.ContextWithInternalPeer(req.Context(), "peer-test"))
		}
		// This node has no store: a call that gets past authentication may
		// stop in its handler, which is not what this test is about.
		rec, _ := serveRecover(srv.Handler(), req)
		return rec
	}
	full := map[string]string{cluster.HeaderForwarded: "1", cluster.HeaderCaller: cluster.CallerNode,
		cluster.HeaderOnBehalfOf: "kubernetes:alice", cluster.HeaderOnBehalfOwner: "team:dev"}
	// Authenticated as the caller, owner team:dev: the delete reaches the
	// handler (not a 401 or 403).
	if rec := call(full, true, true); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("on behalf = %d %s", rec.Code, rec.Body.String())
	}
	// Who it is, through the edge's own in-process check of the principal.
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Pattern = "DELETE /v1/sandboxes/{id}"
	req.TLS = peerTLS("peer-test")
	for k, v := range full {
		req.Header.Set(k, v)
	}
	req = req.WithContext(cluster.ContextWithInternalPeer(req.Context(), "peer-test"))
	who, ok := nodeCertAccess(req, srv.nodeRole)
	if !ok || who.Principal.Kind != controlplane.PrincipalKubernetes || who.Principal.ID != "kubernetes:alice" ||
		who.Identity.OwnerRef != "team:dev" || who.Role != controlplane.RoleRunner {
		t.Fatalf("on behalf access = %+v %v", who, ok)
	}
	// Any other route, whoami included, is not one the API calls.
	method, path = http.MethodGet, "/v1/whoami"
	if rec := call(full, true, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("on behalf on whoami = %d, want 401", rec.Code)
	}
	method, path = http.MethodDelete, "/v1/sandboxes/sb-missing"
	without := func(key string) map[string]string {
		out := map[string]string{}
		for k, v := range full {
			if k != key {
				out[k] = v
			}
		}
		return out
	}
	with := func(key, value string) map[string]string {
		out := without(key)
		out[key] = value
		return out
	}
	for name, tc := range map[string]struct {
		headers        map[string]string
		peer, internal bool
	}{
		"no owner":                {without(cluster.HeaderOnBehalfOwner), true, true},
		"not a Kubernetes caller": {with(cluster.HeaderOnBehalfOf, "oidc:alice"), true, true},
		"an empty user":           {with(cluster.HeaderOnBehalfOf, "kubernetes:"), true, true},
		"not a forward":           {without(cluster.HeaderForwarded), true, true},
		"the edge not speaking":   {without(cluster.HeaderCaller), true, true},
		"no peer certificate":     {full, false, true},
		"no internal listener":    {full, true, false},
	} {
		// 401 from the auth step, or 403 from the guard that refuses
		// X-Cluster-* headers from anything but a peer.
		if rec := call(tc.headers, tc.peer, tc.internal); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want a refusal", name, rec.Code)
		}
	}
}

// The edge stamps a Kubernetes caller's forward: no credential, the node
// speaks, and whom for; any other forward carries no such stamp, even one
// copied from the inbound request.
func TestStampForwardOnBehalf(t *testing.T) {
	kube := controlplane.Access{Identity: controlplane.Identity{OwnerRef: "team:dev"}, Role: controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalKubernetes, ID: "kubernetes:alice"}}
	out := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	out.Header.Set("Authorization", "Bearer leftover")
	cluster.StampForward(out, kube)
	if out.Header.Get("Authorization") != "" || out.Header.Get(cluster.HeaderCaller) != cluster.CallerNode ||
		out.Header.Get(cluster.HeaderOnBehalfOf) != "kubernetes:alice" || out.Header.Get(cluster.HeaderOnBehalfOwner) != "team:dev" {
		t.Fatalf("kubernetes forward headers = %v", out.Header)
	}
	other := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil).WithContext(context.Background())
	other.Header.Set(cluster.HeaderOnBehalfOf, "kubernetes:mallory")
	other.Header.Set(cluster.HeaderOnBehalfOwner, "team:other")
	cluster.StampForward(other, controlplane.OperatorAccess())
	if other.Header.Get(cluster.HeaderOnBehalfOf) != "" || other.Header.Get(cluster.HeaderOnBehalfOwner) != "" {
		t.Fatalf("a stale stamp rode along: %v", other.Header)
	}
}
