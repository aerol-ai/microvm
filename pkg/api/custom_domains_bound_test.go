package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The marker that names the custom hostnames a server bound for a call
// counts only on a forward from a server: from a worker or gateway, or on a
// call that is not a forward, it is no marker at all.
func TestCustomDomainsBoundOnlyFromAServer(t *testing.T) {
	const value = "sb-1 app.customer.com"
	req := func(role string, forwarded bool, header string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", nil)
		if role != "-" {
			r.TLS = peerTLSRole("p1", role)
		}
		if forwarded {
			r.Header.Set(cluster.HeaderForwarded, "1")
		}
		if header != "" {
			r.Header.Set(cluster.HeaderCustomDomainsBound, header)
		}
		return r
	}
	s := &Server{}
	for _, tc := range []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"a server's forward", req(controlplane.NodeRoleServer, true, value), true},
		{"a worker's forward", req(controlplane.NodeRoleWorker, true, value), false},
		{"a gateway's forward", req(controlplane.NodeRoleIngress, true, value), false},
		{"a certificate with no role", req("", true, value), false},
		{"no certificate", req("-", true, value), false},
		{"not a forward", req(controlplane.NodeRoleServer, false, value), false},
		{"no marker", req(controlplane.NodeRoleServer, true, ""), false},
		{"a malformed marker", req(controlplane.NodeRoleServer, true, "sb-1 App.Customer.com"), false},
	} {
		got, ok := s.customDomainsBound(tc.r)
		if ok != tc.want || ok && !got.Covers("sb-1", "app.customer.com") {
			t.Errorf("%s: %+v %v", tc.name, got, ok)
		}
	}

	// The auth edge puts it on the call's context.
	server := NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", nil)
	var seen bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, seen = cluster.CustomDomainsBoundFromContext(r.Context())
	})
	r := req(controlplane.NodeRoleServer, true, value)
	r.Header.Set("Authorization", "Bearer pat-token")
	server.requireAuth(next).ServeHTTP(httptest.NewRecorder(), r)
	if !seen {
		t.Fatal("the auth edge dropped a server's marker")
	}
	r = req(controlplane.NodeRoleWorker, true, value)
	r.Header.Set("Authorization", "Bearer pat-token")
	server.requireAuth(next).ServeHTTP(httptest.NewRecorder(), r)
	if seen {
		t.Fatal("the auth edge took a worker's marker")
	}
}
