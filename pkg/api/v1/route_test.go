package v1

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func fleetToken(role controlplane.Role) controlplane.Access {
	return controlplane.Access{Fleet: true, Role: role, Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_" + string(role)}}
}

// The v1 403 for the PAT on a cluster-internal route keeps the pre-T2
// mTLS text when the request has no peer certificate. A PAT request that
// does carry one but was forwarded is an operator, not a node, and is told
// so; everyone else gets apihttp.WriteForbidden's body.
func TestV1WriteForbidden(t *testing.T) {
	internal := func(access controlplane.Access) apihttp.Denial {
		return apihttp.Denial{Permission: controlplane.PermClusterInternal, Access: access}
	}
	plain := httptest.NewRequest(http.MethodPost, cluster.PublicInternalApplyPath, nil)
	withCert := httptest.NewRequest(http.MethodPost, cluster.PublicInternalApplyPath, nil)
	addVerifiedClientCertificate(withCert, &x509.Certificate{DNSNames: []string{"node:peer-test"}})
	cases := []struct {
		name string
		req  *http.Request
		d    apihttp.Denial
		want string
	}{
		{"PAT without a peer certificate", plain, internal(controlplane.OperatorAccess()), "cluster internal endpoint requires mTLS\n"},
		{"PAT forwarded by a peer", withCert, internal(controlplane.OperatorAccess()), `{"error":"cluster internal endpoints serve cluster nodes only"}` + "\n"},
		{"token admin", plain, internal(fleetToken(controlplane.RoleAdmin)),
			`{"error":"role admin on all teams cannot cluster.internal; it is reserved for cluster nodes and no role grants it","required_permission":"cluster.internal","role":"admin"}` + "\n"},
		{"fleet route", plain, apihttp.Denial{Permission: controlplane.PermFleetAdmin, Access: controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct"}}},
			`{"error":"operator authorization required"}` + "\n"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		writeForbidden(rec, tc.req, tc.d)
		if rec.Code != http.StatusForbidden || rec.Body.String() != tc.want {
			t.Errorf("%s: %d %q, want %q", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

// Only the node: principal reaches a cluster-internal handler: a fleet
// admin token over the same peer certificate is refused before
// withInternalMTLS runs, and the node then still needs live membership.
func TestClusterInternalNeedsTheNodePrincipal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&secretInternalTestCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	var caller controlplane.Access
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), caller)))
		})
	}})
	for name, tc := range map[string]struct {
		access controlplane.Access
		peer   string
		want   int
	}{
		"admin token over mTLS": {fleetToken(controlplane.RoleAdmin), "peer-test", http.StatusForbidden},
		"operator over mTLS":    {controlplane.OperatorAccess(), "peer-test", http.StatusForbidden},
		"live node":             {controlplane.NodeAccess("peer-test"), "peer-test", http.StatusOK},
		"node not a member":     {controlplane.NodeAccess("ghost"), "ghost", http.StatusForbidden},
	} {
		caller = tc.access
		req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalDrainedNodesPath, nil)
		addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"node:" + tc.peer}})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if tc.want == http.StatusOK {
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s: refused %q; a live node must reach the handler", name, rec.Body.String())
			}
			continue
		}
		if rec.Code != tc.want {
			t.Errorf("%s: %d %q, want %d", name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

// Capacity hides template and module inventories from anyone without
// fleet.admin: fleet scope alone (a viewer or auditor bound to every team)
// is not enough.
func TestCapacityRedactsInventoriesWithoutFleetAdmin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("n1", "http://n1", ""))
	if err := st.CreateTemplate(context.Background(), &models.Template{
		ID: "tpl-internal-app", Image: "docker://internal", Status: models.TemplateStatusReady,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	for name, tc := range map[string]struct {
		access  controlplane.Access
		redacts bool
	}{
		"fleet viewer": {fleetToken(controlplane.RoleViewer), true},
		"auditor":      {fleetToken(controlplane.RoleAuditor), true},
		"admin":        {fleetToken(controlplane.RoleAdmin), false},
		"operator":     {controlplane.OperatorAccess(), false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/capacity", nil)
		req = req.WithContext(controlplane.ContextWithAccess(req.Context(), tc.access))
		rec := httptest.NewRecorder()
		h.capacity(rec, req)
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if _, exposed := body["local_template_catalog_ids"]; exposed == tc.redacts {
			t.Errorf("%s: template catalogue exposed=%v, want %v", name, exposed, !tc.redacts)
		}
	}
}

// A fleet-wide read-only caller gets its own audit-read bucket, never the
// operator's, so it cannot spend the operator's budget.
func TestAuditIdentityKeyForFleetPrincipals(t *testing.T) {
	key := func(a controlplane.Access) string {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit", nil)
		return auditIdentityKey(req.WithContext(controlplane.ContextWithAccess(req.Context(), a)))
	}
	if got := key(controlplane.OperatorAccess()); got != auditRateLimitIdentityKey {
		t.Errorf("operator key = %q", got)
	}
	if got := key(controlplane.NodeAccess("n1")); got != auditRateLimitIdentityKey {
		t.Errorf("node key = %q", got)
	}
	if got := key(fleetToken(controlplane.RoleAuditor)); got != "principal:tok_auditor" {
		t.Errorf("auditor key = %q", got)
	}
}

func TestClusterOperatorAccessNeedsFleetAdmin(t *testing.T) {
	for name, tc := range map[string]struct {
		access *controlplane.Access
		want   bool
	}{
		"internal call": {nil, true},
		"operator":      {&controlplane.Access{Fleet: true}, true},
		"fleet viewer":  {ptr(fleetToken(controlplane.RoleViewer)), false},
		"admin":         {ptr(fleetToken(controlplane.RoleAdmin)), true},
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/n1/storage-retired", nil)
		if tc.access != nil {
			req = req.WithContext(controlplane.ContextWithAccess(req.Context(), *tc.access))
		}
		if got := clusterOperatorAccess(req); got != tc.want {
			t.Errorf("%s: clusterOperatorAccess = %v, want %v", name, got, tc.want)
		}
	}
}
