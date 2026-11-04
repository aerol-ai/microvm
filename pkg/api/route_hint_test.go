package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func serve(h http.Handler, method, path, bearer string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestForbiddenHintOnEverySurface is the per-surface D9 test: a token or
// OIDC caller's 403 names its role and team and the role to ask for, in
// each surface's own body. v1 (and the dashboard's metrics) add
// required_permission and role; the facades keep their envelope.
func TestForbiddenHintOnEverySurface(t *testing.T) {
	h := matrixServer().Handler()
	const write = "role viewer on team payments cannot sandbox.write; ask an admin for role runner on team payments"
	cases := []struct {
		name, method, path, bearer string
		header                     map[string]string
		want                       string
	}{
		{"v1", http.MethodPost, "/v1/sandboxes", "avm_viewer_payments", nil,
			`{"error":"` + write + `","required_permission":"sandbox.write","role":"viewer"}` + "\n"},
		{"v1 oidc", http.MethodPost, "/v1/sandboxes", "eyJviewer_payments", nil,
			`{"error":"` + write + `","required_permission":"sandbox.write","role":"viewer"}` + "\n"},
		{"metrics", http.MethodGet, "/v1/metrics", "avm_viewer_payments", nil,
			`{"error":"role viewer on team payments cannot metrics.read; ask an admin for role viewer on all teams","required_permission":"metrics.read","role":"viewer"}` + "\n"},
		{"daytona", http.MethodPost, "/daytona/sandbox", "avm_viewer_payments", nil, `{"error":"` + write + `"}` + "\n"},
		{"e2b bearer", http.MethodPost, "/e2b/sandboxes", "avm_viewer_payments", nil, `{"code":403,"message":"` + write + `"}` + "\n"},
		{"e2b api key", http.MethodPost, "/e2b/sandboxes", "", map[string]string{"X-API-KEY": "avm_viewer_payments"}, `{"code":403,"message":"` + write + `"}` + "\n"},
		{"runloop", http.MethodPost, "/runloop/v1/devboxes", "avm_viewer_payments", nil, `{"message":"` + write + `"}` + "\n"},
		{"fleet route", http.MethodGet, "/v1/templates", "avm_auditor", nil,
			`{"error":"role auditor on all teams cannot fleet.admin; ask an admin for role admin on all teams","required_permission":"fleet.admin","role":"auditor"}` + "\n"},
	}
	for _, tc := range cases {
		rec := serve(h, tc.method, tc.path, tc.bearer, tc.header)
		if rec.Code != http.StatusForbidden || rec.Body.String() != tc.want {
			t.Errorf("%s: %d %q\nwant %q", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

// TestForbiddenBodiesUnchangedForPATAndManaged pins L8: the PAT and managed
// callers get exactly the 403 bodies they got before roles, with identity on
// and off.
func TestForbiddenBodiesUnchangedForPATAndManaged(t *testing.T) {
	operatorOnly := `{"error":"operator authorization required"}` + "\n"
	managed := managedValidator{"managed-runner": {ExternalID: "u1", OwnerRef: "acct-1"}}
	for name, server := range map[string]*Server{
		"identity on":  matrixServer(),
		"identity off": NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", managed),
	} {
		h := server.Handler()
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/v1/templates"},
			{http.MethodPost, "/v1/admin/reconcile"},
			{http.MethodPost, "/v1/audit/verify"},
			{http.MethodGet, "/v1/ingress/dns"},
			{http.MethodGet, "/v1/cluster/members"},
			{http.MethodGet, "/v1/metrics"},
			{http.MethodGet, "/debug/vars"},
			{http.MethodPost, "/v1/cluster/internal/apply"},
		} {
			rec := serve(h, tc.method, tc.path, "managed-runner", nil)
			if rec.Code != http.StatusForbidden || rec.Body.String() != operatorOnly || rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("%s: managed %s %s = %d %q (%s)", name, tc.method, tc.path, rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
			}
		}
		// The PAT on an internal route without a peer certificate: the
		// exact text/plain answer withInternalMTLS gave.
		rec := serve(h, http.MethodPost, "/v1/cluster/internal/apply", "pat-token", nil)
		if rec.Code != http.StatusForbidden || rec.Body.String() != "cluster internal endpoint requires mTLS\n" ||
			!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("%s: PAT on an internal route = %d %q (%s)", name, rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
		}
	}
}

// TestMetricsReadNeedsAFleetBinding (D6): any role bound to every team may
// scrape /v1/metrics; a team binding and a managed caller may not;
// /debug/vars stays fleet.admin.
func TestMetricsReadNeedsAFleetBinding(t *testing.T) {
	h := matrixServer().Handler()
	for bearer, want := range map[string][2]int{
		"pat-token":           {http.StatusOK, http.StatusOK},
		"eyJadmin":            {http.StatusOK, http.StatusOK},
		"avm_auditor":         {http.StatusOK, http.StatusForbidden},
		"avm_viewer_all":      {http.StatusOK, http.StatusForbidden},
		"avm_runner_all":      {http.StatusOK, http.StatusForbidden},
		"avm_viewer_payments": {http.StatusForbidden, http.StatusForbidden},
		"avm_runner_payments": {http.StatusForbidden, http.StatusForbidden},
		"managed-runner":      {http.StatusForbidden, http.StatusForbidden},
	} {
		if got := serve(h, http.MethodGet, "/v1/metrics", bearer, nil).Code; got != want[0] {
			t.Errorf("/v1/metrics as %s = %d, want %d", bearer, got, want[0])
		}
		if got := serve(h, http.MethodGet, "/debug/vars", bearer, nil).Code; got != want[1] {
			t.Errorf("/debug/vars as %s = %d, want %d", bearer, got, want[1])
		}
	}
}

// TestNotFoundCarriesNoHint: another team's sandbox is a 404 with no hint,
// on every surface, for a caller that holds the verb; a caller without the
// verb gets the same 403 whether the id is another team's or does not exist,
// so the hint never tells anyone a sandbox exists.
func TestNotFoundCarriesNoHint(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "hint.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-billing", Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: controlplane.TeamOwnerRef("billing"),
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	tokens := stubCredential{prefix: "avm_", kind: controlplane.PrincipalToken, accept: map[string]controlplane.Access{
		"avm_runner_payments": tokenAccess("payments", controlplane.RoleRunner),
		"avm_viewer_payments": tokenAccess("payments", controlplane.RoleViewer),
	}}
	h := NewServer(discardLogger(), svc, nil, nil, config.Config{IdentityEnabled: true}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, tokens)).Handler()

	for _, path := range []string{"/v1/sandboxes/sb-billing", "/daytona/sandbox/sb-billing", "/e2b/sandboxes/sb-billing"} {
		rec := serve(h, http.MethodGet, path, "avm_runner_payments", nil)
		body := rec.Body.String()
		if rec.Code != http.StatusNotFound || strings.Contains(body, "role") || strings.Contains(body, "required_permission") || strings.Contains(body, "ask an admin") {
			t.Errorf("GET %s as another team's runner = %d %q; want a bare 404", path, rec.Code, body)
		}
	}
	other := serve(h, http.MethodPost, "/v1/sandboxes/sb-billing/toolbox/process/execute", "avm_viewer_payments", nil)
	missing := serve(h, http.MethodPost, "/v1/sandboxes/sb-nope/toolbox/process/execute", "avm_viewer_payments", nil)
	if other.Code != http.StatusForbidden || other.Body.String() != missing.Body.String() || other.Code != missing.Code {
		t.Fatalf("viewer exec on another team's sandbox = %d %q, on a missing one = %d %q; they must match", other.Code, other.Body.String(), missing.Code, missing.Body.String())
	}
}

// TestRemoteMCPInnerCallsUseRoutePermissions: /mcp itself needs only a valid
// principal, so a viewer connects; each tool's inner API call is then
// authorized by that route's own permission, so the viewer's exec comes back
// as the toolbox route's 403 hint while its read-only lookup worked.
func TestRemoteMCPInnerCallsUseRoutePermissions(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-00000000000000bb", Name: "agent", OwnerRef: controlplane.TeamOwnerRef("payments"), Image: "alpine",
		Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	tokens := stubCredential{prefix: "avm_", kind: controlplane.PrincipalToken, accept: map[string]controlplane.Access{
		"avm_viewer_payments": tokenAccess("payments", controlplane.RoleViewer),
	}}
	srv := httptest.NewServer(NewServer(discardLogger(), svc, nil, nil, config.Config{IdentityEnabled: true, MCPEnabled: true, MCPRateLimit: 100}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, tokens)).Handler())
	defer srv.Close()

	transport := &mcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp?sandbox=agent",
		HTTPClient: &http.Client{Transport: bearerTransport{"avm_viewer_payments"}},
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("a viewer may open /mcp (authenticated): %v", err)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "exec", Arguments: map[string]any{"command": "echo"}})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !res.IsError || !strings.Contains(text, "cannot sandbox.exec") {
		t.Fatalf("viewer exec through MCP = %q; want the toolbox route's sandbox.exec refusal", text)
	}
}
