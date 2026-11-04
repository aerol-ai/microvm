package v1

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestWhoAmI(t *testing.T) {
	expires := time.Date(2027, 3, 4, 5, 6, 7, 0, time.FixedZone("x", 3600))
	managed, err := controlplane.ControlPlaneAccess(controlplane.Identity{ExternalID: "ext-1", OwnerRef: "acct-9", Name: "Ana"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		access *controlplane.Access
		status int
		body   string
	}{
		{
			name: "operator", access: ptr(controlplane.OperatorAccess()), status: http.StatusOK,
			body: `{"principal":{"kind":"operator","id":"operator","name":"operator"},"role":"admin","team":"*"}`,
		},
		{
			name: "node", access: ptr(controlplane.NodeAccess("n3")), status: http.StatusOK,
			body: `{"principal":{"kind":"node","id":"node:n3","name":"node:n3"},"role":"admin","team":"*"}`,
		},
		{
			// A managed account is not a team, and its owner ref is never
			// echoed (sandboxes hide it from JSON too).
			name: "managed", access: &managed, status: http.StatusOK,
			body: `{"principal":{"kind":"controlplane","id":"controlplane:ext-1","name":"Ana"},"role":"runner"}`,
		},
		{
			name: "team token with expiry in UTC",
			access: &controlplane.Access{
				Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
				Role:      controlplane.RoleViewer,
				Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_7Hq2", Name: "ci-deploy"},
				ExpiresAt: expires,
			},
			status: http.StatusOK,
			body:   `{"principal":{"kind":"token","id":"tok_7Hq2","name":"ci-deploy"},"role":"viewer","team":"payments","expires_at":"2027-03-04T04:06:07Z"}`,
		},
		{
			name: "no Access never answers as the fleet", status: http.StatusUnauthorized,
			body: `{"error":"unauthorized"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterRoutes(mux, Deps{
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				Auth: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if tc.access != nil {
							r = r.WithContext(controlplane.ContextWithAccess(r.Context(), *tc.access))
						}
						next.ServeHTTP(w, r)
					})
				},
			})
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/whoami", nil))
			if rec.Code != tc.status || strings.TrimSpace(rec.Body.String()) != tc.body {
				t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body.String(), tc.status, tc.body)
			}
		})
	}
}

// TestWhoAmIExplain is the ?explain=1 table (D22) over hand-built Access
// values: which binding is in effect, the note for credentials that carry
// their own role, and the claims read from the caller's own bearer. The
// real edge (verifier, team selection, API tokens) is
// TestWhoAmIExplainThroughTheEdge in pkg/api.
func TestWhoAmIExplain(t *testing.T) {
	payments := controlplane.TeamBinding{Role: controlplane.RoleRunner, Team: "payments", Index: 2, Rule: `okta group="payments-eng" -> runner/payments`}
	billing := controlplane.TeamBinding{Role: controlplane.RoleViewer, Team: "billing", Index: 3, Rule: `okta group="billing-eng" -> viewer/billing`}
	names := &controlplane.ClaimNames{Issuer: "okta", Username: "email", Groups: "groups", Roles: "roles"}
	sso := controlplane.OIDCAccess(controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:ana", Name: "ana@acme.com"},
		[]controlplane.TeamBinding{payments, billing}, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	sso.ClaimNames = names
	selected := billing.Apply(sso)
	noNames := sso
	noNames.ClaimNames = nil
	bearer := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"https://idp","sub":"ana","aud":"cli","exp":1900000000,"email":"ana@acme.com","groups":["payments-eng","billing-eng"]}`)) + ".c2ln"
	managed, err := controlplane.ControlPlaneAccess(controlplane.Identity{ExternalID: "ext-1", OwnerRef: "acct-9"})
	if err != nil {
		t.Fatal(err)
	}
	const tail = `; identity-file bindings don't apply","matched":[]}`
	cases := []struct {
		name    string
		access  controlplane.Access
		query   string
		explain string
	}{
		{"first binding in effect", sso, "explain=1",
			`{"bindings_apply":true,"matched":[{"index":2,"text":"okta group=\"payments-eng\" -> runner/payments","in_effect":true},` +
				`{"index":3,"text":"okta group=\"billing-eng\" -> viewer/billing"}],` +
				`"claims":{"issuer":"okta","username":"ana@acme.com","groups":["payments-eng","billing-eng"]}}`},
		{"the selected team in effect", selected, "explain=true",
			`{"bindings_apply":true,"matched":[{"index":2,"text":"okta group=\"payments-eng\" -> runner/payments"},` +
				`{"index":3,"text":"okta group=\"billing-eng\" -> viewer/billing","in_effect":true}],` +
				`"claims":{"issuer":"okta","username":"ana@acme.com","groups":["payments-eng","billing-eng"]}}`},
		{"no claim names, no claims", noNames, "explain=1",
			`{"bindings_apply":true,"matched":[{"index":2,"text":"okta group=\"payments-eng\" -> runner/payments","in_effect":true},` +
				`{"index":3,"text":"okta group=\"billing-eng\" -> viewer/billing"}]}`},
		{"operator", controlplane.OperatorAccess(), "explain=1", `{"bindings_apply":false,"note":"the operator token (SB_PAT_TOKEN) acts as admin on every team` + tail},
		{"node", controlplane.NodeAccess("n3"), "explain=1", `{"bindings_apply":false,"note":"a cluster peer's certificate acts as admin on every team` + tail},
		{"managed", managed, "explain=1", `{"bindings_apply":false,"note":"the managed control plane sets this account's role` + tail},
		{"API token", controlplane.Access{Role: controlplane.RoleRunner, Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_1"}}, "explain=1",
			`{"bindings_apply":false,"note":"an API token carries its own role and team` + tail},
		{"any other caller", controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalSystem, ID: "system:x"}}, "explain=1",
			`{"bindings_apply":false,"note":"identity-file bindings don't apply to this credential","matched":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterRoutes(mux, Deps{
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				Auth: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), tc.access)))
					})
				},
			})
			req := httptest.NewRequest(http.MethodGet, "/v1/whoami?"+tc.query, nil)
			req.Header.Set("Authorization", "Bearer "+bearer)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			plain, _ := json.Marshal(whoAmIFrom(tc.access))
			// encoding/json writes ">" HTML-escaped; spell the table's
			// canonical "->" the same way.
			gt, _ := json.Marshal(">")
			explain := strings.ReplaceAll(tc.explain, "->", "-"+strings.Trim(string(gt), `"`))
			want := strings.TrimSuffix(string(plain), "}") + `,"explain":` + explain + "}"
			if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != want {
				t.Fatalf("got %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
			}
		})
	}
}

func TestWhoAmIIsAuthenticated(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
		},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/whoami", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("GET /v1/whoami bypassed Deps.Auth: %d", rec.Code)
	}
}

func ptr[T any](v T) *T { return &v }
