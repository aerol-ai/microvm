package v1

import (
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
