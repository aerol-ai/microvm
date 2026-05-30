package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// stubValidator accepts exactly one token and resolves it to a fixed identity;
// every other token is rejected, mirroring the no-op validator's posture.
type stubValidator struct {
	accept   string
	identity controlplane.Identity
}

func (s stubValidator) Validate(_ context.Context, token string) (controlplane.Identity, error) {
	if token == s.accept {
		return s.identity, nil
	}
	return controlplane.Identity{}, controlplane.ErrTokenRejected
}

func TestRequireAuthSecondTokenPath(t *testing.T) {
	srv := &Server{
		patToken: "pat-secret",
		validator: stubValidator{
			accept:   "user-token",
			identity: controlplane.Identity{OwnerRef: "acme", ExternalID: "ext-1"},
		},
	}

	// The protected handler records the Access the middleware attached.
	var gotAccess controlplane.Access
	var gotOK bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccess, gotOK = controlplane.AccessFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := srv.requireAuth(next)

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
		wantOK     bool
		wantOp     bool
		wantOwner  string
	}{
		{"pat is operator", "Bearer pat-secret", http.StatusOK, true, true, ""},
		{"user token is owner-scoped", "Bearer user-token", http.StatusOK, true, false, "acme"},
		{"unknown token 401", "Bearer nope", http.StatusUnauthorized, false, false, ""},
		{"no token 401", "", http.StatusUnauthorized, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAccess, gotOK = controlplane.Access{}, false
			req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			if !gotOK {
				t.Fatalf("expected Access in context")
			}
			if gotAccess.Operator != tc.wantOp {
				t.Fatalf("Operator = %v, want %v", gotAccess.Operator, tc.wantOp)
			}
			if gotAccess.Identity.OwnerRef != tc.wantOwner {
				t.Fatalf("OwnerRef = %q, want %q", gotAccess.Identity.OwnerRef, tc.wantOwner)
			}
		})
	}
}

// TestRequireAuthNoopValidatorRejectsUserTokens proves the open-source posture:
// with the no-op validator, only the PAT authenticates; every other token 401s.
func TestRequireAuthNoopValidatorRejectsUserTokens(t *testing.T) {
	srv := &Server{patToken: "pat-secret", validator: controlplane.Noop().Validator}
	handler := srv.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.Header.Set("Authorization", "Bearer some-user-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("noop validator: status = %d, want 401", rec.Code)
	}
}
