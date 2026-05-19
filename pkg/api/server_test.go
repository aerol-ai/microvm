package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestRequireAuthCases(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		authorization string
		apiKey        string
		body          string
		wantStatus    int
	}{
		{
			name:       "missing_authorization_is_rejected",
			path:       "/v1/sandboxes",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:          "wrong_pat_token_is_rejected",
			path:          "/v1/sandboxes",
			authorization: "Bearer wrong-token",
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name:          "valid_pat_token_reaches_handler",
			path:          "/v1/sandboxes",
			authorization: "Bearer pat-token",
			body:          "not-json",
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "daytona_routes_share_auth_contract",
			path:          "/daytona/sandbox",
			authorization: "Bearer pat-token",
			body:          "not-json",
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "daytona_snapshot_route_shares_auth_contract",
			path:          "/daytona/sandbox/sb-1/snapshot",
			authorization: "Bearer pat-token",
			body:          "not-json",
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "v1_snapshot_route_shares_auth_contract",
			path:          "/v1/sandboxes/sb-1/snapshot",
			authorization: "Bearer pat-token",
			body:          "not-json",
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:       "e2b_missing_api_key_is_rejected",
			path:       "/e2b/sandboxes",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "e2b_wrong_api_key_is_rejected",
			path:       "/e2b/sandboxes",
			apiKey:     "wrong-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "e2b_routes_accept_x_api_key",
			path:       "/e2b/sandboxes",
			apiKey:     "pat-token",
			body:       "not-json",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:          "e2b_routes_also_accept_bearer_pat",
			path:          "/e2b/sandboxes",
			authorization: "Bearer pat-token",
			body:          "not-json",
			wantStatus:    http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, config.Config{}, "pat-token")
			request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			if tc.authorization != "" {
				request.Header.Set("Authorization", tc.authorization)
			}
			if tc.apiKey != "" {
				request.Header.Set("X-API-KEY", tc.apiKey)
			}
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantStatus)
			}
		})
	}
}

// TestDashboardEndpoints covers the operator dashboard mounts:
//
//  1. GET /ui returns the embedded HTML unauthenticated (the page itself
//     carries no secrets; the JS calls inside it carry the PAT).
//  2. GET /debug/vars is PAT-gated — 401 unauth, 200 + JSON with the
//     correct bearer token. The stdlib expvar handler always publishes
//     "cmdline" and "memstats" so the JSON shape is stable even with a
//     nil service.
func TestDashboardEndpoints(t *testing.T) {
	server := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, config.Config{}, "pat-token")

	t.Run("ui_is_served_unauthenticated_as_html", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/ui", nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.Code)
		}
		ct := response.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("Content-Type = %q, want text/html prefix", ct)
		}
		body := response.Body.String()
		if !strings.Contains(strings.ToLower(body), "<!doctype html>") {
			t.Fatalf("body missing <!doctype html> marker; first 120 bytes: %q", body[:min(120, len(body))])
		}
	})

	t.Run("debug_vars_requires_auth", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", response.Code)
		}
	})

	t.Run("debug_vars_returns_json_with_pat", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
		request.Header.Set("Authorization", "Bearer pat-token")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.Code)
		}
		var parsed map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("body is not valid JSON: %v", err)
		}
		// expvar always publishes cmdline + memstats; anchor the test on
		// cmdline to prove we got the real handler and not an empty body.
		if _, ok := parsed["cmdline"]; !ok {
			t.Fatalf("expvar body missing standard \"cmdline\" key; got keys: %v", keysOf(parsed))
		}
	})
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
