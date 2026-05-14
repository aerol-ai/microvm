package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
			server := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, "pat-token")
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
