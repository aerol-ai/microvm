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
		authorization string
		body          string
		wantStatus    int
	}{
		{
			name:       "missing_authorization_is_rejected",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:          "wrong_pat_token_is_rejected",
			authorization: "Bearer wrong-token",
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name:          "valid_pat_token_reaches_handler",
			authorization: "Bearer pat-token",
			body:          "not-json",
			wantStatus:    http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, "pat-token")
			request := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(tc.body))
			if tc.authorization != "" {
				request.Header.Set("Authorization", tc.authorization)
			}
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request)

			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantStatus)
			}
		})
	}
}
