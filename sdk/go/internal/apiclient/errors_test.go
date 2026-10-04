package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDecodeErrorReturnsAPIError(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		retryAfter   string
		wantMessage  string
		wantCode     string
		wantNotFound bool
		wantConflict bool
		wantRetry    bool
		wantAfter    time.Duration
	}{
		{name: "not found with message", status: 404, body: `{"error":"sandbox not found"}`, wantMessage: "sandbox not found", wantNotFound: true},
		{name: "conflict", status: 409, body: `{"error":"sandbox name already in use"}`, wantMessage: "sandbox name already in use", wantConflict: true},
		{name: "code passes through", status: 503, body: `{"error":"gone","code":"artifact_node_unavailable"}`, retryAfter: "7", wantMessage: "gone", wantCode: "artifact_node_unavailable", wantRetry: true, wantAfter: 7 * time.Second},
		{name: "no body falls back to status", status: 500, body: ``, wantMessage: "request failed with status 500"},
		{name: "bad retry-after ignored", status: 429, body: `{"error":"slow down"}`, retryAfter: "soon", wantMessage: "slow down", wantRetry: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			zero := 0
			client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client(), Retry: &RetryConfig{MaxRetries: &zero}})
			_, err := client.Get(context.Background(), "sb-1")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error %T %v is not *APIError", err, err)
			}
			if apiErr.StatusCode != tt.status || apiErr.Message != tt.wantMessage || apiErr.Code != tt.wantCode || err.Error() != tt.wantMessage {
				t.Fatalf("APIError = %+v (Error() %q)", apiErr, err.Error())
			}
			if errors.Is(err, ErrNotFound) != tt.wantNotFound || errors.Is(err, ErrConflict) != tt.wantConflict {
				t.Fatalf("errors.Is mismatch for %d", tt.status)
			}
			if apiErr.Retryable() != tt.wantRetry || apiErr.RetryAfter != tt.wantAfter {
				t.Fatalf("Retryable() = %v RetryAfter = %v", apiErr.Retryable(), apiErr.RetryAfter)
			}
			if errors.Is(err, ErrNameLookupUnsupported) {
				t.Fatal("an HTTP error must not match ErrNameLookupUnsupported")
			}
		})
	}
}

// TestGetByNameVerifiesReply is the client half of CEO review CF5: a server
// that predates ?name= ignores it and returns an unfiltered list page. The
// reply is trusted only when it holds at most one row carrying the name.
func TestGetByNameVerifiesReply(t *testing.T) {
	replies := map[string][]models.Sandbox{
		"agent":    {{ID: "sb-1", Name: "agent"}},
		"missing":  {},
		"old":      {{ID: "sb-1", Name: "a"}, {ID: "sb-2", Name: "b"}, {ID: "sb-3", Name: "c"}},
		"mismatch": {{ID: "sb-4", Name: "someone-else"}},
	}
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		_ = json.NewEncoder(w).Encode(replies[r.URL.Query().Get("name")])
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	ctx := context.Background()

	got, err := client.GetByName(ctx, " agent ", true)
	if err != nil || got.ID != "sb-1" {
		t.Fatalf("GetByName(agent) = (%+v, %v)", got, err)
	}
	if queries[0] != "include_env=true&name=agent" {
		t.Fatalf("query = %q", queries[0])
	}
	if _, err := client.GetByName(ctx, "missing", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByName(missing) error = %v, want ErrNotFound", err)
	}
	for _, name := range []string{"old", "mismatch"} {
		if _, err := client.GetByName(ctx, name, false); !errors.Is(err, ErrNameLookupUnsupported) {
			t.Fatalf("GetByName(%s) error = %v, want ErrNameLookupUnsupported", name, err)
		}
	}
	if _, err := client.GetByName(ctx, "  ", false); err == nil {
		t.Fatal("blank name must be rejected")
	}
	if len(queries) != 4 {
		t.Fatalf("made %d requests, want 4 (blank name sends none)", len(queries))
	}
}

func TestListWithQuerySendsName(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	if _, err := client.ListWithQuery(context.Background(), ListQuery{Name: " agent ", Tags: map[string]string{"team": "x"}}); err != nil {
		t.Fatalf("ListWithQuery: %v", err)
	}
	if _, err := client.ListWithQuery(context.Background(), ListQuery{}); err != nil {
		t.Fatalf("ListWithQuery(empty): %v", err)
	}
	if seen[0] != "tag.team=x&name=agent" || seen[1] != "" {
		t.Fatalf("queries = %q", seen)
	}
}
