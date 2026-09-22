package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Caddy's admin API explains its own failures ("unknown object ID 'x'",
// "invalid traversal path", …). This client used to discard the body, so every
// failure surfaced as a bare "insert caddy route failed: 400" — which made an
// intermittent 400 on the restart path undiagnosable from daemon logs alone
// (live, 2026-09-23; the cause was only visible in Caddy's own journal, which
// does not survive teardown).
func TestUpsertRouteErrorCarriesCaddyDetail(t *testing.T) {
	cases := []struct {
		name        string
		patchStatus int
		putStatus   int
		body        string
		wantParts   []string
	}{
		{
			name:        "insert failure names the route and quotes caddy",
			patchStatus: http.StatusNotFound,
			putStatus:   http.StatusBadRequest,
			body:        `{"error":"invalid traversal path at: apps/http/servers/srv0/routes"}`,
			wantParts:   []string{"insert caddy route", "sandbox-sb-1", "400", "invalid traversal path"},
		},
		{
			name:        "patch failure that is not 404 also quotes caddy",
			patchStatus: http.StatusConflict,
			body:        `{"error":"config is locked"}`,
			wantParts:   []string{"patch caddy route", "409", "config is locked"},
		},
		{
			// A body-less error must still produce the old, readable message
			// rather than a dangling separator.
			name:        "no body falls back to the bare status",
			patchStatus: http.StatusNotFound,
			putStatus:   http.StatusBadRequest,
			body:        "",
			wantParts:   []string{"insert caddy route", "400"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := tc.patchStatus
				if r.Method == http.MethodPut {
					status = tc.putStatus
				}
				w.WriteHeader(status)
				if tc.body != "" {
					_, _ = w.Write([]byte(tc.body))
				}
			}))
			defer srv.Close()

			c := &Client{baseURL: srv.URL, serverID: "srv0", httpClient: srv.Client()}
			err := c.upsertRoute(context.Background(), "sandbox-sb-1", map[string]any{"handle": []any{}})
			if err == nil {
				t.Fatal("upsertRoute() succeeded, want an error")
			}
			for _, want := range tc.wantParts {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

// The detail is bounded so a pathological response cannot blow up a log line.
func TestSendJSONDetailBoundsBody(t *testing.T) {
	huge := strings.Repeat("x", caddyErrDetailMax*4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, serverID: "srv0", httpClient: srv.Client()}
	status, detail, err := c.sendJSONDetail(context.Background(), http.MethodPut, srv.URL, []byte("{}"))
	if err != nil {
		t.Fatalf("sendJSONDetail() error = %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if len(detail) > caddyErrDetailMax {
		t.Fatalf("detail is %d bytes, want <= %d", len(detail), caddyErrDetailMax)
	}
}

// A success must not pay for the body read, and must report no detail.
func TestSendJSONDetailIgnoresBodyOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"note":"should not be read as an error"}`))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, serverID: "srv0", httpClient: srv.Client()}
	status, detail, err := c.sendJSONDetail(context.Background(), http.MethodPost, srv.URL, []byte("{}"))
	if err != nil {
		t.Fatalf("sendJSONDetail() error = %v", err)
	}
	if status != http.StatusOK || detail != "" {
		t.Fatalf("status/detail = %d/%q, want 200/\"\"", status, detail)
	}
}
