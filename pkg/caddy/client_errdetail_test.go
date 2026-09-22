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

// Caddy rebuilds its @id index when it loads a config, so /id/<routeID> can
// 404 while the route IS present. upsertRoute then inserts a second copy and
// Caddy rejects the whole config with "duplicate ID". The duplicate proves the
// route exists, so the in-place PATCH was right all along and is retried.
//
// Live on single-node 2026-09-23 this was 2 of 8 stop->start cycles on a
// public sandbox, surfacing as a bare 400 from POST /v1/sandboxes/{id}/start.
func TestUpsertRouteRetriesPatchOnDuplicateID(t *testing.T) {
	const dup = `{"error":"indexing config: duplicate ID 'sandbox-sb-1' found at /config/apps/http/servers/srv0/routes/0 and /config/apps/http/servers/srv0/routes/3"}`

	var patches, puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			patches++
			// First PATCH races the index rebuild and 404s; the retry, once
			// the duplicate has proven the route exists, succeeds.
			if patches == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			puts++
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(dup))
		}
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, serverID: "srv0", httpClient: srv.Client()}
	if err := c.upsertRoute(context.Background(), "sandbox-sb-1", map[string]any{"handle": []any{}}); err != nil {
		t.Fatalf("upsertRoute() error = %v, want nil — a duplicate ID means the route is already there", err)
	}
	if patches != 2 || puts != 1 {
		t.Fatalf("patches/puts = %d/%d, want 2/1 (patch, insert-rejected, patch again)", patches, puts)
	}
}

// The retry must not mask a genuine failure: if the second PATCH also fails,
// the caller still sees an error carrying Caddy's explanation.
func TestUpsertRouteDuplicateRetryStillReportsPersistentFailure(t *testing.T) {
	const dup = `{"error":"indexing config: duplicate ID 'sandbox-sb-2' found at a and b"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(dup))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, serverID: "srv0", httpClient: srv.Client()}
	err := c.upsertRoute(context.Background(), "sandbox-sb-2", map[string]any{"handle": []any{}})
	if err == nil {
		t.Fatal("upsertRoute() succeeded although every attempt failed")
	}
	if !strings.Contains(err.Error(), "sandbox-sb-2") {
		t.Errorf("error %q does not name the route", err.Error())
	}
}

// A non-duplicate insert failure must NOT trigger the retry — re-PATCHing a
// route that genuinely is not there just wastes a round trip and muddies the
// error the caller sees.
func TestUpsertRouteDoesNotRetryOnUnrelatedInsertFailure(t *testing.T) {
	var patches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches++
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid traversal path at: apps/http/servers/srv0/routes"}`))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, serverID: "srv0", httpClient: srv.Client()}
	err := c.upsertRoute(context.Background(), "sandbox-sb-3", map[string]any{"handle": []any{}})
	if err == nil {
		t.Fatal("upsertRoute() succeeded on an invalid traversal path")
	}
	if patches != 1 {
		t.Fatalf("patches = %d, want 1 (no retry for a non-duplicate failure)", patches)
	}
	if !strings.Contains(err.Error(), "invalid traversal path") {
		t.Errorf("error %q lost Caddy's explanation", err.Error())
	}
}
