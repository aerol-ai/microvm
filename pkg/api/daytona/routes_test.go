package daytona_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/api/daytona"
)

func TestRegisterRoutesAllUseDaytonaPrefix(t *testing.T) {
	mux := http.NewServeMux()
	daytona.RegisterRoutes(mux, daytona.Deps{
		Auth: func(h http.Handler) http.Handler { return h },
	})

	probes := []string{
		"/daytona/sandbox",
		"/daytona/sandbox/paginated",
		"/daytona/sandbox/abc",
		"/daytona/sandbox/abc/toolbox-proxy-url",
		"/daytona/toolbox/abc/version",
	}
	for _, probe := range probes {
		req, _ := http.NewRequest(http.MethodGet, probe, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" || !strings.Contains(pattern, daytona.PathPrefix+"/") {
			t.Errorf("path %q resolved to pattern %q, expected one containing %q", probe, pattern, daytona.PathPrefix)
		}
	}
}

func TestVolumeRoutesReturn405NotImplemented(t *testing.T) {
	mux := http.NewServeMux()
	daytona.RegisterRoutes(mux, daytona.Deps{
		Auth: func(h http.Handler) http.Handler { return h },
	})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/daytona/volumes"},
		{http.MethodPost, "/daytona/volumes"},
		{http.MethodGet, "/daytona/volumes/vol-1"},
		{http.MethodDelete, "/daytona/volumes/vol-1"},
		{http.MethodGet, "/daytona/volumes/by-name/my-volume"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !strings.Contains(body.Error, "future release") {
				t.Fatalf("body.Error = %q, want it to mention future release", body.Error)
			}
		})
	}
}
