package daytona_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
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

// With platform volumes disabled (the default), every /volumes route returns
// 412 Precondition Failed — a clear "configure shared storage to enable this"
// signal, replacing the old blanket 405.
func TestVolumeRoutesReturn412WhenDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	daytona.RegisterRoutes(mux, daytona.Deps{
		Auth:    func(h http.Handler) http.Handler { return h },
		Service: svc,
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
			var body io.Reader
			if tc.method == http.MethodPost {
				body = strings.NewReader(`{"name":"data"}`)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusPreconditionFailed {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusPreconditionFailed, rr.Body.String())
			}
		})
	}
}
