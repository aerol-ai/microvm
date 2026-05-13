package daytona_test

import (
	"net/http"
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
