package v1_test

import (
	"net/http"
	"strings"
	"testing"

	apiv1 "github.com/aerol-ai/microvm/pkg/api/v1"
)

// TestRegisterRoutesPrefix is a smoke test that every v1 route registered on
// the mux begins with PathPrefix. It exists to catch the regression where a
// future maintainer copies the v1 file as a starting point for v2 but forgets
// to update PathPrefix — the route would then accidentally collide on /v1/...
//
// The test does not exercise handler behavior; pkg/api integration tests
// cover that.
func TestRegisterRoutesAllUseV1Prefix(t *testing.T) {
	mux := http.NewServeMux()
	apiv1.RegisterRoutes(mux, apiv1.Deps{
		// Service/Logger can be nil because the test only inspects routing,
		// not handler execution. ServeMux.Handle is the surface under test.
		Auth: func(h http.Handler) http.Handler { return h },
	})

	// http.ServeMux does not expose its registered patterns publicly, so we
	// probe with HEAD to a small set of known v1 paths and assert each
	// resolves (i.e. is not the 404 NotFoundHandler). A path mismatch would
	// indicate someone moved a route off /v1/.
	probes := []string{
		"/v1/capacity",
		"/v1/sandboxes",
		"/v1/sandboxes/abc",
		"/v1/sandboxes/abc/sessions",
		"/v1/sandboxes/abc/toolbox/foo",
	}
	for _, p := range probes {
		req, _ := http.NewRequest(http.MethodGet, p, nil)
		_, pattern := mux.Handler(req)
		// Pattern can be "GET /v1/foo" (method-scoped) or just "/v1/foo".
		// Either way it must contain PathPrefix as a path component.
		if pattern == "" || !strings.Contains(pattern, apiv1.PathPrefix+"/") {
			t.Errorf("path %q resolved to pattern %q, expected one containing %q", p, pattern, apiv1.PathPrefix)
		}
	}
}
