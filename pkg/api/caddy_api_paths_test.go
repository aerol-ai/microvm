package api

import (
	"os"
	"strings"
	"testing"
)

// TestCaddyForwardsEveryPublicRoute: on a domain install Caddy sends only
// the paths its @api matcher names to sandboxd; anything else on the API
// host gets Caddy's own "Sandbox API not found". A public route sandboxd
// serves but Caddy does not forward is dead in production while every
// in-process test passes: the cloud-identity discovery and JWKS documents
// were (UC-431 live, 2026-11-06), and the clouds fetch them anonymously
// through exactly this path. Every public route must be matched by the
// @api matcher in both Caddy configs.
func TestCaddyForwardsEveryPublicRoute(t *testing.T) {
	var paths []string
	for pattern := range publicRoutes {
		paths = append(paths, routePath(pattern))
	}
	for _, prefix := range publicRoutePrefixes {
		paths = append(paths, routePath(prefix))
	}
	for _, file := range []string{"../../packaging/Caddyfile.template", "../../scripts/install.sh"} {
		matchers := apiPathMatchers(t, file)
		for _, path := range paths {
			if !caddyPathMatches(matchers, path) {
				t.Errorf("%s: public route %q is not in the @api path matcher, so Caddy answers it with its own 404", file, path)
			}
		}
	}
}

func routePath(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = pattern[i+1:]
	}
	return strings.TrimSuffix(pattern, "/")
}

// apiPathMatchers returns the paths of the "@api path ..." line in file.
func apiPathMatchers(t *testing.T, file string) []string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[0] == "@api" && fields[1] == "path" {
			return fields[2:]
		}
	}
	t.Fatalf("%s: no @api path matcher", file)
	return nil
}

// caddyPathMatches applies Caddy's path matcher rules: an exact path, or a
// pattern ending in "*" that matches by prefix.
func caddyPathMatches(matchers []string, path string) bool {
	for _, m := range matchers {
		if prefix, ok := strings.CutSuffix(m, "*"); ok {
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if m == path {
			return true
		}
	}
	return false
}
