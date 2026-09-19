package daytona

import (
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func sandboxWithEnv(env map[string]string) *models.Sandbox {
	return &models.Sandbox{ID: "abc", Env: env}
}

// D9 moved env off the default read path: internal/service returns a nil Env
// unless GetSandboxOptions.IncludeEnv is set, and that read is audited. The
// facade went through the no-options Get, so a Daytona client had no way to
// read env back at all. includeEnvRequested is the opt-in, and it must accept
// exactly the spellings /v1's parseIncludeEnv does — the two surfaces drifting
// apart is how a caller ends up silently getting no env on one of them.
func TestIncludeEnvRequested(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{"absent", "", false},
		{"true", "?include_env=true", true},
		{"one", "?include_env=1", true},
		{"yes", "?include_env=yes", true},
		{"uppercase TRUE", "?include_env=TRUE", true},
		{"mixed case Yes", "?include_env=Yes", true},
		{"surrounding whitespace", "?include_env=%20true%20", true},
		{"explicit false", "?include_env=false", false},
		{"zero", "?include_env=0", false},
		{"empty value", "?include_env=", false},
		{"unrelated value", "?include_env=maybe", false},
		{"other params only", "?labels=a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/daytona/sandboxes/abc"+tc.query, nil)
			if got := includeEnvRequested(r); got != tc.want {
				t.Fatalf("includeEnvRequested(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

// hydrateEnvIfRequested must be a no-op on the default path — no second Get,
// no audit event — and must tolerate the nil inputs the handler can hand it.
func TestHydrateEnvIfRequestedNoOpPaths(t *testing.T) {
	h := &handlers{}

	t.Run("nil sandbox", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/daytona/sandboxes/abc?include_env=true", nil)
		if err := h.hydrateEnvIfRequested(r, nil); err != nil {
			t.Fatalf("hydrateEnvIfRequested(nil sandbox) = %v, want nil", err)
		}
	})

	t.Run("not requested leaves env untouched and never calls the service", func(t *testing.T) {
		// deps.Service is nil: if the default path tried to re-read, this would
		// panic rather than return.
		r := httptest.NewRequest("GET", "/daytona/sandboxes/abc", nil)
		sb := sandboxWithEnv(nil)
		if err := h.hydrateEnvIfRequested(r, sb); err != nil {
			t.Fatalf("hydrateEnvIfRequested = %v, want nil", err)
		}
		if sb.Env != nil {
			t.Fatalf("env = %v, want nil on the default path", sb.Env)
		}
	})

	t.Run("requested with no service configured is a no-op, not a panic", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/daytona/sandboxes/abc?include_env=true", nil)
		sb := sandboxWithEnv(nil)
		if err := h.hydrateEnvIfRequested(r, sb); err != nil {
			t.Fatalf("hydrateEnvIfRequested = %v, want nil", err)
		}
	})
}
