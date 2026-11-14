package runloop

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/createpolicy"
)

// TestRunloopCreateRefusedByCreatePolicy: a Runloop blueprint resolves to an
// image held to the operator's create policy; the refusal is a 403 naming
// the rule, and Runloop's envelope tells the SDK not to retry.
func TestRunloopCreateRefusedByCreatePolicy(t *testing.T) {
	env := newTestEnv(t)
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nimages:\n  allowed: [\"alpine:*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.svc.SetCreatePolicy(createpolicy.NewWatcher(path, nil))

	rr := env.do(t, http.MethodPost, "", map[string]any{"blueprint_name": "python"}, nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "images") || !strings.Contains(rr.Body.String(), "python:3.12") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("x-should-retry"); got == "true" {
		t.Fatalf("a policy refusal must not be marked retryable, x-should-retry=%q", got)
	}
}
