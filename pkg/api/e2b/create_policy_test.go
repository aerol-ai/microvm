package e2b

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/createpolicy"
)

// TestE2BCreateRefusedByCreatePolicy: an E2B template resolves to an image,
// and that image is held to the operator's create policy like any other
// create: 403, naming the rule.
func TestE2BCreateRefusedByCreatePolicy(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nimages:\n  allowed: [\"alpine:*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.SetCreatePolicy(createpolicy.NewWatcher(path, nil))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base"}`)))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "images") || !strings.Contains(rr.Body.String(), "ubuntu:22.04") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
