package daytona

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/createpolicy"
)

// TestDaytonaCreateRefusedByCreatePolicy: the Daytona facade's create goes
// through the same service check, so its image is held to the operator's
// create policy and the refusal is a 403 naming the rule.
func TestDaytonaCreateRefusedByCreatePolicy(t *testing.T) {
	env := newDaytonaContractEnv(t)
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nimages:\n  allowed: [\"python:*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.service.SetCreatePolicy(createpolicy.NewWatcher(path, nil))
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	rr := httptest.NewRecorder()
	h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(`{"snapshot":"alpine:3.20"}`)))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "images") || !strings.Contains(rr.Body.String(), "alpine:3.20") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if n := countSandboxes(t, env); n != 0 {
		t.Fatalf("a refused create left %d sandboxes", n)
	}
}
