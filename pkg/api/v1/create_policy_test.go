package v1

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreateRefusedByCreatePolicy: a native create the operator's create
// policy refuses is a 403 with the policy code and a message naming the
// rule, through the routed create handler.
func TestCreateRefusedByCreatePolicy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nlimits:\n  max_cpu: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.SetCreatePolicy(createpolicy.NewWatcher(path, nil))
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20","cpu":2}`)))
	var body models.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusForbidden || body.Code != models.ErrorCodeCreatePolicyDenied || !strings.Contains(body.Error, `"limits.max_cpu"`) {
		t.Fatalf("status=%d code=%q error=%q", rr.Code, body.Code, body.Error)
	}
}
