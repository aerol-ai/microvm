package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// plans/customer-key-custody.md Section 2 and §10 (OV7): on a node whose key
// was revoked, a request that reaches a sealed value answers 503 key_revoked,
// not 500 or a decrypt failure, and nothing sealed reaches the response or
// the log.
func TestRevokedKeyAnswers503(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, cipher, nil, nil)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-1", Image: "alpine:3.20", Status: models.SandboxStatusStarted, ContainerID: "ctr-1", ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 512, DiskGB: 10, OSUser: "root", Env: map[string]string{"TOKEN": "s3cret-value"}, ToolboxToken: "tbx-sealed-token",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{Fleet: true})))
		})
	}})
	get := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1?include_env=true", nil))
		return rr
	}
	if rr := get(); rr.Code != http.StatusOK {
		t.Fatalf("before the revoke: %d %s", rr.Code, rr.Body.String())
	}

	cipher.Revoke()
	rr := get()
	var body models.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusServiceUnavailable || body.Code != models.ErrorCodeKeyRevoked {
		t.Fatalf("revoked: %d %s", rr.Code, rr.Body.String())
	}
	for _, sealed := range []string{"s3cret-value", "tbx-sealed-token"} {
		if strings.Contains(rr.Body.String(), sealed) || strings.Contains(logs.String(), sealed) {
			t.Fatalf("%q reached the response or the log:\n%s\n%s", sealed, rr.Body.String(), logs.String())
		}
	}
}
