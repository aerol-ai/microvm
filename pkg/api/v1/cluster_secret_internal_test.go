package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestClusterInternalSecretPutUnauthenticatedRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := service.New(config.Config{SecretRecipientFanoutEnabled: true}, logger, st, nil, nil, nil, cipher, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://a", ""))
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}})

	body, _ := json.Marshal(secrets.SecretBlob{
		Ref: "cluster-secret://sandbox/sb/v1", SandboxID: "sb", Version: 1, SealedPayload: []byte("x"),
	})
	req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer ok")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("authenticated status = %d body=%s", rr2.Code, rr2.Body.String())
	}

	// Idempotent upsert.
	req3 := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req3.Header.Set("Authorization", "Bearer ok")
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusNoContent {
		t.Fatalf("idempotent upsert status = %d", rr3.Code)
	}
}
