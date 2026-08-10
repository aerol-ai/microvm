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
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func newSecretInternalTestMux(t *testing.T, nodeID string) (*http.ServeMux, *service.Service, *secrets.Cipher) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, cipher, nil, nil)
	svc.AttachCluster(cluster.NewNoop(nodeID, "http://"+nodeID, ""))
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				// Mimic requireAuth: Bearer operator → Operator; else tenant.
				tok := r.Header.Get("Authorization")
				var access controlplane.Access
				if tok == "Bearer operator" {
					access = controlplane.Access{Operator: true}
				} else {
					access = controlplane.Access{Identity: controlplane.Identity{OwnerRef: "tenant-a"}}
				}
				next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), access)))
			})
		},
	})
	return mux, svc, cipher
}

func mustSealBlob(t *testing.T, cipher *secrets.Cipher, sandboxID, nodeID string, recipients []string) secrets.SecretBlob {
	t.Helper()
	bag := secrets.Secrets{Registry: &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "p"}}
	ref := secrets.FormatRef(sandboxID, 1)
	binding := secrets.SealBinding{SandboxID: sandboxID, Ref: ref, Version: 1, Generation: 1}
	sealed, err := secrets.SealEnvelopeBound(cipher, bag, recipients, binding)
	if err != nil {
		t.Fatalf("SealEnvelopeBound: %v", err)
	}
	_ = nodeID
	return secrets.SecretBlob{
		Ref:            ref,
		SandboxID:      sandboxID,
		Version:        1,
		Recipients:     recipients,
		SealedPayload:  sealed,
		SealGeneration: 1,
	}
}

func TestClusterInternalSecretPutUnauthenticatedRejected(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	blob := mustSealBlob(t, cipher, "sb", "node-a", []string{"node-a", "node-b"})
	body, _ := json.Marshal(blob)

	req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rr.Code)
	}
}

func TestClusterInternalSecretPutTenantForbidden(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	blob := mustSealBlob(t, cipher, "sb", "node-a", []string{"node-a", "node-b"})
	body, _ := json.Marshal(blob)

	req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tenant-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("tenant status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterInternalSecretPutOperatorOK(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	blob := mustSealBlob(t, cipher, "sb", "node-a", []string{"node-a", "node-b"})
	body, _ := json.Marshal(blob)

	req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer operator")
	addVerifiedClientCertificate(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("operator status = %d body=%s", rr.Code, rr.Body.String())
	}

	// Idempotent upsert.
	req2 := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer operator")
	addVerifiedClientCertificate(req2)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("idempotent upsert status = %d", rr2.Code)
	}
}

func TestClusterInternalSecretPutRejectsNonRecipient(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	// Sealed only for node-b — node-a must refuse to store.
	blob := mustSealBlob(t, cipher, "sb", "node-a", []string{"node-b", "node-c"})
	body, _ := json.Marshal(blob)

	req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer operator")
	addVerifiedClientCertificate(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-recipient status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterInternalSecretPutRejectsRefMismatch(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	blob := mustSealBlob(t, cipher, "sb", "node-a", []string{"node-a"})
	blob.Ref = "cluster-secret://sandbox/other/v1"
	body, _ := json.Marshal(blob)

	req := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer operator")
	addVerifiedClientCertificate(req)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("ref mismatch status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterInternalSecretDeleteTenantForbidden(t *testing.T) {
	mux, _, _ := newSecretInternalTestMux(t, "node-a")
	req := httptest.NewRequest(http.MethodDelete, cluster.PublicInternalSecretPath+"/sb", nil)
	req.Header.Set("Authorization", "Bearer tenant-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("tenant delete status = %d, want 403", rr.Code)
	}
}

func TestClusterInternalSandboxAuditTenantForbidden(t *testing.T) {
	mux, _, _ := newSecretInternalTestMux(t, "node-a")
	req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalSandboxAuditPath+"sb/audit", nil)
	req.Header.Set("Authorization", "Bearer tenant-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("tenant audit status = %d, want 403", rr.Code)
	}
}
