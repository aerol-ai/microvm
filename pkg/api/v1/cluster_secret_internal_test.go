package v1

import (
	"bytes"
	"crypto/x509"
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

type secretInternalTestCluster struct {
	*cluster.Noop
}

func (c *secretInternalTestCluster) LookupMember(id string) (cluster.Member, bool) {
	if id == "peer-test" {
		return cluster.Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker}, true
	}
	return c.Noop.LookupMember(id)
}

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
	svc.AttachCluster(&secretInternalTestCluster{Noop: cluster.NewNoop(nodeID, "http://"+nodeID, "")})
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
	addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:peer-test"}})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("operator status = %d body=%s", rr.Code, rr.Body.String())
	}

	// Idempotent upsert.
	req2 := httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer operator")
	addVerifiedClientCertificate(req2, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:peer-test"}})
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
	addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:peer-test"}})
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
	addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:peer-test"}})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("ref mismatch status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func internalOperatorRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer operator")
	addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:peer-test"}})
	return req
}

func TestClusterInternalSecretPutValidationAndConflict(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	for name, body := range map[string]string{
		"invalid_json": `{`,
		"empty_ref":    `{"sandbox_id":"sb","sealed_payload":"YQ=="}`,
		"empty_id":     `{"ref":"cluster-secret://sandbox/sb/v1","sealed_payload":"YQ=="}`,
		"empty_sealed": `{"ref":"cluster-secret://sandbox/sb/v1","sandbox_id":"sb"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, internalOperatorRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewBufferString(body)))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	first := mustSealBlob(t, cipher, "sb-conflict", "node-a", []string{"node-a"})
	second := mustSealBlob(t, cipher, "sb-conflict", "node-a", []string{"node-a"})
	for i, blob := range []secrets.SecretBlob{first, second} {
		body, _ := json.Marshal(blob)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, internalOperatorRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body)))
		want := http.StatusNoContent
		if i == 1 {
			want = http.StatusConflict
		}
		if rr.Code != want {
			t.Fatalf("write %d status = %d, want %d body=%s", i, rr.Code, want, rr.Body.String())
		}
	}
}

func TestClusterInternalSecretHeadAndDeleteLifecycle(t *testing.T) {
	mux, _, cipher := newSecretInternalTestMux(t, "node-a")
	blob := mustSealBlob(t, cipher, "sb-lifecycle", "node-a", []string{"node-a"})
	body, _ := json.Marshal(blob)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, internalOperatorRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("put status = %d body=%s", rr.Code, rr.Body.String())
	}

	headPath := cluster.PublicInternalSecretPath + "/sb-lifecycle"
	for _, tc := range []struct {
		query string
		want  int
	}{
		{want: http.StatusNoContent},
		{query: "?min_generation=1", want: http.StatusNoContent},
		{query: "?min_generation=2", want: http.StatusNotFound},
		{query: "?min_generation=0", want: http.StatusBadRequest},
		{query: "?min_generation=bad", want: http.StatusBadRequest},
	} {
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, internalOperatorRequest(http.MethodHead, headPath+tc.query, nil))
		if rr.Code != tc.want {
			t.Fatalf("HEAD %q status = %d, want %d body=%s", tc.query, rr.Code, tc.want, rr.Body.String())
		}
	}

	for _, query := range []string{"?generation=0", "?generation=bad"} {
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, internalOperatorRequest(http.MethodDelete, headPath+query, nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("DELETE %q status = %d body=%s", query, rr.Code, rr.Body.String())
		}
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, internalOperatorRequest(http.MethodDelete, headPath+"?generation=1", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, internalOperatorRequest(http.MethodHead, headPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("post-delete HEAD status = %d", rr.Code)
	}
	// Peer DELETE is idempotent and must ACK retries after the row is gone.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, internalOperatorRequest(http.MethodDelete, headPath, nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("idempotent delete status = %d body=%s", rr.Code, rr.Body.String())
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
