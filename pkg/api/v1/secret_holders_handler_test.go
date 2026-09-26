package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// newHoldersTestHandler mirrors newAuditTestHandler but also hands back the
// store, because seeding a sealed cluster-secret row is the whole point of
// these tests and Service deliberately does not expose its store.
func newHoldersTestHandler(t *testing.T) (*handlers, *storepkg.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{DBPath: dbPath}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://a", ""))
	t.Cleanup(svc.CloseSecretAuditSink)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-holders-1", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		AuditIncarnationID: "inc-holders-1",
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, st, sb.ID
}

// The holders route is the ONLY way an operator (or the integration suite,
// which has a PAT and no client certificate) can observe a sandbox's
// recipient set: every /v1/cluster/internal/* route is mTLS-gated and there
// is no list verb on the peer secret path.
func TestSecretHoldersRouteReturnsRecipients(t *testing.T) {
	h, _, sbID := newHoldersTestHandler(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: operatorAuth})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/sandboxes/"+sbID+"/secret-holders", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		SandboxID string   `json:"sandbox_id"`
		Holders   []string `json:"holders"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	if got.SandboxID != sbID {
		t.Fatalf("sandbox_id = %q, want %q", got.SandboxID, sbID)
	}
	// A sandbox with no sealed secret reports an empty set, NOT 404 — 404 is
	// reserved for a sandbox that does not exist, and a caller asserting
	// "secrets were removed" must be able to tell those apart.
	if got.Holders == nil {
		t.Error("holders is null; an empty JSON array and null are different to a caller asserting 'no holders left'")
	}
}

func TestSecretHoldersRouteUnknownSandboxIs404(t *testing.T) {
	h, _, _ := newHoldersTestHandler(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: operatorAuth})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/sandboxes/sb-nope/secret-holders", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

// The response must never carry the sealed payload. This route is reachable
// with an operator PAT; leaking ciphertext would make an observability read a
// second path to the material the subsystem exists to protect.
func TestSecretHoldersRouteNeverSerialisesCiphertext(t *testing.T) {
	h, st, sbID := newHoldersTestHandler(t)
	const marker = "SEALED-CIPHERTEXT-MARKER"
	rec := storepkg.ClusterSecretRecord{
		Ref:            secrets.FormatRef(sbID, "inc-holders-1", secrets.RefVersion),
		SandboxID:      sbID,
		Version:        secrets.RefVersion,
		Recipients:     []string{"node-b", "node-a"},
		SealedPayload:  []byte(marker),
		SealGeneration: 4,
	}
	if _, err := st.PutClusterSecret(context.Background(), rec); err != nil {
		t.Fatalf("PutClusterSecret: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: operatorAuth})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/sandboxes/"+sbID+"/secret-holders", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, marker) {
		t.Fatalf("response leaked the sealed payload: %s", body)
	}
	// It must still be useful: sorted holders and the generation that fences
	// a reseal.
	if !strings.Contains(body, `"node-a","node-b"`) {
		t.Errorf("holders not returned sorted: %s", body)
	}
	if !strings.Contains(body, `"seal_generation":4`) {
		t.Errorf("seal_generation missing; a caller cannot tell a reseal from no change: %s", body)
	}
}

// The recipient set names which nodes hold a tenant's sealed secret — fleet
// topology a TENANT token must never read. The route is registered behind the
// same op() gate as every other /v1/cluster route; this pins that, because a
// future refactor moving it to d.Auth would silently expose it.
func TestSecretHoldersRouteRejectsNonOperator(t *testing.T) {
	h, _, sbID := newHoldersTestHandler(t)
	mux := http.NewServeMux()
	// Auth that grants a tenant identity but NOT operator.
	tenantAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Operator: false})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: tenantAuth})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/sandboxes/"+sbID+"/secret-holders", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("a non-operator read the recipient set: %s", rr.Body.String())
	}
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401/403", rr.Code)
	}
}
