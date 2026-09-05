package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGetSandboxAuditUnauthenticated401(t *testing.T) {
	h, _ := newAuditTestHandler(t, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: h.deps.Service,
		Logger:  h.deps.Logger,
		Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1/audit", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestGetSandboxAuditRateLimit429RetryAfter(t *testing.T) {
	limiter := NewAuditRateLimiter(AuditRateLimiterConfig{
		IdentityRate: 1,
		OperatorRate: 1,
		NodeRate:     1,
	})
	// Exhaust burst quickly.
	for i := 0; i < 120; i++ {
		if _, ok := limiter.allow("operator"); !ok {
			break
		}
	}
	h, sbID := newAuditTestHandler(t, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service:      h.deps.Service,
		Logger:       h.deps.Logger,
		AuditLimiter: limiter,
		Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Operator: true})
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sbID+"/audit", nil)
	req.Header.Set("Authorization", "Bearer x")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func TestGetSandboxAuditOwnerScopeOtherTenant404(t *testing.T) {
	h, sbID := newAuditTestHandler(t, func(sb *models.Sandbox) { sb.OwnerRef = "acme" })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sbID+"/audit", nil)
	req.SetPathValue("id", sbID)
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "evil"},
	}))
	h.getSandboxAudit(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestGetSandboxAuditReturnsEvents(t *testing.T) {
	h, sbID := newAuditTestHandler(t, nil)
	if _, err := h.deps.Service.GetSandboxWithOptions(context.Background(), sbID, service.GetSandboxOptions{
		IncludeEnv: true, CorrelationID: "req-corr-1",
	}); err != nil {
		t.Fatalf("GetSandboxWithOptions: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sbID+"/audit", nil)
	req.SetPathValue("id", sbID)
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.Access{Operator: true}))
	h.getSandboxAudit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var page service.SecretAuditPage
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Coverage.Partial {
		t.Fatalf("unexpected partial: %+v", page.Coverage)
	}
}

func TestClusterInternalSandboxAuditLocalOnly(t *testing.T) {
	h, sbID := newAuditTestHandler(t, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, cluster.PublicInternalSandboxAuditPath+sbID+"/audit", nil)
	req.SetPathValue("id", sbID)
	h.clusterInternalSandboxAudit(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCorrelationIDFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "r1")
	if got := correlationIDFromRequest(req); got != "r1" {
		t.Fatalf("got %q", got)
	}
	req.Header.Set("X-Correlation-ID", "c1")
	if got := correlationIDFromRequest(req); got != "c1" {
		t.Fatalf("got %q", got)
	}
}

func newAuditTestHandler(t *testing.T, mut func(*models.Sandbox)) (*handlers, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{DBPath: dbPath, SecretAuditRetentionDays: 30}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://a", ""))
	t.Cleanup(svc.CloseSecretAuditSink)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-audit-1", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if mut != nil {
		mut(sb)
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, sb.ID
}
