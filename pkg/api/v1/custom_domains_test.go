package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// customDomainsV1Env spins up the smallest possible v1 mux that can serve
// the custom-domains routes end-to-end: real store, real service, disabled
// caddy (UpsertSandboxRoute is a no-op so the test asserts on store + wire
// shape rather than on the route bytes — pkg/caddy/custom_domains_test.go
// covers the matcher).
type customDomainsV1Env struct {
	mux   http.Handler
	svc   *service.Service
	store *store.Store
}

func newCustomDomainsV1Env(t *testing.T, cfgOverride func(*config.Config)) *customDomainsV1Env {
	t.Helper()
	cfg := config.Config{
		EnableCustomDomains:           true,
		Domain:                        "aerol.cloud",
		CustomDomainsMaxPerSandbox:    models.MaxCustomDomainsPerSandbox,
		CustomDomainVerifyPrefix:      "_aerol-verify",
		CustomDomainVerifyValuePrefix: "aerol-verify=",
	}
	if cfgOverride != nil {
		cfgOverride(&cfg)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	caddyClient := caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	svc := service.New(cfg, logger, st, &noopRuntime{}, nil, caddyClient, nil, nil, nil)
	svc.SetDNSResolver(&mockDNSResolver{
		// TXT value is the hostname itself, not the sandbox ID, so a
		// single record can serve every sandbox that claims the host.
		records: map[string][]string{
			"_aerol-verify.api.acme.com": {"aerol-verify=api.acme.com"},
			"_aerol-verify.acme.com":     {"aerol-verify=acme.com"},
		},
	})

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Operator: true})
				h.ServeHTTP(w, r.WithContext(ctx))
			})
		},
	})
	return &customDomainsV1Env{mux: mux, svc: svc, store: st}
}

func seedSandboxRowV1(t *testing.T, st *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:           id,
		Image:        "test-image",
		Status:       models.SandboxStatusStarted,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
}

func do(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestV1AddCustomDomain_Created(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")

	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", map[string]string{"hostname": "API.Acme.com"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		CustomDomains []models.CustomDomain `json:"custom_domains"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.CustomDomains) != 1 || resp.CustomDomains[0].Hostname != "api.acme.com" {
		t.Fatalf("custom_domains=%+v", resp.CustomDomains)
	}
	if resp.CustomDomains[0].Status != models.CustomDomainPendingDNS {
		t.Fatalf("status=%v", resp.CustomDomains[0].Status)
	}
}

func TestV1AddCustomDomain_Disabled412(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.EnableCustomDomains = false
	})
	seedSandboxRowV1(t, env.store, "sb-1")

	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1AddCustomDomain_IPMode412(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.Domain = ""
	})
	seedSandboxRowV1(t, env.store, "sb-1")

	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1AddCustomDomain_BadHostname400(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")

	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", map[string]string{"hostname": "single-label"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1AddCustomDomain_CrossSandbox409(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-a")
	seedSandboxRowV1(t, env.store, "sb-b")

	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-a/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed status=%d", rr.Code)
	}
	rr = do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-b/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1AddCustomDomain_MissingSandbox404(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/nope/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1ListCustomDomains_Empty(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")

	rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1/custom-domains", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		CustomDomains []models.CustomDomain `json:"custom_domains"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.CustomDomains) != 0 {
		t.Fatalf("expected empty list, got %v", resp.CustomDomains)
	}
}

func TestV1RemoveCustomDomain_NoContent(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-1")
	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed status=%d", rr.Code)
	}
	rr = do(t, env.mux, http.MethodDelete, "/v1/sandboxes/sb-1/custom-domains/API.Acme.com", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
	// Re-delete is 404 (the row is gone).
	rr = do(t, env.mux, http.MethodDelete, "/v1/sandboxes/sb-1/custom-domains/api.acme.com", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("re-delete status=%d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1RemoveCustomDomain_CrossSandbox404(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	seedSandboxRowV1(t, env.store, "sb-a")
	seedSandboxRowV1(t, env.store, "sb-b")
	rr := do(t, env.mux, http.MethodPost, "/v1/sandboxes/sb-a/custom-domains", map[string]string{"hostname": "api.acme.com"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed status=%d", rr.Code)
	}
	rr = do(t, env.mux, http.MethodDelete, "/v1/sandboxes/sb-b/custom-domains/api.acme.com", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}
}
