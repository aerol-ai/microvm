package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A tenant must not be able to name the cluster auto-import registry namespace
// (cluster/<id>/_imported/...), which the daemon pulls with the cluster PAT —
// that would let a tenant pull another tenant's re-homed private image.
func TestImageDistribution_TenantCannotNameImportedRef(t *testing.T) {
	svc := newBundleService(t)
	imported := "aocr.aerol.ai/cluster/c1/_imported/ghcr.io/acme/private-app:v3"

	req := models.CreateSandboxRequest{Image: imported}
	if err := svc.NormalizeCreateImageDistribution(ownerScopedCtx("tenant-b"), &req); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant naming _imported ref = %v, want ErrNotFound", err)
	}
	// Operator/internal (unscoped) callers keep the namespace: auto-import and
	// failover recreate run there.
	reqOp := models.CreateSandboxRequest{Image: imported}
	if err := svc.NormalizeCreateImageDistribution(operatorCtx(), &reqOp); err != nil {
		t.Fatalf("operator naming _imported ref rejected: %v", err)
	}
}

// The toolbox/sessions proxy must not forward the caller's credential into the
// sandbox: toolboxd (tenant-controlled space) authenticates from Authorization,
// so the proxy sets the sandbox's own toolbox token there and strips the
// Sec-WebSocket-Protocol smuggle, keeping only the subprotocol marker.
func TestToolboxProxy_DoesNotForwardCallerBearer(t *testing.T) {
	got := make(chan http.Header, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	port, _ := strconv.Atoi(ts.URL[strings.LastIndex(ts.URL, ":")+1:])
	svc.cfg.ToolboxPort = port
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-tenant-b", OwnerRef: "tenant-b", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
		ToolboxToken: "tbx", ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://api/v1/sandboxes/sb-tenant-b/sessions/s1/attach", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "sandbox.bearer, OPERATOR-PAT-SECRET")
	rec := httptest.NewRecorder()
	if err := svc.ServeToolboxReverseProxy(operatorCtx(), "sb-tenant-b", rec, req, "/sessions/s1/attach"); err != nil {
		t.Fatal(err)
	}
	h := <-got
	if strings.Contains(h.Get("Sec-WebSocket-Protocol"), "OPERATOR-PAT-SECRET") {
		t.Fatalf("caller bearer leaked to toolboxd via Sec-WebSocket-Protocol: %q", h.Get("Sec-WebSocket-Protocol"))
	}
	if h.Get("Sec-WebSocket-Protocol") != "sandbox.bearer" {
		t.Fatalf("subprotocol marker = %q, want 'sandbox.bearer'", h.Get("Sec-WebSocket-Protocol"))
	}
	if h.Get("Authorization") != "Bearer tbx" {
		t.Fatalf("Authorization = %q, want the sandbox toolbox token", h.Get("Authorization"))
	}
}
