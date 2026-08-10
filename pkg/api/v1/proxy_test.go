package v1

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func newProxyTestHandler(t *testing.T, cfg config.Config) (*handlers, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "proxy-test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "secrets.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(cfg, logger, db, nil, nil, nil, cipher, nil, nil)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, db
}

func createProxySandbox(t *testing.T, db *store.Store, id, containerIP, token string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.Create(context.Background(), &models.Sandbox{
		ID:           id,
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		ContainerIP:  containerIP,
		ToolboxToken: token,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("db.Create: %v", err)
	}
}

func TestProxyToToolbox_SandboxNotFound(t *testing.T) {
	h, _ := newProxyTestHandler(t, config.Config{ToolboxPort: 21212})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/missing/toolbox", nil)
	req.SetPathValue("id", "missing")
	h.toolboxProxy(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestToolboxProxy_ForwardsPathAndToken(t *testing.T) {
	var gotPath string
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(port): %v", err)
	}

	h, db := newProxyTestHandler(t, config.Config{ToolboxPort: port})
	createProxySandbox(t, db, "sb-1", host, "toolbox-secret")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1/toolbox/exec", nil)
	req.SetPathValue("id", "sb-1")
	req.SetPathValue("path", "exec")
	h.toolboxProxy(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if gotPath != "/exec" {
		t.Fatalf("upstream path = %q, want /exec", gotPath)
	}
	if gotAuth != "Bearer toolbox-secret" {
		t.Fatalf("upstream auth = %q, want bearer token", gotAuth)
	}
}

func TestSessionsProxy_RewritesToSessionsRootAndNested(t *testing.T) {
	paths := make([]string, 0, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(port): %v", err)
	}

	h, db := newProxyTestHandler(t, config.Config{ToolboxPort: port})
	createProxySandbox(t, db, "sb-2", host, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-2/sessions", nil)
	req.SetPathValue("id", "sb-2")
	h.sessionsProxy(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status(root) = %d, want 204", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-2/sessions/attach", nil)
	req.SetPathValue("id", "sb-2")
	req.SetPathValue("path", "attach")
	h.sessionsProxy(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status(nested) = %d, want 204", rr.Code)
	}

	if len(paths) != 2 || paths[0] != "/sessions" || paths[1] != "/sessions/attach" {
		t.Fatalf("upstream paths = %+v, want [/sessions /sessions/attach]", paths)
	}
}

func TestProxyToToolbox_InvalidTargetURL(t *testing.T) {
	h, db := newProxyTestHandler(t, config.Config{ToolboxPort: 21212})
	createProxySandbox(t, db, "sb-bad", "bad host", "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-bad/toolbox", nil)
	req.SetPathValue("id", "sb-bad")
	req.SetPathValue("path", "")
	h.toolboxProxy(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}
