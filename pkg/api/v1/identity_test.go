package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type identityV1Env struct {
	mux    *http.ServeMux
	svc    *service.Service
	access controlplane.Access
}

func newIdentityV1Env(t *testing.T, issuer string) *identityV1Env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{7}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{IdentityIssuerURL: issuer}, logger, st, &noopRuntime{}, nil,
		caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}), cipher, nil, nil)
	env := &identityV1Env{mux: http.NewServeMux(), svc: svc, access: controlplane.OperatorAccess()}
	RegisterRoutes(env.mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), env.access)))
			})
		},
	})
	return env
}

func TestV1IdentityRoles(t *testing.T) {
	env := newIdentityV1Env(t, "https://api.example.com")
	put := func(path string, body any) *httptest.ResponseRecorder {
		return do(t, env.mux, http.MethodPut, path, body)
	}
	rr := put("/v1/identity/roles/deploy?team=payments", models.IdentityRoleRequest{MinRole: "runner"})
	var role models.IdentityRole
	_ = json.Unmarshal(rr.Body.Bytes(), &role)
	if rr.Code != http.StatusOK || role.Tag != "deploy" || role.Team != "payments" || role.MinRole != "runner" {
		t.Fatalf("PUT = %d %s", rr.Code, rr.Body.String())
	}
	// Idempotent: the same PUT again answers the same row.
	if rr := put("/v1/identity/roles/deploy?team=payments", models.IdentityRoleRequest{MinRole: "runner"}); rr.Code != http.StatusOK {
		t.Fatalf("repeat PUT = %d", rr.Code)
	}
	put("/v1/identity/roles/build?team=payments", models.IdentityRoleRequest{MinRole: "admin"})
	rr = do(t, env.mux, http.MethodGet, "/v1/identity/roles?team=payments&limit=1", nil)
	var list models.IdentityRoleList
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if rr.Code != http.StatusOK || len(list.Roles) != 1 || list.Roles[0].Tag != "build" || list.NextCursor != "build" {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}
	rr = do(t, env.mux, http.MethodGet, "/v1/identity/roles?team=payments&cursor=build", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Roles) != 1 || list.Roles[0].Tag != "deploy" {
		t.Fatalf("page 2 = %s", rr.Body.String())
	}
	for i := 0; i < 2; i++ {
		if rr := do(t, env.mux, http.MethodDelete, "/v1/identity/roles/deploy?team=payments", nil); rr.Code != http.StatusNoContent {
			t.Fatalf("DELETE %d = %d %s", i, rr.Code, rr.Body.String())
		}
	}
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPut, "/v1/identity/roles/Bad:Tag", models.IdentityRoleRequest{MinRole: "runner"}, http.StatusBadRequest},
		{http.MethodPut, "/v1/identity/roles/x", models.IdentityRoleRequest{MinRole: "viewer"}, http.StatusBadRequest},
		{http.MethodPut, "/v1/identity/roles/x?team=Bad%20Team", models.IdentityRoleRequest{MinRole: "runner"}, http.StatusBadRequest},
		{http.MethodGet, "/v1/identity/roles?limit=-1", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/identity/roles?limit=x", nil, http.StatusBadRequest},
	} {
		if rr := do(t, env.mux, tc.method, tc.path, tc.body); rr.Code != tc.want {
			t.Errorf("%s %s = %d %s, want %d", tc.method, tc.path, rr.Code, rr.Body.String(), tc.want)
		}
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/identity/roles/x", strings.NewReader("{bad"))
	rr = httptest.NewRecorder()
	env.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d", rr.Code)
	}
	// D1.5: admin only. A runner bound to a team is refused by the route.
	env.access = controlplane.TokenAccess("tok_r", "r", controlplane.RoleRunner, "payments", time.Now().Add(time.Hour))
	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/v1/identity/roles/deploy"},
		{http.MethodDelete, "/v1/identity/roles/deploy"},
		{http.MethodGet, "/v1/identity/roles"},
		{http.MethodPost, "/v1/identity/keys/rotate"},
	} {
		if rr := do(t, env.mux, tc.method, tc.path, models.IdentityRoleRequest{MinRole: "runner"}); rr.Code != http.StatusForbidden {
			t.Errorf("runner %s %s = %d, want 403", tc.method, tc.path, rr.Code)
		}
	}
}

func TestV1IdentityRotateAndCreateErrors(t *testing.T) {
	env := newIdentityV1Env(t, "https://api.example.com")
	rr := do(t, env.mux, http.MethodPost, "/v1/identity/keys/rotate", nil)
	var rot models.IdentityKeyRotation
	_ = json.Unmarshal(rr.Body.Bytes(), &rot)
	if rr.Code != http.StatusOK || rot.ActiveKeyID == "" || len(rot.PublishedKeyID) != 2 {
		t.Fatalf("rotate = %d %s", rr.Code, rr.Body.String())
	}
	// Never key material in the answer.
	if strings.Contains(rr.Body.String(), "sealed") || strings.Contains(rr.Body.String(), `"d"`) {
		t.Fatalf("rotate answered key material: %s", rr.Body.String())
	}
	// A retry naming the old key is a no-op.
	rr = do(t, env.mux, http.MethodPost, "/v1/identity/keys/rotate", map[string]string{"if_active_key_id": rot.PublishedKeyID[1]})
	var again models.IdentityKeyRotation
	_ = json.Unmarshal(rr.Body.Bytes(), &again)
	if rr.Code != http.StatusOK || again.ActiveKeyID != rot.ActiveKeyID {
		t.Fatalf("retried rotate = %d %s", rr.Code, rr.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/keys/rotate", strings.NewReader("{bad"))
	rr = httptest.NewRecorder()
	env.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad rotate body = %d", rr.Code)
	}
	// Create: a tag not on the list is 403; identity on WASM is 400.
	rr = do(t, env.mux, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "unlisted"}})
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "allow list") {
		t.Fatalf("unlisted tag create = %d %s", rr.Code, rr.Body.String())
	}
	rr = do(t, env.mux, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeDocker, Identity: &models.IdentityRequest{RoleTag: "x", AzureClientID: "half"}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad identity create = %d %s", rr.Code, rr.Body.String())
	}
	// Rotation past the cap inside the JWKS window is 409.
	for i := 0; i < cloudidentity.MaxKeys; i++ {
		rr = do(t, env.mux, http.MethodPost, "/v1/identity/keys/rotate", nil)
		if rr.Code == http.StatusConflict {
			break
		}
	}
	if rr.Code != http.StatusConflict {
		t.Fatalf("rotation past the cap = %d %s", rr.Code, rr.Body.String())
	}
}

func TestV1IdentityOff(t *testing.T) {
	env := newIdentityV1Env(t, "")
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/v1/identity/roles/deploy", models.IdentityRoleRequest{MinRole: "runner"}},
		{http.MethodDelete, "/v1/identity/roles/deploy", nil},
		{http.MethodGet, "/v1/identity/roles", nil},
		{http.MethodPost, "/v1/identity/keys/rotate", nil},
		{http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "deploy"}}},
	} {
		rr := do(t, env.mux, tc.method, tc.path, tc.body)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "SB_IDENTITY_ISSUER_URL") {
			t.Errorf("%s %s with identity off = %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}

// identityStubCluster stands in for a server's replicated identity store.
type identityStubCluster struct {
	*cluster.Noop
	writeErr error
	readErr  error
}

func (s *identityStubCluster) WriteIdentity(_ context.Context, req cluster.IdentityWriteRequest) (cluster.IdentityWriteResponse, error) {
	if s.writeErr != nil {
		return cluster.IdentityWriteResponse{}, s.writeErr
	}
	return cluster.IdentityWriteResponse{Role: req.Role, Changed: true}, nil
}

func (s *identityStubCluster) ReadIdentity(_ context.Context, req cluster.IdentityReadRequest) (cluster.IdentityReadResponse, error) {
	if s.readErr != nil {
		return cluster.IdentityReadResponse{}, s.readErr
	}
	return cluster.IdentityReadResponse{Roles: []cluster.IdentityRoleRecord{{Owner: req.Owner, Tag: "deploy", MinRole: "runner"}}, Authoritative: true}, nil
}

func TestClusterInternalIdentityRoutes(t *testing.T) {
	stub := &identityStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	call := func(fn http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		fn(rr, withPeer(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)), "wrk-a"))
		return rr
	}
	write := `{"role":{"owner":"team:p","tag":"deploy","min_role":"runner"}}`
	rr := call(h.clusterInternalIdentityWrite, cluster.PublicInternalIdentityWritePath, write)
	var out cluster.IdentityWriteResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Role == nil || !out.Changed {
		t.Fatalf("write = %d %s", rr.Code, rr.Body.String())
	}
	stub.writeErr = cluster.ErrIdentityKeysConflict
	rr = call(h.clusterInternalIdentityWrite, cluster.PublicInternalIdentityWritePath, write)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Code == "" {
		t.Fatalf("refusal = %d %s", rr.Code, rr.Body.String())
	}
	stub.writeErr = errors.New("raft apply timed out")
	if rr := call(h.clusterInternalIdentityWrite, cluster.PublicInternalIdentityWritePath, write); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("transient = %d", rr.Code)
	}
	if rr := call(h.clusterInternalIdentityWrite, cluster.PublicInternalIdentityWritePath, "x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", rr.Code)
	}
	rr = call(h.clusterInternalIdentityRead, cluster.PublicInternalIdentityReadPath, `{"owner":"team:p","tags":["deploy"]}`)
	var read cluster.IdentityReadResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &read)
	if rr.Code != http.StatusOK || len(read.Roles) != 1 || !read.Authoritative {
		t.Fatalf("read = %d %s", rr.Code, rr.Body.String())
	}
	stub.readErr = errors.New("no fsm")
	if rr := call(h.clusterInternalIdentityRead, cluster.PublicInternalIdentityReadPath, `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("read error = %d", rr.Code)
	}
	if rr := call(h.clusterInternalIdentityRead, cluster.PublicInternalIdentityReadPath, "x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad read body = %d", rr.Code)
	}
	stateless := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))
	if rr := call(stateless.clusterInternalIdentityWrite, cluster.PublicInternalIdentityWritePath, write); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless write = %d", rr.Code)
	}
	if rr := call(stateless.clusterInternalIdentityRead, cluster.PublicInternalIdentityReadPath, `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless read = %d", rr.Code)
	}
}
