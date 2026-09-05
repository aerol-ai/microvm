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
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

const jsHandlerBody = `export default { async fetch(r) { return new Response("ok"); } };`

func newJSBundleV1TestEnv(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableIsolate: true}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(dir, "bundles")})
	if err != nil {
		t.Fatalf("jsbundle store: %v", err)
	}
	svc.SetIsolateBundleStore(bundleStore)

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return mux
}

func TestV1CreateJSBundle_Success(t *testing.T) {
	h := newJSBundleV1TestEnv(t)
	body, _ := json.Marshal(models.CreateJSBundleRequest{Name: "hook", Source: jsHandlerBody})
	req := httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.JSBundle
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Digest == "" || resp.ModuleRef != "sha256:"+resp.Digest {
		t.Fatalf("resp = %+v, want digest + sha256 ref", resp)
	}
	if resp.Name != "hook" || resp.MainModule != jsbundle.DefaultMainModule {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestV1CreateJSBundleSelectsOneIsolateWorker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	c := &createForwardCluster{
		Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		target: cluster.PlacementTarget{
			NodeID: "isolate-a", InternalURL: "https://isolate-a:21443",
		},
	}
	svc.AttachCluster(c)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	body, _ := json.Marshal(models.CreateJSBundleRequest{Name: "hook", Source: jsHandlerBody})
	rr := httptest.NewRecorder()
	h.createJSBundle(rr, httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body)))

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want forwarded 202", rr.Code)
	}
	if c.forwardedPeer != "https://isolate-a:21443" || len(c.selectRequests) != 1 {
		t.Fatalf("forwarded peer=%q select=%+v", c.forwardedPeer, c.selectRequests)
	}
	if c.selectRequests[0].Runtime != models.RuntimeIsolate {
		t.Fatalf("placement runtime = %q, want isolate", c.selectRequests[0].Runtime)
	}
}

func TestV1GetJSBundleRoutesNodeBoundRefInConstantTime(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	c := &createForwardCluster{
		Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		members: []cluster.Member{{
			NodeID: "isolate-a", InternalURL: "https://isolate-a:21443", Alive: true,
		}},
	}
	svc.AttachCluster(c)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	ref := models.JSBundleRefForNode("sha256:abc", "isolate-a")
	req := httptest.NewRequest(http.MethodGet, "/v1/js-bundles/ignored", nil)
	req.SetPathValue("id", ref)
	rr := httptest.NewRecorder()
	h.getJSBundle(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want forwarded 202", rr.Code)
	}
	if c.forwardedPeer != "https://isolate-a:21443" {
		t.Fatalf("forwarded peer = %q", c.forwardedPeer)
	}
}

func TestValidateClusterIsolateBundleRef(t *testing.T) {
	if err := service.ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "hook",
	}); err == nil {
		t.Fatal("unbound cluster isolate ref was accepted")
	}
	if err := service.ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: models.JSBundleRefForNode("sha256:abc", "isolate-a"),
	}); err != nil {
		t.Fatalf("node-bound cluster isolate ref rejected: %v", err)
	}
	if err := service.ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{
		Runtime: models.RuntimeDocker, Image: "alpine",
	}); err != nil {
		t.Fatalf("non-isolate request rejected: %v", err)
	}
}

func TestV1CreateJSBundle_InvalidJSON(t *testing.T) {
	h := newJSBundleV1TestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader([]byte("{bad")))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestV1CreateJSBundle_BadRequest(t *testing.T) {
	h := newJSBundleV1TestEnv(t)
	// Neither source nor modules → 4xx (service rejects, not a JSON error).
	body, _ := json.Marshal(models.CreateJSBundleRequest{Name: "empty"})
	req := httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code < 400 || rr.Code >= 500 {
		t.Fatalf("status = %d, want a 4xx", rr.Code)
	}
}

func TestV1ListAndGetJSBundle(t *testing.T) {
	h := newJSBundleV1TestEnv(t)
	// Upload one.
	body, _ := json.Marshal(models.CreateJSBundleRequest{Name: "hook", Source: jsHandlerBody})
	postRR := httptest.NewRecorder()
	h.ServeHTTP(postRR, httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body)))
	var created models.JSBundle
	_ = json.NewDecoder(postRR.Body).Decode(&created)

	// List.
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, httptest.NewRequest(http.MethodGet, "/v1/js-bundles", nil))
	if listRR.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRR.Code)
	}
	var list []models.JSBundle
	if err := json.NewDecoder(listRR.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Digest != created.Digest || list[0].Name != "hook" {
		t.Fatalf("list = %+v", list)
	}

	// Get by digest.
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/v1/js-bundles/"+created.Digest, nil))
	if getRR.Code != http.StatusOK {
		t.Fatalf("get status = %d; body=%s", getRR.Code, getRR.Body.String())
	}
	// Unknown digest → 404.
	missRR := httptest.NewRecorder()
	h.ServeHTTP(missRR, httptest.NewRequest(http.MethodGet, "/v1/js-bundles/deadbeef", nil))
	if missRR.Code != http.StatusNotFound {
		t.Fatalf("get miss status = %d, want 404", missRR.Code)
	}
}

func TestV1DeleteJSBundle(t *testing.T) {
	h := newJSBundleV1TestEnv(t)
	body, _ := json.Marshal(models.CreateJSBundleRequest{Source: jsHandlerBody})
	postRR := httptest.NewRecorder()
	h.ServeHTTP(postRR, httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body)))
	var created models.JSBundle
	_ = json.NewDecoder(postRR.Body).Decode(&created)

	delRR := httptest.NewRecorder()
	h.ServeHTTP(delRR, httptest.NewRequest(http.MethodDelete, "/v1/js-bundles/"+created.Digest, nil))
	if delRR.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body=%s", delRR.Code, delRR.Body.String())
	}
	// Now gone.
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, "/v1/js-bundles/"+created.Digest, nil))
	if getRR.Code != http.StatusNotFound {
		t.Fatalf("post-delete get = %d, want 404", getRR.Code)
	}
}
