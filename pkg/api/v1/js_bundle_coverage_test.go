package v1

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateJSBundlePlacementAndForwardBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	body := `{"name":"hook","source":"export default { async fetch(){ return new Response('ok'); } };"}`

	t.Run("no_placement_target", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, EnableIsolate: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&createForwardCluster{
			Noop:      cluster.NewNoop("ingress-a", "http://ingress-a", ""),
			selectErr: cluster.ErrNoPlacementTarget,
		})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.createJSBundle(rr, httptest.NewRequest(http.MethodPost, "/v1/js-bundles", strings.NewReader(body)))
		if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
			t.Fatalf("status=%d retry=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
		}
	})

	t.Run("other_placement_error", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, EnableIsolate: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&createForwardCluster{
			Noop:      cluster.NewNoop("ingress-a", "http://ingress-a", ""),
			selectErr: errors.New("raft down"),
		})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.createJSBundle(rr, httptest.NewRequest(http.MethodPost, "/v1/js-bundles", strings.NewReader(body)))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("self_placement_uses_local", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		svc := service.New(config.Config{EnableCluster: true, EnableIsolate: true}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
		bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(dir, "bundles")})
		if err != nil {
			t.Fatalf("jsbundle: %v", err)
		}
		svc.SetIsolateBundleStore(bundleStore)
		svc.AttachCluster(&createForwardCluster{
			Noop:   cluster.NewNoop("worker-a", "http://worker-a", ""),
			target: cluster.PlacementTarget{NodeID: "worker-a", IsSelf: true},
		})
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.createJSBundle(rr, httptest.NewRequest(http.MethodPost, "/v1/js-bundles", strings.NewReader(body)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("self placement status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bound_ref_self_and_unavailable", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := &createForwardCluster{
			Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
			members: []cluster.Member{
				{NodeID: "dead-a", Alive: false, InternalURL: "https://dead"},
			},
		}
		svc.AttachCluster(c)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}

		selfRef := models.JSBundleRefForNode("sha256:abc", "ingress-a")
		selfReq := httptest.NewRequest(http.MethodGet, "/v1/js-bundles/"+selfRef, nil)
		selfReq.SetPathValue("id", selfRef)
		if h.forwardBoundJSBundle(httptest.NewRecorder(), selfReq) {
			t.Fatal("self-bound ref must stay local")
		}

		deadRef := models.JSBundleRefForNode("sha256:abc", "dead-a")
		deadReq := httptest.NewRequest(http.MethodDelete, "/v1/js-bundles/"+deadRef, nil)
		deadReq.SetPathValue("id", deadRef)
		deadRR := httptest.NewRecorder()
		h.deleteJSBundle(deadRR, deadReq)
		if deadRR.Code != http.StatusServiceUnavailable {
			t.Fatalf("dead owner status = %d", deadRR.Code)
		}

		plain := httptest.NewRequest(http.MethodGet, "/v1/js-bundles/sha256:abc", nil)
		plain.SetPathValue("id", "sha256:abc")
		if h.forwardBoundJSBundle(httptest.NewRecorder(), plain) {
			t.Fatal("unbound digest must not forward")
		}
	})
}

// noLookupClient embeds the Client interface so LookupMember is not promoted
// from *cluster.Noop — the type assertion in forwardBoundJSBundle must fail.
// noLookupClient embeds the Client interface so LookupMember is not promoted
// from *cluster.Noop — the type assertion in forwardBoundJSBundle must fail.
type noLookupClient struct{ cluster.Client }

func TestForwardBoundJSBundleLookupUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&noLookupClient{Client: cluster.NewNoop("ingress-a", "http://ingress-a", "")})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	ref := models.JSBundleRefForNode("sha256:abc", "worker-b")
	req := httptest.NewRequest(http.MethodGet, "/v1/js-bundles/"+ref, nil)
	req.SetPathValue("id", ref)
	rr := httptest.NewRecorder()
	if !h.forwardBoundJSBundle(rr, req) || rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("lookup unavailable status=%d forwarded=%v", rr.Code, rr.Code != 0)
	}
}

func TestListAndDeleteJSBundleStoreErrors(t *testing.T) {
	_ = newJSBundleV1TestEnv(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	_ = st.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableIsolate: true}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	handler := &handlers{deps: Deps{Service: svc, Logger: logger}}

	listRR := httptest.NewRecorder()
	handler.listJSBundles(listRR, httptest.NewRequest(http.MethodGet, "/v1/js-bundles", nil))
	if listRR.Code == http.StatusOK {
		t.Fatal("expected list failure with closed store")
	}

	delRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/js-bundles/deadbeef", nil)
	req.SetPathValue("id", "deadbeef")
	handler.deleteJSBundle(delRR, req)
	if delRR.Code == http.StatusNoContent {
		t.Fatal("expected delete failure with closed store")
	}
}
