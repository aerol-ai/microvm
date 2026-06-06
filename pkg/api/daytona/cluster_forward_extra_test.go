package daytona

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

func TestClusterForwardWrapExtraBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("nil_service", func(t *testing.T) {
		h := newHandlers(Deps{Service: nil})
		localCalled := false
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			localCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if !localCalled || rr.Code != http.StatusOK {
			t.Fatalf("local should be called: code=%d called=%v", rr.Code, localCalled)
		}
	})

	t.Run("nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := newHandlers(Deps{Service: svc})
		localCalled := false
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			localCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if !localCalled || rr.Code != http.StatusOK {
			t.Fatalf("local should be called: code=%d called=%v", rr.Code, localCalled)
		}
	})

	t.Run("unknown_sandbox_different_pathkey", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:     cluster.NewNoop("router", "http://router", ""),
			ownerErr: cluster.ErrUnknownSandbox,
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		localCalled := false
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			localCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("id", "123")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if !localCalled || rr.Code != http.StatusOK {
			t.Fatalf("local should be called: code=%d called=%v", rr.Code, localCalled)
		}
	})

	t.Run("unknown_sandbox_idOrName_both_fail", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:      cluster.NewNoop("router", "http://router", ""),
			ownerErr:  cluster.ErrUnknownSandbox,
			nameErr:   cluster.ErrUnknownSandbox,
			nameID:    "",
			nameOwner: cluster.OwnerInfo{},
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		localCalled := false
		wrapped := h.clusterForwardWrap("idOrName", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			localCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("idOrName", "123")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if !localCalled || rr.Code != http.StatusOK {
			t.Fatalf("local should be called: code=%d called=%v", rr.Code, localCalled)
		}
	})

	t.Run("cluster_other_error", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:     cluster.NewNoop("router", "http://router", ""),
			ownerErr: errors.New("some DB failure"),
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("local should not be called")
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("id", "123")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rr.Code)
		}
	})

	t.Run("owner_is_self", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:  cluster.NewNoop("router", "http://router", ""),
			owner: cluster.OwnerInfo{IsSelf: true},
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		localCalled := false
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			localCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("id", "123")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if !localCalled || rr.Code != http.StatusOK {
			t.Fatalf("local should be called: code=%d called=%v", rr.Code, localCalled)
		}
	})

	t.Run("owner_missing_urls", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:  cluster.NewNoop("router", "http://router", ""),
			owner: cluster.OwnerInfo{IsSelf: false, NodeID: "worker-b", APIURL: "", InternalURL: ""},
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("local should not be called")
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("id", "123")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "owner worker-b URL unknown") {
			t.Fatalf("expected 503 URL unknown, got %d %q", rr.Code, rr.Body.String())
		}
	})

	t.Run("forward_loop_detected", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:  cluster.NewNoop("router", "http://router", ""),
			owner: cluster.OwnerInfo{IsSelf: false, APIURL: "http://worker-a"},
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("local should not be called")
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("id", "123")
		req.Header.Set("X-Cluster-Forwarded", "1")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusMisdirectedRequest {
			t.Fatalf("expected 421, got %d", rr.Code)
		}
	})

	t.Run("forward_using_internal_url", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		fakeCluster := &daytonaOwnerForwardCluster{
			Noop:  cluster.NewNoop("router", "http://router", ""),
			owner: cluster.OwnerInfo{IsSelf: false, InternalURL: "http://worker-a-internal"},
		}
		svc.AttachCluster(fakeCluster)
		h := newHandlers(Deps{Service: svc})
		wrapped := h.clusterForwardWrap("id", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("local should not be called")
		}))
		req := httptest.NewRequest(http.MethodGet, "/sandbox/123", nil)
		req.SetPathValue("id", "123")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("expected 202 from ForwardHTTP, got %d", rr.Code)
		}
		if !fakeCluster.forwarded || fakeCluster.forwardedPeer != "http://worker-a-internal" {
			t.Fatalf("expected forwarded peer to be http://worker-a-internal, got %v / %q", fakeCluster.forwarded, fakeCluster.forwardedPeer)
		}
	})
}
