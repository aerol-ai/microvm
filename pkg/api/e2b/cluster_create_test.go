package e2b

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type e2bForwardCluster struct {
	*cluster.Noop
	target          cluster.PlacementTarget
	reservedID      string
	forwardedTarget string
	forwardedID     string
	forwardedBody   []byte
}

func (c *e2bForwardCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	return c.target, nil
}

func (c *e2bForwardCluster) SelectPlacementWithCandidates(capacity.Request) (cluster.PlacementTarget, []cluster.Member, error) {
	return c.target, []cluster.Member{{NodeID: c.target.NodeID, APIURL: c.target.APIURL, Alive: true}}, nil
}

// SelectPlacementForCreate is what the create path calls now. Without it the
// embedded Noop answers and the create never leaves the router.
func (c *e2bForwardCluster) SelectPlacementForCreate(req capacity.Request, sandboxID string, recipientBackups int) (cluster.PlacementTarget, []string, error) {
	target, candidates, err := c.SelectPlacementWithCandidates(req)
	if err != nil {
		return cluster.PlacementTarget{}, nil, err
	}
	if recipientBackups <= 0 {
		return target, nil, nil
	}
	return target, cluster.SelectSecretRecipients(sandboxID, candidates, target.NodeID, recipientBackups), nil
}

func (c *e2bForwardCluster) ReserveOnTarget(_ context.Context, sandboxID string, _ cluster.PlacementTarget, _ *models.CreateSandboxRequest, _ cluster.PlacementSecrets, _ time.Duration) error {
	c.reservedID = sandboxID
	return nil
}

func (c *e2bForwardCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwardedTarget = r.Header.Get("X-Cluster-Create-Target")
	c.forwardedID = r.Header.Get("X-Cluster-Create-ID")
	c.forwardedBody, _ = io.ReadAll(r.Body)
	w.WriteHeader(http.StatusAccepted)
}

func (c *e2bForwardCluster) AttachInternalHandler(http.Handler) {}

func TestCreateSandboxClusterForwardSkipsLocalIdempotencyAndRuntime(t *testing.T) {
	runtime := newFakeE2BRuntime()
	svc, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})
	fakeCluster := &e2bForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)

	body := `{"templateID":"base","metadata":{"team":"sdk"},"timeout":120}`
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	runtime.mu.Lock()
	createHits := runtime.createHits
	runtime.mu.Unlock()
	if createHits != 0 {
		t.Fatalf("router created %d sandboxes; create must happen only on selected worker", createHits)
	}
	if fakeCluster.forwardedTarget != "worker-a" || fakeCluster.forwardedID == "" || fakeCluster.forwardedID != fakeCluster.reservedID {
		t.Fatalf("forward headers target=%q id=%q reserved=%q", fakeCluster.forwardedTarget, fakeCluster.forwardedID, fakeCluster.reservedID)
	}
	// The forwarded request must carry the original E2B wire body (B2).
	if !strings.Contains(string(fakeCluster.forwardedBody), "base") {
		t.Fatalf("forwarded body = %q, want the original E2B create body", fakeCluster.forwardedBody)
	}
}

type e2bOwnerForwardCluster struct {
	*cluster.Noop
	owner         cluster.OwnerInfo
	ownerErr      error
	forwarded     bool
	forwardedPeer string
}

func (c *e2bOwnerForwardCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	if c.ownerErr != nil {
		return cluster.OwnerInfo{}, c.ownerErr
	}
	return c.owner, nil
}

func (c *e2bOwnerForwardCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwarded = true
	if target.InternalURL != "" {
		c.forwardedPeer = target.InternalURL
	} else {
		c.forwardedPeer = target.APIURL
	}
	w.WriteHeader(http.StatusAccepted)
}

func TestClusterForwardWrapForwardsE2BSandboxOperationsToOwner(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	fakeCluster := &e2bOwnerForwardCluster{
		Noop:  cluster.NewNoop("router", "http://router", ""),
		owner: cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)
	h := newHandlers(Deps{Service: svc})

	localCalled := false
	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/sb-remote/pause", nil)
	req.SetPathValue("id", "sb-remote")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if localCalled {
		t.Fatal("local handler ran on router; owner-owned request must forward")
	}
	if !fakeCluster.forwarded || fakeCluster.forwardedPeer != "http://worker-a:21212" {
		t.Fatalf("forwarded=%v peer=%q, want worker API URL", fakeCluster.forwarded, fakeCluster.forwardedPeer)
	}
}

func TestClusterForwardWrapReturnsGoneForOrphanedE2BPlacement(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	svc.AttachCluster(&e2bOwnerForwardCluster{
		Noop:     cluster.NewNoop("router", "http://router", ""),
		ownerErr: cluster.ErrOrphaned,
	})
	h := newHandlers(Deps{Service: svc})

	wrapped := h.clusterForwardWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("local handler ran for orphaned placement")
	}))
	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes/sb-orphan", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, http.StatusGone, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "placement orphaned") {
		t.Fatalf("body = %q, want orphaned error", rr.Body.String())
	}
}

// /e2b/runtime carries its sandbox id in a header, so it must forward to the
// owner node by that header (plan B5); before, a non-owner node answered 404
// from its local store.
func TestE2BRuntimeForwardsToOwnerByHeader(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	fakeCluster := &e2bOwnerForwardCluster{
		Noop:  cluster.NewNoop("router", "http://router", ""),
		owner: cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)

	req := httptest.NewRequest(http.MethodGet, "/e2b/runtime/process", nil)
	req.Header.Set("E2b-Sandbox-Id", "sb-remote")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !fakeCluster.forwarded {
		t.Fatalf("runtime call was not forwarded to the owner; status %d", rr.Code)
	}
	if rr.Code == http.StatusNotFound {
		t.Fatal("runtime call 404'd on a non-owner node instead of forwarding")
	}
}
