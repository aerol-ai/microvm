package daytona

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type daytonaForwardCluster struct {
	*cluster.Noop
	target          cluster.PlacementTarget
	reservedID      string
	reservedReq     *models.CreateSandboxRequest
	forwardedTarget string
	forwardedID     string
}

func (c *daytonaForwardCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	return c.target, nil
}

func (c *daytonaForwardCluster) ReserveOnTarget(_ context.Context, sandboxID string, _ cluster.PlacementTarget, redacted *models.CreateSandboxRequest, _ cluster.PlacementSecrets, _ time.Duration) error {
	c.reservedID = sandboxID
	c.reservedReq = redacted
	return nil
}

func (c *daytonaForwardCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwardedTarget = r.Header.Get("X-Cluster-Create-Target")
	c.forwardedID = r.Header.Get("X-Cluster-Create-ID")
	w.WriteHeader(http.StatusAccepted)
}

func (c *daytonaForwardCluster) AttachInternalHandler(http.Handler) {}

func TestCreateSandboxClusterForwardBuildsOnTargetNotRouter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &daytonaForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)
	builder := &fakeImageBuilder{}
	h := newHandlers(Deps{
		Service: svc,
		Logger:  logger,
		Builder: builder,
		Build:   BuildConfig{Timeout: time.Minute},
	})

	body := `{"name":"sdk-build","buildInfo":{"dockerfileContent":"FROM alpine\nRUN echo target"}}`
	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.createSandbox(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if len(builder.builds) != 0 {
		t.Fatalf("router built %d images; build must happen only on selected worker", len(builder.builds))
	}
	if fakeCluster.forwardedTarget != "worker-a" || fakeCluster.forwardedID == "" || fakeCluster.forwardedID != fakeCluster.reservedID {
		t.Fatalf("forward headers target=%q id=%q reserved=%q", fakeCluster.forwardedTarget, fakeCluster.forwardedID, fakeCluster.reservedID)
	}
	if fakeCluster.reservedReq == nil || fakeCluster.reservedReq.Name != "sdk-build" {
		t.Fatalf("reserved request = %+v, want Daytona name carried for cluster-wide uniqueness", fakeCluster.reservedReq)
	}
}

type daytonaOwnerForwardCluster struct {
	*cluster.Noop
	owner         cluster.OwnerInfo
	ownerErr      error
	nameID        string
	nameOwner     cluster.OwnerInfo
	nameErr       error
	forwarded     bool
	forwardedPeer string
}

func (c *daytonaOwnerForwardCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	if c.ownerErr != nil {
		return cluster.OwnerInfo{}, c.ownerErr
	}
	return c.owner, nil
}

func (c *daytonaOwnerForwardCluster) OwnerOfName(string) (string, cluster.OwnerInfo, error) {
	if c.nameErr != nil {
		return "", cluster.OwnerInfo{}, c.nameErr
	}
	return c.nameID, c.nameOwner, nil
}

func (c *daytonaOwnerForwardCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwarded = true
	if target.InternalURL != "" {
		c.forwardedPeer = target.InternalURL
	} else {
		c.forwardedPeer = target.APIURL
	}
	w.WriteHeader(http.StatusAccepted)
}

func TestClusterForwardWrapResolvesDaytonaNameToOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &daytonaOwnerForwardCluster{
		Noop:      cluster.NewNoop("router", "http://router", ""),
		ownerErr:  cluster.ErrUnknownSandbox,
		nameID:    "sb-named",
		nameOwner: cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)
	h := newHandlers(Deps{Service: svc, Logger: logger})

	localCalled := false
	wrapped := h.clusterForwardWrap("idOrName", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/named", nil)
	req.SetPathValue("idOrName", "named")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if localCalled {
		t.Fatal("local handler ran on router; name-owned request must forward to owner")
	}
	if !fakeCluster.forwarded || fakeCluster.forwardedPeer != "http://worker-a:21212" {
		t.Fatalf("forwarded=%v peer=%q, want worker API URL", fakeCluster.forwarded, fakeCluster.forwardedPeer)
	}
}

func TestClusterForwardWrapReturnsGoneForOrphanedDaytonaPlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&daytonaOwnerForwardCluster{
		Noop:     cluster.NewNoop("router", "http://router", ""),
		ownerErr: cluster.ErrOrphaned,
	})
	h := newHandlers(Deps{Service: svc, Logger: logger})

	wrapped := h.clusterForwardWrap("idOrName", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("local handler ran for orphaned placement")
	}))
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/sb-orphan", nil)
	req.SetPathValue("idOrName", "sb-orphan")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, http.StatusGone, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), cluster.ErrOrphaned.Error()) {
		t.Fatalf("body = %q, want orphaned error", rr.Body.String())
	}
}
