package v1

import (
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

type createForwardCluster struct {
	*cluster.Noop
	target             cluster.PlacementTarget
	forwardedPeer      string
	forwardedTarget    string
	selectPlacementHit int
}

func (c *createForwardCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	c.selectPlacementHit++
	return c.target, nil
}

func (c *createForwardCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	// Prefer the internal channel for assertion purposes (matches the
	// production preference order) so tests that exercise the mTLS path can
	// also use this stub. Fall back to APIURL when the test didn't populate
	// an internal URL — keeps existing assertions that compare against the
	// public APIURL unchanged.
	if target.InternalURL != "" {
		c.forwardedPeer = target.InternalURL
	} else {
		c.forwardedPeer = target.APIURL
	}
	c.forwardedTarget = r.Header.Get(clusterCreateTargetHeader)
	w.WriteHeader(http.StatusAccepted)
}

func (c *createForwardCluster) AttachInternalHandler(h http.Handler) {}

func TestClusterCreateWrapPinsForwardedCreateToSelectedTarget(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a"),
		target: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if fakeCluster.forwardedPeer != "http://node-b:21212" {
		t.Fatalf("forwarded peer = %q, want node-b API URL", fakeCluster.forwardedPeer)
	}
	if fakeCluster.forwardedTarget != "node-b" {
		t.Fatalf("%s = %q, want node-b", clusterCreateTargetHeader, fakeCluster.forwardedTarget)
	}
	if fakeCluster.selectPlacementHit != 1 {
		t.Fatalf("SelectPlacement calls = %d, want 1", fakeCluster.selectPlacementHit)
	}
}

func TestClusterCreateWrapRejectsCreateForwardedToWrongNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a"),
		target: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	req.Header.Set(clusterCreateTargetHeader, "node-b")
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusMisdirectedRequest)
	}
	if fakeCluster.selectPlacementHit != 0 {
		t.Fatalf("SelectPlacement calls = %d, want 0", fakeCluster.selectPlacementHit)
	}
}

var _ cluster.Client = (*createForwardCluster)(nil)

// ownerOfStubCluster lets a test drive clusterForwardWrap's OwnerOf branch
// without standing up a real raft FSM. The body returns whatever the test
// configured.
type ownerOfStubCluster struct {
	*cluster.Noop
	owner          cluster.OwnerInfo
	err            error
	forwardCalled  bool
	forwardedPeer  string
}

func (c *ownerOfStubCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, c.err
}

func (c *ownerOfStubCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwardCalled = true
	if target.InternalURL != "" {
		c.forwardedPeer = target.InternalURL
	} else {
		c.forwardedPeer = target.APIURL
	}
	w.WriteHeader(http.StatusAccepted)
}

func (c *ownerOfStubCluster) AttachInternalHandler(http.Handler) {}

var _ cluster.Client = (*ownerOfStubCluster)(nil)

// readExpvarInt extracts the current value of an expvar.Int counter by name.
// service.RecordRouteMiss bumps a package-private counter exposed under
// "aerolvm_ingress_route_misses_total"; reading via expvar.Get keeps the
// pkg/api/v1 test boundary clean (no internal/service import for the metric).
func readExpvarInt(t *testing.T, name string) int64 {
	t.Helper()
	v := expvar.Get(name)
	if v == nil {
		t.Fatalf("expvar %q not registered", name)
	}
	got, err := strconv.ParseInt(v.String(), 10, 64)
	if err != nil {
		t.Fatalf("expvar %q value %q parse: %v", name, v.String(), err)
	}
	return got
}

// TestClusterForwardWrapReturns410OnOrphanedPlacement pins the convergence-window
// contract for an orphaned sandbox: when the owning node died and the dead-owner
// reconciler has cleared the placement's OwnerNodeID, every per-sandbox API call
// MUST surface 410 Gone — not 503, not 500. 410 is the "stop retrying, the
// sandbox is permanently gone" signal SDKs and operators key off (see
// docs/src/content/docs/cluster-ingress.mdx and durability.mdx). Without this
// pinned, a future refactor could regress orphan handling to a generic 5xx and
// clients would back off and re-poll instead of issuing a fresh Create.
func TestClusterForwardWrapReturns410OnOrphanedPlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &ownerOfStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a"),
		err:  cluster.ErrOrphaned,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("local handler must not run for an orphaned placement")
	})
	wrapped := h.clusterForwardWrap(local)

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-orphan", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusGone)
	}
	if fake.forwardCalled {
		t.Fatalf("ForwardHTTP called for an orphaned placement; orphans must short-circuit")
	}
	if !strings.Contains(rr.Body.String(), "orphan") {
		t.Fatalf("body = %q, want orphan reason in message", rr.Body.String())
	}
}

// TestClusterForwardWrapReturns503AndBumpsMissCounterOnUnresolvedOwner pins the
// other convergence-window branch: the placement says someone else owns the
// sandbox but gossip hasn't surfaced any forwarding URL yet (mid-rollover, peer
// mid-boot, misconfigured advertise URLs). Contract: 503 ServiceUnavailable AND
// the aerolvm_ingress_route_misses_total counter increments by exactly 1 so
// operator dashboards can spot persistent gossip-convergence lag rather than
// chase sporadic 503s.
func TestClusterForwardWrapReturns503AndBumpsMissCounterOnUnresolvedOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &ownerOfStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a"),
		owner: cluster.OwnerInfo{
			NodeID:      "node-b",
			APIURL:      "",
			InternalURL: "",
			IsSelf:      false,
		},
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("local handler must not run when owner is unknown")
	})
	wrapped := h.clusterForwardWrap(local)

	before := readExpvarInt(t, "aerolvm_ingress_route_misses_total")

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-unresolved", nil)
	req.SetPathValue("id", "sb-unresolved")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if fake.forwardCalled {
		t.Fatalf("ForwardHTTP called with no usable URL; the wrapper must short-circuit")
	}
	if !strings.Contains(rr.Body.String(), "node-b") {
		t.Fatalf("body = %q, want owner node ID in message for operator diagnostics", rr.Body.String())
	}
	if got := readExpvarInt(t, "aerolvm_ingress_route_misses_total") - before; got != 1 {
		t.Fatalf("route-miss counter delta = %d, want 1", got)
	}
}
