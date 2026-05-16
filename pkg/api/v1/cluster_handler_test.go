package v1

import (
	"encoding/json"
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

// placementOfStubCluster lets a test populate both OwnerOf and PlacementOf so
// the convergence-status branch of clusterPlacement can be driven without a
// real FSM. *Noop already provides every other Client method.
type placementOfStubCluster struct {
	*cluster.Noop
	owner     cluster.OwnerInfo
	ownerErr  error
	placement cluster.Placement
	hasPlace  bool
}

func (c *placementOfStubCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, c.ownerErr
}

func (c *placementOfStubCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlace
}

var _ cluster.Client = (*placementOfStubCluster)(nil)

// decodePlacementResponse parses the /v1/cluster/placements/{id} body into the
// fields the tests assert on. Tests use map[string]any rather than the
// handler's internal struct so a future field-name change in the handler
// would surface as a test failure rather than be silently re-tracked.
func decodePlacementResponse(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response: %v body=%q", err, string(body))
	}
	return got
}

// TestClusterPlacementConvergedWhenOwnerIsSelf pins the headline branch: when
// the local node owns the sandbox, exposePort installed the Caddy route
// synchronously, so the response MUST report converged=true regardless of
// what the reconciler's installed-version high-water mark says. Without this,
// a freshly-booted owner could read converged=false on its own sandbox while
// the cluster-ingress reconciler is still catching up to FSM applies for
// OTHER sandboxes — a confusing operator signal.
func TestClusterPlacementConvergedWhenOwnerIsSelf(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &placementOfStubCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a"),
		owner: cluster.OwnerInfo{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
		placement: cluster.Placement{
			SandboxID:   "sb-self",
			OwnerNodeID: "node-a",
			Version:     42,
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				5432: {Protocol: "tcp", HostPort: 40123, PublicURL: "tcp://lb.example.com:40123"},
			},
		},
		hasPlace: true,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/placements/sb-self", nil)
	req.SetPathValue("id", "sb-self")
	rr := httptest.NewRecorder()
	h.clusterPlacement(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	got := decodePlacementResponse(t, rr.Body.Bytes())
	if got["converged"] != true {
		t.Fatalf("converged = %v, want true for owner-self", got["converged"])
	}
	if pv, ok := got["placement_version"].(float64); !ok || uint64(pv) != 42 {
		t.Fatalf("placement_version = %v, want 42", got["placement_version"])
	}
	owner, _ := got["owner"].(map[string]any)
	if owner == nil || owner["is_self"] != true || owner["node_id"] != "node-a" {
		t.Fatalf("owner = %+v, want is_self=true node_id=node-a", owner)
	}
	ports, _ := got["exposed_ports"].(map[string]any)
	if ports == nil || ports["5432"] == nil {
		t.Fatalf("exposed_ports = %+v, want a 5432 entry", got["exposed_ports"])
	}
}

// TestClusterPlacementNotConvergedWhenInstalledVersionTrailsPlacement pins the
// B6 status-surface contract: a non-owner ingress node whose reconciler hasn't
// installed routes up to the placement's Version MUST report converged=false.
// Operators key off this to spot stuck reconcilers per-sandbox instead of
// inferring from aerolvm_ingress_route_lag_versions alone (which is a node-
// wide aggregate that can't pinpoint which sandbox is affected).
func TestClusterPlacementNotConvergedWhenInstalledVersionTrailsPlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &placementOfStubCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a"),
		owner: cluster.OwnerInfo{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
		placement: cluster.Placement{
			SandboxID:   "sb-lagging",
			OwnerNodeID: "node-b",
			OwnerAPIURL: "http://node-b:21212",
			Version:     uint64(readExpvarInt(t, "aerolvm_ingress_placement_version_max")) + 1_000_000,
		},
		hasPlace: true,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/placements/sb-lagging", nil)
	req.SetPathValue("id", "sb-lagging")
	rr := httptest.NewRecorder()
	h.clusterPlacement(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	got := decodePlacementResponse(t, rr.Body.Bytes())
	if got["converged"] != false {
		t.Fatalf("converged = %v, want false for trailing installed_version", got["converged"])
	}
	pv, _ := got["placement_version"].(float64)
	niv, _ := got["node_installed_version"].(float64)
	if uint64(pv) <= uint64(niv) {
		t.Fatalf("placement_version (%v) must exceed node_installed_version (%v) for this test to be meaningful",
			pv, niv)
	}
	owner, _ := got["owner"].(map[string]any)
	if owner == nil || owner["is_self"] != false || owner["node_id"] != "node-b" {
		t.Fatalf("owner = %+v, want is_self=false node_id=node-b", owner)
	}
}

// TestClusterPlacementReturnsOrphanedFlag pins that the orphaned branch keeps
// the same enriched envelope rather than the old ad-hoc {orphaned:true,...}
// shape — operator scripts can always read `converged` / `exposed_ports` /
// `placement_version` without special-casing orphaned vs live placements.
func TestClusterPlacementReturnsOrphanedFlag(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &placementOfStubCluster{
		Noop:     cluster.NewNoop("node-a", "http://node-a"),
		ownerErr: cluster.ErrOrphaned,
		placement: cluster.Placement{
			SandboxID:   "sb-orphan",
			OwnerNodeID: "",
			Version:     7,
		},
		hasPlace: true,
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/placements/sb-orphan", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterPlacement(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	got := decodePlacementResponse(t, rr.Body.Bytes())
	if got["orphaned"] != true {
		t.Fatalf("orphaned = %v, want true", got["orphaned"])
	}
	owner, _ := got["owner"].(map[string]any)
	if owner == nil || owner["node_id"] != "" || owner["is_self"] != false {
		t.Fatalf("owner = %+v, want empty node_id for orphan", owner)
	}
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
