package v1

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type createForwardCluster struct {
	*cluster.Noop
	target             cluster.PlacementTarget
	forwardedPeer      string
	forwardedTarget    string
	forwardedCreateID  string
	selectPlacementHit int

	reserveErr      error
	reserveCalls    []reserveCall
	cancelCalls     []string
}

type reserveCall struct {
	sandboxID string
	target    cluster.PlacementTarget
	redacted  *models.CreateSandboxRequest
	sealed    []byte
	ttl       time.Duration
}

func (c *createForwardCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	c.selectPlacementHit++
	return c.target, nil
}

func (c *createForwardCluster) ReserveOnTarget(_ context.Context, sandboxID string, target cluster.PlacementTarget, redacted *models.CreateSandboxRequest, sealed []byte, ttl time.Duration) error {
	c.reserveCalls = append(c.reserveCalls, reserveCall{sandboxID, target, redacted, sealed, ttl})
	return c.reserveErr
}

func (c *createForwardCluster) CancelReservation(_ context.Context, sandboxID string) error {
	c.cancelCalls = append(c.cancelCalls, sandboxID)
	return nil
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
	c.forwardedCreateID = r.Header.Get(clusterCreateIDHeader)
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
	if len(fakeCluster.reserveCalls) != 1 {
		t.Fatalf("ReserveOnTarget calls = %d, want 1 — reservation MUST be written before forwarding (B2)", len(fakeCluster.reserveCalls))
	}
	rc := fakeCluster.reserveCalls[0]
	if rc.sandboxID == "" {
		t.Fatalf("ReserveOnTarget sandboxID empty; router must mint an ID before reserving")
	}
	if rc.target.NodeID != "node-b" {
		t.Fatalf("ReserveOnTarget target = %q, want node-b", rc.target.NodeID)
	}
	if rc.ttl != clusterReservationTTL {
		t.Fatalf("ReserveOnTarget ttl = %v, want %v", rc.ttl, clusterReservationTTL)
	}
	if fakeCluster.forwardedCreateID != rc.sandboxID {
		t.Fatalf("X-Cluster-Create-ID = %q on forward, want %q (must match the reserved ID)", fakeCluster.forwardedCreateID, rc.sandboxID)
	}
	if len(fakeCluster.cancelCalls) != 0 {
		t.Fatalf("CancelReservation called %d times on success; want 0", len(fakeCluster.cancelCalls))
	}
}

// TestClusterCreateWrapReturns503WhenReserveFails pins that a generic
// reservation failure (e.g. raft not-leader, commit timeout) surfaces as 503,
// not 500, so SDK retry policies treat it as a transient cluster issue and try
// a different node rather than giving up. The forward MUST be skipped because
// the cluster has no intent record yet.
func TestClusterCreateWrapReturns503WhenReserveFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a"),
		target:     cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
		reserveErr: errors.New("raft commit timed out"),
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if fakeCluster.forwardedPeer != "" {
		t.Fatalf("ForwardHTTP fired with peer %q; must not forward when reservation failed", fakeCluster.forwardedPeer)
	}
}

// TestClusterCreateWrapReturns409OnReservationNameConflict pins the name-
// collision contract: the reservation step runs validateNameUniqueLocked
// inside the FSM apply, so a duplicate name is rejected before any docker side
// effect and the client gets a deterministic 409 to retry with a different
// name (rather than the 503 used for "cluster degraded, retry as-is").
func TestClusterCreateWrapReturns409OnReservationNameConflict(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a"),
		target:     cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
		reserveErr: cluster.ErrNameConflict,
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine","name":"dupe"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
	if fakeCluster.forwardedPeer != "" {
		t.Fatalf("ForwardHTTP fired; must not forward on name conflict")
	}
}

// TestClusterCreateWrapForwardedRequiresCreateIDHeader pins the contract that
// a forwarded create MUST carry X-Cluster-Create-ID. Without it, the receiving
// target would mint its own ID and the reservation→placed promotion would
// silently desync the FSM from the local sandbox. The 400 fails the forwarder
// fast (a stale router pre-dating the reservation flow) rather than producing
// an orphan reservation that lingers for 120s.
func TestClusterCreateWrapForwardedRequiresCreateIDHeader(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a"),
		target: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	req.Header.Set(clusterCreateTargetHeader, "node-a")
	// no clusterCreateIDHeader
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rr.Body.String(), clusterCreateIDHeader) {
		t.Fatalf("body = %q, want it to mention %s", rr.Body.String(), clusterCreateIDHeader)
	}
	if len(fakeCluster.reserveCalls) != 0 {
		t.Fatalf("ReserveOnTarget called on a forwarded request; the router already reserved")
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

// drainStubCluster captures SetNodeDrainState calls and lets a test seed the
// IsNodeDrained answer + control the error returned (e.g. a not-leader
// condition). *Noop fills in every other Client method so we only override
// the drain surface the handler touches.
type drainStubCluster struct {
	*cluster.Noop
	setCalls    []drainSetCall
	setErr      error
	drainedView map[string]bool
}

type drainSetCall struct {
	nodeID  string
	drained bool
}

func (c *drainStubCluster) SetNodeDrainState(_ context.Context, nodeID string, drained bool) error {
	c.setCalls = append(c.setCalls, drainSetCall{nodeID, drained})
	return c.setErr
}

func (c *drainStubCluster) IsNodeDrained(nodeID string) bool {
	return c.drainedView[nodeID]
}

func (c *drainStubCluster) Members() []cluster.Member {
	return []cluster.Member{
		{NodeID: "node-a", APIURL: "http://node-a", Alive: true},
		{NodeID: "node-b", APIURL: "http://node-b", Alive: true},
	}
}

var _ cluster.Client = (*drainStubCluster)(nil)

// drainTestHandler wires a drainStubCluster into a Service + handlers so the
// drain/uncordon route handlers can be exercised end-to-end without a real
// raft FSM. Returns both so individual tests can inspect the recorded calls.
func drainTestHandler(t *testing.T, stub *drainStubCluster) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

// TestClusterDrainNodeReturns204AndCallsSet pins the happy path: a drain
// request flips the FSM and returns 204 with no body. Without this, a typo in
// the handler-to-client call (e.g. inverted bool) would slip through.
func TestClusterDrainNodeReturns204AndCallsSet(t *testing.T) {
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a")}
	h := drainTestHandler(t, stub)

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/node-b/drain", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterDrainNode(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body=%q)", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	if len(stub.setCalls) != 1 || stub.setCalls[0].nodeID != "node-b" || !stub.setCalls[0].drained {
		t.Fatalf("setCalls = %+v, want one (node-b, true)", stub.setCalls)
	}
}

// TestClusterUncordonNodeReturns204AndCallsSet mirrors the drain test on the
// reverse edge so a future refactor can't silently make uncordon a no-op.
func TestClusterUncordonNodeReturns204AndCallsSet(t *testing.T) {
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a")}
	h := drainTestHandler(t, stub)

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/node-b/uncordon", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterUncordonNode(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body=%q)", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	if len(stub.setCalls) != 1 || stub.setCalls[0].nodeID != "node-b" || stub.setCalls[0].drained {
		t.Fatalf("setCalls = %+v, want one (node-b, false)", stub.setCalls)
	}
}

// TestClusterDrainNodeReturns503OnNotLeader maps the cluster.ErrNotLeader
// sentinel to a 503 so the operator's retry logic stays uniform with the
// leader-forward path elsewhere — a generic 500 would mask a transient
// leadership flip as a hard failure.
func TestClusterDrainNodeReturns503OnNotLeader(t *testing.T) {
	stub := &drainStubCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a"),
		setErr: cluster.ErrNotLeader,
	}
	h := drainTestHandler(t, stub)

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes/node-b/drain", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterDrainNode(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

// TestClusterDrainNodeRejectsEmptyID guards against a router-side bug that
// stripped the {id} segment: the handler must 400 instead of forwarding an
// empty drain to the FSM (which would itself reject it but with worse UX).
func TestClusterDrainNodeRejectsEmptyID(t *testing.T) {
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a")}
	h := drainTestHandler(t, stub)

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes//drain", nil)
	// SetPathValue intentionally NOT called — simulates an upstream routing bug.
	rr := httptest.NewRecorder()
	h.clusterDrainNode(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body=%q)", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	if len(stub.setCalls) != 0 {
		t.Fatalf("setCalls = %+v, want zero — FSM must not see the empty drain", stub.setCalls)
	}
}

// TestClusterMembersIncludesDrainedField asserts the observability surface:
// a drained node shows up with drained=true on the members list so operators
// can confirm the mark landed without a second round trip to a hypothetical
// /drain-state endpoint.
func TestClusterMembersIncludesDrainedField(t *testing.T) {
	stub := &drainStubCluster{
		Noop:        cluster.NewNoop("node-a", "http://node-a"),
		drainedView: map[string]bool{"node-b": true},
	}
	h := drainTestHandler(t, stub)

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/members", nil)
	rr := httptest.NewRecorder()
	h.clusterMembers(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var body struct {
		Members []struct {
			NodeID  string `json:"node_id"`
			Drained bool   `json:"drained,omitempty"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v body=%q", err, rr.Body.String())
	}
	found := false
	for _, m := range body.Members {
		if m.NodeID == "node-b" {
			found = true
			if !m.Drained {
				t.Fatalf("node-b drained flag = false, want true (body=%q)", rr.Body.String())
			}
		}
		if m.NodeID == "node-a" && m.Drained {
			t.Fatalf("node-a should not appear drained (body=%q)", rr.Body.String())
		}
	}
	if !found {
		t.Fatalf("node-b missing from members list: %q", rr.Body.String())
	}
}
