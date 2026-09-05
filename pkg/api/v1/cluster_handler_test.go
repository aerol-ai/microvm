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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type createForwardCluster struct {
	*cluster.Noop
	target             cluster.PlacementTarget
	forwardedPeer      string
	forwardedTarget    string
	forwardedCreateID  string
	forwardedBody      string
	selectPlacementHit int
	selectRequests     []capacity.Request
	selectErr          error

	reserveErr   error
	reserveCalls []reserveCall
	cancelCalls  []string
	members      []cluster.Member
	drained      map[string]bool
}

type reserveCall struct {
	sandboxID string
	target    cluster.PlacementTarget
	redacted  *models.CreateSandboxRequest
	secrets   cluster.PlacementSecrets
	ttl       time.Duration
}

func (c *createForwardCluster) SelectPlacement(req capacity.Request) (cluster.PlacementTarget, error) {
	target, _, err := c.SelectPlacementWithCandidates(req)
	return target, err
}

func (c *createForwardCluster) SelectPlacementWithCandidates(req capacity.Request) (cluster.PlacementTarget, []cluster.Member, error) {
	c.selectPlacementHit++
	c.selectRequests = append(c.selectRequests, req)
	if c.selectErr != nil {
		return cluster.PlacementTarget{}, nil, c.selectErr
	}
	cands := c.members
	if len(cands) == 0 {
		cands = []cluster.Member{{NodeID: c.target.NodeID, APIURL: c.target.APIURL, Alive: true}}
	}
	return c.target, cands, nil
}

func (c *createForwardCluster) ReserveOnTarget(_ context.Context, sandboxID string, target cluster.PlacementTarget, redacted *models.CreateSandboxRequest, secrets cluster.PlacementSecrets, ttl time.Duration) error {
	c.reserveCalls = append(c.reserveCalls, reserveCall{sandboxID, target, redacted, secrets, ttl})
	return c.reserveErr
}

func (c *createForwardCluster) CancelReservation(_ context.Context, sandboxID string) error {
	c.cancelCalls = append(c.cancelCalls, sandboxID)
	return nil
}

func (c *createForwardCluster) Members() []cluster.Member {
	if c.members != nil {
		return c.members
	}
	return c.Noop.Members()
}

func (c *createForwardCluster) LookupMember(nodeID string) (cluster.Member, bool) {
	for _, member := range c.Members() {
		if member.NodeID == nodeID {
			return member, true
		}
	}
	return cluster.Member{}, false
}

func (c *createForwardCluster) IsNodeDrained(nodeID string) bool {
	return c.drained != nil && c.drained[nodeID]
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
	if body, err := io.ReadAll(r.Body); err == nil {
		c.forwardedBody = string(body)
	}
	w.WriteHeader(http.StatusAccepted)
}

func (c *createForwardCluster) AttachInternalHandler(h http.Handler) {}

func TestClusterCreateWrapPinsForwardedCreateToSelectedTarget(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
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

func TestClusterCreateWrapTemplateIDImpliesFirecrackerPlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-fc", APIURL: "http://worker-fc:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine","disk_gb":2,"overlay_size_gb":8,"template_id":" tpl-fc "}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if len(fakeCluster.selectRequests) != 1 {
		t.Fatalf("SelectPlacement requests = %d, want 1", len(fakeCluster.selectRequests))
	}
	got := fakeCluster.selectRequests[0]
	if got.Runtime != models.RuntimeFirecracker || got.TemplateID != "tpl-fc" || got.DiskGB != 10 {
		t.Fatalf("placement request = %+v, want runtime=firecracker template_id=tpl-fc disk_gb=10", got)
	}
	if len(fakeCluster.reserveCalls) != 1 || fakeCluster.reserveCalls[0].redacted == nil {
		t.Fatalf("ReserveOnTarget calls = %+v, want redacted spec", fakeCluster.reserveCalls)
	}
	redacted := fakeCluster.reserveCalls[0].redacted
	if redacted.Runtime != models.RuntimeFirecracker || redacted.TemplateID != "tpl-fc" {
		t.Fatalf("reserved spec runtime/template = %q/%q, want firecracker/tpl-fc", redacted.Runtime, redacted.TemplateID)
	}
}

func TestCapacityRequestFromCreateIncludesWasmModuleRef(t *testing.T) {
	got := capacityRequestFromCreate(models.CreateSandboxRequest{
		Runtime:   models.RuntimeWasm,
		ModuleRef: "python",
		MemoryMB:  128,
	})

	if got.Runtime != models.RuntimeWasm || got.ModuleRef != "python" {
		t.Fatalf("placement runtime/module = %q/%q, want wasm/python", got.Runtime, got.ModuleRef)
	}
	if got.MemoryMB != 136 {
		t.Fatalf("placement MemoryMB = %d, want request memory plus wasm overhead", got.MemoryMB)
	}
}

func TestCapacityRequestFromCreateTreatsBuiltImagesAsDocker(t *testing.T) {
	got := capacityRequestFromCreate(models.CreateSandboxRequest{Image: docker.BuiltImageNamespace + "/abc:latest"})
	if got.Runtime != models.RuntimeDocker {
		t.Fatalf("placement Runtime = %q, want docker for built local image", got.Runtime)
	}
}

func TestCapacityRequestFromCreatePinsNodeBoundIsolateBundle(t *testing.T) {
	ref := models.JSBundleRefForNode("sha256:abc", "isolate-a")
	got := capacityRequestFromCreate(models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: ref})
	if got.RequiredNodeID != "isolate-a" {
		t.Fatalf("RequiredNodeID = %q, want isolate-a", got.RequiredNodeID)
	}
}

func TestNormalizeCreateRuntimeForPlacementPreservesHostDefault(t *testing.T) {
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	if err := normalizeCreateRuntimeForPlacement(&req); err != nil {
		t.Fatalf("normalizeCreateRuntimeForPlacement: %v", err)
	}
	if req.Runtime != "" {
		t.Fatalf("Runtime = %q, want empty so the selected worker applies its configured default", req.Runtime)
	}
	// The two halves of the gvisor-by-default design must hold together: the
	// forwarded runtime stays empty (above) AND placement still filters by docker
	// (here). A "fix" that drops both defaults would reintroduce the misrouting
	// bug — an omitted-runtime create scoring onto a wasm/firecracker-only
	// worker. A gvisor node advertises "docker" too, so docker filtering keeps the
	// create on a container-capable worker without forcing its runtime.
	if got := capacityRequestFromCreate(req); got.Runtime != models.RuntimeDocker {
		t.Fatalf("placement filter runtime = %q, want docker", got.Runtime)
	}
}

func TestClusterCreateWrapRejectsTemplateIDWithDockerRuntimeBeforePlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-a", APIURL: "http://worker-a:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine","runtime":"docker","template_id":"tpl-fc"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if fakeCluster.selectPlacementHit != 0 {
		t.Fatalf("SelectPlacement calls = %d, want 0", fakeCluster.selectPlacementHit)
	}
	if len(fakeCluster.reserveCalls) != 0 {
		t.Fatalf("ReserveOnTarget calls = %d, want 0", len(fakeCluster.reserveCalls))
	}
	if !strings.Contains(rr.Body.String(), "template_id requires runtime") {
		t.Fatalf("body = %q, want template_id runtime validation", rr.Body.String())
	}
}

func TestClusterCreateWrapForwardsUnspecifiedRuntimeUnchanged(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-gvisor", APIURL: "http://worker-gvisor:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if len(fakeCluster.selectRequests) != 1 || fakeCluster.selectRequests[0].Runtime != models.RuntimeDocker {
		t.Fatalf("placement request = %+v, want docker filter for omitted runtime", fakeCluster.selectRequests)
	}
	var forwarded models.CreateSandboxRequest
	if err := json.Unmarshal([]byte(fakeCluster.forwardedBody), &forwarded); err != nil {
		t.Fatalf("decode forwarded body %q: %v", fakeCluster.forwardedBody, err)
	}
	if forwarded.Runtime != "" {
		t.Fatalf("forwarded Runtime = %q, want empty so worker default is preserved", forwarded.Runtime)
	}
}

func TestClusterCreateWrapDoesNotPutSecretPayloadInRouterReservation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Deliberately no cipher/store on this router service: a cross-node
	// router must be able to reserve and forward without sealing/storing
	// another worker's secret material locally.
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-a", APIURL: "http://worker-a:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	body := `{"image":"private.example.com/app:latest","registry":{"server":"private.example.com","username":"u","password":"super-secret-password"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if len(fakeCluster.reserveCalls) != 1 {
		t.Fatalf("ReserveOnTarget calls = %d, want 1", len(fakeCluster.reserveCalls))
	}
	rc := fakeCluster.reserveCalls[0]
	if rc.redacted == nil || rc.redacted.Registry == nil {
		t.Fatalf("redacted spec missing registry metadata: %+v", rc.redacted)
	}
	if rc.redacted.Registry.Password != "" {
		t.Fatalf("router reservation leaked registry password: %+v", rc.redacted.Registry)
	}
	if rc.redacted.Registry.Server != "private.example.com" || rc.redacted.Registry.Username != "u" {
		t.Fatalf("router reservation lost non-secret registry fields: %+v", rc.redacted.Registry)
	}
	if rc.secrets.Ref != "" || rc.secrets.Version != 0 {
		t.Fatalf("router reservation carried secret handle/payload: %+v", rc.secrets)
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
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
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
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
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

func TestClusterCreateWrapReturns429OnCreateBackpressure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
		target:     cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
		reserveErr: cluster.ErrCreateBackpressure,
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
	if got := rr.Header().Get("Retry-After"); got != strconv.Itoa(cluster.CreateBackpressureRetryAfterSeconds) {
		t.Fatalf("Retry-After = %q, want %d", got, cluster.CreateBackpressureRetryAfterSeconds)
	}
	if fakeCluster.forwardedPeer != "" {
		t.Fatalf("ForwardHTTP fired; must not forward on create backpressure")
	}
}

func TestClusterCreateWrapReturns503WhenNoWorkerCanOwnSandbox(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		selectErr: cluster.ErrNoPlacementTarget,
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if len(fakeCluster.reserveCalls) != 0 {
		t.Fatalf("ReserveOnTarget calls = %d, want 0 when no worker target exists", len(fakeCluster.reserveCalls))
	}
	if fakeCluster.forwardedPeer != "" {
		t.Fatalf("ForwardHTTP fired with peer %q; must not forward without a worker target", fakeCluster.forwardedPeer)
	}
}

func TestClusterCreateWrapKeepsLocalOnlyImagesOnReceivingNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
		target: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	body := `{"image":"e2b/sb-local:default","image_distribution_mode":"local_only"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if fakeCluster.selectPlacementHit != 0 {
		t.Fatalf("SelectPlacement calls = %d, want 0 for local-only image", fakeCluster.selectPlacementHit)
	}
	if len(fakeCluster.reserveCalls) != 0 {
		t.Fatalf("ReserveOnTarget calls = %d, want 0 for local-only image", len(fakeCluster.reserveCalls))
	}
	if fakeCluster.forwardedPeer != "" {
		t.Fatalf("ForwardHTTP fired with peer %q; local-only image must not be forwarded", fakeCluster.forwardedPeer)
	}
}

func TestClusterCreateWrapRoutesLocalOnlyImageOffNonWorkerNode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
		target: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b:21212", IsSelf: false},
		members: []cluster.Member{
			{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
			{NodeID: "worker-b", APIURL: "http://worker-b:21212", Alive: true, Role: config.NodeRoleWorker},
		},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	body := `{"image":"` + docker.BuiltImageNamespace + `/abc:latest"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if fakeCluster.selectPlacementHit != 1 {
		t.Fatalf("SelectPlacement calls = %d, want 1", fakeCluster.selectPlacementHit)
	}
	if fakeCluster.forwardedPeer != "http://worker-b:21212" {
		t.Fatalf("forwarded peer = %q, want worker-b", fakeCluster.forwardedPeer)
	}
	if fakeCluster.forwardedTarget != "worker-b" {
		t.Fatalf("%s = %q, want worker-b", clusterCreateTargetHeader, fakeCluster.forwardedTarget)
	}
	if fakeCluster.forwardedCreateID != "" {
		t.Fatalf("%s = %q, want empty for local-only image forward", clusterCreateIDHeader, fakeCluster.forwardedCreateID)
	}
	if len(fakeCluster.reserveCalls) != 0 {
		t.Fatalf("ReserveOnTarget calls = %d, want 0 for local-only image", len(fakeCluster.reserveCalls))
	}
	if len(fakeCluster.selectRequests) != 1 || fakeCluster.selectRequests[0].Runtime != models.RuntimeDocker {
		t.Fatalf("placement request = %+v, want docker runtime", fakeCluster.selectRequests)
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
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
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
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
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

type membersStubCluster struct {
	*cluster.Noop
	members        []cluster.Member
	internalClient *http.Client
	placement      cluster.PlacementTarget
	placementErr   error
}

func (c *membersStubCluster) Members() []cluster.Member {
	return c.members
}

func (c *membersStubCluster) PeerInternalHTTPClient() *http.Client {
	in := c.internalClient
	if in == nil {
		in = http.DefaultClient
	}
	return in
}

func (c *membersStubCluster) ClientForPeer(string) *http.Client { return c.PeerInternalHTTPClient() }

func (c *membersStubCluster) SelectPlacement(req capacity.Request) (cluster.PlacementTarget, error) {
	target, _, err := c.SelectPlacementWithCandidates(req)
	return target, err
}

func (c *membersStubCluster) SelectPlacementWithCandidates(req capacity.Request) (cluster.PlacementTarget, []cluster.Member, error) {
	if c.placementErr != nil {
		return cluster.PlacementTarget{}, nil, c.placementErr
	}
	if c.placement.NodeID != "" {
		return c.placement, append([]cluster.Member(nil), c.members...), nil
	}
	return c.Noop.SelectPlacementWithCandidates(req)
}

func (c *membersStubCluster) PeerDialMember(m cluster.Member) (*http.Client, string, error) {
	if c.internalClient == nil || strings.TrimSpace(m.InternalURL) == "" {
		return nil, "", cluster.ErrPeerInternalURLRequired
	}
	return c.internalClient, m.InternalURL, nil
}

var _ cluster.Client = (*membersStubCluster)(nil)

func TestClusterListWrapUsesPlacementOwnersAtEnterpriseScale(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	members := []cluster.Member{
		{NodeID: "node-a", APIURL: "http://node-a:21212", Alive: true, Role: config.NodeRoleMixed},
	}
	for i := 0; i < clusterListMaxFanoutPeers+1; i++ {
		members = append(members, cluster.Member{
			NodeID: "worker-" + strconv.Itoa(i),
			APIURL: "http://worker-" + strconv.Itoa(i) + ":21212",
			Alive:  true,
			Role:   config.NodeRoleWorker,
		})
	}
	svc.AttachCluster(&membersStubCluster{
		Noop:    cluster.NewNoop("node-a", "http://node-a:21212", ""),
		members: members,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	rr := httptest.NewRecorder()
	h.clusterListWrap(rr, req)

	// No placement view on a large fleet ⇒ 503 Retry-After (never a local-only
	// 200 that looks complete). Operators use sandbox-index for fleet scans.
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d body=%q", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q, want 1", rr.Header().Get("Retry-After"))
	}
	if !strings.Contains(rr.Body.String(), "placement view is not ready") {
		t.Fatalf("body = %q, want placement view not ready", rr.Body.String())
	}
}

func TestClusterIngressRouteReturnsReplicatedOwnersForSmallIngressTier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	members := []cluster.Member{
		{NodeID: "worker-a", APIURL: "http://worker-a:21212", DataPlaneHost: "worker-a.internal", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "ing-b", APIURL: "http://ing-b:21212", InternalURL: "https://ing-b.internal:21213", DataPlaneHost: "ing-b.internal", Alive: true, Role: config.NodeRoleIngress},
		{NodeID: "ing-a", APIURL: "http://ing-a:21212", InternalURL: "https://ing-a.internal:21213", DataPlaneHost: "ing-a.internal", Alive: true, Role: config.NodeRoleIngress},
		{NodeID: "ing-dead", APIURL: "http://ing-dead:21212", DataPlaneHost: "ing-dead.internal", Alive: false, Role: config.NodeRoleIngress},
	}
	svc.AttachCluster(&membersStubCluster{
		Noop:    cluster.NewNoop("ing-a", "http://ing-a:21212", ""),
		members: members,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/ingress-route/sb-route", nil)
	req.SetPathValue("id", "sb-route")
	rr := httptest.NewRecorder()
	h.clusterIngressRoute(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rr.Code, rr.Body.String())
	}
	var got cluster.IngressShardRoute
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v body=%q", err, rr.Body.String())
	}
	wantShard := cluster.PlacementShardForSandbox("sb-route", cluster.DefaultPlacementShardCount)
	if got.SandboxID != "sb-route" || got.Shard != wantShard || got.ShardCount != cluster.DefaultPlacementShardCount {
		t.Fatalf("route = %+v, want sandbox_id=sb-route shard=%d shard_count=%d", got, wantShard, cluster.DefaultPlacementShardCount)
	}
	if len(got.Owners) != 2 || got.Owners[0].NodeID != "ing-a" || got.Owners[1].NodeID != "ing-b" {
		t.Fatalf("owners = %+v, want replicated owners ing-a and ing-b", got.Owners)
	}
	if got.Owners[0].DataPlaneHost == "" || got.Owners[0].APIURL == "" || got.Owners[0].InternalURL == "" {
		t.Fatalf("owner = %+v, want route targets populated for upstream routers", got.Owners[0])
	}
}

// ownerOfStubCluster lets a test drive clusterForwardWrap's OwnerOf branch
// without standing up a real raft FSM. The body returns whatever the test
// configured.
type ownerOfStubCluster struct {
	*cluster.Noop
	owner         cluster.OwnerInfo
	err           error
	forwardCalled bool
	forwardedPeer string
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
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
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
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
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
		Noop:     cluster.NewNoop("node-a", "http://node-a", ""),
		ownerErr: cluster.ErrOrphaned,
		placement: cluster.Placement{
			SandboxID:           "sb-orphan",
			OwnerNodeID:         "",
			OwnerState:          cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-dead",
			OrphanedUnix:        99,
			Version:             7,
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
	if got["owner_state"] != string(cluster.PlacementOwnerStateOrphaned) || got["orphaned_owner_node_id"] != "node-dead" {
		t.Fatalf("orphan metadata = owner_state:%v orphaned_owner_node_id:%v", got["owner_state"], got["orphaned_owner_node_id"])
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
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
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
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
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
	removeCalls []removeMemberCall
	removeErr   error
	drainedView map[string]bool
}

type drainSetCall struct {
	nodeID  string
	drained bool
}

type removeMemberCall struct {
	nodeID string
	force  bool
}

func (c *drainStubCluster) SetNodeDrainState(_ context.Context, nodeID string, drained bool) error {
	c.setCalls = append(c.setCalls, drainSetCall{nodeID, drained})
	return c.setErr
}

func (c *drainStubCluster) RemoveMember(_ context.Context, nodeID string, force bool) error {
	c.removeCalls = append(c.removeCalls, removeMemberCall{nodeID: nodeID, force: force})
	return c.removeErr
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
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
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
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
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
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
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
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
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

func TestClusterRemoveMemberReturns204AndCallsRemove(t *testing.T) {
	stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h := drainTestHandler(t, stub)

	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/members/node-b?force=true", nil)
	req.SetPathValue("id", "node-b")
	rr := httptest.NewRecorder()
	h.clusterRemoveMember(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body=%q)", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	if len(stub.removeCalls) != 1 || stub.removeCalls[0].nodeID != "node-b" || !stub.removeCalls[0].force {
		t.Fatalf("removeCalls = %+v, want one forced node-b removal", stub.removeCalls)
	}
}

func TestClusterRemoveMemberMapsLifecycleErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "not leader", err: cluster.ErrNotLeader, want: http.StatusServiceUnavailable},
		{name: "unknown", err: cluster.ErrUnknownMember, want: http.StatusNotFound},
		{name: "alive", err: cluster.ErrMemberStillAlive, want: http.StatusConflict},
		{name: "last voter", err: cluster.ErrLastVoter, want: http.StatusConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", ""), removeErr: tc.err}
			h := drainTestHandler(t, stub)

			req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/members/node-b", nil)
			req.SetPathValue("id", "node-b")
			rr := httptest.NewRecorder()
			h.clusterRemoveMember(rr, req)

			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%q)", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

type orphanOpsStubCluster struct {
	*cluster.Noop
	placement   cluster.Placement
	hasPlace    bool
	claimCalls  []string
	claimErr    error
	deleteCalls []string
	deleteErr   error
}

func (c *orphanOpsStubCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.hasPlace
}

func (c *orphanOpsStubCluster) ClaimOrphan(_ context.Context, sandboxID string, _ *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	c.claimCalls = append(c.claimCalls, sandboxID)
	return c.claimErr
}

func (c *orphanOpsStubCluster) DeletePlacement(_ context.Context, sandboxID string) error {
	c.deleteCalls = append(c.deleteCalls, sandboxID)
	return c.deleteErr
}

var _ cluster.Client = (*orphanOpsStubCluster)(nil)

func newOrphanOpsService(t *testing.T, stub *orphanOpsStubCluster, seedLocal bool) (*handlers, func()) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if seedLocal {
		now := time.Now().UTC()
		if err := st.Create(context.Background(), &models.Sandbox{
			ID:             "sb-orphan",
			Image:          "alpine",
			Status:         models.SandboxStatusStarted,
			PublicURL:      "https://sb-orphan.example.com",
			CPU:            1,
			MemoryMB:       256,
			DiskGB:         1,
			OSUser:         "root",
			ToolboxEnabled: true,
			CreatedAt:      now,
			UpdatedAt:      now,
			LastActiveAt:   now,
		}); err != nil {
			t.Fatalf("store.Create: %v", err)
		}
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, func() { _ = st.Close() }
}

func TestClusterReclaimOrphanLocalRequiresLocalRowAndPreviousOwner(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID:           "sb-orphan",
			OwnerState:          cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-a",
			OrphanedUnix:        123,
		},
		hasPlace: true,
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 body=%q", rr.Code, rr.Body.String())
	}
	if len(stub.claimCalls) != 1 || stub.claimCalls[0] != "sb-orphan" {
		t.Fatalf("claimCalls = %+v, want [sb-orphan]", stub.claimCalls)
	}
}

func TestClusterReclaimOrphanLocalRejectsOtherPreviousOwner(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID:           "sb-orphan",
			OwnerState:          cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-b",
			OrphanedUnix:        123,
		},
		hasPlace: true,
	}
	h, cleanup := newOrphanOpsService(t, stub, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-orphan/reclaim-local", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterReclaimOrphanLocal(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 body=%q", rr.Code, rr.Body.String())
	}
	if len(stub.claimCalls) != 0 {
		t.Fatalf("claimCalls = %+v, want none", stub.claimCalls)
	}
}

func TestClusterDeleteOrphanDeletesOnlyOrphanPlacement(t *testing.T) {
	stub := &orphanOpsStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{
			SandboxID:           "sb-orphan",
			OwnerState:          cluster.PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "node-b",
		},
		hasPlace: true,
	}
	h, cleanup := newOrphanOpsService(t, stub, false)
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete, "/v1/cluster/orphans/sb-orphan", nil)
	req.SetPathValue("id", "sb-orphan")
	rr := httptest.NewRecorder()
	h.clusterDeleteOrphan(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 body=%q", rr.Code, rr.Body.String())
	}
	if len(stub.deleteCalls) != 1 || stub.deleteCalls[0] != "sb-orphan" {
		t.Fatalf("deleteCalls = %+v, want [sb-orphan]", stub.deleteCalls)
	}
}

// TestClusterMembersIncludesDrainedField asserts the observability surface:
// a drained node shows up with drained=true on the members list so operators
// can confirm the mark landed without a second round trip to a hypothetical
// /drain-state endpoint.
func TestClusterMembersIncludesDrainedField(t *testing.T) {
	stub := &drainStubCluster{
		Noop:        cluster.NewNoop("node-a", "http://node-a", ""),
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
