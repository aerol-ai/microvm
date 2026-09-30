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

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/time/rate"
)

// --- stubs ------------------------------------------------------------------

type c96bEpochCluster struct {
	*cluster.Noop
	err error
}

func (c *c96bEpochCluster) AllocateArtifactCatalogEpoch(context.Context, string, string, string) (int64, error) {
	return 0, c.err
}

type c96bReassignCluster struct {
	*cluster.Noop
	err error
}

func (c *c96bReassignCluster) ReassignStuckPlacement(context.Context, string, string, string) error {
	return c.err
}

// c96bSecretCluster controls the placement reads the peer secret fences use.
type c96bSecretCluster struct {
	*cluster.Noop
	placements map[string]cluster.Placement
	authErr    error
}

func (c *c96bSecretCluster) PlacementsByIDs([]string) map[string]cluster.Placement {
	return c.placements
}

func (c *c96bSecretCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	if c.authErr != nil {
		return nil, c.authErr
	}
	return map[string]cluster.Placement{}, nil
}

type c96bEmptyTargetCluster struct {
	*cluster.Noop
}

func (c *c96bEmptyTargetCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	return cluster.PlacementTarget{}, nil
}

type c96bNilClientDialer struct {
	*cluster.Noop
}

func (c *c96bNilClientDialer) PeerDialMember(cluster.Member) (*http.Client, string, error) {
	return nil, "", nil
}

type c96bTemplateMembersCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *c96bTemplateMembersCluster) Members() []cluster.Member { return c.members }

// c96bLogBuilder drives the OnLog callbacks the plain fake never invokes.
type c96bLogBuilder struct {
	fakeImageBuilder
}

func (b *c96bLogBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	if req.OnLog != nil {
		req.OnLog("step 1/1")
	}
	return b.fakeImageBuilder.BuildImage(ctx, req)
}

func (b *c96bLogBuilder) PushImage(ctx context.Context, req docker.PushImageRequest) (string, error) {
	if req.OnLog != nil {
		req.OnLog("pushed")
	}
	return b.fakeImageBuilder.PushImage(ctx, req)
}

// --- helpers ----------------------------------------------------------------

func c96bLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func c96bHandlers(svc *service.Service) *handlers {
	return &handlers{deps: Deps{Service: svc, Logger: c96bLogger()}}
}

func c96bServiceWithCluster(cfg config.Config, st *storepkg.Store, c cluster.Client) *service.Service {
	svc := service.New(cfg, c96bLogger(), st, nil, nil, nil, nil, nil, nil)
	if c != nil {
		svc.AttachCluster(c)
	}
	return svc
}

func c96bOpenStore(t *testing.T) *storepkg.Store {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func c96bWithPeer(r *http.Request, peer string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clusterPeerNodeIDContextKey{}, peer))
}

func c96bExpect(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, want, rr.Body.String())
	}
}

// c96bAbortServer sends headers promising more bytes than it writes, then
// drops the connection so the client's body read fails mid-stream.
func c96bAbortServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// c96bFillClusterListAdmission occupies every free sweep slot and returns a
// release func; the package has no parallel tests, so nothing else competes.
func c96bFillClusterListAdmission(t *testing.T) {
	t.Helper()
	n := 0
fill:
	for {
		select {
		case clusterListAdmission <- struct{}{}:
			n++
		default:
			break fill
		}
	}
	t.Cleanup(func() {
		for i := 0; i < n; i++ {
			<-clusterListAdmission
		}
	})
}

func c96bCanceledRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	return r.WithContext(ctx)
}

// --- cluster_handler.go: create / list / query helpers ----------------------

func TestC96bClusterCreateWrapNilServiceEmptyBody(t *testing.T) {
	h := &handlers{deps: Deps{Logger: c96bLogger()}}
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", http.NoBody))
	c96bExpect(t, rr, http.StatusBadRequest)
}

func TestC96bParseRepeatedIntQuerySkipsBlankParts(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x?shard=1,,2&shard=%20,bad,3", nil)
	got := parseRepeatedIntQuery(r, "shard")
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("parseRepeatedIntQuery = %v, want [1 2 3]", got)
	}
}

func TestC96bClusterListWrapReportsMissingOwners(t *testing.T) {
	st := c96bOpenStore(t)
	svc := c96bServiceWithCluster(config.Config{}, st, &placementPageStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		pageResp: cluster.PlacementPageResponse{
			Authoritative: true,
			Placements:    []cluster.Placement{{SandboxID: "sb-ghost", OwnerNodeID: "node-ghost"}},
		},
	})
	rr := httptest.NewRecorder()
	c96bHandlers(svc).clusterListWrap(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil))
	c96bExpect(t, rr, http.StatusOK)
}

// --- cluster_handler.go: orphan + storage retirement ------------------------

func TestC96bOrphanHandlersNoPlacement(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, cluster.NewNoop("node-a", "http://node-a", ""))
	h := c96bHandlers(svc)
	for name, fn := range map[string]http.HandlerFunc{
		"reclaim": h.clusterReclaimOrphanLocal,
		"delete":  h.clusterDeleteOrphan,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/cluster/orphans/sb-x", nil)
			req.SetPathValue("id", "sb-x")
			rr := httptest.NewRecorder()
			fn(rr, req)
			c96bExpect(t, rr, http.StatusNotFound)
		})
	}
}

func TestC96bRetireNodeStorageErrorBranches(t *testing.T) {
	// A nil store makes every retirement service call fail generically.
	h := c96bHandlers(c96bServiceWithCluster(config.Config{}, nil, nil))

	bad := retireReq(t, http.MethodPost, "node-gone", `{`)
	rr := httptest.NewRecorder()
	h.clusterRetireNodeStorage(rr, bad)
	c96bExpect(t, rr, http.StatusBadRequest)

	rr = httptest.NewRecorder()
	h.clusterRetireNodeStorage(rr, retireReq(t, http.MethodPost, "node-gone", `{"reason":"wiped"}`))
	c96bExpect(t, rr, http.StatusBadRequest)

	rr = httptest.NewRecorder()
	h.clusterRevokeNodeStorageRetirement(rr, retireReq(t, http.MethodDelete, "", ""))
	c96bExpect(t, rr, http.StatusBadRequest)

	rr = httptest.NewRecorder()
	h.clusterRevokeNodeStorageRetirement(rr, retireReq(t, http.MethodDelete, "node-gone", ""))
	c96bExpect(t, rr, http.StatusBadRequest)

	rr = httptest.NewRecorder()
	h.clusterListNodeStorageRetirements(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/storage-retirements", nil))
	c96bExpect(t, rr, http.StatusBadRequest)
}

func TestC96bClusterOperatorActorFallsBackToOwnerRef(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: " tenant-x "},
		Operator: true,
	}))
	if got := clusterOperatorActor(r); got != "tenant-x" {
		t.Fatalf("actor = %q, want tenant-x", got)
	}
}

// --- cluster_handler.go: cluster-not-enabled arms ---------------------------

func TestC96bInternalHandlersClusterNotEnabled(t *testing.T) {
	h := newHandlerNilCluster(t)
	cases := map[string]http.HandlerFunc{
		"node_storage_retirements": h.clusterInternalNodeStorageRetirements,
		"artifact_catalog":         h.clusterInternalArtifactCatalog,
		"artifact_catalog_epoch":   h.clusterInternalArtifactCatalogEpoch,
		"storage_obligations":      h.clusterInternalStorageObligations,
		"owned_recovery":           h.clusterInternalOwnedRecovery,
		"reassign_stuck":           h.clusterInternalReassignStuck,
		"drained_nodes":            h.clusterInternalDrainedNodes,
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			fn(rr, c96bWithPeer(httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/x", strings.NewReader(`{}`)), "peer-1"))
			c96bExpect(t, rr, http.StatusServiceUnavailable)
		})
	}
}

func TestC96bInternalHandlersRejectAgentRole(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, &cluster.Agent{})
	h := c96bHandlers(svc)
	for name, fn := range map[string]http.HandlerFunc{
		"storage_obligations": h.clusterInternalStorageObligations,
		"drained_nodes":       h.clusterInternalDrainedNodes,
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			fn(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/x", nil))
			c96bExpect(t, rr, http.StatusServiceUnavailable)
			if !strings.Contains(rr.Body.String(), "control-plane nodes only") {
				t.Fatalf("body = %s, want control-plane-only message", rr.Body.String())
			}
		})
	}
}

func TestC96bArtifactCatalogEpochGenericError(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, &c96bEpochCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		err:  errors.New("raft stalled"),
	})
	rr := httptest.NewRecorder()
	req := c96bWithPeer(httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/artifact-catalog/epoch",
		strings.NewReader(`{"kind":"template","holder":"h"}`)), "peer-1")
	c96bHandlers(svc).clusterInternalArtifactCatalogEpoch(rr, req)
	c96bExpect(t, rr, http.StatusServiceUnavailable)
	if !strings.Contains(rr.Body.String(), "epoch allocation failed") {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func TestC96bClusterInternalApplyRejectsOversizeBody(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, &applyStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	body := bytes.Repeat([]byte("a"), (1<<20)+1)
	rr := httptest.NewRecorder()
	c96bHandlers(svc).clusterInternalApply(rr, httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/apply", bytes.NewReader(body)))
	c96bExpect(t, rr, http.StatusRequestEntityTooLarge)
}

// --- cluster_handler.go: owned recovery / reassign --------------------------

func TestC96bOwnedRecoveryBadJSON(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, cluster.NewNoop("node-a", "http://node-a", ""))
	rr := httptest.NewRecorder()
	req := c96bWithPeer(httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/owned-recovery", strings.NewReader(`{`)), "peer-1")
	c96bHandlers(svc).clusterInternalOwnedRecovery(rr, req)
	c96bExpect(t, rr, http.StatusBadRequest)
}

func TestC96bReassignStuckBranches(t *testing.T) {
	noop := cluster.NewNoop("node-a", "http://node-a", "")
	tests := []struct {
		name string
		c    cluster.Client
		body string
		want int
	}{
		{"bad_json", noop, `{`, http.StatusBadRequest},
		{"no_fsm", noop, `{"sandbox_id":"sb"}`, http.StatusServiceUnavailable},
		{"not_found", &c96bReassignCluster{Noop: noop, err: cluster.ErrUnknownSandbox}, `{"sandbox_id":"sb"}`, http.StatusNotFound},
		{"not_owner", &c96bReassignCluster{Noop: noop, err: cluster.ErrStuckReassignNotOwner}, `{"sandbox_id":"sb"}`, http.StatusConflict},
		{"generic", &c96bReassignCluster{Noop: noop, err: errors.New("boom")}, `{"sandbox_id":"sb"}`, http.StatusInternalServerError},
		{"accepted", &c96bReassignCluster{Noop: noop}, `{"sandbox_id":"sb"}`, http.StatusAccepted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := c96bServiceWithCluster(config.Config{}, nil, tc.c)
			rr := httptest.NewRecorder()
			req := c96bWithPeer(httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/reassign-stuck", strings.NewReader(tc.body)), "peer-1")
			c96bHandlers(svc).clusterInternalReassignStuck(rr, req)
			c96bExpect(t, rr, tc.want)
		})
	}
}

// --- cluster_handler.go: select placement errors ----------------------------

func TestC96bSelectPlacementErrorsAreInBody(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, &membersStubCluster{
		Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
		placementErr: cluster.ErrNoPlacementTarget,
	})
	h := c96bHandlers(svc)
	for name, body := range map[string]string{
		"sandbox_id":  `{"sandbox_id":"sb-1","recipient_backups":1}`,
		"target_only": `{"target_only":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.clusterInternalSelectPlacement(rr, httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader(body)))
			c96bExpect(t, rr, http.StatusOK)
			var resp cluster.SelectPlacementResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Error == "" {
				t.Fatalf("expected placement error in body, got %+v", resp)
			}
		})
	}
}

// --- cluster_handler.go: peer secret put / delete ---------------------------

func TestC96bClusterInternalSecretPutErrorMapping(t *testing.T) {
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	blob := mustSealBlob(t, cipher, "sb-put", "node-a", []string{"node-a"})
	body, _ := json.Marshal(blob)

	tests := []struct {
		name       string
		placements map[string]cluster.Placement
		store      bool
		want       int
	}{
		// nil placement map = the FSM read failed, which must surface as 503.
		{name: "placement_unavailable", placements: nil, store: true, want: http.StatusServiceUnavailable},
		{name: "originator_denied", placements: map[string]cluster.Placement{
			"sb-put": {SandboxID: "sb-put", OwnerNodeID: "node-owner", IncarnationID: blob.IncarnationID},
		}, store: true, want: http.StatusForbidden},
		{name: "store_not_configured", store: false, want: http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var st *storepkg.Store
			if tc.store {
				st = c96bOpenStore(t)
			}
			svc := service.New(config.Config{EnableCluster: true}, c96bLogger(), st, nil, nil, nil, cipher, nil, nil)
			svc.AttachCluster(&c96bSecretCluster{Noop: cluster.NewNoop("node-a", "http://node-a", ""), placements: tc.placements})
			rr := httptest.NewRecorder()
			req := c96bWithPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalSecretPath, bytes.NewReader(body)), "node-other")
			c96bHandlers(svc).clusterInternalSecretPut(rr, req)
			c96bExpect(t, rr, tc.want)
		})
	}
}

func TestC96bClusterInternalSecretDeleteErrorMapping(t *testing.T) {
	noop := cluster.NewNoop("node-a", "http://node-a", "")
	tests := []struct {
		name string
		cfg  config.Config
		c    cluster.Client
		peer string
		gen  string
		want int
	}{
		{name: "originator_denied", cfg: config.Config{EnableCluster: true}, c: noop, peer: "", gen: "1", want: http.StatusForbidden},
		{name: "placement_unavailable", cfg: config.Config{EnableCluster: true},
			c: &c96bSecretCluster{Noop: noop, authErr: errors.New("leader unknown")}, peer: "peer-1", gen: "1", want: http.StatusServiceUnavailable},
		{name: "generation_too_new", cfg: config.Config{}, c: noop, peer: "peer-1", gen: "5", want: http.StatusConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := c96bServiceWithCluster(tc.cfg, c96bOpenStore(t), tc.c)
			req := httptest.NewRequest(http.MethodDelete,
				cluster.PublicInternalSecretPath+"/sb-del?generation="+tc.gen+"&incarnation_id=inc-1", nil)
			req.SetPathValue("sandboxID", "sb-del")
			rr := httptest.NewRecorder()
			c96bHandlers(svc).clusterInternalSecretDelete(rr, c96bWithPeer(req, tc.peer))
			c96bExpect(t, rr, tc.want)
		})
	}
}

// --- audit_handler.go / audit_limit.go --------------------------------------

func TestC96bClusterInternalSandboxAuditListError(t *testing.T) {
	h := newHandlerNoStore(t)
	req := c96bCanceledRequest(http.MethodGet, "/v1/cluster/internal/sandboxes/sb/audit", nil)
	req.SetPathValue("id", "sb")
	rr := httptest.NewRecorder()
	h.clusterInternalSandboxAudit(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("status = 200, want an error for a canceled request; body=%s", rr.Body.String())
	}
}

func TestC96bAuditPeerMiddlewareBranches(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	rr := httptest.NewRecorder()
	NewAuditRateLimiter(AuditRateLimiterConfig{}).PeerMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	c96bExpect(t, rr, http.StatusNoContent)

	// Burst 0 with a finite rate can never be satisfied: Reserve().OK() is false.
	never := &AuditRateLimiter{peer: rate.NewLimiter(1, 0)}
	rr = httptest.NewRecorder()
	never.PeerMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	c96bExpect(t, rr, http.StatusTooManyRequests)

	// One token per hour: the second reservation must wait, so it is refused.
	slow := &AuditRateLimiter{peer: rate.NewLimiter(rate.Every(time.Hour), 1)}
	slow.peer.Allow()
	rr = httptest.NewRecorder()
	slow.PeerMiddleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	c96bExpect(t, rr, http.StatusTooManyRequests)
}

func TestC96bWriteAuditRateLimitedRoundsUpToOneSecond(t *testing.T) {
	rr := httptest.NewRecorder()
	writeAuditRateLimited(rr, 0)
	if got := rr.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestC96bAuditAllowRejectsUnsatisfiableBuckets(t *testing.T) {
	idNever := &AuditRateLimiter{
		identity:      map[string]*auditRateBucket{},
		identityRate:  1,
		identityBurst: 0,
		node:          rate.NewLimiter(rate.Inf, 1),
		operator:      rate.NewLimiter(1, 0),
		overflow:      rate.NewLimiter(1, 0),
	}
	if _, ok := idNever.allow("tenant-a"); ok {
		t.Fatal("identity burst 0 must reject")
	}

	nodeNever := &AuditRateLimiter{
		identity:      map[string]*auditRateBucket{},
		identityRate:  rate.Inf,
		identityBurst: 1,
		node:          rate.NewLimiter(1, 0),
		operator:      rate.NewLimiter(rate.Inf, 1),
		overflow:      rate.NewLimiter(rate.Inf, 1),
	}
	if _, ok := nodeNever.allow("tenant-a"); ok {
		t.Fatal("node burst 0 must reject")
	}

	nodeSlow := &AuditRateLimiter{
		identity:      map[string]*auditRateBucket{},
		identityRate:  rate.Inf,
		identityBurst: 1,
		node:          rate.NewLimiter(rate.Every(time.Hour), 1),
		operator:      rate.NewLimiter(rate.Inf, 1),
		overflow:      rate.NewLimiter(rate.Inf, 1),
	}
	nodeSlow.node.Allow()
	if d, ok := nodeSlow.allow("tenant-a"); ok || d <= 0 {
		t.Fatalf("drained node bucket: retry=%v ok=%v, want positive retry and reject", d, ok)
	}
}

// --- build.go ---------------------------------------------------------------

func c96bBuildRequest(t *testing.T, dockerfile string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	return httptest.NewRequest(http.MethodPost, "/v1/images/build", bytes.NewReader(body))
}

func c96bRemoteBuildService(client *http.Client, internalURL string) *service.Service {
	return c96bServiceWithCluster(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, nil, &membersStubCluster{
		Noop:           cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		internalClient: client,
		placement:      cluster.PlacementTarget{NodeID: "worker-docker", APIURL: internalURL, InternalURL: internalURL},
	})
}

func TestC96bClusterBuildImageWrapPeerFailures(t *testing.T) {
	const dockerfile = "FROM alpine\nRUN echo c96b"
	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not-json")
	}))
	t.Cleanup(invalid.Close)
	unbound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(buildImageResponse{Image: docker.BuildTagFor(dockerfile, nil)})
	}))
	t.Cleanup(unbound.Close)

	tests := []struct {
		name    string
		svc     *service.Service
		wantMsg string
	}{
		{"invalid_response", c96bRemoteBuildService(invalid.Client(), invalid.URL), "invalid response"},
		{"unbound_tag", c96bRemoteBuildService(unbound.Client(), unbound.URL), "unbound image tag"},
		{"dial_error", c96bRemoteBuildService(nil, "http://worker.invalid"), "cluster image build failed"},
		{"bad_url", c96bRemoteBuildService(http.DefaultClient, "http://bad\x7fhost"), "cluster image build failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			c96bHandlers(tc.svc).clusterBuildImageWrap(rr, c96bBuildRequest(t, dockerfile))
			c96bExpect(t, rr, http.StatusBadGateway)
			if !strings.Contains(rr.Body.String(), tc.wantMsg) {
				t.Fatalf("body = %s, want %q", rr.Body.String(), tc.wantMsg)
			}
		})
	}
}

func TestC96bClusterBuildImageWrapEmptyTarget(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, nil,
		&c96bEmptyTargetCluster{Noop: cluster.NewNoop("ingress-a", "http://ingress-a", "")})
	rr := httptest.NewRecorder()
	c96bHandlers(svc).clusterBuildImageWrap(rr, c96bBuildRequest(t, "FROM alpine\nRUN true"))
	c96bExpect(t, rr, http.StatusServiceUnavailable)
	if !strings.Contains(rr.Body.String(), cluster.ErrNoPlacementTarget.Error()) {
		t.Fatalf("body = %s, want ErrNoPlacementTarget", rr.Body.String())
	}
}

func TestC96bRunImageBuildOnTargetBodyReadFails(t *testing.T) {
	srv := c96bAbortServer(t)
	c := &membersStubCluster{Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""), internalClient: srv.Client()}
	h := c96bHandlers(nil)
	parent := httptest.NewRequest(http.MethodPost, "/v1/images/build", nil)
	parent.Header.Set("Authorization", "Bearer x")
	parent.Header.Set("Content-Type", "application/json")
	_, _, _, err := h.runImageBuildOnTarget(c, parent, []byte(`{}`), cluster.Member{NodeID: "w", InternalURL: srv.URL}, false)
	if err == nil {
		t.Fatal("expected body read error from truncated peer response")
	}
}

func TestC96bBuildImageLogsCallbacksAndRefreshFailure(t *testing.T) {
	logger := c96bLogger()
	const dockerfile = "FROM alpine\nRUN echo logs"

	builder := &c96bLogBuilder{}
	h := &handlers{deps: Deps{Builder: builder, Logger: logger}}
	body, _ := json.Marshal(buildImageRequest{
		DockerfileContent: dockerfile,
		Push:              &buildImagePushSpec{Registry: "ghcr.io/acme/app", Username: "u", Password: "p"},
	})
	rr := httptest.NewRecorder()
	h.buildImage(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", bytes.NewReader(body)))
	c96bExpect(t, rr, http.StatusOK)
	if len(builder.builds) != 1 || len(builder.pushes) != 1 {
		t.Fatalf("builds=%d pushes=%d, want 1/1", len(builder.builds), len(builder.pushes))
	}

	cached := &fakeImageBuilder{
		exists:     map[string]bool{docker.BuildTagFor(dockerfile, nil): true},
		refreshErr: errors.New("refresh failed"),
	}
	h = &handlers{deps: Deps{Builder: cached, Logger: logger}}
	rr = httptest.NewRecorder()
	h.buildImage(rr, c96bBuildRequest(t, dockerfile))
	c96bExpect(t, rr, http.StatusOK)
}

// --- snapshot.go ------------------------------------------------------------

func TestC96bResolveSnapshotImageBranches(t *testing.T) {
	logger := c96bLogger()
	const dockerfile = "FROM alpine\nRUN echo snap"
	tag := docker.BuildTagFor(dockerfile, nil)

	h := &handlers{deps: Deps{Builder: &fakeImageBuilder{existsErr: errors.New("daemon down")}, Logger: logger}}
	if _, _, err := h.resolveSnapshotImage(context.Background(), dockerfile, nil); !errors.Is(err, errBuildOperationalV1) {
		t.Fatalf("exists error = %v, want errBuildOperationalV1", err)
	}

	h = &handlers{deps: Deps{Builder: &fakeImageBuilder{
		exists: map[string]bool{tag: true}, refreshErr: errors.New("refresh failed"),
	}, Logger: logger}}
	got, built, err := h.resolveSnapshotImage(context.Background(), dockerfile, nil)
	if err != nil || got != tag || built != "" {
		t.Fatalf("cache hit = (%q, %q, %v), want (%q, \"\", nil)", got, built, err, tag)
	}

	h = &handlers{deps: Deps{Builder: &c96bLogBuilder{}, Logger: logger}}
	got, built, err = h.resolveSnapshotImage(context.Background(), dockerfile, nil)
	if err != nil || got != tag || built != tag {
		t.Fatalf("fresh build = (%q, %q, %v), want (%q, %q, nil)", got, built, err, tag, tag)
	}
}

func TestC96bRegisterSnapshotRollbackRemoveFailureIsLogged(t *testing.T) {
	st := c96bOpenStore(t)
	svc := c96bServiceWithCluster(config.Config{}, st, nil)
	if _, err := svc.RegisterSnapshot(context.Background(), &models.SandboxSnapshot{Name: "snap-c96b", Image: "alpine:3"}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	builder := &c96bLogBuilder{fakeImageBuilder: fakeImageBuilder{removeErr: errors.New("image in use")}}
	h := &handlers{deps: Deps{Service: svc, Builder: builder, Logger: c96bLogger()}}
	body, _ := json.Marshal(registerSnapshotRequest{Name: "snap-c96b", DockerfileContent: "FROM alpine\nRUN echo conflict"})
	rr := httptest.NewRecorder()
	h.registerSnapshot(rr, httptest.NewRequest(http.MethodPost, "/v1/snapshots", bytes.NewReader(body)))
	c96bExpect(t, rr, http.StatusConflict)
	if len(builder.removes) != 1 {
		t.Fatalf("rollback RemoveImage calls = %d, want 1", len(builder.removes))
	}
}

// --- template.go ------------------------------------------------------------

func TestC96bTemplateHelpers(t *testing.T) {
	if templateListKey(nil) != "" {
		t.Fatal("templateListKey(nil) must be empty")
	}
	m, ok := templateMemberByID(cluster.NewNoop("node-a", "http://node-a", ""), "node-a")
	if !ok || m.NodeID != "node-a" {
		t.Fatalf("templateMemberByID via LookupMember = (%+v, %v)", m, ok)
	}
}

func TestC96bClusterTemplateItemWrapInventoryBranches(t *testing.T) {
	local := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	worker := func(known, alive bool) cluster.Member {
		return cluster.Member{
			NodeID: "worker-fc", Role: config.NodeRoleWorker, Alive: alive, InternalURL: "http://worker-fc",
			Capacity: capacity.Snapshot{
				SupportedRuntimes:                  []string{models.RuntimeFirecracker},
				LocalTemplateCatalogInventoryKnown: known,
				LocalTemplateCatalogIDs:            []string{"tpl-1"},
			},
		}
	}
	tests := []struct {
		name    string
		member  cluster.Member
		wantMsg string
	}{
		{"inventory_unknown", worker(false, true), "has not converged"},
		{"owner_dead", worker(true, false), "owner is unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := c96bServiceWithCluster(config.Config{}, nil, &c96bTemplateMembersCluster{
				Noop:    cluster.NewNoop("leader-a", "http://leader-a", ""),
				members: []cluster.Member{{NodeID: "leader-a", Alive: true}, tc.member},
			})
			req := httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-1", nil)
			req.SetPathValue("id", "tpl-1")
			rr := httptest.NewRecorder()
			c96bHandlers(svc).clusterTemplateItemWrap(local)(rr, req)
			c96bExpect(t, rr, http.StatusServiceUnavailable)
			if !strings.Contains(rr.Body.String(), tc.wantMsg) {
				t.Fatalf("body = %s, want %q", rr.Body.String(), tc.wantMsg)
			}
		})
	}
}

func TestC96bTemplatePeerRequestFailures(t *testing.T) {
	c := &membersStubCluster{Noop: cluster.NewNoop("leader-a", "http://leader-a", ""), internalClient: http.DefaultClient}
	parent := httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-1", nil)
	parent.Method = "BAD METHOD"
	if _, _, _, err := templatePeerRequest(c, parent, nil, cluster.Member{NodeID: "w", InternalURL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("expected request construction error for invalid method")
	}

	srv := c96bAbortServer(t)
	c.internalClient = srv.Client()
	parent = httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-1", nil)
	parent.Header.Set("Authorization", "Bearer x")
	parent.Header.Set("Content-Type", "application/json")
	if _, _, _, err := templatePeerRequest(c, parent, nil, cluster.Member{NodeID: "w", InternalURL: srv.URL}); err == nil {
		t.Fatal("expected body read error from truncated peer response")
	}
}

// --- cluster_list.go / js_bundle_cluster.go ---------------------------------

func TestC96bAcquireClusterListSlotHonorsCanceledContext(t *testing.T) {
	c96bFillClusterListAdmission(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := acquireClusterListSlot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestC96bClusterListCacheServesWarmEntry(t *testing.T) {
	var cache clusterListCache[string]
	calls := 0
	sweep := func(*http.Request) (clusterListAggregate[string], error) {
		calls++
		return clusterListAggregate[string]{rows: []string{"a"}}, nil
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	for i := 0; i < 2; i++ {
		got, err := cache.cached(r, sweep)
		if err != nil || len(got.rows) != 1 {
			t.Fatalf("cached #%d = (%+v, %v)", i, got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("sweep calls = %d, want 1 (second read must hit the cache)", calls)
	}
}

func TestC96bClusterListFromPeersStopsOnCanceledParent(t *testing.T) {
	c := cluster.NewNoop("self", "http://self", "")
	peers := make([]cluster.Member, 512)
	for i := range peers {
		peers[i] = cluster.Member{NodeID: "p", InternalURL: "http://p"}
	}
	parent := c96bCanceledRequest(http.MethodGet, "/v1/templates", nil)
	n := 0
	for res := range clusterListFromPeers[string](parent, c, peers, "X-Test") {
		if res.err == nil {
			t.Fatal("Noop has no peer dialer; every dispatched peer must fail")
		}
		n++
	}
	if n >= len(peers) {
		t.Fatalf("dispatched %d peers, want dispatch to stop early on a canceled parent", n)
	}
}

func TestC96bClusterListFromPeerBadBaseURL(t *testing.T) {
	c := &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", ""), internalClient: http.DefaultClient}
	parent := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	if _, err := clusterListFromPeer[string](parent, c, cluster.Member{NodeID: "p", InternalURL: "http://bad\x7fhost"}, "X-Test"); err == nil {
		t.Fatal("expected request construction error for invalid base URL")
	}
}

func TestC96bDialClusterPeerRejectsMissingClient(t *testing.T) {
	c := &c96bNilClientDialer{Noop: cluster.NewNoop("self", "http://self", "")}
	if _, _, err := dialClusterPeer(c, cluster.Member{NodeID: "p", InternalURL: "http://p"}); err == nil {
		t.Fatal("expected error when the dialer yields no mTLS client")
	}
}

func TestC96bClusterListSweepSkipsBlankKeysAndCountsLocalFailure(t *testing.T) {
	c := cluster.NewNoop("self", "http://self", "")
	catalog := func(*http.Request) ([]string, []string, bool) {
		return []string{"", "a", "b"}, []string{"p1"}, true
	}
	got, err := clusterListSweep[string](httptest.NewRequest(http.MethodGet, "/v1/templates", nil), c, models.RuntimeFirecracker, "X-Test",
		[]string{"", "a"}, errors.New("local list down"), func(s string) string { return s }, c96bLogger(), "templates", nil, catalog)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(got.rows) != 2 || got.rows[0] != "a" || got.rows[1] != "b" {
		t.Fatalf("rows = %v, want [a b]", got.rows)
	}
	if got.failedPeers != 1 {
		t.Fatalf("failedPeers = %d, want 1 for the failed local list", got.failedPeers)
	}
}

func TestC96bClusterListJSBundlesWrapBranches(t *testing.T) {
	t.Run("cluster_enabled_but_detached", func(t *testing.T) {
		svc := c96bServiceWithCluster(config.Config{EnableCluster: true}, c96bOpenStore(t), nil)
		svc.ClearClusterForTest()
		rr := httptest.NewRecorder()
		c96bHandlers(svc).clusterListJSBundlesWrap(rr, httptest.NewRequest(http.MethodGet, "/v1/js-bundles", nil))
		c96bExpect(t, rr, http.StatusBadRequest)
	})
	t.Run("sweep_admission_fails", func(t *testing.T) {
		svc := c96bServiceWithCluster(config.Config{EnableCluster: true}, c96bOpenStore(t), cluster.NewNoop("self", "http://self", ""))
		c96bFillClusterListAdmission(t)
		rr := httptest.NewRecorder()
		c96bHandlers(svc).clusterListJSBundlesWrap(rr, c96bCanceledRequest(http.MethodGet, "/v1/js-bundles", nil))
		if rr.Code == http.StatusOK {
			t.Fatalf("status = 200, want an error when no sweep slot can be taken; body=%s", rr.Body.String())
		}
	})
}

// --- handlers.go ------------------------------------------------------------

func TestC96bUpdateNetworkLimitsRejectsNegativeLimit(t *testing.T) {
	st := c96bOpenStore(t)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-net", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	h := c96bHandlers(c96bServiceWithCluster(config.Config{}, st, nil))
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb-net/network-limits", strings.NewReader(`{"network_bytes_in_limit":-1}`))
	req.SetPathValue("id", "sb-net")
	rr := httptest.NewRecorder()
	h.updateNetworkLimits(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("status = 200, want rejection of a negative limit; body=%s", rr.Body.String())
	}
}
