package v1

import (
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
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/time/rate"
)

// TestParseSandboxIDsFilterBranches pins the forwarded-only ids= filter used
// so cluster list peers return just the placement-page subset.
func TestParseSandboxIDsFilterBranches(t *testing.T) {
	if got := parseSandboxIDsFilter(nil); got != nil {
		t.Fatalf("nil request = %v", got)
	}
	plain := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?ids=a,b", nil)
	if got := parseSandboxIDsFilter(plain); got != nil {
		t.Fatalf("unforwarded request must ignore ids: %v", got)
	}
	empty := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	empty.Header.Set("X-Cluster-Forwarded", "1")
	if got := parseSandboxIDsFilter(empty); got != nil {
		t.Fatalf("forwarded without ids = %v", got)
	}
	commas := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?ids=,%20,", nil)
	commas.Header.Set("X-Cluster-Forwarded", "1")
	if got := parseSandboxIDsFilter(commas); got != nil {
		t.Fatalf("only-empty parts = %v", got)
	}
	ok := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?ids=sb-a,%20sb-b,", nil)
	ok.Header.Set("X-Cluster-Forwarded", "1")
	got := parseSandboxIDsFilter(ok)
	if _, a := got["sb-a"]; !a {
		t.Fatalf("missing sb-a: %v", got)
	}
	if _, b := got["sb-b"]; !b {
		t.Fatalf("missing sb-b: %v", got)
	}
}

func liftV1Handler(t *testing.T) (*handlers, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, st
}

func TestListSandboxesFilterAndStoreError(t *testing.T) {
	h, st := liftV1Handler(t)
	now := time.Now().UTC()
	for _, id := range []string{"sb-keep", "sb-drop"} {
		if err := st.Create(context.Background(), &models.Sandbox{
			ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			CPU: 1, MemoryMB: 256, DiskGB: 1, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?ids=sb-keep,missing", nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	rr := httptest.NewRecorder()
	h.listSandboxes(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var listed []*models.Sandbox
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != "sb-keep" {
		t.Fatalf("listed = %+v, want only sb-keep", listed)
	}

	_ = st.Close()
	errRR := httptest.NewRecorder()
	h.listSandboxes(errRR, httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil))
	if errRR.Code != http.StatusInternalServerError {
		t.Fatalf("closed store status = %d", errRR.Code)
	}
}

func TestAuditRateLimiterIdentityAndEvict(t *testing.T) {
	// OwnerRef is the per-tenant bucket key; operator/anonymous collapse so
	// PAT callers share one ceiling instead of one bucket per missing identity.
	opReq := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit", nil)
	opReq = opReq.WithContext(controlplane.ContextWithAccess(opReq.Context(), controlplane.Access{Operator: true}))
	if got := auditIdentityKey(opReq); got != auditRateLimitIdentityKey {
		t.Fatalf("operator key = %q", got)
	}
	ownerReq := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit", nil)
	ownerReq = ownerReq.WithContext(controlplane.ContextWithAccess(ownerReq.Context(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	}))
	if got := auditIdentityKey(ownerReq); got != "acme" {
		t.Fatalf("owner key = %q", got)
	}
	anon := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit", nil)
	anon = anon.WithContext(controlplane.ContextWithAccess(anon.Context(), controlplane.Access{}))
	if got := auditIdentityKey(anon); got != "anonymous" {
		t.Fatalf("anonymous key = %q", got)
	}

	lim := NewAuditRateLimiter(AuditRateLimiterConfig{IdentityRate: 1000, NodeRate: 1000})
	lim.identityMu.Lock()
	lim.identity["stale"] = &auditRateBucket{lim: rate.NewLimiter(1, 1), lastSeen: time.Now().Add(-2 * auditRateLimitIdleTTL)}
	lim.identity["fresh"] = &auditRateBucket{lim: rate.NewLimiter(1, 1), lastSeen: time.Now()}
	lim.evictIdleLocked(time.Now())
	if _, ok := lim.identity["stale"]; ok {
		t.Fatal("expected idle bucket evicted")
	}
	if _, ok := lim.identity["fresh"]; !ok {
		t.Fatal("expected fresh bucket retained")
	}
	lim.identityMu.Unlock()

	// Reuse the same tenant so limiterFor hits the lastSeen refresh path.
	if _, ok := lim.allow("acme"); !ok {
		t.Fatal("first allow should succeed")
	}
	if _, ok := lim.allow("acme"); !ok {
		t.Fatal("second allow should reuse the tenant bucket")
	}

	// Tiny node burst forces the node-delay reject after identity reserve.
	tight := NewAuditRateLimiter(AuditRateLimiterConfig{IdentityRate: 1000, NodeRate: 0.0001})
	tight.node = rate.NewLimiter(rate.Limit(0.0001), 1)
	if _, ok := tight.allow("t1"); !ok {
		t.Fatal("first node token should pass")
	}
	if retry, ok := tight.allow("t2"); ok || retry <= 0 {
		t.Fatalf("expected node delay reject, ok=%v retry=%s", ok, retry)
	}

	var called bool
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	var nilLim *AuditRateLimiter
	nilLim.Middleware(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("nil limiter must pass through")
	}

	okLim := NewAuditRateLimiter(AuditRateLimiterConfig{IdentityRate: 1000, NodeRate: 1000})
	called = false
	okLim.Middleware(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("allowed request must reach next")
	}

	block := NewAuditRateLimiter(AuditRateLimiterConfig{IdentityRate: 1, OperatorRate: 1, NodeRate: 1})
	for i := 0; i < 200; i++ {
		if _, ok := block.allow("operator"); !ok {
			break
		}
	}
	rr := httptest.NewRecorder()
	block.Middleware(next).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d retry=%q", rr.Code, rr.Header().Get("Retry-After"))
	}
}

func TestParseSecretAuditQueryAndAuditHandlers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit?cursor=c1&kind=read&incarnation_id=inc-1&limit=7", nil)
	q := parseSecretAuditQuery(req)
	if q.Cursor != "c1" || q.Kind != "read" || q.IncarnationID != "inc-1" || q.Limit != 7 {
		t.Fatalf("query = %+v", q)
	}
	badLimit := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/x/audit?limit=nope", nil)
	if parseSecretAuditQuery(badLimit).Limit != 0 {
		t.Fatal("invalid limit must stay zero")
	}

	h, sbID := newAuditTestHandler(t, nil)
	missing := httptest.NewRecorder()
	h.getSandboxAudit(missing, httptest.NewRequest(http.MethodGet, "/v1/sandboxes//audit", nil))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing id status = %d", missing.Code)
	}

	// Multiple members + no placement/ACL index is the incomplete-fanout refuse.
	multi := &membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-b", Alive: true, Role: config.NodeRoleWorker},
		},
	}
	h.deps.Service.AttachCluster(multi)
	incRR := httptest.NewRecorder()
	incReq := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sbID+"/audit", nil)
	incReq.SetPathValue("id", sbID)
	h.getSandboxAudit(incRR, incReq)
	if incRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("incomplete index status = %d body=%s", incRR.Code, incRR.Body.String())
	}

	internalMissing := httptest.NewRecorder()
	h.clusterInternalSandboxAudit(internalMissing, httptest.NewRequest(http.MethodGet, "/v1/cluster/internal/sandboxes//audit", nil))
	if internalMissing.Code != http.StatusBadRequest {
		t.Fatalf("internal missing id status = %d", internalMissing.Code)
	}

	alt := httptest.NewRequest(http.MethodGet, "/internal/audit", nil)
	alt.SetPathValue("sandboxID", sbID)
	h.deps.Service.ClearClusterForTest()
	altRR := httptest.NewRecorder()
	h.clusterInternalSandboxAudit(altRR, alt)
	if altRR.Code != http.StatusOK || !strings.Contains(altRR.Body.String(), `"local"`) {
		t.Fatalf("sandboxID path / nil cluster: status=%d body=%s", altRR.Code, altRR.Body.String())
	}
}

func TestWithAuthOperatorNilAuthAndTenant(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := withAuthOperator(Deps{}, next)

	deny := httptest.NewRecorder()
	h.ServeHTTP(deny, httptest.NewRequest(http.MethodGet, "/", nil))
	if deny.Code != http.StatusForbidden {
		t.Fatalf("no access status = %d", deny.Code)
	}

	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	okReq = okReq.WithContext(controlplane.ContextWithAccess(okReq.Context(), controlplane.Access{Operator: true}))
	okRR := httptest.NewRecorder()
	h.ServeHTTP(okRR, okReq)
	if okRR.Code != http.StatusNoContent {
		t.Fatalf("operator status = %d", okRR.Code)
	}
}

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

func TestForwardTemplateToLeaderBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	empty := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", "")},
		leader:             "",
	}
	rr := httptest.NewRecorder()
	if !h.forwardTemplateToLeader(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil), empty, clusterTemplateAggregateHeader) || rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty leader status = %d", rr.Code)
	}

	self := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", "")},
		leader:             "self",
	}
	if h.forwardTemplateToLeader(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/templates", nil), self, clusterTemplateAggregateHeader) {
		t.Fatal("self leader must not forward")
	}

	missing := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{
			Noop:    cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{{NodeID: "self", Alive: true}},
		},
		leader: "gone",
	}
	missRR := httptest.NewRecorder()
	if !h.forwardTemplateToLeader(missRR, httptest.NewRequest(http.MethodGet, "/v1/templates", nil), missing, clusterTemplateAggregateHeader) || missRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing leader status = %d", missRR.Code)
	}

	dead := &templateLeaderCluster{
		membersStubCluster: &membersStubCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "lead", Alive: false, InternalURL: ""},
			},
		},
		leader: "lead",
	}
	deadRR := httptest.NewRecorder()
	if !h.forwardTemplateToLeader(deadRR, httptest.NewRequest(http.MethodGet, "/v1/templates", nil), dead, clusterTemplateAggregateHeader) || deadRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("dead leader status = %d", deadRR.Code)
	}

	// LookupMember miss + Members() hit is the test-client fallback.
	member, found := templateMemberByID(&membersStubCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		members: []cluster.Member{
			{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
		},
	}, "peer")
	if !found || member.NodeID != "peer" {
		t.Fatalf("Members fallback = %+v found=%v", member, found)
	}
	if _, ok := templateMemberByID(&membersStubCluster{Noop: cluster.NewNoop("self", "http://self", "")}, "nope"); ok {
		t.Fatal("expected miss")
	}
	if n := clusterRuntimeUnavailablePeerCount(nil, models.RuntimeFirecracker); n != 0 {
		t.Fatalf("nil cluster count = %d", n)
	}
}

func TestClusterInternalSecretHandlerGaps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := service.New(config.Config{EnableCluster: true}, logger, st, nil, nil, nil, cipher, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	delRR := httptest.NewRecorder()
	h.clusterInternalSecretDelete(delRR, httptest.NewRequest(http.MethodDelete, "/v1/cluster/internal/secrets/", nil))
	if delRR.Code != http.StatusBadRequest {
		t.Fatalf("delete missing id = %d", delRR.Code)
	}

	headRR := httptest.NewRecorder()
	h.clusterInternalSecretHead(headRR, httptest.NewRequest(http.MethodHead, "/v1/cluster/internal/secrets/", nil))
	if headRR.Code != http.StatusBadRequest {
		t.Fatalf("head missing id = %d", headRR.Code)
	}

	_ = st.Close()
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/cluster/internal/secrets/sb-x?generation=1&incarnation_id=inc", nil)
	delReq.SetPathValue("sandboxID", "sb-x")
	closedDel := httptest.NewRecorder()
	h.clusterInternalSecretDelete(closedDel, delReq)
	if closedDel.Code != http.StatusInternalServerError {
		t.Fatalf("delete closed store = %d", closedDel.Code)
	}

	headReq := httptest.NewRequest(http.MethodHead, "/v1/cluster/internal/secrets/sb-x?min_generation=1&incarnation_id=inc", nil)
	headReq.SetPathValue("sandboxID", "sb-x")
	closedHead := httptest.NewRecorder()
	h.clusterInternalSecretHead(closedHead, headReq)
	if closedHead.Code != http.StatusInternalServerError {
		t.Fatalf("head closed store = %d", closedHead.Code)
	}

	// Placement-unavailable PUT: EnableCluster but no cluster client.
	svc.ClearClusterForTest()
	putRR := httptest.NewRecorder()
	h.clusterInternalSecretPut(putRR, httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/secrets", strings.NewReader(
		`{"ref":"cluster-secret://sandbox/sb/v1","sandbox_id":"sb","sealed_payload":"YQ=="}`)))
	if putRR.Code == http.StatusNoContent {
		t.Fatal("expected put failure without live placement")
	}
}

func TestHandlerStoreErrorBranches(t *testing.T) {
	h, st := liftV1Handler(t)
	_ = st.Close()

	resize := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb/resize", strings.NewReader(`{"cpu":2}`))
	req.SetPathValue("id", "sb")
	h.resizeSandbox(resize, req)
	if resize.Code == http.StatusOK {
		t.Fatal("expected resize store error")
	}

	life := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb/lifecycle", strings.NewReader(`{"lifecycle":{}}`))
	lreq.SetPathValue("id", "sb")
	h.updateLifecycle(life, lreq)
	if life.Code == http.StatusOK {
		t.Fatal("expected lifecycle store error")
	}

	net := httptest.NewRecorder()
	nreq := httptest.NewRequest(http.MethodPut, "/v1/sandboxes/sb/network-limits", strings.NewReader(`{"network_bytes_in_limit":1}`))
	nreq.SetPathValue("id", "sb")
	h.updateNetworkLimits(net, nreq)
	if net.Code == http.StatusOK {
		t.Fatal("expected network-limits store error")
	}

	dom := httptest.NewRecorder()
	dreq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb/custom-domains", strings.NewReader(`{"hostname":"ex.test"}`))
	dreq.SetPathValue("id", "sb")
	h.addCustomDomain(dom, dreq)
	if dom.Code == http.StatusCreated {
		t.Fatal("expected custom-domain store error")
	}
}

func TestClusterPlacementLookupErrorAndNilReplicate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&ownerOfStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		err:  errors.New("raft timeout"),
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/sandboxes/sb-1/placement", nil)
	req.SetPathValue("id", "sb-1")
	rr := httptest.NewRecorder()
	h.clusterPlacement(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("placement status = %d", rr.Code)
	}

	svc.ClearClusterForTest()
	h.replicateAddExposedPort(context.Background(), "sb-1", 8080, cluster.ExposedPortRoute{})
	h.replicateRemoveExposedPort(context.Background(), "sb-1", 8080)

	got := capacityRequestFromCreate(models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: models.JSBundleRefForNode("sha256:abc", "worker-b"),
	})
	if got.RequiredNodeID == "" {
		t.Fatalf("expected isolate node-bound required node, got %+v", got)
	}
	encoded, ok := models.EncodeNodeAffinity("worker-b")
	if !ok {
		t.Fatal("EncodeNodeAffinity")
	}
	built := capacityRequestFromCreate(models.CreateSandboxRequest{
		Image: "aerolvm-build/node-" + encoded + "/abc:latest",
	})
	if built.RequiredNodeID != "worker-b" {
		t.Fatalf("built-image required node = %q", built.RequiredNodeID)
	}
	if err := normalizeCreateRuntimeForPlacement(&models.CreateSandboxRequest{Runtime: "nope"}); err == nil {
		t.Fatal("expected invalid runtime")
	}
	minimizePlacementBatchRecord(nil)
}

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

type resizeOKRuntime struct{ noopRuntime }

func (resizeOKRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}

func TestResizeAndLifecycleSuccess(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, resizeOKRuntime{}, nil, nil, nil, nil, nil)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ok", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	resize := httptest.NewRecorder()
	rreq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-ok/resize", strings.NewReader(`{"cpu":2}`))
	rreq.SetPathValue("id", "sb-ok")
	h.resizeSandbox(resize, rreq)
	if resize.Code != http.StatusOK {
		t.Fatalf("resize status = %d body=%s", resize.Code, resize.Body.String())
	}

	life := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb-ok/lifecycle",
		strings.NewReader(`{"lifecycle":{}}`))
	lreq.SetPathValue("id", "sb-ok")
	h.updateLifecycle(life, lreq)
	if life.Code != http.StatusOK {
		t.Fatalf("lifecycle status = %d body=%s", life.Code, life.Body.String())
	}
}

func TestClusterForwardWrapUnknownSandboxFallsThrough(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&ownerOfStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		err:  cluster.ErrUnknownSandbox,
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-x", nil)
	req.SetPathValue("id", "sb-x")
	rr := httptest.NewRecorder()
	h.clusterForwardWrap(local).ServeHTTP(rr, req)
	if rr.Code != http.StatusTeapot {
		t.Fatalf("unknown sandbox should fall through, status=%d", rr.Code)
	}
}

func TestTemplateListCacheHit(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	h.templateLists.put(time.Now(), clusterListAggregate[*models.Template]{rows: []*models.Template{{ID: "cached"}}})
	got, ok := h.templateLists.get(time.Now())
	if !ok || len(got.rows) != 1 {
		t.Fatalf("cache hit = %+v ok=%v", got, ok)
	}
}
