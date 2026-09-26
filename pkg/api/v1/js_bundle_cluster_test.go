package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// jsBundleClusterEnv is a cluster-enabled node (server role, so it holds no
// bundles of its own unless a test uploads one) with a real bundle store.
type jsBundleClusterEnv struct {
	svc     *service.Service
	handler http.Handler
}

func newJSBundleClusterEnv(t *testing.T, selfRole string) *jsBundleClusterEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableIsolate: true, EnableCluster: true, NodeRole: selfRole}, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(dir, "bundles")})
	if err != nil {
		t.Fatalf("jsbundle store: %v", err)
	}
	svc.SetIsolateBundleStore(bundleStore)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(h http.Handler) http.Handler { return h }})
	return &jsBundleClusterEnv{svc: svc, handler: mux}
}

func isolateMember(nodeID, url string) cluster.Member {
	return cluster.Member{
		NodeID: nodeID, APIURL: url, InternalURL: url, Alive: true, Role: config.NodeRoleWorker,
		Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeIsolate}},
	}
}

func jsBundleMembersCluster(selfID string, members ...cluster.Member) *membersStubCluster {
	all := append([]cluster.Member{{NodeID: selfID, APIURL: "http://" + selfID, Alive: true, Role: config.NodeRoleServer}}, members...)
	return &membersStubCluster{
		Noop:           cluster.NewNoop(selfID, "http://"+selfID, ""),
		internalClient: http.DefaultClient,
		members:        all,
	}
}

func listJSBundles(t *testing.T, h http.Handler, headers map[string]string) (*httptest.ResponseRecorder, []*models.JSBundle) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/js-bundles", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var rows []*models.JSBundle
	if rr.Code == http.StatusOK {
		if err := json.NewDecoder(rr.Body).Decode(&rows); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rr, rows
}

// The regression: an ingress/server node holds no bundles, so before the
// wrapper GET /v1/js-bundles returned [] in cluster mode even though uploads
// had succeeded on workers. Now the list is the union of every isolate
// worker's catalogue, deduplicated by digest, with local rows winning.
func TestClusterListJSBundlesMergesIsolateWorkersAndDedupesByDigest(t *testing.T) {
	env := newJSBundleClusterEnv(t, config.NodeRoleServer)
	// A local upload (this server also happens to hold one bundle).
	body, _ := json.Marshal(models.CreateJSBundleRequest{Name: "local", Source: jsHandlerBody})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body))
	req.Header.Set("X-Cluster-Forwarded", "1") // create locally, no placement
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("local upload: %d %s", rr.Code, rr.Body.String())
	}
	var local models.JSBundle
	_ = json.Unmarshal(rr.Body.Bytes(), &local)

	var (
		mu        sync.Mutex
		peerAuths []string
		peerFwd   []string
	)
	peerA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		peerAuths = append(peerAuths, r.Header.Get("Authorization"))
		peerFwd = append(peerFwd, r.Header.Get(clusterJSBundleForwardedHeader))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode([]*models.JSBundle{
			{Digest: local.Digest, ModuleRef: models.JSBundleRefForNode(local.ModuleRef, "iso-a"), Name: "dupe-of-local", MainModule: "worker.js"},
			{Digest: "aaa", ModuleRef: models.JSBundleRefForNode("sha256:aaa", "iso-a"), Name: "a", MainModule: "worker.js", SizeBytes: 10},
		})
	}))
	defer peerA.Close()
	peerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]*models.JSBundle{
			{Digest: "aaa", ModuleRef: models.JSBundleRefForNode("sha256:aaa", "iso-b"), Name: "a-again"},
			{Digest: "bbb", ModuleRef: models.JSBundleRefForNode("sha256:bbb", "iso-b"), Name: "b"},
			nil,
			{Digest: "", ModuleRef: "junk"},
		})
	}))
	defer peerB.Close()
	dockerOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("docker-only worker was asked for js-bundles")
	}))
	defer dockerOnly.Close()
	dockerMember := isolateMember("docker-a", dockerOnly.URL)
	dockerMember.Capacity.SupportedRuntimes = []string{models.RuntimeDocker}
	dead := isolateMember("iso-dead", "https://iso-dead:21443")
	dead.Alive = false
	ingress := cluster.Member{NodeID: "ingress-x", InternalURL: "https://ingress-x:21443", Alive: true, Role: config.NodeRoleIngress}
	env.svc.AttachCluster(jsBundleMembersCluster("server-a",
		isolateMember("iso-a", peerA.URL), isolateMember("iso-b", peerB.URL), dockerMember, dead, ingress))

	rr, rows := listJSBundles(t, env.handler, map[string]string{"Authorization": "Bearer tenant-token"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	byDigest := map[string]*models.JSBundle{}
	for _, row := range rows {
		byDigest[row.Digest] = row
	}
	if len(rows) != 3 || byDigest["aaa"] == nil || byDigest["bbb"] == nil || byDigest[local.Digest] == nil {
		t.Fatalf("rows = %+v, want local + aaa + bbb", rows)
	}
	if byDigest[local.Digest].Name != "local" {
		t.Fatalf("dedupe kept %q for the local digest, want the local row", byDigest[local.Digest].Name)
	}
	// Two workers holding the same digest is one bundle to the caller; peer
	// answers arrive in parallel, so either worker's ref may be the one kept.
	if node, _, ok := models.ParseJSBundleNodeRef(byDigest["aaa"].ModuleRef); !ok || (node != "iso-a" && node != "iso-b") {
		t.Fatalf("aaa ref = %q, want a node-bound ref from iso-a or iso-b", byDigest["aaa"].ModuleRef)
	}
	// The dead isolate worker is reported, not pretended absent.
	if rr.Header().Get("X-Aerol-Partial") != "true" || rr.Header().Get(clusterJSBundleMissingHeader) != "1" {
		t.Fatalf("coverage headers = partial:%q missing:%q, want partial with 1 missing", rr.Header().Get("X-Aerol-Partial"), rr.Header().Get(clusterJSBundleMissingHeader))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(peerAuths) != 1 || peerAuths[0] != "Bearer tenant-token" || peerFwd[0] != "1" {
		t.Fatalf("peer request auth=%v fwd=%v: each peer must apply the caller's owner scoping and answer locally", peerAuths, peerFwd)
	}
}

func TestClusterListJSBundlesForwardedRequestAnswersLocallyOnly(t *testing.T) {
	env := newJSBundleClusterEnv(t, config.NodeRoleWorker)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a forwarded list must never fan out again")
	}))
	defer peer.Close()
	env.svc.AttachCluster(jsBundleMembersCluster("worker-a", isolateMember("iso-b", peer.URL)))
	rr, rows := listJSBundles(t, env.handler, map[string]string{clusterJSBundleForwardedHeader: "1"})
	if rr.Code != http.StatusOK || len(rows) != 0 || rr.Header().Get("X-Aerol-Partial") != "" {
		t.Fatalf("forwarded list = %d rows=%d partial=%q", rr.Code, len(rows), rr.Header().Get("X-Aerol-Partial"))
	}
}

func TestClusterListJSBundlesRoutesIngressToLeaderAndCoalesces(t *testing.T) {
	env := newJSBundleClusterEnv(t, config.NodeRoleIngress)
	base := &membersStubCluster{
		Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		members: []cluster.Member{
			{NodeID: "ingress-a", Alive: true, Role: config.NodeRoleIngress},
			{NodeID: "server-leader", InternalURL: "https://server-leader:21443", Alive: true, Role: config.NodeRoleServer},
		},
	}
	leader := &templateLeaderCluster{membersStubCluster: base, leader: "server-leader"}
	env.svc.AttachCluster(leader)
	rr, _ := listJSBundles(t, env.handler, nil)
	if rr.Code != http.StatusAccepted || leader.forwardedTarget.NodeID != "server-leader" {
		t.Fatalf("ingress list: status %d forwarded to %+v, want leader", rr.Code, leader.forwardedTarget)
	}

	// On the leader, concurrent callers share one sweep.
	leaderEnv := newJSBundleClusterEnv(t, config.NodeRoleServer)
	var calls atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode([]*models.JSBundle{{Digest: "x"}})
	}))
	defer peer.Close()
	leaderEnv.svc.AttachCluster(jsBundleMembersCluster("server-a", isolateMember("iso-a", peer.URL)))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr, rows := listJSBundles(t, leaderEnv.handler, nil)
			if rr.Code != http.StatusOK || len(rows) != 1 {
				t.Errorf("concurrent list = %d rows=%d", rr.Code, len(rows))
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("peer asked %d times for 16 concurrent lists, want 1 coalesced sweep", got)
	}
}

func withOwnerAccess(r *http.Request, owner string) *http.Request {
	return r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: owner},
	}))
}

func createJSBundleAs(t *testing.T, h http.Handler, owner, name string) models.JSBundle {
	t.Helper()
	body, _ := json.Marshal(models.CreateJSBundleRequest{Name: name, Source: jsHandlerBody})
	req := httptest.NewRequest(http.MethodPost, "/v1/js-bundles", bytes.NewReader(body))
	req.Header.Set("X-Cluster-Forwarded", "1")
	req = withOwnerAccess(req, owner)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload %s/%s: %d %s", owner, name, rr.Code, rr.Body.String())
	}
	var created models.JSBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode upload: %v", err)
	}
	return created
}

func listJSBundlesAs(t *testing.T, h http.Handler, owner string) (*httptest.ResponseRecorder, []*models.JSBundle) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/js-bundles", nil)
	req.Header.Set("Authorization", "Bearer "+owner)
	req = withOwnerAccess(req, owner)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var rows []*models.JSBundle
	if rr.Code == http.StatusOK {
		if err := json.NewDecoder(rr.Body).Decode(&rows); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rr, rows
}

// The leader cache used to key singleflight and TTL on the literal "all", so
// tenant B listing within 2s received tenant A's catalogue. Bundles are
// owner-scoped; the cache and sweep Access must be too.
func TestClusterListJSBundlesDoesNotLeakAcrossTenants(t *testing.T) {
	env := newJSBundleClusterEnv(t, config.NodeRoleServer)
	created := createJSBundleAs(t, env.handler, "tenant-a", "private")
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		rows := []*models.JSBundle{}
		if auth == "Bearer tenant-a" {
			rows = []*models.JSBundle{{Digest: "peer-a", ModuleRef: models.JSBundleRefForNode("sha256:peer-a", "iso-a"), Name: "peer-a"}}
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	defer peer.Close()
	env.svc.AttachCluster(jsBundleMembersCluster("server-a", isolateMember("iso-a", peer.URL)))

	rrA, rowsA := listJSBundlesAs(t, env.handler, "tenant-a")
	if rrA.Code != http.StatusOK {
		t.Fatalf("tenant-a list: %d %s", rrA.Code, rrA.Body.String())
	}
	seenA := map[string]bool{}
	for _, row := range rowsA {
		seenA[row.Digest] = true
	}
	if !seenA[created.Digest] {
		t.Fatalf("tenant-a missing its upload: %+v", rowsA)
	}

	rrB, rowsB := listJSBundlesAs(t, env.handler, "tenant-b")
	if rrB.Code != http.StatusOK {
		t.Fatalf("tenant-b list: %d %s", rrB.Code, rrB.Body.String())
	}
	for _, row := range rowsB {
		if row != nil && (row.Digest == created.Digest || row.Digest == "peer-a") {
			t.Fatalf("tenant-b received tenant-a's catalogue: %+v", rowsB)
		}
	}
}

func TestClusterListJSBundlesWithoutClusterIsLocal(t *testing.T) {
	h := newJSBundleV1TestEnv(t) // EnableCluster false
	rr, rows := listJSBundles(t, h, nil)
	if rr.Code != http.StatusOK || len(rows) != 0 || rr.Header().Get("X-Aerol-Partial") != "" {
		t.Fatalf("single-node list = %d rows=%d partial=%q", rr.Code, len(rows), rr.Header().Get("X-Aerol-Partial"))
	}
}

// A bundle's only copy went with its worker: the answer carries a stable code
// so an SDK re-uploads instead of parsing prose.
func TestJSBundleOwnerUnavailableCarriesArtifactCode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&createForwardCluster{
		Noop:    cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		members: []cluster.Member{{NodeID: "isolate-a", InternalURL: "https://isolate-a:21443", Alive: false}},
	})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req := httptest.NewRequest(method, "/v1/js-bundles/x", nil)
		req.SetPathValue("id", models.JSBundleRefForNode("sha256:abc", "isolate-a"))
		rr := httptest.NewRecorder()
		if method == http.MethodGet {
			h.getJSBundle(rr, req)
		} else {
			h.deleteJSBundle(rr, req)
		}
		var body models.ErrorResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if rr.Code != http.StatusServiceUnavailable || body.Code != models.ErrorCodeArtifactNodeUnavailable {
			t.Fatalf("%s dead owner = %d %+v, want 503 %s", method, rr.Code, body, models.ErrorCodeArtifactNodeUnavailable)
		}
	}
}

// The create path: placement pinned to a dead bundle node answers with the
// same code, and without Retry-After — waiting will not bring the bundle back.
func TestCreateSandboxOnDeadBundleNodeCarriesArtifactCode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	c := &createForwardCluster{
		Noop:      cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		selectErr: cluster.ErrArtifactNodeUnavailable,
	}
	svc.AttachCluster(c)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	ref := models.JSBundleRefForNode("sha256:abc", "isolate-gone")
	body, _ := json.Marshal(models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: ref, CPU: 1, MemoryMB: 128})
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)
	var resp models.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusServiceUnavailable || resp.Code != models.ErrorCodeArtifactNodeUnavailable || rr.Header().Get("Retry-After") != "" {
		t.Fatalf("create on dead bundle node = %d %+v retry-after=%q", rr.Code, resp, rr.Header().Get("Retry-After"))
	}
}
