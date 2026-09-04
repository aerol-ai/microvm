package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func templateOperatorAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Operator: true})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// fakeTemplateBuilderV1 is the v1 handler-test stub for
// service.TemplateBuilder. Touches the requested OutPath so the
// success path's os.Stat round-trip produces a non-zero size.
type fakeTemplateBuilderV1 struct {
	mu    sync.Mutex
	calls int
	done  chan struct{}
}

func (f *fakeTemplateBuilderV1) Build(_ context.Context, req service.TemplateBuildRequest) (*service.TemplateBuildResult, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	defer func() {
		if f.done != nil {
			f.done <- struct{}{}
		}
	}()
	if err := os.WriteFile(req.OutPath, []byte("FAKE"), 0o600); err != nil {
		return nil, err
	}
	return &service.TemplateBuildResult{
		RootfsPath: req.OutPath,
		StagingDir: filepath.Join(filepath.Dir(req.OutPath), "staging"),
		SizeBytes:  4,
	}, nil
}

type templateV1Env struct {
	svc     *service.Service
	store   *store.Store
	builder *fakeTemplateBuilderV1
	handler http.Handler
}

func newTemplateV1TestEnv(t *testing.T) *templateV1Env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	templatesDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		EnableFirecracker:       true,
		FirecrackerTemplatesDir: templatesDir,
	}
	svc := service.New(cfg, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	builder := &fakeTemplateBuilderV1{done: make(chan struct{}, 1)}
	svc.SetTemplateBuilder(builder)

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    templateOperatorAuth,
	})
	return &templateV1Env{svc: svc, store: st, builder: builder, handler: mux}
}

func TestClusterCreateTemplateWrapRoutesToFirecrackerWorker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
		target: cluster.PlacementTarget{NodeID: "worker-fc", APIURL: "http://worker-fc:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    templateOperatorAuth,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if fakeCluster.forwardedPeer != "http://worker-fc:21212" {
		t.Fatalf("forwarded peer = %q, want firecracker worker", fakeCluster.forwardedPeer)
	}
	if len(fakeCluster.selectRequests) != 1 || fakeCluster.selectRequests[0].Runtime != models.RuntimeFirecracker {
		t.Fatalf("placement request = %+v, want firecracker runtime", fakeCluster.selectRequests)
	}
}

func TestClusterListTemplatesWrapMergesAndDedupesPeers(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	now := time.Now().UTC()
	local := &models.Template{
		ID: "tpl-shared", Image: "docker://local",
		Status: models.TemplateStatusReady, RootfsPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := env.store.CreateTemplate(context.Background(), local); err != nil {
		t.Fatalf("CreateTemplate local: %v", err)
	}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(clusterTemplateForwardedHeader); got != "1" {
			t.Fatalf("%s = %q, want 1", clusterTemplateForwardedHeader, got)
		}
		rows := []*models.Template{
			{ID: "tpl-shared", Image: "docker://peer-dupe", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now},
			{ID: "tpl-peer", Image: "docker://peer", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now},
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))

	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var rows []*models.Template
	if err := json.NewDecoder(rr.Body).Decode(&rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("templates = %+v, want local duplicate plus one peer row", rows)
	}
	byID := map[string]*models.Template{}
	for _, row := range rows {
		byID[row.ID] = row
	}
	if byID["tpl-shared"].Image != "docker://local" {
		t.Fatalf("dedupe kept image %q, want local row", byID["tpl-shared"].Image)
	}
	if byID["tpl-peer"] == nil {
		t.Fatalf("merged rows missing peer template: %+v", rows)
	}
}

func TestClusterListTemplatesWrapCoalescesConcurrentIngressRequests(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	var calls atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode([]*models.Template{{ID: "tpl-peer"}})
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))

	const callers = 32
	start := make(chan struct{})
	errs := make(chan string, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
			if rr.Code != http.StatusOK {
				errs <- rr.Body.String()
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("list failed: %s", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("peer list calls = %d, want 1 coalesced aggregate", got)
	}
}

type templateLeaderCluster struct {
	*membersStubCluster
	leader              string
	forwardedTarget     cluster.Endpoint
	forwardedHeader     string
	forwardedItemHeader string
}

func (c *templateLeaderCluster) Leader() string { return c.leader }

func (c *templateLeaderCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwardedTarget = target
	c.forwardedHeader = r.Header.Get(clusterTemplateAggregateHeader)
	c.forwardedItemHeader = r.Header.Get(clusterTemplateItemLeaderHeader)
	w.WriteHeader(http.StatusAccepted)
}

func TestClusterListTemplatesWrapRoutesIngressToLeader(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	base := &membersStubCluster{
		Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		members: []cluster.Member{
			{NodeID: "ingress-a", Alive: true, Role: config.NodeRoleIngress},
			{NodeID: "server-leader", InternalURL: "https://server-leader:21443", Alive: true, Role: config.NodeRoleServer},
		},
	}
	c := &templateLeaderCluster{membersStubCluster: base, leader: "server-leader"}
	env.svc.AttachCluster(c)

	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want forwarded response", rr.Code)
	}
	if c.forwardedTarget.NodeID != "server-leader" || c.forwardedHeader != "1" {
		t.Fatalf("forward = (%+v, header=%q), want leader aggregate", c.forwardedTarget, c.forwardedHeader)
	}
}

func TestClusterTemplateItemWrapRoutesIngressToLeaderBeforeInventory(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	base := &membersStubCluster{
		Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
		members: []cluster.Member{
			{NodeID: "ingress-a", Alive: true, Role: config.NodeRoleIngress},
			{NodeID: "server-leader", InternalURL: "https://server-leader:21443", Alive: true, Role: config.NodeRoleServer},
		},
	}
	c := &templateLeaderCluster{membersStubCluster: base, leader: "server-leader"}
	env.svc.AttachCluster(c)

	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-pending", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want forwarded response", rr.Code)
	}
	if c.forwardedTarget.NodeID != "server-leader" {
		t.Fatalf("forward target = %+v, want leader", c.forwardedTarget)
	}
	if c.forwardedItemHeader != "1" {
		t.Fatalf("item leader header = %q, want 1", c.forwardedItemHeader)
	}
}

func TestClusterTemplateItemWrapRoutesPeerGetDeleteAndRebuild(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	now := time.Now().UTC()
	seen := map[string]bool{}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(clusterTemplateForwardedHeader); got != "1" {
			t.Fatalf("%s = %q, want 1", clusterTemplateForwardedHeader, got)
		}
		seen[r.Method+" "+r.URL.Path] = true
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/templates/tpl-remote":
			_ = json.NewEncoder(w).Encode(&models.Template{ID: "tpl-remote", Image: "docker://peer", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/templates/tpl-remote":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/templates/tpl-remote/rebuild":
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(&models.Template{ID: "tpl-remote", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now})
		default:
			http.NotFound(w, r)
		}
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))

	cases := []struct {
		method string
		path   string
		want   int
	}{
		{method: http.MethodGet, path: "/v1/templates/tpl-remote", want: http.StatusOK},
		{method: http.MethodDelete, path: "/v1/templates/tpl-remote", want: http.StatusNoContent},
		{method: http.MethodPost, path: "/v1/templates/tpl-remote/rebuild", want: http.StatusAccepted},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("%s %s status = %d, want %d: %s", tc.method, tc.path, rr.Code, tc.want, rr.Body.String())
		}
		if !seen[tc.method+" "+tc.path] {
			t.Fatalf("peer did not see %s %s", tc.method, tc.path)
		}
	}
}

func TestClusterTemplateItemWrapFallsBackLocalAfterPeer404(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	now := time.Now().UTC()
	tpl := &models.Template{
		ID: "tpl-local", Image: "docker://local",
		Status: models.TemplateStatusReady, RootfsPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate local: %v", err)
	}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))

	req := httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-local", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var got models.Template
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "tpl-local" {
		t.Fatalf("template ID = %q, want tpl-local", got.ID)
	}
}

func templateMembersCluster(selfID, peerURL string) cluster.Client {
	return &membersStubCluster{
		Noop:           cluster.NewNoop(selfID, "http://"+selfID, ""),
		internalClient: http.DefaultClient,
		members: []cluster.Member{
			{NodeID: selfID, APIURL: "http://" + selfID, Alive: true, Role: config.NodeRoleServer},
			{
				NodeID: "worker-fc", APIURL: peerURL, InternalURL: peerURL, Alive: true, Role: config.NodeRoleWorker,
				Capacity: capacity.Snapshot{
					SupportedRuntimes:                  []string{models.RuntimeFirecracker},
					LocalTemplateCatalogInventoryKnown: true,
					LocalTemplateCatalogIDs: []string{
						"tpl-peer", "tpl-remote", "tpl-x", "missing-tpl", "x",
					},
				},
			},
		},
	}
}

func TestTemplateOwnerFromInventoryIsDirectAndFailClosed(t *testing.T) {
	members := []cluster.Member{
		{NodeID: "server-a", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "unknown", InternalURL: "https://unknown", Alive: true, Role: config.NodeRoleWorker,
			Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}}},
		{NodeID: "worker-z", InternalURL: "https://worker-z", Alive: true, Role: config.NodeRoleWorker,
			Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}, LocalTemplateCatalogInventoryKnown: true, LocalTemplateCatalogIDs: []string{"tpl-a"}}},
		{NodeID: "worker-a", InternalURL: "https://worker-a", Alive: true, Role: config.NodeRoleWorker,
			Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}, LocalTemplateCatalogInventoryKnown: true, LocalTemplateCatalogIDs: []string{"tpl-a"}}},
	}
	c := &membersStubCluster{Noop: cluster.NewNoop("server-a", "", ""), members: members}
	owner, unknown, ok := templateOwnerFromInventory(c, "tpl-a")
	if !ok || owner.NodeID != "worker-a" {
		t.Fatalf("owner = %+v, ok=%v; want deterministic worker-a", owner, ok)
	}
	if !unknown {
		t.Fatal("unknown inventory must remain visible even when an owner is found")
	}
	_, unknown, ok = templateOwnerFromInventory(c, "missing")
	if ok || !unknown {
		t.Fatalf("missing lookup = ok=%v unknown=%v, want fail-closed unknown", ok, unknown)
	}
}

func TestTemplateOwnerFromInventoryKeepsUnavailableOwnerVisible(t *testing.T) {
	members := []cluster.Member{
		{NodeID: "server-a", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "worker-dead", InternalURL: "https://worker-dead", Alive: false, Role: config.NodeRoleWorker,
			Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}, LocalTemplateCatalogInventoryKnown: true, LocalTemplateCatalogIDs: []string{"tpl-dead"}}},
	}
	c := &membersStubCluster{Noop: cluster.NewNoop("server-a", "", ""), members: members}
	owner, unknown, ok := templateOwnerFromInventory(c, "tpl-dead")
	if !ok || unknown || owner.NodeID != "worker-dead" || owner.Alive {
		t.Fatalf("owner = %+v unknown=%v ok=%v, want visible unavailable owner", owner, unknown, ok)
	}
}

// TestV1CreateTemplate_Returns202 is the canonical happy path: POST
// returns 202 + a PENDING row, and the background goroutine fires the
// builder. This is the API-shape contract Phase 2 promises clients.
func TestV1CreateTemplate_InvalidJSON(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1DeleteTemplate_Success(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	tpl := &models.Template{
		ID: "tpl-del", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, RootfsPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/v1/templates/tpl-del", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1ListTemplates_StoreError(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	_ = env.store.Close()
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1GetTemplate_Success(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	tpl := &models.Template{
		ID: "tpl-get", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, RootfsPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-get", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1CreateTemplate_Returns202(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/templates",
		strings.NewReader(`{"id":"tpl-api","image":"docker://alpine:3.19"}`))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.Template
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != "tpl-api" || resp.Status != models.TemplateStatusPending {
		t.Fatalf("resp = %+v, want id=tpl-api status=pending", resp)
	}

	select {
	case <-env.builder.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("builder.Build did not run")
	}
}

// TestV1GetTemplate_MissingReturns404 confirms the well-known
// not-found mapping carries the right HTTP status — store.ErrNotFound
// already routes through WriteStoreAwareError, but a regression in
// that wiring would silently turn 404s into 400s.
func TestV1GetTemplate_MissingReturns404(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-nope", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// TestV1ListTemplates_ReturnsRows confirms LIST is wired and returns
// JSON in the obvious shape.
func TestV1ListTemplates_ReturnsRows(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	if _, err := env.svc.CreateTemplate(context.Background(), models.CreateTemplateRequest{
		ID: "tpl-list", Image: "docker://alpine:3.19",
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	// Wait for the background build goroutine to complete before the test
	// returns, so t.TempDir cleanup can remove the directories it created.
	select {
	case <-env.builder.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("builder.Build did not run")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var rows []models.Template
	if err := json.NewDecoder(rr.Body).Decode(&rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "tpl-list" {
		t.Fatalf("rows = %+v, want exactly [tpl-list]", rows)
	}
}

// TestV1RebuildTemplate_ReadyReturns202 pins the operator-rebuild
// contract: POST against a ready template returns 202 + the (now
// unhealthy or post-rebuild) row. The service-layer concurrency tests
// cover idempotency; this test pins the HTTP shape and routing.
func TestV1RebuildTemplate_ReadyReturns202(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	// Seed a ready template directly so we don't have to drive the full
	// build pipeline. Snapshot paths are populated so the row passes
	// MarkSnapshotCorrupt's preconditions.
	tpl := &models.Template{
		ID:                 "tpl-rebuild",
		Image:              "docker://alpine:3.19",
		Status:             models.TemplateStatusReady,
		RootfsPath:         filepath.Join(t.TempDir(), "rootfs.ext4"),
		RootfsSizeBytes:    6,
		SnapshotMemoryPath: filepath.Join(t.TempDir(), "snapshot.memory"),
		SnapshotStatePath:  filepath.Join(t.TempDir(), "snapshot.state"),
		SnapshotSizeBytes:  8,
		SnapshotChecksum:   "sha256:dead|sha256:beef",
		SnapshotVsockCID:   42,
		HasSnapshot:        true,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/templates/"+tpl.ID+"/rebuild", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.Template
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// We don't bind the response status here because the harness has no
	// snapshotter wired — MarkSnapshotCorrupt flips the row to unhealthy
	// but the kicked rebuild goroutine will fail without wiring. The
	// HTTP-level invariant is "row no longer ready" + 202.
	if resp.ID != tpl.ID {
		t.Errorf("resp.ID = %q, want %q", resp.ID, tpl.ID)
	}
	if resp.Status == models.TemplateStatusReady {
		t.Errorf("status = ready after rebuild; want unhealthy or downstream state")
	}
}

// TestV1RebuildTemplate_MissingReturns404 pins the well-known 404
// mapping. The handler routes through WriteStoreAwareError which maps
// store.ErrNotFound to 404; a regression would silently turn this
// into a 400.
func TestV1RebuildTemplate_MissingReturns404(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/templates/tpl-nope/rebuild", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// TestV1RebuildTemplate_NotEligibleReturns412 pins the new sentinel
// mapping. A pending template (or any non-{ready,unhealthy} state)
// surfaces ErrTemplateNotRebuildable, which WriteStoreAwareError maps
// to 412 Precondition Failed. Without this mapping an operator's
// "rebuild that template" tooling would see 400 and not be able to
// distinguish "row not eligible" from "malformed request".
func TestV1RebuildTemplate_NotEligibleReturns412(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	tpl := &models.Template{
		ID: "tpl-pending", Image: "docker://alpine:3.19",
		Status:    models.TemplateStatusPending,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/templates/"+tpl.ID+"/rebuild", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412; body=%s", rr.Code, rr.Body.String())
	}
}

// TestV1DeleteTemplate_InUseReturns409 pins the API contract for the
// ErrTemplateInUse sentinel (added in apihttp.WriteStoreAwareError):
// an active sandbox holding template_id forces the operator to
// destroy the sandbox first instead of yanking rootfs out from under
// a live Firecracker guest. We seed the store directly to avoid
// pulling in the runtime.
func TestV1DeleteTemplate_InUseReturns409(t *testing.T) {
	env := newTemplateV1TestEnv(t)

	tpl := &models.Template{
		ID: "tpl-busy-api", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, RootfsPath: "/var/lib/aerolvm/templates/tpl-busy-api/rootfs.ext4",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	sb := &models.Sandbox{
		ID: "sb-busy-api", Image: "docker://alpine:3.19",
		Status: models.SandboxStatusStarted, ContainerID: "ctr", ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root",
		Env: map[string]string{}, ToolboxEnabled: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(),
		Runtime: models.RuntimeFirecracker, TemplateID: tpl.ID,
	}
	if err := env.store.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/templates/"+tpl.ID, nil)
	delRR := httptest.NewRecorder()
	env.handler.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusConflict {
		t.Fatalf("delete status = %d, want 409; body=%s", delRR.Code, delRR.Body.String())
	}
}
