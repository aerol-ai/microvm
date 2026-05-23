package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakePendingStore is a hand-rolled in-memory store covering only the
// surface AutoImportReconciler depends on. Concurrent-safe so the
// reconciler's bounded fan-out doesn't race the test.
type fakePendingStore struct {
	mu       sync.Mutex
	sandbox  map[string]*models.Sandbox
	pending  map[string]bool
	getErr   map[string]error
	setCalls atomic.Int64
}

func newFakeStore() *fakePendingStore {
	return &fakePendingStore{
		sandbox: map[string]*models.Sandbox{},
		pending: map[string]bool{},
		getErr:  map[string]error{},
	}
}

func (f *fakePendingStore) seed(id string, pending bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sandbox[id] = &models.Sandbox{ID: id, AutoImportPending: pending}
	f.pending[id] = pending
}

func (f *fakePendingStore) seedDeleted(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending[id] = true
	f.getErr[id] = errors.New("sandbox vanished")
}

func (f *fakePendingStore) ListAutoImportPendingIDs(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.pending))
	for id, on := range f.pending {
		if on {
			out = append(out, id)
		}
	}
	return out, nil
}

func (f *fakePendingStore) Get(ctx context.Context, id string) (*models.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErr[id]; err != nil {
		return nil, err
	}
	s, ok := f.sandbox[id]
	if !ok {
		return nil, errors.New("not found")
	}
	copy := *s
	copy.AutoImportPending = f.pending[id]
	return &copy, nil
}

func (f *fakePendingStore) SetAutoImportPending(ctx context.Context, id string, pending bool) error {
	f.setCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending[id] = pending
	if s, ok := f.sandbox[id]; ok {
		s.AutoImportPending = pending
	}
	return nil
}

type fakeSpecResolver struct {
	specs map[string]*models.CreateSandboxRequest
}

func (r *fakeSpecResolver) GetSandboxSpec(id string) (*models.CreateSandboxRequest, bool) {
	s, ok := r.specs[id]
	return s, ok
}

func eligibleSpec() *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{
		Image:                 "ghcr.io/aerol-ai/sandbox:v1",
		ImageDigest:           "sha256:aabbccdd",
		ImageRegistryRef:      "ghcr.io/aerol-ai/sandbox:v1",
		ImageDistributionMode: models.ImageDistributionExternalRegistry,
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
}

func runReconciler(t *testing.T, store *fakePendingStore, specs map[string]*models.CreateSandboxRequest, srv *httptest.Server) AutoImportReconcileStats {
	t.Helper()
	imp, err := NewAutoImporter(validImportCfg(srv.URL))
	if err != nil {
		t.Fatalf("importer: %v", err)
	}
	r := NewAutoImportReconciler(imp, store, &fakeSpecResolver{specs: specs}, slog.Default(), 2)
	stats, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return stats
}

func TestReconciler_SuccessClearsPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(importResponse{
			Status: "imported", RegistryRef: "aocr.aerol.ai/cluster/cl/_imported/ghcr.io/aerol-ai/sandbox:v1--idle-90d",
		})
	}))
	defer srv.Close()

	store := newFakeStore()
	store.seed("sb-1", true)
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{"sb-1": eligibleSpec()}, srv)
	if stats.Succeeded != 1 || stats.Failed != 0 || stats.Skipped != 0 {
		t.Fatalf("stats = %+v, want 1/0/0", stats)
	}
	if store.pending["sb-1"] {
		t.Fatalf("pending flag not cleared after success")
	}
}

func TestReconciler_FailureLeavesPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()

	store := newFakeStore()
	store.seed("sb-1", true)
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{"sb-1": eligibleSpec()}, srv)
	if stats.Failed != 1 {
		t.Fatalf("expected Failed=1, got %+v", stats)
	}
	if !store.pending["sb-1"] {
		t.Fatalf("pending flag must remain set on failure for next sweep")
	}
}

func TestReconciler_NoSpecSkipsAndClears(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("import endpoint hit despite missing spec")
	}))
	defer srv.Close()

	store := newFakeStore()
	store.seed("sb-orphan", true)
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{}, srv) // no spec for sb-orphan
	if stats.Skipped != 1 {
		t.Fatalf("expected Skipped=1, got %+v", stats)
	}
	if store.pending["sb-orphan"] {
		t.Fatalf("missing-spec rows must have their flag cleared to avoid infinite scan")
	}
}

func TestReconciler_FailoverNoneSkipsAndClears(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("import endpoint hit despite failover=none")
	}))
	defer srv.Close()

	spec := eligibleSpec()
	spec.Failover = &models.Failover{Policy: models.FailoverPolicyNone}
	store := newFakeStore()
	store.seed("sb-1", true)
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{"sb-1": spec}, srv)
	if stats.Skipped != 1 {
		t.Fatalf("expected Skipped=1, got %+v", stats)
	}
	if store.pending["sb-1"] {
		t.Fatalf("non-recreate spec must clear the flag")
	}
}

func TestReconciler_AlreadyImportedSpecSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("import endpoint hit despite mode=aocr_imported")
	}))
	defer srv.Close()

	spec := eligibleSpec()
	spec.ImageDistributionMode = models.ImageDistributionAOCRImported
	store := newFakeStore()
	store.seed("sb-1", true)
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{"sb-1": spec}, srv)
	if stats.Skipped != 1 {
		t.Fatalf("expected Skipped=1, got %+v", stats)
	}
}

func TestReconciler_MissingDigestSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("import endpoint hit despite missing digest")
	}))
	defer srv.Close()

	spec := eligibleSpec()
	spec.ImageDigest = ""
	store := newFakeStore()
	store.seed("sb-1", true)
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{"sb-1": spec}, srv)
	if stats.Skipped != 1 {
		t.Fatalf("expected Skipped=1, got %+v", stats)
	}
}

func TestReconciler_DeletedSandboxSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("import endpoint hit despite sandbox vanished")
	}))
	defer srv.Close()

	store := newFakeStore()
	store.seedDeleted("sb-gone")
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{"sb-gone": eligibleSpec()}, srv)
	if stats.Skipped != 1 {
		t.Fatalf("expected Skipped=1, got %+v", stats)
	}
}

func TestReconciler_BoundedConcurrency(t *testing.T) {
	var inFlight atomic.Int64
	var peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(importResponse{Status: "imported", RegistryRef: "x"})
	}))
	defer srv.Close()

	store := newFakeStore()
	specs := map[string]*models.CreateSandboxRequest{}
	for i := 0; i < 6; i++ {
		id := "sb-" + string(rune('a'+i))
		store.seed(id, true)
		specs[id] = eligibleSpec()
	}
	stats := runReconciler(t, store, specs, srv) // maxInFlight=2 in helper
	if stats.Succeeded != 6 {
		t.Fatalf("expected 6 succeeded, got %+v", stats)
	}
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency %d > cap 2", peak.Load())
	}
}

func TestReconciler_EmptyListNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server should not be hit when no rows pending")
	}))
	defer srv.Close()

	store := newFakeStore()
	stats := runReconciler(t, store, map[string]*models.CreateSandboxRequest{}, srv)
	if stats.Scanned != 0 {
		t.Fatalf("scanned %d > 0 on empty store", stats.Scanned)
	}
}

func TestReconciler_NilImporterYieldsNoReconciler(t *testing.T) {
	r := NewAutoImportReconciler(nil, newFakeStore(), &fakeSpecResolver{}, slog.Default(), 0)
	if r != nil {
		t.Fatalf("expected nil reconciler when importer is nil, got %v", r)
	}
}

func TestParseUpstreamFromRegistryRef(t *testing.T) {
	cases := []struct {
		name, ref, image, host, repo, tag string
	}{
		{"prefers ref", "ghcr.io/foo/bar:v1", "", "ghcr.io", "foo/bar", "v1"},
		{"falls back to image", "", "ghcr.io/foo/bar:v1", "ghcr.io", "foo/bar", "v1"},
		{"no tag", "ghcr.io/foo/bar", "", "ghcr.io", "foo/bar", ""},
		{"dockerhub bare returns empty", "", "redis:7", "", "", ""},
		{"dockerhub library returns empty", "", "library/redis", "", "", ""},
		{"localhost host", "localhost:5000/foo:bar", "", "localhost:5000", "foo", "bar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, r, tg := parseUpstreamFromRegistryRef(c.ref, c.image)
			if h != c.host || r != c.repo || tg != c.tag {
				t.Fatalf("got (%q,%q,%q) want (%q,%q,%q)", h, r, tg, c.host, c.repo, c.tag)
			}
		})
	}
}
