package v1

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
)

// newHandlerWithStore returns a handlers instance backed by a real in-memory
// SQLite store so handlers that reach into service/store work without panicking.
func newHandlerWithStore(t *testing.T) *handlers {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, db, nil, nil, nil, nil, nil, nil)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func newHandlerNilCluster(t *testing.T) *handlers {
	t.Helper()
	h := newHandlerNoStore(t)
	h.deps.Service.ClearClusterForTest()
	return h
}

// newHandlerNoStore is fine for handlers that don't touch the store.
func newHandlerNoStore(t *testing.T) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

// TestHandlers_Capacity covers the 0% capacity handler.
func TestHandlers_Capacity(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/capacity", nil)
	h.capacity(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
}

// TestHandlers_ListSandboxes_Empty covers the 0% listSandboxes handler.
func TestHandlers_ListSandboxes_Empty(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	h.listSandboxes(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var result []any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("len = %d, want 0 on empty store", len(result))
	}
}

// TestHandlers_ListSandboxes_TagFilter exercises parseTagFilter path.
func TestHandlers_ListSandboxes_TagFilter(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?tag.owner=alice&tag.env=prod", nil)
	h.listSandboxes(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

// TestHandlers_GetSandbox_NotFound covers the 0% getSandbox → 404 path.
func TestHandlers_GetSandbox_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	h.getSandbox(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestHandlers_StartSandbox_NotFound covers the 0% startSandbox → 404 path.
func TestHandlers_StartSandbox_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/missing/start", nil)
	req.SetPathValue("id", "missing")
	h.startSandbox(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestHandlers_StopSandbox_NotFound covers the 0% stopSandbox → 404 path.
func TestHandlers_StopSandbox_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/missing/stop", nil)
	req.SetPathValue("id", "missing")
	h.stopSandbox(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestHandlers_ListMounts_NotFound covers the 0% listMounts → 404 path.
func TestHandlers_ListMounts_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/missing/mounts", nil)
	req.SetPathValue("id", "missing")
	h.listMounts(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestHandlers_GetNetworkUsage_NotFound covers the 0% getNetworkUsage → 404 path.
func TestHandlers_GetNetworkUsage_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/missing/network", nil)
	req.SetPathValue("id", "missing")
	h.getNetworkUsage(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestHandlers_UpdateNetworkLimits_InvalidJSON covers the early-exit on bad body.
func TestHandlers_UpdateNetworkLimits_InvalidJSON(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/sb/network", strings.NewReader("{bad"))
	req.SetPathValue("id", "sb")
	h.updateNetworkLimits(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// TestHandlers_UpdateNetworkLimits_NotFound covers the 404 path via getNetworkUsage call.
func TestHandlers_UpdateNetworkLimits_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sandboxes/missing/network", strings.NewReader(`{}`))
	req.SetPathValue("id", "missing")
	h.updateNetworkLimits(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestHandlers_IngressDNS covers the ingressDNS handler.
func TestHandlers_IngressDNS(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ingress/dns", nil)
	h.ingressDNS(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

// TestParseTagFilter exercises the tag query parsing helper.
func TestParseTagFilter(t *testing.T) {
	t.Run("no tags", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
		if f := parseTagFilter(req); f != nil {
			t.Errorf("parseTagFilter = %v, want nil for no tags", f)
		}
	})

	t.Run("one tag", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?tag.owner=alice", nil)
		f := parseTagFilter(req)
		if f["owner"] != "alice" {
			t.Errorf("owner = %q, want alice", f["owner"])
		}
	})

	t.Run("empty tag name ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?tag.=val", nil)
		f := parseTagFilter(req)
		if len(f) != 0 {
			t.Errorf("filter = %v, want empty (empty tag name)", f)
		}
	})

	t.Run("non-tag param ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes?limit=10", nil)
		f := parseTagFilter(req)
		if len(f) != 0 {
			t.Errorf("filter = %v, want empty", f)
		}
	})
}

// TestParsePositiveIntQuery covers the cluster helper parsePositiveIntQuery.
func TestParsePositiveIntQuery(t *testing.T) {
	cases := []struct {
		url  string
		key  string
		want int
	}{
		{"/x?limit=10", "limit", 10},
		{"/x?limit=0", "limit", 0},
		{"/x?limit=-5", "limit", 0},
		{"/x?limit=abc", "limit", 0},
		{"/x", "limit", 0},
		{"/x?limit=3", "limit", 3},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.url, nil)
		got := parsePositiveIntQuery(req, c.key)
		if got != c.want {
			t.Errorf("parsePositiveIntQuery(%q, %q) = %d, want %d", c.url, c.key, got, c.want)
		}
	}
}

// TestParseRepeatedIntQuery covers parseRepeatedIntQuery.
func TestParseRepeatedIntQuery(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if got := parseRepeatedIntQuery(req, "shard"); len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("single values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x?shard=1&shard=3", nil)
		got := parseRepeatedIntQuery(req, "shard")
		if len(got) != 2 || got[0] != 1 || got[1] != 3 {
			t.Errorf("got %v, want [1, 3]", got)
		}
	})

	t.Run("comma-separated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x?shard=2,4,6", nil)
		got := parseRepeatedIntQuery(req, "shard")
		if len(got) != 3 {
			t.Errorf("got %v, want [2, 4, 6]", got)
		}
	})

	t.Run("invalid values skipped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x?shard=1,bad,3", nil)
		got := parseRepeatedIntQuery(req, "shard")
		if len(got) != 2 || got[0] != 1 || got[1] != 3 {
			t.Errorf("got %v, want [1, 3]", got)
		}
	})
}

// TestHandlers_ClusterLeader_StandaloneNoop covers the leader handler with the
// default Noop cluster (service.New always installs "standalone" as the node ID).
func TestHandlers_ClusterLeader_StandaloneNoop(t *testing.T) {
	h := newHandlerNoStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/leader", nil)
	h.clusterLeader(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	// The Noop cluster returns its own node ID; just verify the field is present.
	if _, ok := body["leader"]; !ok {
		t.Error("response missing leader field")
	}
}

// TestHandlers_ClusterSandboxIndex_NoopCluster covers the sandbox index with
// the default Noop cluster (returns empty placement page).
func TestHandlers_ClusterSandboxIndex_NoopCluster(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/sandbox-index", nil)
	h.clusterSandboxIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
}

// TestHandlers_ClusterDestroyWrap_NotFound covers the destroy-not-found path.
func TestHandlers_ClusterDestroyWrap_NotFound(t *testing.T) {
	h := newHandlerWithStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/sandboxes/ghost", nil)
	req.SetPathValue("id", "ghost")
	h.clusterDestroyWrap(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rr.Code, rr.Body.String())
	}
}

// TestRedactPlacementSecretFields covers the redact helper.
func TestRedactPlacementSecretFields(t *testing.T) {
	redactPlacementSecretFields(nil) // must not panic

	p := &cluster.Placement{
		SecretRef:     "ref123",
		SecretVersion: 7,
		SealedSecrets: []byte("secret"),
		SandboxID:     "sb-1",
	}
	redactPlacementSecretFields(p)
	if p.SecretRef != "" {
		t.Errorf("SecretRef = %q, want empty after redact", p.SecretRef)
	}
	if p.SecretVersion != 0 {
		t.Errorf("SecretVersion = %d, want 0 after redact", p.SecretVersion)
	}
	if p.SealedSecrets != nil {
		t.Errorf("SealedSecrets = %v, want nil after redact", p.SealedSecrets)
	}
	// Non-secret field must be preserved.
	if p.SandboxID != "sb-1" {
		t.Errorf("SandboxID = %q, want sb-1 (must not be cleared)", p.SandboxID)
	}
}
