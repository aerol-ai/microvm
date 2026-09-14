package v1

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTemplateListCacheHit(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	now := time.Now()
	h.templateLists.put("operator", now, clusterListAggregate[*models.Template]{rows: []*models.Template{{ID: "cached"}}})
	got, ok := h.templateLists.get("operator", now)
	if !ok || len(got.rows) != 1 {
		t.Fatalf("cache hit = %+v ok=%v", got, ok)
	}
}

func TestClusterListCacheIsolatesCallersAndPrunesExpired(t *testing.T) {
	var c clusterListCache[*models.JSBundle]
	now := time.Now()
	c.put("owner:a", now, clusterListAggregate[*models.JSBundle]{rows: []*models.JSBundle{{Digest: "aaa"}}})
	c.put("owner:b", now, clusterListAggregate[*models.JSBundle]{rows: []*models.JSBundle{{Digest: "bbb"}}})
	a, ok := c.get("owner:a", now)
	if !ok || len(a.rows) != 1 || a.rows[0].Digest != "aaa" {
		t.Fatalf("tenant a = %+v ok=%v", a, ok)
	}
	b, ok := c.get("owner:b", now)
	if !ok || len(b.rows) != 1 || b.rows[0].Digest != "bbb" {
		t.Fatalf("tenant b leaked or missed: %+v ok=%v", b, ok)
	}
	if _, ok := c.get("owner:a", now.Add(clusterListCacheTTL)); ok {
		t.Fatal("expired tenant-a entry was still served")
	}
	c.put("owner:c", now.Add(clusterListCacheTTL), clusterListAggregate[*models.JSBundle]{rows: []*models.JSBundle{{Digest: "ccc"}}})
	if _, ok := c.get("owner:a", now.Add(clusterListCacheTTL)); ok {
		t.Fatal("put did not prune the expired tenant-a entry")
	}
}

func TestClusterListCallerKeyScopesTenants(t *testing.T) {
	if got := clusterListCallerKey(nil); got != "operator" {
		t.Fatalf("nil request = %q", got)
	}
	if got := clusterListCallerKey(httptest.NewRequest(http.MethodGet, "/", nil)); got != "operator" {
		t.Fatalf("unscoped = %q", got)
	}
	op := httptest.NewRequest(http.MethodGet, "/", nil)
	op = op.WithContext(controlplane.ContextWithAccess(op.Context(), controlplane.Access{Operator: true, Identity: controlplane.Identity{OwnerRef: "acme"}}))
	if got := clusterListCallerKey(op); got != "operator" {
		t.Fatalf("operator = %q", got)
	}
	blank := httptest.NewRequest(http.MethodGet, "/", nil)
	blank = blank.WithContext(controlplane.ContextWithAccess(blank.Context(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "  "}}))
	if got := clusterListCallerKey(blank); got != "operator" {
		t.Fatalf("blank owner = %q", got)
	}
	tenant := httptest.NewRequest(http.MethodGet, "/", nil)
	tenant = tenant.WithContext(controlplane.ContextWithAccess(tenant.Context(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acme"}}))
	if got := clusterListCallerKey(tenant); got != "owner:acme" {
		t.Fatalf("tenant = %q", got)
	}
}
