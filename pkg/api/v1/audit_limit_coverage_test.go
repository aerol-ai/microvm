package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"golang.org/x/time/rate"
)

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
