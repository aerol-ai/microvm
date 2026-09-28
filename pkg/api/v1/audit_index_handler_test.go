package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func operatorAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Operator: true})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func TestAuditPeerRouteIsRateLimitedSeparatelyFromPublic(t *testing.T) {
	limiter := NewAuditRateLimiter(AuditRateLimiterConfig{IdentityRate: 1, OperatorRate: 1, NodeRate: 1})
	// Exhaust the peer bucket; the public buckets stay untouched.
	for i := 0; i < 200; i++ {
		res := limiter.peer.Reserve()
		if !res.OK() || res.Delay() > 0 {
			res.Cancel()
			break
		}
	}
	rr := httptest.NewRecorder()
	limiter.PeerMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("limited request reached the handler")
	})).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("peer limit: status %d retry-after %q", rr.Code, rr.Header().Get("Retry-After"))
	}
	// Public traffic on the same node is unaffected by the peer storm.
	if retry, ok := limiter.allow("operator"); !ok {
		t.Fatalf("public bucket throttled by peer traffic (retry %v)", retry)
	}
	// And the wiring: the internal route carries the peer limiter, the
	// public one the identity/node limiter. Peer auth rejects first here
	// (no mTLS peer), which is fine — we only check that a nil limiter does
	// not break registration and a non-nil one is consulted.
	var nilLimiter *AuditRateLimiter
	passed := false
	nilLimiter.PeerMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed = true })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !passed {
		t.Fatal("nil limiter must pass through")
	}
	h, _ := newAuditTestHandler(t, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, AuditLimiter: limiter, Auth: operatorAuth})
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalSandboxAuditPath+"sb-audit-1/audit", nil))
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusTooManyRequests {
		t.Fatalf("internal audit route without peer identity: status %d", rr.Code)
	}
}

func TestAuditBusyMapsTo429WithRetryAfter(t *testing.T) {
	h, sbID := newAuditTestHandler(t, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: operatorAuth})
	release := service.HoldSecretAuditQuerySlotsForTest()
	defer release()
	started := time.Now()
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sbID+"/audit", nil))
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("saturated node: status %d retry-after %q body %s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("saturated read queued instead of failing fast")
	}
}

func TestAuditVerifyEndpointIsOperatorOnlyAndReportsChain(t *testing.T) {
	h, sbID := newAuditTestHandler(t, nil)
	mux := http.NewServeMux()
	tenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := controlplane.ContextWithAccess(r.Context(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acme"}})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: tenant})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/audit/verify", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("tenant verify: status %d", rr.Code)
	}

	// Produce some evidence, then verify as an operator.
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{DBPath: dbPath, SecretAuditRetentionDays: 30, EgressAttributionEnabled: true, AuditIndexEnabled: true}, h.deps.Logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://a", ""))
	t.Cleanup(svc.CloseSecretAuditSink)
	observe := svc.EgressAuditObserver()
	for i := 0; i < 5; i++ {
		observe(sbID, "tcp", "10.0.0.1:443")
	}
	if err := svc.ValidateSecretAuditSink(); err != nil { // flushes the writer
		t.Fatal(err)
	}
	mux = http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: h.deps.Logger, Auth: operatorAuth})
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/audit/verify", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("operator verify: status %d body %s", rr.Code, rr.Body.String())
	}
	var report service.SecretAuditVerification
	if err := json.Unmarshal(rr.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.OK || !report.WriterTipMatches || report.Head == "" || report.Records != 5 {
		t.Fatalf("report = %+v", report)
	}
	// A verification already in flight is a 429, not a second O(file) pass.
	release := service.HoldSecretAuditVerifyForTest()
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/audit/verify", nil))
	release()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent verify: status %d", rr.Code)
	}
}
