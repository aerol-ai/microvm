package v1

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"golang.org/x/time/rate"
)

const (
	defaultAuditIdentityRate  = 10.0
	defaultAuditIdentityBurst = 20
	defaultAuditOperatorRate  = 50.0
	defaultAuditOperatorBurst = 100
	defaultAuditNodeRate      = 50.0
	defaultAuditNodeBurst     = 100
	auditRateLimitIdentityKey = "operator"
)

// AuditRateLimiter bounds GET /v1/sandboxes/{id}/audit fan-out amplification.
// Per-identity (OwnerRef; operator PAT → "operator") plus a per-node ceiling.
// On reject: 429 + Retry-After — never silent truncation.
type AuditRateLimiter struct {
	identityMu    sync.Mutex
	identity      map[string]*rate.Limiter
	identityRate  rate.Limit
	identityBurst int
	operatorRate  rate.Limit
	operatorBurst int
	node          *rate.Limiter
}

// AuditRateLimiterConfig holds token-bucket rates from config.
type AuditRateLimiterConfig struct {
	IdentityRate float64
	OperatorRate float64
	NodeRate     float64
}

// NewAuditRateLimiter builds limiters with the decided defaults when rates are
// zero/negative.
func NewAuditRateLimiter(cfg AuditRateLimiterConfig) *AuditRateLimiter {
	idRate := cfg.IdentityRate
	if idRate <= 0 {
		idRate = defaultAuditIdentityRate
	}
	opRate := cfg.OperatorRate
	if opRate <= 0 {
		opRate = defaultAuditOperatorRate
	}
	nodeRate := cfg.NodeRate
	if nodeRate <= 0 {
		nodeRate = defaultAuditNodeRate
	}
	return &AuditRateLimiter{
		identity:      make(map[string]*rate.Limiter),
		identityRate:  rate.Limit(idRate),
		identityBurst: defaultAuditIdentityBurst,
		operatorRate:  rate.Limit(opRate),
		operatorBurst: defaultAuditOperatorBurst,
		node:          rate.NewLimiter(rate.Limit(nodeRate), defaultAuditNodeBurst),
	}
}

// Middleware wraps only the public audit route.
func (a *AuditRateLimiter) Middleware(next http.Handler) http.Handler {
	if a == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := auditIdentityKey(r)
		if retry, ok := a.allow(key); !ok {
			sec := int(math.Ceil(retry.Seconds()))
			if sec < 1 {
				sec = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(sec))
			apihttp.WriteError(w, http.StatusTooManyRequests, "audit rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func auditIdentityKey(r *http.Request) string {
	access, ok := controlplane.AccessFromContext(r.Context())
	if !ok || access.Operator {
		return auditRateLimitIdentityKey
	}
	if ref := access.Identity.OwnerRef; ref != "" {
		return ref
	}
	return "anonymous"
}

func (a *AuditRateLimiter) allow(key string) (retryAfter time.Duration, ok bool) {
	a.identityMu.Lock()
	lim := a.limiterFor(key)
	idRes := lim.Reserve()
	a.identityMu.Unlock()
	if !idRes.OK() {
		return time.Second, false
	}
	if d := idRes.Delay(); d > 0 {
		idRes.Cancel()
		return d, false
	}
	nodeRes := a.node.Reserve()
	if !nodeRes.OK() {
		idRes.Cancel()
		return time.Second, false
	}
	if d := nodeRes.Delay(); d > 0 {
		nodeRes.Cancel()
		idRes.Cancel()
		return d, false
	}
	return 0, true
}

func (a *AuditRateLimiter) limiterFor(key string) *rate.Limiter {
	if lim, ok := a.identity[key]; ok {
		return lim
	}
	r, b := a.identityRate, a.identityBurst
	if key == auditRateLimitIdentityKey {
		r, b = a.operatorRate, a.operatorBurst
	}
	lim := rate.NewLimiter(r, b)
	a.identity[key] = lim
	return lim
}
