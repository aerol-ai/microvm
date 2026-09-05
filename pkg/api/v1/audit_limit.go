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
	auditRateLimitIdleTTL     = 30 * time.Minute
	auditRateLimitEvictEvery  = time.Minute
	auditRateLimitMaxBuckets  = 10_000
)

type auditRateBucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// AuditRateLimiter bounds GET /v1/sandboxes/{id}/audit fan-out amplification.
// Per-identity (OwnerRef; operator PAT → "operator") plus a per-node ceiling.
// On reject: 429 + Retry-After — never silent truncation.
type AuditRateLimiter struct {
	identityMu    sync.Mutex
	identity      map[string]*auditRateBucket
	identityRate  rate.Limit
	identityBurst int
	operator      *rate.Limiter
	overflow      *rate.Limiter
	node          *rate.Limiter
	lastEvict     time.Time
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
		identity:      make(map[string]*auditRateBucket),
		identityRate:  rate.Limit(idRate),
		identityBurst: defaultAuditIdentityBurst,
		operator:      rate.NewLimiter(rate.Limit(opRate), defaultAuditOperatorBurst),
		overflow:      rate.NewLimiter(rate.Limit(idRate), defaultAuditIdentityBurst),
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
	if key == auditRateLimitIdentityKey {
		return a.operator
	}
	now := time.Now()
	if a.lastEvict.IsZero() || now.Sub(a.lastEvict) >= auditRateLimitEvictEvery {
		a.evictIdleLocked(now)
		a.lastEvict = now
	}
	if b, ok := a.identity[key]; ok {
		b.lastSeen = now
		return b.lim
	}
	if len(a.identity) >= auditRateLimitMaxBuckets {
		// Do not churn the map or scan 10K buckets for every attacker-supplied
		// identity. New identities share one bounded overflow bucket until the
		// periodic idle sweep frees capacity.
		return a.overflow
	}
	lim := rate.NewLimiter(a.identityRate, a.identityBurst)
	a.identity[key] = &auditRateBucket{lim: lim, lastSeen: now}
	return lim
}

func (a *AuditRateLimiter) evictIdleLocked(now time.Time) {
	for k, b := range a.identity {
		if now.Sub(b.lastSeen) > auditRateLimitIdleTTL {
			delete(a.identity, k)
		}
	}
}
