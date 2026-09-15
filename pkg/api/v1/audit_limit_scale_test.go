package v1

import (
	"fmt"
	"testing"
)

func TestAuditRateLimiterBoundsIdentityMapWithoutChurn(t *testing.T) {
	limiter := NewAuditRateLimiter(AuditRateLimiterConfig{})
	limiter.identityMu.Lock()
	for i := 0; i < auditRateLimitMaxBuckets*2; i++ {
		_ = limiter.limiterFor(fmt.Sprintf("tenant-%d", i))
	}
	got := len(limiter.identity)
	operator := limiter.limiterFor(auditRateLimitIdentityKey)
	limiter.identityMu.Unlock()
	if got != auditRateLimitMaxBuckets {
		t.Fatalf("identity buckets = %d, want hard cap %d", got, auditRateLimitMaxBuckets)
	}
	if operator != limiter.operator {
		t.Fatal("operator traffic must retain its dedicated limiter at identity capacity")
	}
}
