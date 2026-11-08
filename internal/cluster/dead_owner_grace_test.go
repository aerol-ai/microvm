package cluster

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// The ownership lease is half the dead-owner grace, and the grace keeps its
// 30s default for a Config built without config.Load.
func TestDeadOwnerGraceAndOwnershipLease(t *testing.T) {
	for _, tc := range []struct {
		grace     time.Duration
		wantGrace time.Duration
		wantLease time.Duration
	}{
		{grace: 0, wantGrace: 30 * time.Second, wantLease: 15 * time.Second},
		{grace: -time.Second, wantGrace: 30 * time.Second, wantLease: 15 * time.Second},
		{grace: 10 * time.Second, wantGrace: 10 * time.Second, wantLease: 5 * time.Second},
	} {
		cfg := config.Config{ClusterDeadOwnerGrace: tc.grace}
		if got := DeadOwnerGrace(cfg); got != tc.wantGrace {
			t.Errorf("DeadOwnerGrace(%s) = %s, want %s", tc.grace, got, tc.wantGrace)
		}
		if got := OwnershipLease(cfg); got != tc.wantLease {
			t.Errorf("OwnershipLease(%s) = %s, want %s", tc.grace, got, tc.wantLease)
		}
	}
}
