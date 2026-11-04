package dnsfilter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"golang.org/x/time/rate"
)

func TestSetOperatorReplacesTheGuard(t *testing.T) {
	f := New(&fakeSources{}, nil, nil, Config{})
	f.SetOperator(egresspolicy.DialGuard{DenyFloor: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}}, nil)
	if len(f.guard().DenyFloor) != 1 {
		t.Fatalf("guard = %+v", f.guard())
	}
	if f.upstream() != nil {
		t.Fatal("upstream should stay unset")
	}
}

func TestSweepDropsIdleLimiters(t *testing.T) {
	f := New(&fakeSources{}, nil, nil, Config{})
	now := time.Now()
	f.limiters["old"] = &limiterEntry{lim: rate.NewLimiter(1, 1), seen: now.Add(-limiterIdle - time.Second)}
	f.limiters["new"] = &limiterEntry{lim: rate.NewLimiter(1, 1), seen: now}
	f.sweepLimitersLocked(now)
	if _, ok := f.limiters["old"]; ok {
		t.Fatal("idle limiter was kept")
	}
	if _, ok := f.limiters["new"]; !ok {
		t.Fatal("fresh limiter was dropped")
	}
}
