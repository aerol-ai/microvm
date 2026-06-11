package service

import (
	"testing"
	"time"
)

// TestACMEBudgetAllowsUpToThreshold: the 240th Reserve (capacity 300,
// fraction 0.8) succeeds; the 241st denies. Exact-edge test for the
// daemon-wide LE brake so a config tweak that off-by-ones the threshold
// is caught immediately.
func TestACMEBudgetAllowsUpToThreshold(t *testing.T) {
	clk := newFakeClock()
	b := newBudgetForTest(10, time.Hour, 0.8, clk)
	if b.Threshold() != 8 {
		t.Fatalf("threshold = %d, want 8", b.Threshold())
	}
	for i := 0; i < 8; i++ {
		ok, _ := b.Reserve("sb", "h")
		if !ok {
			t.Fatalf("Reserve #%d denied; expected allow", i+1)
		}
	}
	ok, retry := b.Reserve("sb", "h")
	if ok {
		t.Fatal("Reserve #9 allowed; expected deny")
	}
	if retry <= 0 {
		t.Fatalf("retry = %v, want > 0", retry)
	}
}

// TestACMEBudgetAgesOutWindow: an attempt older than window is pruned
// and frees a slot for the next Reserve. Without sliding-window
// semantics the brake would lock the daemon out forever after one
// burst.
func TestACMEBudgetAgesOutWindow(t *testing.T) {
	clk := newFakeClock()
	b := newBudgetForTest(10, time.Hour, 0.8, clk)
	for i := 0; i < 8; i++ {
		b.Reserve("sb", "h")
	}
	if ok, _ := b.Reserve("sb", "h"); ok {
		t.Fatal("expected deny at threshold")
	}
	clk.Advance(time.Hour + time.Minute)
	ok, _ := b.Reserve("sb", "h")
	if !ok {
		t.Fatal("expected allow after window slide")
	}
	if got := b.InWindow(); got != 1 {
		t.Fatalf("in-window = %d, want 1 (only the post-slide attempt)", got)
	}
}

// TestACMEBudgetRetryAfterMatchesOldest: retry-after is the time until
// the oldest in-window attempt ages out. Caddy uses this header to
// pause issuance; an inflated value silently delays valid renewals.
func TestACMEBudgetRetryAfterMatchesOldest(t *testing.T) {
	clk := newFakeClock()
	b := newBudgetForTest(10, time.Hour, 0.8, clk)
	b.Reserve("sb", "h") // attempt 1 at t=0
	clk.Advance(10 * time.Minute)
	for i := 0; i < 7; i++ {
		b.Reserve("sb", "h") // attempts 2..8 at t=10m
	}
	_, retry := b.Reserve("sb", "h")
	// Oldest attempt was at t=0; window=1h; we're at t=10m; should
	// expire in 50m.
	want := 50 * time.Minute
	if retry < want-time.Second || retry > want+time.Second {
		t.Fatalf("retry = %v, want ≈ %v", retry, want)
	}
}

// TestACMEBudgetNilAlwaysAllows: a disabled budget (nil receiver) is
// the zero-friction default for single-node deployments and tests; the
// TLSAsk hot path must stay one-liner-clean when there's no brake.
func TestACMEBudgetNilAlwaysAllows(t *testing.T) {
	var b *ACMEBudget
	for i := 0; i < 1000; i++ {
		if ok, retry := b.Reserve("sb", "h"); !ok || retry != 0 {
			t.Fatalf("nil budget denied: ok=%v retry=%v", ok, retry)
		}
	}
	if got := b.InWindow(); got != 0 {
		t.Fatalf("nil budget InWindow = %d, want 0", got)
	}
	if got := b.Threshold(); got != 0 {
		t.Fatalf("nil budget Threshold = %d, want 0", got)
	}
}

// TestNewACMEBudgetRejectsBadConfig: invalid config returns nil rather
// than a misbehaving bucket — this is what makes the nil receiver
// pattern safe at the call site.
func TestNewACMEBudgetRejectsBadConfig(t *testing.T) {
	cases := []ACMEBudgetConfig{
		{Capacity: 0, Window: time.Hour, Fraction: 0.5},
		{Capacity: 10, Window: 0, Fraction: 0.5},
		{Capacity: 10, Window: time.Hour, Fraction: 0},
		{Capacity: 10, Window: time.Hour, Fraction: 1},
		{Capacity: 10, Window: time.Hour, Fraction: 1.5},
	}
	for i, c := range cases {
		if got := NewACMEBudget(c); got != nil {
			t.Fatalf("case %d: NewACMEBudget(%+v) = %v, want nil", i, c, got)
		}
	}
}

// TestACMEBudgetThrottleHookFires: the test hook lets the TLSAsk
// observability counter increment without the budget reaching into
// expvar directly (keeps the package boundary clean).
func TestACMEBudgetThrottleHookFires(t *testing.T) {
	clk := newFakeClock()
	b := newBudgetForTest(2, time.Hour, 0.5, clk) // threshold=1
	var got struct {
		sandbox string
		retry   time.Duration
		fired   int
	}
	b.onThrottle = func(sandboxID string, retry time.Duration) {
		got.sandbox = sandboxID
		got.retry = retry
		got.fired++
	}
	b.Reserve("sb-a", "h") // allow (at threshold)
	b.Reserve("sb-b", "h") // deny
	if got.fired != 1 {
		t.Fatalf("hook fired %d times, want 1", got.fired)
	}
	if got.sandbox != "sb-b" {
		t.Fatalf("hook sandbox = %q, want sb-b", got.sandbox)
	}
	if got.retry <= 0 {
		t.Fatalf("hook retry = %v, want > 0", got.retry)
	}
}

func newBudgetForTest(capacity int, window time.Duration, fraction float64, clk *fakeClock) *ACMEBudget {
	b := NewACMEBudget(ACMEBudgetConfig{
		Capacity: capacity,
		Window:   window,
		Fraction: fraction,
	})
	if b == nil {
		return nil
	}
	b.now = clk.Now
	return b
}
