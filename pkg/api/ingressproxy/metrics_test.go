package ingressproxy

import (
	"expvar"
	"sync"
	"testing"
	"time"
)

// TestIssuanceTrackerLifecycle: Started exposes the hostname as an
// expvar gauge whose value is the live age; Completed clears the gauge
// and observes the duration into the histogram. The map must shrink
// when issuance completes — a leak here turns a long-lived sandboxd
// into an unbounded gauge collection.
func TestIssuanceTrackerLifecycle(t *testing.T) {
	clk := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	gauge := new(expvar.Map).Init()
	tr := newIssuanceTrackerWithGauge(gauge)
	tr.now = clk.Now

	tr.Started("api.acme.com")
	if tr.inProgress() != 1 {
		t.Fatalf("inProgress = %d, want 1", tr.inProgress())
	}
	clk.advance(45 * time.Second)
	val := gauge.Get("api.acme.com")
	if val == nil {
		t.Fatal("gauge missing entry for api.acme.com")
	}
	got := val.(expvar.Func)().(float64)
	if got < 44 || got > 46 {
		t.Fatalf("gauge value = %v, want ≈ 45", got)
	}

	tr.completed("api.acme.com")
	if tr.inProgress() != 0 {
		t.Fatalf("inProgress = %d, want 0 after completion", tr.inProgress())
	}
	if gauge.Get("api.acme.com") != nil {
		t.Fatal("gauge still has entry for completed hostname")
	}
}

// TestIssuanceTrackerStartedIdempotent: a duplicate Started call for
// the same host keeps the original start time. Without this the gauge
// would reset every time Caddy retried an ask, undercounting actual
// issuance duration.
func TestIssuanceTrackerStartedIdempotent(t *testing.T) {
	clk := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	gauge := new(expvar.Map).Init()
	tr := newIssuanceTrackerWithGauge(gauge)
	tr.now = clk.Now

	tr.Started("api.acme.com")
	clk.advance(30 * time.Second)
	tr.Started("api.acme.com") // duplicate — must not reset
	clk.advance(15 * time.Second)

	val := gauge.Get("api.acme.com").(expvar.Func)().(float64)
	if val < 44 || val > 46 {
		t.Fatalf("gauge value = %v, want ≈ 45 (start kept original ts)", val)
	}
}

// TestIssuanceTrackerCompletedUntracked: completing an unseen host
// is a no-op. Prevents a stray service-layer call (e.g. status →
// ready arriving before any ask) from skewing the duration histogram.
func TestIssuanceTrackerCompletedUntracked(t *testing.T) {
	gauge := new(expvar.Map).Init()
	tr := newIssuanceTrackerWithGauge(gauge)
	tr.completed("never-started.example.com") // must not panic
	if tr.inProgress() != 0 {
		t.Fatalf("inProgress = %d, want 0", tr.inProgress())
	}
}

// TestRecordAskResultIncrementsExpvar: the package-level counter
// publishes the result label so /debug/vars surfaces F4 (listener
// liveness) as a per-result series.
func TestRecordAskResultIncrementsExpvar(t *testing.T) {
	before := readCounter(t, askRequestsTotal, AskResultOK)
	RecordAskResult(AskResultOK)
	RecordAskResult(AskResultOK)
	RecordAskResult(AskResultUnknown)

	if got := readCounter(t, askRequestsTotal, AskResultOK) - before; got != 2 {
		t.Fatalf("ok delta = %d, want 2", got)
	}
	if got := readCounter(t, askRequestsTotal, AskResultUnknown); got < 1 {
		t.Fatalf("unknown counter not incremented")
	}
}

func readCounter(t *testing.T, m *expvar.Map, key string) int64 {
	t.Helper()
	v := m.Get(key)
	if v == nil {
		return 0
	}
	if iv, ok := v.(*expvar.Int); ok {
		return iv.Value()
	}
	t.Fatalf("counter %q is not *expvar.Int (got %T)", key, v)
	return 0
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
