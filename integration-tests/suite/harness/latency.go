package harness

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Latencies collects request durations from many probe goroutines at once.
// UC-171 uses it for the routing A/B (plans/cluster-phase-2.md §4.2): the
// flag's pass rule is "no worse than flag-off", which needs the fresh
// connection latency of every successful probe, not only a failure count.
type Latencies struct {
	mu sync.Mutex
	d  []time.Duration
}

// Add records one successful probe's duration.
func (l *Latencies) Add(d time.Duration) {
	l.mu.Lock()
	l.d = append(l.d, d)
	l.mu.Unlock()
}

// LatencySummary is the shape the bank report stores. Milliseconds as
// floats, because a fresh in-VPC request takes a few ms and whole
// milliseconds would round the A/B's difference away.
type LatencySummary struct {
	N     int     `json:"n"`
	P50MS float64 `json:"p50_ms"`
	P99MS float64 `json:"p99_ms"`
	MaxMS float64 `json:"max_ms"`
}

// Summary returns the nearest-rank p50, p99 and max of what was added.
// Nearest-rank, not interpolation: every reported value is a latency some
// probe really saw, and the bank cases (bankSummarize) rank the same way.
func (l *Latencies) Summary() LatencySummary {
	l.mu.Lock()
	s := append([]time.Duration(nil), l.d...)
	l.mu.Unlock()
	if len(s) == 0 {
		return LatencySummary{}
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	rank := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		if i < 0 {
			i = 0
		}
		return float64(s[i].Microseconds()) / 1000
	}
	return LatencySummary{N: len(s), P50MS: rank(0.50), P99MS: rank(0.99), MaxMS: rank(1)}
}

func (s LatencySummary) String() string {
	if s.N == 0 {
		return "n=0"
	}
	return fmt.Sprintf("p50 %.1fms p99 %.1fms max %.1fms (n=%d)", s.P50MS, s.P99MS, s.MaxMS, s.N)
}
