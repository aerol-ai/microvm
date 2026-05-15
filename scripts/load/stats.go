package main

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// statsRecorder accumulates per-op latency series so the harness can print
// p50/p95/p99 at exit. The CSV is the canonical artifact for analysis; the
// stderr summary is so an operator running the harness interactively gets
// the headline numbers without having to load the CSV into a notebook.
type statsRecorder struct {
	mu sync.Mutex
	// Per-op samples. Keys are the same op strings produced by runOnce
	// ("create", "probe", "destroy").
	durations map[string][]time.Duration
	// Per-op status code histograms. Used to spot 5xx surges that the
	// percentile view alone would hide (a fast 500 is still a 500).
	statuses map[string]map[int]int
	// route_lag is reported separately because for the "probe" op it is
	// the load-bearing SLO (placement-to-ingress convergence) — having it
	// merged with raw HTTP latency would obscure it.
	probeLags []time.Duration
	// dropped counts ticks the rate driver couldn't dispatch because the
	// concurrency cap was full. Spikes here mean the cluster is keeping
	// up worse than the requested rate.
	dropped atomic.Int64
}

func newStatsRecorder() *statsRecorder {
	return &statsRecorder{
		durations: make(map[string][]time.Duration),
		statuses:  make(map[string]map[int]int),
	}
}

func (s *statsRecorder) record(sm sample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durations[sm.op] = append(s.durations[sm.op], sm.dur)
	if _, ok := s.statuses[sm.op]; !ok {
		s.statuses[sm.op] = make(map[int]int)
	}
	s.statuses[sm.op][sm.status]++
	if sm.op == "probe" {
		s.probeLags = append(s.probeLags, sm.routeLag)
	}
}

func (s *statsRecorder) printSummary(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "----- ingress_churn summary -----")
	if dropped := s.dropped.Load(); dropped > 0 {
		fmt.Fprintf(w, "ticks dropped (concurrency saturated): %d\n", dropped)
	}

	// Stable order so successive runs are visually comparable.
	ops := make([]string, 0, len(s.durations))
	for op := range s.durations {
		ops = append(ops, op)
	}
	sort.Strings(ops)

	for _, op := range ops {
		series := append([]time.Duration(nil), s.durations[op]...)
		printPercentiles(w, op+" latency", series)
		// Status code breakdown in deterministic order.
		codes := make([]int, 0, len(s.statuses[op]))
		for code := range s.statuses[op] {
			codes = append(codes, code)
		}
		sort.Ints(codes)
		fmt.Fprintf(w, "  %s status codes:", op)
		for _, code := range codes {
			fmt.Fprintf(w, " %d=%d", code, s.statuses[op][code])
		}
		fmt.Fprintln(w)
	}

	if len(s.probeLags) > 0 {
		printPercentiles(w, "placement-to-ingress convergence", append([]time.Duration(nil), s.probeLags...))
	}
}

// printPercentiles sorts series in place and writes p50/p95/p99/max to w.
// SLO targets are inlined in the label so a reader doesn't have to hold the
// stage-2 release-gate doc open in another tab.
func printPercentiles(w io.Writer, label string, series []time.Duration) {
	if len(series) == 0 {
		return
	}
	sort.Slice(series, func(i, j int) bool { return series[i] < series[j] })
	fmt.Fprintf(w, "%s (n=%d):\n", label, len(series))
	fmt.Fprintf(w, "  p50=%s p95=%s p99=%s max=%s\n",
		fmtMs(percentile(series, 0.50)),
		fmtMs(percentile(series, 0.95)),
		fmtMs(percentile(series, 0.99)),
		fmtMs(series[len(series)-1]),
	)
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	// Nearest-rank: index = ceil(q * n) - 1, clamped to [0, n-1]. Same
	// definition Prometheus's histogram_quantile uses on its top end, and
	// avoids the "interpolate between two adjacent samples" complexity
	// that doesn't change anything at the n we'll see.
	idx := int(q * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func fmtMs(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
}
