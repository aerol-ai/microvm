package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	// 100 samples 1ms..100ms (sorted). Nearest-rank p50=50ms, p95=95ms,
	// p99=99ms. Confirms the percentile helper does what the harness
	// summary claims it does — without this, "p95=2s" claims in the
	// release artifact would be a vibe.
	series := make([]time.Duration, 100)
	for i := range series {
		series[i] = time.Duration(i+1) * time.Millisecond
	}
	cases := []struct {
		q    float64
		want time.Duration
	}{
		{0.50, 51 * time.Millisecond}, // ceil(0.5*100)=50, idx 50 → value 51
		{0.95, 96 * time.Millisecond},
		{0.99, time.Duration(100) * time.Millisecond},
	}
	for _, tc := range cases {
		got := percentile(series, tc.q)
		if got != tc.want {
			t.Errorf("percentile(q=%v) = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestPrintSummaryShape(t *testing.T) {
	rec := newStatsRecorder()
	rec.record(sample{op: "create", dur: 5 * time.Millisecond, status: 200})
	rec.record(sample{op: "create", dur: 10 * time.Millisecond, status: 200})
	rec.record(sample{op: "probe", dur: 30 * time.Millisecond, status: 200, routeLag: 250 * time.Millisecond})
	rec.dropped.Add(2)

	var buf bytes.Buffer
	rec.printSummary(&buf)
	out := buf.String()

	for _, want := range []string{
		"ticks dropped (concurrency saturated): 2",
		"create latency",
		"probe latency",
		"placement-to-ingress convergence",
		"200=2", // create status histogram
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n--- output ---\n%s", want, out)
		}
	}
}
