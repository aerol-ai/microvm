package harness

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLatencySummaryNearestRank(t *testing.T) {
	cases := []struct {
		name string
		in   []time.Duration
		want LatencySummary
	}{
		{name: "empty", want: LatencySummary{}},
		{name: "one sample is every percentile", in: []time.Duration{7 * time.Millisecond},
			want: LatencySummary{N: 1, P50MS: 7, P99MS: 7, MaxMS: 7}},
		// 1..100 ms, added out of order: nearest rank puts p50 on the 50th
		// value and p99 on the 99th, never between two.
		{name: "hundred samples", in: func() []time.Duration {
			var d []time.Duration
			for i := 100; i >= 1; i-- {
				d = append(d, time.Duration(i)*time.Millisecond)
			}
			return d
		}(), want: LatencySummary{N: 100, P50MS: 50, P99MS: 99, MaxMS: 100}},
		// Sub-millisecond resolution survives: in-VPC requests are a few ms.
		{name: "fractional ms", in: []time.Duration{1500 * time.Microsecond, 2500 * time.Microsecond},
			want: LatencySummary{N: 2, P50MS: 1.5, P99MS: 2.5, MaxMS: 2.5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var l Latencies
			for _, d := range tc.in {
				l.Add(d)
			}
			if got := l.Summary(); got != tc.want {
				t.Fatalf("Summary() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The probes add from several goroutines at once (run with -race).
func TestLatenciesConcurrentAdd(t *testing.T) {
	var l Latencies
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.Add(time.Millisecond)
			}
		}()
	}
	wg.Wait()
	if s := l.Summary(); s.N != 800 || s.P99MS != 1 {
		t.Fatalf("Summary() = %+v, want 800 samples of 1ms", s)
	}
}

func TestLatencySummaryString(t *testing.T) {
	if got := (LatencySummary{}).String(); got != "n=0" {
		t.Errorf("empty = %q", got)
	}
	got := LatencySummary{N: 3, P50MS: 4.25, P99MS: 9, MaxMS: 9}.String()
	if !strings.Contains(got, "p50 4.2ms") && !strings.Contains(got, "p50 4.3ms") {
		t.Errorf("String() = %q, want the p50 at 0.1ms resolution", got)
	}
	if !strings.Contains(got, "p99 9.0ms") || !strings.Contains(got, "(n=3)") {
		t.Errorf("String() = %q", got)
	}
}

func TestDetailMarkerRoundTrip(t *testing.T) {
	rt := &recordingTB{}
	ReportDetail(rt, "expose-to-200 %dms\nhttp %s", 41, "p50 3.0ms")
	if len(rt.logs) != 1 {
		t.Fatalf("logged %d lines, want 1", len(rt.logs))
	}
	if strings.Contains(rt.logs[0], "\n") {
		t.Fatalf("the marker spans lines (go test -json would split it): %q", rt.logs[0])
	}
	// go test prefixes the line with the caller's file and line.
	got, ok := ParseDetailMarker("    ingress_routing_test.go:300: " + rt.logs[0] + "\n")
	if !ok || got != "expose-to-200 41ms http p50 3.0ms" {
		t.Fatalf("ParseDetailMarker = %q, %v", got, ok)
	}
	for _, line := range []string{"", "plain output", "ucdetail=", "ucdetail=   "} {
		if d, ok := ParseDetailMarker(line); ok {
			t.Errorf("ParseDetailMarker(%q) = %q, want no marker", line, d)
		}
	}
}
