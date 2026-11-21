package gate

import (
	"context"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// The gate's part of a split-mode create, as a paired measurement: every
// round runs the create's containerd calls straight to the stand-in
// containerd (single mode) and through the helper's socket and gate
// (split), in turns, so load on the machine falls on both alike. Runs only
// with AEROL_BUDGET_ROUNDS set (and AEROL_BUDGET_PER_ROUND, default 5):
//
//	AEROL_BUDGET_ROUNDS=25 go test -run TestGateCreateBudget -v ./internal/rootd/gate/
func TestGateCreateBudget(t *testing.T) {
	rounds, per := budgetRounds(t)
	gb := newGateBench(t, 0)
	ctx := namespaces.WithNamespace(context.Background(), testNS)
	var single, split, loads []float64
	n := 0
	for r := range rounds {
		loads = append(loads, loadAvg())
		var s, p []float64
		for k := range per {
			for _, gated := range orderOf(r + k) {
				c := gb.direct
				if gated {
					c = gb.gated
				}
				n++
				t0 := time.Now()
				if err := gateCreate(ctx, t, c, fmt.Sprintf("b-%d", n)); err != nil {
					t.Fatal(err)
				}
				ms := float64(time.Since(t0).Microseconds()) / 1000
				if gated {
					p = append(p, ms)
				} else {
					s = append(s, ms)
				}
			}
		}
		single, split = append(single, median(s)), append(split, median(p))
	}
	t.Logf("gate, one create's containerd calls: %s", pairedSummary(single, split))
	t.Logf("load average (1 min) over the rounds: %.2f to %.2f", slices.Min(loads), slices.Max(loads))
}

// budgetRounds reads the run's size, or skips.
func budgetRounds(t *testing.T) (rounds, per int) {
	rounds, _ = strconv.Atoi(os.Getenv("AEROL_BUDGET_ROUNDS"))
	if rounds <= 0 {
		t.Skip("a measurement: set AEROL_BUDGET_ROUNDS")
	}
	per = 5
	if v, err := strconv.Atoi(os.Getenv("AEROL_BUDGET_PER_ROUND")); err == nil && v > 0 {
		per = v
	}
	return rounds, per
}

// orderOf turns which mode goes first: [single, split] or [split, single].
func orderOf(i int) []bool {
	if i%2 == 0 {
		return []bool{false, true}
	}
	return []bool{true, false}
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// tCrit is the two-sided 95% Student t value for df degrees of freedom.
func tCrit(df int) float64 {
	table := []float64{12.71, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145,
		2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042}
	if df >= 1 && df <= len(table) {
		return table[df-1]
	}
	return 1.96
}

// pairedSummary: each side's median of round medians, and the per-round
// difference (b - a): its mean with a 95% confidence interval, and its
// median.
func pairedSummary(a, b []float64) string {
	d := make([]float64, len(a))
	var mean float64
	for i := range a {
		d[i] = b[i] - a[i]
		mean += d[i]
	}
	mean /= float64(len(d))
	var ss float64
	for _, x := range d {
		ss += (x - mean) * (x - mean)
	}
	half := 0.0
	if len(d) > 1 {
		half = tCrit(len(d)-1) * math.Sqrt(ss/float64(len(d)-1)) / math.Sqrt(float64(len(d)))
	}
	return fmt.Sprintf("single %.2f ms, split %.2f ms; split - single per round: mean %+.2f ms (95%% CI %+.2f to %+.2f), median %+.2f ms, %d rounds",
		median(a), median(b), mean, mean-half, mean+half, median(d), len(d))
}

// loadAvg is the machine's 1-minute load average (the Docker VM's, in a
// container), or -1 where there is none to read.
func loadAvg() float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	f, _ := strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	return f
}
