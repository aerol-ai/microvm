package gate

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// BenchmarkGateCreateAlone is one create's containerd calls with nothing
// else running, directly (single mode) and through the helper's socket and
// gate (split mode), one of each per iteration, the order turning each
// time so drift hits both alike. Reports p50 and p99 of each, and the
// gate's cost per create, split p50 minus single p50, which is what the
// boot-path budget (plans/security-gaps-m1-m4.md §3.7) is held against.
//
//	go test -run '^$' -bench GateCreateAlone -benchtime 2000x ./internal/rootd/gate/
func BenchmarkGateCreateAlone(b *testing.B) {
	gb := newGateBench(b, 0)
	ctx := namespaces.WithNamespace(context.Background(), testNS)
	direct, gated := make([]time.Duration, 0, b.N), make([]time.Duration, 0, b.N)
	for i := 0; i < b.N; i++ {
		for m := range 2 {
			useGate := (i+m)%2 == 1
			c := gb.direct
			if useGate {
				c = gb.gated
			}
			t0 := time.Now()
			if err := gateCreate(ctx, b, c, fmt.Sprintf("a-%d-%d", i, m)); err != nil {
				b.Fatal(err)
			}
			if d := time.Since(t0); useGate {
				gated = append(gated, d)
			} else {
				direct = append(direct, d)
			}
		}
	}
	if refs := gb.refused(); len(refs) != 0 {
		b.Fatalf("the gate refused the creates: %+v", refs[0])
	}
	b.ReportMetric(float64(percentileOf(direct, 0.5).Microseconds()), "single-p50-us")
	b.ReportMetric(float64(percentileOf(direct, 0.99).Microseconds()), "single-p99-us")
	b.ReportMetric(float64(percentileOf(gated, 0.5).Microseconds()), "split-p50-us")
	b.ReportMetric(float64(percentileOf(gated, 0.99).Microseconds()), "split-p99-us")
	b.ReportMetric(float64((percentileOf(gated, 0.5) - percentileOf(direct, 0.5)).Microseconds()), "gate-p50-us")
}

// BenchmarkGateAdoptAlone is a warm-pool adoption's containerd calls
// (internal/runtime/containerd adoptParked: the new sandbox's ID is free,
// then load, labels, info and relabel of the parked container), directly
// and through the gate, as BenchmarkGateCreateAlone. A warm create makes
// these and no container or task create, so this is the gate's share of
// the +1 ms warm budget.
//
//	go test -run '^$' -bench GateAdoptAlone -benchtime 2000x ./internal/rootd/gate/
func BenchmarkGateAdoptAlone(b *testing.B) {
	gb := newGateBench(b, 0)
	ctx := namespaces.WithNamespace(context.Background(), testNS)
	if err := gateCreate(ctx, b, gb.direct, "parked"); err != nil {
		b.Fatal(err)
	}
	direct, gated := make([]time.Duration, 0, b.N), make([]time.Duration, 0, b.N)
	for i := 0; i < b.N; i++ {
		for m := range 2 {
			useGate := (i+m)%2 == 1
			c := gb.direct
			if useGate {
				c = gb.gated
			}
			t0 := time.Now()
			if _, err := c.LoadContainer(ctx, fmt.Sprintf("sb-new-%d-%d", i, m)); err == nil {
				b.Fatal("the new sandbox's ID is taken")
			}
			ct, err := c.LoadContainer(ctx, "parked")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := ct.Labels(ctx); err != nil {
				b.Fatal(err)
			}
			if _, err := ct.Info(ctx); err != nil {
				b.Fatal(err)
			}
			if _, err := ct.SetLabels(ctx, map[string]string{"aerolvm.sandbox_id": fmt.Sprintf("sb-new-%d-%d", i, m)}); err != nil {
				b.Fatal(err)
			}
			if d := time.Since(t0); useGate {
				gated = append(gated, d)
			} else {
				direct = append(direct, d)
			}
		}
	}
	if refs := gb.refused(); len(refs) != 0 {
		b.Fatalf("the gate refused the adoption: %+v", refs[0])
	}
	b.ReportMetric(float64(percentileOf(direct, 0.5).Microseconds()), "single-p50-us")
	b.ReportMetric(float64(percentileOf(direct, 0.99).Microseconds()), "single-p99-us")
	b.ReportMetric(float64(percentileOf(gated, 0.5).Microseconds()), "split-p50-us")
	b.ReportMetric(float64(percentileOf(gated, 0.99).Microseconds()), "split-p99-us")
	b.ReportMetric(float64((percentileOf(gated, 0.5) - percentileOf(direct, 0.5)).Microseconds()), "gate-p50-us")
}
