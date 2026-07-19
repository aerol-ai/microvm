package wasm

import (
	"expvar"
	"strconv"
	"testing"
)

func expvarInt(v expvar.Var) int64 {
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

func TestMetricsExportExpvar(t *testing.T) {
	hitsBefore := expvarInt(metricHit)
	missesBefore := expvarInt(metricMiss)
	refillsBefore := expvarInt(metricRefill)
	spawnFailsBefore := expvarInt(metricSpawnFail)

	m := &Metrics{}
	m.recordHit()
	m.recordMiss()
	m.RecordRefill()
	m.RecordSpawnFail()

	if got := expvarInt(metricHit) - hitsBefore; got != 1 {
		t.Fatalf("hits delta = %d, want 1", got)
	}
	if got := expvarInt(metricMiss) - missesBefore; got != 1 {
		t.Fatalf("misses delta = %d, want 1", got)
	}
	if got := expvarInt(metricRefill) - refillsBefore; got != 1 {
		t.Fatalf("refills delta = %d, want 1", got)
	}
	if got := expvarInt(metricSpawnFail) - spawnFailsBefore; got != 1 {
		t.Fatalf("spawn fails delta = %d, want 1", got)
	}

	snap := m.Stats()
	if snap.Hits != 1 || snap.Misses != 1 || snap.Refilled != 1 || snap.SpawnFail != 1 {
		t.Fatalf("snap = %+v", snap)
	}
	var nilMetrics *Metrics
	if nilMetrics.Stats() != (Snapshot{}) {
		t.Fatal("nil metrics should return empty snapshot")
	}
}
