package dockerpool

import "testing"

func TestMetricsStatsAndCounters(t *testing.T) {
	m := &Metrics{}
	m.recordHit()
	m.recordMiss()
	m.recordRefill()
	m.recordOrphan()
	m.recordStaleImage()
	m.RecordSpawnFail()
	m.setParked(3)
	m.recordAdoptMS(12.5)

	snap := m.Stats()
	if snap.Hits != 1 || snap.Misses != 1 || snap.Refilled != 1 ||
		snap.Orphans != 1 || snap.StaleImages != 1 || snap.SpawnFail != 1 {
		t.Fatalf("snap = %+v", snap)
	}
	var nilMetrics *Metrics
	if nilMetrics.Stats() != (Snapshot{}) {
		t.Fatal("nil metrics should return empty snapshot")
	}
}
