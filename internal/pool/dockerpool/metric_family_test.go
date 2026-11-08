package dockerpool

import "testing"

// testFamily is registered once: expvar refuses a name twice.
var testFamily = NewMetricFamily("aerolvm_test_pool_family")

// A pool with a MetricFamily counts each event into the family as well as
// into its own counters and the shared aerolvm_docker_pool_* series.
func TestMetricFamilyCountsAlongsideSharedSeries(t *testing.T) {
	p := New(nil)
	p.SetMetricFamily(testFamily)
	m := p.Metrics()

	before := map[string]int64{
		"hits":   testFamily.hits.Value(),
		"misses": testFamily.misses.Value(),
		"refill": testFamily.refills.Value(),
		"orphan": testFamily.orphans.Value(),
		"spawn":  testFamily.spawnFails.Value(),
		"shared": metricHit.Value(),
	}
	m.recordHit()
	m.recordMiss()
	m.recordRefill()
	m.recordOrphan()
	m.RecordSpawnFail()
	m.setParked(3)

	got := map[string]int64{
		"hits":   testFamily.hits.Value() - before["hits"],
		"misses": testFamily.misses.Value() - before["misses"],
		"refill": testFamily.refills.Value() - before["refill"],
		"orphan": testFamily.orphans.Value() - before["orphan"],
		"spawn":  testFamily.spawnFails.Value() - before["spawn"],
		"shared": metricHit.Value() - before["shared"],
	}
	for name, delta := range got {
		if delta != 1 {
			t.Errorf("%s delta = %d, want 1", name, delta)
		}
	}
	if v := testFamily.parked.Value(); v != 3 {
		t.Errorf("family parked = %d, want 3", v)
	}
	if s := m.Stats(); s.Hits != 1 || s.Misses != 1 || s.Refilled != 1 || s.Orphans != 1 || s.SpawnFail != 1 {
		t.Errorf("pool's own counters = %+v, want one of each", s)
	}
}

func TestSetMetricFamilyNilSafe(t *testing.T) {
	var p *Pool
	p.SetMetricFamily(testFamily) // must not panic
	(&Pool{}).SetMetricFamily(testFamily)
}
