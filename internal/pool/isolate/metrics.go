package isolate

import (
	"expvar"
	"sync/atomic"
)

// The aerolvm_ prefix is load-bearing: observability's expvar exporter only
// publishes aerolvm_-prefixed vars into /v1/metrics.
var (
	metricHit       = expvar.NewInt("aerolvm_isolate_pool_hits_total")
	metricMiss      = expvar.NewInt("aerolvm_isolate_pool_misses_total")
	metricRefill    = expvar.NewInt("aerolvm_isolate_pool_refills_total")
	metricSpawnFail = expvar.NewInt("aerolvm_isolate_pool_spawn_fails_total")
)

// Metrics are hit/miss/refill counters for expvar-style observation.
type Metrics struct {
	Hits      atomic.Int64
	Misses    atomic.Int64
	Refilled  atomic.Int64
	SpawnFail atomic.Int64
}

// Snapshot is a point-in-time view of pool counters.
type Snapshot struct {
	Hits      int64
	Misses    int64
	Refilled  int64
	SpawnFail int64
}

func (m *Metrics) recordHit() {
	m.Hits.Add(1)
	metricHit.Add(1)
}

func (m *Metrics) recordMiss() {
	m.Misses.Add(1)
	metricMiss.Add(1)
}

func (m *Metrics) recordRefill() {
	m.Refilled.Add(1)
	metricRefill.Add(1)
}

func (m *Metrics) recordSpawnFail() {
	m.SpawnFail.Add(1)
	metricSpawnFail.Add(1)
}

// Stats returns current counter values.
func (m *Metrics) Stats() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Hits:      m.Hits.Load(),
		Misses:    m.Misses.Load(),
		Refilled:  m.Refilled.Load(),
		SpawnFail: m.SpawnFail.Load(),
	}
}
