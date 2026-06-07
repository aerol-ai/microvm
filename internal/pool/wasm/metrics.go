package wasm

import "sync/atomic"

// Metrics tracks warm-pool hit/miss and refill counters (expvar-friendly via Snapshot).
type Metrics struct {
	Hits      atomic.Int64
	Misses    atomic.Int64
	Refilled  atomic.Int64
	SpawnFail atomic.Int64
}

// Snapshot returns a point-in-time view of pool counters.
type Snapshot struct {
	Hits      int64
	Misses    int64
	Refilled  int64
	SpawnFail int64
}

func (m *Metrics) recordHit()  { m.Hits.Add(1) }
func (m *Metrics) recordMiss() { m.Misses.Add(1) }

func (m *Metrics) RecordRefill()    { m.Refilled.Add(1) }
func (m *Metrics) RecordSpawnFail() { m.SpawnFail.Add(1) }

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
