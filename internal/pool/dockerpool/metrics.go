package dockerpool

import (
	"expvar"
	"sync/atomic"
)

var (
	metricHit        = expvar.NewInt("docker_pool_hit")
	metricMiss       = expvar.NewInt("docker_pool_miss")
	metricRefill     = expvar.NewInt("docker_pool_refill")
	metricOrphan     = expvar.NewInt("docker_pool_orphan")
	metricParked     = expvar.NewInt("docker_pool_parked")
	metricStaleImage = expvar.NewInt("docker_pool_stale_image")
	metricSpawnFail  = expvar.NewInt("docker_pool_spawn_fail")
	adoptMS          = expvar.NewFloat("docker_pool_adopt_ms")
)

// Metrics exposes pool counters for tests and expvar export.
type Metrics struct {
	hits       atomic.Int64
	misses     atomic.Int64
	refilled   atomic.Int64
	orphans    atomic.Int64
	staleImage atomic.Int64
	spawnFail  atomic.Int64
}

// Snapshot is a point-in-time view of pool counters.
type Snapshot struct {
	Hits        int64
	Misses      int64
	Refilled    int64
	Orphans     int64
	StaleImages int64
	SpawnFail   int64
}

func (m *Metrics) recordHit() {
	m.hits.Add(1)
	metricHit.Add(1)
}

func (m *Metrics) recordMiss() {
	m.misses.Add(1)
	metricMiss.Add(1)
}

func (m *Metrics) recordRefill() {
	m.refilled.Add(1)
	metricRefill.Add(1)
}

func (m *Metrics) recordOrphan() {
	m.orphans.Add(1)
	metricOrphan.Add(1)
}

func (m *Metrics) recordStaleImage() {
	m.staleImage.Add(1)
	metricStaleImage.Add(1)
}

func (m *Metrics) RecordSpawnFail() {
	m.spawnFail.Add(1)
	metricSpawnFail.Add(1)
}

func (m *Metrics) setParked(n int) { metricParked.Set(int64(n)) }

func (m *Metrics) recordAdoptMS(ms float64) { adoptMS.Set(ms) }

// Stats returns current counter values.
func (m *Metrics) Stats() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Hits:        m.hits.Load(),
		Misses:      m.misses.Load(),
		Refilled:    m.refilled.Load(),
		Orphans:     m.orphans.Load(),
		StaleImages: m.staleImage.Load(),
		SpawnFail:   m.spawnFail.Load(),
	}
}
