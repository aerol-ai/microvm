package dockerpool

import (
	"expvar"
	"sync/atomic"
)

// The aerolvm_ prefix is load-bearing: observability's expvar exporter only
// publishes aerolvm_-prefixed vars into /v1/metrics, so anything without it
// is invisible to Prometheus (readable only via the authed /debug/vars).
// Names align with the netns pool's aerolvm_docker_netns_pool_* family.
var (
	metricHit         = expvar.NewInt("aerolvm_docker_pool_hits_total")
	metricMiss        = expvar.NewInt("aerolvm_docker_pool_misses_total")
	metricRefill      = expvar.NewInt("aerolvm_docker_pool_refills_total")
	metricOrphan      = expvar.NewInt("aerolvm_docker_pool_orphans_total")
	metricParked      = expvar.NewInt("aerolvm_docker_pool_parked")
	metricStaleImage  = expvar.NewInt("aerolvm_docker_pool_stale_images_total")
	metricSpawnFail   = expvar.NewInt("aerolvm_docker_pool_spawn_fails_total")
	metricTargetEvict = expvar.NewInt("aerolvm_docker_pool_target_evictions_total")
	adoptMS           = expvar.NewFloat("aerolvm_docker_pool_adopt_ms")
)

// Metrics exposes pool counters for tests and expvar export.
type Metrics struct {
	hits         atomic.Int64
	misses       atomic.Int64
	refilled     atomic.Int64
	orphans      atomic.Int64
	staleImage   atomic.Int64
	spawnFail    atomic.Int64
	targetEvicts atomic.Int64
}

// Snapshot is a point-in-time view of pool counters.
type Snapshot struct {
	Hits         int64
	Misses       int64
	Refilled     int64
	Orphans      int64
	StaleImages  int64
	SpawnFail    int64
	TargetEvicts int64
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

func (m *Metrics) recordTargetEvict() {
	m.targetEvicts.Add(1)
	metricTargetEvict.Add(1)
}

func (m *Metrics) setParked(n int) { metricParked.Set(int64(n)) }

// RecordAdoptMS publishes the latest successful adopt handshake duration.
// Exported because the adopt happens in pkg/docker, not in this package.
func (m *Metrics) RecordAdoptMS(ms float64) {
	if m == nil {
		return
	}
	adoptMS.Set(ms)
}

// Stats returns current counter values.
func (m *Metrics) Stats() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Hits:         m.hits.Load(),
		Misses:       m.misses.Load(),
		Refilled:     m.refilled.Load(),
		Orphans:      m.orphans.Load(),
		StaleImages:  m.staleImage.Load(),
		SpawnFail:    m.spawnFail.Load(),
		TargetEvicts: m.targetEvicts.Load(),
	}
}
