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
	metricReclaim     = expvar.NewInt("aerolvm_docker_pool_reclaims_total")
	metricReplaced    = expvar.NewInt("aerolvm_docker_pool_replaced_total")
	// metricDestroyFail counts failed parked-container teardowns, each retry
	// included. The pending gauges are in pending_destroy.go.
	metricDestroyFail = expvar.NewInt("aerolvm_docker_pool_destroy_failures_total")
	adoptMS           = expvar.NewFloat("aerolvm_docker_pool_adopt_ms")
)

// MetricFamily is a second set of process-wide counters a pool also counts
// into. The containerd warm pool is this same queue, so its events have
// always landed in the aerolvm_docker_pool_* series above, which the
// warm-pool dashboards read; that stays as it is. A family adds the
// engine's own series beside it, so a reader can tell the two pools apart
// (aerolvm_containerd_pool_*, TODOS.md: containerdpool exported none).
type MetricFamily struct {
	hits, misses, refills, orphans, spawnFails *expvar.Int
	parked                                     *expvar.Int
}

// NewMetricFamily registers prefix_hits_total, prefix_misses_total,
// prefix_refills_total, prefix_orphans_total, prefix_spawn_fails_total and
// the prefix_parked gauge. Call it once per prefix (package init): expvar
// refuses a name twice.
func NewMetricFamily(prefix string) *MetricFamily {
	return &MetricFamily{
		hits:       expvar.NewInt(prefix + "_hits_total"),
		misses:     expvar.NewInt(prefix + "_misses_total"),
		refills:    expvar.NewInt(prefix + "_refills_total"),
		orphans:    expvar.NewInt(prefix + "_orphans_total"),
		spawnFails: expvar.NewInt(prefix + "_spawn_fails_total"),
		parked:     expvar.NewInt(prefix + "_parked"),
	}
}

// SetMetricFamily makes the pool count into f as well as the shared docker
// series. Set it before the pool is in use (containerdpool.New does).
func (p *Pool) SetMetricFamily(f *MetricFamily) {
	if p == nil || p.metrics == nil {
		return
	}
	p.metrics.family = f
}

// Metrics exposes pool counters for tests and expvar export.
type Metrics struct {
	// family, when set, is counted into alongside the shared series.
	family *MetricFamily

	hits         atomic.Int64
	misses       atomic.Int64
	refilled     atomic.Int64
	orphans      atomic.Int64
	staleImage   atomic.Int64
	spawnFail    atomic.Int64
	targetEvicts atomic.Int64
	reclaims     atomic.Int64
	replaced     atomic.Int64
	destroyFails atomic.Int64
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
	// Reclaims counts parked slots given back to admit a real sandbox. A
	// steady rate means the pool is sized past what the node can spare.
	Reclaims int64
	// Replaced counts parked slots destroyed because their entry's image
	// changed (on_image_change replace_now), before any create used them.
	Replaced int64
	// DestroyFailures counts parked-container teardowns that failed, retries
	// included. Each failed container is kept and retried until it is gone.
	DestroyFailures int64
}

func (m *Metrics) recordHit() {
	m.hits.Add(1)
	metricHit.Add(1)
	if m.family != nil {
		m.family.hits.Add(1)
	}
}

func (m *Metrics) recordMiss() {
	m.misses.Add(1)
	metricMiss.Add(1)
	if m.family != nil {
		m.family.misses.Add(1)
	}
}

func (m *Metrics) recordRefill() {
	m.refilled.Add(1)
	metricRefill.Add(1)
	if m.family != nil {
		m.family.refills.Add(1)
	}
}

func (m *Metrics) recordOrphan() {
	m.orphans.Add(1)
	metricOrphan.Add(1)
	if m.family != nil {
		m.family.orphans.Add(1)
	}
}

func (m *Metrics) recordStaleImage() {
	m.staleImage.Add(1)
	metricStaleImage.Add(1)
}

func (m *Metrics) RecordSpawnFail() {
	m.spawnFail.Add(1)
	metricSpawnFail.Add(1)
	if m.family != nil {
		m.family.spawnFails.Add(1)
	}
}

func (m *Metrics) recordTargetEvict() {
	m.targetEvicts.Add(1)
	metricTargetEvict.Add(1)
}

func (m *Metrics) recordReclaim(n int) {
	m.reclaims.Add(int64(n))
	metricReclaim.Add(int64(n))
}

func (m *Metrics) recordReplaced(n int) {
	m.replaced.Add(int64(n))
	metricReplaced.Add(int64(n))
}

func (m *Metrics) recordDestroyFail() {
	m.destroyFails.Add(1)
	metricDestroyFail.Add(1)
}

func (m *Metrics) setParked(n int) {
	metricParked.Set(int64(n))
	if m.family != nil {
		m.family.parked.Set(int64(n))
	}
}

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
		Reclaims:     m.reclaims.Load(),
		Replaced:     m.replaced.Load(),

		DestroyFailures: m.destroyFails.Load(),
	}
}
