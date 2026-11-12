// Package usagemetrics keeps per-owner usage counters on one worker, for
// /v1/metrics (plans/kubernetes-v2-architecture.md, C20).
//
// Why it lives on each worker: Prometheus scrapes every worker and a
// recording rule sums rate() by owner. Nothing is added up in the leader,
// so a leader change, a worker restart or a worker that leaves can neither
// lose nor double-count what was already scraped. Each process labels its
// series with its own incarnation, so a restart starts new series instead
// of making a counter go backwards.
//
// Two numbers per owner (CEO review RQ16):
//   - reserved: each running sandbox's CPU and memory limit times the time
//     it ran. This is the charge: it is what the worker's machine is paid
//     for, and it is known for every runtime.
//   - consumed: CPU time and memory measured from the sandbox's cgroup.
//     It is shown next to the charge and never changes it.
//
// The units are vCPU-seconds and MiB-seconds, never money. The MiB matches
// Sandbox.MemoryMB, which the rest of AerolVM treats as MiB, and the
// "mib-s" unit of the managed usage samples (internal/service/usage.go).
package usagemetrics

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Metric names. Counters end in _total, as every counter on /v1/metrics
// does.
const (
	MetricReservedCPU    = "aerolvm_usage_reserved_cpu_seconds_total"
	MetricReservedMemory = "aerolvm_usage_reserved_memory_mib_seconds_total"
	MetricConsumedCPU    = "aerolvm_usage_consumed_cpu_seconds_total"
	MetricConsumedMemory = "aerolvm_usage_consumed_memory_mib_seconds_total"
	MetricReadFailures   = "aerolvm_usage_consumed_read_failures_total"
	MetricLastSample     = "aerolvm_usage_last_sample_timestamp_seconds"
)

// OwnerRetention is how long an owner's series stay after its last
// sandbox on this worker stops or leaves. Prometheus must scrape the final
// value at least once, or the last increase is lost; an hour is many
// scrapes. Dropping the series after that keeps the series count bounded
// by the owners active in the last hour, not every owner the worker has
// ever run. If the owner comes back later, its counter starts again at
// zero, and rate() reads that as a counter reset, which it handles.
const OwnerRetention = time.Hour

// Sandbox is one sandbox row as a sample sees it.
type Sandbox struct {
	ID       string
	Owner    string
	CPU      float64
	MemoryMB int
	// Running is true while the sandbox is started. Only a running sandbox
	// holds its CPU and memory, so only it is charged.
	Running   bool
	CreatedAt time.Time
	// UpdatedAt is the row's last write. For a sandbox that is no longer
	// running, it is no earlier than the stop, so it is where the charge
	// ends.
	UpdatedAt time.Time
	// Consumed is the measured use, or nil when it was not read (a runtime
	// with no cgroup per sandbox, or a failed read).
	Consumed *Consumed
}

// Consumed is one reading of a sandbox's cgroup.
type Consumed struct {
	// CPUSeconds is the CPU time the cgroup has used since it was made. It
	// only grows, until the cgroup is made anew by a restart.
	CPUSeconds float64
	// MemoryBytes is the memory the cgroup holds now.
	MemoryBytes uint64
}

// Family is one metric with all its series, ready to print in the
// Prometheus text format.
type Family struct {
	Name    string
	Help    string
	Type    string // "counter" or "gauge"
	Samples []Sample
}

// Sample is one series of a family.
type Sample struct {
	Labels []Label
	Value  float64
}

// Label is one label of a series.
type Label struct {
	Name  string
	Value string
}

// NewIncarnation returns a label value that is new for each process
// start, so two runs of sandboxd on one worker never share a series.
func NewIncarnation() string {
	var b [8]byte
	// crypto/rand.Read never returns an error (Go 1.24 and later).
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Meter holds the counters of one sandboxd process. It is safe for
// concurrent use: the sampler calls Observe, the destroy path calls Close,
// and /v1/metrics calls Collect.
type Meter struct {
	incarnation string
	start       time.Time

	mu       sync.Mutex
	lastTick time.Time
	open     map[string]*cursor
	// closed holds sandboxes Close took out since the last Observe. The
	// sampler reads the store before it calls Observe, so that read can
	// still list a sandbox that was destroyed a moment later. Without this
	// set, Observe would open it again and charge it twice.
	closed       map[string]struct{}
	owners       map[string]*ownerTotals
	readFailures uint64
}

// cursor is one running sandbox: how far it has been charged, and at what
// size.
type cursor struct {
	owner    string
	cpu      float64
	memoryMB int
	// since is where the reserved charge has reached.
	since time.Time
	// memSince is where the consumed memory charge has reached. It lags
	// since when a cgroup read fails, and the next good reading covers the
	// gap.
	memSince time.Time
	// cpuSeconds is the last CPU reading; hasCPU says there was one.
	cpuSeconds float64
	hasCPU     bool
	// fresh is true for a sandbox made during this process. Its cgroup's
	// whole CPU count was used during this incarnation, so the first
	// reading counts in full. For an older sandbox, the first reading is
	// only a baseline: the previous incarnation counted what came before.
	fresh bool
}

type ownerTotals struct {
	reservedCPU    float64
	reservedMemory float64
	consumedCPU    float64
	consumedMemory float64
	open           int
	idleSince      time.Time
}

// NewMeter returns an empty meter for a process that started at start.
func NewMeter(incarnation string, start time.Time) *Meter {
	return &Meter{
		incarnation: incarnation,
		start:       start,
		open:        map[string]*cursor{},
		closed:      map[string]struct{}{},
		owners:      map[string]*ownerTotals{},
	}
}

// Incarnation is the label value of this meter's series.
func (m *Meter) Incarnation() string { return m.incarnation }

// Observe takes one sample at now: every sandbox row on this worker, with
// a cgroup reading for the running ones, and how many readings failed.
//
// A running sandbox is charged from where its last sample left off. One
// seen for the first time is charged from the last sample, or from its
// creation if that came later, or from the process start on the first
// sample. A sandbox that stopped is charged up to its row's last write, and
// one that vanished without a Close is charged up to the last sample only:
// with no stop time, AerolVM charges less rather than more.
func (m *Meter) Observe(now time.Time, sandboxes []Sandbox, readFailures int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	from := m.lastTick
	if from.IsZero() {
		from = m.start
	}
	if now.Before(from) {
		// The clock stepped back. Charging nothing beats a negative charge.
		now = from
	}
	running := make(map[string]struct{}, len(sandboxes))
	for i := range sandboxes {
		sb := &sandboxes[i]
		if _, gone := m.closed[sb.ID]; gone {
			continue
		}
		c := m.open[sb.ID]
		if !sb.Running {
			if c != nil {
				m.closeLocked(sb.ID, c, clampTime(sb.UpdatedAt, c.since, now))
			}
			continue
		}
		running[sb.ID] = struct{}{}
		if c == nil {
			c = m.openLocked(sb, from, now)
		}
		// The window since the last sample is charged at the size the
		// sandbox had then; a resize counts from this sample on.
		m.chargeReservedLocked(c, now)
		c.cpu, c.memoryMB = sb.CPU, sb.MemoryMB
		if sb.Consumed != nil {
			m.chargeConsumedLocked(c, *sb.Consumed, now)
		}
	}
	for id, c := range m.open {
		if _, ok := running[id]; !ok {
			m.closeLocked(id, c, c.since)
		}
	}
	clear(m.closed)
	if readFailures > 0 {
		m.readFailures += uint64(readFailures)
	}
	m.lastTick = now
	for owner, o := range m.owners {
		if o.open == 0 && now.Sub(o.idleSince) >= OwnerRetention {
			delete(m.owners, owner)
		}
	}
}

// Close charges a sandbox up to at and stops charging it. The service
// calls it when it deletes a sandbox's row, so a sandbox removed between
// two samples is charged up to its removal, not to the next sample. A nil
// meter (the exporter is off) does nothing.
func (m *Meter) Close(id string, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed[id] = struct{}{}
	if c := m.open[id]; c != nil {
		m.closeLocked(id, c, at)
	}
}

func (m *Meter) openLocked(sb *Sandbox, from, now time.Time) *cursor {
	since := from
	if sb.CreatedAt.After(since) {
		since = sb.CreatedAt
	}
	if since.After(now) {
		since = now
	}
	c := &cursor{
		owner:    sb.Owner,
		cpu:      sb.CPU,
		memoryMB: sb.MemoryMB,
		since:    since,
		memSince: since,
		fresh:    !sb.CreatedAt.Before(m.start),
	}
	m.open[sb.ID] = c
	o := m.owners[sb.Owner]
	if o == nil {
		o = &ownerTotals{}
		m.owners[sb.Owner] = o
	}
	o.open++
	return c
}

func (m *Meter) closeLocked(id string, c *cursor, at time.Time) {
	m.chargeReservedLocked(c, at)
	delete(m.open, id)
	o := m.owners[c.owner]
	o.open--
	if o.open == 0 {
		o.idleSince = at
	}
}

func (m *Meter) chargeReservedLocked(c *cursor, at time.Time) {
	d := at.Sub(c.since).Seconds()
	if d <= 0 {
		return
	}
	o := m.owners[c.owner]
	o.reservedCPU += max(c.cpu, 0) * d
	o.reservedMemory += float64(max(c.memoryMB, 0)) * d
	c.since = at
}

func (m *Meter) chargeConsumedLocked(c *cursor, r Consumed, now time.Time) {
	o := m.owners[c.owner]
	switch {
	case c.hasCPU && r.CPUSeconds >= c.cpuSeconds:
		o.consumedCPU += r.CPUSeconds - c.cpuSeconds
	case c.hasCPU || c.fresh:
		// A count below the last one is a new cgroup (the task restarted
		// and started again from zero), and a fresh sandbox's cgroup began
		// in this process: either way, all of it is new use.
		o.consumedCPU += r.CPUSeconds
	}
	c.cpuSeconds, c.hasCPU = r.CPUSeconds, true
	if d := now.Sub(c.memSince).Seconds(); d > 0 {
		o.consumedMemory += float64(r.MemoryBytes) / (1 << 20) * d
		c.memSince = now
	}
}

// Collect returns every family with its current values. An owner appears
// only once one of its sandboxes ran on this worker during this process,
// and goes OwnerRetention after its last one stopped.
func (m *Meter) Collect() []Family {
	m.mu.Lock()
	defer m.mu.Unlock()
	owners := make([]string, 0, len(m.owners))
	for owner := range m.owners {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	inc := Label{Name: "incarnation", Value: m.incarnation}
	perOwner := func(name, help string, value func(*ownerTotals) float64) Family {
		f := Family{Name: name, Help: help, Type: "counter"}
		for _, owner := range owners {
			f.Samples = append(f.Samples, Sample{
				Labels: []Label{{Name: "owner", Value: owner}, inc},
				Value:  value(m.owners[owner]),
			})
		}
		return f
	}
	out := []Family{
		perOwner(MetricReservedCPU,
			"vCPU-seconds reserved by an owner's running sandboxes on this worker: each sandbox's CPU limit times the time it ran. The charge.",
			func(o *ownerTotals) float64 { return o.reservedCPU }),
		perOwner(MetricReservedMemory,
			"MiB-seconds reserved by an owner's running sandboxes on this worker: each sandbox's memory limit times the time it ran. The charge.",
			func(o *ownerTotals) float64 { return o.reservedMemory }),
		perOwner(MetricConsumedCPU,
			"CPU-seconds an owner's sandboxes on this worker used, from their cgroups. Shown next to the charge; never billed.",
			func(o *ownerTotals) float64 { return o.consumedCPU }),
		perOwner(MetricConsumedMemory,
			"MiB-seconds of memory an owner's sandboxes on this worker held, from their cgroups. Shown next to the charge; never billed.",
			func(o *ownerTotals) float64 { return o.consumedMemory }),
		{
			Name:    MetricReadFailures,
			Help:    "Cgroup readings of running sandboxes that failed. Their consumed use is missing for that sample.",
			Type:    "counter",
			Samples: []Sample{{Labels: []Label{inc}, Value: float64(m.readFailures)}},
		},
	}
	if !m.lastTick.IsZero() {
		out = append(out, Family{
			Name:    MetricLastSample,
			Help:    "Unix time of the last usage sample. An old value means the usage counters have stopped moving.",
			Type:    "gauge",
			Samples: []Sample{{Labels: []Label{inc}, Value: float64(m.lastTick.UnixNano()) / 1e9}},
		})
	}
	return out
}

// clampTime returns t limited to [lo, hi].
func clampTime(t, lo, hi time.Time) time.Time {
	if t.Before(lo) {
		return lo
	}
	if t.After(hi) {
		return hi
	}
	return t
}
