package service

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Neutral usage kinds and units — the wire vocabulary for samples shipped to the
// managed control plane. Defined here (not imported from the private client) so
// the open-source build owns its emission contract; the managed ingest matches
// on these string values.
const (
	usageKindUptime       = "uptime"
	usageKindCPUReserved  = "cpu_reserved"
	usageKindCPULive      = "cpu_live"
	usageKindMemReserved  = "mem_reserved"
	usageKindMemLive      = "mem_live"
	usageKindDiskReserved = "disk_reserved"
	usageKindGPU          = "gpu"
	usageKindEgress       = "egress"
	usageKindIngress      = "ingress"

	usageUnitSeconds    = "s"
	usageUnitVCPUSecond = "vcpu-s"
	usageUnitMiBSecond  = "mib-s"
	usageUnitGiBSecond  = "gib-s"
	usageUnitGPUSecond  = "gpu-s"
	usageUnitBytes      = "bytes"
)

// SetUsageReporter installs the control-plane usage reporter. The managed daemon
// calls this once at boot; the open-source build never does, so usageReporter
// stays nil and every emit path is a no-op that allocates nothing.
func (s *Service) SetUsageReporter(r controlplane.Reporter) {
	s.usageReporter = r
}

// usageEnabled reports whether a reporter is wired. All emit paths short-circuit
// on false so the open-source build does no extra work.
func (s *Service) usageEnabled() bool { return s.usageReporter != nil }

// usageWindowStart returns the start of the next reserved-usage window for a
// sandbox: its cursor if present, else the fallback (clamped so a first-seen
// sandbox never emits an unbounded backfill). It does not advance the cursor.
func (s *Service) usageWindowStart(id string, fallback time.Time) time.Time {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	if t, ok := s.usageCursor[id]; ok {
		return t
	}
	return fallback
}

// advanceUsageCursor records windowEnd as the new cursor for a sandbox, so the
// next window (sweep or edge) begins exactly where this one ended.
func (s *Service) advanceUsageCursor(id string, windowEnd time.Time) {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	if s.usageCursor == nil {
		s.usageCursor = make(map[string]time.Time)
	}
	s.usageCursor[id] = windowEnd
}

// dropUsageCursor forgets a sandbox's cursor (after a terminal destroy edge) so
// the map doesn't grow without bound.
func (s *Service) dropUsageCursor(id string) {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	delete(s.usageCursor, id)
}

// emitUsage ships a batch best-effort. It is only ever called from background
// loops (reconcile, event monitor, netstats sink, live sampler) — never the
// request hot path. The Reporter contract guarantees a non-blocking
// implementation (durable buffering lives downstream in the fluent agent), so a
// direct call is safe; we still swallow+log errors so a delivery hiccup can
// never break reconcile or event handling.
func (s *Service) emitUsage(ctx context.Context, samples []controlplane.Sample) {
	if s.usageReporter == nil || len(samples) == 0 {
		return
	}
	if err := s.usageReporter.Report(ctx, samples); err != nil {
		s.logger.Warn("usage report failed; samples dropped (delivery is best-effort)",
			"count", len(samples), "error", err)
	}
}

// usageEventID is a stable idempotency key: the same (sandbox, kind, window-end)
// always hashes to the same id, so an at-least-once delivery path can dedupe
// retried sends. windowEnd is quantized to the emitting tick.
func usageEventID(sandboxID, kind string, windowEnd time.Time) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sandboxID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(kind))
	_, _ = h.Write([]byte{0})
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(windowEnd.UnixNano()))
	_, _ = h.Write(buf[:])
	return strconv.FormatUint(h.Sum64(), 16)
}

// gpuReservedCount maps a GPU request to a billable count: nil → 0, Count<=0 →
// 1 (the model treats 0 as "default 1"; -1 "all" is counted as 1 here since the
// host-level fan-out is not known at this layer — the managed side can refine).
func gpuReservedCount(g *models.GPURequest) int {
	if g == nil {
		return 0
	}
	if g.Count <= 0 {
		return 1
	}
	return g.Count
}

// appendReservedSamples builds the per-window reserved-resource samples for one
// sandbox. uptime + cpu/mem/gpu accrue only while Started (compute is live);
// disk_reserved accrues whenever the sandbox exists — Started or Stopped —
// because a parked sandbox still holds its disk reservation. Image storage is
// never emitted. Each rate is scaled by the window length in seconds.
func appendReservedSamples(out []controlplane.Sample, sb *models.Sandbox, windowStart, windowEnd time.Time) []controlplane.Sample {
	if sb == nil {
		return out
	}
	windowSeconds := windowEnd.Sub(windowStart).Seconds()
	if windowSeconds <= 0 {
		return out
	}
	add := func(kind, unit string, value float64) {
		if value <= 0 {
			return
		}
		out = append(out, controlplane.Sample{
			EventID:     usageEventID(sb.ID, kind, windowEnd),
			OwnerRef:    sb.OwnerRef,
			SandboxID:   sb.ID,
			Kind:        kind,
			Value:       value,
			Unit:        unit,
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
		})
	}

	// Disk reservation is charged while parked too — it occupies the host disk
	// whether or not the container is running.
	add(usageKindDiskReserved, usageUnitGiBSecond, float64(sb.DiskGB)*windowSeconds)

	if sb.Status == models.SandboxStatusStarted {
		add(usageKindUptime, usageUnitSeconds, windowSeconds)
		add(usageKindCPUReserved, usageUnitVCPUSecond, sb.CPU*windowSeconds)
		add(usageKindMemReserved, usageUnitMiBSecond, float64(sb.MemoryMB)*windowSeconds)
		if n := gpuReservedCount(sb.GPUs); n > 0 {
			add(usageKindGPU, usageUnitGPUSecond, float64(n)*windowSeconds)
		}
	}
	return out
}

// reconcileFallbackWindowStart bounds the first window for a sandbox the cursor
// hasn't seen yet: one reconcile interval back, but never before the sandbox was
// created, so a freshly-created sandbox doesn't backfill a full interval.
func (s *Service) reconcileFallbackWindowStart(sb *models.Sandbox, now time.Time) time.Time {
	interval := s.cfg.ReconcileInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	start := now.Add(-interval)
	if !sb.CreatedAt.IsZero() && sb.CreatedAt.After(start) {
		start = sb.CreatedAt.UTC()
	}
	return start
}

// emitReservedUsage emits one window of reserved-resource + uptime samples for
// every known sandbox, advancing each sandbox's cursor to now. Called at the end
// of each reconcile sweep. The per-sandbox cursor makes consecutive sweeps — and
// any interleaved lifecycle edges — tile each timeline without gaps or overlaps.
// No-op when no reporter is wired (open-source build).
func (s *Service) emitReservedUsage(ctx context.Context, sandboxes []*models.Sandbox) {
	s.emitReservedUsageAt(ctx, sandboxes, time.Now().UTC())
}

// emitReservedUsageAt is emitReservedUsage with an injectable clock for tests.
func (s *Service) emitReservedUsageAt(ctx context.Context, sandboxes []*models.Sandbox, now time.Time) {
	if !s.usageEnabled() || len(sandboxes) == 0 {
		return
	}
	now = now.UTC()
	samples := make([]controlplane.Sample, 0, len(sandboxes)*2)
	for _, sb := range sandboxes {
		if sb == nil || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		windowStart := s.usageWindowStart(sb.ID, s.reconcileFallbackWindowStart(sb, now))
		if !windowStart.Before(now) {
			continue
		}
		samples = appendReservedSamples(samples, sb, windowStart, now)
		s.advanceUsageCursor(sb.ID, now)
	}
	s.emitUsage(ctx, samples)
}

// emitLifecycleStopUsage closes a sandbox's open reserved window at a stop/die/
// oom/destroy edge, so a sandbox that ran and exited between reconcile sweeps
// still has its tail metered. The window is [cursor, edgeTime]; the cursor is
// advanced to edgeTime so the next sweep doesn't re-emit it. drop=true also
// forgets the cursor (terminal destroy). No-op when no reporter is wired.
func (s *Service) emitLifecycleStopUsage(ctx context.Context, sb *models.Sandbox, edgeTime time.Time, drop bool) {
	if !s.usageEnabled() || sb == nil {
		return
	}
	edgeTime = edgeTime.UTC()
	windowStart := s.usageWindowStart(sb.ID, s.reconcileFallbackWindowStart(sb, edgeTime))
	if windowStart.Before(edgeTime) {
		// Treat the sandbox as Started for the tail: the edge marks the end of a
		// running window (die/stop/oom always follow a running state).
		tail := *sb
		tail.Status = models.SandboxStatusStarted
		samples := appendReservedSamples(nil, &tail, windowStart, edgeTime)
		s.advanceUsageCursor(sb.ID, edgeTime)
		s.emitUsage(ctx, samples)
	}
	if drop {
		s.dropUsageCursor(sb.ID)
	}
}

// noteLifecycleStart begins a sandbox's accrual window at a start edge by
// seeding its cursor, so the next sweep meters from the actual start rather than
// one reconcile interval back. No emission here — uptime accrues forward.
func (s *Service) noteLifecycleStart(id string, edgeTime time.Time) {
	if !s.usageEnabled() {
		return
	}
	s.advanceUsageCursor(id, edgeTime.UTC())
}

// emitNetworkUsage emits egress/ingress samples from a netstats per-tick delta.
// bytesIn/bytesOut are the delta bytes since the previous tick; the window is
// [sampledAt-pollInterval, sampledAt]. Called from the netstats poller sink
// (background), never the request path. No-op when no reporter is wired.
func (s *Service) emitNetworkUsage(ctx context.Context, sb *models.Sandbox, bytesIn, bytesOut int64, sampledAt time.Time) {
	if !s.usageEnabled() || sb == nil || (bytesIn <= 0 && bytesOut <= 0) {
		return
	}
	windowEnd := sampledAt.UTC()
	windowStart := windowEnd
	if iv := s.cfg.NetstatsPollInterval; iv > 0 {
		windowStart = windowEnd.Add(-iv)
	}
	samples := make([]controlplane.Sample, 0, 2)
	mk := func(kind string, value int64) {
		if value <= 0 {
			return
		}
		samples = append(samples, controlplane.Sample{
			EventID:     usageEventID(sb.ID, kind, windowEnd),
			OwnerRef:    sb.OwnerRef,
			SandboxID:   sb.ID,
			Kind:        kind,
			Value:       float64(value),
			Unit:        usageUnitBytes,
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
		})
	}
	mk(usageKindIngress, bytesIn)
	mk(usageKindEgress, bytesOut)
	s.emitUsage(ctx, samples)
}
