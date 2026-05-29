package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// liveStatFunc fetches a one-shot CPU/memory snapshot for a container. In
// production it is bound to the Docker client's ContainerStats; tests supply a
// fake so the sampler can be exercised without a live daemon.
type liveStatFunc func(ctx context.Context, containerRef string) (docker.ContainerStat, error)

// liveSamplePoint is the previous live-sampler observation for one sandbox: its
// cumulative CPU counter and when it was read. The next tick differences the
// counter against this to get CPU-seconds consumed over the window.
type liveSamplePoint struct {
	cpuTotalNanos uint64
	at            time.Time
}

// liveSampleFloor is the minimum interval between live sweeps (≤1 Hz). An
// operator value below this is clamped up so an aggressive setting can't hammer
// the Docker stats endpoint.
const liveSampleFloor = time.Second

// StartLiveUsageSampler launches the opt-in live CPU/memory sampler if, and only
// if, all of these hold: an interval is configured (> 0), a usage reporter is
// wired (managed build), and a Docker client is available to query. Under the
// open-source build (no reporter) or the default config (interval 0) it returns
// immediately and starts no goroutine — so this is genuinely off unless an
// operator opts in on a managed node.
//
// The sampler is deliberately additive to the reserved axes: reserved gives the
// provisioned envelope from the row (no I/O), live gives measured consumption
// from one cheap stats read per running Docker sandbox per tick. Firecracker
// sandboxes are skipped (the Docker stats endpoint doesn't know them); their
// reserved axes still flow.
func (s *Service) StartLiveUsageSampler(ctx context.Context) {
	interval := s.cfg.FleetLiveSampleInterval
	if interval <= 0 {
		return // disabled (the default)
	}
	if !s.usageEnabled() {
		return // open-source build: nothing to ship samples to
	}
	if s.events == nil {
		s.logger.Warn("fleet live sampler: no docker client; live cpu/mem disabled (reserved axes unaffected)")
		return
	}
	if interval < liveSampleFloor {
		interval = liveSampleFloor
	}
	s.logger.Info("fleet live usage sampler enabled", "interval", interval)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.sampleLiveUsageOnce(ctx, now.UTC(), s.events.ContainerStats)
			}
		}
	}()
}

// sampleLiveUsageOnce takes one live reading across all running Docker sandboxes
// and emits cpu_live / mem_live for the window since each sandbox's previous
// reading. Best-effort throughout: a per-container stats error skips just that
// sandbox (its cursor is left so the next tick reanchors), and the whole sweep
// is off the request path. Exported-ish only via the ticker; never called from
// a handler.
func (s *Service) sampleLiveUsageOnce(ctx context.Context, now time.Time, fetch liveStatFunc) {
	sandboxes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("fleet live sampler: list sandboxes failed", "error", err)
		return
	}
	active := make(map[string]struct{}, len(sandboxes))
	var samples []controlplane.Sample
	for _, sb := range sandboxes {
		if sb == nil || sb.Status != models.SandboxStatusStarted || s.isFirecrackerSandbox(sb) {
			continue
		}
		active[sb.ID] = struct{}{}

		ref := sb.ContainerID
		if ref == "" {
			ref = sb.ID
		}
		stat, err := fetch(ctx, ref)
		if err != nil {
			// Container may be mid-transition (just started/stopping) or briefly
			// unreachable; skip without disturbing the cursor so the next tick
			// re-anchors cleanly.
			s.logger.Debug("fleet live sampler: container stats failed; skipping",
				"sandbox_id", sb.ID, "error", err)
			continue
		}

		prev, hadPrev := s.liveCursorPoint(sb.ID)
		s.liveCursorSet(sb.ID, liveSamplePoint{cpuTotalNanos: stat.CPUTotalNanos, at: now})
		if !hadPrev || !now.After(prev.at) {
			continue // first observation (or non-advancing clock): no window yet
		}

		windowSeconds := now.Sub(prev.at).Seconds()
		// CPU: difference the monotonic counter into vcpu-seconds. A counter that
		// went backwards (container restart re-anchored the cgroup) is treated as
		// no measurable CPU this window rather than a negative figure.
		if stat.CPUTotalNanos > prev.cpuTotalNanos {
			cpuSeconds := float64(stat.CPUTotalNanos-prev.cpuTotalNanos) / 1e9
			samples = append(samples, controlplane.Sample{
				EventID:     usageEventID(sb.ID, usageKindCPULive, now),
				OwnerRef:    sb.OwnerRef,
				SandboxID:   sb.ID,
				Kind:        usageKindCPULive,
				Value:       cpuSeconds,
				Unit:        usageUnitVCPUSecond,
				WindowStart: prev.at,
				WindowEnd:   now,
			})
		}
		// Memory: a gauge, scaled by the window into mib-seconds so it composes
		// with mem_reserved on the same unit.
		memMiB := float64(stat.MemBytes) / (1024 * 1024)
		if memMiB > 0 {
			samples = append(samples, controlplane.Sample{
				EventID:     usageEventID(sb.ID, usageKindMemLive, now),
				OwnerRef:    sb.OwnerRef,
				SandboxID:   sb.ID,
				Kind:        usageKindMemLive,
				Value:       memMiB * windowSeconds,
				Unit:        usageUnitMiBSecond,
				WindowStart: prev.at,
				WindowEnd:   now,
			})
		}
	}

	// Forget cursors for sandboxes no longer running so the map can't grow
	// without bound across the daemon's life.
	s.liveCursorPrune(active)
	s.emitUsage(ctx, samples)
}

func (s *Service) liveCursorPoint(id string) (liveSamplePoint, bool) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	p, ok := s.liveCursor[id]
	return p, ok
}

func (s *Service) liveCursorSet(id string, p liveSamplePoint) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.liveCursor == nil {
		s.liveCursor = make(map[string]liveSamplePoint)
	}
	s.liveCursor[id] = p
}

func (s *Service) liveCursorPrune(active map[string]struct{}) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	for id := range s.liveCursor {
		if _, ok := active[id]; !ok {
			delete(s.liveCursor, id)
		}
	}
}
