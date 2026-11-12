package service

import (
	"context"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/usagemetrics"
	"github.com/aerol-ai/microvm/pkg/models"
)

// usageMetricsInterval is how often the usage exporter samples. It bounds
// the two errors a sample can make: a sandbox started again between two
// samples is charged from the earlier one, and a sandbox whose row vanished
// with no stop time is charged up to the earlier one. 15 s is half a usual
// 30 s scrape, so every scrape sees new values. A var so tests can shorten
// it.
var usageMetricsInterval = 15 * time.Second

// usageDockerStatsTimeout bounds one Docker stats read, so one stuck
// container cannot hold up the whole sample.
const usageDockerStatsTimeout = 2 * time.Second

// UsageMeter returns the per-owner usage counters for /v1/metrics, or nil
// when the exporter is off.
func (s *Service) UsageMeter() *usagemetrics.Meter { return s.usageMeter.Load() }

// StartUsageMetrics starts the per-owner usage exporter
// (plans/kubernetes-v2-architecture.md, C20) when SB_USAGE_METRICS_ENABLED
// is on, and does nothing otherwise.
//
// It runs on its own ticker, off every request path: CreateSandbox and the
// capacity path are untouched. Each sample is one narrow store read plus,
// per running sandbox, one read of its cgroup files (containerd, runc or
// gVisor) or one Docker stats call (the Docker engine). The counters stay
// in this process and leave it only when Prometheus scrapes /v1/metrics;
// unlike the managed usageReporter, nothing is sent anywhere.
func (s *Service) StartUsageMetrics(ctx context.Context) {
	if !s.cfg.UsageMetricsEnabled || s.store == nil {
		return
	}
	m := usagemetrics.NewMeter(usagemetrics.NewIncarnation(), time.Now().UTC())
	if !s.usageMeter.CompareAndSwap(nil, m) {
		return // already running: one set of counters per process
	}
	s.logger.Info("usage metrics exporter enabled",
		"incarnation", m.Incarnation(), "interval", usageMetricsInterval)
	go func() {
		// The first sample comes at once. Prometheus's rate() cannot count
		// the first value of a new series, so starting each owner's series
		// near zero loses almost nothing of this process's first interval.
		s.sampleUsageMetricsOnce(ctx, time.Now().UTC())
		t := time.NewTicker(usageMetricsInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.sampleUsageMetricsOnce(ctx, now.UTC())
			}
		}
	}()
}

// sampleUsageMetricsOnce reads this node's sandboxes and their cgroups and
// gives them to the meter. A store error skips the whole sample:
// aerolvm_usage_last_sample_timestamp_seconds then stops moving, which is
// what the stale-exporter alert watches.
func (s *Service) sampleUsageMetricsOnce(ctx context.Context, now time.Time) {
	m := s.usageMeter.Load()
	if m == nil {
		return
	}
	rows, err := s.store.ListUsageRows(ctx)
	if err != nil {
		s.logger.Warn("usage metrics: list sandboxes failed; sample skipped", "error", err)
		return
	}
	sample := make([]usagemetrics.Sandbox, 0, len(rows))
	failures := 0
	for _, sb := range rows {
		u := usagemetrics.Sandbox{
			ID:        sb.ID,
			Owner:     sb.OwnerRef,
			CPU:       sb.CPU,
			MemoryMB:  sb.MemoryMB,
			Running:   sb.Status == models.SandboxStatusStarted,
			CreatedAt: sb.CreatedAt,
			UpdatedAt: sb.UpdatedAt,
		}
		if u.Running {
			c, ok, err := s.readConsumedUsage(ctx, sb)
			switch {
			case err != nil:
				// A task between a stop and a start has no cgroup for a
				// moment. Counted, so a steady rate is visible.
				failures++
				s.logger.Debug("usage metrics: read sandbox use failed",
					"sandbox_id", sb.ID, "error", err)
			case ok:
				u.Consumed = &c
			}
		}
		sample = append(sample, u)
	}
	m.Observe(now, sample, failures)
}

// readConsumedUsage reads one running sandbox's measured CPU and memory.
// ok is false for a sandbox nothing can be read for: a Firecracker, WASM
// or isolate sandbox, which has no cgroup of its own, or a runtime this
// node does not have. Its reserved use is still charged.
//
// A runtime that names its sandbox's cgroup (containerd, for runc and
// gVisor alike) is read from the cgroup files. The Docker engine keeps the
// Docker stats call the older live sampler uses: where Docker puts a
// container's cgroup depends on its cgroup driver and settings, which
// sandboxd does not know.
func (s *Service) readConsumedUsage(ctx context.Context, sb *models.Sandbox) (usagemetrics.Consumed, bool, error) {
	ref := strings.TrimSpace(sb.ContainerID)
	if ref == "" {
		ref = sb.ID
	}
	rt, err := s.runtimeForSandbox(sb)
	if err != nil || rt == nil {
		return usagemetrics.Consumed{}, false, nil
	}
	if loc, ok := rt.(runtime.CgroupLocator); ok {
		root := s.usageCgroupRoot
		if root == "" {
			root = usagemetrics.DefaultCgroupRoot
		}
		c, err := usagemetrics.ReadCgroup(root, loc.SandboxCgroup(ref))
		return c, err == nil, err
	}
	if s.isFirecrackerSandbox(sb) || s.isWasmSandbox(sb) || s.isIsolateSandbox(sb) ||
		models.SandboxEngine(sb) != models.ContainerEngineDocker {
		return usagemetrics.Consumed{}, false, nil
	}
	fetch := s.usageDockerStats
	if fetch == nil {
		if s.dockerAux == nil {
			return usagemetrics.Consumed{}, false, nil
		}
		fetch = s.dockerAux.ContainerStats
	}
	rctx, cancel := context.WithTimeout(ctx, usageDockerStatsTimeout)
	defer cancel()
	st, err := fetch(rctx, ref)
	if err != nil {
		return usagemetrics.Consumed{}, false, err
	}
	return usagemetrics.Consumed{CPUSeconds: float64(st.CPUTotalNanos) / 1e9, MemoryBytes: st.MemBytes}, true, nil
}

// closeUsageMetrics charges a sandbox up to now and stops charging it. The
// two paths that delete a sandbox's row call it, so a sandbox removed
// between samples is charged up to its removal. It is one atomic load when
// the exporter is off.
func (s *Service) closeUsageMetrics(id string) {
	if m := s.usageMeter.Load(); m != nil {
		m.Close(id, time.Now().UTC())
	}
}
