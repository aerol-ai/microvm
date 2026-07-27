package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

// EnsureNetstatsReady boots the per-sandbox network byte-counter poller
// under a single-flight latch. Same lazy-bootstrap shape as
// EnsureLayer4Ready: caller pays the bootstrap cost only once across the
// daemon's lifetime, and the poller goroutine survives until ctx — typically
// the daemon's signal context — is cancelled.
//
// Failure here is non-fatal: callers log and continue. Without the poller,
// network counters stay at zero and quotas never trigger; both Create and
// reads of /network/usage still work.
func (s *Service) EnsureNetstatsReady(ctx context.Context) error {
	if s.netstatsReady.Load() {
		return nil
	}
	s.netstatsMu.Lock()
	defer s.netstatsMu.Unlock()
	if s.netstatsReady.Load() {
		return nil
	}
	if s.cfg.NetstatsPollInterval <= 0 {
		return errors.New("netstats poll interval must be > 0")
	}
	if s.events == nil {
		return errors.New("netstats requires the docker events client for PID lookup")
	}

	poller := netstats.NewPoller(
		s.logger,
		netstats.NewReader(),
		s.events,
		netstatsServiceLister{svc: s},
		netstatsServiceSink{svc: s},
		s.cfg.NetstatsPollInterval,
	)
	if err := poller.Start(ctx); err != nil {
		return fmt.Errorf("start netstats poller: %w", err)
	}
	s.netstatsPoller = poller
	s.netstatsReady.Store(true)
	return nil
}

// GetNetworkUsage returns the current cumulative byte counters and
// configured limits for a sandbox. Callers handle ErrNotFound translation.
//
// Best-effort lazy bootstrap of the netstats poller: if boot's
// EnsureNetstatsReady failed (cold-start race against the docker daemon, etc.)
// this call retries it under the same single-flight latch. Failure is logged
// and swallowed — the caller still gets back whatever counters the store has,
// and the next call will retry again.
func (s *Service) GetNetworkUsage(ctx context.Context, id string) (*models.NetworkUsage, error) {
	if err := s.EnsureNetstatsReady(ctx); err != nil {
		s.logger.Warn("netstats lazy bootstrap failed; counters may be stale",
			"sandbox_id", id, "error", err)
	}
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	usage := &models.NetworkUsage{
		SandboxID:       sandbox.ID,
		BytesIn:         sandbox.NetworkBytesIn,
		BytesOut:        sandbox.NetworkBytesOut,
		BytesInLimit:    sandbox.NetworkBytesInLimit,
		BytesOutLimit:   sandbox.NetworkBytesOutLimit,
		QuotaExceeded:   sandbox.NetworkQuotaExceeded,
		QuotaExceededAt: sandbox.NetworkQuotaExceededAt,
	}
	if last := s.netstatsLastTick.Load(); last > 0 {
		t := time.Unix(0, last).UTC()
		usage.LastSampledAt = &t
	}
	return usage, nil
}

// SetNetworkLimits writes new caps (0 = unlimited) and re-evaluates the
// quota state. If the new limit moves the sandbox back under-quota, the
// matching ingress/egress block is cleared. If it leaves the sandbox over,
// the matching block is (re-)applied.
//
// Egress clears are conditional: NetworkBlockAll uses the same DOCKER-USER
// row as the quota egress block, so we must not lift it here when the
// operator's blanket egress block is still on. See pkg/docker/netrules
// commentary on the shared rule.
func (s *Service) SetNetworkLimits(ctx context.Context, id string, bytesInLimit, bytesOutLimit int64) (*models.NetworkUsage, error) {
	if bytesInLimit < 0 || bytesOutLimit < 0 {
		return nil, errors.New("network byte limits must be >= 0")
	}
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.isFirecrackerSandbox(sandbox) && (bytesInLimit > 0 || bytesOutLimit > 0) {
		return nil, unsupportedFirecrackerOption("network byte limits")
	}
	// Stronger lazy-bootstrap case than GetNetworkUsage: setting a limit
	// implies the operator wants enforcement to start. If the poller is
	// down, "limit set, never enforced" is silent failure of a security
	// control. Best-effort still — the limit is persisted either way and
	// reconcile will re-evaluate; this just shortens the window before the
	// poller starts feeding the quota check.
	if err := s.EnsureNetstatsReady(ctx); err != nil {
		s.logger.Warn("netstats lazy bootstrap failed; quota enforcement may be delayed",
			"sandbox_id", id, "error", err)
	}
	if err := s.store.SetNetworkLimits(ctx, id, bytesInLimit, bytesOutLimit); err != nil {
		return nil, err
	}
	sandbox, err = s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	overIn := bytesInLimit > 0 && sandbox.NetworkBytesIn >= bytesInLimit
	overOut := bytesOutLimit > 0 && sandbox.NetworkBytesOut >= bytesOutLimit
	s.applyNetworkQuotaState(ctx, sandbox, overIn, overOut)

	return s.GetNetworkUsage(ctx, id)
}

// applyNetworkQuotaState reconciles iptables and the quota flag with the
// observed (over-in, over-out) state for a single sandbox. Idempotent on
// both sides — called from the poller sink, the SetNetworkLimits path, and
// the reconcile re-heal path.
func (s *Service) applyNetworkQuotaState(ctx context.Context, sandbox *models.Sandbox, overIn, overOut bool) {
	if sandbox == nil {
		return
	}
	if s.isWasmSandbox(sandbox) {
		s.syncWasmNetworkPolicy(sandbox, overIn, overOut)
		if overIn || overOut {
			if err := s.store.MarkNetworkQuotaExceeded(ctx, sandbox.ID, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.logger.Warn("mark network quota exceeded failed",
					"sandbox_id", sandbox.ID, "error", err)
			}
		} else if sandbox.NetworkQuotaExceeded {
			if err := s.store.ClearNetworkQuotaExceeded(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.logger.Warn("clear network quota exceeded failed",
					"sandbox_id", sandbox.ID, "error", err)
			}
		}
		return
	}

	// iptables reconciliation needs an IP to install rules against. A
	// sandbox in a state with no ContainerIP (stopped, between create and
	// runtime ready, etc.) has nothing to firewall — Start / reconcile
	// reapplies quota state via this same function once an IP exists.
	// Store-flag reconciliation below is intentionally NOT gated on the IP:
	// without that, a sandbox stopped while over-quota would have its
	// `quota_exceeded` flag stuck true even after the operator raises the
	// limit and the over-quota condition no longer holds.
	if sandbox.ContainerIP != "" {
		cr, err := s.containerRuntimeForSandbox(sandbox)
		if err != nil {
			s.logger.Warn("apply network quota skipped: runtime has no container network rules",
				"sandbox_id", sandbox.ID, "error", err)
		} else {
			// Egress: only clear when NetworkBlockAll is also off. NetworkBlockAll
			// owns the same DOCKER-USER row, so ApplyNetworkBlockAll is the right
			// shared installer for the quota path too.
			if overOut {
				if err := cr.ApplyNetworkBlockAll(sandbox.ContainerIP); err != nil {
					s.logger.Warn("apply quota egress block failed",
						"sandbox_id", sandbox.ID, "ip", sandbox.ContainerIP, "error", err)
				}
			} else if !sandbox.NetworkBlockAll {
				if err := cr.ClearNetworkBlockEgress(sandbox.ContainerIP); err != nil {
					s.logger.Warn("clear quota egress block failed",
						"sandbox_id", sandbox.ID, "ip", sandbox.ContainerIP, "error", err)
				}
			}

			if overIn {
				if err := cr.ApplyNetworkBlockIngress(sandbox.ContainerIP); err != nil {
					s.logger.Warn("apply quota ingress block failed",
						"sandbox_id", sandbox.ID, "ip", sandbox.ContainerIP, "error", err)
				}
			} else {
				if err := cr.ClearNetworkBlockIngress(sandbox.ContainerIP); err != nil {
					s.logger.Warn("clear quota ingress block failed",
						"sandbox_id", sandbox.ID, "ip", sandbox.ContainerIP, "error", err)
				}
			}
		}
	}

	if overIn || overOut {
		if err := s.store.MarkNetworkQuotaExceeded(ctx, sandbox.ID, time.Now().UTC()); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("mark network quota exceeded failed",
				"sandbox_id", sandbox.ID, "error", err)
		}
	} else if sandbox.NetworkQuotaExceeded {
		if err := s.store.ClearNetworkQuotaExceeded(ctx, sandbox.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("clear network quota exceeded failed",
				"sandbox_id", sandbox.ID, "error", err)
		}
	}
}

// netstatsServiceLister adapts Service to the netstats.SandboxLister
// interface. Defined as a wrapper struct so Service itself doesn't grow a
// public NetstatsTargets method that would be confusing on the API surface.
type netstatsServiceLister struct{ svc *Service }

func (l netstatsServiceLister) NetstatsTargets(ctx context.Context) []netstats.Target {
	sandboxes, err := l.svc.store.List(ctx)
	if err != nil {
		l.svc.logger.Warn("netstats: list sandboxes failed", "error", err)
		return nil
	}
	out := make([]netstats.Target, 0, len(sandboxes))
	for _, sb := range sandboxes {
		if sb == nil || sb.Status != models.SandboxStatusStarted {
			continue
		}
		// Sandboxes with both limits at 0 (unlimited) and counters already
		// at 0 are still polled — operators expect /network/usage to reflect
		// real traffic even before they set a limit. Skip empty container
		// refs which would otherwise hit the PID lookup path uselessly.
		ref := sb.ContainerID
		if ref == "" {
			ref = sb.ID
		}
		out = append(out, netstats.Target{SandboxID: sb.ID, ContainerRef: ref})
	}
	return out
}

// netstatsServiceSink adapts Service to the netstats.SampleSink interface.
type netstatsServiceSink struct{ svc *Service }

func (k netstatsServiceSink) HandleSamples(ctx context.Context, samples []netstats.Sample) {
	k.svc.drainWasmNetworkCounters(ctx)
	k.handleNetworkSamples(ctx, samples)
}

func (k netstatsServiceSink) handleNetworkSamples(ctx context.Context, samples []netstats.Sample) {
	if len(samples) == 0 {
		return
	}
	for _, sample := range samples {
		// Activity floor for the idle sweep under bypass-on: record the
		// SampledAt of any network activity before the zero-byte skip. Warm
		// bypass traffic no longer touches through sandboxd, and L4/TLS can
		// also be an idle-but-established TCP socket with no byte delta.
		if sample.BytesIn > 0 || sample.BytesOut > 0 || sample.ActiveTCP {
			k.svc.recordNetstatsActivity(sample.SandboxID, sample.SampledAt)
		}
		if sample.BytesIn == 0 && sample.BytesOut == 0 {
			continue
		}
		if err := k.svc.store.UpdateSandboxNetCounters(ctx, sample.SandboxID, sample.BytesIn, sample.BytesOut); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			k.svc.logger.Warn("netstats: update counters failed",
				"sandbox_id", sample.SandboxID, "error", err)
			continue
		}
		if k.svc.testAfterNetstatsUpdate != nil {
			k.svc.testAfterNetstatsUpdate()
		}

		// After persisting deltas, re-read the row so the quota check works
		// against the post-update cumulative — including any concurrent
		// SetNetworkLimits change to the caps. Cheap: SQLite, single row,
		// already in cache.
		sandbox, err := k.svc.store.Get(ctx, sample.SandboxID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			k.svc.logger.Warn("netstats: re-fetch sandbox failed",
				"sandbox_id", sample.SandboxID, "error", err)
			continue
		}

		// Mirror the per-tick byte deltas as egress/ingress usage samples
		// (owner_ref comes off the row we just re-read). No-op without a
		// reporter; the poller goroutine is already off the request path.
		k.svc.emitNetworkUsage(ctx, sandbox, sample.BytesIn, sample.BytesOut, sample.SampledAt)

		overIn := sandbox.NetworkBytesInLimit > 0 && sandbox.NetworkBytesIn >= sandbox.NetworkBytesInLimit
		overOut := sandbox.NetworkBytesOutLimit > 0 && sandbox.NetworkBytesOut >= sandbox.NetworkBytesOutLimit
		if overIn || overOut || sandbox.NetworkQuotaExceeded {
			k.svc.applyNetworkQuotaState(ctx, sandbox, overIn, overOut)
		}
	}

	if len(samples) > 0 {
		k.svc.netstatsLastTick.Store(samples[len(samples)-1].SampledAt.UnixNano())
	}
}
