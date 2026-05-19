package netstats

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// PIDLookup resolves a sandbox container reference to the host PID of its
// init process. Implemented by *docker.Client.ContainerPID.
type PIDLookup interface {
	ContainerPID(ctx context.Context, containerRef string) (int, error)
}

// SandboxLister returns the sandboxes that should be polled this tick.
// Returning a fresh slice on each call is fine — the poller doesn't retain
// it. Items must include both the sandbox ID (for callbacks) and the
// container reference (for the PID lookup); when a container is not yet
// running the lister can omit it or include it with empty containerRef.
type SandboxLister interface {
	NetstatsTargets(ctx context.Context) []Target
}

// Target is one row the poller will sample on the next tick.
type Target struct {
	SandboxID    string
	ContainerRef string
}

// SampleSink receives per-tick deltas. Implementations typically call into
// the store to add deltas to the cumulative counters and check quotas.
// Implementations MUST be safe to call from the poller goroutine.
type SampleSink interface {
	HandleSamples(ctx context.Context, samples []Sample)
}

// Sample is the per-sandbox delta the poller produces each tick.
// BytesIn/BytesOut are non-negative deltas since the last successful sample
// for the same (sandbox, PID) pair. The first observation of any new PID
// produces a Sample with zero deltas — the cumulative reading at that point
// is stored as the baseline so subsequent ticks compute meaningful diffs.
// This makes the poller restart-safe: container restart → new PID → fresh
// baseline → no spurious giant delta from the cumulative counter resetting
// to a small number.
type Sample struct {
	SandboxID string
	BytesIn   int64
	BytesOut  int64
	SampledAt time.Time
}

// Poller drives the netstats loop. Construct via NewPoller and call Start
// once; call Stop on shutdown to release the goroutine cleanly.
type Poller struct {
	logger   *slog.Logger
	reader   *Reader
	lookup   PIDLookup
	lister   SandboxLister
	sink     SampleSink
	interval time.Duration

	mu        sync.Mutex
	baselines map[string]baseline // keyed by sandbox ID
}

type baseline struct {
	pid      int
	counters Counters
}

// NewPoller wires the dependencies together. interval <= 0 is rejected at
// Start; the caller controls the cadence so deployments with thousands of
// sandboxes can dial it down.
func NewPoller(logger *slog.Logger, reader *Reader, lookup PIDLookup, lister SandboxLister, sink SampleSink, interval time.Duration) *Poller {
	return &Poller{
		logger:    logger,
		reader:    reader,
		lookup:    lookup,
		lister:    lister,
		sink:      sink,
		interval:  interval,
		baselines: make(map[string]baseline),
	}
}

// Start launches the poll loop in a goroutine and returns immediately. The
// goroutine exits when ctx is cancelled. Calling Start more than once on the
// same Poller will spawn additional loops — don't do that.
func (p *Poller) Start(ctx context.Context) error {
	if p.interval <= 0 {
		return errors.New("netstats: poll interval must be > 0")
	}
	go p.run(ctx)
	return nil
}

func (p *Poller) run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.tick(ctx, now)
		}
	}
}

// tick is exposed (lowercase but visible to test files in-package) so tests
// can drive a deterministic sample without standing up a real ticker.
func (p *Poller) tick(ctx context.Context, now time.Time) {
	start := time.Now()
	targets := p.lister.NetstatsTargets(ctx)
	dropped := make(map[string]int64)
	sampleCount := 0
	defer func() {
		recordPoll(time.Since(start), len(targets), sampleCount, dropped)
	}()
	if len(targets) == 0 {
		p.gcBaselines(targets)
		return
	}

	samples := make([]Sample, 0, len(targets))
	for _, t := range targets {
		if t.SandboxID == "" {
			dropped["missing_sandbox_id"]++
			continue
		}
		// Per the SandboxLister contract, an empty ContainerRef means "not
		// running this tick" — same semantics as a failed PID lookup or
		// ErrNotRunning below. Drop the baseline so the next tick (when the
		// container is up and the ref reappears) re-baselines from the new
		// PID instead of diffing against a stale one. Without this, baselines
		// for sandboxes stuck in not-yet-running states would accumulate.
		if t.ContainerRef == "" {
			p.dropBaseline(t.SandboxID)
			dropped["empty_container_ref"]++
			continue
		}

		pid, err := p.lookup.ContainerPID(ctx, t.ContainerRef)
		if err != nil {
			p.logger.Debug("netstats: pid lookup failed", "sandbox_id", t.SandboxID, "error", err)
			dropped["pid_lookup_failed"]++
			continue
		}
		if pid <= 0 {
			p.dropBaseline(t.SandboxID)
			dropped["not_running"]++
			continue
		}

		current, err := p.reader.Read(pid)
		if err != nil {
			if errors.Is(err, ErrNotRunning) {
				p.dropBaseline(t.SandboxID)
				dropped["not_running"]++
				continue
			}
			p.logger.Debug("netstats: read failed", "sandbox_id", t.SandboxID, "pid", pid, "error", err)
			dropped["read_failed"]++
			continue
		}

		delta := p.diffAndUpdate(t.SandboxID, pid, current)
		samples = append(samples, Sample{
			SandboxID: t.SandboxID,
			BytesIn:   delta.BytesIn,
			BytesOut:  delta.BytesOut,
			SampledAt: now,
		})
	}

	p.gcBaselines(targets)

	if len(samples) > 0 {
		sampleCount = len(samples)
		p.sink.HandleSamples(ctx, samples)
	}
}

// diffAndUpdate computes the delta against the stored baseline and rotates
// the baseline forward. If PID changed (container restart) or no baseline
// exists yet (first observation), returns a zero delta and stores `current`
// as the new baseline — see Sample doc for why.
func (p *Poller) diffAndUpdate(sandboxID string, pid int, current Counters) Counters {
	p.mu.Lock()
	defer p.mu.Unlock()
	prev, ok := p.baselines[sandboxID]
	p.baselines[sandboxID] = baseline{pid: pid, counters: current}
	if !ok || prev.pid != pid {
		return Counters{}
	}
	return Counters{
		BytesIn:  nonNegative(current.BytesIn - prev.counters.BytesIn),
		BytesOut: nonNegative(current.BytesOut - prev.counters.BytesOut),
	}
}

// dropBaseline forgets a sandbox so a future Start (and new PID) starts
// clean. Called when the container is no longer running this tick.
func (p *Poller) dropBaseline(sandboxID string) {
	p.mu.Lock()
	delete(p.baselines, sandboxID)
	p.mu.Unlock()
}

// gcBaselines drops any baselines whose sandbox is no longer in the target
// list — covers Destroy, where the sandbox is gone from the store before the
// next tick.
func (p *Poller) gcBaselines(targets []Target) {
	keep := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		keep[t.SandboxID] = struct{}{}
	}
	p.mu.Lock()
	for id := range p.baselines {
		if _, ok := keep[id]; !ok {
			delete(p.baselines, id)
		}
	}
	p.mu.Unlock()
}

func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
