package netstats

import (
	"context"
	"errors"
	"log/slog"
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
	// Seen is the reading this sandbox's counters were last credited up to,
	// as the sink stored it from an earlier Sample.Seen. The zero value is
	// SeenUnknown, so a lister that does not track readings gets a baseline,
	// never a whole counter credited twice.
	Seen Seen
}

// Seen is a counter reading the store has credited. The poller keeps no
// readings of its own: each tick measures against the stored one, and the
// sink stores the new one with the bytes it credits, in one write. That is
// what tells the cases apart that an in-memory baseline could not (issue
// #69):
//
//   - a new sandbox (PID SeenNew): its network came up with the container,
//     so the first reading is all of its traffic and is credited whole;
//   - a sandboxd restart: the stored reading is still there, so the next
//     reading is measured from it, including traffic while sandboxd was down;
//   - a container restart (another PID): Docker gives the new container a
//     new network namespace, so its counters begin again below the stored
//     reading and are credited whole; the containerd engine keeps the
//     namespace across a stop and start, so its counters carry on above the
//     stored reading and only the difference is credited.
//
// A restarted Docker container that moves more than the old reading before
// the first poll is taken for a carried-on counter and is credited the
// difference: an undercount of at most the old reading, which was itself
// already credited. Where the cases cannot be told apart, the poller picks
// the one that counts less.
type Seen struct {
	// PID is SeenUnknown, SeenNew, or the PID the counters were read
	// through.
	PID      int
	BytesIn  int64
	BytesOut int64
}

const (
	// SeenUnknown: nothing is known about what was credited (a row from
	// before readings were stored), so the next reading is only a baseline.
	SeenUnknown = 0
	// SeenNew: a new sandbox with nothing credited yet.
	SeenNew = -1
)

// SampleSink receives per-tick deltas. Implementations typically call into
// the store to add deltas to the cumulative counters and check quotas.
// Implementations MUST be safe to call from the poller goroutine, and MUST
// store each non-nil Sample.Seen with that sample's bytes, atomically, for
// the lister to return as Target.Seen: a sink that drops it gets the same
// bytes again on the next tick.
type SampleSink interface {
	HandleSamples(ctx context.Context, samples []Sample)
}

// Sample is the per-sandbox delta the poller produces each tick.
// BytesIn/BytesOut are the non-negative bytes to credit: the traffic since
// Target.Seen (see Seen for how a new sandbox and a restart are told
// apart). ActiveTCP is the current socket-state observation, not a delta, so
// a sample can carry "this sandbox has an established TCP connection" even
// while its byte deltas are zero.
type Sample struct {
	SandboxID string
	BytesIn   int64
	BytesOut  int64
	ActiveTCP bool
	SampledAt time.Time
	// Seen is the reading to store as this sandbox's new Target.Seen, with
	// these bytes. Nil when it equals the stored one (no traffic since), so
	// an idle sandbox costs no write.
	Seen *Seen
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
}

// NewPoller wires the dependencies together. interval <= 0 is rejected at
// Start; the caller controls the cadence so deployments with thousands of
// sandboxes can dial it down.
func NewPoller(logger *slog.Logger, reader *Reader, lookup PIDLookup, lister SandboxLister, sink SampleSink, interval time.Duration) *Poller {
	return &Poller{
		logger:   logger,
		reader:   reader,
		lookup:   lookup,
		lister:   lister,
		sink:     sink,
		interval: interval,
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
		return
	}

	samples := make([]Sample, 0, len(targets))
	for _, t := range targets {
		if t.SandboxID == "" {
			dropped["missing_sandbox_id"]++
			continue
		}
		// Per the SandboxLister contract, an empty ContainerRef means "not
		// running this tick". Nothing is kept for it: the stored reading
		// stays, and the next reading is measured against it.
		if t.ContainerRef == "" {
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
			dropped["not_running"]++
			continue
		}

		current, err := p.reader.Read(pid)
		if err != nil {
			if errors.Is(err, ErrNotRunning) {
				dropped["not_running"]++
				continue
			}
			p.logger.Debug("netstats: read failed", "sandbox_id", t.SandboxID, "pid", pid, "error", err)
			dropped["read_failed"]++
			continue
		}

		in, out := credit(t.Seen, pid, current)
		sample := Sample{
			SandboxID: t.SandboxID,
			BytesIn:   in,
			BytesOut:  out,
			ActiveTCP: current.ActiveTCP,
			SampledAt: now,
		}
		if seen := (Seen{PID: pid, BytesIn: current.BytesIn, BytesOut: current.BytesOut}); seen != t.Seen {
			sample.Seen = &seen
		}
		samples = append(samples, sample)
	}

	// Always invoke the sink so alternate runtimes (WASM HTTP mediator) can
	// drain byte counters even when no Docker targets produced deltas.
	sampleCount = len(samples)
	p.sink.HandleSamples(ctx, samples)
}

// credit returns the bytes a reading adds to what seen says was credited.
// See Seen for the cases.
func credit(seen Seen, pid int, current Counters) (in, out int64) {
	switch {
	case seen.PID == SeenNew:
		return current.BytesIn, current.BytesOut
	case seen.PID <= 0:
		// SeenUnknown, or a value no build writes: baseline only.
		return 0, 0
	case seen.PID != pid && (current.BytesIn < seen.BytesIn || current.BytesOut < seen.BytesOut):
		// Another process, and its counters are below the old reading: a
		// new network namespace whose counters began at zero.
		return current.BytesIn, current.BytesOut
	default:
		// The same counters as the stored reading, carried on. A counter
		// that went down under the same process (an interface removed)
		// credits nothing for that direction rather than guess.
		return nonNegative(current.BytesIn - seen.BytesIn), nonNegative(current.BytesOut - seen.BytesOut)
	}
}

func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
