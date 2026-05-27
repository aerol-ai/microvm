package firecracker

// rss_sampler.go is the PR 5-A foundation for the Phase 5 memory-
// overcommit admission axis. It tracks per-VMM resident-set-size in
// MB and exposes the aggregate to admission via a single atomic load.
//
// Why a sampler and not on-demand reads at Admit time:
//
//   - Admit is on the hot path of CreateSandbox and is called under
//     Admitter.mu. A per-Admit fan-out across N firecracker pids
//     would add ~N file opens to every create; bursty admits would
//     amplify that into the admitter's hold time.
//   - RSS doesn't move fast enough to matter sub-second. Phase 5
//     refuses aggressively on a *watermark* (some headroom held in
//     reserve for spikes), not on a tight ratio — a 1Hz sample is
//     well under any meaningful drift between admit decisions.
//
// Why in this package and not pkg/capacity: PIDs are firecracker-
// specific. The cross-package boundary is the RSSSource interface
// PR 5-B will declare on capacity's side; this sampler satisfies it
// structurally (`TotalRSSMB() int`) so neither package needs to
// import the other.
//
// Scope of PR 5-A: substrate only. PR 5-B wires this into capacity;
// PR 5-C registers real PIDs from Driver.Create / WarmSpawn /
// poolspawner. Today the sampler has no callers in the daemon — the
// tests are the only consumers — so landing PR 5-A is a no-op on
// production admission behaviour.

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// readRSSPagesFn is the test seam for parsing /proc/<pid>/statm.
// Default points at the platform-tagged readRSSPagesForPID (real
// /proc on linux, zero-stub elsewhere). Tests swap it to feed canned
// per-pid values without needing root or a real firecracker.
//
// Function-variable rather than interface to match the seam style in
// seams.go's vmmSpawner / vmmClientFactory — the contract is a single
// function call, not a multi-method surface.
var readRSSPagesFn = readRSSPagesForPID

// hostPageSizeBytes is read once at package init. /proc/<pid>/statm
// reports counts in pages, and os.Getpagesize is constant for a given
// kernel build. Avoiding a per-sample syscall keeps sampleOnce a pure
// CPU/file-read loop.
var hostPageSizeBytes = int64(os.Getpagesize())

// RSSSampler tracks per-VMM resident-set-size and exposes the
// aggregate via TotalRSSMB. The zero value is not usable; construct
// with NewRSSSampler.
//
// Goroutine safety: Register / Unregister take mu; TotalRSSMB does an
// atomic load with no lock so admission (PR 5-B) can call it under
// Admitter.mu without nested-lock concerns. sampleOnce takes mu only
// long enough to snapshot the pid map, releases it for the
// readRSSPagesFn calls, then takes mu again to commit updates — that
// keeps a slow /proc read on one bad pid from blocking Register on a
// new spawn.
type RSSSampler struct {
	logger *slog.Logger

	mu      sync.Mutex
	pids    map[string]int // logical id (slotID / sandboxID) → pid
	samples map[string]int // logical id → last-sampled MB; cleared on Unregister

	total atomic.Int64
	// ready flips to true at the end of the first sampleOnce. Admission
	// (PR 5-B) checks this before consulting TotalRSSMB so a cold-start
	// daemon doesn't admit infinitely on the assumption that "0 RSS"
	// means "host is empty" — pre-tick the sampler has no opinion yet,
	// and the safer default is to fall back to nominal accounting.
	ready atomic.Bool
}

// NewRSSSampler returns a sampler with empty registries and zero
// total. Logger may be nil — discarded internally if so.
func NewRSSSampler(logger *slog.Logger) *RSSSampler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return &RSSSampler{
		logger:  logger,
		pids:    make(map[string]int),
		samples: make(map[string]int),
	}
}

// Register sets the pid for id. Idempotent on the same id: a second
// call overwrites the prior pid silently. The next sampleOnce reads
// the new pid; until then, the prior sample lingers in the aggregate
// (sub-second staleness is acceptable per the design — see file
// header).
//
// Empty id or non-positive pid are rejected silently — admission
// counters would be wrong either way, and the caller (PR 5-C's
// Driver.Create) is expected to gate on these before calling.
func (s *RSSSampler) Register(id string, pid int) {
	if id == "" || pid <= 0 {
		return
	}
	s.mu.Lock()
	s.pids[id] = pid
	s.mu.Unlock()
}

// Unregister drops id from the registry, removes any cached sample,
// and decrements the aggregate by the cached MB so admission sees the
// VMM go away immediately (rather than waiting for the next tick to
// notice the dead pid). No-op on unknown id.
func (s *RSSSampler) Unregister(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	delete(s.pids, id)
	prior, hadSample := s.samples[id]
	if hadSample {
		delete(s.samples, id)
	}
	s.mu.Unlock()
	if hadSample && prior > 0 {
		s.total.Add(int64(-prior))
	}
}

// TotalRSSMB returns the most recent aggregate. Reads the atomic
// once. Returns 0 before the first sampleOnce; pair with Ready() to
// distinguish "no data yet" from "genuinely 0 MB resident".
func (s *RSSSampler) TotalRSSMB() int {
	return int(s.total.Load())
}

// Ready reports whether sampleOnce has run at least once. Admission
// uses this to gate the RSS check: pre-tick, capacity falls back to
// nominal accounting because TotalRSSMB() returning 0 would otherwise
// look indistinguishable from "host is empty" and break overcommit
// safety the moment the operator sets a non-zero watermark ratio.
func (s *RSSSampler) Ready() bool {
	return s.ready.Load()
}

// Run drives sampleOnce on a fixed interval until ctx is done.
// Blocks; callers start it as `go sampler.Run(ctx, interval)` from
// main.go (PR 5-B). Interval ≤0 disables the loop (Run returns
// immediately) — useful for tests that drive sampleOnce manually.
func (s *RSSSampler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sampleOnce()
		}
	}
}

// sampleOnce reads the current pid map under mu, releases mu, calls
// readRSSPagesFn for each pid, then commits the new samples and
// recomputes the aggregate. Per-pid errors (process gone, file
// malformed) are logged at debug and recorded as 0 — one dead VMM
// must not poison admission across the host.
func (s *RSSSampler) sampleOnce() {
	// Ready is flipped on every call, not just the first. Cheap, and
	// keeps the "first tick after a config reload" invariant the same
	// as the "first tick after boot" invariant — admission only ever
	// needs to know "has at least one sample window completed".
	defer s.ready.Store(true)

	s.mu.Lock()
	if len(s.pids) == 0 {
		// Common case at cold start: keep the total at whatever it
		// last was (likely 0). Unregister already decremented; nothing
		// to do.
		s.mu.Unlock()
		return
	}
	pids := make(map[string]int, len(s.pids))
	maps.Copy(pids, s.pids)
	s.mu.Unlock()

	next := make(map[string]int, len(pids))
	for id, pid := range pids {
		pages, err := readRSSPagesFn(pid)
		if err != nil {
			s.logger.Debug("rss sample failed", "id", id, "pid", pid, "err", err)
			next[id] = 0
			continue
		}
		next[id] = pagesToMB(pages)
	}

	// Filter, sum, and commit under one critical section. Computing
	// liveTotal here (rather than after Unlock) avoids a race with
	// Unregister, which mutates s.samples under mu and would mutate
	// the same map a post-unlock iteration was scanning.
	s.mu.Lock()
	live := make(map[string]int, len(next))
	var liveTotal int64
	for id, mb := range next {
		// Drop entries Unregistered while we were sampling. Entries
		// Registered mid-sample land in s.pids but aren't in `next`;
		// the next sampleOnce picks them up — keeps the "new pids
		// reflect on the next tick" guarantee in the doc comment.
		if _, stillRegistered := s.pids[id]; stillRegistered {
			live[id] = mb
			liveTotal += int64(mb)
		}
	}
	s.samples = live
	s.mu.Unlock()
	s.total.Store(liveTotal)
}

// pagesToMB converts a /proc/statm page count to megabytes. Rounds
// down: admission's job is to be slightly conservative about
// available memory (i.e., report slightly more "used"), so any
// fractional MB attributable to a VMM lands in the host's favour.
func pagesToMB(pages int64) int {
	if pages <= 0 {
		return 0
	}
	bytes := pages * hostPageSizeBytes
	const mib = int64(1 << 20)
	return int(bytes / mib)
}

// discard satisfies io.Writer for the slog fallback when the caller
// passes a nil logger. Avoids pulling in io.Discard's package for a
// single use.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
