package ipv6fence

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ReassertInterval paces the check that the fence is still in the kernel,
// matching the host firewall chains' re-assert (pkg/daemon
// chainReassertInterval).
const ReassertInterval = 30 * time.Second

// ErrNotSynced is what Ready answers before the first Sync.
var ErrNotSynced = errors.New("ipv6 fence: not installed yet")

// ready is 1 per runtime whose sandboxes the fence covers, 0 otherwise
// (/debug/vars aerolvm_ipv6_fence_ready).
var ready = expvar.NewMap("aerolvm_ipv6_fence_ready")

// Source names, for one runtime, the host interfaces its sandboxes sit on.
// Spec may fail (dockerd not answering yet): that runtime's creates are
// refused until a later sync gets it.
type Source struct {
	Runtime string
	Spec    func(ctx context.Context) (Spec, error)
}

// Supervisor installs the fence for every source and keeps it there. The
// create gate asks Ready; the daemon runs Sync once at boot, before the API
// serves, then Run.
type Supervisor struct {
	be       Backend
	sources  []Source
	logger   *slog.Logger
	reassert time.Duration
	now      func() time.Time

	// mu serializes syncs (boot, ticks).
	mu sync.Mutex
	// specs is each source's last good spec; a source is asked again when
	// it has none or the reassert is due.
	specs map[string]Spec
	// applied is the key of the spec the kernel holds ("" after a failure).
	applied   string
	applyErr  error
	checkedAt time.Time
	// status is each runtime's result (nil: covered), read by Ready
	// without the lock.
	status atomic.Pointer[map[string]error]
}

// NewSupervisor returns a supervisor for sources over be.
func NewSupervisor(be Backend, logger *slog.Logger, sources ...Source) *Supervisor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Supervisor{
		be:       be,
		sources:  sources,
		logger:   logger,
		reassert: ReassertInterval,
		now:      time.Now,
		specs:    map[string]Spec{},
	}
}

// Ready reports whether the fence covers runtime's sandboxes: nil when it
// does, or when runtime is not one this supervisor fences (WASM and
// isolate sandboxes have no interface on the node).
func (s *Supervisor) Ready(runtime string) error {
	if s == nil {
		return nil
	}
	st := s.status.Load()
	if st == nil {
		return ErrNotSynced
	}
	err, ok := (*st)[runtime]
	if !ok {
		return nil
	}
	return err
}

// Run syncs every tick until ctx ends: a failed install is retried within
// tick, a changed spec (dockerd's bridge came up) is applied, and every
// ReassertInterval the kernel is checked and the fence put back if
// something took it away.
func (s *Supervisor) Run(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 5 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sync(ctx, false)
		}
	}
}

// Sync installs the fence when it is new, changed or failed last time
// (force: always), and checks it when the reassert is due.
func (s *Supervisor) Sync(ctx context.Context, force bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	due := force || now.Sub(s.checkedAt) >= s.reassert

	status := make(map[string]error, len(s.sources))
	var union Spec
	for _, src := range s.sources {
		_, have := s.specs[src.Runtime]
		if due || !have {
			got, err := s.sourceSpec(ctx, src)
			switch {
			case err == nil:
				s.specs[src.Runtime] = got
			case !have:
				status[src.Runtime] = err
				continue
			default:
				// Keep the last names it gave: a source that cannot
				// answer right now (dockerd restarting) must not take
				// its bridge out of the fence under running sandboxes.
				s.logger.Warn("ipv6 fence: interface source failed; keeping its last interfaces", "runtime", src.Runtime, "error", err)
			}
		}
		union = union.Merge(s.specs[src.Runtime])
		status[src.Runtime] = nil
	}
	union, _ = union.Normalize() // every part was normalized already
	key := union.Key()
	rules := Plan(union)

	repaired := false
	switch {
	case force || key != s.applied || s.applyErr != nil:
		s.applyErr = s.be.Apply(rules)
	case due:
		ok, err := s.be.Check(rules)
		if err == nil && !ok {
			err = s.be.Apply(rules)
			repaired = err == nil
		}
		s.applyErr = err
	}
	if s.applyErr != nil {
		s.applied = ""
	} else {
		s.applied = key
	}
	if due {
		s.checkedAt = now
	}
	for rt, err := range status {
		if err == nil && s.applyErr != nil {
			status[rt] = fmt.Errorf("ipv6 fence: install %s: %w", key, s.applyErr)
		}
	}
	s.publish(status, repaired, key)
}

// sourceSpec asks one source for its interfaces.
func (s *Supervisor) sourceSpec(ctx context.Context, src Source) (spec Spec, err error) {
	if src.Spec == nil {
		return Spec{}, fmt.Errorf("ipv6 fence: %s: no interface source", src.Runtime)
	}
	got, err := src.Spec(ctx)
	if err == nil {
		got, err = got.Normalize()
	}
	if err == nil && got.Empty() {
		err = errors.New("no sandbox interface named")
	}
	if err != nil {
		return Spec{}, fmt.Errorf("ipv6 fence: %s: %w", src.Runtime, err)
	}
	return got, nil
}

// publish stores the per-runtime result, exports it and logs each change.
func (s *Supervisor) publish(status map[string]error, repaired bool, key string) {
	var prev map[string]error
	if p := s.status.Load(); p != nil {
		prev = *p
	}
	s.status.Store(&status)
	names := make([]string, 0, len(status))
	for rt := range status {
		names = append(names, rt)
	}
	sort.Strings(names)
	for _, rt := range names {
		err := status[rt]
		v := new(expvar.Int)
		if err == nil {
			v.Set(1)
		}
		ready.Set(rt, v)
		before, seen := prev[rt]
		switch {
		case err == nil && repaired:
			s.logger.Warn("ipv6 fence was missing and has been put back; something rewrote the host firewall", "runtime", rt, "fence", key, "layers", s.layers())
		case seen && errText(before) == errText(err):
		case err == nil:
			s.logger.Info("ipv6 fence installed: no IPv6 between this runtime's sandboxes or from them to the node", "runtime", rt, "fence", key, "layers", s.layers())
		default:
			s.logger.Error("ipv6 fence not installed: this runtime's creates are refused until it is", "runtime", rt, "error", err)
		}
	}
}

// layers says which tables hold the fence when the backend can tell.
func (s *Supervisor) layers() string {
	if l, ok := s.be.(interface{ Layers() string }); ok {
		return l.Layers()
	}
	return "bridge+ip6"
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
