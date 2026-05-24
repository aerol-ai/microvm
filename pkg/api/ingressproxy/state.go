package ingressproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// errAdmissionPerSandbox / errAdmissionGlobal / errBufferBudget are
// the three admission-control rejections the handler maps to 503 +
// Retry-After. They are distinguishable so logs and metrics can show
// which limit fired without parsing message strings.
var (
	errAdmissionPerSandbox = errors.New("per-sandbox pending wake limit exceeded")
	errAdmissionGlobal     = errors.New("global pending wake limit exceeded")
	errBufferBudget        = errors.New("global wake buffer budget exhausted")
)

// proxyState holds the per-listener admission and single-flight state.
// Embedded in handlers so every request shares the same counters.
//
// Two independent concerns:
//
//  1. Admission gating (pendingMu) — caps how many cold-start HTTP
//     requests can simultaneously hold the wake + readiness window
//     per sandbox and across the whole node. Mirrors the L4 admission
//     scheme. Slots are released as soon as the readiness probe
//     finishes; they do NOT cover the proxy hop itself, because at
//     that point the sandbox is warm and behaves like any other
//     reverse-proxy backend.
//
//  2. Probe single-flight (probeMu) — collapses 10k concurrent
//     readiness probes for the same (sandbox, port) to one TCP dial
//     loop with channel fan-out. The wake helper already
//     single-flights StartSandbox; without this, the convoy that
//     wake released would all dial the same container in lockstep.
//
//  3. Buffer-byte budget (bufferMu) — semaphore over the total bytes
//     held in cold-start request buffers. Without this, 10k cold POSTs
//     near MaxBufferBytes could pin >80 GB of memory.
type proxyState struct {
	pendingMu         sync.Mutex
	pendingPerSandbox map[string]int
	pendingGlobal     int
	pendingPerCap     int
	pendingGlobalCap  int

	probeMu      sync.Mutex
	probeFlights map[string]*probeFlight

	bufferMu      sync.Mutex
	bufferedBytes int64
	bufferedCap   int64
}

// probeFlight is one in-flight readiness probe shared by all callers
// converging on the same (sandbox, port). The leader runs the probe
// with a detached context (so the leader's request cancellation does
// not strand followers); followers select on done OR their own
// caller context.
type probeFlight struct {
	done chan struct{}
	err  error
}

func newProxyState(perSandboxCap, globalCap int, bufferCap int64) *proxyState {
	return &proxyState{
		pendingPerSandbox: make(map[string]int),
		pendingPerCap:     perSandboxCap,
		pendingGlobalCap:  globalCap,
		probeFlights:      make(map[string]*probeFlight),
		bufferedCap:       bufferCap,
	}
}

// acquirePending reserves one pending-wake slot for id. Returns a
// release function on success; returns the rejection sentinel
// (errAdmissionPerSandbox / errAdmissionGlobal) when the relevant cap
// would be exceeded. The release function is idempotent.
//
// A zero cap is treated as "no limit" so tests and small deployments
// can opt out without rewiring.
func (s *proxyState) acquirePending(id string) (func(), error) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingGlobalCap > 0 && s.pendingGlobal >= s.pendingGlobalCap {
		return nil, errAdmissionGlobal
	}
	if s.pendingPerCap > 0 && s.pendingPerSandbox[id] >= s.pendingPerCap {
		return nil, errAdmissionPerSandbox
	}
	s.pendingPerSandbox[id]++
	s.pendingGlobal++

	var released bool
	return func() {
		s.pendingMu.Lock()
		defer s.pendingMu.Unlock()
		if released {
			return
		}
		released = true
		if cur := s.pendingPerSandbox[id]; cur <= 1 {
			delete(s.pendingPerSandbox, id)
		} else {
			s.pendingPerSandbox[id] = cur - 1
		}
		if s.pendingGlobal > 0 {
			s.pendingGlobal--
		}
	}, nil
}

// acquireBuffer reserves n bytes from the global buffer budget. Returns
// a release function on success; returns errBufferBudget when the cap
// would be exceeded. Zero cap means unbounded (tests / opt-out).
func (s *proxyState) acquireBuffer(n int64) (func(), error) {
	if n <= 0 {
		return func() {}, nil
	}
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()
	if s.bufferedCap > 0 && s.bufferedBytes+n > s.bufferedCap {
		return nil, errBufferBudget
	}
	s.bufferedBytes += n
	var released bool
	return func() {
		s.bufferMu.Lock()
		defer s.bufferMu.Unlock()
		if released {
			return
		}
		released = true
		s.bufferedBytes -= n
		if s.bufferedBytes < 0 {
			s.bufferedBytes = 0
		}
	}, nil
}

// probeOnce runs the readiness probe at most once per (id, port). If a
// flight is already in progress, all later callers wait on its result.
// The leader runs probeFn in the foreground with a detached context so
// its result is shared even if the leader's own caller drops; followers
// honor their own ctx for cancellation.
func (s *proxyState) probeOnce(
	ctx context.Context,
	id string, port int,
	budget time.Duration,
	probeFn func(context.Context, time.Duration) error,
) error {
	key := fmt.Sprintf("%s:%d", id, port)

	s.probeMu.Lock()
	flight, exists := s.probeFlights[key]
	if !exists {
		flight = &probeFlight{done: make(chan struct{})}
		s.probeFlights[key] = flight
		s.probeMu.Unlock()

		// Leader: run with a detached context capped at budget so
		// followers see a result even if the leader's own request
		// context is cancelled mid-probe.
		probeCtx, cancel := context.WithTimeout(context.Background(), budget)
		flight.err = probeFn(probeCtx, budget)
		cancel()
		close(flight.done)

		s.probeMu.Lock()
		delete(s.probeFlights, key)
		s.probeMu.Unlock()

		// Leader still honors its caller's cancellation: if ctx is
		// already dead by the time the probe returned, surface that
		// (the caller has already given up).
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return flight.err
	}
	s.probeMu.Unlock()

	select {
	case <-flight.done:
		return flight.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
