package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrEgressSelfTestFailed refuses a gateway-mode create on a node whose
// per-bridge self-test failed (plans/egress-domain-filtering.md §5.3 step
// 4, T41): redirected traffic would never reach the gateway there, so the
// sandbox would have no egress at all. 501, like any node that can't offer
// hostname filtering; in a cluster the node also stops advertising
// egress_gateway_ready, so placement goes elsewhere.
var ErrEgressSelfTestFailed = fmt.Errorf("egress hostname filtering is not available on this node (gateway self-test failed): %w", models.ErrRuntimeNotImplemented)

// Self-test retry pacing. An absent bridge (containerd's aerolvm0 before the
// first sandbox) is checked again soon; a failing one backs off, since the
// usual cause is host firewall config that only an operator changes.
const (
	selfTestAbsentRetry = 10 * time.Second
	selfTestMinBackoff  = 10 * time.Second
	selfTestMaxBackoff  = 5 * time.Minute
)

var (
	egressSelfTestFailuresTotal = expvar.NewInt("aerolvm_egress_selftest_failures_total")
	activeEgressSelfTest        atomic.Pointer[egressSelfTest]
)

func init() {
	expvar.Publish("aerolvm_egress_selftest_ok", expvar.Func(func() any {
		if st := activeEgressSelfTest.Load(); st != nil && st.failed.Load() {
			return 0
		}
		return 1
	}))
}

type selfTestStatus int

const (
	selfTestPending selfTestStatus = iota
	selfTestPassed
	selfTestAbsent
	selfTestFailedStatus
)

// egressSelfTest is the per-bridge self-test state.
type egressSelfTest struct {
	probe egress.ProbeNet
	// kick asks the supervisor to re-test now (a gateway-mode attach while
	// a bridge is still untested).
	kick chan struct{}

	failed atomic.Bool
	// tested is set once every bridge has a verdict for the first time;
	// until then the node can't say it filters (startup only: a later
	// re-test keeps the previous verdicts while it runs).
	tested atomic.Bool

	mu        sync.Mutex
	status    map[string]selfTestStatus
	lastErr   map[string]string
	next      time.Time
	backoff   time.Duration
	retestAll bool
}

// SetEgressSelfTest wires the probe network builder. nil (tests, non-Linux)
// skips the self-test.
func (s *Service) SetEgressSelfTest(pn egress.ProbeNet) {
	if pn == nil {
		s.egressSelfTest = nil
		return
	}
	st := &egressSelfTest{probe: pn, kick: make(chan struct{}, 1), status: map[string]selfTestStatus{}, lastErr: map[string]string{}}
	s.egressSelfTest = st
	activeEgressSelfTest.Store(st)
}

// egressSelfTestFailed reports whether some bridge failed its self-test.
func (s *Service) egressSelfTestFailed() bool {
	return s.egressSelfTest != nil && s.egressSelfTest.failed.Load()
}

// egressSelfTestPending reports whether the first self-test round has not
// finished yet, so whether the redirect works is still unknown.
func (s *Service) egressSelfTestPending() bool {
	return s.egressSelfTest != nil && !s.egressSelfTest.tested.Load()
}

// requestEgressSelfTests asks the supervisor to re-test every bridge. A
// full sync calls it (startup, gateway restart): the probe itself runs on
// the supervisor, never inline on a create that happened to trigger the
// sync.
func (s *Service) requestEgressSelfTests() {
	st := s.egressSelfTest
	if st == nil {
		return
	}
	st.mu.Lock()
	st.retestAll = true
	st.next = time.Now()
	st.mu.Unlock()
	select {
	case st.kick <- struct{}{}:
	default:
	}
}

// runEgressSelfTests probes bridges: every one when all is set (after a
// full sync), otherwise only those not yet passed. A verdict (pass, absent,
// fail) is recorded; any other error means the gateway could not be asked
// and is returned, leaving the bridge's state as it was. Callers hold
// egressMu.
func (s *Service) runEgressSelfTests(ctx context.Context, bridges []egress.Bridge, all bool) error {
	st := s.egressSelfTest
	if st == nil {
		return nil
	}
	gw := s.egressGateway()
	var gatewayErr error
	for i, b := range bridges {
		// The TAP pool has no bridge device to probe from. Its guests'
		// traffic is routed, not bridged, and meets the same redirect and
		// wildcard listeners the container bridges' probes exercise.
		if b.Wildcard() {
			continue
		}
		st.mu.Lock()
		cur := st.status[b.Name]
		st.mu.Unlock()
		if !all && cur == selfTestPassed {
			continue
		}
		err := egress.SelfTest(ctx, gw, st.probe, b, i)
		next := cur
		switch {
		case err == nil:
			next = selfTestPassed
		case errors.Is(err, egress.ErrBridgeAbsent):
			next = selfTestAbsent
		case errors.Is(err, egress.ErrSelfTest):
			next = selfTestFailedStatus
			egressSelfTestFailuresTotal.Add(1)
		default:
			gatewayErr = errors.Join(gatewayErr, err)
			continue
		}
		s.recordSelfTest(b.Name, cur, next, err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	anyFailed, anyPending := false, false
	for _, v := range st.status {
		switch v {
		case selfTestFailedStatus:
			anyFailed = true
		case selfTestAbsent, selfTestPending:
			anyPending = true
		}
	}
	st.failed.Store(anyFailed)
	if gatewayErr == nil {
		st.tested.Store(true)
	}
	switch {
	case anyFailed:
		st.backoff = min(max(st.backoff*2, selfTestMinBackoff), selfTestMaxBackoff)
		st.next = time.Now().Add(st.backoff)
	case anyPending:
		st.backoff = 0
		st.next = time.Now().Add(selfTestAbsentRetry)
	default:
		st.backoff = 0
		st.next = time.Time{}
	}
	return gatewayErr
}

// recordSelfTest stores one bridge's verdict and logs transitions only.
func (s *Service) recordSelfTest(bridge string, prev, next selfTestStatus, err error) {
	st := s.egressSelfTest
	st.mu.Lock()
	st.status[bridge] = next
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	changed := prev != next || st.lastErr[bridge] != msg
	st.lastErr[bridge] = msg
	st.mu.Unlock()
	if !changed {
		return
	}
	switch next {
	case selfTestPassed:
		s.logger.Info("egress gateway self-test passed", "bridge", bridge)
	case selfTestFailedStatus:
		s.logger.Error("egress gateway self-test failed; hostname-filtered creates get 501 on this node", "bridge", bridge, "error", msg)
	case selfTestAbsent:
		s.logger.Info("egress gateway self-test waiting for the bridge to appear", "bridge", bridge)
	}
}

// retryEgressSelfTests runs the requested full re-test, or re-tests bridges
// that have not passed once their retry time comes (or on a kick). A bridge
// that appeared since the last discovery is handed to the gateway first, so
// it has listeners to test. A gateway outage mid-test keeps the request for
// the next tick.
func (s *Service) retryEgressSelfTests(ctx context.Context, force bool) {
	st := s.egressSelfTest
	if st == nil || !s.egressReady.Load() {
		return
	}
	st.mu.Lock()
	all := st.retestAll
	due := all || (!st.next.IsZero() && (force || !time.Now().Before(st.next)))
	st.retestAll = false
	st.mu.Unlock()
	if !due {
		return
	}
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	bridges, _ := s.gatewayBridges(ctx)
	err := s.egressGateway().SetBridges(ctx, bridges)
	if err == nil {
		err = s.runEgressSelfTests(ctx, bridges, all)
	}
	if err != nil && all {
		st.mu.Lock()
		st.retestAll = true
		st.mu.Unlock()
	}
}

// kickEgressSelfTest asks the supervisor for an early re-test when a
// bridge is still untested; the attach path calls it, so a fresh containerd
// node tests aerolvm0 right after its first sandbox creates it.
func (s *Service) kickEgressSelfTest() {
	st := s.egressSelfTest
	if st == nil {
		return
	}
	st.mu.Lock()
	pending := !st.next.IsZero()
	st.mu.Unlock()
	if !pending {
		return
	}
	select {
	case st.kick <- struct{}{}:
	default:
	}
}

// egressSelfTestKick is the supervisor's wake channel (nil without a test).
func (s *Service) egressSelfTestKick() <-chan struct{} {
	if s.egressSelfTest == nil {
		return nil
	}
	return s.egressSelfTest.kick
}
