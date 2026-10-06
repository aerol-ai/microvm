package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrEgressOperatorConfigInvalid refuses every create while the operator
// file (SB_EGRESS_OPERATOR_FILE, plans/egress-domain-filtering.md §5.10) is
// present but invalid at boot: the default policy and the ceiling are
// unknown, so the only safe answer is no (503, code
// egress_operator_config_invalid). An invalid reload keeps the last good
// file instead and never lands here.
var ErrEgressOperatorConfigInvalid = errors.New("egress operator file is invalid; creates are refused until it is fixed")

// Operator-file metrics. The info series carries the file's hash as its
// label, so SandboxdEgressOperatorConfigDrift can compare nodes.
var (
	egressOperatorInfo     = expvar.NewMap("aerolvm_egress_operator_config_info")
	egressOperatorInfoMu   sync.Mutex
	activeEgressOperatorFn atomic.Pointer[operator.Watcher]
)

func init() {
	expvar.Publish("aerolvm_egress_operator_config_load_failures_total", expvar.Func(func() any {
		if w := activeEgressOperatorFn.Load(); w != nil {
			return w.Failures()
		}
		return 0
	}))
}

// SetEgressOperator wires the operator-file watcher (nil: no file, today's
// behavior). The daemon runs the watcher's poll loop.
func (s *Service) SetEgressOperator(w *operator.Watcher) {
	s.egressOperatorWatcher = w
	if w != nil {
		activeEgressOperatorFn.Store(w)
		publishOperatorHash(w.Current())
		s.applyEgressFloor(context.Background(), w.Current())
	}
}

// OnEgressOperatorChange is the watcher's change callback: it refreshes the
// drift metric and the host-firewall floor. The gateway reads the file
// itself; the control-port guard follows on the next supervisor tick.
func (s *Service) OnEgressOperatorChange(op *operator.Operator) {
	publishOperatorHash(op)
	s.applyEgressFloor(context.Background(), op)
}

// applyEgressFloor installs the operator's deny_cidrs as a node-wide DROP on
// each container engine's bridge (§5.10 PC-2). It is the floor's copy that
// works without the egress gateway; failures are logged, not fatal, because
// the gateway's own floor and the WASM/isolate dial guards still hold it.
func (s *Service) applyEgressFloor(ctx context.Context, op *operator.Operator) {
	if s == nil || op == nil {
		return
	}
	for _, rt := range []runtime.Runtime{s.docker, s.containerd} {
		fs, ok := rt.(runtime.EgressFloorSetter)
		if !ok || rt == nil {
			continue
		}
		if err := fs.SetEgressFloor(ctx, op.DenyFloor()); err != nil {
			s.logger.Error("egress: deny floor not installed on the host firewall", "error", err)
		}
	}
}

func publishOperatorHash(op *operator.Operator) {
	egressOperatorInfoMu.Lock()
	defer egressOperatorInfoMu.Unlock()
	egressOperatorInfo.Init()
	if op != nil {
		v := new(expvar.Int)
		v.Set(1)
		egressOperatorInfo.Set(op.Hash(), v)
	}
}

// egressOperator returns the last good operator file, or nil.
func (s *Service) egressOperator() *operator.Operator {
	if s == nil || s.egressOperatorWatcher == nil {
		return nil
	}
	return s.egressOperatorWatcher.Current()
}

// hasEgressFields reports whether a create says anything about egress.
func hasEgressFields(req *models.CreateSandboxRequest) bool {
	return req.NetworkBlockAll || len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0
}

// applyEgressOperatorPolicy applies the operator file to a create (§5.10
// PC-2), before any runtime work:
//   - a create with no egress fields gets the default policy, written into
//     the request so the stored spec carries it: GET shows it, failover
//     replays it, and a later edit of the file never changes a running
//     sandbox;
//   - the effective policy must fit the ceiling, or the create is refused
//     with 400 naming the entry.
//
// A failover replay is exempt from both: its stored spec already carries
// what was decided at create, and a ceiling tightened since must not strand
// a running sandbox. Org references in the default are expanded to their
// entries until profiles exist as references (Phase 2).
func (s *Service) applyEgressOperatorPolicy(req *models.CreateSandboxRequest, replay bool) error {
	if s.egressOperatorWatcher != nil {
		if err := s.egressOperatorWatcher.BootError(); err != nil {
			return fmt.Errorf("%w: %v", ErrEgressOperatorConfigInvalid, err)
		}
	}
	op := s.egressOperator()
	if op == nil || replay {
		return nil
	}
	if !hasEgressFields(req) {
		switch op.DefaultMode() {
		case operator.ModeBlockAll:
			req.NetworkBlockAll = true
		case operator.ModeAllowlist:
			allow, err := expandOrgRefs(op, op.DefaultAllowOut())
			if err != nil {
				return err
			}
			req.NetworkAllowOut = allow
		}
	}
	// A transparent CONNECT on arbitrary ports is out of scope (§5.10 PC-4):
	// host:port rules for names the upstream proxies must be 80 or 443.
	for _, raw := range req.NetworkAllowOut {
		e, err := egresspolicy.ParseEntry(raw)
		if err != nil || e.Port == 0 || e.Port == 80 || e.Port == 443 {
			continue
		}
		if (e.Kind == egresspolicy.KindHost || e.Kind == egresspolicy.KindWildcard) && op.ProxiesName(e.Host) {
			return fmt.Errorf("%w: network_allow_out entry %q: %s is reached through the upstream proxy, which only carries ports 80 and 443", egresspolicy.ErrInvalid, raw, e.Host)
		}
	}
	if c := op.Ceiling(); c != nil {
		pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: req.NetworkAllowOut, DenyOut: req.NetworkDenyOut, BlockAll: req.NetworkBlockAll})
		if err != nil {
			return err
		}
		if err := c.Fits(pol); err != nil {
			return fmt.Errorf("%w: egress policy is outside this deployment's ceiling: %v", egresspolicy.ErrInvalid, err)
		}
	}
	return nil
}

// expandOrgRefs replaces org:<name> entries with the profile's entries.
func expandOrgRefs(op *operator.Operator, entries []string) ([]string, error) {
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e, operator.OrgProfilePrefix) {
			out = append(out, e)
			continue
		}
		p, ok := op.OrgProfile(e)
		if !ok {
			return nil, fmt.Errorf("%w: default policy references unknown %s", egresspolicy.ErrInvalid, e)
		}
		for _, entry := range p.AllowEntries() {
			out = append(out, entry.String())
		}
	}
	return out, nil
}
