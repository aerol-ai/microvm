package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Host egress rules belong to an address, not to a sandbox (review 6). A
// container's CIDR rule sets and hold DROP are keyed by its source IP, so
// they outlive the sandbox row and the process, and the address's next
// owner shares their specs: an allowlist's catch-all DROP and the hold DROP
// are the same rule for every sandbox on the IP. An old ACCEPT left above a
// new owner's reused DROP lets the new owner out, and clearing the old rules
// after the handoff removes the DROP the new owner relies on.
//
// So what a sandbox leaves at an address is recorded against the address,
// durably (pending_egress_rule_clears), before it is cleared, and is only
// ever cleared two ways:
//   - nobody holds the address: the rules are removed outright;
//   - a started sandbox holds it: that sandbox's enforcement is rebuilt by
//     the transition applicator, which removes them under its swap block
//     and then puts its own rules back (clearPendingFor), so the specs both
//     share come back and nothing is open in between.
//
// Every path that installs a container's enforcement checks the address
// (create, start, reconcile, transitions), and every path that lets go of
// one records it first (stop, destroy, reconcile of a runtime gone or
// moved), so a handoff in either order ends with the new owner rebuilt; a
// clear that ran while a new owner's rules were going in, before its row
// showed it, is caught by the clear log (egressClearLog).

// errEgressAttach marks a transition that failed only at the gateway
// attach: a start keeps the sandbox, shut and held, rather than stopping it.
var errEgressAttach = errors.New("egress gateway attach")

type ruleClearKey struct{ scope, ip string }

func (k ruleClearKey) String() string { return k.scope + "|" + k.ip }

// ruleScope names the firewall a container sandbox's rules live in: its
// engine's, or Firecracker's.
func ruleScope(sb *models.Sandbox) string {
	if sb.Runtime == models.RuntimeFirecracker {
		return models.RuntimeFirecracker
	}
	return models.SandboxEngine(sb)
}

func ruleClearKeyOf(sb *models.Sandbox) ruleClearKey {
	return ruleClearKey{scope: ruleScope(sb), ip: sb.ContainerIP}
}

// scopeRuntime is the container runtime whose firewall scope names.
func (s *Service) scopeRuntime(scope string) (runtime.ContainerRuntime, error) {
	if scope == models.RuntimeFirecracker {
		return s.containerRuntimeForSandbox(&models.Sandbox{Runtime: models.RuntimeFirecracker})
	}
	return s.containerRuntimeForSandbox(&models.Sandbox{Engine: scope})
}

// hasHostRules reports whether sb's egress is enforced by host rules on its
// address: a container or VM, not a WASM or isolate sandbox, whose mediator
// enforces it.
func (s *Service) hasHostRules(sb *models.Sandbox) bool {
	return !s.isWasmSandbox(sb) && !s.isIsolateSandbox(sb)
}

// egressRuleClears is the pending rule clears this process works from: the
// store's ledger, read once (the lazy bootstrap latch), plus every entry
// written since. An entry the store refused stays here, so this process
// still retries it.
type egressRuleClears struct {
	loaded atomic.Bool
	loadMu sync.Mutex
	mu     sync.Mutex
	m      map[ruleClearKey]store.PendingEgressRuleClear
}

func (p *egressRuleClears) get(k ruleClearKey) (store.PendingEgressRuleClear, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[k]
	return e, ok
}

func (p *egressRuleClears) put(e store.PendingEgressRuleClear) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := ruleClearKey{e.Scope, e.IP}
	if e.Empty() {
		delete(p.m, k)
		return
	}
	if p.m == nil {
		p.m = map[ruleClearKey]store.PendingEgressRuleClear{}
	}
	p.m[k] = e
}

func (p *egressRuleClears) snapshot() map[ruleClearKey]store.PendingEgressRuleClear {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.m)
}

// egressClearLog numbers the clears of addresses nobody held and keeps the
// latest few. ipHolder sees a new owner only once its row carries the
// address (or, for docker and pooled netns, once the runtime has it), but
// its driver installs its rules before that: a clear in between, from a
// stop or destroy handled late, removes the specs they share, its
// catch-all DROP among them, and it is left with only its ACCEPTs. So
// create and start note the generation before their rules go in and check,
// once the row is stored, whether their own address was cleared since
// (settleEnforcedEgress); if so they are rebuilt.
type egressClearLog struct {
	gen  atomic.Uint64
	mu   sync.Mutex
	ring [256]clearMark
	next int
}

type clearMark struct {
	k   ruleClearKey
	gen uint64
}

func (l *egressClearLog) now() uint64 { return l.gen.Load() }

func (l *egressClearLog) mark(k ruleClearKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring[l.next] = clearMark{k, l.gen.Add(1)}
	l.next = (l.next + 1) % len(l.ring)
}

// clearedSince reports whether k was cleared after gen. Past the ring's
// reach it can't tell, and says yes: the rebuild that answers it is safe.
func (l *egressClearLog) clearedSince(k ruleClearKey, gen uint64) bool {
	cur := l.gen.Load()
	switch {
	case cur == gen:
		return false
	case cur-gen > uint64(len(l.ring)):
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.ring {
		if m.gen > gen && m.k == k {
			return true
		}
	}
	return false
}

// mergeRuleClears is a ∪ b at one address.
func mergeRuleClears(a, b store.PendingEgressRuleClear) store.PendingEgressRuleClear {
	out := b
	out.Rules = unionInstalled(store.InstalledEgress{CIDR: a.Rules}, store.InstalledEgress{CIDR: b.Rules}).CIDR
	out.Hold = a.Hold || b.Hold
	if !a.CreatedAt.IsZero() {
		out.CreatedAt = a.CreatedAt
	}
	return out
}

// loadRuleClears reads the store's ledger into the working set once per
// process. It is single-flight, and a failed read is tried again by the
// next caller.
func (s *Service) loadRuleClears(ctx context.Context) error {
	p := &s.egressRuleClears
	if p.loaded.Load() {
		return nil
	}
	p.loadMu.Lock()
	defer p.loadMu.Unlock()
	if p.loaded.Load() {
		return nil
	}
	list, err := s.store.ListPendingEgressRuleClears(ctx)
	if err != nil {
		return err
	}
	for _, e := range list {
		if cur, ok := p.get(ruleClearKey{e.Scope, e.IP}); ok {
			e = mergeRuleClears(e, cur)
		}
		p.put(e)
	}
	p.loaded.Store(true)
	return nil
}

// pendingRuleClear is what is pending at k.
func (s *Service) pendingRuleClear(ctx context.Context, k ruleClearKey) (store.PendingEgressRuleClear, bool, error) {
	if err := s.loadRuleClears(ctx); err != nil {
		return store.PendingEgressRuleClear{}, false, err
	}
	e, ok := s.egressRuleClears.get(k)
	return e, ok, nil
}

// rulesPendingAt reports whether rules another enforcement left may be at
// sb's address. It is a map lookup once the ledger is read, so the create
// path pays nothing for it. Unknown (the ledger can't be read) counts as
// yes: the rebuild that answers it fails closed.
func (s *Service) rulesPendingAt(ctx context.Context, sb *models.Sandbox) bool {
	if sb.ContainerIP == "" || !s.hasHostRules(sb) {
		return false
	}
	_, ok, err := s.pendingRuleClear(ctx, ruleClearKeyOf(sb))
	return ok || err != nil
}

// recordRuleClear durably records that e's rules may be left at its
// address, merged with what is pending there. With clearInstalledFor set,
// the same write drops that sandbox's installed record: its rules now
// belong to the address, and a crash can't leave them in neither place.
// Callers hold the address's lock. The error is a write the store refused:
// the entry is then retried by this process only.
func (s *Service) recordRuleClear(ctx context.Context, e store.PendingEgressRuleClear, clearInstalledFor string) (store.PendingEgressRuleClear, error) {
	_ = s.loadRuleClears(ctx) // best effort: the store merges with its own entry anyway
	if cur, ok := s.egressRuleClears.get(ruleClearKey{e.Scope, e.IP}); ok {
		e = mergeRuleClears(cur, e)
	}
	merged, err := s.store.AddPendingEgressRuleClear(ctx, e, clearInstalledFor, time.Now().UTC())
	if err != nil {
		merged = e
		err = fmt.Errorf("record the egress rules left at %s: %w", e.IP, err)
	}
	s.egressRuleClears.put(merged)
	return merged, err
}

// settleRuleClear records what is left at e's address after a clear: the
// entry goes when nothing is. Callers hold the address's lock.
func (s *Service) settleRuleClear(ctx context.Context, e store.PendingEgressRuleClear) {
	s.egressRuleClears.put(e)
	if err := s.store.SetPendingEgressRuleClear(ctx, e, time.Now().UTC()); err != nil {
		// The store keeps an older, larger entry: a later process clears
		// rules that are already gone, which is idempotent.
		s.logger.Warn("egress: pending rule clear not updated", "ip", e.IP, "error", err)
	}
}

// ruleClear is the CIDR rule sets and hold DROP to remove from an IP.
type ruleClear struct {
	sets []store.CIDRRules
	hold bool
}

// clearRules removes rc from ip and returns what it couldn't remove. All
// removals are idempotent.
func clearRules(cr runtime.ContainerRuntime, ip string, rc ruleClear, warn func(error)) ruleClear {
	var left ruleClear
	for _, r := range rc.sets {
		if err := cr.ClearEgressPolicy(ip, r.Allow, r.Deny); err != nil {
			warn(err)
			left.sets = append(left.sets, r)
		}
	}
	if holder, ok := cr.(runtime.EgressHolder); ok && rc.hold {
		if err := holder.ClearEgressHold(ip); err != nil {
			warn(err)
			left.hold = true
		}
	}
	return left
}

// clearUnheld removes everything pending at e's address, which no sandbox
// holds, and records what is left. It is logged before anything goes, so a
// new owner the store didn't show yet sees it (egressClearLog). Callers
// hold the address's lock.
func (s *Service) clearUnheld(ctx context.Context, cr runtime.ContainerRuntime, e store.PendingEgressRuleClear) {
	s.egressClears.mark(ruleClearKey{e.Scope, e.IP})
	left := clearRules(cr, e.IP, ruleClear{sets: e.Rules, hold: e.Hold}, func(err error) {
		s.logger.Warn("egress rule clear failed", "ip", e.IP, "error", err)
	})
	e.Rules, e.Hold = left.sets, left.hold
	s.settleRuleClear(ctx, e)
}

// ipHolder is the sandbox that holds ip now, other than leaving: from the
// store (creating and started rows, claimed netns slots) and, when the
// runtime can tell, its own view, which must agree. known is false when
// that can't be settled: a lookup failed, two claim it, or the store names
// a sandbox the runtime doesn't have on the address (a row whose container
// is gone, which reconcile settles). Nothing is cleared or rebuilt then: a
// wrong clear fails open, and a rebuild of a sandbox that isn't there would
// put its rules back on an address it no longer has.
func (s *Service) ipHolder(ctx context.Context, cr runtime.ContainerRuntime, ip, leaving string) (holder string, known bool) {
	claimants, err := s.store.SandboxIDsClaimingContainerIP(ctx, ip)
	if err != nil {
		return "", false
	}
	for _, id := range claimants {
		if id == leaving {
			continue
		}
		if holder != "" && holder != id {
			return "", false
		}
		holder = id
	}
	resolver, ok := cr.(runtime.IPOwnerResolver)
	if !ok {
		return holder, true
	}
	owner, err := resolver.IPOwner(ctx, ip)
	if err != nil {
		return "", false
	}
	if owner == leaving {
		owner = ""
	}
	if holder != "" && owner != holder {
		return "", false
	}
	return owner, true
}

// teardownSandboxEgress removes the egress enforcement a sandbox leaves at
// ip as it lets go of the address (a stop, a destroy, a runtime reconcile
// finds gone or moved): the gateway attachment (retried until it lands),
// every CIDR rule set the installed record names, and the hold DROP. A
// partial transition can leave a gateway and CIDR rules at once, so
// neither excludes the other; every exit path uses this, so none tears
// down less than another (review 5 findings 5 and 6).
//
// The rules are recorded against the address first, in the same write
// that drops the installed record, and only then cleared, so a failure, a
// crash or a restart leaves them in the ledger for the retry rather than
// nowhere (review 6 findings 3 and 4). If another sandbox may already hold
// the address, they are not cleared here: that sandbox's enforcement is
// rebuilt instead (finding 1). The error is a record the store refused:
// a destroy must then keep its row, the retry anchor.
func (s *Service) teardownSandboxEgress(ctx context.Context, sb *models.Sandbox, ip string) error {
	holder, err := s.leaveAddress(ctx, sb, ip)
	if holder != "" {
		s.rebuildHolder(ctx, holder)
	}
	return err
}

// leaveAddress is the teardown under sb's policy lock, the one a rebuild of
// sb takes, so a rebuild that saw sb running can't put its rules back after
// they were recorded and cleared here. The lock is released before another
// sandbox is rebuilt: the striped locks are never held two at a time.
func (s *Service) leaveAddress(ctx context.Context, sb *models.Sandbox, ip string) (string, error) {
	unlock := s.egressPolicyLocks.lock(sb.ID)
	defer unlock()
	inst, _, err := s.installedEgress(ctx, sb)
	if err != nil {
		// Unknown: tear down what the stored policy installs, and try the
		// detach, a no-op for a sandbox the gateway doesn't have.
		inst = installedOf(sb)
		inst.Gateway = true
	}
	if inst.Gateway || isGatewayMode(sb) {
		s.detachSandboxEgress(ctx, sb, ip)
	}
	if ip == "" || !s.hasHostRules(sb) {
		return "", nil
	}
	return s.leaveRules(ctx, store.PendingEgressRuleClear{
		Scope: ruleScope(sb), IP: ip, SandboxID: sb.ID, Rules: inst.CIDR, Hold: true,
	})
}

// leaveRules records e, then clears what is pending at its address if no
// other sandbox may hold it, and returns that sandbox if one does. A record
// the store refused is an error only while something is still left: once
// everything is cleared there is nothing for a restart to lose.
func (s *Service) leaveRules(ctx context.Context, e store.PendingEgressRuleClear) (string, error) {
	k := ruleClearKey{e.Scope, e.IP}
	unlock := s.egressIPLocks.lock(k.String())
	defer unlock()
	merged, err := s.recordRuleClear(ctx, e, e.SandboxID)
	cr, cerr := s.scopeRuntime(e.Scope)
	if cerr != nil {
		return "", err // the retry clears them once the runtime is there
	}
	holder, known := s.ipHolder(ctx, cr, e.IP, e.SandboxID)
	if !known || holder != "" {
		return holder, err
	}
	s.clearUnheld(ctx, cr, merged)
	if _, left := s.egressRuleClears.get(k); !left {
		return "", nil
	}
	return "", err
}

// rebuildHolder rebuilds the enforcement of the sandbox holding an address
// with rules pending at it. One still being created is left alone: its
// create checks the address once it is stored started (settleEnforcedEgress),
// and the supervisor's pass catches the rest.
func (s *Service) rebuildHolder(ctx context.Context, id string) {
	if err := s.rebuildEgress(ctx, id, nil, false); err != nil {
		s.logger.Debug("egress: rebuild of the address's holder failed", "sandbox_id", id, "error", err)
	}
}

// clearPendingFor clears the rules pending at owner's address before its
// own go back in. The caller has the address shut (the swap block) and
// re-applies owner's enforcement after, so the specs both share come back.
// The hold DROP is owner's to keep or lift: a leftover one goes only if
// owner has no hold of its own. Anything left is an error, so the caller
// holds owner (fail closed) and the retry tries again.
func (s *Service) clearPendingFor(ctx context.Context, cr runtime.ContainerRuntime, owner *models.Sandbox) error {
	k := ruleClearKeyOf(owner)
	unlock := s.egressIPLocks.lock(k.String())
	defer unlock()
	e, ok, err := s.pendingRuleClear(ctx, k)
	if err != nil {
		return fmt.Errorf("read the egress rules left at the address: %w", err)
	}
	if !ok {
		return nil
	}
	clearHold := false
	if e.Hold {
		unlockHold := s.egressHoldLocks.lock(owner.ID)
		defer unlockHold()
		held, herr := s.egressHeld(ctx, owner)
		switch {
		case herr != nil:
			// Unknown: the DROP stays, and so does the entry.
		case held:
			e.Hold = false // owner's own hold now, lifted by its release
		default:
			clearHold = true
		}
	}
	left := clearRules(cr, owner.ContainerIP, ruleClear{sets: e.Rules, hold: clearHold}, func(err error) {
		s.logger.Warn("egress rule clear failed", "sandbox_id", owner.ID, "ip", owner.ContainerIP, "error", err)
	})
	e.Rules = left.sets
	if clearHold {
		e.Hold = left.hold
	}
	s.settleRuleClear(ctx, e)
	if !e.Empty() {
		return fmt.Errorf("egress rules left at %s by another enforcement are not cleared yet", owner.ContainerIP)
	}
	return nil
}

// retryRuleClears works the pending rule clears: an address nobody holds is
// cleared; one a sandbox holds has that sandbox's enforcement rebuilt; one
// that can't be settled (a lookup failed, the runtime isn't there) waits
// for a later pass. The first pass after a restart reads the ledger from
// the store (review 6 finding 3).
func (s *Service) retryRuleClears(ctx context.Context) {
	if err := s.loadRuleClears(ctx); err != nil {
		s.logger.Debug("egress: pending rule clears not read", "error", err)
		return
	}
	for k := range s.egressRuleClears.snapshot() {
		if holder := s.retryRuleClear(ctx, k); holder != "" {
			s.rebuildHolder(ctx, holder)
		}
	}
}

func (s *Service) retryRuleClear(ctx context.Context, k ruleClearKey) string {
	cr, err := s.scopeRuntime(k.scope)
	if err != nil {
		return ""
	}
	unlock := s.egressIPLocks.lock(k.String())
	defer unlock()
	e, ok := s.egressRuleClears.get(k)
	if !ok {
		return ""
	}
	// Nobody is leaving: a sandbox whose own row still claims the address
	// (its destroy failed, say) is its holder, and is rebuilt like any.
	holder, known := s.ipHolder(ctx, cr, k.ip, "")
	if !known || holder != "" {
		return holder
	}
	s.clearUnheld(ctx, cr, e)
	return ""
}

// rebuildEgress applies a sandbox's stored policy again when there is
// something to finish: an apply_failed hold, a transition that didn't
// finish (its installed record), or rules another enforcement left at its
// address. live, when set, is the caller's view of the container (its
// current IP and status, which it may not have stored yet); the policy is
// the stored one, read under the policy lock, and is copied back into live
// so the caller's own row write doesn't put an older one back. It resolved
// no profiles, so a profile hold stays.
//
// force rebuilds even with nothing recorded to finish: the address was
// cleared while the caller's rules were going in (egressClearLog).
func (s *Service) rebuildEgress(ctx context.Context, id string, live *models.Sandbox, force bool) error {
	unlock := s.egressPolicyLocks.lock(id)
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if live != nil {
		sb.ContainerID, sb.ContainerIP, sb.Status = live.ContainerID, live.ContainerIP, live.Status
		adoptStoredPolicy(live, sb)
	}
	st, err := s.store.GetEgressState(ctx, id)
	if err != nil {
		return err
	}
	if st.Installed == nil && st.HoldReason != egressHoldApplyFailed {
		if sb.Status != models.SandboxStatusStarted || !force && !s.rulesPendingAt(ctx, sb) {
			return nil
		}
		// Only rules another enforcement left: rebuilt only for a container
		// the runtime has running on that address now (the caller's live
		// view says so). A row whose container is gone, or just stopped with
		// its teardown next, would otherwise get its rules put back on an
		// address it no longer has, and the entry that names them dropped.
		if live == nil && !s.runningAt(ctx, sb) {
			return nil
		}
	}
	return s.applyStoredTransition(ctx, sb, sb, applyHolds)
}

// runningAt reports whether the runtime has sb's container running on
// sb.ContainerIP now.
func (s *Service) runningAt(ctx context.Context, sb *models.Sandbox) bool {
	rt, err := s.runtimeForSandbox(sb)
	if err != nil {
		return false
	}
	state, err := rt.Inspect(ctx, s.runtimeRef(sb))
	return err == nil && state != nil && state.Status == models.SandboxStatusStarted && state.ContainerIP == sb.ContainerIP
}

// adoptStoredPolicy gives sb the stored policy of cur (the columns a policy
// write owns), keeping sb's view of the container.
func adoptStoredPolicy(sb, cur *models.Sandbox) {
	sb.NetworkBlockAll = cur.NetworkBlockAll
	sb.NetworkAllowOut = cur.NetworkAllowOut
	sb.NetworkDenyOut = cur.NetworkDenyOut
	sb.NetworkEgressMode = cur.NetworkEgressMode
	sb.NetworkEgressRules = cur.NetworkEgressRules
}

// settleEnforcedEgress runs once a create or start has stored its row
// with its address, and rebuilds the sandbox's enforcement if the address
// has rules another sandbox left there (review 6 finding 1), or was
// cleared since clearGen, when its rules were about to go in
// (egressClearLog). Under the address's lock, so a sandbox leaving the
// address either saw this one as its holder or recorded and logged its
// clear before this check. Normally a lock, an atomic read and a map
// lookup.
func (s *Service) settleEnforcedEgress(ctx context.Context, sb *models.Sandbox, clearGen uint64) {
	if sb.Status != models.SandboxStatusStarted || sb.ContainerIP == "" || !s.hasHostRules(sb) {
		return
	}
	k := ruleClearKeyOf(sb)
	unlock := s.egressIPLocks.lock(k.String())
	cleared := s.egressClears.clearedSince(k, clearGen)
	_, pending, err := s.pendingRuleClear(ctx, k)
	unlock()
	if !cleared && !pending && err == nil {
		return
	}
	if err := s.rebuildEgress(ctx, sb.ID, sb, cleared); err != nil {
		// The applicator held it (apply_failed): shut, and retried.
		s.logger.Warn("egress: sandbox's address not rebuilt; held", "sandbox_id", sb.ID, "ip", sb.ContainerIP, "error", err)
	}
}

// enforceEgressOnStart puts a container's stored egress policy in place as
// it starts, before the start reports success or publishes a route, under
// the policy lock so a PUT can't interleave. It is the plain apply unless
// the sandbox has an unfinished transition (its installed record) or its
// address has rules another enforcement left: then the transition
// applicator rebuilds the address's enforcement under its swap block, so a
// start never succeeds with old rules still effective (review 6 finding
// 2). sb is the caller's view (its new IP and status); the stored policy,
// read under the lock, replaces its policy, so a PUT that finished since
// the caller read the row is what goes in, and what the caller writes back.
func (s *Service) enforceEgressOnStart(ctx context.Context, cr runtime.ContainerRuntime, sb *models.Sandbox) error {
	unlock := s.egressPolicyLocks.lock(sb.ID)
	defer unlock()
	cur, err := s.store.Get(ctx, sb.ID)
	var st store.EgressState
	if err == nil {
		adoptStoredPolicy(sb, cur)
		st, err = s.store.GetEgressState(ctx, sb.ID)
	} else if errors.Is(err, store.ErrNotFound) {
		err = nil
	}
	if err != nil {
		// The store can't say what to enforce. A sandbox with nothing to
		// enforce and nothing left at its address starts as before, and
		// the caller's row write reports the store; any other is refused.
		if !hasEgressConfig(sb) && !s.rulesPendingAt(ctx, sb) {
			return nil
		}
		return fmt.Errorf("apply egress on start: %w", err)
	}
	if st.Installed == nil && !s.rulesPendingAt(ctx, sb) {
		return s.applyEgressOnStart(ctx, cr, sb)
	}
	err = s.applyStoredTransition(ctx, sb, sb, applyHolds)
	if errors.Is(err, errEgressAttach) {
		// Shut and held (apply_failed), as a plain start whose attach
		// fails is: the start succeeds and the retry finishes the rest.
		return nil
	}
	if err != nil {
		return fmt.Errorf("apply egress on start: %w", err)
	}
	return nil
}

// applyEgressOnStart is the plain start apply: block-all and the
// selective-egress policy on the container's IP (both Exists-guarded), or
// for gateway mode the block-all DROP and the attach. A failed attach
// leaves the sandbox shut and held rather than stopping it: the hold is the
// gateway-mode fail-closed state (CEO D16).
func (s *Service) applyEgressOnStart(ctx context.Context, cr runtime.ContainerRuntime, sb *models.Sandbox) error {
	if isGatewayMode(sb) {
		if err := cr.ApplyNetworkBlockAll(sb.ContainerIP); err != nil {
			return fmt.Errorf("apply network block on start: %w", err)
		}
		if err := s.attachSandboxEgress(ctx, sb, cr); err != nil {
			s.holdSandboxEgress(ctx, sb, cr, egressHoldUnavailable)
		}
		return nil
	}
	if sb.NetworkBlockAll {
		if err := cr.ApplyNetworkBlockAll(sb.ContainerIP); err != nil {
			return fmt.Errorf("apply network block on start: %w", err)
		}
	}
	if len(sb.NetworkAllowOut) > 0 || len(sb.NetworkDenyOut) > 0 {
		if err := cr.ApplyEgressPolicy(sb.ContainerIP, sb.NetworkAllowOut, sb.NetworkDenyOut); err != nil {
			return fmt.Errorf("apply egress policy on start: %w", err)
		}
	}
	// A VM's stop-time block lifts once its policy is back in place (the
	// transition applicator lifts its own swap block, the same rule).
	if err := s.liftStartedGuest(cr, sb); err != nil {
		s.logger.Warn("egress: lift the stop-time block on start failed", "sandbox_id", sb.ID, "error", err)
	}
	return nil
}
