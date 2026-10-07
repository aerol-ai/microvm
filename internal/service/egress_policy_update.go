package service

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrEgressSpecCommitFailed means a policy update could not be committed to
// the cluster's replicated spec, so nothing changed (503
// spec_commit_failed). Committing first and strictly (D10) is what keeps a
// failover from resurrecting the old policy.
var ErrEgressSpecCommitFailed = errors.New("egress policy update not committed to the cluster; nothing changed")

// ErrEgressApplyFailedHeld means a policy update is stored but could not be
// made live. A running container sandbox is held without egress (D16) until
// a retry of the idempotent PUT or the reconcile pass applies it (503
// apply_failed_held).
var ErrEgressApplyFailedHeld = errors.New("egress policy stored but not applied; the sandbox is held until it can be")

// ErrEgressPolicyBusy means the sandbox is mid-create or mid-transition, so
// a policy written now could be overtaken by the request it was created
// with (409, retry shortly).
var ErrEgressPolicyBusy = errors.New("sandbox is changing state; retry the egress policy update shortly")

// wasmEgressPolicySetter replaces a WASM sandbox's mediator policy live.
type wasmEgressPolicySetter interface {
	SetEgressPolicy(sandboxID string, allow, deny []string, learn bool) error
}

// isolateEgressPolicyUpdater replaces an isolate sandbox's egress proxy
// policy live.
type isolateEgressPolicyUpdater interface {
	UpdateEgressPolicy(sandboxID string, blockAll bool, allow, deny []string, learn bool, rules []egresspolicy.RuleSpec, secrets map[string]string) error
}

// egressPolicyLocks serializes policy updates per sandbox (§5.8 step 2). A
// fixed set of stripes keeps memory flat across sandbox churn; two sandboxes
// sharing a stripe only queue behind each other.
type egressPolicyLocks [64]sync.Mutex

func (l *egressPolicyLocks) lock(id string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	mu := &l[h.Sum32()%uint32(len(l))]
	mu.Lock()
	return mu.Unlock
}

// UpdateNetworkPolicy replaces a sandbox's egress policy live
// (plans/egress-domain-filtering.md §5.8). Steps, under a per-sandbox mutex:
// validate with the create grammar and the operator ceiling; in a cluster,
// commit the patched spec first and strictly (a failure returns 503 and
// changes nothing, D10); write the store; apply the transition, tightening
// before loosening. A 2xx means the policy is stored, replicated and live. A
// stopped container is only stored; Start applies it. Sending the current
// policy again is a no-op, so the PUT is safe to retry.
func (s *Service) UpdateNetworkPolicy(ctx context.Context, id string, req models.NetworkPolicyRequest) (*models.NetworkPolicy, error) {
	return s.updateNetworkPolicy(ctx, id, req, false)
}

// UpdateNetworkLists replaces a sandbox's block-all flag and allow and deny
// lists and keeps its profile references, for facades whose APIs can't
// express profiles (E2B updateNetwork, D19). The references are read under
// the same per-sandbox lock as the write, so a concurrent native PUT can't
// be undone. Block-all on a sandbox that references profiles is a 409:
// clearing them is the owner's call, through the native API.
func (s *Service) UpdateNetworkLists(ctx context.Context, id string, blockAll bool, allowOut, denyOut []string) (*models.NetworkPolicy, error) {
	return s.updateNetworkPolicy(ctx, id, models.NetworkPolicyRequest{NetworkBlockAll: blockAll, NetworkAllowOut: allowOut, NetworkDenyOut: denyOut}, true)
}

// ErrEgressLearnConflict is a facade update that sets lists on a learn-mode
// sandbox (409): learn mode needs empty lists, and switching it to enforce is
// the owner's call, through the native API.
var ErrEgressLearnConflict = errors.New("sandbox is in egress learn mode; switch it to enforce with the native policy API before setting lists")

// ErrEgressProfilesConflict is a facade block-all on a sandbox that
// references egress profiles (409).
var ErrEgressProfilesConflict = errors.New("sandbox references egress profiles; clear them with the native policy API before blocking all egress")

func (s *Service) updateNetworkPolicy(ctx context.Context, id string, req models.NetworkPolicyRequest, keepProfiles bool) (*models.NetworkPolicy, error) {
	if s.egressOperatorWatcher != nil {
		if err := s.egressOperatorWatcher.BootError(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEgressOperatorConfigInvalid, err)
		}
	}
	unlock := s.egressPolicyLocks.lock(id)
	defer unlock()

	old, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	switch old.Status {
	case models.SandboxStatusCreating, models.SandboxStatusAwaitingRuntime, models.SandboxStatusPassivateFailed:
		return nil, fmt.Errorf("%w (status %s)", ErrEgressPolicyBusy, old.Status)
	}
	prior, err := s.store.GetSandboxEgressProfiles(ctx, id)
	if err != nil {
		return nil, err
	}
	if keepProfiles {
		req.EgressProfiles = nil
		for _, r := range prior.Refs {
			req.EgressProfiles = append(req.EgressProfiles, r.Name)
		}
		if req.NetworkBlockAll && len(req.EgressProfiles) > 0 {
			return nil, ErrEgressProfilesConflict
		}
		// Learn mode needs empty lists, so a facade that sets lists on a
		// learn-mode sandbox is told so rather than silently switched to
		// enforce (D19). Rules ride along like profiles.
		req.NetworkEgressMode = old.NetworkEgressMode
		req.NetworkEgressRules = old.NetworkEgressRules
		if req.NetworkEgressMode == models.NetworkEgressModeLearn && (req.NetworkBlockAll || len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0) {
			return nil, ErrEgressLearnConflict
		}
	} else if err := s.refuseDisabledBuiltins(req.EgressProfiles); err != nil {
		return nil, err
	}
	create := models.CreateSandboxRequest{NetworkBlockAll: req.NetworkBlockAll, NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut,
		EgressProfiles: req.EgressProfiles, NetworkEgressMode: req.NetworkEgressMode, NetworkEgressRules: req.NetworkEgressRules}
	if _, err := compileCreateEgress(&create); err != nil {
		return nil, err
	}
	if s.isFirecrackerSandbox(old) {
		if err := s.checkFirecrackerEgress(&create); err != nil {
			return nil, err
		}
	}
	// Profiles resolve in the sandbox owner's namespace, whoever calls.
	resolved, err := s.resolveEgressProfiles(ctx, old.OwnerRef, create.NetworkAllowOut, create.EgressProfiles)
	if err != nil {
		return nil, err
	}
	// The replicated spec keeps built-ins pinned (CEO D11): a bare
	// builtin:<name> here moves the sandbox to this node's newest version.
	create.EgressProfiles = resolved.Refs
	effective := create
	effective.NetworkAllowOut = resolved.Effective
	pol, err := compileCreateEgressEffective(&effective)
	if err != nil {
		return nil, err
	}
	if op := s.egressOperator(); op != nil {
		if err := checkEgressOperatorLimits(op, &effective); err != nil {
			return nil, err
		}
	}
	next := *old
	next.NetworkBlockAll, next.NetworkAllowOut, next.NetworkDenyOut = effective.NetworkBlockAll, effective.NetworkAllowOut, effective.NetworkDenyOut
	next.NetworkEgressMode = effective.NetworkEgressMode
	next.NetworkEgressRules = effective.NetworkEgressRules
	containerRT := !s.isWasmSandbox(old) && !s.isIsolateSandbox(old)
	if len(next.NetworkEgressRules) > 0 && s.isWasmSandbox(old) {
		return nil, unsupportedWasmEgressRules()
	}
	if hasBinariesRule(next.NetworkEgressRules) && (s.isIsolateSandbox(old) || old.Runtime == models.RuntimeGvisor) {
		return nil, unsupportedBinaries(old.Runtime)
	}
	if containerRT && hasInspectRule(next.NetworkEgressRules) {
		st, err := s.store.GetEgressState(ctx, id)
		if err != nil {
			return nil, err
		}
		if !st.InspectCA {
			return nil, ErrEgressInspectRecreate
		}
		// A key the sandbox holds in clear is already exposed: injecting it
		// now would protect nothing (P3-2).
		for _, k := range injectKeys(next.NetworkEgressRules) {
			if !slices.Contains(st.Withheld, k) {
				return nil, fmt.Errorf("%w: the sandbox holds %s in clear", ErrEgressInjectRecreate, k)
			}
		}
	} else if keys := injectKeys(next.NetworkEgressRules); len(keys) > 0 {
		if err := s.checkInjectKeys(ctx, old, keys); err != nil {
			return nil, err
		}
	}
	if containerRT && pol.GatewayMode() {
		if err := s.requireEgressGateway(); err != nil {
			return nil, err
		}
	}
	st, err := s.store.GetEgressState(ctx, id)
	if err != nil {
		return nil, err
	}
	// The no-op is only for a policy known to be applied: any hold means the
	// stored policy may not be the enforced one, so an identical retry
	// applies it (review finding 2).
	if samePolicy(old, &next) && sameProfiles(prior, resolved) && st.HoldReason == "" {
		return s.effectivePolicy(ctx, old, resolved), nil
	}
	if err := s.commitPolicySpec(ctx, id, &create, st.Withheld); err != nil {
		return nil, err
	}
	if err := s.store.WriteNetworkPolicy(ctx, id, store.NetworkPolicyWrite{
		BlockAll: next.NetworkBlockAll, AllowOut: next.NetworkAllowOut, DenyOut: next.NetworkDenyOut,
		Inline: resolved.Inline, Profiles: resolved.Refs, OwnerRef: old.OwnerRef, Mode: next.NetworkEgressMode,
		Rules: next.NetworkEgressRules,
	}); err != nil {
		return nil, err
	}
	if err := s.applyStoredTransition(ctx, old, &next); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgressApplyFailedHeld, err)
	}
	if err := s.store.SetEgressProfilesApplied(ctx, id, resolved.Applied); err != nil {
		return nil, err
	}
	return s.effectivePolicy(ctx, &next, resolved), nil
}

// applyStoredTransition applies a policy change already in the store. A
// failure holds the sandbox (apply_failed) on every runtime, so it is shut
// rather than left on whatever the half-applied transition enforces, and
// the hold is what tells a retry, and the supervisor, that the stored
// policy still has to be applied. Success releases any hold the transition
// replaced.
func (s *Service) applyStoredTransition(ctx context.Context, old, next *models.Sandbox) error {
	if err := s.applyPolicyTransition(ctx, old, next); err != nil {
		s.holdUnapplied(ctx, next, egressHoldApplyFailed)
		return err
	}
	if s.isWasmSandbox(next) || s.isIsolateSandbox(next) {
		return s.releaseMediatedHold(ctx, next.ID)
	}
	return nil
}

// reapplyStoredPolicy applies a held sandbox's stored policy again (the
// supervisor's retry of an apply_failed hold).
func (s *Service) reapplyStoredPolicy(ctx context.Context, id string) error {
	unlock := s.egressPolicyLocks.lock(id)
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.applyStoredTransition(ctx, sb, sb)
}

// holdUnapplied shuts a sandbox whose stored policy isn't enforced and
// records why. Containers get the host-firewall hold DROP and the gateway's
// block; the WASM and isolate mediators get block-all, which their next
// successful policy apply replaces. Best effort after the record: each
// layer alone keeps the sandbox shut.
func (s *Service) holdUnapplied(ctx context.Context, sb *models.Sandbox, reason string) {
	switch {
	case s.isWasmSandbox(sb):
		if err := s.store.SetEgressHold(ctx, sb.ID, reason, time.Now().UTC()); err != nil {
			s.logger.Warn("egress: persist hold failed", "sandbox_id", sb.ID, "reason", reason, "error", err)
		}
		if sink, ok := s.wasm.(wasmNetworkPolicySink); ok && sink != nil {
			overIn, _ := quotaOver(sb)
			sink.SetNetworkBlocks(sb.ID, overIn || sb.NetworkBlockAll, true)
		}
		s.refreshHeldGauge(ctx)
	case s.isIsolateSandbox(sb):
		if err := s.store.SetEgressHold(ctx, sb.ID, reason, time.Now().UTC()); err != nil {
			s.logger.Warn("egress: persist hold failed", "sandbox_id", sb.ID, "reason", reason, "error", err)
		}
		if updater, ok := s.isolate.(isolateEgressPolicyUpdater); ok {
			if err := updater.UpdateEgressPolicy(sb.ID, true, nil, nil, false, nil, nil); err != nil {
				s.logger.Warn("egress: isolate hold not applied", "sandbox_id", sb.ID, "error", err)
			}
		}
		s.refreshHeldGauge(ctx)
	default:
		cr, err := s.containerRuntimeForSandbox(sb)
		if err != nil {
			if err := s.store.SetEgressHold(ctx, sb.ID, reason, time.Now().UTC()); err != nil {
				s.logger.Warn("egress: persist hold failed", "sandbox_id", sb.ID, "reason", reason, "error", err)
			}
			s.refreshHeldGauge(ctx)
			return
		}
		s.holdSandboxEgress(ctx, sb, cr, reason)
	}
}

// releaseMediatedHold clears a WASM or isolate sandbox's hold record once
// its mediator has the stored policy (the apply itself lifted block-all).
func (s *Service) releaseMediatedHold(ctx context.Context, id string) error {
	st, err := s.store.GetEgressState(ctx, id)
	if err != nil || st.HoldReason == "" {
		return err
	}
	if err := s.store.ClearEgressHold(ctx, id, time.Now().UTC()); err != nil {
		return err
	}
	s.refreshHeldGauge(ctx)
	return nil
}

// applyPolicyTransition makes a stored policy change live. The WASM and
// isolate drivers keep the policy for the next instantiation as well, so
// they hear about every change; a stopped container has nothing live and
// Start reads the stored row.
func (s *Service) applyPolicyTransition(ctx context.Context, old, next *models.Sandbox) error {
	switch {
	case s.isWasmSandbox(old):
		return s.applyWasmPolicy(next)
	case s.isIsolateSandbox(old):
		return s.applyIsolatePolicy(ctx, next)
	case next.Status == models.SandboxStatusStarted:
		return s.applyContainerPolicy(ctx, old, next)
	}
	return nil
}

func samePolicy(a, b *models.Sandbox) bool {
	return a.NetworkBlockAll == b.NetworkBlockAll && slices.Equal(a.NetworkAllowOut, b.NetworkAllowOut) && slices.Equal(a.NetworkDenyOut, b.NetworkDenyOut) &&
		a.NetworkEgressMode == b.NetworkEgressMode && slices.EqualFunc(a.NetworkEgressRules, b.NetworkEgressRules, sameEgressRule)
}

func sameEgressRule(a, b models.EgressRule) bool {
	return a.Host == b.Host && a.Inspect == b.Inspect && slices.Equal(a.Ports, b.Ports) && slices.Equal(a.Methods, b.Methods) && slices.Equal(a.Paths, b.Paths) &&
		slices.Equal(a.Binaries, b.Binaries) &&
		(a.Inject == nil) == (b.Inject == nil) && (a.Inject == nil || *a.Inject == *b.Inject)
}

// sameProfiles reports whether the stored references, their applied
// generations and the inline list already match a resolution.
func sameProfiles(prior store.SandboxEgressProfiles, r resolvedEgress) bool {
	if len(r.Refs) == 0 {
		return len(prior.Refs) == 0
	}
	return slices.Equal(prior.Refs, r.Applied) && slices.Equal(prior.Inline, r.Inline)
}

func (s *Service) effectivePolicy(ctx context.Context, sb *models.Sandbox, r resolvedEgress) *models.NetworkPolicy {
	inline := sb.NetworkAllowOut
	if len(r.Refs) > 0 {
		inline = r.Inline
	}
	effective, _ := countHostnames(sb.NetworkAllowOut)
	return &models.NetworkPolicy{
		NetworkBlockAll:        sb.NetworkBlockAll,
		NetworkAllowOut:        append([]string{}, inline...),
		NetworkDenyOut:         append([]string{}, sb.NetworkDenyOut...),
		EgressProfiles:         append([]string{}, r.Refs...),
		NetworkEgressMode:      egressModeName(sb.NetworkEgressMode),
		NetworkEgressRules:     sb.NetworkEgressRules,
		EffectiveHostnameCount: effective,
		EgressStatus:           s.EgressStatus(ctx, sb),
	}
}

// commitPolicySpec writes the new policy into the cluster's replicated spec
// before anything local changes. Unlike replicateSpecPatch it is strict: a
// failure is returned, so a failover can never bring back the old policy
// after this call answered 2xx. A sandbox with no replicated spec (single
// node, pre-cluster) has nothing to commit.
func (s *Service) commitPolicySpec(ctx context.Context, id string, create *models.CreateSandboxRequest, withheld []string) error {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	spec := c.SpecOf(id)
	if spec == nil {
		return nil
	}
	// Every egress field: a failover replays the spec, so one left behind
	// would bring back the old profiles, mode or rules.
	spec.NetworkBlockAll, spec.NetworkAllowOut, spec.NetworkDenyOut = create.NetworkBlockAll, create.NetworkAllowOut, create.NetworkDenyOut
	spec.EgressProfiles, spec.NetworkEgressMode, spec.NetworkEgressRules = create.EgressProfiles, create.NetworkEgressMode, create.NetworkEgressRules
	// Keys withheld at create stay withheld after their inject rule goes
	// (P3-2).
	for _, k := range withheld {
		if !slices.Contains(spec.EgressWithheldEnv, k) {
			spec.EgressWithheldEnv = append(spec.EgressWithheldEnv, k)
		}
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.UpsertSpec(commitCtx, id, spec, cluster.PlacementSecrets{}); err != nil {
		if errors.Is(err, cluster.ErrRecoveryPayloadTooLarge) {
			return fmt.Errorf("%w: sandbox spec too large to replicate: %v", egresspolicy.ErrInvalid, err)
		}
		return fmt.Errorf("%w: %v", ErrEgressSpecCommitFailed, err)
	}
	return nil
}

// quotaOver reports which byte caps a sandbox has crossed.
func quotaOver(sb *models.Sandbox) (in, out bool) {
	in = sb.NetworkBytesInLimit > 0 && sb.NetworkBytesIn >= sb.NetworkBytesInLimit
	out = sb.NetworkBytesOutLimit > 0 && sb.NetworkBytesOut >= sb.NetworkBytesOutLimit
	return in, out
}

func (s *Service) applyWasmPolicy(sb *models.Sandbox) error {
	setter, ok := s.wasm.(wasmEgressPolicySetter)
	if !ok {
		return errors.New("wasm runtime cannot update egress policy")
	}
	if err := setter.SetEgressPolicy(sb.ID, sb.NetworkAllowOut, sb.NetworkDenyOut, sb.NetworkEgressMode == models.NetworkEgressModeLearn); err != nil {
		return err
	}
	overIn, overOut := quotaOver(sb)
	s.syncWasmNetworkPolicy(sb, overIn, overOut)
	return nil
}

func (s *Service) applyIsolatePolicy(ctx context.Context, sb *models.Sandbox) error {
	updater, ok := s.isolate.(isolateEgressPolicyUpdater)
	if !ok {
		return errors.New("isolate runtime cannot update egress policy")
	}
	return updater.UpdateEgressPolicy(sb.ID, sb.NetworkBlockAll, sb.NetworkAllowOut, sb.NetworkDenyOut, sb.NetworkEgressMode == models.NetworkEgressModeLearn,
		egressRuleSpecs(sb.NetworkEgressRules), s.egressSecrets(ctx, sb))
}

// applyContainerPolicy moves a running container sandbox from old's policy to
// nu's (§5.8 transitions). It always tightens first: a block-all DROP covers
// the whole swap, the old mode is torn down under it, the new one is put in
// place, and only then is the DROP lifted. A gateway attach that fails holds
// the sandbox (D16); the DROP stays either way.
func (s *Service) applyContainerPolicy(ctx context.Context, old, nu *models.Sandbox) error {
	ip := nu.ContainerIP
	if ip == "" {
		return nil
	}
	cr, err := s.containerRuntimeForSandbox(nu)
	if err != nil {
		return err
	}
	oldGW, newGW := isGatewayMode(old), isGatewayMode(nu)
	if err := cr.ApplyNetworkBlockAll(ip); err != nil {
		return fmt.Errorf("block egress for the policy swap: %w", err)
	}
	// Leave the old mode. Gateway to gateway stays attached: Attach with the
	// new spec swaps the rules and flushes what the old policy learned.
	switch {
	case oldGW && !newGW:
		s.detachSandboxEgress(ctx, old, ip)
	case !oldGW && (len(old.NetworkAllowOut) > 0 || len(old.NetworkDenyOut) > 0):
		if err := cr.ClearEgressPolicy(ip, old.NetworkAllowOut, old.NetworkDenyOut); err != nil {
			return fmt.Errorf("clear the old egress rules: %w", err)
		}
	}
	// A hold is released only once the new policy is in place (the caller
	// holds on any failure): a gateway attach releases it itself.
	switch {
	case nu.NetworkBlockAll:
		return s.releaseEgressHold(ctx, nu, cr)
	case newGW:
		return s.attachSandboxEgress(ctx, nu, cr)
	case len(nu.NetworkAllowOut) > 0 || len(nu.NetworkDenyOut) > 0:
		if err := cr.ApplyEgressPolicy(ip, nu.NetworkAllowOut, nu.NetworkDenyOut); err != nil {
			return fmt.Errorf("apply the new egress rules: %w", err)
		}
	}
	if err := s.releaseEgressHold(ctx, nu, cr); err != nil {
		return err
	}
	if _, overOut := quotaOver(nu); overOut {
		return nil // the quota keeps the same DROP
	}
	if err := cr.ClearNetworkBlockEgress(ip); err != nil {
		return fmt.Errorf("lift the swap block: %w", err)
	}
	return nil
}

// egressModeName spells out the stored mode for responses.
func egressModeName(mode string) string {
	if mode == models.NetworkEgressModeLearn {
		return models.NetworkEgressModeLearn
	}
	return models.NetworkEgressModeEnforce
}
