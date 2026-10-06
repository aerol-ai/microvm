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
	SetEgressPolicy(sandboxID string, allow, deny []string) error
}

// isolateEgressPolicyUpdater replaces an isolate sandbox's egress proxy
// policy live.
type isolateEgressPolicyUpdater interface {
	UpdateEgressPolicy(sandboxID string, blockAll bool, allow, deny []string) error
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
	create := models.CreateSandboxRequest{NetworkBlockAll: req.NetworkBlockAll, NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut}
	pol, err := compileCreateEgress(&create)
	if err != nil {
		return nil, err
	}
	if s.egressOperatorWatcher != nil {
		if err := s.egressOperatorWatcher.BootError(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEgressOperatorConfigInvalid, err)
		}
	}
	if op := s.egressOperator(); op != nil {
		if err := checkEgressOperatorLimits(op, &create); err != nil {
			return nil, err
		}
	}
	unlock := s.egressPolicyLocks.lock(id)
	defer unlock()

	old, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.isFirecrackerSandbox(old) {
		return nil, unsupportedFirecrackerOption("live egress policy updates")
	}
	switch old.Status {
	case models.SandboxStatusCreating, models.SandboxStatusAwaitingRuntime, models.SandboxStatusPassivateFailed:
		return nil, fmt.Errorf("%w (status %s)", ErrEgressPolicyBusy, old.Status)
	}
	next := *old
	next.NetworkBlockAll, next.NetworkAllowOut, next.NetworkDenyOut = create.NetworkBlockAll, create.NetworkAllowOut, create.NetworkDenyOut
	containerRT := !s.isWasmSandbox(old) && !s.isIsolateSandbox(old)
	if containerRT && pol.GatewayMode() {
		if !s.egressEnabled() {
			return nil, ErrEgressGatewayRequired
		}
		if s.egressSelfTestFailed() {
			return nil, ErrEgressSelfTestFailed
		}
		if s.egressSelfTestPending() {
			return nil, fmt.Errorf("%w: the gateway self-test has not finished yet", ErrEgressGatewayUnavailable)
		}
	}
	if samePolicy(old, &next) && s.EgressStatus(ctx, old) != EgressStatusHeld && s.EgressStatus(ctx, old) != EgressStatusUnavailable {
		return s.effectivePolicy(ctx, old), nil
	}

	if err := s.commitPolicySpec(ctx, id, &create); err != nil {
		return nil, err
	}
	if err := s.store.SetNetworkPolicy(ctx, id, next.NetworkBlockAll, next.NetworkAllowOut, next.NetworkDenyOut); err != nil {
		return nil, err
	}
	// The WASM and isolate drivers keep the policy for the next
	// instantiation as well, so they hear about every update; a stopped
	// container has nothing live and Start reads the stored row.
	switch {
	case s.isWasmSandbox(old):
		err = s.applyWasmPolicy(&next)
	case s.isIsolateSandbox(old):
		err = s.applyIsolatePolicy(&next)
	case next.Status == models.SandboxStatusStarted:
		err = s.applyContainerPolicy(ctx, old, &next)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgressApplyFailedHeld, err)
	}
	return s.effectivePolicy(ctx, &next), nil
}

func samePolicy(a, b *models.Sandbox) bool {
	return a.NetworkBlockAll == b.NetworkBlockAll && slices.Equal(a.NetworkAllowOut, b.NetworkAllowOut) && slices.Equal(a.NetworkDenyOut, b.NetworkDenyOut)
}

func (s *Service) effectivePolicy(ctx context.Context, sb *models.Sandbox) *models.NetworkPolicy {
	return &models.NetworkPolicy{
		NetworkBlockAll: sb.NetworkBlockAll,
		NetworkAllowOut: append([]string{}, sb.NetworkAllowOut...),
		NetworkDenyOut:  append([]string{}, sb.NetworkDenyOut...),
		EgressStatus:    s.EgressStatus(ctx, sb),
	}
}

// commitPolicySpec writes the new policy into the cluster's replicated spec
// before anything local changes. Unlike replicateSpecPatch it is strict: a
// failure is returned, so a failover can never bring back the old policy
// after this call answered 2xx. A sandbox with no replicated spec (single
// node, pre-cluster) has nothing to commit.
func (s *Service) commitPolicySpec(ctx context.Context, id string, create *models.CreateSandboxRequest) error {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	spec := c.SpecOf(id)
	if spec == nil {
		return nil
	}
	spec.NetworkBlockAll, spec.NetworkAllowOut, spec.NetworkDenyOut = create.NetworkBlockAll, create.NetworkAllowOut, create.NetworkDenyOut
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
	if err := setter.SetEgressPolicy(sb.ID, sb.NetworkAllowOut, sb.NetworkDenyOut); err != nil {
		return err
	}
	overIn, overOut := quotaOver(sb)
	s.syncWasmNetworkPolicy(sb, overIn, overOut)
	return nil
}

func (s *Service) applyIsolatePolicy(sb *models.Sandbox) error {
	updater, ok := s.isolate.(isolateEgressPolicyUpdater)
	if !ok {
		return errors.New("isolate runtime cannot update egress policy")
	}
	return updater.UpdateEgressPolicy(sb.ID, sb.NetworkBlockAll, sb.NetworkAllowOut, sb.NetworkDenyOut)
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
	if !newGW {
		// A hold only guards gateway mode (or a stored policy that would not
		// compile, which this call has just replaced).
		if err := s.releaseEgressHold(ctx, nu, cr); err != nil {
			return err
		}
	}
	switch {
	case nu.NetworkBlockAll:
		return nil
	case newGW:
		if err := s.attachSandboxEgress(ctx, nu, cr); err != nil {
			s.holdSandboxEgress(ctx, nu, cr, egressHoldAttachFailed)
			return err
		}
		return nil
	case len(nu.NetworkAllowOut) > 0 || len(nu.NetworkDenyOut) > 0:
		if err := cr.ApplyEgressPolicy(ip, nu.NetworkAllowOut, nu.NetworkDenyOut); err != nil {
			return fmt.Errorf("apply the new egress rules: %w", err)
		}
	}
	if _, overOut := quotaOver(nu); overOut {
		return nil // the quota keeps the same DROP
	}
	if err := cr.ClearNetworkBlockEgress(ip); err != nil {
		return fmt.Errorf("lift the swap block: %w", err)
	}
	return nil
}
