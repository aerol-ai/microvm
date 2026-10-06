package service

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// egressProfileReapplyInterval is how often this node checks its sandboxes'
// profiles for changes. A profile PUT on this node wakes the pass at once;
// in a cluster, other nodes see the change within one interval of their
// view of the profiles catching up (D21: at most 30 s fleet-wide).
const egressProfileReapplyInterval = 10 * time.Second

// profileKick is buffered one: a profile PUT wakes the re-apply pass
// without waiting for it, and wakes that arrive during a pass coalesce.
func (s *Service) profileKick() chan struct{} {
	s.egressProfileKickOnce.Do(func() { s.egressProfileKick = make(chan struct{}, 1) })
	return s.egressProfileKick
}

func (s *Service) kickEgressProfileReapply() {
	select {
	case s.profileKick() <- struct{}{}:
	default:
	}
}

// SuperviseEgressProfiles re-applies changed egress profiles to this node's
// sandboxes until ctx ends: each owner re-applies its own referencing
// sandboxes, with no cross-node calls beyond reading the profiles (D21).
func (s *Service) SuperviseEgressProfiles(ctx context.Context) {
	t := time.NewTicker(egressProfileReapplyInterval)
	defer t.Stop()
	for {
		s.reapplyEgressProfiles(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.profileKick():
		}
	}
}

type profileKey struct{ owner, name string }

// reapplyEgressProfiles finds the sandboxes whose live generation of some
// profile is behind the profile's, and re-applies each, at most
// EgressProfileApplyQPS per second.
func (s *Service) reapplyEgressProfiles(ctx context.Context) {
	refs, err := s.store.ProfileReferences(ctx)
	if err != nil {
		s.logger.Warn("egress: list profile references", "error", err)
		return
	}
	current := map[profileKey]int64{}
	stale := map[string]bool{}
	for _, r := range refs {
		k := profileKey{r.OwnerRef, r.Profile}
		gen, ok := current[k]
		if !ok {
			p, err := s.lookupEgressProfile(ctx, r.OwnerRef, r.Profile)
			switch {
			case errors.Is(err, ErrEgressProfileNotFound), errors.Is(err, egresspolicy.ErrBuiltinUnknown), errors.Is(err, ErrOrgProfileInvalid),
				errors.Is(err, ErrEgressProfileUnavailable) && strings.HasPrefix(r.Profile, egresspolicy.BuiltinProfilePrefix):
				// Gone, out of the operator file, or a built-in version this
				// node lacks: re-applying holds the sandbox.
				gen = -1
			case err != nil:
				s.logger.Warn("egress: read profile for re-apply", "profile", r.Profile, "error", err)
				continue
			default:
				gen = p.Generation
			}
			current[k] = gen
		}
		if r.AppliedGeneration != gen {
			stale[r.SandboxID] = true
		}
	}
	// A sandbox held for its profiles is retried every pass: the profile may
	// be back at the same generation it had when the sandbox last applied it.
	if holds, err := s.store.ListEgressHolds(ctx); err == nil {
		for id, reason := range holds {
			if isProfileHold(reason) {
				stale[id] = true
			}
		}
	}
	ids := make([]string, 0, len(stale))
	for id := range stale {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	qps := s.cfg.EgressProfileApplyQPS
	if qps <= 0 {
		qps = 50
	}
	pace := time.NewTicker(time.Second / time.Duration(qps))
	defer pace.Stop()
	for i, id := range ids {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-pace.C:
			}
		}
		if err := s.reapplySandboxProfiles(ctx, id); err != nil {
			egressProfileApplyFailedTotal.Add(1)
			s.logger.Warn("egress: profile change not applied; sandbox held until it is", "sandbox_id", id, "error", err)
		}
	}
}

// reapplySandboxProfiles recomputes one sandbox's effective allow list from
// its current profiles and applies it like a policy PUT that keeps the same
// inline list and references. A failure leaves the sandbox shut (the swap
// DROP, or a hold) and its applied generations unchanged, so the next pass
// retries.
func (s *Service) reapplySandboxProfiles(ctx context.Context, id string) error {
	unlock := s.egressPolicyLocks.lock(id)
	defer unlock()
	old, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	prior, err := s.store.GetSandboxEgressProfiles(ctx, id)
	if err != nil || len(prior.Refs) == 0 {
		return err
	}
	names := make([]string, len(prior.Refs))
	for i, r := range prior.Refs {
		names[i] = r.Name
	}
	resolved, err := s.resolveEgressProfiles(ctx, old.OwnerRef, prior.Inline, names)
	if err != nil {
		s.holdForProfiles(ctx, old, profileHoldReason(err, names))
		return err
	}
	next := *old
	next.NetworkAllowOut = resolved.Effective
	// Profiles and block-all are exclusive, so a block-all row here is a
	// failover replay that ran block-all until its profiles resolved.
	next.NetworkBlockAll = false
	st, err := s.store.GetEgressState(ctx, id)
	if err != nil {
		return err
	}
	// A profile hold is lifted only by a re-apply, even one whose list
	// didn't change while the profile was unreadable.
	held := isProfileHold(st.HoldReason)
	if held || !slices.Equal(old.NetworkAllowOut, next.NetworkAllowOut) {
		if err := s.store.WriteNetworkPolicy(ctx, id, store.NetworkPolicyWrite{
			BlockAll: next.NetworkBlockAll, AllowOut: next.NetworkAllowOut, DenyOut: next.NetworkDenyOut,
			Inline: resolved.Inline, Profiles: resolved.Refs, OwnerRef: old.OwnerRef, Mode: old.NetworkEgressMode,
		}); err != nil {
			return err
		}
		if err := s.applyPolicyTransition(ctx, old, &next); err != nil {
			return err
		}
		// A container's attach lifts its hold; the WASM and isolate
		// mediators have only the record to clear.
		if held && (s.isWasmSandbox(old) || s.isIsolateSandbox(old)) {
			if err := s.store.ClearEgressHold(ctx, id, time.Now().UTC()); err != nil {
				return err
			}
			s.refreshHeldGauge(ctx)
		}
	}
	return s.store.SetEgressProfilesApplied(ctx, id, resolved.Applied)
}

// holdForProfiles shuts a running container sandbox whose profiles can't be
// resolved, so it never keeps serving entries its owner may have removed.
// The WASM and isolate mediators keep their last policy until a re-apply
// succeeds.
func (s *Service) holdForProfiles(ctx context.Context, sb *models.Sandbox, reason string) {
	if sb.Status != models.SandboxStatusStarted || sb.ContainerIP == "" || s.isWasmSandbox(sb) || s.isIsolateSandbox(sb) {
		return
	}
	cr, err := s.containerRuntimeForSandbox(sb)
	if err != nil {
		return
	}
	s.holdSandboxEgress(ctx, sb, cr, reason)
}

// profileHoldReason names why a sandbox's profiles stopped resolving. An org
// profile is checked by no one before a reload lands (the file has no API
// and the cluster's cap check can't see it), so a reference that left the
// file, or a union over the cap on a sandbox that uses org profiles, is
// org_profile_invalid (§5.10 PC-3).
func profileHoldReason(err error, refs []string) string {
	if errors.Is(err, ErrOrgProfileInvalid) {
		return egressHoldOrgProfileInvalid
	}
	usesOrg := slices.ContainsFunc(refs, func(r string) bool { return strings.HasPrefix(r, egresspolicy.OrgProfilePrefix) })
	if usesOrg && errors.Is(err, egresspolicy.ErrInvalid) {
		return egressHoldOrgProfileInvalid
	}
	return egressHoldProfileUnavailable
}
