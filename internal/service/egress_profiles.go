package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Named egress profiles (plans/egress-domain-filtering.md D21, P2-6): owner-
// scoped allowlists sandboxes reference by name. A sandbox's effective allow
// list is its inline entries plus every referenced profile's. The sandboxes
// row stores that effective list, which every enforcement path reads; the
// inline list and the references are kept beside it (store.WriteNetworkPolicy)
// for GET, policy replays and the re-apply pass.

// ErrEgressProfileNotFound is a profile GET for a name the owner doesn't
// have (404).
var ErrEgressProfileNotFound = store.ErrEgressProfileNotFound

// ErrEgressProfileInUse is a DELETE of a profile live sandboxes reference
// (409).
var ErrEgressProfileInUse = store.ErrEgressProfileInUse

// ErrEgressProfileCapExceeded is a profile PUT that would push a referencing
// sandbox past the 1024-hostname union cap (409, naming the sandboxes), so a
// re-apply never fails on caps.
var ErrEgressProfileCapExceeded = errors.New("egress profile update would exceed a referencing sandbox's hostname cap")

// ErrEgressProfileUnavailable means the profiles a policy references could
// not be read right now (503, retry).
var ErrEgressProfileUnavailable = errors.New("egress profiles are unavailable")

const (
	// maxProfileDescription bounds a profile's free-text description.
	maxProfileDescription = 1024
	// defaultProfileListLimit and maxProfileListLimit page GET
	// /v1/egress-profiles like the other list APIs.
	defaultProfileListLimit = 100
	maxProfileListLimit     = 500
)

// egressProfileBackend stores profiles and answers which sandboxes reference
// one. The single-node backend is the store; a cluster keeps them in the
// Raft FSM.
type egressProfileBackend interface {
	PutEgressProfile(ctx context.Context, owner, name string, allowOut []string, description string, now time.Time) (models.EgressProfile, bool, error)
	GetEgressProfile(ctx context.Context, owner, name string) (models.EgressProfile, error)
	ListEgressProfiles(ctx context.Context, owner, after string, limit int) ([]models.EgressProfile, error)
	DeleteEgressProfile(ctx context.Context, owner, name string) error
}

func (s *Service) egressProfileBackend() egressProfileBackend {
	if s.egressProfiles != nil {
		return s.egressProfiles
	}
	if s.ClusterEnabled() {
		// A node's own store would give each node its own profiles.
		return noClusterProfiles{}
	}
	return s.store
}

// noClusterProfiles answers every profile call on a cluster that has no
// replicated profile store wired.
type noClusterProfiles struct{}

var errNoClusterProfiles = fmt.Errorf("%w: this cluster has no replicated profile store", ErrEgressProfileUnavailable)

func (noClusterProfiles) PutEgressProfile(context.Context, string, string, []string, string, time.Time) (models.EgressProfile, bool, error) {
	return models.EgressProfile{}, false, errNoClusterProfiles
}

func (noClusterProfiles) GetEgressProfile(context.Context, string, string) (models.EgressProfile, error) {
	return models.EgressProfile{}, errNoClusterProfiles
}

func (noClusterProfiles) ListEgressProfiles(context.Context, string, string, int) ([]models.EgressProfile, error) {
	return nil, errNoClusterProfiles
}

func (noClusterProfiles) DeleteEgressProfile(context.Context, string, string) error {
	return errNoClusterProfiles
}

// PutEgressProfile creates or replaces one of the caller's profiles. The
// same body twice is a no-op. A change is checked against the operator's
// ceiling and against the hostname cap of every sandbox that references the
// profile, then stored; referencing sandboxes pick it up from the re-apply
// pass, which this call wakes.
func (s *Service) PutEgressProfile(ctx context.Context, name string, req models.EgressProfileRequest) (*models.EgressProfile, error) {
	if err := egresspolicy.ValidateProfileName(name); err != nil {
		return nil, err
	}
	if len(req.Description) > maxProfileDescription {
		return nil, fmt.Errorf("%w: description is %d bytes; the limit is %d", egresspolicy.ErrInvalid, len(req.Description), maxProfileDescription)
	}
	entries, err := egresspolicy.ParseAllowList("allow_out", req.AllowOut, egresspolicy.MaxProfileHostnames)
	if err != nil {
		return nil, err
	}
	allow := make([]string, len(entries))
	for i, e := range entries {
		allow[i] = e.String()
	}
	if c := s.egressOperator().Ceiling(); c != nil {
		pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: allow, MaxHostnames: egresspolicy.MaxProfileHostnames})
		if err != nil {
			return nil, err
		}
		if err := c.Fits(pol); err != nil {
			return nil, fmt.Errorf("%w: egress profile is outside this deployment's ceiling: %v", egresspolicy.ErrInvalid, err)
		}
	}
	owner, _ := ownerScope(ctx)
	if err := s.checkProfileUnionCaps(ctx, owner, name, egresspolicy.CountHostnames(entries)); err != nil {
		return nil, err
	}
	p, changed, err := s.egressProfileBackend().PutEgressProfile(ctx, owner, name, allow, req.Description, time.Now())
	if err != nil {
		return nil, err
	}
	if changed {
		s.kickEgressProfileReapply()
	}
	return &p, nil
}

// checkProfileUnionCaps refuses a profile change that would push a sandbox
// referencing it past MaxUnionHostnames. The cap counts every list's
// hostnames, duplicates across lists included, so the check needs only
// counts and agrees exactly with the one creates and policy PUTs make.
func (s *Service) checkProfileUnionCaps(ctx context.Context, owner, name string, newCount int) error {
	refs, err := s.store.SandboxesReferencingProfile(ctx, owner, name)
	if err != nil || len(refs) == 0 {
		return err
	}
	counts := map[string]int{name: newCount}
	var over []string
	for _, ref := range refs {
		state, err := s.store.GetSandboxEgressProfiles(ctx, ref.SandboxID)
		if err != nil {
			return err
		}
		total, err := countHostnames(state.Inline)
		if err != nil {
			return err
		}
		for _, r := range state.Refs {
			n, ok := counts[r.Name]
			if !ok {
				p, err := s.egressProfileBackend().GetEgressProfile(ctx, owner, r.Name)
				if err != nil && !errors.Is(err, ErrEgressProfileNotFound) {
					return err
				}
				if n, err = countHostnames(p.AllowOut); err != nil {
					return err
				}
				counts[r.Name] = n
			}
			total += n
		}
		if total > egresspolicy.MaxUnionHostnames {
			over = append(over, ref.SandboxID)
		}
	}
	if len(over) > 0 {
		return fmt.Errorf("%w: with this change %s would hold more than %d hostname entries across their allow list and profiles",
			ErrEgressProfileCapExceeded, strings.Join(over, ", "), egresspolicy.MaxUnionHostnames)
	}
	return nil
}

func countHostnames(entries []string) (int, error) {
	parsed, err := egresspolicy.ParseAllowList("allow_out", entries, egresspolicy.MaxUnionHostnames)
	if err != nil {
		return 0, err
	}
	return egresspolicy.CountHostnames(parsed), nil
}

// GetEgressProfile returns one of the caller's profiles.
func (s *Service) GetEgressProfile(ctx context.Context, name string) (*models.EgressProfile, error) {
	owner, _ := ownerScope(ctx)
	p, err := s.egressProfileBackend().GetEgressProfile(ctx, owner, name)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListEgressProfiles returns a page of the caller's profiles by name.
func (s *Service) ListEgressProfiles(ctx context.Context, cursor string, limit int) (*models.EgressProfileList, error) {
	switch {
	case limit <= 0:
		limit = defaultProfileListLimit
	case limit > maxProfileListLimit:
		limit = maxProfileListLimit
	}
	owner, _ := ownerScope(ctx)
	page, err := s.egressProfileBackend().ListEgressProfiles(ctx, owner, cursor, limit+1)
	if err != nil {
		return nil, err
	}
	out := &models.EgressProfileList{Profiles: page}
	if len(page) > limit {
		out.Profiles = page[:limit]
		out.NextCursor = page[limit-1].Name
	}
	return out, nil
}

// DeleteEgressProfile removes one of the caller's profiles; one a live
// sandbox references is refused with 409. Deleting a profile that is gone
// succeeds.
func (s *Service) DeleteEgressProfile(ctx context.Context, name string) error {
	if err := egresspolicy.ValidateProfileName(name); err != nil {
		return err
	}
	owner, _ := ownerScope(ctx)
	return s.egressProfileBackend().DeleteEgressProfile(ctx, owner, name)
}

// resolvedEgress is a policy's profile references resolved against the
// current profiles.
type resolvedEgress struct {
	Inline    []string
	Refs      []string
	Applied   []models.EgressProfileRef
	Effective []string
	Hostnames int
}

// resolveEgressProfiles expands a policy's references for owner. With no
// references the effective list is the inline one. The inline list must
// already be valid. An unknown profile is a 400 naming it; one that can't be
// read right now is a 503.
func (s *Service) resolveEgressProfiles(ctx context.Context, owner string, inline, refs []string) (resolvedEgress, error) {
	r := resolvedEgress{Inline: inline, Refs: refs, Effective: inline}
	n, err := countHostnames(inline)
	if err != nil {
		return r, err
	}
	r.Hostnames = n
	if len(refs) == 0 {
		return r, nil
	}
	if err := egresspolicy.ValidateProfileRefs(refs); err != nil {
		return r, err
	}
	lists := make([][]string, 0, len(refs))
	for _, ref := range refs {
		if strings.HasPrefix(ref, egresspolicy.OrgProfilePrefix) || strings.HasPrefix(ref, egresspolicy.BuiltinProfilePrefix) {
			return r, fmt.Errorf("%w: egress_profiles entry %q: org: and builtin: profiles are not available yet", egresspolicy.ErrInvalid, ref)
		}
		p, err := s.egressProfileBackend().GetEgressProfile(ctx, owner, ref)
		if errors.Is(err, ErrEgressProfileNotFound) {
			return r, fmt.Errorf("%w: egress_profiles entry %q: no such profile", egresspolicy.ErrInvalid, ref)
		}
		if err != nil {
			return r, fmt.Errorf("%w: %v", ErrEgressProfileUnavailable, err)
		}
		n, err := countHostnames(p.AllowOut)
		if err != nil {
			return r, err
		}
		r.Hostnames += n
		lists = append(lists, p.AllowOut)
		r.Applied = append(r.Applied, models.EgressProfileRef{Name: ref, Generation: p.Generation})
	}
	if r.Hostnames > egresspolicy.MaxUnionHostnames {
		return r, fmt.Errorf("%w: network_allow_out and egress_profiles have %d hostname entries together; the limit is %d",
			egresspolicy.ErrInvalid, r.Hostnames, egresspolicy.MaxUnionHostnames)
	}
	if r.Effective, err = egresspolicy.Union(inline, lists...); err != nil {
		return r, err
	}
	return r, nil
}

// showEgressProfiles puts the inline allow list and the profile references
// back on sandboxes read for an API response, in place of the effective list
// the row stores. A sandbox that references no profile is left as is.
func (s *Service) showEgressProfiles(ctx context.Context, sandboxes ...*models.Sandbox) {
	ids := make([]string, 0, len(sandboxes))
	for _, sb := range sandboxes {
		if sb != nil {
			ids = append(ids, sb.ID)
		}
	}
	states, err := s.store.GetSandboxesEgressProfiles(ctx, ids)
	if err != nil {
		s.logger.Warn("egress: read profile references for a response", "error", err)
		return
	}
	for _, sb := range sandboxes {
		state, ok := states[sbID(sb)]
		if !ok {
			continue
		}
		sb.NetworkAllowOut = state.Inline
		sb.EgressProfiles = make([]string, len(state.Refs))
		for i, ref := range state.Refs {
			sb.EgressProfiles[i] = ref.Name
		}
		sb.EgressProfilesApplied = state.Refs
	}
}

func sbID(sb *models.Sandbox) string {
	if sb == nil {
		return ""
	}
	return sb.ID
}

// recordCreateEgressProfiles stores a new sandbox's profile references and
// inline list next to the row the create wrote. Without them the row's
// effective list would have nothing to explain it and profile updates
// would never reach the sandbox, so a failure undoes the create.
func (s *Service) recordCreateEgressProfiles(ctx context.Context, sb *models.Sandbox, r resolvedEgress) error {
	err := s.store.SetSandboxEgressProfiles(ctx, sb.ID, store.NetworkPolicyWrite{Inline: r.Inline, Profiles: r.Refs, OwnerRef: sb.OwnerRef})
	if err == nil {
		err = s.store.SetEgressProfilesApplied(ctx, sb.ID, r.Applied)
	}
	if err != nil {
		if derr := s.DestroySandbox(context.WithoutCancel(ctx), sb.ID); derr != nil {
			s.logger.Warn("egress: undo create after a profile write failed", "sandbox_id", sb.ID, "error", derr)
		}
		return fmt.Errorf("record egress profiles: %w", err)
	}
	sb.NetworkAllowOut = r.Inline
	sb.EgressProfiles = r.Refs
	sb.EgressProfilesApplied = r.Applied
	return nil
}
