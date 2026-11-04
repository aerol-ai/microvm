package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
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

// ErrOrgProfileInvalid is an org: reference the operator file doesn't define
// (400 at create and policy PUT; a hold with reason org_profile_invalid on a
// running sandbox, §5.10 PC-3).
var ErrOrgProfileInvalid = errors.New("org egress profile is not defined")

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
		if c, ok := s.Cluster().(egressProfileCluster); ok {
			return clusterProfiles{c}
		}
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
	// A cluster decides the cap at apply time, against every node's
	// sandboxes; a single node checks its own.
	if !s.ClusterEnabled() {
		if err := s.checkProfileUnionCaps(ctx, owner, name, egresspolicy.CountHostnames(entries)); err != nil {
			return nil, err
		}
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
				p, err := s.lookupEgressProfile(ctx, owner, r.Name)
				if err != nil && !errors.Is(err, ErrEgressProfileNotFound) && !errors.Is(err, egresspolicy.ErrBuiltinUnknown) &&
					!errors.Is(err, ErrEgressProfileUnavailable) {
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

// GetEgressProfile returns one of the caller's profiles, a built-in one
// (builtin:<name> is its newest version, builtin:<name>@<version> that one)
// or one of the operator's org profiles, which every tenant can read.
func (s *Service) GetEgressProfile(ctx context.Context, name string) (*models.EgressProfile, error) {
	if strings.HasPrefix(name, egresspolicy.OrgProfilePrefix) {
		entries, desc, ok := s.egressOperator().OrgProfileEntries(name)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrEgressProfileNotFound, name)
		}
		return &models.EgressProfile{Name: name, AllowOut: entries, Description: desc, Generation: orgProfileGeneration(entries)}, nil
	}
	if strings.HasPrefix(name, egresspolicy.BuiltinProfilePrefix) {
		b, err := egresspolicy.ResolveBuiltin(name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEgressProfileNotFound, err)
		}
		return &models.EgressProfile{Name: b.Ref, AllowOut: b.AllowOut, Generation: b.Version,
			Description: "AerolVM built-in profile " + b.Name + ", version " + strconv.FormatInt(b.Version, 10)}, nil
	}
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
	r.Refs = make([]string, 0, len(refs))
	for _, ref := range refs {
		p, err := s.lookupEgressProfile(ctx, owner, ref)
		switch {
		case errors.Is(err, ErrEgressProfileNotFound):
			return r, fmt.Errorf("%w: egress_profiles entry %q: no such profile", egresspolicy.ErrInvalid, ref)
		case errors.Is(err, ErrOrgProfileInvalid):
			return r, fmt.Errorf("%w: egress_profiles entry %q: %w", egresspolicy.ErrInvalid, ref, err)
		case errors.Is(err, egresspolicy.ErrBuiltinUnknown):
			return r, fmt.Errorf("%w: egress_profiles entry %q: %v", egresspolicy.ErrInvalid, ref, err)
		case errors.Is(err, ErrEgressProfileUnavailable):
			return r, err
		case err != nil:
			return r, fmt.Errorf("%w: %v", ErrEgressProfileUnavailable, err)
		}
		n, err := countHostnames(p.AllowOut)
		if err != nil {
			return r, err
		}
		r.Hostnames += n
		lists = append(lists, p.AllowOut)
		r.Refs = append(r.Refs, p.Ref)
		r.Applied = append(r.Applied, models.EgressProfileRef{Name: p.Ref, Generation: p.Generation})
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

// egressProfileBody is a referenced profile's entries at its current
// generation. Ref is the reference as the spec stores it: a bare built-in
// comes back pinned.
type egressProfileBody struct {
	Ref        string
	AllowOut   []string
	Generation int64
}

// lookupEgressProfile reads the profile a reference names. A built-in comes
// from the binary's catalogue, its version standing in for a generation: a
// pinned version never changes, so the re-apply pass never sees one move. A
// version this node's catalogue doesn't have yet is unavailable, not unknown:
// a newer node pinned it, and the sandbox fails closed until it is owned by a
// node that has it (CEO D11).
func (s *Service) lookupEgressProfile(ctx context.Context, owner, ref string) (egressProfileBody, error) {
	switch {
	case strings.HasPrefix(ref, egresspolicy.BuiltinProfilePrefix):
		b, err := egresspolicy.ResolveBuiltin(ref)
		if errors.Is(err, egresspolicy.ErrBuiltinVersionMissing) {
			return egressProfileBody{}, fmt.Errorf("%w: %v", ErrEgressProfileUnavailable, err)
		}
		if err != nil {
			return egressProfileBody{}, err
		}
		return egressProfileBody{Ref: b.Ref, AllowOut: b.AllowOut, Generation: b.Version}, nil
	case strings.HasPrefix(ref, egresspolicy.OrgProfilePrefix):
		entries, _, ok := s.egressOperator().OrgProfileEntries(ref)
		if !ok {
			return egressProfileBody{}, fmt.Errorf("%w: %s is not in this deployment's operator file", ErrOrgProfileInvalid, ref)
		}
		return egressProfileBody{Ref: ref, AllowOut: entries, Generation: orgProfileGeneration(entries)}, nil
	}
	p, err := s.egressProfileBackend().GetEgressProfile(ctx, owner, ref)
	if err != nil {
		return egressProfileBody{}, err
	}
	return egressProfileBody{Ref: ref, AllowOut: p.AllowOut, Generation: p.Generation}, nil
}

// orgProfileGeneration is an org profile's generation: a hash of its
// entries, since the operator file has no counter (§5.10 PC-3). Any edit
// changes it, so the re-apply pass sees the edit; positive, so it never
// collides with the pass's -1 for "gone".
func orgProfileGeneration(entries []string) int64 {
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return max(int64(binary.BigEndian.Uint64(sum[:8])>>1), 1)
}

// NormalizeCreateEgressProfiles pins each bare builtin:<name> in a create to
// this node's newest version, so the spec the cluster replicates carries the
// pinned form and a failover rebuilds the same list (CEO D11). The owner node
// calls it after any forward, so the pin is its own catalogue's. Other
// references are left for the create to resolve.
func NormalizeCreateEgressProfiles(req *models.CreateSandboxRequest) {
	var pinned []string
	for i, ref := range req.EgressProfiles {
		if !strings.HasPrefix(ref, egresspolicy.BuiltinProfilePrefix) || strings.Contains(ref, "@") {
			continue
		}
		if b, err := egresspolicy.ResolveBuiltin(ref); err == nil {
			// Copy before the first write: the caller's request shares the
			// backing array.
			if pinned == nil {
				pinned = append([]string(nil), req.EgressProfiles...)
			}
			pinned[i] = b.Ref
		}
	}
	if pinned != nil {
		req.EgressProfiles = pinned
	}
}

// refuseDisabledBuiltins applies the operator file's built-in switch
// (§5.10 PC-3) to references a caller supplies. It never touches a running
// sandbox: replays and re-applies keep the built-ins they were created with.
func (s *Service) refuseDisabledBuiltins(refs []string) error {
	if s.egressOperator().BuiltinProfiles() {
		return nil
	}
	for _, ref := range refs {
		if strings.HasPrefix(ref, egresspolicy.BuiltinProfilePrefix) {
			return fmt.Errorf("%w: egress_profiles entry %q: built-in profiles disabled on this deployment", egresspolicy.ErrInvalid, ref)
		}
	}
	return nil
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

// resolveCreateEgress expands a create's profile references into req's
// effective allow list. A failover replay can't refuse a spec the cluster
// already holds, so one whose profiles can't be read here (a built-in
// version newer than this node's catalogue, a profile read that failed)
// runs block-all and held instead (CEO D11, G7); the re-apply pass lifts
// the hold once they resolve. held reports that case.
func (s *Service) resolveCreateEgress(ctx context.Context, ownerRef string, req *models.CreateSandboxRequest) (resolvedEgress, bool, error) {
	resolved, err := s.resolveEgressProfiles(ctx, ownerRef, req.NetworkAllowOut, req.EgressProfiles)
	if err == nil {
		req.NetworkAllowOut = resolved.Effective
		return resolved, false, nil
	}
	if !isStoredSpecReplay(ctx) || !errors.Is(err, ErrEgressProfileUnavailable) {
		return resolved, false, err
	}
	s.logger.Warn("egress: profiles unavailable on failover; sandbox runs block-all until they resolve", "error", err)
	resolved = resolvedEgress{Inline: req.NetworkAllowOut, Refs: req.EgressProfiles}
	// deny_out stays: the re-apply restores it with the allow list.
	req.NetworkBlockAll, req.NetworkAllowOut, req.EgressProfiles = true, nil, nil
	return resolved, true, nil
}

// recordCreateEgressState stores a new sandbox's profile references, inline
// list and egress mode next to the row the create wrote. Without them the
// row's effective list would have nothing to explain it, profile updates
// would never reach the sandbox and a learn-mode sandbox would read as
// enforce, so a failure undoes the create. held records the profile hold a
// replay that ran block-all needs, so the re-apply pass revisits it.
func (s *Service) recordCreateEgressState(ctx context.Context, sb *models.Sandbox, r resolvedEgress, mode string, rules []models.EgressRule, withheld []string, held bool) error {
	// A container sandbox created with an inspect rule trusts the node's CA
	// for its whole life, so a later policy change may add more (P3-1).
	// Its injected env keys were replaced with placeholders, so later inject
	// rules may use them (P3-2).
	inspectCA := hasInspectRule(rules) && models.RuntimeUsesEgressGateway(sb.Runtime)
	if !models.RuntimeUsesEgressGateway(sb.Runtime) {
		withheld = nil // an isolate never sees its env
	}
	err := s.store.SetSandboxEgressProfiles(ctx, sb.ID, store.NetworkPolicyWrite{Inline: r.Inline, Profiles: r.Refs, OwnerRef: sb.OwnerRef, Mode: mode,
		Rules: rules, InspectCA: inspectCA, Withheld: withheld})
	if err == nil && len(r.Applied) > 0 {
		err = s.store.SetEgressProfilesApplied(ctx, sb.ID, r.Applied)
	}
	if err == nil && held {
		if err = s.recordHoldOnly(ctx, sb.ID, egressHoldProfileUnavailable); err == nil {
			s.refreshHeldGauge(ctx)
		}
	}
	if err != nil {
		if derr := s.DestroySandbox(context.WithoutCancel(ctx), sb.ID); derr != nil {
			s.logger.Warn("egress: undo create after a profile write failed", "sandbox_id", sb.ID, "error", derr)
		}
		return fmt.Errorf("record egress profiles: %w", err)
	}
	sb.NetworkEgressMode = mode
	sb.NetworkEgressRules = rules
	if len(r.Refs) > 0 {
		sb.NetworkAllowOut = r.Inline
		sb.EgressProfiles = r.Refs
		sb.EgressProfilesApplied = r.Applied
	}
	return nil
}
