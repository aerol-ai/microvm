package cluster

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Named egress profiles in the Raft FSM (plans/egress-domain-filtering.md
// D21, CEO D19). Profiles are replicated objects; the FSM also keeps a
// profile → referencing-sandbox index, derived from each placement's spec,
// so delete-in-use and the union cap are decided at apply time and every
// replica reaches the same answer however writes race.
const (
	opPutEgressProfile    opCode = 27 // create or replace one owner's named egress profile
	opDeleteEgressProfile opCode = 28 // remove one, refused while a placement references it
)

// fsmOpsVersion is the FSM op set this build applies, advertised in gossip
// meta ("fv"). An old build fails an op it doesn't know, so a leader accepts
// a write that needs a newer op only once every Raft server reports at least
// that version (egressProfileWritesAllowed).
const (
	fsmOpsVersion              = 1
	egressProfileFSMOpsVersion = 1 // opPutEgressProfile, opDeleteEgressProfile
)

var (
	// ErrEgressProfileInUse is a delete of a profile placements reference.
	ErrEgressProfileInUse = errors.New("cluster: egress profile is referenced by sandboxes")
	// ErrEgressProfileCapExceeded is a profile change that would push a
	// referencing sandbox past the union hostname cap.
	ErrEgressProfileCapExceeded = errors.New("cluster: egress profile change would exceed a referencing sandbox's hostname cap")
	// ErrClusterVersion is a write that needs an FSM op some Raft server's
	// build doesn't apply yet; it succeeds once the rolling upgrade is done.
	ErrClusterVersion = errors.New("cluster: not every server runs a build that supports this write yet")
)

// EgressProfileKey names one owner's profile.
type EgressProfileKey struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// EgressProfileRecord is one replicated profile. HostnameCount is computed by
// the proposer (the entries are canonical) so the apply-time cap check needs
// only counts.
type EgressProfileRecord struct {
	Owner           string   `json:"owner"`
	Name            string   `json:"name"`
	AllowOut        []string `json:"allow_out"`
	Description     string   `json:"description,omitempty"`
	HostnameCount   int      `json:"hostname_count"`
	Generation      int64    `json:"generation"`
	CreatedUnixNano int64    `json:"created_unix_nano"`
	UpdatedUnixNano int64    `json:"updated_unix_nano"`
}

func (r EgressProfileRecord) key() EgressProfileKey { return EgressProfileKey{r.Owner, r.Name} }

func cloneEgressProfileRecord(r EgressProfileRecord) EgressProfileRecord {
	r.AllowOut = append([]string(nil), r.AllowOut...)
	return r
}

// egressProfileApplyResult is the leader FSM's answer to opPutEgressProfile.
type egressProfileApplyResult struct {
	Profile EgressProfileRecord
	Changed bool
}

// egressInlineHostnames counts a spec's inline hostname entries for the
// hot row. The spec was validated at the API; an entry that no longer
// parses counts as a hostname, which can only make the cap stricter.
func egressInlineHostnames(spec *models.CreateSandboxRequest) int {
	if spec == nil || len(spec.EgressProfiles) == 0 {
		return 0
	}
	entries, err := egresspolicy.ParseAllowList(egresspolicy.FieldAllowOut, spec.NetworkAllowOut, egresspolicy.MaxUnionHostnames)
	if err != nil {
		return len(spec.NetworkAllowOut)
	}
	return egresspolicy.CountHostnames(entries)
}

func (f *placementFSM) applyPutEgressProfileLocked(cmd command) (any, error) {
	in := cmd.EgressProfile
	if in == nil || strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("placementFSM: opPutEgressProfile requires a profile")
	}
	key := in.key()
	old, exists := f.egressProfiles[key]
	if exists && slices.Equal(old.AllowOut, in.AllowOut) && old.Description == in.Description {
		return egressProfileApplyResult{Profile: cloneEgressProfileRecord(*old)}, nil
	}
	if over := f.egressProfileCapOverLocked(key, in.HostnameCount); len(over) > 0 {
		return nil, fmt.Errorf("%w: with this change %s would hold more than %d hostname entries across their allow list and profiles",
			ErrEgressProfileCapExceeded, strings.Join(over, ", "), egresspolicy.MaxUnionHostnames)
	}
	rec := cloneEgressProfileRecord(*in)
	rec.Generation, rec.CreatedUnixNano = 1, cmd.StampUnixNano
	if exists {
		rec.Generation, rec.CreatedUnixNano = old.Generation+1, old.CreatedUnixNano
	}
	rec.UpdatedUnixNano = cmd.StampUnixNano
	f.egressProfiles[key] = &rec
	return egressProfileApplyResult{Profile: cloneEgressProfileRecord(rec), Changed: true}, nil
}

func (f *placementFSM) applyDeleteEgressProfileLocked(cmd command) error {
	in := cmd.EgressProfile
	if in == nil || strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("placementFSM: opDeleteEgressProfile requires a profile")
	}
	key := in.key()
	if refs := f.egressProfileRefs[key]; len(refs) > 0 {
		return fmt.Errorf("%w: %d sandbox(es) reference %s", ErrEgressProfileInUse, len(refs), key.Name)
	}
	delete(f.egressProfiles, key)
	return nil
}

// egressProfileCapOverLocked returns the sandboxes referencing key that a
// profile of newCount hostnames would push past MaxUnionHostnames, counting
// each list's hostnames (duplicates across lists included) exactly as the
// service does at create and policy PUT.
func (f *placementFSM) egressProfileCapOverLocked(key EgressProfileKey, newCount int) []string {
	var over []string
	for id := range f.egressProfileRefs[key] {
		p, ok := f.placements[id]
		if !ok {
			continue
		}
		total := p.EgressInlineHostnames
		for _, name := range p.EgressProfiles {
			k := EgressProfileKey{p.OwnerRef, name}
			if k == key {
				total += newCount
			} else if rec, ok := f.egressProfiles[k]; ok {
				total += rec.HostnameCount
			}
		}
		if total > egresspolicy.MaxUnionHostnames {
			over = append(over, id)
		}
	}
	sort.Strings(over)
	return over
}

// reindexEgressProfilesLocked moves a placement's entries in the reference
// index from its old hot row to its new one (nil removes it). Every write
// and delete of f.placements passes through here, so the index can't drift
// from the rows it is derived from.
func (f *placementFSM) reindexEgressProfilesLocked(id string, old, nu *Placement) {
	if old != nil {
		for _, name := range old.EgressProfiles {
			k := EgressProfileKey{old.OwnerRef, name}
			if refs := f.egressProfileRefs[k]; refs != nil {
				delete(refs, id)
				if len(refs) == 0 {
					delete(f.egressProfileRefs, k)
				}
			}
		}
	}
	if nu != nil {
		for _, name := range nu.EgressProfiles {
			k := EgressProfileKey{nu.OwnerRef, name}
			refs := f.egressProfileRefs[k]
			if refs == nil {
				refs = make(map[string]struct{})
				f.egressProfileRefs[k] = refs
			}
			refs[id] = struct{}{}
		}
	}
}

// releaseEgressProfilesLocked drops a placement about to be deleted from the
// reference index.
func (f *placementFSM) releaseEgressProfilesLocked(id string) {
	if old, ok := f.placements[id]; ok {
		f.reindexEgressProfilesLocked(id, &old, nil)
	}
}

func (f *placementFSM) egressProfile(owner, name string) (EgressProfileRecord, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rec, ok := f.egressProfiles[EgressProfileKey{owner, name}]
	if !ok {
		return EgressProfileRecord{}, false
	}
	return cloneEgressProfileRecord(*rec), true
}

// egressProfilesPage returns up to limit of owner's profiles by name, after
// the name in after.
func (f *placementFSM) egressProfilesPage(owner, after string, limit int) []EgressProfileRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var names []string
	for k := range f.egressProfiles {
		if k.Owner == owner && k.Name > after {
			names = append(names, k.Name)
		}
	}
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}
	out := make([]EgressProfileRecord, 0, len(names))
	for _, n := range names {
		out = append(out, cloneEgressProfileRecord(*f.egressProfiles[EgressProfileKey{owner, n}]))
	}
	return out
}

func (f *placementFSM) egressProfilesSnapshotLocked() []EgressProfileRecord {
	out := make([]EgressProfileRecord, 0, len(f.egressProfiles))
	for _, rec := range f.egressProfiles {
		out = append(out, cloneEgressProfileRecord(*rec))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner != out[j].Owner {
			return out[i].Owner < out[j].Owner
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (f *placementFSM) restoreEgressProfilesLocked(records []EgressProfileRecord) {
	f.egressProfiles = make(map[EgressProfileKey]*EgressProfileRecord, len(records))
	for _, r := range records {
		rec := cloneEgressProfileRecord(r)
		f.egressProfiles[rec.key()] = &rec
	}
}
