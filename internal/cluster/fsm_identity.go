package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// Cloud identity per sandbox in the Raft FSM (plans/sandbox-cloud-identity.md
// D1.3, D1.5). Two replicated objects, the same shape as named egress
// profiles:
//
//   - The signing key set. One set for the deployment, replaced whole under
//     a generation compare-and-swap: the proposer reads the set, decides
//     (make the first key, rotate, reseal under a new server key) and names
//     the generation it read. Apply is serial, so of two nodes that both
//     found no key, or both rotated, exactly one wins on every replica and
//     the other re-reads. Private keys are sealed under the server key every
//     node shares; the FSM never holds one in the clear.
//   - Each owner's role-tag allow list: which tags a sandbox may claim in
//     its token's subject, and the least caller role that may create one.
//
// Apply checks the same invariants the service does (cloudidentity.KeySet
// Validate, the tag and role grammar), with pure functions of the command,
// so every replica reaches the same answer.
const (
	opPutIdentityKeys    opCode = 35 // replace the signing key set, CAS on its generation
	opPutIdentityRole    opCode = 36 // create or change one owner's role tag
	opDeleteIdentityRole opCode = 37 // remove one (idempotent)
)

var (
	// ErrIdentityKeysConflict is a key-set write whose expected generation
	// is stale: another node wrote first. Re-read and decide again.
	ErrIdentityKeysConflict = errors.New("cluster: identity signing keys changed concurrently")
	// ErrIdentityInvalid is a key set or role the FSM refuses.
	ErrIdentityInvalid = errors.New("cluster: invalid identity write")
)

// IdentityKeysWrite is opPutIdentityKeys' payload.
type IdentityKeysWrite struct {
	ExpectedGeneration int64                     `json:"expected_generation"`
	Keys               []cloudidentity.KeyRecord `json:"keys"`
}

// IdentityRoleKey names one owner's role tag.
type IdentityRoleKey struct {
	Owner string `json:"owner"`
	Tag   string `json:"tag"`
}

// IdentityRoleRecord is one replicated role tag.
type IdentityRoleRecord struct {
	Owner           string `json:"owner"`
	Tag             string `json:"tag"`
	MinRole         string `json:"min_role"`
	CreatedUnixNano int64  `json:"created_unix_nano"`
	UpdatedUnixNano int64  `json:"updated_unix_nano"`
}

func (r IdentityRoleRecord) key() IdentityRoleKey { return IdentityRoleKey{r.Owner, r.Tag} }

// identityKeysApplyResult and identityRoleApplyResult are the leader FSM's
// answers, read only by the proposing leader.
type identityKeysApplyResult struct {
	Keys cloudidentity.KeySet
}

type identityRoleApplyResult struct {
	Role    IdentityRoleRecord
	Changed bool
}

// identityState is the FSM's identity objects. It lives behind
// placementFSM.mu like the egress profiles: identity writes are rare
// (admin calls, a rotation), and reads copy out under the read lock.
type identityState struct {
	keys  cloudidentity.KeySet
	roles map[IdentityRoleKey]*IdentityRoleRecord
}

func (f *placementFSM) identityLocked() *identityState {
	if f.identity == nil {
		f.identity = &identityState{roles: map[IdentityRoleKey]*IdentityRoleRecord{}}
	}
	return f.identity
}

func (f *placementFSM) applyPutIdentityKeysLocked(cmd command) (any, error) {
	in := cmd.IdentityKeys
	if in == nil {
		return nil, fmt.Errorf("%w: opPutIdentityKeys requires a key set", ErrIdentityInvalid)
	}
	st := f.identityLocked()
	if in.ExpectedGeneration != st.keys.Generation {
		return nil, fmt.Errorf("%w: at generation %d, not %d", ErrIdentityKeysConflict, st.keys.Generation, in.ExpectedGeneration)
	}
	next := cloudidentity.KeySet{Generation: in.ExpectedGeneration + 1, Keys: in.Keys}.Clone()
	if err := next.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	st.keys = next
	return identityKeysApplyResult{Keys: next.Clone()}, nil
}

func (f *placementFSM) applyPutIdentityRoleLocked(cmd command) (any, error) {
	in := cmd.IdentityRole
	if in == nil {
		return nil, fmt.Errorf("%w: opPutIdentityRole requires a role", ErrIdentityInvalid)
	}
	if err := cloudidentity.ValidateRoleTag(in.Tag); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityInvalid, err)
	}
	if !cloudidentity.ValidMinRole(in.MinRole) {
		return nil, fmt.Errorf("%w: min_role %q", ErrIdentityInvalid, in.MinRole)
	}
	st := f.identityLocked()
	old, exists := st.roles[in.key()]
	if exists && old.MinRole == in.MinRole {
		// A retried proposal answers with the row it already made.
		return identityRoleApplyResult{Role: *old}, nil
	}
	rec := IdentityRoleRecord{Owner: in.Owner, Tag: in.Tag, MinRole: in.MinRole, CreatedUnixNano: cmd.StampUnixNano, UpdatedUnixNano: cmd.StampUnixNano}
	if exists {
		rec.CreatedUnixNano = old.CreatedUnixNano
	}
	st.roles[rec.key()] = &rec
	return identityRoleApplyResult{Role: rec, Changed: true}, nil
}

func (f *placementFSM) applyDeleteIdentityRoleLocked(cmd command) error {
	in := cmd.IdentityRole
	if in == nil || strings.TrimSpace(in.Tag) == "" {
		return fmt.Errorf("%w: opDeleteIdentityRole requires a tag", ErrIdentityInvalid)
	}
	delete(f.identityLocked().roles, in.key())
	return nil
}

// identityKeys returns a copy of the key set.
func (f *placementFSM) identityKeys() cloudidentity.KeySet {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.identity == nil {
		return cloudidentity.KeySet{}
	}
	return f.identity.keys.Clone()
}

// identityRoles returns the named tags of owner, or a page by tag after
// after when tags is empty.
func (f *placementFSM) identityRoles(owner string, tags []string, after string, limit int) []IdentityRoleRecord {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []IdentityRoleRecord{}
	if f.identity == nil {
		return out
	}
	if len(tags) > 0 {
		for _, tag := range tags {
			if rec, ok := f.identity.roles[IdentityRoleKey{owner, tag}]; ok {
				out = append(out, *rec)
			}
		}
		return out
	}
	var names []string
	for k := range f.identity.roles {
		if k.Owner == owner && k.Tag > after {
			names = append(names, k.Tag)
		}
	}
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}
	for _, n := range names {
		out = append(out, *f.identity.roles[IdentityRoleKey{owner, n}])
	}
	return out
}

// identitySnapshotLocked is the identity state for a snapshot.
func (f *placementFSM) identitySnapshotLocked() (*cloudidentity.KeySet, []IdentityRoleRecord) {
	if f.identity == nil {
		return nil, nil
	}
	keys := f.identity.keys.Clone()
	roles := make([]IdentityRoleRecord, 0, len(f.identity.roles))
	for _, rec := range f.identity.roles {
		roles = append(roles, *rec)
	}
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].Owner != roles[j].Owner {
			return roles[i].Owner < roles[j].Owner
		}
		return roles[i].Tag < roles[j].Tag
	})
	return &keys, roles
}

// restoreIdentityLocked replaces the identity state from a snapshot. An
// older snapshot carries neither field and restores to no keys and no
// roles, which is the state before this feature.
func (f *placementFSM) restoreIdentityLocked(keys *cloudidentity.KeySet, roles []IdentityRoleRecord) {
	st := &identityState{roles: make(map[IdentityRoleKey]*IdentityRoleRecord, len(roles))}
	if keys != nil {
		st.keys = keys.Clone()
	}
	for _, r := range roles {
		rec := r
		st.roles[rec.key()] = &rec
	}
	f.identity = st
}
