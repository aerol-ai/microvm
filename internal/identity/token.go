package identity

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// TokenRecord is one API token as sandboxd stores and replicates it: about
// 200 bytes. The plaintext secret is never in it; SecretHash is SHA-256 of
// the secret. Records are immutable once created (a token is revoked, never
// edited), so a copy may share SecretHash's backing array.
type TokenRecord struct {
	// ID is the public id (tok_…): the lookup key and the audit caller id.
	ID   string            `json:"id"`
	Name string            `json:"name"`
	Role controlplane.Role `json:"role"`
	// OwnerRef is team:<team> for a team-bound token and "" for a token
	// bound to every team, which is unscoped like the PAT.
	OwnerRef string `json:"owner_ref,omitempty"`
	// CreatedBy is the principal id of whoever minted it.
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	SecretHash []byte    `json:"secret_hash"`
	// Version is the Raft log index of the write that created it, in a
	// cluster; 0 on a single node. Mirrors merge on it, so a delete at a
	// higher index always wins over a stale copy of the row.
	Version uint64 `json:"version,omitempty"`
}

// ErrInvalidTokenRecord is a record no store accepts.
var ErrInvalidTokenRecord = errors.New("identity: invalid token record")

// Validate checks a record before it is stored. Every store runs it, so a
// cluster's FSM refuses the same records a single node's SQLite does.
func (r TokenRecord) Validate() error {
	switch {
	case !identitywire.ValidAPITokenID(r.ID):
		return fmt.Errorf("%w: id %q", ErrInvalidTokenRecord, r.ID)
	case !identitywire.ValidTokenName(r.Name):
		return fmt.Errorf("%w: name %q", ErrInvalidTokenRecord, r.Name)
	case !r.Role.Valid():
		return fmt.Errorf("%w: role %q", ErrInvalidTokenRecord, r.Role)
	case len(r.SecretHash) != 32:
		return fmt.Errorf("%w: secret hash is %d bytes", ErrInvalidTokenRecord, len(r.SecretHash))
	case r.ExpiresAt.IsZero():
		return fmt.Errorf("%w: no expiry", ErrInvalidTokenRecord)
	}
	team := r.Team()
	if r.OwnerRef != "" && !strings.HasPrefix(r.OwnerRef, controlplane.TeamOwnerPrefix) {
		return fmt.Errorf("%w: owner %q is not a team", ErrInvalidTokenRecord, r.OwnerRef)
	}
	if team != controlplane.FleetTeam && !identitywire.ValidTeamName(team) {
		return fmt.Errorf("%w: owner %q", ErrInvalidTokenRecord, r.OwnerRef)
	}
	if r.Role.RequiresFleet() && team != controlplane.FleetTeam {
		return fmt.Errorf("%w: role %s must be bound to every team", ErrInvalidTokenRecord, r.Role)
	}
	return nil
}

// Team is the token's team name, or "*" for a token bound to every team.
func (r TokenRecord) Team() string {
	if r.OwnerRef == "" {
		return controlplane.FleetTeam
	}
	if team, ok := strings.CutPrefix(r.OwnerRef, controlplane.TeamOwnerPrefix); ok {
		return team
	}
	return r.OwnerRef
}

// OwnerRefForTeam is the owner ref a token bound to team carries.
func OwnerRefForTeam(team string) string {
	if team == controlplane.FleetTeam {
		return ""
	}
	return controlplane.TeamOwnerRef(team)
}

// Expired reports whether the token no longer authenticates at now.
func (r TokenRecord) Expired(now time.Time) bool { return !now.Before(r.ExpiresAt) }

// Access is the caller a request presenting this token acts as.
func (r TokenRecord) Access() controlplane.Access {
	return controlplane.TokenAccess(r.ID, r.Name, r.Role, r.Team(), r.ExpiresAt)
}

// Clone copies r with its own SecretHash, for a store that keeps it.
func (r TokenRecord) Clone() TokenRecord {
	r.SecretHash = append([]byte(nil), r.SecretHash...)
	return r
}

// NameKey is the uniqueness key: names are unique per team (§5.4).
func (r TokenRecord) NameKey() string { return r.OwnerRef + "\x00" + r.Name }

// SortTokenRecords orders records by team, then name, then id: the order
// every list answers in.
func SortTokenRecords(recs []TokenRecord) {
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].OwnerRef != recs[j].OwnerRef {
			return recs[i].OwnerRef < recs[j].OwnerRef
		}
		if recs[i].Name != recs[j].Name {
			return recs[i].Name < recs[j].Name
		}
		return recs[i].ID < recs[j].ID
	})
}

// TokenLookup is what the request path asks about a token id. It answers
// from memory only, never with a network call or a disk read.
//
// found reports whether id is a stored token. fresh reports whether this
// node can vouch for that answer: false only on a mirror that has not
// synced within SB_IDENTITY_MAX_STALE, where a revoked token might still
// look live (or a new one not yet appear).
type TokenLookup interface {
	LookupToken(id string) (rec TokenRecord, found, fresh bool)
}

// TokenSet is the single-node token index: every stored token in memory,
// loaded once at boot and updated on every write, so a request never reads
// SQLite. One process owns the store, so it is never stale.
type TokenSet struct {
	mu   sync.RWMutex
	byID map[string]TokenRecord
}

// LookupToken answers from memory; a single node is always fresh.
func (s *TokenSet) LookupToken(id string) (TokenRecord, bool, bool) {
	s.mu.RLock()
	rec, ok := s.byID[id]
	s.mu.RUnlock()
	return rec, ok, true
}

// Put stores rec, replacing any record with its id.
func (s *TokenSet) Put(rec TokenRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = make(map[string]TokenRecord)
	}
	s.byID[rec.ID] = rec.Clone()
}

// Delete forgets id. A missing id is a no-op.
func (s *TokenSet) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// Replace swaps the whole set, as at boot.
func (s *TokenSet) Replace(recs []TokenRecord) {
	next := make(map[string]TokenRecord, len(recs))
	for _, r := range recs {
		next[r.ID] = r.Clone()
	}
	s.mu.Lock()
	s.byID = next
	s.mu.Unlock()
}

// Len is the number of stored tokens.
func (s *TokenSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// CountAPITokens counts the unexpired tokens by role, for the
// aerolvm_api_tokens gauge.
func (s *TokenSet) CountAPITokens(now time.Time) map[controlplane.Role]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[controlplane.Role]int, 4)
	for _, rec := range s.byID {
		if !rec.Expired(now) {
			out[rec.Role]++
		}
	}
	return out
}
