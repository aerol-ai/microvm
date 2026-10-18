package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/identity"
)

// Scoped API tokens in the Raft FSM (plans/identity-and-access.md §5.4).
// The FSM holds every token's record (hash, never the secret) keyed by id,
// with a (team, name) index so names stay unique per team whatever order
// concurrent creates commit in: apply is serial, so the first wins and the
// second gets ErrAPITokenNameTaken on every replica alike.
//
// Next to the rows sits a node-local change ring the worker mirrors poll
// (identity.TokenMirror). Like the placement change log it is derived, never
// in the snapshot, and never influences what apply decides.
const (
	opPutAPIToken    opCode = 31 // store one new API token record
	opDeleteAPIToken opCode = 32 // remove one (revoke, or the expiry sweep)
)

var (
	// ErrAPITokenNameTaken is a create whose name another token in the same
	// team already holds (409).
	ErrAPITokenNameTaken = errors.New("cluster: API token name already used in this team")
	// ErrAPITokenIDTaken is a create whose random id collides with another
	// token's: the proposer mints a new id and retries.
	ErrAPITokenIDTaken = errors.New("cluster: API token id already exists")
)

// apiTokenApplyResult is the leader FSM's answer to opPutAPIToken.
type apiTokenApplyResult struct {
	Token identity.TokenRecord
}

// apiTokenState is the replicated token table plus its change ring. It has
// its own lock so a token check on a server node never waits behind a
// placement apply holding the FSM lock. Lock order: placementFSM.mu, then
// apiTokenState.mu; readers take only apiTokenState.mu.
type apiTokenState struct {
	mu     sync.RWMutex
	byID   map[string]*identity.TokenRecord
	byName map[string]string // TokenRecord.NameKey() -> id
	ring   *apiTokenRing
	// last is the Raft index of the newest token change, or of the
	// snapshot this state was restored from. A cursor at or past it is
	// current: the 304 answer, one compare under a read lock.
	last uint64
}

func newAPITokenState() *apiTokenState {
	return &apiTokenState{byID: map[string]*identity.TokenRecord{}, byName: map[string]string{}, ring: newAPITokenRing()}
}

// apiTokens returns the FSM's token state, creating it for FSMs built as
// struct literals in tests.
func (f *placementFSM) apiTokens() *apiTokenState {
	f.apiTokenInit.Do(func() {
		if f.tokens == nil {
			f.tokens = newAPITokenState()
		}
	})
	return f.tokens
}

func (f *placementFSM) applyPutAPITokenLocked(cmd command) (any, error) {
	in := cmd.APIToken
	if in == nil {
		return nil, fmt.Errorf("placementFSM: opPutAPIToken requires a token")
	}
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("placementFSM: opPutAPIToken: %w", err)
	}
	s := f.apiTokens()
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byID[in.ID]; ok {
		// A retried proposal of the same create is answered with the row
		// it already made; a different token on the same id never
		// overwrites one.
		if old.NameKey() == in.NameKey() && string(old.SecretHash) == string(in.SecretHash) {
			return apiTokenApplyResult{Token: old.Clone()}, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrAPITokenIDTaken, in.ID)
	}
	if holder, ok := s.byName[in.NameKey()]; ok {
		return nil, fmt.Errorf("%w: %q (held by %s)", ErrAPITokenNameTaken, in.Name, holder)
	}
	rec := in.Clone()
	rec.Version = f.version
	s.byID[rec.ID] = &rec
	s.byName[rec.NameKey()] = rec.ID
	s.ring.record(f.version, rec.ID, false, cmd.StampUnixNano)
	s.last = f.version
	return apiTokenApplyResult{Token: rec.Clone()}, nil
}

func (f *placementFSM) applyDeleteAPITokenLocked(cmd command) error {
	id := strings.TrimSpace(cmd.APITokenID)
	if id == "" {
		return fmt.Errorf("placementFSM: opDeleteAPIToken requires a token id")
	}
	s := f.apiTokens()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		// Revoke is idempotent: a token already gone is not a change, so
		// no mirror is woken for it.
		return nil
	}
	delete(s.byID, id)
	if s.byName[rec.NameKey()] == id {
		delete(s.byName, rec.NameKey())
	}
	s.ring.record(f.version, id, true, cmd.StampUnixNano)
	s.last = f.version
	return nil
}

// lookup answers the request path on a server node: a map read under the
// token lock only.
func (s *apiTokenState) lookup(id string) (identity.TokenRecord, bool) {
	s.mu.RLock()
	rec, ok := s.byID[id]
	s.mu.RUnlock()
	if !ok {
		return identity.TokenRecord{}, false
	}
	return *rec, true
}

// all returns every record, sorted for listing.
func (s *apiTokenState) all() []identity.TokenRecord {
	s.mu.RLock()
	out := make([]identity.TokenRecord, 0, len(s.byID))
	for _, rec := range s.byID {
		out = append(out, rec.Clone())
	}
	s.mu.RUnlock()
	identity.SortTokenRecords(out)
	return out
}

// expiredBefore returns the ids of tokens that expired before cutoff.
func (s *apiTokenState) expiredBefore(cutoff time.Time) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []string
	for id, rec := range s.byID {
		if rec.ExpiresAt.Before(cutoff) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// apiTokenPageByteBudget keeps a page well under the mirror's 12 MiB cap
// (identity.MaxMirrorPageBytes) with room for JSON overhead. A var so tests
// can shrink it.
var apiTokenPageByteBudget = 8 << 20

// apiTokenEncodedSize approximates one record's JSON size for the budget:
// the fixed fields plus the variable strings, rounded up generously.
func apiTokenEncodedSize(rec *identity.TokenRecord) int {
	const fixed = 320 // keys, two timestamps, the base64 hash, the version
	return fixed + len(rec.ID) + len(rec.Name) + len(rec.OwnerRef) + len(rec.CreatedBy) + len(rec.Role)
}

// page returns up to limit records with id > after, in id order, within the
// byte budget, plus this server's token version at the time of the read.
func (s *apiTokenState) page(after string, limit int) identity.TokenPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := identity.TokenPage{Tokens: []identity.TokenRecord{}, Version: s.last}
	budget := apiTokenPageByteBudget
	for i, id := range ids {
		rec := s.byID[id]
		size := apiTokenEncodedSize(rec)
		if (limit > 0 && len(out.Tokens) >= limit) || (size > budget && len(out.Tokens) > 0) {
			out.Next = ids[i-1]
			return out
		}
		budget -= size
		out.Tokens = append(out.Tokens, rec.Clone())
	}
	return out
}

// changesSince serves the ring: unchanged (the caller answers 304), a delta
// of each changed id's latest state, or a resnapshot when since is older
// than the ring covers. Values are read at serve time, so a token created
// and revoked inside the window is sent once, as deleted.
func (s *apiTokenState) changesSince(since uint64) (identity.TokenChanges, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if since >= s.last {
		return identity.TokenChanges{Changes: []identity.TokenChange{}, Next: since, Floor: s.ring.floor}, false
	}
	resp := identity.TokenChanges{Changes: []identity.TokenChange{}, Floor: s.ring.floor}
	if since < s.ring.floor {
		resp.Resnapshot = true
		resp.Next = s.last
		return resp, true
	}
	budget := apiTokenPageByteBudget
	pos := map[string]int{}
	next := since
	for i := s.ring.first(since); i < s.ring.len(); i++ {
		e := s.ring.at(i)
		ch := identity.TokenChange{Index: e.index, ID: e.id}
		size := 64 + len(e.id)
		if rec, ok := s.byID[e.id]; ok && !e.deleted {
			cp := rec.Clone()
			ch.Token = &cp
			size = apiTokenEncodedSize(rec)
		} else {
			ch.Deleted = true
		}
		if size > budget && len(resp.Changes) > 0 {
			resp.More = true
			break
		}
		budget -= size
		if k, seen := pos[e.id]; seen {
			resp.Changes[k] = ch
		} else {
			pos[e.id] = len(resp.Changes)
			resp.Changes = append(resp.Changes, ch)
		}
		next = e.index
	}
	if !resp.More {
		next = s.last
	}
	resp.Next = next
	return resp, true
}

func (s *apiTokenState) snapshot() []identity.TokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identity.TokenRecord, 0, len(s.byID))
	for _, rec := range s.byID {
		out = append(out, rec.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// restore replaces the table from a snapshot taken at version. The ring is
// node-local, so it restarts empty with its floor at version: any older
// cursor resnapshots instead of silently missing a change.
func (s *apiTokenState) restore(records []identity.TokenRecord, version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*identity.TokenRecord, len(records))
	s.byName = make(map[string]string, len(records))
	for _, r := range records {
		if r.ID == "" {
			continue
		}
		rec := r.Clone()
		s.byID[rec.ID] = &rec
		s.byName[rec.NameKey()] = rec.ID
	}
	s.ring.reset(version)
	s.last = version
}

// The change ring (finding 7.3). It keeps the last ten minutes of token
// changes, at least apiTokenRingMin entries and at most apiTokenRingMax. A
// fixed-size ring overflowed by a burst of creates (5,000 CI tokens) would
// push all 2,000 mirrors into a page walk at once; the time window keeps a
// burst inside the ring, and the cap bounds it at ~3 MB on a server.
// Deletes are entries too: versioned tombstones, so a mirror catching up
// past a revoke always sees it (finding 4.4).
const (
	apiTokenRingWindow = 10 * time.Minute
	apiTokenRingMin    = 1024
	apiTokenRingMax    = 65536
)

type apiTokenRingEntry struct {
	index   uint64
	id      string
	deleted bool
	stamp   int64 // proposer's clock (command.StampUnixNano), 0 if unknown
}

// apiTokenRing is a deque of changes in index order. floor: every change
// at index <= floor may be missing, so a cursor below it cannot be served.
type apiTokenRing struct {
	entries []apiTokenRingEntry
	head    int
	floor   uint64
	last    uint64
	window  time.Duration
	min     int
	max     int
}

func newAPITokenRing() *apiTokenRing {
	return &apiTokenRing{window: apiTokenRingWindow, min: apiTokenRingMin, max: apiTokenRingMax}
}

func (r *apiTokenRing) len() int                   { return len(r.entries) - r.head }
func (r *apiTokenRing) at(i int) apiTokenRingEntry { return r.entries[r.head+i] }

// first is the position of the first entry newer than since.
func (r *apiTokenRing) first(since uint64) int {
	return sort.Search(r.len(), func(i int) bool { return r.at(i).index > since })
}

func (r *apiTokenRing) reset(floor uint64) {
	r.entries, r.head = nil, 0
	r.floor, r.last = floor, floor
}

// record appends one change. An index that goes backwards (a test applying
// raft.Log{Index: 0}, or a restarted log) cannot be ordered against what is
// kept, so the ring resets and older cursors resnapshot.
func (r *apiTokenRing) record(index uint64, id string, deleted bool, stamp int64) {
	if index < r.last {
		var floor uint64
		if index > 0 {
			floor = index - 1
		}
		r.reset(floor)
	}
	r.entries = append(r.entries, apiTokenRingEntry{index: index, id: id, deleted: deleted, stamp: stamp})
	r.last = index
	for r.len() > r.max {
		r.evict()
	}
	if stamp > 0 {
		cutoff := stamp - int64(r.window)
		for r.len() > r.min {
			oldest := r.at(0)
			if oldest.stamp <= 0 || oldest.stamp >= cutoff {
				break
			}
			r.evict()
		}
	}
	// Compact once the evicted prefix is both large and most of the slice,
	// so the backing array stays proportional to what is kept.
	if r.head > r.min && r.head*2 > len(r.entries) {
		r.entries = append([]apiTokenRingEntry(nil), r.entries[r.head:]...)
		r.head = 0
	}
}

func (r *apiTokenRing) evict() {
	oldest := r.entries[r.head]
	r.entries[r.head] = apiTokenRingEntry{}
	r.head++
	if oldest.index > r.floor {
		r.floor = oldest.index
	}
}
