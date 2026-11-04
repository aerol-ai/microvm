package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// Regression tests for API tokens in the Raft FSM
// (plans/identity-and-access.md §5.4; CLAUDE.md hard rule 6): apply,
// snapshot, restore, an old snapshot without tokens, the change ring and
// the mirror protocol against the real FSM.

var tokenTestEpoch = time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)

type tokenLog struct {
	t     *testing.T
	fsm   *placementFSM
	idx   uint64
	stamp time.Time
}

func newTokenLog(t *testing.T) *tokenLog {
	return &tokenLog{t: t, fsm: newPlacementFSM(), stamp: tokenTestEpoch}
}

func (l *tokenLog) apply(cmd command) any {
	l.t.Helper()
	if cmd.StampUnixNano == 0 {
		cmd.StampUnixNano = l.stamp.UnixNano()
	}
	data, err := encodeCommand(cmd)
	if err != nil {
		l.t.Fatal(err)
	}
	l.idx++
	return l.fsm.Apply(&raft.Log{Index: l.idx, Data: data})
}

func (l *tokenLog) put(rec identity.TokenRecord) any {
	return l.apply(command{Op: opPutAPIToken, APIToken: &rec})
}

func (l *tokenLog) del(id string) any {
	return l.apply(command{Op: opDeleteAPIToken, APITokenID: id})
}

func newTokenRecord(t testing.TB, name, team string, role controlplane.Role) identity.TokenRecord {
	t.Helper()
	tok, err := identitywire.NewAPIToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := tok.SecretHash()
	return identity.TokenRecord{
		ID: tok.ID, Name: name, Role: role, OwnerRef: identity.OwnerRefForTeam(team), CreatedBy: "operator",
		CreatedAt: tokenTestEpoch, ExpiresAt: tokenTestEpoch.Add(90 * 24 * time.Hour), SecretHash: hash[:],
	}
}

func TestFSMAPITokenApply(t *testing.T) {
	l := newTokenLog(t)
	ci := newTokenRecord(t, "ci-deploy", "payments", controlplane.RoleRunner)
	res, ok := l.put(ci).(apiTokenApplyResult)
	if !ok || res.Token.ID != ci.ID || res.Token.Version != 1 {
		t.Fatalf("create = %#v", l.fsm.apiTokens().byID)
	}
	if got, found := l.fsm.apiTokens().lookup(ci.ID); !found || got.Version != 1 || got.Name != "ci-deploy" {
		t.Fatalf("lookup = %+v %v", got, found)
	}

	// Names are unique per team: the same name in the same team is refused,
	// in another team or fleet-wide it is a different token.
	dup := newTokenRecord(t, "ci-deploy", "payments", controlplane.RoleViewer)
	if err := asApplyErr(l.put(dup)); !errors.Is(err, ErrAPITokenNameTaken) {
		t.Fatalf("same name, same team: %v", err)
	}
	if _, ok := l.put(newTokenRecord(t, "ci-deploy", "checkout", controlplane.RoleRunner)).(apiTokenApplyResult); !ok {
		t.Fatal("the same name in another team is allowed")
	}
	if _, ok := l.put(newTokenRecord(t, "ci-deploy", controlplane.FleetTeam, controlplane.RoleViewer)).(apiTokenApplyResult); !ok {
		t.Fatal("the same name fleet-wide is allowed")
	}

	// A retried proposal of the same create is answered with its row, and
	// records no new change.
	last := l.fsm.apiTokens().last
	if res, ok := l.put(ci).(apiTokenApplyResult); !ok || res.Token.Version != 1 || l.fsm.apiTokens().last != last {
		t.Fatalf("retried create = %+v (last %d -> %d)", res, last, l.fsm.apiTokens().last)
	}
	// A different token on the same id never overwrites it.
	clash := newTokenRecord(t, "other", "payments", controlplane.RoleRunner)
	clash.ID = ci.ID
	if err := asApplyErr(l.put(clash)); !errors.Is(err, ErrAPITokenIDTaken) {
		t.Fatalf("id clash: %v", err)
	}
	bad := newTokenRecord(t, "x", "payments", controlplane.RoleAdmin) // admin bound to one team
	if err := asApplyErr(l.put(bad)); !errors.Is(err, identity.ErrInvalidTokenRecord) {
		t.Fatalf("invalid record: %v", err)
	}
	if err := asApplyErr(l.apply(command{Op: opPutAPIToken})); err == nil {
		t.Fatal("a put without a token must fail")
	}

	// Revoke deletes at once, frees the name, and is idempotent.
	if err := asApplyErr(l.del(ci.ID)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, found := l.fsm.apiTokens().lookup(ci.ID); found {
		t.Fatal("revoked token still found")
	}
	last = l.fsm.apiTokens().last
	if err := asApplyErr(l.del(ci.ID)); err != nil || l.fsm.apiTokens().last != last {
		t.Fatalf("a repeat revoke is a no-op: %v", err)
	}
	if err := asApplyErr(l.apply(command{Op: opDeleteAPIToken})); err == nil {
		t.Fatal("a delete without an id must fail")
	}
	if _, ok := l.put(dup).(apiTokenApplyResult); !ok {
		t.Fatal("after the revoke the name is free")
	}
}

// Two creates of one name racing through the FSM: apply is serial, so
// exactly one wins and the other gets ErrAPITokenNameTaken (§5.4, Section 4
// async ordering 2).
func TestFSMAPITokenConcurrentSameName(t *testing.T) {
	for round := 0; round < 20; round++ {
		fsm := newPlacementFSM()
		var idx atomic.Uint64
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]any, 2)
		for i := range results {
			rec := newTokenRecord(t, "deploy", "payments", controlplane.RoleRunner)
			data, err := encodeCommand(command{Op: opPutAPIToken, APIToken: &rec, StampUnixNano: 1})
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = fsm.Apply(&raft.Log{Index: idx.Add(1), Data: data})
			}(i)
		}
		close(start)
		wg.Wait()
		wins, taken := 0, 0
		for _, r := range results {
			switch v := r.(type) {
			case apiTokenApplyResult:
				wins++
			case error:
				if errors.Is(v, ErrAPITokenNameTaken) {
					taken++
				}
			}
		}
		if wins != 1 || taken != 1 {
			t.Fatalf("round %d: %d wins, %d name-taken; want exactly one of each", round, wins, taken)
		}
	}
}

func TestFSMAPITokenSnapshotRestore(t *testing.T) {
	l := newTokenLog(t)
	a := newTokenRecord(t, "a", "payments", controlplane.RoleRunner)
	b := newTokenRecord(t, "b", controlplane.FleetTeam, controlplane.RoleAuditor)
	c := newTokenRecord(t, "c", "checkout", controlplane.RoleViewer)
	l.put(a)
	l.put(b)
	l.put(c)
	l.del(c.ID)
	snap, err := l.fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.apiTokens().all(), l.fsm.apiTokens().all()) || len(restored.apiTokens().all()) != 2 {
		t.Fatal("tokens did not survive the snapshot")
	}
	if got, ok := restored.apiTokens().lookup(a.ID); !ok || got.Version != 1 || !bytes.Equal(got.SecretHash, a.SecretHash) {
		t.Fatalf("restored row = %+v %v", got, ok)
	}
	// The name index is rebuilt: a taken name is still taken.
	dup := newTokenRecord(t, "a", "payments", controlplane.RoleRunner)
	data, _ := encodeCommand(command{Op: opPutAPIToken, APIToken: &dup})
	if err := asApplyErr(restored.Apply(&raft.Log{Index: 10, Data: data})); !errors.Is(err, ErrAPITokenNameTaken) {
		t.Fatalf("name index after restore: %v", err)
	}
	// The ring is node-local: after a restore any older cursor resnapshots,
	// and the snapshot's own version is current.
	fresh := newPlacementFSM()
	_ = fresh.Restore(io.NopCloser(bytes.NewReader(sink.Bytes())))
	if resp, changed := fresh.apiTokens().changesSince(1); !changed || !resp.Resnapshot {
		t.Fatalf("old cursor after restore = %+v", resp)
	}
	if _, changed := fresh.apiTokens().changesSince(l.idx); changed {
		t.Fatal("a cursor at the snapshot version is current")
	}

	// A snapshot from a build without tokens restores to none, and an
	// older build reading a newer snapshot simply has no field to fill.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 7}); err != nil {
		t.Fatal(err)
	}
	old := newPlacementFSM()
	old.apiTokens().restore([]identity.TokenRecord{a}, 1) // something to clear
	if err := old.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if len(old.apiTokens().all()) != 0 || old.apiTokens().last != 7 {
		t.Fatalf("an old snapshot must restore to no tokens at its version: %d tokens, last %d", len(old.apiTokens().all()), old.apiTokens().last)
	}
	// The snapshot lists tokens by id, so every replica persists the same
	// bytes.
	ids := []string{}
	for _, r := range l.fsm.apiTokens().snapshot() {
		ids = append(ids, r.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("snapshot order = %v", ids)
	}
}

// An FSM built as a struct literal (tests elsewhere) still gets a token
// table on first use.
func TestFSMAPITokensLazyInit(t *testing.T) {
	f := &placementFSM{}
	if f.apiTokens() == nil || f.apiTokens() != f.apiTokens() {
		t.Fatal("lazy token state")
	}
}

func TestAPITokenChangesSince(t *testing.T) {
	l := newTokenLog(t)
	a := newTokenRecord(t, "a", "payments", controlplane.RoleRunner)
	b := newTokenRecord(t, "b", "payments", controlplane.RoleRunner)
	l.put(a) // 1
	l.put(b) // 2
	s := l.fsm.apiTokens()
	if _, changed := s.changesSince(2); changed {
		t.Fatal("a current cursor is unchanged (304)")
	}
	if _, changed := s.changesSince(99); changed {
		t.Fatal("a cursor ahead of this server is unchanged too")
	}
	resp, changed := s.changesSince(0)
	if !changed || resp.Resnapshot || len(resp.Changes) != 2 || resp.Next != 2 || resp.More {
		t.Fatalf("since 0 = %+v", resp)
	}
	// Created and revoked inside the window: sent once, as deleted, with
	// the revoke's index.
	l.del(a.ID) // 3
	resp, _ = s.changesSince(0)
	if len(resp.Changes) != 2 || !resp.Changes[0].Deleted || resp.Changes[0].Index != 3 || resp.Changes[0].Token != nil {
		t.Fatalf("create+revoke = %+v", resp.Changes)
	}
	resp, _ = s.changesSince(2)
	if len(resp.Changes) != 1 || !resp.Changes[0].Deleted || resp.Next != 3 {
		t.Fatalf("since 2 = %+v", resp)
	}
	// A tight budget pages, never losing a change.
	saved := apiTokenPageByteBudget
	apiTokenPageByteBudget = 1
	defer func() { apiTokenPageByteBudget = saved }()
	// One change per response: the put of a (sent as deleted, it is gone
	// now), the put of b, then the revoke of a, which ends the run.
	var cursor uint64
	var seen []uint64
	for i := 0; i < 5; i++ {
		resp, changed := s.changesSince(cursor)
		if !changed {
			break
		}
		if len(resp.Changes) != 1 {
			t.Fatalf("budgeted page %d = %+v", i, resp)
		}
		seen = append(seen, resp.Changes[0].Index)
		cursor = resp.Next
		if !resp.More {
			break
		}
	}
	if len(seen) != 3 || seen[0] != 1 || seen[1] != 2 || seen[2] != 3 || cursor != 3 {
		t.Fatalf("budgeted walk saw %v, cursor %d", seen, cursor)
	}
}

// TestAPITokenRingKeepsABurst (finding 7.3): 5,000 creates in one minute
// stay inside the ring, so a mirror whose cursor predates the burst gets a
// delta, never a resnapshot.
func TestAPITokenRingKeepsABurst(t *testing.T) {
	l := newTokenLog(t)
	l.put(newTokenRecord(t, "seed", "payments", controlplane.RoleRunner))
	cursor := l.idx
	const burst = 5000
	for i := 0; i < burst; i++ {
		l.stamp = tokenTestEpoch.Add(time.Duration(i) * time.Minute / burst)
		rec := newTokenRecord(t, "ci-"+itoa(i), "payments", controlplane.RoleRunner)
		if _, ok := l.put(rec).(apiTokenApplyResult); !ok {
			t.Fatalf("create %d failed", i)
		}
	}
	s := l.fsm.apiTokens()
	if s.ring.len() != burst+1 || s.ring.floor != 0 {
		t.Fatalf("ring holds %d entries, floor %d; a one-minute burst must not evict", s.ring.len(), s.ring.floor)
	}
	got, polls := 0, 0
	for {
		resp, changed := s.changesSince(cursor)
		if !changed {
			break
		}
		if resp.Resnapshot {
			t.Fatal("a mirror behind a 5,000-create burst was told to resnapshot")
		}
		got += len(resp.Changes)
		cursor = resp.Next
		polls++
		if !resp.More {
			break
		}
	}
	if got != burst || cursor != l.idx {
		t.Fatalf("delta carried %d of %d creates in %d polls, cursor %d", got, burst, polls, cursor)
	}
}

func TestAPITokenRingEviction(t *testing.T) {
	// Older than the window and over the minimum: evicted, floor raised.
	r := newAPITokenRing()
	t0 := tokenTestEpoch.UnixNano()
	for i := uint64(1); i <= 1500; i++ {
		r.record(i, "tok", false, t0)
	}
	r.record(1501, "tok", false, t0+int64(11*time.Minute))
	if r.len() != apiTokenRingMin || r.floor != 1501-apiTokenRingMin {
		t.Fatalf("time eviction: len %d floor %d", r.len(), r.floor)
	}
	if r.first(r.floor) != 0 || r.at(0).index != r.floor+1 {
		t.Fatal("the first kept entry follows the floor")
	}
	// Inside the window: kept up to the hard cap.
	capped := &apiTokenRing{window: time.Hour, min: 2, max: 4}
	for i := uint64(1); i <= 6; i++ {
		capped.record(i, "tok", true, t0)
	}
	if capped.len() != 4 || capped.floor != 2 {
		t.Fatalf("cap eviction: len %d floor %d", capped.len(), capped.floor)
	}
	// Entries with no stamp are never evicted by time.
	nostamp := &apiTokenRing{window: time.Minute, min: 1, max: 100}
	nostamp.record(1, "a", false, 0)
	nostamp.record(2, "b", false, t0+int64(time.Hour))
	if nostamp.len() != 2 {
		t.Fatalf("unstamped entry evicted: len %d", nostamp.len())
	}
	// An index that goes backwards resets the ring below it.
	nostamp.record(1, "c", false, 0)
	if nostamp.len() != 1 || nostamp.floor != 0 {
		t.Fatalf("backwards index: len %d floor %d", nostamp.len(), nostamp.floor)
	}
	nostamp.record(5, "d", false, 0)
	nostamp.record(3, "e", false, 0)
	if nostamp.floor != 2 || nostamp.len() != 1 {
		t.Fatalf("backwards index above 1: floor %d len %d", nostamp.floor, nostamp.len())
	}
	// The evicted prefix is compacted away.
	compact := &apiTokenRing{window: time.Hour, min: 2, max: 3}
	for i := uint64(1); i <= 20; i++ {
		compact.record(i, "tok", false, t0)
	}
	if compact.len() != 3 || len(compact.entries) > 8 {
		t.Fatalf("compaction: len %d, backing %d", compact.len(), len(compact.entries))
	}
}

func TestAPITokenPage(t *testing.T) {
	l := newTokenLog(t)
	var ids []string
	for i := 0; i < 5; i++ {
		rec := newTokenRecord(t, "p"+itoa(i), "payments", controlplane.RoleRunner)
		l.put(rec)
		ids = append(ids, rec.ID)
	}
	sort.Strings(ids)
	s := l.fsm.apiTokens()
	page := s.page("", 2)
	if len(page.Tokens) != 2 || page.Next != ids[1] || page.Version != l.idx {
		t.Fatalf("first page = %d tokens, next %q", len(page.Tokens), page.Next)
	}
	page = s.page(page.Next, 0)
	if len(page.Tokens) != 3 || page.Next != "" || page.Tokens[0].ID != ids[2] {
		t.Fatalf("rest = %d tokens, next %q", len(page.Tokens), page.Next)
	}
	saved := apiTokenPageByteBudget
	apiTokenPageByteBudget = 1
	defer func() { apiTokenPageByteBudget = saved }()
	if page := s.page("", 0); len(page.Tokens) != 1 || page.Next != ids[0] {
		t.Fatalf("a budget smaller than a row still sends one: %d next %q", len(page.Tokens), page.Next)
	}
	if got := s.expiredBefore(tokenTestEpoch.Add(91 * 24 * time.Hour)); len(got) != 5 {
		t.Fatalf("expired = %v", got)
	}
	if got := s.expiredBefore(tokenTestEpoch); len(got) != 0 {
		t.Fatalf("nothing expired yet: %v", got)
	}
}

// fsmTokenFeed serves a mirror straight from an FSM, with the same JSON
// the internal handlers send, and a pause point between page reads.
type fsmTokenFeed struct {
	fsm        *placementFSM
	pages      atomic.Int64
	beforePage func(n int64)
}

func (f *fsmTokenFeed) FetchTokenChanges(_ context.Context, since uint64) ([]byte, error) {
	resp, changed := f.fsm.apiTokens().changesSince(since)
	if !changed {
		return nil, identity.ErrTokensUnchanged
	}
	return json.Marshal(resp)
}

func (f *fsmTokenFeed) FetchTokenPage(_ context.Context, after string, limit int) ([]byte, error) {
	n := f.pages.Add(1) - 1
	if f.beforePage != nil {
		f.beforePage(n)
	}
	return json.Marshal(f.fsm.apiTokens().page(after, limit))
}

// TestMirrorPageWalkRacingRevokeNeverResurrects (finding 4.4) against the
// real FSM: the page walk is paused after reading token T, T is revoked,
// the walk resumes, and T is absent from the copy the moment the walk
// completes.
func TestMirrorPageWalkRacingRevokeNeverResurrects(t *testing.T) {
	l := newTokenLog(t)
	var recs []identity.TokenRecord
	for i := 0; i < 3; i++ {
		rec := newTokenRecord(t, "r"+itoa(i), "payments", controlplane.RoleRunner)
		l.put(rec)
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ID < recs[j].ID })
	victim := recs[0] // on the first page
	feed := &fsmTokenFeed{fsm: l.fsm}
	feed.beforePage = func(n int64) {
		if n == 1 {
			if err := asApplyErr(l.del(victim.ID)); err != nil {
				t.Errorf("revoke during the walk: %v", err)
			}
		}
	}
	m := identity.NewTokenMirror(feed, identity.MirrorConfig{PageLimit: 1})
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if feed.pages.Load() < 2 {
		t.Fatal("the walk must have been paused between pages")
	}
	if _, found, fresh := m.LookupToken(victim.ID); found || !fresh {
		t.Fatalf("revoked during the walk: found=%v fresh=%v; it must never come back", found, fresh)
	}
	if m.Len() != 2 {
		t.Fatalf("copy holds %d tokens, want 2", m.Len())
	}
	// And a later poll keeps it gone.
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := m.LookupToken(victim.ID); found {
		t.Fatal("resurrected by a later poll")
	}
}

// A mirror whose cursor predates a 5,000-create burst catches up by delta:
// no second page walk (7.3).
func TestMirrorCatchesUpOnABurstWithoutResnapshot(t *testing.T) {
	l := newTokenLog(t)
	l.put(newTokenRecord(t, "seed", "payments", controlplane.RoleRunner))
	feed := &fsmTokenFeed{fsm: l.fsm}
	m := identity.NewTokenMirror(feed, identity.MirrorConfig{})
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	walks := feed.pages.Load()
	for i := 0; i < 5000; i++ {
		l.stamp = tokenTestEpoch.Add(time.Duration(i) * time.Minute / 5000)
		l.put(newTokenRecord(t, "b"+itoa(i), "payments", controlplane.RoleRunner))
	}
	for i := 0; i < 4; i++ { // a few polls, each following More
		if err := m.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if feed.pages.Load() != walks {
		t.Fatalf("the burst forced %d page reads: a resnapshot", feed.pages.Load()-walks)
	}
	if m.Len() != 5001 || m.Cursor() != l.idx {
		t.Fatalf("mirror holds %d tokens at cursor %d, want 5001 at %d", m.Len(), m.Cursor(), l.idx)
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}
	return string(b)
}
