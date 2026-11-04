package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// fakeFeed is a server tier in miniature: versioned rows, a change log with
// a floor (the ring), the 304 rule, and paging. It serves the same JSON
// bodies internal/cluster does.
type fakeFeed struct {
	mu      sync.Mutex
	version uint64
	rows    map[string]TokenRecord
	log     []TokenChange // Index/ID/Deleted only
	floor   uint64

	calls     atomic.Int64
	pageLimit int
	// perPoll caps changes per response, to exercise More.
	perPoll int
	// pageVersionLag lowers the Version a page reports by this much, the
	// way a lagging server would.
	pageVersionLag map[int]uint64
	// beforePage runs before page n is served (n from 0): a pause point.
	beforePage  func(n int)
	pagesServed int
	changesErr  error
	pageErr     error
	pageBody    []byte // when set, served instead of a real page
	changesBody []byte // when set, served instead of real changes
}

func newFakeFeed() *fakeFeed { return &fakeFeed{rows: map[string]TokenRecord{}} }

func (f *fakeFeed) put(rec TokenRecord) TokenRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version++
	rec.Version = f.version
	f.rows[rec.ID] = rec.Clone()
	f.log = append(f.log, TokenChange{Index: f.version, ID: rec.ID})
	return rec
}

func (f *fakeFeed) del(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version++
	delete(f.rows, id)
	f.log = append(f.log, TokenChange{Index: f.version, ID: id, Deleted: true})
}

// overflow drops the change log, as a ring that evicted everything.
func (f *fakeFeed) overflow() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.floor, f.log = f.version, nil
}

func (f *fakeFeed) FetchTokenChanges(_ context.Context, since uint64) ([]byte, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.changesErr != nil {
		return nil, f.changesErr
	}
	if f.changesBody != nil {
		return f.changesBody, nil
	}
	if since >= f.version {
		return nil, ErrTokensUnchanged
	}
	resp := TokenChanges{Changes: []TokenChange{}, Floor: f.floor}
	if since < f.floor {
		resp.Resnapshot, resp.Next = true, f.version
		return json.Marshal(resp)
	}
	pos := map[string]int{}
	resp.Next = f.version
	for _, e := range f.log {
		if e.Index <= since {
			continue
		}
		if f.perPoll > 0 && len(pos) >= f.perPoll && pos[e.ID] == 0 {
			if _, seen := pos[e.ID]; !seen {
				resp.More = true
				resp.Next = resp.Changes[len(resp.Changes)-1].Index
				break
			}
		}
		ch := TokenChange{Index: e.Index, ID: e.ID, Deleted: true}
		if rec, ok := f.rows[e.ID]; ok && !e.Deleted {
			cp := rec.Clone()
			ch.Token, ch.Deleted = &cp, false
		}
		if k, seen := pos[e.ID]; seen {
			resp.Changes[k] = ch
			continue
		}
		pos[e.ID] = len(resp.Changes)
		resp.Changes = append(resp.Changes, ch)
	}
	return json.Marshal(resp)
}

func (f *fakeFeed) FetchTokenPage(_ context.Context, after string, limit int) ([]byte, error) {
	f.calls.Add(1)
	f.mu.Lock()
	n := f.pagesServed
	f.pagesServed++
	hook := f.beforePage
	f.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pageErr != nil {
		return nil, f.pageErr
	}
	if f.pageBody != nil {
		return f.pageBody, nil
	}
	if f.pageLimit > 0 && (limit <= 0 || limit > f.pageLimit) {
		limit = f.pageLimit
	}
	var ids []string
	for id := range f.rows {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	page := TokenPage{Tokens: []TokenRecord{}, Version: f.version - f.pageVersionLag[n]}
	for i, id := range ids {
		if limit > 0 && len(page.Tokens) == limit {
			page.Next = ids[i-1]
			break
		}
		page.Tokens = append(page.Tokens, f.rows[id].Clone())
	}
	return json.Marshal(page)
}

type mirrorClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mirrorClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mirrorClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestMirror(feed TokenFeed) (*TokenMirror, *mirrorClock) {
	clock := &mirrorClock{now: testNow}
	return NewTokenMirror(feed, MirrorConfig{Now: clock.Now}), clock
}

func mustSync(t *testing.T, m *TokenMirror) {
	t.Helper()
	if err := m.Sync(t.Context()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

func lookupState(m *TokenMirror, id string) (found, fresh bool) {
	_, found, fresh = m.LookupToken(id)
	return found, fresh
}

// TestTokenMirrorSyncAndDeltas: no answer is fresh before the first sync;
// the first sync page-walks; later syncs apply deltas and 304s.
func TestTokenMirrorSyncAndDeltas(t *testing.T) {
	feed := newFakeFeed()
	_, a := mint(t, "a", "payments", controlplane.RoleRunner)
	a = feed.put(a)
	m, _ := newTestMirror(feed)
	if found, fresh := lookupState(m, a.ID); found || fresh {
		t.Fatalf("before the first sync: found=%v fresh=%v, want neither", found, fresh)
	}
	mustSync(t, m)
	if found, fresh := lookupState(m, a.ID); !found || !fresh || m.Len() != 1 || m.Cursor() != a.Version {
		t.Fatalf("after the first sync: found=%v fresh=%v len=%d cursor=%d", found, fresh, m.Len(), m.Cursor())
	}
	_, b := mint(t, "b", "payments", controlplane.RoleViewer)
	b = feed.put(b)
	feed.del(a.ID)
	mustSync(t, m)
	if found, _ := lookupState(m, a.ID); found {
		t.Fatal("a revoke must reach the mirror on its next poll")
	}
	if found, _ := lookupState(m, b.ID); !found || m.Cursor() != feed.version {
		t.Fatalf("a create must reach the mirror: cursor=%d", m.Cursor())
	}
	calls := feed.calls.Load()
	mustSync(t, m) // nothing new: one 304
	if feed.calls.Load() != calls+1 {
		t.Fatal("an unchanged poll is exactly one call")
	}
}

// TestTokenMirrorStaleness: a copy older than MaxStale is not fresh, and a
// failed sync leaves the copy in place; the next good sync makes it fresh.
func TestTokenMirrorStaleness(t *testing.T) {
	feed := newFakeFeed()
	_, a := mint(t, "a", "payments", controlplane.RoleRunner)
	a = feed.put(a)
	m, clock := newTestMirror(feed)
	mustSync(t, m)
	clock.advance(DefaultMaxStale)
	if _, fresh := lookupState(m, a.ID); !fresh {
		t.Fatal("exactly MaxStale old is still fresh")
	}
	feed.changesErr = errors.New("server tier unreachable")
	clock.advance(time.Second)
	if err := m.Sync(t.Context()); err == nil {
		t.Fatal("a failed poll reports the error")
	}
	found, fresh := lookupState(m, a.ID)
	if !found || fresh {
		t.Fatalf("stale copy: found=%v fresh=%v, want the row kept but not fresh", found, fresh)
	}
	if m.Age() <= DefaultMaxStale {
		t.Fatalf("Age = %v", m.Age())
	}
	feed.changesErr = nil
	mustSync(t, m)
	if _, fresh := lookupState(m, a.ID); !fresh {
		t.Fatal("a good poll makes the copy fresh again")
	}
}

// TestTokenMirrorResnapshot: a cursor older than the server's ring asks for
// a page walk, which the mirror does on its next step.
func TestTokenMirrorResnapshot(t *testing.T) {
	feed := newFakeFeed()
	_, a := mint(t, "a", "payments", controlplane.RoleRunner)
	feed.put(a)
	m, _ := newTestMirror(feed)
	mustSync(t, m)
	_, b := mint(t, "b", "payments", controlplane.RoleRunner)
	b = feed.put(b)
	feed.del(a.ID)
	feed.overflow()
	before := mirrorResnapshots.Value()
	if err := m.Sync(t.Context()); !errors.Is(err, errResnapshot) {
		t.Fatalf("Sync = %v, want a resnapshot request", err)
	}
	if !m.needResync.Load() || !m.forced.Load() || mirrorResnapshots.Value() != before+1 {
		t.Fatal("a resnapshot is requested and counted")
	}
	mustSync(t, m)
	if found, _ := lookupState(m, a.ID); found {
		t.Fatal("the page walk reflects the revoke")
	}
	if found, _ := lookupState(m, b.ID); !found || m.forced.Load() {
		t.Fatal("the page walk picks up the create and clears the request")
	}
}

// TestTokenMirrorPagedWalkAndMore: pages and paginated deltas are followed
// to the end in one sync.
func TestTokenMirrorPagedWalkAndMore(t *testing.T) {
	feed := newFakeFeed()
	feed.pageLimit, feed.perPoll = 2, 1
	var ids []string
	for i := 0; i < 5; i++ {
		_, r := mint(t, "t"+string(rune('a'+i)), "payments", controlplane.RoleRunner)
		ids = append(ids, feed.put(r).ID)
	}
	m := NewTokenMirror(feed, MirrorConfig{PageLimit: 2, Now: func() time.Time { return testNow }})
	mustSync(t, m)
	if m.Len() != 5 {
		t.Fatalf("walk got %d tokens, want 5", m.Len())
	}
	for i := 0; i < 3; i++ {
		_, r := mint(t, "n"+string(rune('a'+i)), "payments", controlplane.RoleRunner)
		feed.put(r)
	}
	feed.del(ids[0])
	mustSync(t, m)
	if m.Len() != 7 || m.Cursor() != feed.version {
		t.Fatalf("paginated delta: len=%d cursor=%d version=%d", m.Len(), m.Cursor(), feed.version)
	}
}

// TestTokenMirrorWalkRacingRevoke (finding 4.4): a page walk paused after
// reading token T while T is revoked never brings T back. The catch-up
// from the walk's version replays the revoke before the copy is used.
func TestTokenMirrorWalkRacingRevoke(t *testing.T) {
	feed := newFakeFeed()
	feed.pageLimit = 1
	_, t1 := mint(t, "t1", "payments", controlplane.RoleRunner)
	_, t2 := mint(t, "t2", "payments", controlplane.RoleRunner)
	t1, t2 = feed.put(t1), feed.put(t2)
	first := t1.ID
	if t2.ID < first {
		first = t2.ID
	}
	feed.beforePage = func(n int) {
		if n == 1 { // page 0 (holding `first`) is read; revoke it now
			feed.del(first)
		}
	}
	m := NewTokenMirror(feed, MirrorConfig{PageLimit: 1, Now: func() time.Time { return testNow }})
	mustSync(t, m)
	if found, fresh := lookupState(m, first); found || !fresh {
		t.Fatalf("revoked during the walk: found=%v fresh=%v; it must never be resurrected", found, fresh)
	}
	if m.Len() != 1 {
		t.Fatalf("len = %d", m.Len())
	}
}

// A page served by a lagging server reports a lower version; the catch-up
// starts from the lowest page version so nothing in between is missed.
func TestTokenMirrorCatchUpFromLowestPageVersion(t *testing.T) {
	feed := newFakeFeed()
	feed.pageLimit = 1
	_, a := mint(t, "a", "payments", controlplane.RoleRunner)
	_, b := mint(t, "b", "payments", controlplane.RoleRunner)
	feed.put(a)
	feed.put(b)
	feed.pageVersionLag = map[int]uint64{1: 1}
	m := NewTokenMirror(feed, MirrorConfig{PageLimit: 1, Now: func() time.Time { return testNow }})
	mustSync(t, m)
	if m.Cursor() != feed.version || m.Len() != 2 {
		t.Fatalf("cursor=%d len=%d", m.Cursor(), m.Len())
	}
}

// TestTokenMirrorRefusesOversizedPages (finding 5.5): a feed response over
// 12 MiB is refused undecoded, counted, and the copy is left alone.
func TestTokenMirrorRefusesOversizedPages(t *testing.T) {
	huge := append([]byte(`{"tokens":[],"pad":"`), bytes.Repeat([]byte("x"), MaxMirrorPageBytes)...)
	huge = append(huge, '"', '}')
	feed := newFakeFeed()
	feed.pageBody = huge
	m, _ := newTestMirror(feed)
	before := mirrorPagesRefused.Value()
	if err := m.Sync(t.Context()); !errors.Is(err, ErrMirrorPageTooLarge) {
		t.Fatalf("oversized page: %v", err)
	}
	if mirrorPagesRefused.Value() != before+1 {
		t.Fatal("an oversized page is counted")
	}
	feed.pageBody = nil
	mustSync(t, m)
	feed.put(TokenRecord{ID: "tok_aaaaaaaaaaaa", Name: "x", Role: controlplane.RoleViewer, ExpiresAt: testNow.Add(time.Hour), SecretHash: make([]byte, 32)})
	feed.changesBody = huge
	if err := m.Sync(t.Context()); !errors.Is(err, ErrMirrorPageTooLarge) {
		t.Fatalf("oversized delta: %v", err)
	}
	// Exactly at the cap is accepted.
	atCap := append([]byte(`{"tokens":[],"pad":"`), bytes.Repeat([]byte("x"), MaxMirrorPageBytes-len(`{"tokens":[],"pad":""}`))...)
	atCap = append(atCap, '"', '}')
	var page TokenPage
	if err := decodeMirrorBody(atCap, &page); err != nil {
		t.Fatalf("a body of exactly %d bytes: %v", len(atCap), err)
	}
}

func TestTokenMirrorFeedErrors(t *testing.T) {
	feed := newFakeFeed()
	feed.pageErr = errors.New("down")
	m, _ := newTestMirror(feed)
	if err := m.Sync(t.Context()); err == nil || !m.needResync.Load() {
		t.Fatal("a failed walk leaves the walk due")
	}
	feed.pageErr = nil
	feed.pageBody = []byte("{not json")
	if err := m.Sync(t.Context()); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("bad page JSON: %v", err)
	}
	feed.pageBody = nil
	feed.changesErr = errors.New("down")
	_, r := mint(t, "r", "payments", controlplane.RoleRunner)
	feed.put(r)
	if err := m.Sync(t.Context()); err == nil {
		t.Fatal("a failed catch-up fails the walk")
	}
	feed.changesErr = nil
	feed.changesBody = []byte("{not json")
	if err := m.Sync(t.Context()); err == nil {
		t.Fatal("bad catch-up JSON fails the walk")
	}
	feed.changesBody = nil
	mustSync(t, m)
	feed.changesBody = []byte("[]")
	_, r2 := mint(t, "r2", "payments", controlplane.RoleRunner)
	feed.put(r2)
	if err := m.Sync(t.Context()); err == nil {
		t.Fatal("bad poll JSON fails the poll")
	}
	// A ring overflow during the walk's catch-up asks for another walk.
	feed.changesBody = nil
	m2, _ := newTestMirror(feed)
	// The walk's only page was read one version back (a lagging server),
	// and by the catch-up the ring no longer covers that version.
	feed.pagesServed = 0
	feed.pageVersionLag = map[int]uint64{0: 1}
	feed.beforePage = func(int) { feed.overflow() }
	if err := m2.Sync(t.Context()); !errors.Is(err, errResnapshot) {
		t.Fatalf("overflow during the walk: %v", err)
	}
}

// TestTokenMirrorRunLoop drives Run with an injected sleep: failures back
// off 5 s doubling to 30 s, a good sync resets to the poll interval with
// jitter, and a server-requested resnapshot waits the spread first.
func TestTokenMirrorRunLoop(t *testing.T) {
	feed := newFakeFeed()
	feed.pageErr = errors.New("down")
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var waits []time.Duration
	clock := &mirrorClock{now: testNow}
	m := NewTokenMirror(feed, MirrorConfig{
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		Now:    clock.Now,
		Rand:   func() float64 { return 0.5 },
		Sleep: func(ctx context.Context, d time.Duration) bool {
			waits = append(waits, d)
			clock.advance(d)
			switch len(waits) {
			case 6:
				feed.pageErr = nil // the server tier comes back
			case 8:
				// A change, then a ring overflow: the next poll's cursor is
				// below the floor and is told to resnapshot.
				feed.put(TokenRecord{ID: "tok_cccccccccccc", Name: "c", Role: controlplane.RoleViewer, ExpiresAt: testNow.Add(time.Hour), SecretHash: make([]byte, 32)})
				feed.overflow()
			case 12:
				cancel()
				return false
			}
			return ctx.Err() == nil
		},
	})
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		if waits[i] != w {
			t.Fatalf("backoff %d = %v, want %v (all: %v)", i, waits[i], w, waits)
		}
	}
	if waits[6] != 5*time.Second+500*time.Millisecond {
		t.Fatalf("after recovery the poll interval with jitter: %v", waits[6])
	}
	// Wait 8 is the poll that hit the overflow: the loop goes round at once
	// (0), then waits the resnapshot spread (0.5 * 30 s) before walking.
	if waits[8] != 0 || waits[9] != 15*time.Second {
		t.Fatalf("resnapshot waits = %v, %v (all: %v)", waits[8], waits[9], waits)
	}
	out := logs.String()
	for _, want := range []string{"sync failed", "is stale", "current again", "resnapshotting", "full page walk"} {
		if !strings.Contains(out, want) {
			t.Errorf("logs lack %q:\n%s", want, out)
		}
	}
	if activeMirror.Load() == m {
		t.Fatal("Run clears the active mirror when it stops")
	}
}

// TestResnapshotDelaySpread is the 7.3 check: when a ring overflow tells
// every mirror to resnapshot at once, their page walks spread over the
// whole 30 s window instead of landing together.
func TestResnapshotDelaySpread(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	m := NewTokenMirror(newFakeFeed(), MirrorConfig{Rand: r.Float64})
	const mirrors = 2000
	var buckets [30]int
	lo, hi := time.Hour, time.Duration(0)
	for i := 0; i < mirrors; i++ {
		d := m.ResnapshotDelay()
		if d < 0 || d >= DefaultResnapshotSpread {
			t.Fatalf("delay %v outside [0, 30s)", d)
		}
		lo, hi = min(lo, d), max(hi, d)
		buckets[int(d/time.Second)]++
	}
	if spread := hi - lo; spread < 29*time.Second {
		t.Fatalf("2,000 forced resnapshots spread over %v, want about 30 s", spread)
	}
	fair := mirrors / len(buckets)
	for sec, n := range buckets {
		if n > 2*fair {
			t.Fatalf("second %d holds %d page walks, more than twice its share (%d)", sec, n, fair)
		}
	}
	if DefaultResnapshotSpread < 30*time.Second {
		t.Fatal("the spread window is at least 30 s")
	}
}

func TestMirrorAgeMetric(t *testing.T) {
	v := expvar.Get("aerolvm_identity_mirror_age_seconds")
	if v == nil {
		t.Fatal("age metric not published")
	}
	activeMirror.Store(nil)
	if v.String() != "0" {
		t.Fatalf("no mirror: %s", v.String())
	}
	m, clock := newTestMirror(newFakeFeed())
	mustSync(t, m)
	clock.advance(7 * time.Second)
	activeMirror.Store(m)
	defer activeMirror.Store(nil)
	if v.String() != "7" {
		t.Fatalf("age = %s, want 7", v.String())
	}
}

func TestMirrorDefaultsAndSleep(t *testing.T) {
	c := MirrorConfig{}.withDefaults()
	if c.SyncInterval != DefaultSyncInterval || c.MaxStale != DefaultMaxStale || c.ResnapshotSpread != DefaultResnapshotSpread || c.PageLimit <= 0 {
		t.Fatalf("defaults: %+v", c)
	}
	if !sleepCtx(t.Context(), 0) || !sleepCtx(t.Context(), time.Millisecond) {
		t.Fatal("sleepCtx on a live context")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if sleepCtx(ctx, time.Hour) || sleepCtx(ctx, 0) {
		t.Fatal("sleepCtx on a cancelled context")
	}
}

// mergeTokenChange is the higher-version rule on its own.
func TestMergeTokenChange(t *testing.T) {
	rows := map[string]TokenRecord{}
	v5 := TokenRecord{ID: "tok_x", Version: 5}
	mergeTokenChange(rows, TokenChange{Index: 5, ID: "tok_x", Token: &v5})
	mergeTokenChange(rows, TokenChange{Index: 3, ID: "tok_x", Deleted: true})
	if _, ok := rows["tok_x"]; !ok {
		t.Fatal("a delete older than the row must not remove it")
	}
	v4 := TokenRecord{ID: "tok_x", Version: 4, Name: "old"}
	mergeTokenChange(rows, TokenChange{Index: 4, ID: "tok_x", Token: &v4})
	if rows["tok_x"].Name == "old" {
		t.Fatal("an older row must not replace a newer one")
	}
	mergeTokenChange(rows, TokenChange{Index: 9, ID: "tok_x", Deleted: true})
	if _, ok := rows["tok_x"]; ok {
		t.Fatal("a newer delete removes the row")
	}
	mergeTokenChange(rows, TokenChange{Index: 10, ID: "tok_y"}) // neither: ignored
	if len(rows) != 0 {
		t.Fatal("a change with no token and no delete is ignored")
	}
}
