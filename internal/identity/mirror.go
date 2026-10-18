package identity

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// The token mirror (plans/identity-and-access.md §5.4): every cluster node
// that holds no Raft state keeps a full in-memory copy of the token list, so
// checking a token is a local map read and a spray of unknown ids never
// reaches the server tier. It is the placement feed's cursor idea
// (internal/cluster/agent_placement_feed.go), simplified to a 5 s poll:
//
//	not synced ─► page walk (every page carries its server's version V)
//	            ─► catch up: changes since min(V) until 304 ─► synced, cursor
//	synced ────► changes?since=cursor every SB_IDENTITY_SYNC_INTERVAL (+jitter)
//	            ├─ 304 (cursor current) ─────────► fresh
//	            ├─ delta (from the change ring) ─► merge, cursor = Next, fresh
//	            └─ resnapshot (cursor older than the ring)
//	                 ─► wait a random 0–30 s ─► page walk again
//
// Merging keeps the higher version: a row is replaced only by one at least
// as new, and a delete at index I removes a row only if the row's version is
// not above I. Deletes travel as versioned tombstones, so a page walk that
// read a token before it was revoked cannot bring it back: the catch-up
// replays the revoke (CEO review finding 4.4).
//
// The resnapshot wait spreads a ring overflow over 30 s, so 2,000 mirrors do
// not page-walk the server tier at once (finding 7.3). Network errors keep
// the current copy and retry with backoff (5 s doubling to 30 s). Once the
// copy is older than SB_IDENTITY_MAX_STALE the mirror answers "not fresh"
// and TokenAuthenticator refuses tokens with 503, except on metrics.read
// routes (D16).
//
// Requests never trigger a sync: a lookup is always a map read. The first
// sync starts with the daemon and retries in the same loop, so the request
// path never calls the server tier, even before the first sync (L2, D21).

// TokenChange is one token's latest state since a cursor.
type TokenChange struct {
	// Index is the Raft index of the newest change to this id in the
	// served range. A delete removes a mirror's row only if the row's
	// Version is not above Index.
	Index   uint64       `json:"index"`
	ID      string       `json:"id"`
	Deleted bool         `json:"deleted,omitempty"`
	Token   *TokenRecord `json:"token,omitempty"`
}

// TokenChanges answers GET /v1/cluster/internal/tokens?since=N.
type TokenChanges struct {
	Changes []TokenChange `json:"changes"`
	// Next is the cursor to send as since on the next poll.
	Next uint64 `json:"next"`
	// More means the byte budget cut the response short: poll again now.
	More bool `json:"more,omitempty"`
	// Resnapshot means the server's change ring no longer covers since.
	Resnapshot bool   `json:"resnapshot,omitempty"`
	Floor      uint64 `json:"floor"`
}

// TokenPage is one page of the full token list, in id order.
type TokenPage struct {
	Tokens []TokenRecord `json:"tokens"`
	// Next is the id to send as after for the following page; "" at the end.
	Next string `json:"next,omitempty"`
	// Version is the serving server's token version when it read the page.
	Version uint64 `json:"version"`
}

// TokenFeed fetches the server tier's token feed (cluster.Agent implements
// it with its control-plane client). It returns raw JSON so the mirror can
// refuse an oversized page before decoding it.
type TokenFeed interface {
	// FetchTokenChanges returns a TokenChanges body, or ErrTokensUnchanged
	// when nothing changed since the cursor (a 304).
	FetchTokenChanges(ctx context.Context, since uint64) ([]byte, error)
	// FetchTokenPage returns a TokenPage body.
	FetchTokenPage(ctx context.Context, after string, limit int) ([]byte, error)
}

var (
	// ErrTokensUnchanged is a 304 from the feed: the cursor is current.
	ErrTokensUnchanged = errors.New("identity: no token changes since the cursor")
	// ErrMirrorPageTooLarge refuses a feed response over MaxMirrorPageBytes
	// (CEO review finding 5.5).
	ErrMirrorPageTooLarge = errors.New("identity: token mirror page exceeds the size cap")
	// errResnapshot asks the run loop for a jittered page walk.
	errResnapshot = errors.New("identity: token feed asked for a resnapshot")
)

// MaxMirrorPageBytes caps one feed response: the FSM read budget
// (internal/cluster placementPageByteBudget). The server pages well under
// it; anything larger is a misbehaving server and is refused undecoded.
const MaxMirrorPageBytes = 12 << 20

// Mirror defaults (setup/config-defaults.md).
const (
	DefaultSyncInterval     = 5 * time.Second
	DefaultMaxStale         = 60 * time.Second
	DefaultResnapshotSpread = 30 * time.Second
	defaultPageLimit        = 2000
	maxSyncBackoff          = 30 * time.Second
	// maxPollsPerSync bounds one Sync's "More" loop, so a server that keeps
	// saying More cannot pin the loop; the next tick carries on.
	maxPollsPerSync = 64
)

// MirrorConfig tunes a TokenMirror. Zero values take the defaults; tests
// inject the clock, the random source and the sleep.
type MirrorConfig struct {
	SyncInterval     time.Duration
	MaxStale         time.Duration
	ResnapshotSpread time.Duration
	PageLimit        int
	Logger           *slog.Logger
	Now              func() time.Time
	// Rand returns a uniform float in [0, 1).
	Rand func() float64
	// Sleep waits d or until ctx ends; false means ctx ended.
	Sleep func(ctx context.Context, d time.Duration) bool
}

func (c MirrorConfig) withDefaults() MirrorConfig {
	if c.SyncInterval <= 0 {
		c.SyncInterval = DefaultSyncInterval
	}
	if c.MaxStale <= 0 {
		c.MaxStale = DefaultMaxStale
	}
	if c.ResnapshotSpread <= 0 {
		c.ResnapshotSpread = DefaultResnapshotSpread
	}
	if c.PageLimit <= 0 {
		c.PageLimit = defaultPageLimit
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// TokenMirror is a non-Raft node's copy of the token list.
type TokenMirror struct {
	feed    TokenFeed
	cfg     MirrorConfig
	started time.Time

	mu     sync.RWMutex
	rows   map[string]TokenRecord
	cursor uint64
	synced bool

	// needResync: the next Sync page-walks. forced: the server asked for it
	// (a resnapshot), so the run loop waits the spread first. Only the
	// first sync at boot walks at once.
	needResync atomic.Bool
	forced     atomic.Bool
	// lastSync is the unix-nano time of the last sync that reached the
	// server tier and left the copy current.
	lastSync atomic.Int64

	staleLogged bool // run loop only
}

// NewTokenMirror builds a mirror over feed. It holds nothing until Run (or
// Sync) completes its first page walk, and is never fresh before that.
func NewTokenMirror(feed TokenFeed, cfg MirrorConfig) *TokenMirror {
	cfg = cfg.withDefaults()
	m := &TokenMirror{feed: feed, cfg: cfg, started: cfg.Now(), rows: map[string]TokenRecord{}}
	m.needResync.Store(true)
	return m
}

// LookupToken answers from the copy. fresh is false before the first sync
// and once the copy is older than MaxStale.
func (m *TokenMirror) LookupToken(id string) (TokenRecord, bool, bool) {
	m.mu.RLock()
	rec, ok := m.rows[id]
	synced := m.synced
	m.mu.RUnlock()
	return rec, ok, synced && m.age() <= m.cfg.MaxStale
}

// Age is how long since the copy was last known current. Before the first
// sync it is the time since the mirror started.
func (m *TokenMirror) Age() time.Duration { return m.age() }

func (m *TokenMirror) age() time.Duration {
	last := m.lastSync.Load()
	if last == 0 {
		return m.cfg.Now().Sub(m.started)
	}
	return m.cfg.Now().Sub(time.Unix(0, last))
}

// Len is the number of tokens in the copy.
func (m *TokenMirror) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rows)
}

// Cursor is the feed position the copy is current to.
func (m *TokenMirror) Cursor() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cursor
}

// Run keeps the copy current until ctx ends.
func (m *TokenMirror) Run(ctx context.Context) {
	activeMirror.Store(m)
	defer activeMirror.CompareAndSwap(m, nil)
	backoff := m.cfg.SyncInterval
	for ctx.Err() == nil {
		if m.forced.Load() {
			if !m.cfg.Sleep(ctx, m.ResnapshotDelay()) {
				return
			}
		}
		err := m.Sync(ctx)
		wait := m.pollDelay()
		switch {
		case err == nil:
			backoff = m.cfg.SyncInterval
			m.noteFresh()
		case errors.Is(err, errResnapshot):
			wait = 0 // the jittered wait happens at the top of the loop
		default:
			if ctx.Err() != nil {
				return
			}
			m.logWarn("identity: token mirror sync failed; keeping the current copy", "err", err, "retry_in", backoff)
			wait = backoff
			backoff = min(backoff*2, maxSyncBackoff)
			m.noteStale()
		}
		if !m.cfg.Sleep(ctx, wait) {
			return
		}
	}
}

// ResnapshotDelay is how long a mirror the server told to resnapshot waits
// before its page walk: uniform over ResnapshotSpread, so a ring overflow
// that hits every mirror at once spreads their walks over 30 s (7.3).
func (m *TokenMirror) ResnapshotDelay() time.Duration {
	return time.Duration(m.cfg.Rand() * float64(m.cfg.ResnapshotSpread))
}

// pollDelay is the sync interval plus up to a fifth of it, so polls from
// many nodes drift apart instead of arriving in lockstep.
func (m *TokenMirror) pollDelay() time.Duration {
	return m.cfg.SyncInterval + time.Duration(m.cfg.Rand()*float64(m.cfg.SyncInterval/5))
}

// Sync runs one step: the page walk if one is due, otherwise one poll.
func (m *TokenMirror) Sync(ctx context.Context) error {
	if m.needResync.Load() {
		return m.resync(ctx)
	}
	return m.poll(ctx)
}

func (m *TokenMirror) poll(ctx context.Context) error {
	for i := 0; i < maxPollsPerSync; i++ {
		m.mu.RLock()
		since := m.cursor
		m.mu.RUnlock()
		body, err := m.feed.FetchTokenChanges(ctx, since)
		if errors.Is(err, ErrTokensUnchanged) {
			m.markSynced()
			return nil
		}
		if err != nil {
			return err
		}
		var resp TokenChanges
		if err := decodeMirrorBody(body, &resp); err != nil {
			return err
		}
		if resp.Resnapshot {
			m.requestResnapshot(since, resp.Floor)
			return errResnapshot
		}
		m.mu.Lock()
		for _, ch := range resp.Changes {
			mergeTokenChange(m.rows, ch)
		}
		if resp.Next > m.cursor {
			m.cursor = resp.Next
		}
		m.mu.Unlock()
		if !resp.More {
			m.markSynced()
			return nil
		}
	}
	return nil
}

func (m *TokenMirror) requestResnapshot(since, floor uint64) {
	m.needResync.Store(true)
	m.forced.Store(true)
	mirrorResnapshots.Add(1)
	m.logInfo("identity: token mirror cursor is older than the server's change ring; resnapshotting",
		"since", since, "floor", floor)
}

// resync page-walks the full list, then replays every change since the
// lowest version any page was read at, and only then swaps the copy in.
func (m *TokenMirror) resync(ctx context.Context) error {
	rows := make(map[string]TokenRecord)
	after := ""
	low := uint64(0)
	pages := 0
	for {
		body, err := m.feed.FetchTokenPage(ctx, after, m.cfg.PageLimit)
		if err != nil {
			return err
		}
		var page TokenPage
		if err := decodeMirrorBody(body, &page); err != nil {
			return err
		}
		if pages == 0 || page.Version < low {
			low = page.Version
		}
		pages++
		for _, rec := range page.Tokens {
			mergeTokenChange(rows, TokenChange{Index: rec.Version, ID: rec.ID, Token: &rec})
		}
		if page.Next == "" || page.Next <= after {
			break
		}
		after = page.Next
	}
	// Catch up from the lowest page version: a page served by a lagging
	// server, or read before a revoke landed, is corrected here, before
	// the copy is ever used (finding 4.4).
	cursor := low
	for i := 0; i < maxPollsPerSync; i++ {
		body, err := m.feed.FetchTokenChanges(ctx, cursor)
		if errors.Is(err, ErrTokensUnchanged) {
			break
		}
		if err != nil {
			return err
		}
		var resp TokenChanges
		if err := decodeMirrorBody(body, &resp); err != nil {
			return err
		}
		if resp.Resnapshot {
			// The ring moved past the walk while it ran: walk again,
			// spread like any other resnapshot.
			m.requestResnapshot(cursor, resp.Floor)
			return errResnapshot
		}
		for _, ch := range resp.Changes {
			mergeTokenChange(rows, ch)
		}
		if resp.Next > cursor {
			cursor = resp.Next
		}
		if !resp.More {
			break
		}
	}
	m.mu.Lock()
	m.rows = rows
	m.cursor = cursor
	m.synced = true
	m.mu.Unlock()
	m.needResync.Store(false)
	m.forced.Store(false)
	m.markSynced()
	m.logInfo("identity: token mirror synced from a full page walk", "tokens", len(rows), "cursor", cursor, "pages", pages)
	return nil
}

// mergeTokenChange applies one change under the higher-version rule.
func mergeTokenChange(rows map[string]TokenRecord, ch TokenChange) {
	cur, ok := rows[ch.ID]
	switch {
	case ch.Deleted:
		if ok && cur.Version <= ch.Index {
			delete(rows, ch.ID)
		}
	case ch.Token != nil:
		if !ok || ch.Token.Version >= cur.Version {
			rows[ch.ID] = ch.Token.Clone()
		}
	}
}

func (m *TokenMirror) markSynced() { m.lastSync.Store(m.cfg.Now().UnixNano()) }

// noteFresh logs leaving the stale state once.
func (m *TokenMirror) noteFresh() {
	if m.staleLogged {
		m.staleLogged = false
		m.logInfo("identity: token mirror is current again; API tokens are accepted", "tokens", m.Len())
	}
}

// noteStale logs entering the stale state once.
func (m *TokenMirror) noteStale() {
	if !m.staleLogged && m.age() > m.cfg.MaxStale {
		m.staleLogged = true
		m.logWarn("identity: token mirror is stale; API tokens are refused with 503 except on metrics.read routes",
			"age", m.age().Round(time.Second), "max_stale", m.cfg.MaxStale)
	}
}

func (m *TokenMirror) logWarn(msg string, args ...any) {
	if m.cfg.Logger != nil {
		m.cfg.Logger.Warn(msg, args...)
	}
}

func (m *TokenMirror) logInfo(msg string, args ...any) {
	if m.cfg.Logger != nil {
		m.cfg.Logger.Info(msg, args...)
	}
}

// decodeMirrorBody refuses an oversized body before decoding it (5.5).
func decodeMirrorBody(body []byte, out any) error {
	if len(body) > MaxMirrorPageBytes {
		mirrorPagesRefused.Add(1)
		return fmt.Errorf("%w: %d bytes, cap %d", ErrMirrorPageTooLarge, len(body), MaxMirrorPageBytes)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("identity: decode token feed: %w", err)
	}
	return nil
}

// Mirror metrics (plans/identity-and-access.md §5.15).
var (
	activeMirror atomic.Pointer[TokenMirror]
	// mirrorResnapshots counts page walks a server asked for.
	mirrorResnapshots = expvar.NewInt("aerolvm_identity_mirror_resnapshots_total")
	// mirrorPagesRefused counts feed responses refused over the size cap.
	mirrorPagesRefused = expvar.NewInt("aerolvm_identity_mirror_page_refused_total")
)

func init() {
	// aerolvm_identity_mirror_age_seconds: how old this node's token copy
	// is. 0 on a node with no mirror (a single node or a Raft server reads
	// its own state, which is always current).
	expvar.Publish("aerolvm_identity_mirror_age_seconds", expvar.Func(func() any {
		if m := activeMirror.Load(); m != nil {
			return m.age().Seconds()
		}
		return 0
	}))
}
