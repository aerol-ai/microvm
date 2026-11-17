package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Signing that only servers do (least privilege). The record and why it is
// server-only are in cluster/fsm_server_signing.go. This side:
//
//	a server        opens the record's seed with its server key ring and
//	                derives the keys (secrets.ServerTokenKey, ...)
//	the leader      writes the record once every member verifies what
//	                servers sign, and reseals it after a ring rotation
//	                (UpkeepServerSigning)
//	a worker or     reads the public keys from the server tier
//	gateway         (signingKeyMirror) and has a server sign for it
//
// Which keys check a sandbox token:
//
//	no record yet (or a single node)  the server key ring's, as before
//	a record                          the keys derived from the seed; a
//	                                  token signed with a ring key only if
//	                                  issued before the record's Since
//
// A worker that has not read the feed takes no ring-signed token: it cannot
// tell whether servers took over, so it reads the feed first, and refuses
// the token if it cannot.

// serverSigningAAD binds the sealed seed to its purpose.
var serverSigningAAD = []byte("aerolvm-server-signing-seed/v1")

// serverSigningLead is how long after the record is written its keys alone
// count: every node reads it, and signs through the servers, well before
// tokens signed the old way stop counting.
const serverSigningLead = 2 * time.Minute

// serverSigningUpkeepEvery is the leader's upkeep cadence. Nothing in it is
// urgent: the record is written once, and resealed after a rotation.
const serverSigningUpkeepEvery = 30 * time.Second

var (
	// ErrServerSigningOff is a call that needs the server signing record
	// before one exists (503: a server further behind, or a cluster not yet
	// on the version that writes it).
	ErrServerSigningOff = errors.New("server signing is not on in this cluster yet")
	// ErrSignNotOwner is a node asking a server to sign for a sandbox it
	// does not own (403).
	ErrSignNotOwner = errors.New("only the sandbox's owner node may ask for its tokens")
)

// serverSigningCluster is a server's view of the record (cluster.Cluster).
type serverSigningCluster interface {
	ServerSigningRecord() (cluster.ServerSigning, bool)
	ServerSigningGate(force bool) cluster.ServerSigningGate
	WriteServerSigning(ctx context.Context, w cluster.ServerSigningWrite, force bool) (cluster.ServerSigning, error)
	IsLeader() bool
}

// signingFeedCluster is a worker's or gateway's (cluster.Agent).
type signingFeedCluster interface {
	FetchSigningKeys(context.Context) (cluster.SigningKeys, error)
	SignSandboxToken(context.Context, cluster.SandboxTokenSignRequest) (cluster.SandboxTokenSignResponse, error)
	SignIdentityToken(context.Context, cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error)
}

// serverKeys is the record's seed as this server opened it, and the keys
// derived from it for the ring ids it held then.
type serverKeys struct {
	sealed  []byte
	ringIDs []uint32
	since   int64
	seed    []byte
	current uint32
	tokens  map[uint32]ed25519.PrivateKey
	// identity seals the cloud-identity signing keys; made on first use.
	identity *secrets.ServerSealer
}

// serverSigningState is a node's signing state.
type serverSigningState struct {
	mu     sync.Mutex
	keys   *serverKeys
	mirror *signingKeyMirror
	// heldReason and heldLogged throttle the leader's log line while the
	// gate holds the record back (UpkeepServerSigning).
	heldReason string
	heldLogged time.Time
	// Seams; nil in production.
	rand io.Reader
	now  func() time.Time
}

func (s *Service) signingNow() time.Time {
	if s.serverSigning.now != nil {
		return s.serverSigning.now()
	}
	return time.Now()
}

// openServerKeys returns this server's keys from the record, opened with its
// ring, and nil with no record or on a node that holds none.
func (s *Service) openServerKeys() (*serverKeys, error) {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok {
		return nil, nil
	}
	rec, have := c.ServerSigningRecord()
	if !have {
		return nil, nil
	}
	if s.cipher == nil {
		return nil, fmt.Errorf("%w: no server key to open the signing seed with", ErrSandboxTokensUnavailable)
	}
	ids := s.cipher.KeyIDs()
	st := &s.serverSigning
	st.mu.Lock()
	defer st.mu.Unlock()
	if k := st.keys; k != nil && bytes.Equal(k.sealed, rec.Sealed) && slices.Equal(k.ringIDs, ids) {
		return k, nil
	}
	seed, err := s.cipher.DecryptWithAAD(rec.Sealed, serverSigningAAD)
	if err != nil {
		return nil, fmt.Errorf("%w: open the signing seed: %v", ErrSandboxTokensUnavailable, err)
	}
	if len(seed) != secrets.ServerSeedSize {
		return nil, secrets.ErrServerSeed
	}
	k := &serverKeys{sealed: bytes.Clone(rec.Sealed), ringIDs: ids, since: rec.SinceUnixNano, seed: seed, tokens: map[uint32]ed25519.PrivateKey{}}
	for _, id := range ids {
		kid, key, err := secrets.ServerTokenKey(seed, id)
		if err != nil {
			return nil, err
		}
		k.tokens[kid] = key
	}
	if k.current, err = secrets.ServerTokenKeyID(s.cipher.CurrentKeyID()); err != nil {
		return nil, err
	}
	st.keys = k
	return k, nil
}

// SandboxTokenSigner signs with the server key derived for the ring's
// current key (sandboxtoken.Signer).
func (k *serverKeys) SandboxTokenSigner() (uint32, ed25519.PrivateKey, error) {
	key := k.tokens[k.current]
	if key == nil {
		return 0, nil, fmt.Errorf("no server token key for key id %d", k.current)
	}
	return k.current, key, nil
}

// SandboxTokenVerifyKey is a server key's public half.
func (k *serverKeys) SandboxTokenVerifyKey(kid uint32) (ed25519.PublicKey, bool) {
	key := k.tokens[kid]
	if key == nil {
		return nil, false
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	return pub, ok
}

// signingMode is what this node knows about the record: whether there is
// one (on), its Since, and when tokens signed the old way stopped counting
// at all (oldTokensEnd, 0 until the operator ends them). known is false
// only on a worker or gateway that has not read the feed.
type signingMode struct {
	known        bool
	on           bool
	since        int64
	oldTokensEnd int64
}

// currentSigningMode reads the mode: a single node is never on; a server
// reads its FSM; a worker or gateway its mirror of the feed.
func (s *Service) currentSigningMode() signingMode {
	if !s.ClusterEnabled() {
		return signingMode{known: true}
	}
	switch c := s.Cluster().(type) {
	case serverSigningCluster:
		rec, ok := c.ServerSigningRecord()
		return signingMode{known: true, on: ok, since: rec.SinceUnixNano, oldTokensEnd: rec.OldTokensEndUnixNano}
	case signingFeedCluster:
		return s.signingMirror(c).view(0).mode
	}
	return signingMode{known: true}
}

// serversMaySign reports whether servers sign, or this node cannot tell:
// the SSH bridge gate's rule (ssh_bridge_key.go), which fails closed.
func (s *Service) serversMaySign() bool {
	mode := s.currentSigningMode()
	return !mode.known || mode.on
}

// signingMirror returns this node's mirror of the feed, made on first use.
func (s *Service) signingMirror(c signingFeedCluster) *signingKeyMirror {
	st := &s.serverSigning
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.mirror == nil {
		st.mirror = &signingKeyMirror{fetch: c.FetchSigningKeys, now: st.now}
	}
	return st.mirror
}

// SigningKeysFeed is what a server answers the feed with: Since, and the
// public token keys for every key its ring holds. No record: Since 0.
func (s *Service) SigningKeysFeed() (cluster.SigningKeys, error) {
	if _, ok := s.Cluster().(serverSigningCluster); !ok {
		return cluster.SigningKeys{}, ErrServerSigningOff
	}
	k, err := s.openServerKeys()
	if err != nil || k == nil {
		return cluster.SigningKeys{}, err
	}
	out := cluster.SigningKeys{SinceUnixNano: k.since, TokenKeys: make(map[uint32][]byte, len(k.tokens))}
	if rec, ok := s.Cluster().(serverSigningCluster).ServerSigningRecord(); ok {
		out.OldTokensEndUnixNano = rec.OldTokensEndUnixNano
	}
	for kid := range k.tokens {
		if pub, ok := k.SandboxTokenVerifyKey(kid); ok {
			out.TokenKeys[kid] = []byte(pub)
		}
	}
	return out, nil
}

// UpkeepServerSigning is one pass of the leader's upkeep: write the record
// once the gate allows it (cluster.ServerSigningGate), and reseal it under
// the ring's current key after a rotation. Every other node returns at once.
func (s *Service) UpkeepServerSigning(ctx context.Context) error {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok || !c.IsLeader() || s.cipher == nil {
		return nil
	}
	rec, have := c.ServerSigningRecord()
	if !have {
		g := c.ServerSigningGate(false)
		if !g.Allowed {
			s.logSigningHeld(g)
			return nil
		}
		_, err := s.writeServerSigningRecord(ctx, c, false)
		return err
	}
	resealed, _, changed, err := s.cipher.Reseal(rec.Sealed, serverSigningAAD)
	if err != nil || !changed {
		return err
	}
	_, err = c.WriteServerSigning(ctx, cluster.ServerSigningWrite{
		Signing: cluster.ServerSigning{Sealed: resealed, SinceUnixNano: rec.SinceUnixNano},
		Expect:  rec.Sealed,
	}, false)
	return err
}

// signingHeldLogEvery is how often the leader repeats why the record waits.
const signingHeldLogEvery = 10 * time.Minute

// logSigningHeld logs why the record waits, once the active version allows
// it (before that a rollout is simply not finished): on a new reason, then
// every signingHeldLogEvery.
func (s *Service) logSigningHeld(g cluster.ServerSigningGate) {
	if g.ActiveFV < cluster.ServerSigningFSMOpsVersion {
		return
	}
	st := &s.serverSigning
	st.mu.Lock()
	now := s.signingNow()
	due := g.Reason != st.heldReason || now.Sub(st.heldLogged) >= signingHeldLogEvery
	if due {
		st.heldReason, st.heldLogged = g.Reason, now
	}
	st.mu.Unlock()
	if due && s.logger != nil {
		s.logger.Warn("cluster: servers do not sign sandbox tokens yet", "reason", g.Reason, "waiting_on", g.Waiting)
	}
}

// writeServerSigningRecord writes the record with a fresh seed.
func (s *Service) writeServerSigningRecord(ctx context.Context, c serverSigningCluster, force bool) (cluster.ServerSigning, error) {
	seed := make([]byte, secrets.ServerSeedSize)
	r := s.serverSigning.rand
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, seed); err != nil {
		return cluster.ServerSigning{}, err
	}
	sealed, err := s.cipher.EncryptWithAAD(seed, serverSigningAAD)
	clear(seed)
	if err != nil {
		return cluster.ServerSigning{}, err
	}
	written, err := c.WriteServerSigning(ctx, cluster.ServerSigningWrite{Signing: cluster.ServerSigning{
		Sealed: sealed, SinceUnixNano: s.signingNow().Add(serverSigningLead).UnixNano(),
	}}, force)
	if err == nil && s.logger != nil {
		s.logger.Info("cluster: servers now sign sandbox tokens and cloud-identity tokens",
			"tokens_signed_before_only_until", time.Unix(0, written.SinceUnixNano).UTC(), "started_by_operator", force)
	}
	return written, err
}

// ErrServerSigningNotLeader is a call only the leader serves (the API
// forwards it there).
var ErrServerSigningNotLeader = errors.New("only the cluster leader starts server signing or ends old tokens")

// StartServerSigning writes the record now, past members that report an
// older or unknown version (the operator's override of the one gossip
// check, cluster.ServerSigningGate). The active cluster version still has
// to allow it. A record that exists is answered as it is.
func (s *Service) StartServerSigning(ctx context.Context) (cluster.ServerSigning, error) {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok || !c.IsLeader() {
		return cluster.ServerSigning{}, ErrServerSigningNotLeader
	}
	if s.cipher == nil {
		return cluster.ServerSigning{}, ErrSandboxTokensUnavailable
	}
	if rec, have := c.ServerSigningRecord(); have {
		return rec, nil
	}
	return s.writeServerSigningRecord(ctx, c, true)
}

// EndOldSandboxTokens ends every sandbox token signed the old way (with a
// server key ring key), whenever it was issued: from now on only the
// servers' tokens count. Without it, one issued before Since counts until
// it expires, at most the token max TTL after Since. Nodes take it within
// a feed refresh (signingKeysRefreshEvery).
func (s *Service) EndOldSandboxTokens(ctx context.Context) (cluster.ServerSigning, error) {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok || !c.IsLeader() {
		return cluster.ServerSigning{}, ErrServerSigningNotLeader
	}
	if _, have := c.ServerSigningRecord(); !have {
		return cluster.ServerSigning{}, ErrServerSigningOff
	}
	rec, err := c.WriteServerSigning(ctx, cluster.ServerSigningWrite{EndOldTokens: true}, false)
	if err == nil && s.logger != nil {
		s.logger.Warn("cluster: sandbox tokens signed before servers signed no longer count",
			"from", time.Unix(0, rec.OldTokensEndUnixNano).UTC())
	}
	return rec, err
}

// ServerSigningStatus is the record and the gate, for the operator.
func (s *Service) ServerSigningStatus() (cluster.ServerSigning, cluster.ServerSigningGate, bool, error) {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok {
		return cluster.ServerSigning{}, cluster.ServerSigningGate{}, false, ErrServerSigningNotLeader
	}
	rec, have := c.ServerSigningRecord()
	return rec, c.ServerSigningGate(false), have, nil
}

// StartServerSigningUpkeep runs UpkeepServerSigning, and the identity
// key upkeep that follows the record (identity_server_signing.go), while
// ctx lives, on a server; on a worker or gateway it reads the feed from
// boot and every signingKeysRefreshEvery, so the copy every token check
// and every SSH bridge reads is never older than that while a server
// answers. A no-op outside a cluster.
func (s *Service) StartServerSigningUpkeep(ctx context.Context) {
	if !s.ClusterEnabled() {
		return
	}
	if c, ok := s.Cluster().(signingFeedCluster); ok {
		m := s.signingMirror(c)
		go func() {
			t := time.NewTicker(signingKeysRefreshEvery)
			defer t.Stop()
			for {
				m.refresh()
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
		return
	}
	if _, ok := s.Cluster().(serverSigningCluster); !ok {
		return
	}
	go func() {
		t := time.NewTicker(serverSigningUpkeepEvery)
		defer t.Stop()
		for {
			if err := s.UpkeepServerSigning(ctx); err != nil && s.logger != nil {
				s.logger.Warn("cluster: server signing upkeep failed; will retry", "error", err)
			}
			if err := s.UpkeepServerIdentityKeys(ctx); err != nil && s.logger != nil {
				s.logger.Warn("identity: moving the signing keys to the servers failed; will retry", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// sandboxTokenKeys is the key source a token is checked with on this node:
// the ring's keys for ring key ids, and the servers' for server key ids. A
// server key id is looked up whatever the mode this node last read: a
// server signs as soon as the record exists, and a worker learns of it from
// the first token that names a server key it does not know.
func (s *Service) sandboxTokenKeys() sandboxtoken.KeySource {
	src := tokenKeySource{}
	if s.cipher != nil {
		src.ring = s.cipher
	}
	switch c := s.Cluster().(type) {
	case serverSigningCluster:
		src.server = func(kid uint32) (ed25519.PublicKey, bool) {
			k, err := s.openServerKeys()
			if err != nil || k == nil {
				return nil, false
			}
			return k.SandboxTokenVerifyKey(kid)
		}
	case signingFeedCluster:
		if s.ClusterEnabled() {
			m := s.signingMirror(c)
			src.server = func(kid uint32) (ed25519.PublicKey, bool) {
				pub := m.view(kid).key
				return pub, pub != nil
			}
		}
	}
	return src
}

// legacyTokenAllowed reports whether a token signed with a server key ring
// key (not a server key) still counts under mode at now: always before
// servers took over; after, only when issued before Since, and not once
// the operator ended such tokens (oldTokensEnd). A worker that cannot tell
// takes none.
func legacyTokenAllowed(mode signingMode, c sandboxtoken.Claims, now time.Time) bool {
	if c.KeyID&secrets.ServerKeyIDBit != 0 {
		return true
	}
	if !mode.known {
		return false
	}
	if !mode.on {
		return true
	}
	if mode.oldTokensEnd > 0 && !now.Before(time.Unix(0, mode.oldTokensEnd)) {
		return false
	}
	return time.Unix(c.IssuedAt, 0).Before(time.Unix(0, mode.since))
}

// tokenKeySource checks server-key ids with the server keys and the rest
// with the ring.
type tokenKeySource struct {
	ring   sandboxtoken.KeySource
	server func(kid uint32) (ed25519.PublicKey, bool)
}

func (k tokenKeySource) SandboxTokenVerifyKey(kid uint32) (ed25519.PublicKey, bool) {
	if kid&secrets.ServerKeyIDBit != 0 {
		if k.server == nil {
			return nil, false
		}
		return k.server(kid)
	}
	if k.ring == nil {
		return nil, false
	}
	return k.ring.SandboxTokenVerifyKey(kid)
}

// Feed mirror timing.
const (
	// signingKeysRefreshEvery is the ticker every worker and gateway reads
	// the feed on, from boot (StartServerSigningUpkeep).
	signingKeysRefreshEvery = 30 * time.Second
	// signingKeysStaleOff is how old a copy that says servers do not sign
	// may be and still be answered from: a record written after the copy
	// was read has a Since at least serverSigningLead after it, so for half
	// that the copy's answer is still right. Older, a check reads the feed
	// first; if no server answers, the node assumes servers may have taken
	// over at the earliest they could have (stale copy rule, view).
	signingKeysStaleOff = serverSigningLead / 2
	// signingKeysRetryWait is the least time between two reads a check
	// waits for: tokens with key ids no server made, or a server tier that
	// does not answer, cost one read a window, not one a request.
	signingKeysRetryWait    = 5 * time.Second
	signingKeysFetchTimeout = 3 * time.Second
)

// signingKeyMirror is a worker's or gateway's copy of the feed. One read is
// in flight at a time; a check that needs one waits for it.
type signingKeyMirror struct {
	mu           sync.Mutex
	fetch        func(context.Context) (cluster.SigningKeys, error)
	known        bool
	since        int64
	oldTokensEnd int64
	keys         map[uint32]ed25519.PublicKey
	fetchedAt    time.Time
	triedAt      time.Time
	// inflight is closed when the read in flight ends; nil with none.
	inflight chan struct{}
	now      func() time.Time
}

func (m *signingKeyMirror) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// applyLocked takes a read. A failed read keeps what the mirror had, and
// Since and the old-token end never go back: servers never stop signing
// once they start, and a server behind the others may still answer 0.
func (m *signingKeyMirror) applyLocked(got cluster.SigningKeys, err error) {
	if err != nil {
		return
	}
	if got.SinceUnixNano == 0 && m.since != 0 {
		return
	}
	keys := make(map[uint32]ed25519.PublicKey, len(got.TokenKeys))
	for kid, pub := range got.TokenKeys {
		if kid&secrets.ServerKeyIDBit != 0 && len(pub) == ed25519.PublicKeySize {
			keys[kid] = ed25519.PublicKey(bytes.Clone(pub))
		}
	}
	m.known, m.since, m.keys, m.fetchedAt = true, got.SinceUnixNano, keys, m.clock()
	m.oldTokensEnd = max(m.oldTokensEnd, got.OldTokensEndUnixNano)
}

// readLocked reads the feed, or waits for the read in flight, with mu held
// on entry and on return; mu is released while the read runs, so a slow
// server tier never holds the checks that need no read. A waiter waits at
// most the read's own timeout.
func (m *signingKeyMirror) readLocked() {
	if ch := m.inflight; ch != nil {
		m.mu.Unlock()
		select {
		case <-ch:
		case <-time.After(signingKeysFetchTimeout + time.Second):
		}
		m.mu.Lock()
		return
	}
	ch := make(chan struct{})
	m.inflight, m.triedAt = ch, m.clock()
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), signingKeysFetchTimeout)
	got, err := m.fetch(ctx)
	cancel()
	m.mu.Lock()
	m.applyLocked(got, err)
	m.inflight = nil
	close(ch)
}

// refresh reads the feed now (the ticker), or waits for the read in flight.
func (m *signingKeyMirror) refresh() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readLocked()
}

// mirrorView is one check's answer: the mode, and key wantKey's public half.
type mirrorView struct {
	mode signingMode
	key  ed25519.PublicKey
}

// view answers a check. One that cannot be answered from the copy (nothing
// known yet, key wantKey unknown, or a copy that says servers do not sign
// and is older than signingKeysStaleOff) waits for a read, at most once a
// signingKeysRetryWait unless one is in flight; any other old copy is read
// again in the background. A copy that says servers do not sign and stays
// too old (no server answered) answers that they may have, from the
// earliest time they could have: only tokens signed the old way before
// that still count, and nothing is signed the old way.
func (m *signingKeyMirror) view(wantKey uint32) mirrorView {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	stale := m.known && m.since == 0 && now.Sub(m.fetchedAt) >= signingKeysStaleOff
	need := !m.known || stale || (wantKey != 0 && m.keys[wantKey] == nil)
	switch {
	case need && (m.inflight != nil || m.triedAt.IsZero() || now.Sub(m.triedAt) >= signingKeysRetryWait):
		m.readLocked()
	case !need && m.inflight == nil && now.Sub(m.fetchedAt) >= signingKeysRefreshEvery:
		go m.refresh()
	}
	mode := signingMode{known: m.known, on: m.since > 0, since: m.since, oldTokensEnd: m.oldTokensEnd}
	if m.known && m.since == 0 && m.clock().Sub(m.fetchedAt) >= signingKeysStaleOff {
		mode.on, mode.since = true, m.fetchedAt.Add(signingKeysStaleOff).UnixNano()
	}
	return mirrorView{mode: mode, key: m.keys[wantKey]}
}
