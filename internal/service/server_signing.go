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
	ServerSigningAllowed() bool
	WriteServerSigning(context.Context, cluster.ServerSigningWrite) (cluster.ServerSigning, error)
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
// one (on), and its Since. known is false only on a worker or gateway that
// could not read the feed.
type signingMode struct {
	known bool
	on    bool
	since int64
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
		return signingMode{known: true, on: ok, since: rec.SinceUnixNano}
	case signingFeedCluster:
		known, since, _ := s.signingMirror(c).state(0)
		return signingMode{known: known, on: since > 0, since: since}
	}
	return signingMode{known: true}
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
	for kid := range k.tokens {
		if pub, ok := k.SandboxTokenVerifyKey(kid); ok {
			out.TokenKeys[kid] = []byte(pub)
		}
	}
	return out, nil
}

// UpkeepServerSigning is one pass of the leader's upkeep: write the record
// once every member verifies what servers sign, and reseal it under the
// ring's current key after a rotation. Every other node returns at once.
func (s *Service) UpkeepServerSigning(ctx context.Context) error {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok || !c.IsLeader() || s.cipher == nil {
		return nil
	}
	rec, have := c.ServerSigningRecord()
	if !have {
		if !c.ServerSigningAllowed() {
			return nil
		}
		seed := make([]byte, secrets.ServerSeedSize)
		r := s.serverSigning.rand
		if r == nil {
			r = rand.Reader
		}
		if _, err := io.ReadFull(r, seed); err != nil {
			return err
		}
		sealed, err := s.cipher.EncryptWithAAD(seed, serverSigningAAD)
		clear(seed)
		if err != nil {
			return err
		}
		written, err := c.WriteServerSigning(ctx, cluster.ServerSigningWrite{Signing: cluster.ServerSigning{
			Sealed: sealed, SinceUnixNano: s.signingNow().Add(serverSigningLead).UnixNano(),
		}})
		if err == nil && s.logger != nil {
			s.logger.Info("cluster: servers now sign sandbox tokens and cloud-identity tokens",
				"tokens_signed_before_only_until", time.Unix(0, written.SinceUnixNano).UTC())
		}
		return err
	}
	resealed, _, changed, err := s.cipher.Reseal(rec.Sealed, serverSigningAAD)
	if err != nil || !changed {
		return err
	}
	_, err = c.WriteServerSigning(ctx, cluster.ServerSigningWrite{
		Signing: cluster.ServerSigning{Sealed: resealed, SinceUnixNano: rec.SinceUnixNano},
		Expect:  rec.Sealed,
	})
	return err
}

// StartServerSigningUpkeep runs UpkeepServerSigning, and the identity
// key upkeep that follows the record (identity_server_signing.go), while
// ctx lives. It is a no-op off a server.
func (s *Service) StartServerSigningUpkeep(ctx context.Context) {
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
				_, _, pub := m.state(kid)
				return pub, pub != nil
			}
		}
	}
	return src
}

// legacyTokenAllowed reports whether a token signed with a server key ring
// key (not a server key) still counts under mode: always before servers
// took over, and after only when issued before Since. A worker that cannot
// tell takes none.
func legacyTokenAllowed(mode signingMode, c sandboxtoken.Claims) bool {
	if c.KeyID&secrets.ServerKeyIDBit != 0 {
		return true
	}
	if !mode.known {
		return false
	}
	if !mode.on {
		return true
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
	signingKeysRefreshEvery = time.Minute
	// signingKeysRetryWait is the least time between two reads that a
	// request waits for (the first, or one for an unknown key id): tokens
	// with key ids no server made, or a server tier that does not answer,
	// cost one read a window, not one a request.
	signingKeysRetryWait    = 5 * time.Second
	signingKeysFetchTimeout = 3 * time.Second
)

// signingKeyMirror is a worker's or gateway's copy of the feed.
type signingKeyMirror struct {
	mu         sync.Mutex
	fetch      func(context.Context) (cluster.SigningKeys, error)
	known      bool
	since      int64
	keys       map[uint32]ed25519.PublicKey
	fetchedAt  time.Time
	triedAt    time.Time
	refreshing bool
	now        func() time.Time
}

func (m *signingKeyMirror) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// read fetches the feed. Not under mu: a slow server tier must not hold
// every token check on this node.
func (m *signingKeyMirror) read() (cluster.SigningKeys, error) {
	ctx, cancel := context.WithTimeout(context.Background(), signingKeysFetchTimeout)
	defer cancel()
	return m.fetch(ctx)
}

// applyLocked takes a read. A failed read keeps what the mirror had, and
// Since never goes back: servers never stop signing once they start, and a
// server behind the others may still answer 0.
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
}

// state returns what the mirror knows. A caller that cannot be answered
// without a read (nothing known yet, or key wantKey unknown) waits for one,
// at most once a signingKeysRetryWait; an old copy is refreshed in the
// background.
func (m *signingKeyMirror) state(wantKey uint32) (known bool, since int64, pub ed25519.PublicKey) {
	m.mu.Lock()
	now := m.clock()
	needNow := !m.known || (wantKey != 0 && m.keys[wantKey] == nil)
	if needNow && now.Sub(m.triedAt) >= signingKeysRetryWait {
		m.triedAt = now
		m.mu.Unlock()
		got, err := m.read()
		m.mu.Lock()
		m.applyLocked(got, err)
	} else if m.known && !m.refreshing && now.Sub(m.fetchedAt) >= signingKeysRefreshEvery {
		m.refreshing = true
		go func() {
			got, err := m.read()
			m.mu.Lock()
			defer m.mu.Unlock()
			m.refreshing = false
			m.applyLocked(got, err)
		}()
	}
	defer m.mu.Unlock()
	return m.known, m.since, m.keys[wantKey]
}
