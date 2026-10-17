package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// An issuer's signing keys (§5.5). Keys come only from the issuer's own
// discovery document or its jwks_file: the JWT headers jku, x5u and an
// embedded jwk are never consulted (CEO review finding 3.5). They are
// fetched at daemon start, refreshed hourly, and refetched on an unknown key
// id at most once a minute per issuer. A JWKS fetch is never per request: a
// spray of tokens with made-up key ids costs the provider one request a
// minute per node.

// MaxDocumentBytes caps a discovery or JWKS document (finding 5.5): a
// misbehaving provider cannot make a node buffer an unbounded body.
const MaxDocumentBytes = 1 << 20

// supportedAlgs is every algorithm a token may be signed with. An issuer's
// allowed set is this intersected with what its discovery advertises, so
// alg:none and the HMAC algorithms never verify, whatever a header says.
var supportedAlgs = map[string]bool{"RS256": true, "ES256": true, "EdDSA": true}

var joseAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}

// minRSABits refuses weak RSA keys a provider (or an attacker controlling a
// jwks_file) might publish.
const minRSABits = 2048

var (
	// errKeysRateLimited: a fetch ran less than a refetch gap ago.
	errKeysRateLimited = errors.New("identity: JWKS refetch rate-limited")
	// errKeyWaitTimeout: the fetch did not finish within the request's wait.
	errKeyWaitTimeout = errors.New("identity: JWKS fetch did not finish in time")
	// errBadSignature: no key the issuer publishes verifies the token.
	errBadSignature = errors.New("identity: token signature does not verify")
	// errDocumentTooLarge: a discovery or JWKS body over MaxDocumentBytes.
	errDocumentTooLarge = fmt.Errorf("identity: provider document larger than %d bytes", MaxDocumentBytes)
)

// keySnapshot is one fetched key set. It is immutable once stored.
type keySnapshot struct {
	keys    []jose.JSONWebKey
	algs    map[string]bool
	fetched time.Time
}

// fetchCall is one in-flight fetch; waiters block on done.
type fetchCall struct {
	done chan struct{}
	err  error
}

// keySet holds one issuer's keys. The hot path is ready.Load() plus
// snap.Load(): two atomic loads. The slow path is the lazy-bootstrap pattern
// (CLAUDE.md rule 3, Service.EnsureLayer4Ready): the latch stays unset until
// a fetch succeeds, and mu single-flights fetches so a thundering herd of
// first requests, or of unknown-kid requests, starts exactly one. mu guards
// only the in-flight call, never the network round trip, so a request can
// stop waiting after keyWait while the fetch finishes for the next one.
type keySet struct {
	issuer   string // issuer name: the metric label
	url      string
	jwksFile string
	client   *http.Client
	now      func() time.Time
	minGap   time.Duration
	timeout  time.Duration
	log      *slog.Logger

	ready atomic.Bool
	snap  atomic.Pointer[keySnapshot]
	// gen changes when a key id the issuer used to publish disappears, so
	// a cached token verified with a withdrawn key is checked again.
	gen atomic.Uint64

	mu          sync.Mutex
	lastAttempt time.Time
	inflight    *fetchCall

	// jwksURL is the discovered JWKS endpoint, reused until a fetch fails.
	// Only the single in-flight fetch touches it.
	jwksURL string
	advAlgs []string
}

func newKeySet(iss *Issuer, opts *VerifierOptions) *keySet {
	return &keySet{
		issuer:   iss.Name,
		url:      iss.URL,
		jwksFile: iss.JWKSFile,
		client:   opts.HTTPClient,
		now:      opts.Now,
		minGap:   opts.RefetchGap,
		timeout:  opts.FetchTimeout,
		log:      opts.Logger,
	}
}

// keySetID keys the registry that keeps fetched keys across identity-file
// reloads: an issuer whose source is unchanged keeps its keys.
func keySetID(iss *Issuer) string {
	return iss.Name + "\x00" + iss.URL + "\x00" + iss.JWKSFile
}

// refresh starts a fetch unless one ran within minGap (errKeysRateLimited)
// and waits up to wait for it; a fetch already in flight is joined, not
// repeated. With wait 0 it only starts the fetch.
func (k *keySet) refresh(ctx context.Context, wait time.Duration) error {
	k.mu.Lock()
	call := k.inflight
	if call == nil {
		now := k.now()
		if !k.lastAttempt.IsZero() && now.Sub(k.lastAttempt) < k.minGap {
			k.mu.Unlock()
			return errKeysRateLimited
		}
		k.lastAttempt = now
		call = &fetchCall{done: make(chan struct{})}
		k.inflight = call
		go k.run(call)
	}
	k.mu.Unlock()
	if wait <= 0 {
		return errKeyWaitTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-call.done:
		return call.err
	case <-timer.C:
		return errKeyWaitTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (k *keySet) run(call *fetchCall) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	call.err = k.fetch(ctx)
	k.mu.Lock()
	k.inflight = nil
	k.mu.Unlock()
	close(call.done)
}

// fetch loads the key set from the issuer's jwks_file or discovery, and
// publishes it only when it holds at least one usable key.
func (k *keySet) fetch(ctx context.Context) error {
	var (
		keys     []jose.JSONWebKey
		algs     = map[string]bool{}
		tooLarge bool
		err      error
	)
	if k.jwksFile != "" {
		keys, tooLarge, err = k.readFile()
		for alg := range supportedAlgs {
			algs[alg] = true
		}
	} else {
		keys, algs, tooLarge, err = k.fetchRemote(ctx)
	}
	if err == nil && len(keys) == 0 {
		err = errors.New("the key set holds no usable RS256, ES256 or EdDSA signing key")
	}
	if err == nil && len(algs) == 0 {
		err = errors.New("the issuer advertises none of RS256, ES256 and EdDSA")
	}
	now := k.now()
	if err != nil {
		result := fetchError
		if tooLarge {
			result = fetchTooLarge
		}
		observeJWKSFetch(k.issuer, result, now)
		k.jwksURL = ""
		k.log.Warn("identity: fetching an issuer's signing keys failed; tokens it signs get 503 until a fetch succeeds",
			"issuer", k.issuer, "error", clip(err.Error()))
		return err
	}
	if prev := k.snap.Load(); prev != nil && withdrewKey(prev.keys, keys) {
		k.gen.Add(1)
	}
	k.snap.Store(&keySnapshot{keys: keys, algs: algs, fetched: now})
	k.ready.Store(true)
	observeJWKSFetch(k.issuer, fetchOK, now)
	return nil
}

// fetchRemote runs OIDC discovery (go-oidc checks the discovered issuer is
// exactly ours), then reads the JWKS it names.
func (k *keySet) fetchRemote(ctx context.Context) (keys []jose.JSONWebKey, algs map[string]bool, tooLarge bool, err error) {
	if k.jwksURL == "" {
		var over atomic.Bool
		provider, derr := oidc.NewProvider(oidc.ClientContext(ctx, cappedClient(k.client, oversizeDiscovery, &over)), k.url)
		if derr != nil {
			return nil, nil, over.Load(), fmt.Errorf("discovery: %w", derr)
		}
		var meta struct {
			JWKSURI string   `json:"jwks_uri"`
			Algs    []string `json:"id_token_signing_alg_values_supported"`
		}
		if derr := provider.Claims(&meta); derr != nil {
			return nil, nil, false, fmt.Errorf("discovery: %w", derr)
		}
		u, perr := url.Parse(meta.JWKSURI)
		if perr != nil || u.Scheme != "https" || u.Host == "" {
			return nil, nil, false, fmt.Errorf("discovery: jwks_uri %q is not an https URL", meta.JWKSURI)
		}
		k.jwksURL, k.advAlgs = meta.JWKSURI, meta.Algs
		if len(k.advAlgs) == 0 {
			// The field is required by OIDC discovery; RS256 is the one
			// algorithm every provider must support.
			k.advAlgs = []string{"RS256"}
		}
	}
	algs = map[string]bool{}
	for _, a := range k.advAlgs {
		if supportedAlgs[a] {
			algs[a] = true
		}
	}
	var over atomic.Bool
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.jwksURL, nil)
	if err != nil {
		return nil, nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cappedClient(k.client, oversizeJWKS, &over).Do(req)
	if err != nil {
		return nil, nil, over.Load(), fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, over.Load(), fmt.Errorf("jwks: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, false, fmt.Errorf("jwks: %s", resp.Status)
	}
	keys, err = parseJWKS(body)
	return keys, algs, false, err
}

func (k *keySet) readFile() ([]jose.JSONWebKey, bool, error) {
	f, err := os.Open(k.jwksFile)
	if err != nil {
		return nil, false, fmt.Errorf("jwks_file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxDocumentBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("jwks_file: %w", err)
	}
	if len(raw) > MaxDocumentBytes {
		observeOversize(oversizeJWKS)
		return nil, true, errDocumentTooLarge
	}
	keys, err := parseJWKS(raw)
	return keys, false, err
}

// parseJWKS keeps the usable public signing keys and skips the rest, as
// RFC 7517 §5 asks: encryption keys, unsupported algorithms or key types,
// RSA keys under 2048 bits, curves other than P-256, and private keys (a
// key set that publishes one is broken, and its private half is not ours
// to hold).
func parseJWKS(raw []byte) ([]jose.JSONWebKey, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	var keys []jose.JSONWebKey
	for _, item := range doc.Keys {
		var meta struct {
			Alg string `json:"alg"`
			Use string `json:"use"`
		}
		if json.Unmarshal(item, &meta) != nil {
			continue
		}
		if (meta.Use != "" && meta.Use != "sig") || (meta.Alg != "" && !supportedAlgs[meta.Alg]) {
			continue
		}
		var jwk jose.JSONWebKey
		if json.Unmarshal(item, &jwk) != nil {
			continue
		}
		switch pub := jwk.Key.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < minRSABits {
				continue
			}
		case *ecdsa.PublicKey:
			if pub.Curve != elliptic.P256() {
				continue
			}
		case ed25519.PublicKey:
		default:
			continue
		}
		keys = append(keys, jwk)
	}
	return keys, nil
}

// withdrewKey reports whether a key id in prev is missing from next.
func withdrewKey(prev, next []jose.JSONWebKey) bool {
	ids := make(map[string]struct{}, len(next))
	for _, k := range next {
		ids[k.KeyID] = struct{}{}
	}
	for _, k := range prev {
		if _, ok := ids[k.KeyID]; !ok {
			return true
		}
	}
	return false
}

// verifyOutcome is how VerifySignature tells the verifier, through go-oidc
// (which flattens errors to strings), that keys were unavailable rather than
// the signature wrong, and that the signature did verify.
type verifyOutcome struct {
	unavailable bool
	signatureOK bool
}

type outcomeKey struct{}

// VerifySignature implements oidc.KeySet. go-oidc has already parsed the
// token with the issuer's algorithms; this parses it again (a few µs, cold
// path only) because go-oidc keeps its parsed copy private. An unknown key
// id triggers one rate-limited refetch, waited for up to wait.
func (k *keySet) verifySignature(ctx context.Context, raw string, wait time.Duration) ([]byte, error) {
	outcome, _ := ctx.Value(outcomeKey{}).(*verifyOutcome)
	jws, err := jose.ParseSigned(raw, joseAlgs)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errBadSignature
	}
	sig := jws.Signatures[0].Header
	if snap := k.snap.Load(); snap != nil {
		payload, known := snap.verify(jws, sig.KeyID, sig.Algorithm)
		if payload != nil {
			markVerified(outcome)
			return payload, nil
		}
		if known {
			// The issuer publishes this key: the signature is simply wrong,
			// and refetching would not change that.
			return nil, errBadSignature
		}
	}
	if err := k.refresh(ctx, wait); err != nil {
		if errors.Is(err, errKeysRateLimited) && k.ready.Load() {
			// Refetched within the last minute and still unknown.
			return nil, errBadSignature
		}
		if outcome != nil {
			outcome.unavailable = true
		}
		return nil, err
	}
	if payload, _ := k.snap.Load().verify(jws, sig.KeyID, sig.Algorithm); payload != nil {
		markVerified(outcome)
		return payload, nil
	}
	return nil, errBadSignature
}

func markVerified(o *verifyOutcome) {
	if o != nil {
		o.signatureOK = true
	}
}

// verify tries the snapshot's keys for kid (every key when the token names
// none). known reports whether the snapshot has a key with that id.
func (s *keySnapshot) verify(jws *jose.JSONWebSignature, kid, alg string) (payload []byte, known bool) {
	if s == nil {
		return nil, false
	}
	if !s.algs[alg] {
		// An algorithm the issuer does not sign with is refused outright;
		// no refetch would make it acceptable.
		return nil, true
	}
	for i := range s.keys {
		key := &s.keys[i]
		if kid != "" && key.KeyID != kid {
			continue
		}
		if kid != "" {
			known = true
		}
		if key.Algorithm != "" && key.Algorithm != alg {
			continue
		}
		if out, err := jws.Verify(key); err == nil {
			return out, true
		}
	}
	return nil, known
}

// keySetAdapter binds a keySet to the wait a request may spend on a
// refetch, as go-oidc's KeySet interface takes no options.
type keySetAdapter struct {
	keys *keySet
	wait time.Duration
}

func (a keySetAdapter) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	return a.keys.verifySignature(ctx, raw, a.wait)
}

// cappedClient is client with every response body capped at
// MaxDocumentBytes; reading past the cap fails, counts the oversize metric
// once, and sets over.
func cappedClient(client *http.Client, input string, over *atomic.Bool) *http.Client {
	c := *client
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = cappedTransport{base: base, input: input, over: over}
	return &c
}

type cappedTransport struct {
	base  http.RoundTripper
	input string
	over  *atomic.Bool
}

func (t cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > MaxDocumentBytes {
		resp.Body.Close()
		t.tripped()
		return nil, errDocumentTooLarge
	}
	resp.Body = &cappedBody{rc: resp.Body, left: MaxDocumentBytes, t: t}
	return resp, nil
}

func (t cappedTransport) tripped() {
	if t.over.CompareAndSwap(false, true) {
		observeOversize(t.input)
	}
}

type cappedBody struct {
	rc   io.ReadCloser
	left int64
	t    cappedTransport
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errDocumentTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		b.t.tripped()
		return n, errDocumentTooLarge
	}
	return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }

// clip bounds an error string before it reaches a log: provider error
// bodies are echoed into go-oidc's errors.
func clip(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
