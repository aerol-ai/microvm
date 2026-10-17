// Package identity is sandboxd's own named-credential machinery
// (plans/identity-and-access.md): the identity file and its bindings, and
// the OIDC verifier that checks an identity provider's signed token offline.
//
// sandboxd is a resource server, the same model as the Kubernetes API server
// with --oidc-issuer-url (§5.0, L1–L8): the company's identity provider logs
// the person in, and every node verifies the provider's token itself from
// the provider's published keys. There is no login service, no session and
// no per-request call out: the only network traffic is the JWKS fetch at
// start, hourly, and at most once a minute per issuer on an unknown key id.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// MaxJWTBytes caps a bearer the verifier will parse (finding 5.5): ID tokens
// and workload tokens are 1–2 KB, even with a long groups claim.
const MaxJWTBytes = 16 << 10

// clockLeeway is the skew allowed on exp, nbf and iat (§4: 60 s). Nodes run
// NTP already, because Raft needs it.
const clockLeeway = 60 * time.Second

// Defaults for VerifierOptions.
const (
	DefaultRefetchGap      = time.Minute
	DefaultRefreshInterval = time.Hour
	DefaultKeyWait         = 2 * time.Second
	DefaultFetchTimeout    = 10 * time.Second
	maxSubjectBytes        = 255
)

// VerifierOptions tunes a Verifier. The zero value is production: the
// system trust store, the CLAUDE.md lazy-bootstrap timings and the §5.5
// cache bounds. Tests inject an *http.Client that trusts their httptest
// issuer and a clock; there is no insecure-issuer switch (finding 5.4).
type VerifierOptions struct {
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
	// RefetchGap is the least time between two JWKS fetches for one
	// issuer, whatever triggers them (an unknown kid, a failed boot).
	RefetchGap time.Duration
	// RefreshInterval re-fetches a healthy issuer's keys.
	RefreshInterval time.Duration
	// KeyWait is how long a request waits for a fetch it triggered.
	KeyWait time.Duration
	// FetchTimeout bounds one discovery + JWKS round trip.
	FetchTimeout time.Duration
	CacheEntries int
	CacheBytes   int
}

func (o VerifierOptions) withDefaults() VerifierOptions {
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: DefaultFetchTimeout}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RefetchGap <= 0 {
		o.RefetchGap = DefaultRefetchGap
	}
	if o.RefreshInterval <= 0 {
		o.RefreshInterval = DefaultRefreshInterval
	}
	if o.KeyWait <= 0 {
		o.KeyWait = DefaultKeyWait
	}
	if o.FetchTimeout <= 0 {
		o.FetchTimeout = DefaultFetchTimeout
	}
	if o.CacheEntries <= 0 {
		o.CacheEntries = DefaultCacheEntries
	}
	if o.CacheBytes <= 0 {
		o.CacheBytes = DefaultCacheBytes
	}
	return o
}

// Verifier checks identity-provider JWTs against the identity file in force.
// It implements the API edge's authenticator interface (pkg/api), so the
// daemon appends it to the chain with WithCredentialAuthenticator.
type Verifier struct {
	source func() *Config
	opts   VerifierOptions

	state atomic.Pointer[verifierState]
	// mu serialises rebuilds; keySets keeps each issuer's fetched keys
	// across identity-file reloads (guarded by mu).
	mu      sync.Mutex
	keySets map[string]*keySet
}

// verifierState is the verifier compiled for one identity file: its
// issuers' key sets and a cache that holds that file's binding matches.
type verifierState struct {
	cfg     *Config
	issuers map[*Issuer]*issuerVerifier
	cache   *tokenCache
}

type issuerVerifier struct {
	iss  *Issuer
	keys *keySet
	oidc *oidc.IDTokenVerifier
}

// NewVerifier verifies against whatever source returns at each request:
// the identity-file watcher's last good file, or nil while none has loaded
// (every JWT then gets 503).
func NewVerifier(source func() *Config, opts VerifierOptions) *Verifier {
	return &Verifier{source: source, opts: opts.withDefaults(), keySets: map[string]*keySet{}}
}

// current returns the state for the file in force, compiling it on the
// first request after a reload.
func (v *Verifier) current() (*verifierState, error) {
	cfg := v.source()
	if cfg == nil {
		return nil, controlplane.ErrIdentityUnavailable
	}
	if st := v.state.Load(); st != nil && st.cfg == cfg {
		return st, nil
	}
	return v.rebuild(cfg), nil
}

func (v *Verifier) rebuild(cfg *Config) *verifierState {
	v.mu.Lock()
	defer v.mu.Unlock()
	if st := v.state.Load(); st != nil && st.cfg == cfg {
		return st
	}
	st := &verifierState{
		cfg:     cfg,
		issuers: make(map[*Issuer]*issuerVerifier, len(cfg.Issuers)),
		cache:   newTokenCache(v.opts.CacheEntries, v.opts.CacheBytes),
	}
	keep := make(map[string]*keySet, len(cfg.Issuers))
	for _, iss := range cfg.Issuers {
		id := keySetID(iss)
		ks := v.keySets[id]
		if ks == nil {
			ks = newKeySet(iss, &v.opts)
			// Start fetching now, not on the first token: a new issuer in a
			// reloaded file is ready before anyone signs in with it.
			_ = ks.refresh(context.Background(), 0)
		}
		keep[id] = ks
		st.issuers[iss] = &issuerVerifier{
			iss:  iss,
			keys: ks,
			// go-oidc parses the token with the allowed algorithms, checks
			// the signature through our key set and the issuer exactly. The
			// audience and time checks need the identity file's list of
			// audiences and §4's 60 s leeway, which go-oidc's single client
			// id and fixed nbf leeway cannot express, so they run below.
			oidc: oidc.NewVerifier(iss.URL, keySetAdapter{keys: ks, wait: v.opts.KeyWait}, &oidc.Config{
				SupportedSigningAlgs: []string{"RS256", "ES256", "EdDSA"},
				SkipClientIDCheck:    true,
				SkipExpiryCheck:      true,
			}),
		}
	}
	v.keySets = keep
	v.state.Store(st)
	return st
}

// Bootstrap fetches every issuer's keys, waiting up to the fetch timeout.
// The daemon calls it at start in the background; a provider that is down
// leaves its tokens at 503 until a later fetch succeeds, and the PAT and
// avm_ tokens are unaffected.
func (v *Verifier) Bootstrap(ctx context.Context) {
	st, err := v.current()
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	for _, iv := range st.issuers {
		if iv.keys.ready.Load() {
			continue
		}
		wg.Add(1)
		go func(ks *keySet) {
			defer wg.Done()
			if err := ks.refresh(ctx, v.opts.FetchTimeout+time.Second); err != nil && !errors.Is(err, errKeysRateLimited) {
				v.opts.Logger.Warn("identity: issuer keys unavailable at start", "issuer", ks.issuer, "error", clip(err.Error()))
			}
		}(iv.keys)
	}
	wg.Wait()
}

// Run keeps keys fresh until ctx ends: every tick it retries an issuer that
// has none yet and refreshes one whose keys are older than the refresh
// interval. Both go through the refetch gap.
func (v *Verifier) Run(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = v.opts.RefetchGap
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v.maintainKeys(ctx)
		}
	}
}

func (v *Verifier) maintainKeys(ctx context.Context) {
	st, err := v.current()
	if err != nil {
		return
	}
	now := v.opts.Now()
	for _, iv := range st.issuers {
		snap := iv.keys.snap.Load()
		if snap == nil || now.Sub(snap.fetched) >= v.opts.RefreshInterval {
			_ = iv.keys.refresh(ctx, 0)
		}
	}
}

// Authenticate implements the API edge's Authenticator. A bearer that is
// not shaped like a JWT is not this authenticator's (matched=false). A JWT
// is always decided here: an Access, a *controlplane.CredentialError with a
// D17 reason, a *controlplane.NoBindingError (403), or
// controlplane.ErrIdentityUnavailable (503).
func (v *Verifier) Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error) {
	if !looksLikeJWT(bearer) {
		return controlplane.Access{}, false, nil
	}
	if len(bearer) > MaxJWTBytes {
		observeOversize(oversizeJWT)
		return controlplane.Access{}, true, reject(controlplane.RejectMalformed)
	}
	st, err := v.current()
	if err != nil {
		return controlplane.Access{}, true, err
	}
	key := sha256.Sum256([]byte(bearer))
	tok, hit := st.cache.get(key)
	if hit && tok.stale() {
		st.cache.remove(key)
		hit = false
	}
	now := v.opts.Now()
	if !hit {
		ctx := context.Background()
		if r != nil {
			ctx = r.Context()
		}
		tok, err = v.verify(ctx, st, bearer, now)
		if err != nil {
			return controlplane.Access{}, true, err
		}
		st.cache.put(key, tok)
	}
	if now.After(tok.expires.Add(clockLeeway)) {
		st.cache.remove(key)
		return controlplane.Access{}, true, reject(controlplane.RejectExpired)
	}
	if len(tok.bindings) == 0 {
		return controlplane.Access{}, true, &controlplane.NoBindingError{
			Issuer: tok.issuer, Name: tok.principal.Name, Groups: tok.groups, Overage: tok.overage,
		}
	}
	return controlplane.OIDCAccess(tok.principal, tok.bindings, tok.expires), true, nil
}

// jwtHeader is the part of the JOSE header read before any key is touched.
// jku, x5u and jwk are deliberately absent: keys come only from the
// issuer's discovery or jwks_file.
type jwtHeader struct {
	Alg string `json:"alg"`
}

// verify is the cold path: header, claims, issuer, signature, then the
// claim checks, the deny list and the bindings, in that order, so a bad
// signature is reported as one whatever the claims say.
func (v *Verifier) verify(ctx context.Context, st *verifierState, raw string, now time.Time) (*verifiedToken, error) {
	header, claims, ok := decodeUnverified(raw)
	if !ok {
		return nil, reject(controlplane.RejectMalformed)
	}
	if !supportedAlgs[header.Alg] {
		// alg:none, HS256 and anything else outside RS256/ES256/EdDSA.
		return nil, reject(controlplane.RejectInvalidSignature)
	}
	if claims == nil {
		return nil, reject(controlplane.RejectMalformed)
	}
	iss, ok := st.cfg.issuerForIss(claims.iss)
	if !ok {
		return nil, reject(controlplane.RejectUnknownIssuer)
	}
	iv := st.issuers[iss]
	if !iv.keys.ready.Load() {
		if err := iv.keys.refresh(ctx, v.opts.KeyWait); err != nil && !iv.keys.ready.Load() {
			return nil, controlplane.ErrIdentityUnavailable
		}
	}
	if snap := iv.keys.snap.Load(); snap == nil || !snap.algs[header.Alg] {
		return nil, reject(controlplane.RejectInvalidSignature)
	}
	gen := iv.keys.gen.Load()
	outcome := &verifyOutcome{}
	if _, err := iv.oidc.Verify(context.WithValue(ctx, outcomeKey{}, outcome), raw); err != nil {
		switch {
		case outcome.unavailable:
			return nil, controlplane.ErrIdentityUnavailable
		case outcome.signatureOK:
			// Signed, but go-oidc refused the payload (a broken
			// _claim_names, say).
			return nil, reject(controlplane.RejectMalformed)
		}
		return nil, reject(controlplane.RejectInvalidSignature)
	}
	if !iss.acceptsAudience(claims.aud) {
		return nil, reject(controlplane.RejectWrongAudience)
	}
	if now.After(claims.exp.Add(clockLeeway)) {
		return nil, reject(controlplane.RejectExpired)
	}
	if (!claims.nbf.IsZero() && claims.nbf.After(now.Add(clockLeeway))) ||
		(!claims.iat.IsZero() && claims.iat.After(now.Add(clockLeeway))) {
		return nil, reject(controlplane.RejectNotYetValid)
	}
	start := claims.iat
	if start.IsZero() {
		start = now
	}
	if claims.exp.Sub(start) > iss.MaxTokenLifetime {
		return nil, reject(controlplane.RejectTooLongLived)
	}
	if !validSubject(claims.sub) {
		return nil, reject(controlplane.RejectMalformed)
	}
	if st.cfg.Denied(iss.Name, claims.sub) {
		// The emergency block (deny_subjects): refused like a revoked
		// credential, on every request after the reload that added it.
		return nil, reject(controlplane.RejectUnknownOrRevoked)
	}
	m := iss.match(claims)
	tok := &verifiedToken{
		principal: controlplane.Principal{
			Kind: controlplane.PrincipalOIDC,
			// sub is stable and the email is only the display name, so an
			// email rename never splits a person's audit history.
			ID:   string(controlplane.PrincipalOIDC) + ":" + iss.Name + ":" + claims.sub,
			Name: displayNameClaim(claims, iss),
		},
		bindings: m.bindings,
		issuer:   iss.Name,
		overage:  m.overage,
		expires:  claims.exp,
		keys:     iv.keys,
		gen:      gen,
	}
	if len(m.bindings) == 0 {
		tok.groups = sanitizeGroups(m.groups)
	}
	return tok, nil
}

func (iss *Issuer) acceptsAudience(aud []string) bool {
	for _, a := range aud {
		if _, ok := iss.audiences[a]; ok {
			return true
		}
	}
	return false
}

// decodeUnverified reads the header and claims before the signature is
// checked, only to pick the issuer and refuse bad algorithms early. The
// payload bytes are the ones the signature covers, so once go-oidc has
// verified it these claims are the verified claims. ok=false is a malformed
// token; a nil claims with ok=true is a header that parsed and a payload
// that did not.
func decodeUnverified(raw string) (jwtHeader, *tokenClaims, bool) {
	var h jwtHeader
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return h, nil, false
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return h, nil, false
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return h, nil, true
	}
	claims, err := parseClaims(pb)
	if err != nil {
		return h, nil, true
	}
	return h, claims, true
}

// looksLikeJWT reports a compact JWS shape: three base64url segments, the
// first two non-empty (an alg:none token has an empty third, and is claimed
// here so it is refused, not handed to another authenticator).
func looksLikeJWT(s string) bool {
	if strings.Count(s, ".") != 2 {
		return false
	}
	first := strings.IndexByte(s, '.')
	second := first + 1 + strings.IndexByte(s[first+1:], '.')
	if first == 0 || second == first+1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// validSubject: RFC 7519 sub is a short case-sensitive string; one with
// control characters or over 255 bytes is not a provider's.
func validSubject(sub string) bool {
	if sub == "" || len(sub) > maxSubjectBytes {
		return false
	}
	for _, r := range sub {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// displayNameClaim is the username claim when it is a string, else sub,
// truncated and stripped of control characters (finding 3.6).
func displayNameClaim(c *tokenClaims, iss *Issuer) string {
	if name, ok := stringClaim(c.raw[iss.UsernameClaim]); ok {
		if clean := controlplane.SanitizeDisplayName(name); clean != "" {
			return clean
		}
	}
	return controlplane.SanitizeDisplayName(c.sub)
}

func sanitizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if clean := controlplane.SanitizeDisplayName(g); clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func reject(reason controlplane.RejectReason) error {
	return &controlplane.CredentialError{Kind: controlplane.PrincipalOIDC, Reason: reason}
}
