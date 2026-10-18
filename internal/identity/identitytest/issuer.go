// Package identitytest is an in-process OIDC identity provider for tests:
// an httptest TLS server publishing a discovery document and a JWKS, and a
// minting helper. Tests reach it with Client(), an *http.Client that trusts
// only its certificate, so no test ever touches the real network or needs
// an insecure-issuer switch (plans/identity-and-access.md finding 5.4).
package identitytest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Key is one signing key the issuer holds.
type Key struct {
	ID      string
	Alg     jose.SignatureAlgorithm
	Private crypto.Signer
}

// Public is the key's JWK as the issuer publishes it.
func (k Key) Public() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.Private.Public(), KeyID: k.ID, Algorithm: string(k.Alg), Use: "sig"}
}

// Issuer is a test identity provider.
type Issuer struct {
	Server *httptest.Server
	// URL is the issuer URL, the iss its tokens carry.
	URL string

	// DiscoveryHits and JWKSHits count requests, so a test can assert
	// "exactly one refetch".
	DiscoveryHits atomic.Int32
	JWKSHits      atomic.Int32
	// FailJWKS makes the JWKS endpoint answer 503; FailDiscovery the
	// discovery document.
	FailJWKS      atomic.Bool
	FailDiscovery atomic.Bool

	mu        sync.Mutex
	signing   Key
	published []Key
	algs      []string
	// jwksOverride and discoveryOverride replace a document's body.
	jwksOverride      []byte
	discoveryOverride []byte
	issuerOverride    string
	nextID            int
}

// New starts an issuer with one RS256 key that advertises RS256, ES256 and
// EdDSA.
func New(t testing.TB) *Issuer {
	t.Helper()
	iss := &Issuer{algs: []string{"RS256", "ES256", "EdDSA"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", iss.serveDiscovery)
	mux.HandleFunc("GET /jwks", iss.serveJWKS)
	iss.Server = httptest.NewTLSServer(mux)
	t.Cleanup(iss.Server.Close)
	iss.URL = iss.Server.URL
	key := iss.NewKey(t, jose.RS256)
	iss.signing = key
	iss.published = []Key{key}
	return iss
}

// Client trusts the issuer's certificate and nothing else.
func (i *Issuer) Client() *http.Client { return i.Server.Client() }

// NewKey makes a key for alg with a fresh key id. It is not published.
func (i *Issuer) NewKey(t testing.TB, alg jose.SignatureAlgorithm) Key {
	t.Helper()
	i.mu.Lock()
	i.nextID++
	id := "k" + strconv.Itoa(i.nextID)
	i.mu.Unlock()
	var (
		priv crypto.Signer
		err  error
	)
	switch alg {
	case jose.RS256:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case jose.ES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.EdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("identitytest: no key type for %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: id, Alg: alg, Private: priv}
}

// Rotate publishes a new key of alg next to the old ones and signs with it
// from now on, the way a provider rotates.
func (i *Issuer) Rotate(t testing.TB, alg jose.SignatureAlgorithm) Key {
	t.Helper()
	key := i.NewKey(t, alg)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.published = append(i.published, key)
	i.signing = key
	return key
}

// Publish sets the published key set.
func (i *Issuer) Publish(keys ...Key) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.published = append([]Key(nil), keys...)
}

// SigningKey is the key Mint signs with by default.
func (i *Issuer) SigningKey() Key {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.signing
}

// SetAlgs sets the advertised id_token_signing_alg_values_supported.
func (i *Issuer) SetAlgs(algs ...string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.algs = algs
}

// SetJWKSBody replaces the JWKS response body (nil restores it).
func (i *Issuer) SetJWKSBody(body []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.jwksOverride = body
}

// SetDiscoveryBody replaces the discovery response body (nil restores it).
func (i *Issuer) SetDiscoveryBody(body []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.discoveryOverride = body
}

// SetDiscoveredIssuer makes discovery claim another issuer URL.
func (i *Issuer) SetDiscoveredIssuer(url string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.issuerOverride = url
}

// JWKS is the published key set as JSON.
func (i *Issuer) JWKS() []byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	set := jose.JSONWebKeySet{}
	for _, k := range i.published {
		set.Keys = append(set.Keys, k.Public())
	}
	raw, _ := json.Marshal(set)
	return raw
}

func (i *Issuer) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	i.DiscoveryHits.Add(1)
	if i.FailDiscovery.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	i.mu.Lock()
	body := i.discoveryOverride
	issuer := i.URL
	if i.issuerOverride != "" {
		issuer = i.issuerOverride
	}
	algs := i.algs
	i.mu.Unlock()
	if body == nil {
		body, _ = json.Marshal(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              i.URL + "/jwks",
			"authorization_endpoint":                i.URL + "/authorize",
			"token_endpoint":                        i.URL + "/token",
			"id_token_signing_alg_values_supported": algs,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (i *Issuer) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	i.JWKSHits.Add(1)
	if i.FailJWKS.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	i.mu.Lock()
	body := i.jwksOverride
	i.mu.Unlock()
	if body == nil {
		body = i.JWKS()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// Claims is a standard ID-token claim set for this issuer: issued at now,
// valid for an hour, for audience aud, with an email and groups.
func (i *Issuer) Claims(now time.Time, aud, sub string, groups ...string) map[string]any {
	c := map[string]any{
		"iss":            i.URL,
		"sub":            sub,
		"aud":            aud,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"email":          sub + "@acme.com",
		"email_verified": true,
	}
	if groups != nil {
		c["groups"] = groups
	}
	return c
}

// MintOptions changes how Mint signs.
type MintOptions struct {
	// Key signs instead of the issuer's signing key.
	Key *Key
	// Headers are extra protected headers (jku, x5u, jwk, ...).
	Headers map[jose.HeaderKey]any
	// NoKeyID leaves kid out of the header.
	NoKeyID bool
}

// Mint signs claims with the issuer's signing key.
func (i *Issuer) Mint(t testing.TB, claims map[string]any) string {
	t.Helper()
	return i.MintWith(t, claims, MintOptions{})
}

// MintWith signs claims as opts says.
func (i *Issuer) MintWith(t testing.TB, claims map[string]any, opts MintOptions) string {
	t.Helper()
	key := i.SigningKey()
	if opts.Key != nil {
		key = *opts.Key
	}
	so := (&jose.SignerOptions{}).WithType("JWT")
	for k, v := range opts.Headers {
		so = so.WithHeader(k, v)
	}
	jwk := jose.JSONWebKey{Key: key.Private, KeyID: key.ID}
	if opts.NoKeyID {
		jwk.KeyID = ""
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.Alg, Key: jwk}, so)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// MintHMAC signs claims with HS256 and secret: the HMAC-confusion attack,
// for which the secret is often the issuer's public key bytes.
func MintHMAC(t testing.TB, claims map[string]any, secret []byte, kid string) string {
	t.Helper()
	so := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, so)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Unsigned builds an alg:none token: header.payload. with no signature.
func Unsigned(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}
