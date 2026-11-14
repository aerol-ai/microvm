// Package sandboxtoken is the signed, scoped per-sandbox token
// (plans/agent-sandbox-feature-parity.md §5.9, A1): a credential an owner
// can hand to a browser or an end user that works for one sandbox only,
// optionally narrowed to one port, one path prefix and a set of methods,
// and that expires. It is checked with no database call: the signature and
// the claims are everything a node needs.
//
// # Format
//
//	avmst_<kid>.<payload>.<sig>
//
// kid is the decimal id of the server key that signed it, payload is the
// base64url (no padding) JSON of Claims, and sig is the base64url Ed25519
// signature over "aerolvm-sandbox-token/v1\x00<kid>.<payload>". The kid is
// outside the payload so the signature is checked before any JSON is
// parsed; it is still covered by the signature.
//
// # Keys
//
// There is no key store of its own. The signing key is derived (HKDF-SHA256,
// its own label) from the server key ring that already seals secrets and
// keys the idempotency digests (pkg/secrets token_keys.go). Every node of a
// cluster holds the same ring, so every node derives the same key pair and
// verifies a token any node issued. A key-store revoke drops the ring, and
// with it every token: nothing signs or verifies until the key is back.
//
// # Threat model
//
//   - A stolen token is a bearer credential for exactly its scope until it
//     expires: one sandbox, and within it either the toolbox (no port: exec,
//     files and sessions under the path prefix and methods) or one public
//     port (port set: HTTP to that port's public URL, A2). A port token is
//     refused at the toolbox and a toolbox token at a public port. It can
//     never reach another sandbox, any other API route, or mint, extend or
//     widen a token: POST /v1/sandboxes/{id}/tokens refuses a sandbox token.
//     The issuer needed sandbox.exec on that sandbox, the most a token can
//     grant, so a token never holds more than the person who issued it.
//   - There is no revocation list (that would be the database call this
//     design avoids). A token dies at expiry, when its sandbox is deleted
//     (the sandbox id no longer resolves), when the server key it was
//     signed with is retired, or when its sandbox's tokens are revoked.
//     Lifetimes are still short: expiry is required and capped by
//     SB_SANDBOX_TOKEN_MAX_TTL (default 24h).
//   - Revoke is per sandbox, not per token: POST
//     /v1/sandboxes/{id}/tokens/revoke stores a not-before second on the
//     sandbox's row (NotBeforeAt), and every token issued before it is
//     refused (CheckNotBefore). The check costs no extra read: the toolbox
//     route already reads the row on the owner node, and a gated port reads
//     it from the same warm-cache entry or row read as its gate. A new row
//     (a create, a failover recreate on another node, a WASM migration)
//     starts with a not-before of its creation, so a token from before it
//     never reaches it: not a token for a deleted sandbox whose id was
//     reused, nor one revoked on an owner that then died. A node that
//     takes a placement back and reuses the row it kept from before raises
//     that row to the takeover's time, so a token revoked on the owner in
//     between stays refused there too.
//   - Replay inside the lifetime is by design: it is a bearer token, like a
//     signed URL. It travels only over HTTPS (A2 refuses token visibility
//     without a domain) and is never forwarded into the sandbox: the toolbox
//     proxy replaces Authorization with the sandbox's own toolbox token, and
//     the public port strips the cookie and the ?token= parameter.
//   - Expiry and clock skew: a node accepts a token from ClockSkew before
//     its issue time to ClockSkew after its expiry, so two nodes whose clocks
//     disagree by up to ClockSkew agree on it. A token whose lifetime is
//     longer than the verifying node's cap is refused (too_long_lived), so a
//     bug or a node with a larger cap cannot mint a token that outlives the
//     operator's limit elsewhere.
//   - Key rotation: the current server key signs; every key the ring still
//     holds (staged or the previous current key) verifies. A staged key
//     never signs, because a node that has not read the staged ring yet
//     could not check it. Retiring a key ends its tokens, so the rotation
//     runbook waits SB_SANDBOX_TOKEN_MAX_TTL after a promote before the
//     retire. An unknown key id is refused like a bad signature.
//   - Tampering: any change to the kid, payload or signature fails the
//     Ed25519 check (Go's ed25519.Verify rejects non-canonical signatures,
//     and the base64 decoding is strict, so one token has one encoding).
//     No secret is ever compared byte by byte here, so there is no
//     timing-sensitive comparison to make constant-time.
//   - Logging: the token string is never logged, put in an error, an audit
//     record or a metric. Only its id (stk_…, the jti claim) is: the issue
//     call's audit record names it, and a call made with a token records
//     sandbox_token:<id> as its caller. Refusals say only the reason
//     (malformed, invalid_signature, expired, not_yet_valid,
//     too_long_lived, revoked) and, for a scope miss, which part (sandbox,
//     port, path or method), never a claim value or a key id.
package sandboxtoken

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prefix starts every sandbox token. It is distinct from avm_ API tokens
// and from a JWT, so the API edge routes a bearer to the right check
// without trying the others.
const Prefix = "avmst_"

// TokenIDPrefix starts a token's public id: what audit records and logs
// name instead of the token.
const TokenIDPrefix = "stk_"

// MaxTokenLen bounds the work a forged token can cause before the
// signature check refuses it. A real token is a few hundred bytes.
const MaxTokenLen = 4096

// ClockSkew is how far two nodes' clocks may disagree and still agree on a
// token's validity window.
const ClockSkew = 30 * time.Second

// MaxPathPrefixLen and MaxSandboxIDLen bound the claims a caller can put in
// a token (and so the token's length).
const (
	MaxPathPrefixLen = 1024
	MaxSandboxIDLen  = 128
	maxOwnerLen      = 512
)

const (
	claimsVersion  = 1
	signingContext = "aerolvm-sandbox-token/v1\x00"
)

// b64 is strict base64url without padding: a token has exactly one
// encoding, so a re-encoded signature cannot pass as a different token.
var b64 = base64.RawURLEncoding.Strict()

// Refusal reasons. Each is a fixed word a caller may see; none carries a
// claim value, a key id or which key was tried.
var (
	ErrMalformed        = errors.New("sandbox token: malformed")
	ErrInvalidSignature = errors.New("sandbox token: invalid signature")
	ErrExpired          = errors.New("sandbox token: expired")
	ErrNotYetValid      = errors.New("sandbox token: not yet valid")
	ErrTooLongLived     = errors.New("sandbox token: lifetime is longer than this server allows")
	// ErrRevoked is a good token issued before its sandbox's tokens were
	// revoked (CheckNotBefore).
	ErrRevoked = errors.New("sandbox token: revoked")
	// ErrOutOfScope is a valid token used for a request it does not cover.
	// ScopeError says which part.
	ErrOutOfScope = errors.New("sandbox token: does not cover this request")
)

// Scope parts a ScopeError names.
const (
	ScopeSandbox = "sandbox"
	ScopePort    = "port"
	ScopePath    = "path"
	ScopeMethod  = "method"
)

// ScopeError is ErrOutOfScope naming the part of the request the token does
// not cover: a fixed word, never a value from the token or the request.
type ScopeError struct{ Part string }

func (e *ScopeError) Error() string { return ErrOutOfScope.Error() + " (" + e.Part + ")" }

// Unwrap makes errors.Is(err, ErrOutOfScope) hold.
func (e *ScopeError) Unwrap() error { return ErrOutOfScope }

// Claims is what a token says. The JSON names are short because the token
// rides in a URL (?token=) and a cookie.
type Claims struct {
	Version int `json:"v"`
	// TokenID is the public id (stk_…), safe for logs and audit records.
	TokenID   string `json:"jti"`
	SandboxID string `json:"sbx"`
	// Owner is the sandbox's owner ref at issue time. The toolbox side
	// scopes the caller to it, so even a scope-check bug could not reach
	// another owner's sandbox.
	Owner string `json:"own,omitempty"`
	// Port, when set, makes this a public-port token (A2) for that port;
	// zero makes it a toolbox token. Never both.
	Port int `json:"port,omitempty"`
	// PathPrefix, when set, limits the request path: the toolbox path
	// (for example /files) or the public URL path. Segment-aware: /files
	// covers /files and /files/x, not /files-x.
	PathPrefix string `json:"path,omitempty"`
	// Methods, when set, are the only HTTP methods allowed.
	Methods   []string `json:"m,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	// KeyID is the server key that signed the token. It is carried in the
	// token's first segment, not the JSON.
	KeyID uint32 `json:"-"`
}

// Expiry is ExpiresAt as a time.
func (c Claims) Expiry() time.Time { return time.Unix(c.ExpiresAt, 0).UTC() }

// NotBeforeAt is the not-before second a revoke (or a new row) made at now
// stores: the second after now's. IssuedAt is whole seconds, so a token
// issued earlier in now's own second carries the same IssuedAt as one
// issued later in it; storing now's second would let the earlier one
// through. The next second refuses both, and IssueTime lifts a token issued
// after the revoke but inside that same second up to it, so that one works.
func NotBeforeAt(now time.Time) int64 { return now.Unix() + 1 }

// IssueTime is the time a token issued at now says it was issued, for a
// sandbox whose tokens_not_before is notBefore: now, or notBefore when that
// is later. It is later only for a token issued in the second of a revoke
// or of the row's creation, and then by under a second (well inside
// ClockSkew, so every node accepts it). After a clock step back on the
// owner it can be further ahead; the token then reads not_yet_valid until
// the clock catches up, rather than slipping under the revoke.
func IssueTime(now time.Time, notBefore int64) time.Time {
	if notBefore > now.Unix() {
		return time.Unix(notBefore, 0)
	}
	return now
}

// CheckNotBefore refuses a token issued before notBefore, its sandbox's
// tokens_not_before (0: nothing was ever revoked).
func (c Claims) CheckNotBefore(notBefore int64) error {
	if c.IssuedAt < notBefore {
		return ErrRevoked
	}
	return nil
}

// Signer is the signing half of a key ring (secrets.Cipher).
type Signer interface {
	SandboxTokenSigner() (uint32, ed25519.PrivateKey, error)
}

// KeySource is the verifying half of a key ring (secrets.Cipher).
type KeySource interface {
	SandboxTokenVerifyKey(id uint32) (ed25519.PublicKey, bool)
}

// allowedMethods are the methods a token may name. A fixed list keeps an
// odd method name out of tokens, logs and the 403 text.
var allowedMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true,
}

// NormalizeMethods upper-cases, checks, de-duplicates and sorts methods.
func NormalizeMethods(methods []string) ([]string, error) {
	if len(methods) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(methods))
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !allowedMethods[m] {
			return nil, fmt.Errorf("method %q is not one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", m)
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ValidatePathPrefix checks a path prefix: empty, or an absolute, clean path
// (no "..", ".", "//" or trailing slash, except "/" itself) without a query,
// a fragment or a control character.
func ValidatePathPrefix(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > MaxPathPrefixLen {
		return fmt.Errorf("path prefix is longer than %d bytes", MaxPathPrefixLen)
	}
	if !strings.HasPrefix(p, "/") {
		return errors.New("path prefix must start with /")
	}
	if strings.ContainsAny(p, "?#") {
		return errors.New("path prefix must not hold a query or a fragment")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return errors.New("path prefix must not hold a control character")
		}
	}
	if pathpkg.Clean(p) != p {
		return errors.New("path prefix must be a clean path: no .., ., // or trailing /")
	}
	return nil
}

// validateScope checks the claims every token must satisfy, at issue and
// again after a signature check (a signed token is still re-checked: a key
// shared by every node is only as careful as the least careful signer).
func (c Claims) validateScope() error {
	switch {
	case c.SandboxID == "" || len(c.SandboxID) > MaxSandboxIDLen:
		return errors.New("sandbox id is missing or too long")
	case len(c.Owner) > maxOwnerLen:
		return errors.New("owner is too long")
	case c.Port < 0 || c.Port > 65535:
		return errors.New("port must be between 1 and 65535")
	}
	if err := ValidatePathPrefix(c.PathPrefix); err != nil {
		return err
	}
	norm, err := NormalizeMethods(c.Methods)
	if err != nil {
		return err
	}
	if !slices.Equal(norm, c.Methods) {
		return errors.New("methods must be upper-case, sorted and not repeat")
	}
	return nil
}

// NewTokenID returns a fresh public token id.
func NewTokenID() (string, error) { return newTokenID(rand.Reader) }

func newTokenID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("sandbox token id: %w", err)
	}
	return TokenIDPrefix + hex.EncodeToString(b[:]), nil
}

// Sign signs c with s's current key. It sets Version and KeyID, and refuses
// claims a verifier would refuse (no id, no lifetime, a bad scope).
func Sign(s Signer, c Claims) (string, Claims, error) {
	if s == nil {
		return "", Claims{}, errors.New("sandbox token: no signing key")
	}
	c.Version = claimsVersion
	methods, err := NormalizeMethods(c.Methods)
	if err != nil {
		return "", Claims{}, fmt.Errorf("sandbox token: %w", err)
	}
	c.Methods = methods
	if !strings.HasPrefix(c.TokenID, TokenIDPrefix) {
		return "", Claims{}, errors.New("sandbox token: token id is missing")
	}
	if c.ExpiresAt <= c.IssuedAt {
		return "", Claims{}, errors.New("sandbox token: expiry must be after issue time")
	}
	if err := c.validateScope(); err != nil {
		return "", Claims{}, fmt.Errorf("sandbox token: %w", err)
	}
	kid, priv, err := s.SandboxTokenSigner()
	if err != nil {
		return "", Claims{}, err
	}
	c.KeyID = kid
	payload, err := json.Marshal(c)
	if err != nil {
		return "", Claims{}, fmt.Errorf("sandbox token: %w", err)
	}
	head := strconv.FormatUint(uint64(kid), 10) + "." + b64.EncodeToString(payload)
	sig := ed25519.Sign(priv, signingInput(head))
	return Prefix + head + "." + b64.EncodeToString(sig), c, nil
}

func signingInput(head string) []byte {
	return append([]byte(signingContext), head...)
}

// IsToken reports whether raw is shaped like a sandbox token (by prefix
// only); the API edge uses it to pick this check for a bearer.
func IsToken(raw string) bool { return strings.HasPrefix(raw, Prefix) }

// Verify checks raw's signature against keys, then its claims and its
// validity window at now. maxTTL, when positive, is the longest lifetime
// this node accepts. The error is one of the sentinels above; it never
// holds the token or a claim value.
func Verify(keys KeySource, raw string, now time.Time, maxTTL time.Duration) (Claims, error) {
	if keys == nil || !IsToken(raw) || len(raw) > MaxTokenLen {
		return Claims{}, ErrMalformed
	}
	body := raw[len(Prefix):]
	kidPart, rest, ok := strings.Cut(body, ".")
	if !ok {
		return Claims{}, ErrMalformed
	}
	payloadPart, sigPart, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(sigPart, ".") {
		return Claims{}, ErrMalformed
	}
	kid, err := parseKeyID(kidPart)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	sig, err := b64.DecodeString(sigPart)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Claims{}, ErrMalformed
	}
	pub, ok := keys.SandboxTokenVerifyKey(kid)
	if !ok {
		// An unknown or retired key reads exactly like a bad signature:
		// a caller learns nothing about which key ids exist.
		return Claims{}, ErrInvalidSignature
	}
	if !ed25519.Verify(pub, signingInput(kidPart+"."+payloadPart), sig) {
		return Claims{}, ErrInvalidSignature
	}
	payload, err := b64.DecodeString(payloadPart)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return Claims{}, ErrMalformed
	}
	c.KeyID = kid
	if c.Version != claimsVersion || !strings.HasPrefix(c.TokenID, TokenIDPrefix) || c.ExpiresAt <= c.IssuedAt || c.validateScope() != nil {
		return Claims{}, ErrMalformed
	}
	lifetime := time.Duration(c.ExpiresAt-c.IssuedAt) * time.Second
	if maxTTL > 0 && lifetime > maxTTL {
		return Claims{}, ErrTooLongLived
	}
	if time.Unix(c.IssuedAt, 0).After(now.Add(ClockSkew)) {
		return Claims{}, ErrNotYetValid
	}
	if now.After(time.Unix(c.ExpiresAt, 0).Add(ClockSkew)) {
		return Claims{}, ErrExpired
	}
	return c, nil
}

// parseKeyID reads the kid segment: a canonical decimal uint32 (no sign,
// no leading zero), so one key id has one spelling.
func parseKeyID(s string) (uint32, error) {
	if s == "" || len(s) > 10 || (len(s) > 1 && s[0] == '0') {
		return 0, ErrMalformed
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrMalformed
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, ErrMalformed
	}
	return uint32(n), nil
}

// Request is the part of a request a token's scope is checked against.
// Port is zero for a toolbox request and the guest port for a public-port
// request. Path is the toolbox path (after /toolbox) or the URL path.
type Request struct {
	SandboxID string
	Port      int
	Path      string
	Method    string
}

// Allows reports whether c covers req. The order is fixed (sandbox, port,
// method, path) so a refusal names the first part that does not match.
func (c Claims) Allows(req Request) error {
	if req.SandboxID == "" || req.SandboxID != c.SandboxID {
		return &ScopeError{Part: ScopeSandbox}
	}
	if req.Port != c.Port {
		return &ScopeError{Part: ScopePort}
	}
	if len(c.Methods) > 0 {
		allowed := false
		for _, m := range c.Methods {
			if m == req.Method {
				allowed = true
				break
			}
		}
		if !allowed {
			return &ScopeError{Part: ScopeMethod}
		}
	}
	if !PathCovered(c.PathPrefix, req.Path) {
		return &ScopeError{Part: ScopePath}
	}
	return nil
}

// PathCovered reports whether p is under prefix, segment by segment. A path
// that is not clean (".." or "." segments, "//") is never covered by a
// prefix: the check and the upstream that serves the request could resolve
// it differently. A trailing slash is allowed (a directory URL).
func PathCovered(prefix, p string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if p == "" || p[0] != '/' {
		return false
	}
	trimmed := p
	if len(trimmed) > 1 {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	if pathpkg.Clean(trimmed) != trimmed {
		return false
	}
	return trimmed == prefix || strings.HasPrefix(trimmed, prefix+"/")
}
