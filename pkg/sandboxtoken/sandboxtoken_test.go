package sandboxtoken

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testRing is a key ring like secrets.Cipher's: one current key that signs,
// and every held key verifies.
type testRing struct {
	current uint32
	keys    map[uint32]ed25519.PrivateKey
	err     error
}

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func newRing(current uint32, ids ...uint32) *testRing {
	r := &testRing{current: current, keys: map[uint32]ed25519.PrivateKey{}}
	for _, id := range ids {
		r.keys[id] = seedKey(byte(id + 1))
	}
	return r
}

func (r *testRing) SandboxTokenSigner() (uint32, ed25519.PrivateKey, error) {
	if r.err != nil {
		return 0, nil, r.err
	}
	return r.current, r.keys[r.current], nil
}

func (r *testRing) SandboxTokenVerifyKey(id uint32) (ed25519.PublicKey, bool) {
	k, ok := r.keys[id]
	if !ok {
		return nil, false
	}
	return k.Public().(ed25519.PublicKey), true
}

var t0 = time.Unix(1_800_000_000, 0)

func baseClaims() Claims {
	return Claims{
		TokenID:   "stk_0123456789abcdef0123456789abcdef",
		SandboxID: "sb-1111111111111111",
		Owner:     "team:payments",
		IssuedAt:  t0.Unix(),
		ExpiresAt: t0.Add(time.Hour).Unix(),
	}
}

func mustSign(t *testing.T, s Signer, c Claims) string {
	t.Helper()
	tok, _, err := Sign(s, c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	ring := newRing(3, 3)
	c := baseClaims()
	c.Port = 8080
	c.PathPrefix = "/app"
	c.Methods = []string{"post", "GET", "get"}
	tok, signed, err := Sign(ring, c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, Prefix+"3.") || signed.KeyID != 3 || signed.Version != 1 {
		t.Fatalf("token %q claims %+v", tok, signed)
	}
	if strings.Join(signed.Methods, ",") != "GET,POST" {
		t.Fatalf("methods not normalized: %v", signed.Methods)
	}
	got, err := Verify(ring, tok, t0.Add(time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.SandboxID != c.SandboxID || got.Owner != c.Owner || got.Port != 8080 || got.PathPrefix != "/app" ||
		got.KeyID != 3 || got.TokenID != c.TokenID || !got.Expiry().Equal(t0.Add(time.Hour)) {
		t.Fatalf("claims = %+v", got)
	}
	if !IsToken(tok) || IsToken("avm_abc") {
		t.Fatal("IsToken")
	}
}

// Every way a token can be wrong is refused with a fixed reason, and no
// error text carries the token or any claim.
func TestVerifyRefusals(t *testing.T) {
	ring := newRing(1, 1)
	good := mustSign(t, ring, baseClaims())
	kid, rest, _ := strings.Cut(strings.TrimPrefix(good, Prefix), ".")
	payload, sig, _ := strings.Cut(rest, ".")

	resign := func(head string) string {
		return Prefix + head + "." + b64.EncodeToString(ed25519.Sign(ring.keys[1], signingInput(head)))
	}
	signedPayload := func(v any) string {
		raw, _ := json.Marshal(v)
		return resign("1." + b64.EncodeToString(raw))
	}
	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	otherRing := newRing(1, 1)
	otherRing.keys[1] = seedKey(99)

	long := baseClaims()
	long.ExpiresAt = long.IssuedAt + int64((25 * time.Hour).Seconds())
	future := baseClaims()
	future.IssuedAt = t0.Add(time.Hour).Unix()
	future.ExpiresAt = t0.Add(2 * time.Hour).Unix()

	cases := []struct {
		name string
		keys KeySource
		raw  string
		now  time.Time
		want error
	}{
		{"no prefix", ring, strings.TrimPrefix(good, Prefix), t0, ErrMalformed},
		{"avm_ token", ring, "avm_abc", t0, ErrMalformed},
		{"too long", ring, good + strings.Repeat("A", MaxTokenLen), t0, ErrMalformed},
		{"no dots", ring, Prefix + "1", t0, ErrMalformed},
		{"one dot", ring, Prefix + kid + "." + payload, t0, ErrMalformed},
		{"three dots", ring, good + ".x", t0, ErrMalformed},
		{"non-decimal kid", ring, Prefix + "x." + rest, t0, ErrMalformed},
		{"leading-zero kid", ring, Prefix + "01." + rest, t0, ErrMalformed},
		{"kid overflow", ring, Prefix + "99999999999." + rest, t0, ErrMalformed},
		{"empty kid", ring, Prefix + "." + rest, t0, ErrMalformed},
		{"short signature", ring, Prefix + kid + "." + payload + ".AAAA", t0, ErrMalformed},
		{"signature not base64", ring, Prefix + kid + "." + payload + "." + strings.Repeat("*", 86), t0, ErrMalformed},
		{"unknown kid", ring, Prefix + "7." + rest, t0, ErrInvalidSignature},
		{"wrong key", otherRing, good, t0, ErrInvalidSignature},
		{"tampered payload", ring, Prefix + kid + "." + flip(payload, 10) + "." + sig, t0, ErrInvalidSignature},
		{"tampered signature last byte", ring, Prefix + kid + "." + payload + "." + flip(sig, len(sig)-2), t0, ErrInvalidSignature},
		{"kid swapped to another held key", newRing(1, 1, 2), Prefix + "2." + rest, t0, ErrInvalidSignature},
		{"payload not base64 but signed", ring, resign("1.***"), t0, ErrMalformed},
		{"payload not JSON", ring, resign("1." + b64.EncodeToString([]byte("not json"))), t0, ErrMalformed},
		{"unknown claim", ring, signedPayload(map[string]any{"v": 1, "jti": "stk_x", "sbx": "sb", "iat": 1, "exp": 2, "admin": true}), t0, ErrMalformed},
		{"two JSON values", ring, resign("1." + b64.EncodeToString([]byte(`{"v":1} {"v":1}`))), t0, ErrMalformed},
		{"wrong version", ring, signedPayload(map[string]any{"v": 2, "jti": "stk_x", "sbx": "sb", "iat": t0.Unix(), "exp": t0.Unix() + 60}), t0, ErrMalformed},
		{"no token id", ring, signedPayload(map[string]any{"v": 1, "sbx": "sb", "iat": t0.Unix(), "exp": t0.Unix() + 60}), t0, ErrMalformed},
		{"no sandbox", ring, signedPayload(map[string]any{"v": 1, "jti": "stk_x", "iat": t0.Unix(), "exp": t0.Unix() + 60}), t0, ErrMalformed},
		{"expiry before issue", ring, signedPayload(map[string]any{"v": 1, "jti": "stk_x", "sbx": "sb", "iat": t0.Unix(), "exp": t0.Unix()}), t0, ErrMalformed},
		{"lower-case method", ring, signedPayload(map[string]any{"v": 1, "jti": "stk_x", "sbx": "sb", "m": []string{"get"}, "iat": t0.Unix(), "exp": t0.Unix() + 60}), t0, ErrMalformed},
		{"unclean path", ring, signedPayload(map[string]any{"v": 1, "jti": "stk_x", "sbx": "sb", "path": "/a/../b", "iat": t0.Unix(), "exp": t0.Unix() + 60}), t0, ErrMalformed},
		{"bad port", ring, signedPayload(map[string]any{"v": 1, "jti": "stk_x", "sbx": "sb", "port": 70000, "iat": t0.Unix(), "exp": t0.Unix() + 60}), t0, ErrMalformed},
		{"too long lived", ring, mustSign(t, ring, long), t0, ErrTooLongLived},
		{"expired", ring, good, t0.Add(time.Hour + ClockSkew + time.Second), ErrExpired},
		{"not yet valid", ring, mustSign(t, ring, future), t0, ErrNotYetValid},
		{"nil keys", nil, good, t0, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.keys, tc.raw, tc.now, 24*time.Hour)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
			msg := err.Error()
			if strings.Contains(msg, payload) || strings.Contains(msg, sig) || strings.Contains(msg, "sb-1111") || strings.Contains(msg, "payments") {
				t.Fatalf("error %q leaks the token or a claim", msg)
			}
		})
	}
}

// Two nodes whose clocks disagree by up to ClockSkew agree on a token: it
// is good from ClockSkew before its issue time to ClockSkew after expiry.
func TestVerifyClockSkewBound(t *testing.T) {
	ring := newRing(0, 0)
	c := baseClaims()
	tok := mustSign(t, ring, c)
	exp := time.Unix(c.ExpiresAt, 0)
	iat := time.Unix(c.IssuedAt, 0)
	for _, tc := range []struct {
		name string
		now  time.Time
		want error
	}{
		{"verifier clock behind the issuer by the skew", iat.Add(-ClockSkew), nil},
		{"verifier clock behind by more than the skew", iat.Add(-ClockSkew - time.Second), ErrNotYetValid},
		{"just past expiry, inside the skew", exp.Add(ClockSkew), nil},
		{"past expiry plus the skew", exp.Add(ClockSkew + time.Second), ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(ring, tok, tc.now, 0); !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// Rotation: a token signed under the previous key verifies while the ring
// still holds it, and not once it is retired; new tokens use the new key.
func TestVerifyAcrossRotation(t *testing.T) {
	ring := newRing(0, 0)
	oldTok := mustSign(t, ring, baseClaims())

	ring.keys[1] = seedKey(2) // staged
	ring.current = 1          // promoted
	newTok := mustSign(t, ring, baseClaims())
	if !strings.HasPrefix(newTok, Prefix+"1.") {
		t.Fatalf("new token not under the new key: %q", newTok[:12])
	}
	for _, tok := range []string{oldTok, newTok} {
		if _, err := Verify(ring, tok, t0, time.Hour); err != nil {
			t.Fatalf("during rotation: %v", err)
		}
	}
	delete(ring.keys, 0) // retired
	if _, err := Verify(ring, oldTok, t0, time.Hour); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("token under a retired key: %v", err)
	}
	if _, err := Verify(ring, newTok, t0, time.Hour); err != nil {
		t.Fatalf("token under the current key after retire: %v", err)
	}
}

func TestSignRefusesBadClaims(t *testing.T) {
	ring := newRing(0, 0)
	mutate := func(f func(*Claims)) Claims {
		c := baseClaims()
		f(&c)
		return c
	}
	for name, c := range map[string]Claims{
		"no token id":     mutate(func(c *Claims) { c.TokenID = "" }),
		"no lifetime":     mutate(func(c *Claims) { c.ExpiresAt = c.IssuedAt }),
		"no sandbox":      mutate(func(c *Claims) { c.SandboxID = "" }),
		"long sandbox id": mutate(func(c *Claims) { c.SandboxID = strings.Repeat("s", MaxSandboxIDLen+1) }),
		"long owner":      mutate(func(c *Claims) { c.Owner = strings.Repeat("o", maxOwnerLen+1) }),
		"negative port":   mutate(func(c *Claims) { c.Port = -1 }),
		"bad method":      mutate(func(c *Claims) { c.Methods = []string{"TRACE"} }),
		"relative path":   mutate(func(c *Claims) { c.PathPrefix = "files" }),
	} {
		if _, _, err := Sign(ring, c); err == nil {
			t.Fatalf("%s: signed", name)
		}
	}
	if _, _, err := Sign(nil, baseClaims()); err == nil {
		t.Fatal("signed with no signer")
	}
	ring.err = errors.New("revoked")
	if _, _, err := Sign(ring, baseClaims()); err == nil || err.Error() != "revoked" {
		t.Fatalf("signer error not returned: %v", err)
	}
}

func TestValidatePathPrefix(t *testing.T) {
	for p, ok := range map[string]bool{
		"":           true,
		"/":          true,
		"/files":     true,
		"/files/sub": true,
		"files":      false,
		"/files/":    false,
		"/a/../b":    false,
		"/a/./b":     false,
		"//a":        false,
		"/a?b":       false,
		"/a#b":       false,
		"/a\nb":      false,
		"/a\x7fb":    false,
		"/" + strings.Repeat("a", MaxPathPrefixLen): false,
	} {
		if err := ValidatePathPrefix(p); (err == nil) != ok {
			t.Fatalf("ValidatePathPrefix(%q) = %v, want ok=%v", p, err, ok)
		}
	}
}

// Scope: each part of the request is checked, and the refusal names the
// first part that does not match with a fixed word.
func TestAllows(t *testing.T) {
	c := baseClaims()
	c.PathPrefix = "/files"
	c.Methods = []string{"GET", "HEAD"}
	toolbox := Request{SandboxID: c.SandboxID, Path: "/files/download", Method: "GET"}
	for _, tc := range []struct {
		name string
		req  Request
		part string
	}{
		{"covered", toolbox, ""},
		{"exact prefix", Request{SandboxID: c.SandboxID, Path: "/files", Method: "HEAD"}, ""},
		{"trailing slash", Request{SandboxID: c.SandboxID, Path: "/files/", Method: "GET"}, ""},
		{"another sandbox", Request{SandboxID: "sb-2222222222222222", Path: "/files", Method: "GET"}, ScopeSandbox},
		{"no sandbox", Request{Path: "/files", Method: "GET"}, ScopeSandbox},
		{"a port on a toolbox token", Request{SandboxID: c.SandboxID, Port: 8080, Path: "/files", Method: "GET"}, ScopePort},
		{"method not listed", Request{SandboxID: c.SandboxID, Path: "/files", Method: "POST"}, ScopeMethod},
		{"sibling path", Request{SandboxID: c.SandboxID, Path: "/files-x", Method: "GET"}, ScopePath},
		{"another path", Request{SandboxID: c.SandboxID, Path: "/exec", Method: "GET"}, ScopePath},
		{"dot-dot escape", Request{SandboxID: c.SandboxID, Path: "/files/../exec", Method: "GET"}, ScopePath},
		{"double slash", Request{SandboxID: c.SandboxID, Path: "/files//x", Method: "GET"}, ScopePath},
		{"relative", Request{SandboxID: c.SandboxID, Path: "files", Method: "GET"}, ScopePath},
		{"empty path", Request{SandboxID: c.SandboxID, Path: "", Method: "GET"}, ScopePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Allows(tc.req)
			if tc.part == "" {
				if err != nil {
					t.Fatalf("Allows = %v", err)
				}
				return
			}
			var se *ScopeError
			if !errors.As(err, &se) || se.Part != tc.part || !errors.Is(err, ErrOutOfScope) {
				t.Fatalf("Allows = %v, want scope part %q", err, tc.part)
			}
			if !strings.HasSuffix(err.Error(), "("+tc.part+")") {
				t.Fatalf("message %q", err.Error())
			}
		})
	}

	// A port token covers only its port; no prefix and no methods mean any.
	port := baseClaims()
	port.Port = 3000
	if err := port.Allows(Request{SandboxID: port.SandboxID, Port: 3000, Path: "/a/../b", Method: "DELETE"}); err != nil {
		t.Fatalf("an unrestricted port token: %v", err)
	}
	if err := port.Allows(Request{SandboxID: port.SandboxID, Path: "/", Method: "GET"}); err == nil {
		t.Fatal("a port token covers the toolbox")
	}
}

func TestNewTokenID(t *testing.T) {
	a, err := NewTokenID()
	if err != nil || !strings.HasPrefix(a, TokenIDPrefix) || len(a) != len(TokenIDPrefix)+32 {
		t.Fatalf("NewTokenID = %q, %v", a, err)
	}
	b, _ := NewTokenID()
	if a == b {
		t.Fatal("two token ids are equal")
	}
	if _, err := newTokenID(bytes.NewReader(nil)); err == nil {
		t.Fatal("a failing random source gave an id")
	}
}

func TestNormalizeMethods(t *testing.T) {
	got, err := NormalizeMethods([]string{" delete", "GET", "get"})
	if err != nil || strings.Join(got, ",") != "DELETE,GET" {
		t.Fatalf("NormalizeMethods = %v, %v", got, err)
	}
	if got, err := NormalizeMethods(nil); got != nil || err != nil {
		t.Fatalf("empty = %v, %v", got, err)
	}
	if _, err := NormalizeMethods([]string{"CONNECT"}); err == nil {
		t.Fatal("CONNECT allowed")
	}
}

// The kid in the first segment is what verification uses; a payload that
// tries to carry its own kid is an unknown field.
func TestKidLivesOutsideThePayload(t *testing.T) {
	ring := newRing(5, 5)
	tok := mustSign(t, ring, baseClaims())
	_, rest, _ := strings.Cut(strings.TrimPrefix(tok, Prefix), ".")
	payload, _, _ := strings.Cut(rest, ".")
	raw, err := b64.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"kid"`)) || bytes.Contains(raw, []byte(`KeyID`)) {
		t.Fatalf("payload carries a key id: %s", raw)
	}
	if !strings.HasPrefix(tok, Prefix+strconv.Itoa(5)+".") {
		t.Fatal("kid segment missing")
	}
}
