package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleCreds() UpstreamCredentials {
	return UpstreamCredentials{
		UpstreamHost: "ghcr.io",
		Username:     "octocat",
		Password:     "ghp_xxxxxxxxxxxx",
		Scope:        "repository:_/ghcr/aerol-ai/sandbox:pull",
	}
}

// unwrapForTest is the AOCR-side `unwrap` reimplemented in Go against the
// wire format. If WrapUpstreamCreds ever drifts from what AOCR's auth
// service expects, this round-trip will break and so will production.
func unwrapForTest(t *testing.T, token string, key []byte) wrapEnvelope {
	t.Helper()
	if !strings.HasPrefix(token, IdentityTokenPrefix) {
		t.Fatalf("token missing %q prefix", IdentityTokenPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, IdentityTokenPrefix))
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	const tagLen = 16
	const nonceLen = 12
	if len(raw) < nonceLen+tagLen+1 {
		t.Fatalf("blob too short: %d", len(raw))
	}
	nonce := raw[:nonceLen]
	body := raw[nonceLen:]
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	plain, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var env wrapEnvelope
	if err := json.Unmarshal(plain, &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	return env
}

func TestWrapUpstreamCreds_RoundTrip(t *testing.T) {
	ring := ParseUpstreamWrapKeyRing(b64(key32(0xaa)))
	creds := sampleCreds()
	token, err := WrapUpstreamCreds(ring, creds)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	env := unwrapForTest(t, token, key32(0xaa))
	if env.V != 1 {
		t.Fatalf("envelope version: got %d", env.V)
	}
	if env.Creds != creds {
		t.Fatalf("creds round-trip mismatch: got %+v want %+v", env.Creds, creds)
	}
	// Timestamp should be within a few seconds of now.
	age := time.Since(time.UnixMilli(env.Ts))
	if age < 0 || age > 5*time.Second {
		t.Fatalf("envelope timestamp implausible: ts=%d age=%v", env.Ts, age)
	}
}

func TestWrapUpstreamCreds_UsesCurrentKey(t *testing.T) {
	raw := "new:" + b64(key32(0x11)) + "," + "old:" + b64(key32(0x22))
	ring := ParseUpstreamWrapKeyRing(raw)
	token, err := WrapUpstreamCreds(ring, sampleCreds())
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	// The current key must decrypt successfully (the negative case — old
	// key cannot — is covered by TestWrapUpstreamCreds_OldKeyCannotDecryptNewBlob).
	_ = unwrapForTest(t, token, key32(0x11))
}

func TestWrapUpstreamCreds_OldKeyCannotDecryptNewBlob(t *testing.T) {
	raw := "new:" + b64(key32(0x11)) + "," + "old:" + b64(key32(0x22))
	ring := ParseUpstreamWrapKeyRing(raw)
	token, err := WrapUpstreamCreds(ring, sampleCreds())
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	// Manual decrypt with the OLD key — must fail.
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, IdentityTokenPrefix))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	block, _ := aes.NewCipher(key32(0x22))
	gcm, _ := cipher.NewGCM(block)
	if _, err := gcm.Open(nil, body[:12], body[12:], nil); err == nil {
		t.Fatalf("old key unexpectedly decrypted new blob")
	}
}

func TestWrapUpstreamCreds_EmptyRing(t *testing.T) {
	ring := &UpstreamWrapKeyRing{}
	if _, err := WrapUpstreamCreds(ring, sampleCreds()); err == nil {
		t.Fatalf("expected error for empty ring")
	}
}

func TestWrapUpstreamCreds_RequiresHost(t *testing.T) {
	ring := ParseUpstreamWrapKeyRing(b64(key32(0xaa)))
	creds := sampleCreds()
	creds.UpstreamHost = ""
	if _, err := WrapUpstreamCreds(ring, creds); err == nil {
		t.Fatalf("expected error for empty upstream host")
	}
}

func TestWrapUpstreamCreds_TamperedBlobFailsToOpen(t *testing.T) {
	ring := ParseUpstreamWrapKeyRing(b64(key32(0xaa)))
	token, err := WrapUpstreamCreds(ring, sampleCreds())
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, IdentityTokenPrefix))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a byte in the ciphertext region (after nonce, before tag).
	body[15] ^= 0xff
	block, _ := aes.NewCipher(key32(0xaa))
	gcm, _ := cipher.NewGCM(block)
	if _, err := gcm.Open(nil, body[:12], body[12:], nil); err == nil {
		t.Fatalf("tampered blob unexpectedly verified")
	}
}

func TestWrapUpstreamCreds_DeterministicEnvelopeVersion(t *testing.T) {
	// The AOCR side hard-rejects anything that isn't envelope v=1. This
	// catches silent drift if the constant is ever bumped without
	// coordination.
	ring := ParseUpstreamWrapKeyRing(b64(key32(0xee)))
	token, err := wrapWithClock(ring, sampleCreds(), func() time.Time { return time.UnixMilli(1700000000000) })
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	env := unwrapForTest(t, token, key32(0xee))
	if env.V != 1 {
		t.Fatalf("envelope v must be 1, got %d", env.V)
	}
	if env.Ts != 1700000000000 {
		t.Fatalf("clock not respected, got ts=%d", env.Ts)
	}
}

func TestIdentityTokenPrefixIsStable(t *testing.T) {
	// Constant value lock-in. Changing this requires a coordinated
	// rollout with AOCR (`WRAPPED_UPSTREAM_TOKEN_PREFIX` in
	// auth/src/upstreamAuth/strategy.ts).
	if IdentityTokenPrefix != "aocrwrap:" {
		t.Fatalf("prefix drifted from contract: %q", IdentityTokenPrefix)
	}
}
