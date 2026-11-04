package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aerol-ai/microvm/internal/identity/identitytest"
)

func jwkJSON(t *testing.T, k jose.JSONWebKey) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestParseJWKS: only usable public signing keys survive, as RFC 7517 §5
// asks; a bad member is skipped, not fatal for the whole set.
func TestParseJWKS(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	members := []json.RawMessage{
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa", Use: "sig", Algorithm: "RS256"}),
		jwkJSON(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "p256"}),
		jwkJSON(t, jose.JSONWebKey{Key: &weak.PublicKey, KeyID: "weak"}),
		jwkJSON(t, jose.JSONWebKey{Key: &p384.PublicKey, KeyID: "p384"}),
		jwkJSON(t, jose.JSONWebKey{Key: rsaKey, KeyID: "private"}),
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "enc", Use: "enc"}),
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "ps", Algorithm: "PS256"}),
		json.RawMessage(`{"kty":"oct","k":"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0","kid":"hmac"}`),
		json.RawMessage(`{"kty":"OKP","crv":"X448","x":"AAAA","kid":"x448"}`),
		json.RawMessage(`"not an object"`),
	}
	doc, _ := json.Marshal(map[string]any{"keys": members})
	keys, err := parseJWKS(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, k := range keys {
		got = append(got, k.KeyID)
	}
	if strings.Join(got, ",") != "rsa,p256" {
		t.Fatalf("kept %v, want only the usable public signing keys rsa,p256", got)
	}
	if _, err := parseJWKS([]byte("{")); err == nil {
		t.Fatal("a broken document must fail")
	}
}

// TestCappedTransport: a body over the cap fails whether or not the
// server declared its length, and counts the oversize metric once.
func TestCappedTransport(t *testing.T) {
	big := strings.Repeat("a", MaxDocumentBytes+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/declared" {
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
		} else {
			w.(http.Flusher).Flush() // chunked: no declared length
		}
		_, _ = io.WriteString(w, big)
	}))
	t.Cleanup(srv.Close)
	for _, path := range []string{"/declared", "/chunked"} {
		var over atomic.Bool
		before := oversizeCount(oversizeJWKS)
		resp, err := cappedClient(srv.Client(), oversizeJWKS, &over).Get(srv.URL + path)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_, again := resp.Body.Read(make([]byte, 1))
			resp.Body.Close()
			if !errors.Is(again, errDocumentTooLarge) {
				t.Fatalf("%s: a read after the cap = %v", path, again)
			}
		}
		if !errors.Is(err, errDocumentTooLarge) || !over.Load() || oversizeCount(oversizeJWKS) != before+1 {
			t.Fatalf("%s: err %v over %v", path, err, over.Load())
		}
	}
	var over atomic.Bool
	if _, err := cappedClient(&http.Client{Transport: failingTransport{}}, oversizeJWKS, &over).Get(srv.URL); err == nil {
		t.Fatal("a transport error must pass through")
	}
	if clip(strings.Repeat("x", 600)) != strings.Repeat("x", 512)+"…" || clip("short") != "short" {
		t.Fatal("clip")
	}
}

// TestVerifySignatureBranches drives the key set directly: a snapshot that
// refuses an algorithm without a refetch, an unparsable token, and an
// unknown kid when the provider is down.
func TestVerifySignatureBranches(t *testing.T) {
	env := newVerifierEnv(t, "")
	if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); err != nil {
		t.Fatal(err)
	}
	st, _ := env.v.current()
	var ks *keySet
	for _, iv := range st.issuers {
		ks = iv.keys
	}
	snap := ks.snap.Load()
	jws, err := jose.ParseSigned(env.iss.Mint(t, env.claims("00u1")), joseAlgs)
	if err != nil {
		t.Fatal(err)
	}
	if payload, known := snap.verify(jws, "", "PS256"); payload != nil || !known {
		t.Fatal("an algorithm the issuer does not sign with is known-bad, never a refetch")
	}
	if payload, known := (*keySnapshot)(nil).verify(jws, "k1", "RS256"); payload != nil || known {
		t.Fatal("no snapshot verifies nothing")
	}
	if _, err := ks.verifySignature(t.Context(), "garbage", 0); err == nil {
		t.Fatal("an unparsable token must fail")
	}

	// Unknown kid while the provider is down and the gap has passed: the
	// fetch fails, and the outcome says unavailable (503), not bad.
	stranger := env.iss.NewKey(t, jose.RS256)
	env.iss.FailJWKS.Store(true)
	env.clock.Advance(2 * time.Minute)
	outcome := &verifyOutcome{}
	ctx := context.WithValue(t.Context(), outcomeKey{}, outcome)
	token := env.iss.MintWith(t, env.claims("x"), identitytest.MintOptions{Key: &stranger})
	if _, err := ks.verifySignature(ctx, token, env.v.opts.KeyWait); err == nil || !outcome.unavailable {
		t.Fatalf("unknown kid, provider down: err %v outcome %+v", err, outcome)
	}
}
