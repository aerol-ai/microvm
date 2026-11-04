package identitytest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func get(t *testing.T, iss *Issuer, path string) (int, []byte) {
	t.Helper()
	resp, err := iss.Client().Get(iss.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestIssuerDocuments(t *testing.T) {
	iss := New(t)
	code, body := get(t, iss, "/.well-known/openid-configuration")
	var disc map[string]any
	if code != http.StatusOK || json.Unmarshal(body, &disc) != nil || disc["issuer"] != iss.URL || disc["jwks_uri"] != iss.URL+"/jwks" {
		t.Fatalf("discovery %d %s", code, body)
	}
	code, body = get(t, iss, "/jwks")
	var set jose.JSONWebKeySet
	if code != http.StatusOK || json.Unmarshal(body, &set) != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != iss.SigningKey().ID {
		t.Fatalf("jwks %d %s", code, body)
	}
	if iss.DiscoveryHits.Load() != 1 || iss.JWKSHits.Load() != 1 {
		t.Fatal("hits not counted")
	}

	iss.SetAlgs("ES256")
	iss.SetDiscoveredIssuer("https://other")
	_, body = get(t, iss, "/.well-known/openid-configuration")
	if !strings.Contains(string(body), `"issuer":"https://other"`) || !strings.Contains(string(body), `["ES256"]`) {
		t.Fatalf("overridden discovery %s", body)
	}
	iss.SetDiscoveryBody([]byte(`{"x":1}`))
	iss.SetJWKSBody([]byte(`{"keys":[]}`))
	if _, body = get(t, iss, "/.well-known/openid-configuration"); string(body) != `{"x":1}` {
		t.Fatalf("discovery body override %s", body)
	}
	if _, body = get(t, iss, "/jwks"); string(body) != `{"keys":[]}` {
		t.Fatalf("jwks body override %s", body)
	}
	iss.FailDiscovery.Store(true)
	iss.FailJWKS.Store(true)
	if code, _ = get(t, iss, "/.well-known/openid-configuration"); code != http.StatusServiceUnavailable {
		t.Fatalf("failing discovery %d", code)
	}
	if code, _ = get(t, iss, "/jwks"); code != http.StatusServiceUnavailable {
		t.Fatalf("failing jwks %d", code)
	}
}

func TestIssuerKeysAndMinting(t *testing.T) {
	iss := New(t)
	now := time.Unix(1_800_000_000, 0)
	claims := iss.Claims(now, "aud", "00u1", "g1")
	if claims["iss"] != iss.URL || claims["exp"] != now.Add(time.Hour).Unix() || claims["email"] != "00u1@acme.com" {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := iss.Claims(now, "aud", "x")["groups"]; ok {
		t.Fatal("no groups asked, none set")
	}
	for _, alg := range []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA} {
		key := iss.Rotate(t, alg)
		if iss.SigningKey().ID != key.ID || key.Public().Algorithm != string(alg) {
			t.Fatalf("rotate %s", alg)
		}
		token := iss.Mint(t, claims)
		jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{alg})
		if err != nil {
			t.Fatal(err)
		}
		if jws.Signatures[0].Header.KeyID != key.ID {
			t.Fatalf("kid = %q", jws.Signatures[0].Header.KeyID)
		}
		if _, err := jws.Verify(key.Private.Public()); err != nil {
			t.Fatalf("%s token does not verify: %v", alg, err)
		}
	}
	other := iss.NewKey(t, jose.RS256)
	iss.Publish(other)
	var set jose.JSONWebKeySet
	_ = json.Unmarshal(iss.JWKS(), &set)
	if len(set.Keys) != 1 || set.Keys[0].KeyID != other.ID {
		t.Fatalf("published %+v", set.Keys)
	}
	token := iss.MintWith(t, claims, MintOptions{Key: &other, NoKeyID: true, Headers: map[jose.HeaderKey]any{"jku": "https://x"}})
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || jws.Signatures[0].Header.KeyID != "" || jws.Signatures[0].Protected.ExtraHeaders["jku"] != "https://x" {
		t.Fatalf("MintWith: %v %+v", err, jws)
	}
	hmac := MintHMAC(t, claims, []byte(strings.Repeat("s", 32)), "k")
	if _, err := jose.ParseSigned(hmac, []jose.SignatureAlgorithm{jose.HS256}); err != nil {
		t.Fatalf("hmac token: %v", err)
	}
	unsigned := Unsigned(map[string]any{"alg": "none"}, claims)
	if !strings.HasSuffix(unsigned, ".") || strings.Count(unsigned, ".") != 2 {
		t.Fatalf("unsigned = %q", unsigned)
	}
}
