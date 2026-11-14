package cloudidentity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	testKeysOnce sync.Once
	testKeys     []*rsa.PrivateKey
)

// keys generates a few RSA keys once: generation is the slow part of these
// tests.
func keys(t *testing.T, n int) []*rsa.PrivateKey {
	t.Helper()
	testKeysOnce.Do(func() {
		for i := 0; i < 4; i++ {
			k, err := GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			testKeys = append(testKeys, k)
		}
	})
	return testKeys[:n]
}

// fakeSeal stands in for the secrets cipher: it prefixes the AAD, so a test
// can check the AAD binds the key id.
func fakeSeal(plain, aad []byte) ([]byte, error) {
	return append(append(append([]byte{}, aad...), '|'), plain...), nil
}

func record(t *testing.T, key *rsa.PrivateKey, now time.Time) KeyRecord {
	t.Helper()
	rec, err := NewKeyRecord(key, now, fakeSeal)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestValidateIssuerURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"https://api.example.com", "https://api.example.com", true},
		{"https://API.Example.com/", "https://api.example.com", true},
		{" https://api.example.com:8443 ", "https://api.example.com:8443", true},
		{"http://api.example.com", "", false},
		{"https://api.example.com/identity", "", false},
		{"https://api.example.com?x=1", "", false},
		{"https://api.example.com#f", "", false},
		{"https://user@api.example.com", "", false},
		{"https://", "", false},
		{"", "", false},
		{"::", "", false},
	} {
		got, err := ValidateIssuerURL(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ValidateIssuerURL(%q) = %q, %v; want %q ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrIssuerURL) {
			t.Errorf("ValidateIssuerURL(%q) error %v is not ErrIssuerURL", tc.in, err)
		}
	}
}

func TestDiscoveryNamesTheJWKS(t *testing.T) {
	raw, err := Discovery("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "https://api.example.com" || doc["jwks_uri"] != "https://api.example.com/.well-known/jwks.json" {
		t.Fatalf("discovery = %s", raw)
	}
	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Fatalf("algorithms = %v, want [RS256]", algs)
	}
}

func TestRoleTagAndAudience(t *testing.T) {
	for _, tc := range []struct {
		tag string
		ok  bool
	}{
		{"deploy", true}, {"a", true}, {"ci_runner-2", true}, {strings.Repeat("a", 63), true},
		{"", false}, {"-x", false}, {"_x", false}, {"Deploy", false}, {"a:b", false},
		{"a b", false}, {strings.Repeat("a", 64), false}, {"a/b", false},
	} {
		if err := ValidateRoleTag(tc.tag); (err == nil) != tc.ok {
			t.Errorf("ValidateRoleTag(%q) = %v, want ok=%v", tc.tag, err, tc.ok)
		}
	}
	for _, tc := range []struct {
		aud string
		ok  bool
	}{
		{"sts.amazonaws.com", true}, {"api://AzureADTokenExchange", true},
		{"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aerol", true},
		{"", false}, {"a b", false}, {"a\nb", false}, {strings.Repeat("a", 257), false}, {"é", false},
	} {
		if err := ValidateAudience(tc.aud); (err == nil) != tc.ok {
			t.Errorf("ValidateAudience(%q) = %v, want ok=%v", tc.aud, err, tc.ok)
		}
	}
}

func TestRequestValidateAndEnv(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:role/sandbox-deploy"
	const guid = "0b7a3c2e-1f4d-4a5b-9c8d-7e6f5a4b3c2d"
	for _, tc := range []struct {
		name    string
		req     Request
		ok      bool
		wantEnv map[string]string
	}{
		{"tag only", Request{RoleTag: " deploy "}, true, map[string]string{EnvTokenFile: TokenFile}},
		{"aws", Request{RoleTag: "deploy", AWSRoleARN: arn}, true, map[string]string{
			EnvTokenFile: TokenFile, EnvAWSTokenFile: TokenFile, EnvAWSRoleARN: arn}},
		{"aws gov path", Request{RoleTag: "deploy", AWSRoleARN: "arn:aws-us-gov:iam::123456789012:role/team/x"}, true, nil},
		{"azure", Request{RoleTag: "deploy", AzureClientID: guid, AzureTenantID: guid}, true, map[string]string{
			EnvTokenFile: TokenFile, EnvAzureTokenFile: TokenFile, EnvAzureClientID: guid, EnvAzureTenantID: guid}},
		{"bad tag", Request{RoleTag: "A:B"}, false, nil},
		{"bad audience", Request{RoleTag: "x", Audience: "a b"}, false, nil},
		{"bad arn", Request{RoleTag: "x", AWSRoleARN: "arn:aws:iam::12:role/x"}, false, nil},
		{"user arn", Request{RoleTag: "x", AWSRoleARN: "arn:aws:iam::123456789012:user/x"}, false, nil},
		{"azure half", Request{RoleTag: "x", AzureClientID: guid}, false, nil},
		{"azure not guid", Request{RoleTag: "x", AzureClientID: "abc", AzureTenantID: guid}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req.Normalize()
			err := req.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v is not ErrInvalid", err)
			}
			if req.Audience != DefaultAudience && tc.req.Audience == "" {
				t.Fatalf("audience = %q, want the default", req.Audience)
			}
			if tc.wantEnv != nil {
				got := req.Env()
				if len(got) != len(tc.wantEnv) {
					t.Fatalf("env = %v, want %v", got, tc.wantEnv)
				}
				for k, v := range tc.wantEnv {
					if got[k] != v {
						t.Fatalf("env[%s] = %q, want %q", k, got[k], v)
					}
				}
			}
		})
	}
}

// Point 6: distinct owners never share a subject, whatever their names.
func TestSubjectOwnersNeverCollide(t *testing.T) {
	owners := []string{
		"", "team:payments", "team:operator", "operator", "team:a-b", "account:x", "x",
		"team:Upper", "team:a:b", "a:b", "a%3Ab", "a_b", "team:", "acct.1-x",
	}
	seen := map[string]string{}
	for _, o := range owners {
		sub := Subject(o, "deploy")
		if prev, dup := seen[sub]; dup {
			t.Fatalf("owners %q and %q share subject %q", prev, o, sub)
		}
		seen[sub] = o
	}
	for _, tc := range []struct{ owner, sub, team string }{
		{"team:payments", "team:payments:role:deploy", "payments"},
		{"", "operator:role:deploy", ""},
		{"team:operator", "team:operator:role:deploy", "operator"},
		{"acme", "account:acme:role:deploy", ""},
		{"a:b", "account:a%3Ab:role:deploy", ""},
		{"team:Upper", "account:team%3AUpper:role:deploy", ""},
	} {
		if got := Subject(tc.owner, "deploy"); got != tc.sub {
			t.Errorf("Subject(%q) = %q, want %q", tc.owner, got, tc.sub)
		}
		if _, team := SubjectOwner(tc.owner); team != tc.team {
			t.Errorf("SubjectOwner(%q) team = %q, want %q", tc.owner, team, tc.team)
		}
	}
}

func TestIssueVerifiesWithTheJWKS(t *testing.T) {
	k := keys(t, 2)
	now := time.Unix(1_800_000_000, 0)
	rec := record(t, k[0], now)
	signer := Signer{KeyID: rec.ID, Key: k[0]}
	tok, err := signer.Issue(IssueRequest{
		Issuer: "https://api.example.com", OwnerRef: "team:payments", SandboxID: "sb-1",
		RoleTag: "deploy", Audience: DefaultAudience, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := tok.Claims
	if c.Subject != "team:payments:role:deploy" || c.Team != "payments" || c.Role != "deploy" || c.Sandbox != "sb-1" ||
		c.Audience != DefaultAudience || c.Issuer != "https://api.example.com" || len(c.ID) != 32 {
		t.Fatalf("claims = %+v", c)
	}
	if c.IssuedAt != now.Unix() || c.NotBefore != now.Unix()-60 || c.Expiry != now.Unix()+3600 {
		t.Fatalf("times iat=%d nbf=%d exp=%d", c.IssuedAt, c.NotBefore, c.Expiry)
	}
	if !tok.Expires().Equal(now.Add(time.Hour)) || tok.KeyID != rec.ID {
		t.Fatalf("token meta = %v %s", tok.Expires(), tok.KeyID)
	}
	header, _, _ := strings.Cut(tok.Raw, ".")
	hb, _ := base64.RawURLEncoding.DecodeString(header)
	var h map[string]string
	_ = json.Unmarshal(hb, &h)
	if h["alg"] != "RS256" || h["kid"] != rec.ID || h["typ"] != "JWT" {
		t.Fatalf("header = %s", hb)
	}

	jwks, err := JWKS([]KeyRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(jwks, []byte(`"d"`)) || bytes.Contains(jwks, []byte(`"p"`)) {
		t.Fatalf("JWKS carries private material: %s", jwks)
	}
	got, err := Verify(tok.Raw, jwks, now.Add(30*time.Minute))
	if err != nil || got != c {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	// Clock skew: a cloud 59 s behind accepts it; expiry is final.
	if _, err := Verify(tok.Raw, jwks, now.Add(-59*time.Second)); err != nil {
		t.Fatalf("skewed verify: %v", err)
	}
	for name, at := range map[string]time.Time{"expired": now.Add(time.Hour), "early": now.Add(-61 * time.Second)} {
		if _, err := Verify(tok.Raw, jwks, at); err == nil {
			t.Fatalf("%s token verified", name)
		}
	}
	// Another key's JWKS does not verify it.
	other, _ := JWKS([]KeyRecord{record(t, k[1], now)})
	if _, err := Verify(tok.Raw, other, now); err == nil {
		t.Fatal("token verified with another key's JWKS")
	}
	// A tampered payload does not verify.
	parts := strings.Split(tok.Raw, ".")
	forged, _ := json.Marshal(Claims{Subject: "team:other:role:deploy", NotBefore: 0, Expiry: now.Unix() + 10})
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)
	if _, err := Verify(strings.Join(parts, "."), jwks, now); err == nil {
		t.Fatal("forged token verified")
	}
}

func TestIssueRefusesBadInput(t *testing.T) {
	k := keys(t, 1)
	now := time.Now()
	good := IssueRequest{Issuer: "https://i", SandboxID: "sb", RoleTag: "r", Audience: "a", Now: now}
	for name, tc := range map[string]struct {
		s   Signer
		req IssueRequest
	}{
		"no key":    {Signer{}, good},
		"no issuer": {Signer{KeyID: "k", Key: k[0]}, IssueRequest{SandboxID: "sb", RoleTag: "r", Audience: "a"}},
		"bad tag":   {Signer{KeyID: "k", Key: k[0]}, IssueRequest{Issuer: "https://i", SandboxID: "sb", RoleTag: "R", Audience: "a"}},
		"bad aud":   {Signer{KeyID: "k", Key: k[0]}, IssueRequest{Issuer: "https://i", SandboxID: "sb", RoleTag: "r", Audience: ""}},
		"rand fail": {Signer{KeyID: "k", Key: k[0]}, IssueRequest{Issuer: "https://i", SandboxID: "sb", RoleTag: "r", Audience: "a", Rand: bytes.NewReader(nil)}},
	} {
		if _, err := tc.s.Issue(tc.req); err == nil {
			t.Errorf("%s: Issue succeeded", name)
		}
	}
}

func TestVerifyRefusesMalformed(t *testing.T) {
	for name, tc := range map[string]struct{ raw, jwks string }{
		"bad jwks":  {"a.b.c", "{"},
		"bad token": {"not-a-jwt", `{"keys":[]}`},
		"no kid":    {"eyJhbGciOiJSUzI1NiJ9.e30.AA", `{"keys":[]}`},
	} {
		if _, err := Verify(tc.raw, []byte(tc.jwks), time.Now()); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestKeyRecordRoundTrip(t *testing.T) {
	k := keys(t, 1)[0]
	rec := record(t, k, time.Unix(10, 0))
	prefix := append(SealAAD(rec.ID), '|')
	if !bytes.HasPrefix(rec.SealedPrivate, prefix) {
		t.Fatal("sealed key is not bound to its key id")
	}
	parsed, err := ParsePrivateKey(rec.SealedPrivate[len(prefix):])
	if err != nil || !parsed.Equal(k) {
		t.Fatalf("ParsePrivateKey = %v", err)
	}
	if _, err := ParsePrivateKey([]byte("junk")); err == nil {
		t.Fatal("junk parsed")
	}
	if _, err := NewKeyRecord(k, time.Now(), func([]byte, []byte) ([]byte, error) { return nil, errors.New("sealed") }); err == nil {
		t.Fatal("seal failure ignored")
	}
	if _, err := MarshalPrivateKey(nil); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("MarshalPrivateKey(nil) = %v", err)
	}
	if _, err := PublicJWK(nil, "x"); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("PublicJWK(nil) = %v", err)
	}
	if _, err := KeyID(nil); err == nil {
		t.Fatal("KeyID(nil) succeeded")
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := MarshalPrivateKey(weak); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak key marshalled: %v", err)
	}
	if _, err := PublicJWK(&weak.PublicKey, "x"); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak public key encoded: %v", err)
	}
	if id1, _ := KeyID(&k.PublicKey); id1 != rec.ID {
		t.Fatalf("kid not stable: %s vs %s", id1, rec.ID)
	}
	clone := rec.Clone()
	clone.SealedPrivate[0] ^= 0xff
	if rec.SealedPrivate[0] == clone.SealedPrivate[0] {
		t.Fatal("Clone shares bytes")
	}
}

func TestKeySetRotationAndPublishing(t *testing.T) {
	k := keys(t, 3)
	t0 := time.Unix(1_800_000_000, 0)
	a := record(t, k[0], t0)
	set := KeySet{Generation: 1, Keys: []KeyRecord{a}}
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (KeySet{}).Validate(); err != nil {
		t.Fatalf("empty set invalid: %v", err)
	}
	t1 := t0.Add(time.Minute)
	b := record(t, k[1], t1)
	rotated, err := set.Rotate(b, t1)
	if err != nil {
		t.Fatal(err)
	}
	if active, ok := rotated.Active(); !ok || active.ID != b.ID {
		t.Fatalf("active = %v", active.ID)
	}
	if pub := rotated.Published(t1.Add(119 * time.Minute)); len(pub) != 2 || pub[0].ID != b.ID || pub[1].ID != a.ID {
		t.Fatalf("published at +119m = %v", ids(pub))
	}
	if pub := rotated.Published(t1.Add(2 * time.Hour)); len(pub) != 1 || pub[0].ID != b.ID {
		t.Fatalf("published at +2h = %v", ids(pub))
	}
	if set.Keys[0].RetiredUnixNano != 0 {
		t.Fatal("Rotate changed the set it was given")
	}
	// A rotation past the window drops the expired key from the set too.
	c := record(t, k[2], t1.Add(3*time.Hour))
	again, err := rotated.Rotate(c, t1.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Keys) != 2 || again.Keys[0].ID != b.ID || again.Keys[1].ID != c.ID {
		t.Fatalf("after second rotation keys = %v", ids(again.Keys))
	}
	if _, err := rotated.Rotate(KeyRecord{ID: "x", RetiredUnixNano: 1}, t1); err == nil {
		t.Fatal("rotated to a retired key")
	}
	if _, err := rotated.Rotate(b, t1); err == nil {
		t.Fatal("rotated to a key already in the set")
	}
	if _, ok := (KeySet{}).Active(); ok {
		t.Fatal("empty set has an active key")
	}
	jwks, err := JWKS(rotated.Published(t1))
	if err != nil || !bytes.Contains(jwks, []byte(a.ID)) || !bytes.Contains(jwks, []byte(b.ID)) {
		t.Fatalf("jwks = %s, %v", jwks, err)
	}
	if cl := rotated.Clone(); &cl.Keys[0] == &rotated.Keys[0] {
		t.Fatal("Clone shares keys")
	}
}

func TestKeySetValidateRefuses(t *testing.T) {
	k := keys(t, 2)
	now := time.Now()
	a, b := record(t, k[0], now), record(t, k[1], now)
	privJWK, _ := json.Marshal(map[string]string{"kty": "oct", "k": "AAAA"})
	many := KeySet{}
	for i := 0; i <= MaxKeys; i++ {
		r := a
		r.ID = string(rune('a' + i))
		many.Keys = append(many.Keys, r)
	}
	for name, set := range map[string]KeySet{
		"two active":  {Keys: []KeyRecord{a, b}},
		"none active": {Keys: []KeyRecord{withRetired(a, 1)}},
		"repeated id": {Keys: []KeyRecord{a, withRetired(a, 1)}},
		"no id":       {Keys: []KeyRecord{withID(a, "")}},
		"wrong id":    {Keys: []KeyRecord{withID(a, b.ID)}},
		"no sealed":   {Keys: []KeyRecord{{ID: a.ID, PublicJWK: a.PublicJWK}}},
		"bad jwk":     {Keys: []KeyRecord{{ID: a.ID, SealedPrivate: []byte{1}, PublicJWK: []byte("{")}}},
		"not rsa":     {Keys: []KeyRecord{{ID: a.ID, SealedPrivate: []byte{1}, PublicJWK: privJWK}}},
		"private jwk": {Keys: []KeyRecord{{ID: a.ID, SealedPrivate: []byte{1}, PublicJWK: privateJWK(t, k[0], a.ID)}}},
		"too many":    many,
	} {
		if err := set.Validate(); !errors.Is(err, ErrKeySetInvalid) {
			t.Errorf("%s: Validate = %v, want ErrKeySetInvalid", name, err)
		}
	}
	if _, err := JWKS([]KeyRecord{{ID: "x", PublicJWK: privJWK}}); err == nil {
		t.Fatal("JWKS published a non-RSA key")
	}
}

func privateJWK(t *testing.T, k *rsa.PrivateKey, kid string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"kty": "RSA", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": "AQAB",
		"d": base64.RawURLEncoding.EncodeToString(k.D.Bytes()),
		"p": base64.RawURLEncoding.EncodeToString(k.Primes[0].Bytes()),
		"q": base64.RawURLEncoding.EncodeToString(k.Primes[1].Bytes()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func withRetired(r KeyRecord, at int64) KeyRecord { r.RetiredUnixNano = at; return r }
func withID(r KeyRecord, id string) KeyRecord     { r.ID = id; return r }

func ids(keys []KeyRecord) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.ID
	}
	return out
}
