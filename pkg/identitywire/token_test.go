package identitywire

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func mustToken(t testing.TB) APIToken {
	t.Helper()
	tok, err := NewAPIToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestAPITokenRoundTrip: a minted token parses back to the same id and
// secret, matches the published scanner pattern, and has the fixed length.
func TestAPITokenRoundTrip(t *testing.T) {
	pattern := regexp.MustCompile(`^` + APITokenPattern + `$`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := mustToken(t)
		plain := tok.Plaintext()
		if len(plain) != APITokenLength || !pattern.MatchString(plain) {
			t.Fatalf("token %q: length %d, pattern match %v", plain, len(plain), pattern.MatchString(plain))
		}
		got, err := ParseAPIToken(plain)
		if err != nil || got != tok {
			t.Fatalf("parse(%q) = %+v, %v; want %+v", plain, got, err, tok)
		}
		if !ValidAPITokenID(tok.ID) || !LooksLikeAPIToken(plain) {
			t.Fatalf("id %q or token not recognised", tok.ID)
		}
		if seen[tok.ID] {
			t.Fatalf("duplicate id %s in 200 draws", tok.ID)
		}
		seen[tok.ID] = true
		if h := tok.SecretHash(); h != HashAPITokenSecret(tok.Secret) {
			t.Fatal("SecretHash must be SHA-256 of the secret")
		}
	}
}

// TestParseAPITokenRefusesMalformed is the checksum-before-lookup contract:
// every corruption of a real token is refused by shape or checksum alone.
func TestParseAPITokenRefusesMalformed(t *testing.T) {
	plain := mustToken(t).Plaintext()
	flip := func(i int) string {
		b := []byte(plain)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	cases := map[string]string{
		"empty":                "",
		"prefix only":          "avm_",
		"short":                plain[:len(plain)-1],
		"long":                 plain + "x",
		"wrong prefix":         "avx_" + plain[4:],
		"id character flipped": flip(idStart + 3),
		"secret flipped":       flip(secretOff + 10),
		"checksum flipped":     flip(crcOff + 2),
		"missing separator":    plain[:secretSep] + "x" + plain[secretSep+1:],
		"id not base62":        plain[:idStart] + "-" + plain[idStart+1:],
		"crc not base62":       plain[:crcOff] + "_" + plain[crcOff+1:],
		"secret bad char":      plain[:secretOff] + "+" + plain[secretOff+1:],
		"uppercase prefix":     "AVM_" + plain[4:],
		"surrounding space":    " " + plain[:len(plain)-1],
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAPIToken(s); !errors.Is(err, ErrMalformedAPIToken) {
				t.Fatalf("ParseAPIToken(%q) err = %v, want malformed", s, err)
			}
		})
	}
	// A secret whose last character carries non-zero trailing bits decodes
	// to the same bytes as the canonical one; only one encoding is valid.
	body := plain[:crcSep]
	last := body[len(body)-1]
	alt := strings.IndexByte("AEIMQUYcgkosw048", last)
	if alt >= 0 {
		noncanon := body[:len(body)-1] + string("BFJNRVZdhlptx159"[alt]) // same top bits, a low bit set
		forged := noncanon + "_" + checksum(noncanon)
		if _, err := ParseAPIToken(forged); !errors.Is(err, ErrMalformedAPIToken) {
			t.Fatalf("non-canonical secret accepted: %v", err)
		}
	}
}

func TestAPITokenRedaction(t *testing.T) {
	tok := mustToken(t)
	for _, s := range []string{tok.String(), fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok)} {
		if strings.Contains(s, tok.Secret) {
			t.Fatalf("%q leaks the secret", s)
		}
		if !strings.Contains(s, "[REDACTED]") {
			t.Fatalf("%q is not marked redacted", s)
		}
	}
}

func TestNewAPITokenEntropySourceErrors(t *testing.T) {
	if _, err := NewAPIToken(iotest.ErrReader(errors.New("no entropy"))); err == nil {
		t.Fatal("an id read failure must fail the mint")
	}
	// Enough bytes for the id (all < 248) but none for the secret.
	if _, err := NewAPIToken(bytes.NewReader(bytes.Repeat([]byte{1}, 32))); err == nil {
		t.Fatal("a secret read failure must fail the mint")
	}
	// Rejection sampling skips bytes >= 248 and keeps drawing.
	src := append(bytes.Repeat([]byte{255}, 32), bytes.Repeat([]byte{61}, 32)...)
	src = append(src, bytes.Repeat([]byte{7}, 32)...)
	tok, err := NewAPIToken(bytes.NewReader(src))
	if err != nil || tok.ID != "tok_zzzzzzzzzzzz" {
		t.Fatalf("rejection sampling: %+v, %v", tok, err)
	}
}

func TestValidAPITokenIDAndIDFrom(t *testing.T) {
	tok := mustToken(t)
	cases := []struct {
		in     string
		wantID string
		ok     bool
	}{
		{tok.ID, tok.ID, true},
		{"  " + tok.ID + "\n", tok.ID, true},
		{tok.Plaintext(), tok.ID, true},
		{"tok_short", "", false},
		{"tok_" + strings.Repeat("a", 13), "", false},
		{"tok_aaaaaaaaaaa-", "", false},
		{"xok_aaaaaaaaaaaa", "", false},
		{tok.Plaintext()[:60] + "_zzzzzz", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		id, ok := APITokenIDFrom(tc.in)
		if id != tc.wantID || ok != tc.ok {
			t.Errorf("APITokenIDFrom(%q) = %q, %v; want %q, %v", tc.in, id, ok, tc.wantID, tc.ok)
		}
	}
}

func TestNameRules(t *testing.T) {
	tokenNames := map[string]bool{
		"ci-deploy": true, "CI.deploy_2": true, strings.Repeat("a", 64): true,
		"": false, strings.Repeat("a", 65): false, "has space": false, "ünï": false, "semi;colon": false, "new\nline": false,
	}
	for name, want := range tokenNames {
		if got := ValidTokenName(name); got != want {
			t.Errorf("ValidTokenName(%q) = %v, want %v", name, got, want)
		}
	}
	teams := map[string]bool{
		"payments": true, "team-2": true, strings.Repeat("a", 63): true,
		"": false, "*": false, "Payments": false, strings.Repeat("a", 64): false, "pay_ments": false, "pay.ments": false,
	}
	for team, want := range teams {
		if got := ValidTeamName(team); got != want {
			t.Errorf("ValidTeamName(%q) = %v, want %v", team, got, want)
		}
	}
}

func TestParseTokenTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"90d", 90 * 24 * time.Hour, true},
		{" 1d ", 24 * time.Hour, true},
		{"720h", 720 * time.Hour, true},
		{"1h30m", 90 * time.Minute, true},
		{"0d", 0, false},
		{"-3d", 0, false},
		{"0s", 0, false},
		{"-1h", 0, false},
		{"", 0, false},
		{"d", 0, false},
		{"1.5d", 0, false},
		{"1h30d", 0, false},
		{"forever", 0, false},
		{"99999999d", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseTokenTTL(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseTokenTTL(%q) = %v, %v; want %v ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

// FuzzParseAPIToken (CEO review D21): no input panics, and anything the
// parser accepts is canonical, so formatting it back gives the same string.
func FuzzParseAPIToken(f *testing.F) {
	for i := 0; i < 4; i++ {
		tok, err := NewAPIToken(rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(tok.Plaintext())
	}
	f.Add("")
	f.Add("avm_")
	f.Add("avm_" + strings.Repeat("_", APITokenLength-4))
	f.Add(strings.Repeat("\x00", APITokenLength))
	f.Fuzz(func(t *testing.T, s string) {
		tok, err := ParseAPIToken(s)
		if err != nil {
			if !errors.Is(err, ErrMalformedAPIToken) {
				t.Fatalf("unexpected error type %v", err)
			}
			return
		}
		if tok.Plaintext() != s {
			t.Fatalf("accepted %q but formats back as %q", s, tok.Plaintext())
		}
		if !ValidAPITokenID(tok.ID) {
			t.Fatalf("accepted token with invalid id %q", tok.ID)
		}
	})
}
