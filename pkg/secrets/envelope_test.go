package secrets

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

type failRand struct {
	n   int
	err error
}

func (f *failRand) Read(p []byte) (int, error) {
	f.n++
	if f.err != nil && f.n >= 1 {
		return 0, f.err
	}
	for i := range p {
		p[i] = 1
	}
	return len(p), nil
}

type failAfterRand struct {
	calls  int
	failAt int
}

func (f *failAfterRand) Read(p []byte) (int, error) {
	f.calls++
	if f.calls >= f.failAt {
		return 0, errors.New("entropy exhausted")
	}
	for i := range p {
		p[i] = byte(f.calls)
	}
	return len(p), nil
}

func TestSealOpenEnvelopeRoundTripAndEmpty(t *testing.T) {
	c := testCipher(t)
	empty, err := SealEnvelope(c, Secrets{}, []string{"node-a"})
	if err != nil || empty != nil {
		t.Fatalf("empty SealEnvelope = %v %v", empty, err)
	}
	if _, err := SealEnvelope(nil, Secrets{Registry: &models.RegistryAuth{Password: "p"}}, nil); err == nil {
		t.Fatal("nil cipher should fail")
	}

	sealed, err := SealEnvelope(c, Secrets{
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "pw"},
	}, []string{" node-b ", "node-a", "node-b"})
	if err != nil || len(sealed) == 0 {
		t.Fatalf("SealEnvelope: %v", err)
	}
	got, err := OpenEnvelope(c, sealed, "node-a")
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if got.Registry == nil || got.Registry.Password != "pw" {
		t.Fatalf("got = %+v", got.Registry)
	}
	if _, err := OpenEnvelope(c, sealed, "node-z"); !errors.Is(err, ErrRecipientDenied) {
		t.Fatalf("wrong recipient = %v", err)
	}
	emptyOpen, err := OpenEnvelope(c, nil, "node-a")
	if err != nil || emptyOpen.Registry != nil {
		t.Fatalf("empty OpenEnvelope = %+v %v", emptyOpen, err)
	}
}

func TestOpenRawEnvelopeV2AndLegacy(t *testing.T) {
	c := testCipher(t)
	plain := []byte(`{"registry":{"password":"v2-pass"}}`)
	payload, err := c.EncryptWithAAD(plain, V2AAD([]string{"*"}))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := json.Marshal(sealedSecretsEnvelope{
		Version: 2, Recipients: []string{"*"}, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRawEnvelope(c, v2, "")
	if err != nil || string(got) != string(plain) {
		t.Fatalf("v2 open = %q %v", got, err)
	}
	if aad := string(V2AAD([]string{"b", "a"})); aad == "" || aad[:len("aerolvm-cluster-secrets-v2")] != "aerolvm-cluster-secrets-v2" {
		t.Fatalf("V2AAD = %q", aad)
	}

	legacyPlain := []byte("legacy-raw")
	raw, err := c.Encrypt(legacyPlain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := OpenRawEnvelope(c, raw, "any")
	if err != nil || string(out) != string(legacyPlain) {
		t.Fatalf("legacy open = %q %v", out, err)
	}
}

func TestOpenRawEnvelopeErrorBranches(t *testing.T) {
	c := testCipher(t)
	if _, err := OpenRawEnvelope(nil, []byte("x"), ""); err == nil {
		t.Fatal("nil cipher")
	}
	if _, err := OpenRawEnvelope(c, []byte(`{"version":3,"recipients":["*"],"payload":"YQ=="}`), ""); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("missing wrapped key = %v", err)
	}
	if _, err := OpenEnvelopePayload([]byte("short"), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []string{"*"}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad dek = %v", err)
	}
	dek := make([]byte, 32)
	if _, err := OpenEnvelopePayload(dek, []byte{1, 2, 3}, []string{"*"}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("short payload = %v", err)
	}
}

func TestNormalizeRecipients(t *testing.T) {
	got := NormalizeRecipients([]string{" node-b ", "node-a", "node-b", "", "node-c"})
	if len(got) != 3 || got[0] != "node-a" || got[1] != "node-b" || got[2] != "node-c" {
		t.Fatalf("NormalizeRecipients = %#v", got)
	}
	if got := NormalizeRecipients(nil); len(got) != 1 || got[0] != "*" {
		t.Fatalf("nil recipients = %#v", got)
	}
}

func TestSealRawEnvelopeEntropyFailures(t *testing.T) {
	c := testCipher(t)
	old := rand.Reader
	t.Cleanup(func() { rand.Reader = old })

	rand.Reader = &failRand{err: errors.New("dek fail")}
	if _, err := SealRawEnvelope(c, []byte(`{}`), []string{"*"}); err == nil {
		t.Fatal("expected dek entropy failure")
	}
	rand.Reader = &failAfterRand{failAt: 2}
	if _, err := SealRawEnvelope(c, []byte(`{}`), []string{"*"}); err == nil {
		t.Fatal("expected nonce entropy failure")
	}
	if _, err := SealRawEnvelope(nil, []byte(`{}`), nil); err == nil {
		t.Fatal("nil cipher SealRawEnvelope")
	}
	if _, err := SealRawEnvelope(&Cipher{}, []byte(`{}`), []string{"*"}); err == nil {
		t.Fatal("uninitialized cipher wrap should fail")
	}
}

func TestOpenEnvelopeBadJSONAndDecryptFailures(t *testing.T) {
	c := testCipher(t)
	if _, err := OpenEnvelope(c, []byte("not-json"), ""); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad json = %v", err)
	}
	// Valid v3 envelope JSON with garbage wrapped key → unwrap fails.
	env, err := json.Marshal(sealedSecretsEnvelope{
		Version: EnvelopeVersion, Recipients: []string{"*"},
		WrappedKey: []byte("short"), Payload: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRawEnvelope(c, env, ""); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad wrapped key = %v", err)
	}
	// v2 envelope with bad ciphertext.
	v2, err := json.Marshal(sealedSecretsEnvelope{
		Version: 2, Recipients: []string{"*"}, Payload: []byte("tiny"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRawEnvelope(c, v2, ""); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad v2 = %v", err)
	}
	if _, err := OpenRawEnvelope(c, []byte("not-an-envelope"), ""); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("legacy decrypt fail = %v", err)
	}

	// Seal then open with wrong payload AAD by tampering recipients field only
	// (keeps ciphertext but breaks recipient binding on open).
	sealed, err := SealEnvelope(c, Secrets{Registry: &models.RegistryAuth{Password: "x"}}, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	var wire sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Recipients = []string{"node-a", "node-extra"}
	tampered, _ := json.Marshal(wire)
	if _, err := OpenRawEnvelope(c, tampered, "node-a"); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered recipients = %v", err)
	}
}

func TestEnvelopeRecipients(t *testing.T) {
	c := testCipher(t)
	sealed, err := SealEnvelope(c, Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"node-b", "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := EnvelopeRecipients(sealed)
	if err != nil {
		t.Fatalf("EnvelopeRecipients: %v", err)
	}
	want := NormalizeRecipients([]string{"node-a", "node-b"})
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if _, err := EnvelopeRecipients(nil); err == nil {
		t.Fatal("empty sealed should error")
	}
	if _, err := EnvelopeRecipients([]byte(`{"version":3}`)); err == nil {
		t.Fatal("missing payload should error")
	}
}

func TestOpenEnvelopePayloadGCMOpenFailure(t *testing.T) {
	c := testCipher(t)
	sealed, err := SealRawEnvelope(c, []byte(`{"x":1}`), []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	var env sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	dek, err := c.DecryptWithAAD(env.WrappedKey, KeyAAD([]string{"*"}))
	if err != nil {
		t.Fatal(err)
	}
	env.Payload[len(env.Payload)-1] ^= 0xff
	if _, err := OpenEnvelopePayload(dek, env.Payload, []string{"*"}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered payload = %v", err)
	}
}
