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

func testBinding() SealBinding {
	return SealBinding{SandboxID: "sb-1", Ref: FormatRef("sb-1", RefVersion), Version: RefVersion, Generation: 1}
}

func TestSealOpenEnvelopeBoundRoundTripAndEmpty(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	empty, err := SealEnvelopeBound(c, Secrets{}, []string{"node-a"}, binding)
	if err != nil || empty != nil {
		t.Fatalf("empty SealEnvelopeBound = %v %v", empty, err)
	}
	if _, err := SealEnvelopeBound(nil, Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"node-a"}, binding); err == nil {
		t.Fatal("nil cipher should fail")
	}

	sealed, err := SealEnvelopeBound(c, Secrets{
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "pw"},
	}, []string{" node-b ", "node-a", "node-b"}, binding)
	if err != nil || len(sealed) == 0 {
		t.Fatalf("SealEnvelopeBound: %v", err)
	}
	got, err := OpenEnvelopeBound(c, sealed, "node-a", binding)
	if err != nil {
		t.Fatalf("OpenEnvelopeBound: %v", err)
	}
	if got.Registry == nil || got.Registry.Password != "pw" {
		t.Fatalf("got = %+v", got.Registry)
	}
	if _, err := OpenEnvelopeBound(c, sealed, "node-z", binding); !errors.Is(err, ErrRecipientDenied) {
		t.Fatalf("wrong recipient = %v", err)
	}
	emptyOpen, err := OpenEnvelopeBound(c, nil, "node-a", binding)
	if err != nil || emptyOpen.Registry != nil {
		t.Fatalf("empty OpenEnvelopeBound = %+v %v", emptyOpen, err)
	}
}

func TestEnvelopeRejectsDowngradeAndUnboundInputs(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	for _, sealed := range [][]byte{
		[]byte(`{"version":3,"recipients":["node-a"],"wrapped_key":"YQ==","payload":"YQ=="}`),
		[]byte(`{"version":2,"recipients":["node-a"],"payload":"YQ=="}`),
		[]byte("legacy-raw"),
	} {
		if _, err := OpenRawEnvelopeBound(c, sealed, "node-a", binding); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("downgrade payload error = %v", err)
		}
	}
	if _, err := SealRawEnvelopeBound(c, []byte(`{}`), nil, binding); err == nil {
		t.Fatal("empty recipient set should fail")
	}
	if _, err := SealRawEnvelopeBound(c, []byte(`{}`), []string{"*"}, binding); err == nil {
		t.Fatal("wildcard recipient should fail")
	}
	if _, err := SealRawEnvelopeBound(c, []byte(`{}`), []string{"node-a"}, SealBinding{}); err == nil {
		t.Fatal("missing binding should fail")
	}
	if RecipientAllowed([]string{"*"}, "node-a") {
		t.Fatal("wildcard recipient must never authorize a node")
	}
}

func TestOpenRawEnvelopeBoundErrorBranches(t *testing.T) {
	binding := testBinding()
	if _, err := OpenRawEnvelopeBound(nil, []byte("x"), "node-a", binding); err == nil {
		t.Fatal("nil cipher")
	}
	if _, err := OpenEnvelopePayloadBound([]byte("short"), make([]byte, 13), []string{"node-a"}, binding); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad dek = %v", err)
	}
	if _, err := OpenEnvelopePayloadBound(make([]byte, 32), []byte{1, 2, 3}, []string{"node-a"}, binding); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("short payload = %v", err)
	}
}

func TestNormalizeRecipients(t *testing.T) {
	got := NormalizeRecipients([]string{" node-b ", "node-a", "node-b", "", "node-c"})
	if len(got) != 3 || got[0] != "node-a" || got[1] != "node-b" || got[2] != "node-c" {
		t.Fatalf("NormalizeRecipients = %#v", got)
	}
	if got := NormalizeRecipients(nil); len(got) != 0 {
		t.Fatalf("nil recipients = %#v", got)
	}
}

func TestSealRawEnvelopeEntropyFailures(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	old := rand.Reader
	t.Cleanup(func() { rand.Reader = old })

	rand.Reader = &failRand{err: errors.New("dek fail")}
	if _, err := SealRawEnvelopeBound(c, []byte(`{}`), []string{"node-a"}, binding); err == nil {
		t.Fatal("expected dek entropy failure")
	}
	rand.Reader = &failAfterRand{failAt: 2}
	if _, err := SealRawEnvelopeBound(c, []byte(`{}`), []string{"node-a"}, binding); err == nil {
		t.Fatal("expected nonce entropy failure")
	}
	if _, err := SealRawEnvelopeBound(nil, []byte(`{}`), []string{"node-a"}, binding); err == nil {
		t.Fatal("nil cipher SealRawEnvelopeBound")
	}
	if _, err := SealRawEnvelopeBound(&Cipher{}, []byte(`{}`), []string{"node-a"}, binding); err == nil {
		t.Fatal("uninitialized cipher wrap should fail")
	}
}

func TestOpenEnvelopeBadJSONAndDecryptFailures(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	if _, err := OpenEnvelopeBound(c, []byte("not-json"), "node-a", binding); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad json = %v", err)
	}
	// Valid v4 envelope JSON with garbage wrapped key → unwrap fails.
	env, err := json.Marshal(sealedSecretsEnvelope{
		Version: EnvelopeVersion, Recipients: []string{"node-a"}, SandboxID: binding.SandboxID,
		Ref: binding.Ref, RefVersion: binding.Version, Generation: binding.Generation,
		WrappedKey: []byte("short"), Payload: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRawEnvelopeBound(c, env, "node-a", binding); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad wrapped key = %v", err)
	}

	// Seal then open with wrong payload AAD by tampering recipients field only
	// (keeps ciphertext but breaks recipient binding on open).
	sealed, err := SealEnvelopeBound(c, Secrets{Registry: &models.RegistryAuth{Password: "x"}}, []string{"node-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	var wire sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Recipients = []string{"node-a", "node-extra"}
	tampered, _ := json.Marshal(wire)
	if _, err := OpenRawEnvelopeBound(c, tampered, "node-a", binding); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered recipients = %v", err)
	}
}

func TestEnvelopeRecipients(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	sealed, err := SealEnvelopeBound(c, Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"node-b", "node-a"}, binding)
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
	if _, err := EnvelopeRecipients([]byte(`{"version":4}`)); err == nil {
		t.Fatal("missing payload should error")
	}
}

func TestOpenEnvelopePayloadGCMOpenFailure(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	sealed, err := SealRawEnvelopeBound(c, []byte(`{"x":1}`), []string{"node-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	var env sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	dek, err := c.DecryptWithAAD(env.WrappedKey, KeyAADBound([]string{"node-a"}, binding))
	if err != nil {
		t.Fatal(err)
	}
	env.Payload[len(env.Payload)-1] ^= 0xff
	if _, err := OpenEnvelopePayloadBound(dek, env.Payload, []string{"node-a"}, binding); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered payload = %v", err)
	}
}
