package pkcs11

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestWrappedFormatRoundTrip(t *testing.T) {
	iv := bytes.Repeat([]byte{7}, ivLen)
	ct := bytes.Repeat([]byte{9}, tagLen+32)
	raw, err := encodeWrapped(wrappedKey{Label: "kek-2026", IV: iv, Ciphertext: ct})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.WrappedKeyBackend(raw) != secrets.ProviderPKCS11 {
		t.Fatalf("router does not see %q as pkcs11", raw[:8])
	}
	got, err := decodeWrapped(raw)
	if err != nil || got.Label != "kek-2026" || !bytes.Equal(got.IV, iv) || !bytes.Equal(got.Ciphertext, ct) {
		t.Fatalf("decode = %+v %v", got, err)
	}
}

func TestWrappedFormatRefusals(t *testing.T) {
	iv := bytes.Repeat([]byte{1}, ivLen)
	ct := bytes.Repeat([]byte{2}, tagLen+1)
	for name, w := range map[string]wrappedKey{
		"no label":   {IV: iv, Ciphertext: ct},
		"long label": {Label: strings.Repeat("l", 256), IV: iv, Ciphertext: ct},
		"zero IV":    {Label: "k", IV: make([]byte, ivLen), Ciphertext: ct},
		"short IV":   {Label: "k", IV: iv[:8], Ciphertext: ct},
		"tag only":   {Label: "k", IV: iv, Ciphertext: ct[:tagLen]},
	} {
		if _, err := encodeWrapped(w); err == nil {
			t.Fatalf("%s: encoded", name)
		}
	}
	good, _ := encodeWrapped(wrappedKey{Label: "k", IV: iv, Ciphertext: ct})
	zeroIV := append([]byte(nil), good...)
	copy(zeroIV[len(formatPrefix)+2:], make([]byte, ivLen))
	for name, raw := range map[string][]byte{
		"vault ciphertext": []byte("vault:v1:abc"),
		"prefix only":      []byte(formatPrefix),
		"zero label len":   append([]byte(formatPrefix), 0),
		"truncated":        good[:len(good)-tagLen],
		"zero IV":          zeroIV,
	} {
		if _, err := decodeWrapped(raw); !errors.Is(err, secrets.ErrDecryptFailed) {
			t.Fatalf("%s: decode = %v, want ErrDecryptFailed", name, err)
		}
	}
}
