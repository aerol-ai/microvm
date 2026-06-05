package secrets

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestCipherRoundTrip(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	c, err := NewCipher(keyB64, "")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	cases := [][]byte{
		nil,
		[]byte(""),
		[]byte("hello"),
		bytes.Repeat([]byte{0xff}, 4096),
	}
	for _, plain := range cases {
		sealed, err := c.Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%d bytes): %v", len(plain), err)
		}
		got, err := c.Decrypt(sealed)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(plain))
		}
	}
}

func TestCipherDetectsTampering(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	c, err := NewCipher(keyB64, "")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	sealed, err := c.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the ciphertext portion.
	tampered := append([]byte{}, sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("expected Decrypt to fail on tampered ciphertext")
	}

	// Truncated input.
	if _, err := c.Decrypt(sealed[:5]); err == nil {
		t.Fatal("expected Decrypt to fail on truncated input")
	}
}

func TestCipherWrongKeyFails(t *testing.T) {
	keyA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	keyB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	a, _ := NewCipher(keyA, "")
	b, _ := NewCipher(keyB, "")
	sealed, _ := a.Encrypt([]byte("x"))
	if _, err := b.Decrypt(sealed); err == nil {
		t.Fatal("expected Decrypt to fail with the wrong key")
	}
}

func TestCipherAutoGeneratesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "key")

	c1, err := NewCipher("", path)
	if err != nil {
		t.Fatalf("first NewCipher: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}

	// Second call must load the same key — sealed-by-c1 must open under c2.
	c2, err := NewCipher("", path)
	if err != nil {
		t.Fatalf("second NewCipher: %v", err)
	}
	sealed, _ := c1.Encrypt([]byte("durable"))
	got, err := c2.Decrypt(sealed)
	if err != nil {
		t.Fatalf("c2 decrypt: %v", err)
	}
	if string(got) != "durable" {
		t.Errorf("got %q, want durable", got)
	}
}

func TestCipherRejectsBadKeyLengths(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("not32"))
	if _, err := NewCipher(short, ""); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := NewCipher("not-base64!!!", ""); err == nil {
		t.Fatal("expected error for non-base64 key")
	}
}

func TestCipherNilRejects(t *testing.T) {
	var c *Cipher
	if _, err := c.EncryptWithAAD([]byte("a"), nil); err == nil {
		t.Fatal("EncryptWithAAD: expected error on nil cipher")
	}
	if _, err := c.DecryptWithAAD([]byte("a"), nil); err == nil {
		t.Fatal("DecryptWithAAD: expected error on nil cipher")
	}
}

func TestCipherDecryptWithAADShort(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	c, _ := NewCipher(keyB64, "")
	if _, err := c.DecryptWithAAD([]byte("short"), nil); err == nil {
		t.Fatal("DecryptWithAAD: expected error on short cipher")
	}
}

func TestLoadOrGenerateKeyEdgeCases(t *testing.T) {
	if _, err := loadOrGenerateKey("", ""); err == nil {
		t.Fatal("expected error with empty key and empty fallback path")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	os.WriteFile(path, []byte("invalid-base64-xyz!"), 0600)
	if _, err := loadOrGenerateKey("", path); err == nil {
		t.Fatal("expected error for invalid base64 in fallback file")
	}

	os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte("short-key"))), 0600)
	if _, err := loadOrGenerateKey("", path); err == nil {
		t.Fatal("expected error for short key in fallback file")
	}

	// Using a directory as a file path should trigger a read error.
	isdir := filepath.Join(dir, "isdir")
	os.Mkdir(isdir, 0700)
	if _, err := loadOrGenerateKey("", isdir); err == nil {
		t.Fatal("expected error when fallback path is a directory")
	}
}

func TestCipherAAD(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	c, _ := NewCipher(keyB64, "")
	sealed, err := c.EncryptWithAAD([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecryptWithAAD(sealed, []byte("wrong-aad")); err == nil {
		t.Fatal("expected error with wrong aad")
	}
	if _, err := c.DecryptWithAAD(sealed, []byte("aad")); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}
