package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// §10: one Revoke stops every holder of the shared Cipher; Restore takes back
// only the same key.
func TestCipherRevokeRestore(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	c, err := NewCipherFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Encrypt([]byte("toolbox token"))
	if err != nil {
		t.Fatal(err)
	}
	c.Revoke()
	if !c.Revoked() {
		t.Fatal("Revoked")
	}
	if _, err := c.Decrypt(sealed); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("open after revoke = %v", err)
	}
	if _, err := c.EncryptWithAAD([]byte("x"), []byte("aad")); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("seal after revoke = %v", err)
	}
	if !IsKeyStoreError(fmt.Errorf("open toolbox token: %w", ErrKeyRevoked)) || IsKeyStoreError(ErrDecryptFailed) {
		t.Fatal("IsKeyStoreError")
	}
	if err := c.RestoreRing([]RingKey{{ID: 0, Key: bytes.Repeat([]byte{5}, 32), Current: true}}); err == nil {
		t.Fatal("a different key restored")
	}
	if !c.Revoked() {
		t.Fatal("a refused restore cleared the revoke")
	}
	if err := c.RestoreRing([]RingKey{{ID: 0, Key: key, Current: true}}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Decrypt(sealed); err != nil || string(got) != "toolbox token" || c.Revoked() {
		t.Fatalf("after restore = %q %v", got, err)
	}
	var nilCipher *Cipher
	nilCipher.Revoke()
	if nilCipher.Revoked() || nilCipher.RestoreRing([]RingKey{{ID: 0, Key: key, Current: true}}) == nil {
		t.Fatal("nil cipher")
	}
	if _, err := (&Cipher{}).Encrypt(nil); err == nil || errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("zero cipher = %v, want not initialized", err)
	}
	if err := (&Cipher{}).RestoreRing([]RingKey{{ID: 0, Key: key[:7], Current: true}}); err == nil {
		t.Fatal("a key AES refuses was restored")
	}
}
