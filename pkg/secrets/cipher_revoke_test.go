package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
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

// §4, async ordering 1: once Revoke returns no new seal or open succeeds,
// but one that loaded the ring before it may finish ("operations already
// running when the revoke lands may complete").
func TestCipherRevokeDuringDecrypt(t *testing.T) {
	c, err := NewCipherFromKey(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Encrypt([]byte("registry auth"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.afterLoad = func() { once.Do(func() { close(loaded); <-release }) }
	type result struct {
		plain []byte
		err   error
	}
	inFlight := make(chan result, 1)
	go func() {
		plain, err := c.Decrypt(sealed)
		inFlight <- result{plain, err}
	}()
	<-loaded
	c.Revoke()
	if _, err := c.Decrypt(sealed); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("an open that started after the revoke = %v, want ErrKeyRevoked", err)
	}
	if _, err := c.Encrypt([]byte("x")); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("a seal that started after the revoke = %v, want ErrKeyRevoked", err)
	}
	close(release)
	if r := <-inFlight; r.err != nil || string(r.plain) != "registry auth" {
		t.Fatalf("the open in flight across the revoke = %q %v, want the plaintext", r.plain, r.err)
	}
}
