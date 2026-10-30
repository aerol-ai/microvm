package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
)

var randReader io.Reader = rand.Reader

// EnvAAD binds an environment to both its sandbox and lifecycle. JSON string
// framing prevents ambiguous boundaries even if an ID contains a delimiter.
func EnvAAD(sandboxID, incarnationID string) []byte {
	aad, _ := json.Marshal([3]string{"sandbox-env/v1", sandboxID, incarnationID})
	return aad
}

// Cipher seals and opens user-supplied secrets (cloud credentials for sandbox
// mounts) using AES-256-GCM. The seal format is `nonce(12) || ciphertext+tag`.
// The key never leaves this package; sealed bytes are what crosses other
// trust boundaries (DB, logs, error messages).
//
// The AEAD sits behind an atomic pointer so a key-store revoke can drop it
// for every holder at once: the store and the service share one Cipher, and
// after Revoke every seal and open returns ErrKeyRevoked
// (plans/customer-key-custody.md §10).
type Cipher struct {
	gcm     atomic.Pointer[aeadBox]
	revoked atomic.Bool
	// check identifies the key, so Restore takes back only the same one.
	check []byte
}

type aeadBox struct{ gcm cipher.AEAD }

// NewCipher constructs a Cipher from either an explicit key (base64-encoded,
// must decode to 32 bytes) or a fallback file path. If the explicit key is
// empty and the fallback path does not exist, a fresh 32-byte key is
// generated and persisted at the path with mode 0600.
func NewCipher(keyB64, fallbackPath string) (*Cipher, error) {
	keyBytes, err := loadOrGenerateKey(keyB64, fallbackPath)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(keyBytes)
	if err != nil {
		return nil, err
	}
	c := &Cipher{check: serverKeyCheck(keyBytes)}
	c.gcm.Store(&aeadBox{gcm: gcm})
	return c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm wrap: %w", err)
	}
	return gcm, nil
}

// Revoke drops the key from memory: every later seal and open returns
// ErrKeyRevoked until Restore. Go cannot promise the bytes are zeroed, so
// the docs say "dropped", not "wiped".
func (c *Cipher) Revoke() {
	if c == nil {
		return
	}
	c.revoked.Store(true)
	c.gcm.Store(nil)
}

// Restore takes the key back after a revoke ends (eng D12). Only the key
// the Cipher was built with is accepted: a different one would make every
// sealed row unreadable.
func (c *Cipher) Restore(key []byte) error {
	if c == nil {
		return errors.New("cipher not initialized")
	}
	if !hmac.Equal(serverKeyCheck(key), c.check) {
		return errors.New("restore: not the key this cipher was built with")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	c.gcm.Store(&aeadBox{gcm: gcm})
	c.revoked.Store(false)
	return nil
}

// Revoked reports whether Revoke dropped the key.
func (c *Cipher) Revoked() bool { return c != nil && c.revoked.Load() }

func (c *Cipher) aead() (cipher.AEAD, error) {
	if c == nil {
		return nil, errors.New("cipher not initialized")
	}
	if b := c.gcm.Load(); b != nil {
		return b.gcm, nil
	}
	if c.revoked.Load() {
		return nil, fmt.Errorf("%w: the server key was dropped", ErrKeyRevoked)
	}
	return nil, errors.New("cipher not initialized")
}

// Encrypt seals plaintext. Empty input is allowed and produces a non-empty
// sealed blob (the nonce alone authenticates that no plaintext was sealed).
func (c *Cipher) Encrypt(plain []byte) ([]byte, error) {
	return c.EncryptWithAAD(plain, nil)
}

func (c *Cipher) EncryptWithAAD(plain []byte, aad []byte) ([]byte, error) {
	gcm, err := c.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plain, aad)
	return append(nonce, sealed...), nil
}

// Decrypt opens a sealed blob produced by Encrypt. Tampering, truncation, or
// using a different key all return an error.
func (c *Cipher) Decrypt(sealed []byte) ([]byte, error) {
	return c.DecryptWithAAD(sealed, nil)
}

func (c *Cipher) DecryptWithAAD(sealed []byte, aad []byte) ([]byte, error) {
	gcm, err := c.aead()
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed blob too short")
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}

func loadOrGenerateKey(keyB64, fallbackPath string) ([]byte, error) {
	if keyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(decoded))
		}
		return decoded, nil
	}

	if fallbackPath == "" {
		return nil, errors.New("no encryption key configured and no fallback path provided")
	}

	if data, err := os.ReadFile(fallbackPath); err == nil {
		decoded, decErr := base64.StdEncoding.DecodeString(string(data))
		if decErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("invalid encryption key at %s", fallbackPath)
		}
		return decoded, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key %s: %w", fallbackPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(fallbackPath), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(randReader, keyBytes); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(fallbackPath, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("write encryption key: %w", err)
	}
	return keyBytes, nil
}
