package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Cipher seals and opens user-supplied secrets (cloud credentials for sandbox
// mounts) using AES-256-GCM. The seal format is `nonce(12) || ciphertext+tag`.
// The key never leaves this package; sealed bytes are what crosses other
// trust boundaries (DB, logs, error messages).
type Cipher struct {
	gcm cipher.AEAD
}

// NewCipher constructs a Cipher from either an explicit key (base64-encoded,
// must decode to 32 bytes) or a fallback file path. If the explicit key is
// empty and the fallback path does not exist, a fresh 32-byte key is
// generated and persisted at the path with mode 0600.
func NewCipher(keyB64, fallbackPath string) (*Cipher, error) {
	keyBytes, err := loadOrGenerateKey(keyB64, fallbackPath)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm wrap: %w", err)
	}
	return &Cipher{gcm: gcm}, nil
}

// Encrypt seals plaintext. Empty input is allowed and produces a non-empty
// sealed blob (the nonce alone authenticates that no plaintext was sealed).
func (c *Cipher) Encrypt(plain []byte) ([]byte, error) {
	if c == nil || c.gcm == nil {
		return nil, errors.New("cipher not initialized")
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := c.gcm.Seal(nil, nonce, plain, nil)
	return append(nonce, sealed...), nil
}

// Decrypt opens a sealed blob produced by Encrypt. Tampering, truncation, or
// using a different key all return an error.
func (c *Cipher) Decrypt(sealed []byte) ([]byte, error) {
	if c == nil || c.gcm == nil {
		return nil, errors.New("cipher not initialized")
	}
	if len(sealed) < c.gcm.NonceSize() {
		return nil, errors.New("sealed blob too short")
	}
	nonce, body := sealed[:c.gcm.NonceSize()], sealed[c.gcm.NonceSize():]
	plain, err := c.gcm.Open(nil, nonce, body, nil)
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
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(fallbackPath, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("write encryption key: %w", err)
	}
	return keyBytes, nil
}
