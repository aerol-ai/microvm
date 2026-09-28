package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// FakeKMS is an offline DataKeyWrapper for contract tests and local
// development. It AES-GCM-wraps DEKs with an in-memory test key and can
// inject throttle / deny / unavailable failures.
type FakeKMS struct {
	mu   sync.Mutex
	gcm  cipher.AEAD
	key  []byte
	wrap int
	// Injected failure modes (checked under mu on each call).
	Throttle    bool
	Deny        bool
	Unavailable bool
}

// NewFakeKMS returns a FakeKMS with a random 32-byte wrapping key.
func NewFakeKMS() (*FakeKMS, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate fake kms key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &FakeKMS{gcm: gcm, key: key}, nil
}

// Wrap implements DataKeyWrapper.
func (f *FakeKMS) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injectedLocked(); err != nil {
		return nil, err
	}
	nonce := make([]byte, f.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("fake kms nonce: %w", err)
	}
	f.wrap++
	return append(nonce, f.gcm.Seal(nil, nonce, dek, encryptionContextAAD(encCtx))...), nil
}

// Unwrap implements DataKeyWrapper.
func (f *FakeKMS) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injectedLocked(); err != nil {
		return nil, err
	}
	if len(wrapped) < f.gcm.NonceSize() {
		return nil, fmt.Errorf("%w: fake kms wrapped key too short", ErrDecryptFailed)
	}
	nonce, body := wrapped[:f.gcm.NonceSize()], wrapped[f.gcm.NonceSize():]
	plain, err := f.gcm.Open(nil, nonce, body, encryptionContextAAD(encCtx))
	if err != nil {
		return nil, fmt.Errorf("%w: fake kms unwrap: %v", ErrDecryptFailed, err)
	}
	return plain, nil
}

func encryptionContextAAD(encCtx map[string]string) []byte {
	if len(encCtx) == 0 {
		return nil
	}
	keys := make([]string, 0, len(encCtx))
	for k := range encCtx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(encCtx[k])
		b.WriteByte(0)
	}
	return []byte(b.String())
}

func (f *FakeKMS) injectedLocked() error {
	switch {
	case f.Unavailable:
		return fmt.Errorf("%w: fake kms unavailable", ErrProviderUnavailable)
	case f.Throttle:
		return fmt.Errorf("%w: fake kms throttled", ErrProviderThrottled)
	case f.Deny:
		return fmt.Errorf("%w: fake kms denied", ErrProviderDenied)
	default:
		return nil
	}
}
