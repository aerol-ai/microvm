package secrets

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
)

// DataKeyWrapper wraps and unwraps per-secret data encryption keys (DEKs).
// Local Cipher uses AES-GCM with AAD; AWS KMS / FakeKMS implement the same
// seam so KMSProvider never talks to a concrete backend.
//
// encCtx is optional additional authenticated context (AWS KMS EncryptionContext
// / FakeKMS AAD). Boot canaries pass nil; production envelope wraps bind it.
type DataKeyWrapper interface {
	Wrap(ctx context.Context, dek []byte, encCtx map[string]string) (wrapped []byte, err error)
	Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) (dek []byte, err error)
}

// CanaryWrapUnwrap exercises Wrap+Unwrap with a random 32-byte DEK. Used at
// daemon boot for awskms (E4 lite). Does not touch BlobStore or create rows.
func CanaryWrapUnwrap(ctx context.Context, w DataKeyWrapper) error {
	if w == nil {
		return fmt.Errorf("%w: secret provider wrap backend is not configured", ErrProviderUnavailable)
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return fmt.Errorf("generate secret provider canary key: %w", err)
	}
	encCtx := map[string]string{"aerolvm.canary": "1"}
	wrapped, err := w.Wrap(ctx, dek, encCtx)
	if err != nil {
		return fmt.Errorf("secret provider canary wrap: %w", err)
	}
	got, err := w.Unwrap(ctx, wrapped, encCtx)
	if err != nil {
		return fmt.Errorf("secret provider canary unwrap: %w", err)
	}
	if len(got) != len(dek) {
		return fmt.Errorf("secret provider canary length mismatch: got %d want %d", len(got), len(dek))
	}
	for i := range dek {
		if got[i] != dek[i] {
			return fmt.Errorf("secret provider canary plaintext mismatch")
		}
	}
	return nil
}
