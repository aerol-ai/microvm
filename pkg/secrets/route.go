package secrets

import (
	"bytes"
	"context"
	"fmt"
)

// Wrapped-key tags. Vault and OpenBao ciphertext starts with "vault:v<N>:" on
// its own; PKCS#11 output starts with "p11:". AWS KMS blobs are opaque and
// local rows wrap under the server key, so both are untagged. A tag lets a
// node name the backend that wrapped a row before calling out, instead of
// failing with a bare decrypt error after a provider switch.
const (
	tagVault  = "vault:"
	tagPKCS11 = "p11:"
)

// WrappedKeyBackend names the backend that wrapped w by its tag:
// ProviderVault, ProviderPKCS11, or "" for an untagged key (local or AWS KMS).
func WrappedKeyBackend(w []byte) string {
	switch {
	case bytes.HasPrefix(w, []byte(tagVault)):
		return ProviderVault
	case bytes.HasPrefix(w, []byte(tagPKCS11)):
		return ProviderPKCS11
	default:
		return ""
	}
}

// Router seals with the configured provider and opens each wrapped key with
// whichever configured backend its tag names, even when that is not the
// sealing provider. That is what makes a provider switch two-step with no
// failover window: every node gets the new backend's settings first, then the
// sealing provider flips (plans/customer-key-custody.md §12, eng D8). An
// untagged key opens with AWS KMS whenever AWS KMS is configured, whatever the
// sealing provider (eng D22); local rows never reach the router, because the
// server key opens them first.
type Router struct {
	sealName string
	seal     DataKeyWrapper
	openers  map[string]DataKeyWrapper
}

// NewRouter seals with seal (named sealName) and opens with openers, keyed by
// provider name. The sealing wrapper is added to openers under sealName.
func NewRouter(sealName string, seal DataKeyWrapper, openers map[string]DataKeyWrapper) *Router {
	all := make(map[string]DataKeyWrapper, len(openers)+1)
	for name, w := range openers {
		if w != nil {
			all[name] = w
		}
	}
	if seal != nil {
		all[sealName] = seal
	}
	return &Router{sealName: sealName, seal: seal, openers: all}
}

// Wrap implements DataKeyWrapper with the sealing provider.
func (r *Router) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	if r == nil || r.seal == nil {
		return nil, fmt.Errorf("%w: secret provider wrap backend is not configured", ErrProviderUnavailable)
	}
	return r.seal.Wrap(ctx, dek, encCtx)
}

// Unwrap implements DataKeyWrapper with the backend the wrapped key's tag
// names.
func (r *Router) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: secret provider wrap backend is not configured", ErrProviderUnavailable)
	}
	backend := WrappedKeyBackend(wrapped)
	if backend == "" {
		backend = ProviderAWSKMS
	}
	w := r.openers[backend]
	if w == nil {
		return nil, fmt.Errorf("%w: row wrapped by %s; node configured for %s and has no %s settings", ErrProviderUnavailable, backend, r.sealName, backend)
	}
	return w.Unwrap(ctx, wrapped, encCtx)
}
