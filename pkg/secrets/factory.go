package secrets

import (
	"context"
	"fmt"
	"strings"
)

// Provider name constants for SB_SECRET_PROVIDER.
const (
	ProviderLocal  = "local"
	ProviderAWSKMS = "awskms"
	ProviderVault  = "vault"
)

// ProviderOptions selects and constructs a secrets.Provider.
type ProviderOptions struct {
	// Name is local | awskms | vault (default local).
	Name string
	// AWSKMSKeyID is required when Name=awskms.
	AWSKMSKeyID string
	// Cipher is required for local.
	Cipher *Cipher
	// Store persists sealed blobs for every provider.
	Store BlobStore
	// Wrapper overrides the awskms backend (tests inject FakeKMS).
	Wrapper DataKeyWrapper
}

// NormalizeProviderName lowercases and defaults empty to local.
func NormalizeProviderName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ProviderLocal
	}
	return name
}

// NewProvider builds the configured Provider. Vault is a known value that
// returns a clear not-implemented error (no silent fallback to local).
// For awskms, also returns the DataKeyWrapper so callers can run CanaryWrapUnwrap.
func NewProvider(ctx context.Context, opts ProviderOptions) (Provider, DataKeyWrapper, error) {
	if opts.Store == nil {
		return nil, nil, fmt.Errorf("cluster secret store is not configured")
	}
	switch NormalizeProviderName(opts.Name) {
	case ProviderLocal:
		if opts.Cipher == nil {
			return nil, nil, fmt.Errorf("cluster secrets cipher is not configured")
		}
		return NewLocalProvider(opts.Cipher, opts.Store), nil, nil
	case ProviderAWSKMS:
		w := opts.Wrapper
		if w == nil {
			var err error
			w, err = NewAWSKMS(ctx, opts.AWSKMSKeyID)
			if err != nil {
				return nil, nil, err
			}
		}
		return NewKMSProvider(w, opts.Store), w, nil
	case ProviderVault:
		return nil, nil, fmt.Errorf("SB_SECRET_PROVIDER=vault is not implemented yet; use local or awskms")
	default:
		return nil, nil, fmt.Errorf("SB_SECRET_PROVIDER must be %q, %q, or %q (got %q)", ProviderLocal, ProviderAWSKMS, ProviderVault, opts.Name)
	}
}
