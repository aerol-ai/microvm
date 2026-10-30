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
	ProviderPKCS11 = "pkcs11"
)

// DefaultMaxInFlight is the default foreground cap on key-store calls per node
// (SB_SECRET_PROVIDER_MAX_INFLIGHT).
const DefaultMaxInFlight = 8

// ProviderOptions selects and constructs a secrets.Provider.
type ProviderOptions struct {
	// Name is local | awskms | vault | pkcs11 (default local).
	Name string
	// AWSKMSKeyID is required when Name=awskms.
	AWSKMSKeyID string
	// Cipher is required for local.
	Cipher *Cipher
	// Store persists sealed blobs for every provider.
	Store BlobStore
	// Wrapper overrides the sealing backend (tests inject FakeKMS). NewWrapper
	// still routes and limits it.
	Wrapper DataKeyWrapper
	// Prebuilt is a wrapper NewWrapper already built (routed and limited),
	// reused as-is so one key-store client serves boot, the provider and the
	// background loop.
	Prebuilt DataKeyWrapper
	// MaxInFlight is the foreground cap (SB_SECRET_PROVIDER_MAX_INFLIGHT);
	// 0 means DefaultMaxInFlight.
	MaxInFlight int
	// Observer is told how long calls waited for a key-store slot; may be nil.
	Observer LimiterObserver
}

// NormalizeProviderName lowercases and defaults empty to local.
func NormalizeProviderName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ProviderLocal
	}
	return name
}

// IsExternalProvider reports whether name keeps key material in an external
// key store (anything but local).
func IsExternalProvider(name string) bool {
	switch NormalizeProviderName(name) {
	case ProviderAWSKMS, ProviderVault, ProviderPKCS11:
		return true
	default:
		return false
	}
}

// NewWrapper builds the key-store client for an external provider from config
// alone, with no store, so the daemon can build it before the server key is
// unwrapped. It returns nil for local. The result routes by wrapped-key tag
// and limits in-flight calls. vault and pkcs11 are known names that refuse
// until their wrappers land, never falling back to local.
func NewWrapper(ctx context.Context, opts ProviderOptions) (DataKeyWrapper, error) {
	name := NormalizeProviderName(opts.Name)
	var seal DataKeyWrapper
	switch name {
	case ProviderLocal:
		return nil, nil
	case ProviderAWSKMS:
		seal = opts.Wrapper
		if seal == nil {
			w, err := NewAWSKMS(ctx, opts.AWSKMSKeyID)
			if err != nil {
				return nil, err
			}
			seal = w
		}
	case ProviderVault, ProviderPKCS11:
		return nil, fmt.Errorf("SB_SECRET_PROVIDER=%s is not implemented yet; use local or awskms", name)
	default:
		return nil, fmt.Errorf("SB_SECRET_PROVIDER must be %q, %q, %q or %q (got %q)", ProviderLocal, ProviderAWSKMS, ProviderVault, ProviderPKCS11, opts.Name)
	}
	maxInFlight := opts.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = DefaultMaxInFlight
	}
	return NewLimitedWrapper(NewRouter(name, seal, nil), maxInFlight, opts.Observer), nil
}

// NewProvider builds the configured Provider. For an external provider it
// also returns the DataKeyWrapper so callers can run CanaryWrapUnwrap.
func NewProvider(ctx context.Context, opts ProviderOptions) (Provider, DataKeyWrapper, error) {
	if opts.Store == nil {
		return nil, nil, fmt.Errorf("cluster secret store is not configured")
	}
	name := NormalizeProviderName(opts.Name)
	if name == ProviderLocal {
		if opts.Cipher == nil {
			return nil, nil, fmt.Errorf("cluster secrets cipher is not configured")
		}
		return NewLocalProvider(opts.Cipher, opts.Store), nil, nil
	}
	w := opts.Prebuilt
	if w == nil {
		var err error
		w, err = NewWrapper(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
	}
	return NewKMSProvider(w, opts.Store), w, nil
}
