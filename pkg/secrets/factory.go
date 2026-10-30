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
	// AWSKMSKeyID is required when Name=awskms. Set with another provider, it
	// lets the node still open AWS KMS rows during a switch.
	AWSKMSKeyID string
	// Vault is required when Name=vault. Set with another provider, it lets
	// the node already open vault rows during a switch.
	Vault VaultOptions
	// PKCS11 is the running PKCS#11 helper client, required when
	// Name=pkcs11. pkg/daemon starts it (the vendor library lives in its own
	// process, eng D5), so this package never imports pkg/secrets/pkcs11.
	// Set with another provider, it lets the node open p11 rows.
	PKCS11 DataKeyWrapper
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
// unwrapped. It returns nil for local. The result seals with the configured
// provider, opens each row with whichever backend its tag names among those
// the node has settings for (so a provider switch is two steps, §12), and
// limits in-flight calls.
func NewWrapper(ctx context.Context, opts ProviderOptions) (DataKeyWrapper, error) {
	name := NormalizeProviderName(opts.Name)
	switch name {
	case ProviderLocal:
		return nil, nil
	case ProviderAWSKMS, ProviderVault, ProviderPKCS11:
	default:
		return nil, fmt.Errorf("SB_SECRET_PROVIDER must be %q, %q, %q or %q (got %q)", ProviderLocal, ProviderAWSKMS, ProviderVault, ProviderPKCS11, opts.Name)
	}
	openers := map[string]DataKeyWrapper{}
	if name == ProviderAWSKMS || strings.TrimSpace(opts.AWSKMSKeyID) != "" {
		if name != ProviderAWSKMS || opts.Wrapper == nil {
			w, err := NewAWSKMS(ctx, opts.AWSKMSKeyID)
			if err != nil {
				return nil, err
			}
			openers[ProviderAWSKMS] = w
		}
	}
	if name == ProviderVault || opts.Vault.Configured() {
		if name != ProviderVault || opts.Wrapper == nil {
			v, err := NewVault(opts.Vault)
			if err != nil {
				return nil, err
			}
			openers[ProviderVault] = v
		}
	}
	if opts.PKCS11 != nil {
		openers[ProviderPKCS11] = opts.PKCS11
	}
	seal := opts.Wrapper
	if seal == nil {
		seal = openers[name]
	}
	if seal == nil {
		return nil, fmt.Errorf("SB_SECRET_PROVIDER=%s: the PKCS#11 helper is not running", name)
	}
	if v, ok := seal.(*Vault); ok {
		// A token that may create keys would undo a revoke, so it stops the
		// boot whatever SB_SECRET_PROVIDER_STRICT_BOOT says. A Vault that is
		// down here is the canary's to report; the check runs again before
		// the first encrypt.
		pctx, cancel := context.WithTimeout(ContextWithBackgroundPurpose(ctx, "boot"), vaultPolicyCheckTimeout)
		err := v.ensurePolicy(pctx)
		cancel()
		if IsVaultPolicyError(err) {
			return nil, err
		}
	}
	maxInFlight := opts.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = DefaultMaxInFlight
	}
	return NewLimitedWrapper(NewRouter(name, seal, openers), maxInFlight, opts.Observer), nil
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
