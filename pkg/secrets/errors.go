package secrets

import "errors"

// Typed sentinel errors for secret provider operations. Callers and metrics
// should prefer errors.Is on these before string-matching.
var (
	ErrNotFound        = errors.New("secret not found")
	ErrRecipientDenied = errors.New("recipient denied")
	ErrVersionMismatch = errors.New("secret version mismatch")
	ErrDecryptFailed   = errors.New("secret decrypt failed")

	// Provider-agnostic (used by external backends in T10+).
	ErrProviderUnavailable = errors.New("secret provider unavailable")
	ErrProviderThrottled   = errors.New("secret provider throttled")
	ErrProviderDenied      = errors.New("secret provider denied")

	// ErrKeyRevoked means the key store deliberately refused the key: it was
	// disabled, deleted or scheduled for deletion. Only these signals may trip a
	// revoke (plans/customer-key-custody.md §10); a permission error or an outage
	// never does.
	ErrKeyRevoked = errors.New("key revoked by the key store")
	// ErrKeyVersionRetired means the row was wrapped under a key version the
	// key store no longer decrypts. It marks a stale row, never a revoke.
	ErrKeyVersionRetired = errors.New("key version retired by the key store")
)
