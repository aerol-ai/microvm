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
)
