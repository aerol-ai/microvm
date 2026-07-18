package jsbundle

import "errors"

var (
	// ErrInvalidBundle is a structural validation failure (missing main
	// module, empty source, no compatibility date).
	ErrInvalidBundle = errors.New("jsbundle: invalid bundle")
	// ErrBundleNotFound is returned when a ref (digest or uploaded name) does
	// not resolve to a stored bundle.
	ErrBundleNotFound = errors.New("jsbundle: bundle not found")
	// ErrBundleTooLarge is returned when a bundle exceeds the store's size cap
	// (abuse control, plans/isolate-runtime.md §8).
	ErrBundleTooLarge = errors.New("jsbundle: bundle exceeds size cap")
	// ErrTenantQuotaExceeded is returned when storing a bundle would push a
	// tenant past its bundle-count quota (abuse control).
	ErrTenantQuotaExceeded = errors.New("jsbundle: tenant bundle quota exceeded")
	// ErrUnsupportedRef is returned for a reference shape the resolver does
	// not understand.
	ErrUnsupportedRef = errors.New("jsbundle: unsupported bundle reference")
)
