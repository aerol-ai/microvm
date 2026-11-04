//go:build cgo

package pkcs11

// openBackend opens the HSM token named by cfg.
func openBackend(cfg TokenConfig) (closingBackend, error) {
	return OpenToken(cfg)
}
