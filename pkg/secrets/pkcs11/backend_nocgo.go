//go:build !cgo

package pkcs11

import "errors"

// openBackend refuses: the PKCS#11 module is loaded through cgo (eng D6).
func openBackend(TokenConfig) (closingBackend, error) {
	return nil, errors.New("pkcs11 needs a cgo build of sandboxd")
}
