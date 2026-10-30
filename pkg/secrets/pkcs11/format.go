package pkcs11

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Wrapped-key format, ours and versioned (plans/customer-key-custody.md §2):
//
//	"p11:1:" | label length (1 byte) | label | IV (12 bytes) | ciphertext+tag
//
// The label names the HSM key object that wrapped the DEK, which is what lets
// a node open rows across a label rotation (eng D23).
const (
	formatPrefix = "p11:1:"
	ivLen        = 12
	tagLen       = 16
	maxLabelLen  = 255
)

// wrappedKey is one decoded p11 wrapped key.
type wrappedKey struct {
	Label      string
	IV         []byte
	Ciphertext []byte // ciphertext with the GCM tag appended
}

func encodeWrapped(w wrappedKey) ([]byte, error) {
	if w.Label == "" || len(w.Label) > maxLabelLen {
		return nil, fmt.Errorf("pkcs11 key label must be 1-%d bytes", maxLabelLen)
	}
	if len(w.IV) != ivLen || isZero(w.IV) {
		return nil, errors.New("pkcs11 wrap produced no usable IV")
	}
	if len(w.Ciphertext) <= tagLen {
		return nil, errors.New("pkcs11 wrap produced no ciphertext")
	}
	var b bytes.Buffer
	b.WriteString(formatPrefix)
	b.WriteByte(byte(len(w.Label)))
	b.WriteString(w.Label)
	b.Write(w.IV)
	b.Write(w.Ciphertext)
	return b.Bytes(), nil
}

func decodeWrapped(raw []byte) (wrappedKey, error) {
	bad := func(why string) (wrappedKey, error) {
		return wrappedKey{}, fmt.Errorf("%w: pkcs11 wrapped key: %s", secrets.ErrDecryptFailed, why)
	}
	if !bytes.HasPrefix(raw, []byte(formatPrefix)) {
		return bad("unknown format")
	}
	rest := raw[len(formatPrefix):]
	if len(rest) < 1 {
		return bad("truncated")
	}
	n := int(rest[0])
	rest = rest[1:]
	if n == 0 || len(rest) < n+ivLen+tagLen+1 {
		return bad("truncated")
	}
	w := wrappedKey{Label: string(rest[:n]), IV: append([]byte(nil), rest[n:n+ivLen]...), Ciphertext: append([]byte(nil), rest[n+ivLen:]...)}
	if isZero(w.IV) {
		// No wrap ever writes an all-zero IV; one here was forged or corrupted.
		return bad("all-zero IV")
	}
	return w, nil
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
