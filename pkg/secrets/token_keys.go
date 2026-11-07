package secrets

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// sandboxTokenKeyInfo is the HKDF label of the Ed25519 seed a server key's
// sandbox tokens are signed with (pkg/sandboxtoken). It differs from the
// digest and key-check labels, so none of the three says anything about the
// others, and HKDF is one-way, so none says anything about the server key.
const sandboxTokenKeyInfo = "aerolvm-sandbox-token/v1"

// deriveSandboxTokenKey turns a 32-byte server key into its token signing
// key. Deterministic on purpose: every node of a cluster holds the same
// server key ring, so every node derives the same key pair from it and can
// check a token any node signed, with no key distribution of its own.
func deriveSandboxTokenKey(key []byte) (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, key, nil, sandboxTokenKeyInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("derive sandbox token key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SandboxTokenSigner returns the key new sandbox tokens are signed with:
// the one derived from the current server key, with that key's id. A staged
// key (decrypt-only, not yet promoted) never signs, because a node that has
// not yet read the staged ring could not check what it signed.
func (c *Cipher) SandboxTokenSigner() (uint32, ed25519.PrivateKey, error) {
	r, err := c.activeRing()
	if err != nil {
		return 0, nil, err
	}
	key := r.tokenKeys[r.current]
	if key == nil {
		return 0, nil, fmt.Errorf("server key %d has no token key", r.current)
	}
	return r.current, key, nil
}

// SandboxTokenVerifyKey returns the public key for key id, from any key the
// ring still holds: the current one, a staged one, or the previous current
// key during a rotation. That is the rotation rule for tokens: a new key
// signs as soon as it is current, and the old key keeps verifying until the
// operator retires it. ok is false for an id the ring does not hold (never
// seen, or retired), and for a revoked Cipher.
func (c *Cipher) SandboxTokenVerifyKey(id uint32) (ed25519.PublicKey, bool) {
	r := c.loadRing()
	if r == nil {
		return nil, false
	}
	key := r.tokenKeys[id]
	if key == nil {
		return nil, false
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	return pub, ok
}
