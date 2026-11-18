package secrets

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Keys only servers hold (least privilege). A cluster's servers share a
// random seed no worker or gateway holds (the Raft FSM's server signing
// record); these derive from it:
//
//	sandbox tokens   one Ed25519 key per server key ring id, so a ring
//	                 rotation rotates them as it rotated the ring-derived
//	                 ones; key id ServerKeyIDBit | ring id
//	identity seal    the AEAD the cloud-identity signing keys are sealed
//	                 with, so only a server opens one
//
// HKDF is one-way: none of them says anything about the seed or each other.

// ServerSeedSize is the seed's length.
const ServerSeedSize = 32

// ServerKeyIDBit marks a sandbox token key id as one derived from the
// server seed. Ring ids are small counters that never reach it, so the two
// kinds never collide, and a build that knows only ring keys finds no key
// for such an id.
const ServerKeyIDBit uint32 = 1 << 31

const (
	serverTokenKeyInfo    = "aerolvm-server-sandbox-token/v1"
	serverIdentitySealKey = "aerolvm-server-identity-seal/v1"
)

// ErrServerSeed is a seed of the wrong length.
var ErrServerSeed = errors.New("server signing seed must be 32 bytes")

// ServerTokenKeyID is the sandbox token key id for ring id.
func ServerTokenKeyID(ringID uint32) (uint32, error) {
	if ringID&ServerKeyIDBit != 0 {
		return 0, fmt.Errorf("server key ring id %d is out of range", ringID)
	}
	return ServerKeyIDBit | ringID, nil
}

// ServerTokenKey derives the sandbox token key for ring id from seed.
func ServerTokenKey(seed []byte, ringID uint32) (uint32, ed25519.PrivateKey, error) {
	if len(seed) != ServerSeedSize {
		return 0, nil, ErrServerSeed
	}
	kid, err := ServerTokenKeyID(ringID)
	if err != nil {
		return 0, nil, err
	}
	key, err := hkdf.Key(sha256.New, seed, nil, serverTokenKeyInfo+"\x00"+strconv.FormatUint(uint64(ringID), 10), ed25519.SeedSize)
	if err != nil {
		return 0, nil, fmt.Errorf("derive server token key: %w", err)
	}
	return kid, ed25519.NewKeyFromSeed(key), nil
}

// ServerSealer seals and opens with a key derived from the server seed:
// what only servers may open (the cloud-identity signing keys). A sealed
// blob is nonce || ciphertext+tag.
type ServerSealer struct{ aead cipher.AEAD }

// NewServerIdentitySealer derives the sealer for cloud-identity signing
// keys from seed.
func NewServerIdentitySealer(seed []byte) (*ServerSealer, error) {
	if len(seed) != ServerSeedSize {
		return nil, ErrServerSeed
	}
	key, err := hkdf.Key(sha256.New, seed, nil, serverIdentitySealKey, 32)
	if err != nil {
		return nil, fmt.Errorf("derive server identity seal key: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &ServerSealer{aead: gcm}, nil
}

// Seal seals plain, bound to aad.
func (s *ServerSealer) Seal(plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("server seal nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plain, aad), nil
}

// Open opens what Seal sealed with the same aad.
func (s *ServerSealer) Open(sealed, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n+s.aead.Overhead() {
		return nil, errors.New("server seal: too short")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], aad)
}
