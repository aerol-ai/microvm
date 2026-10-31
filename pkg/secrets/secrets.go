package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
)

var randReader io.Reader = rand.Reader

// EnvAAD binds an environment to both its sandbox and lifecycle. JSON string
// framing prevents ambiguous boundaries even if an ID contains a delimiter.
func EnvAAD(sandboxID, incarnationID string) []byte {
	aad, _ := json.Marshal([3]string{"sandbox-env/v1", sandboxID, incarnationID})
	return aad
}

// Cipher seals and opens user-supplied secrets (cloud credentials for sandbox
// mounts) using AES-256-GCM. The seal format is `nonce(12) || ciphertext+tag`.
// The key never leaves this package; sealed bytes are what crosses other
// trust boundaries (DB, logs, error messages).
//
// The AEAD sits behind an atomic pointer so a key-store revoke can drop it
// for every holder at once: the store and the service share one Cipher, and
// after Revoke every seal and open returns ErrKeyRevoked
// (plans/customer-key-custody.md §10).
type Cipher struct {
	ring    atomic.Pointer[keyRing]
	revoked atomic.Bool
	// mu serializes ring changes (SetRing, Revoke, RestoreRing).
	mu sync.Mutex
	// checks are the ids and checks of every key this Cipher has held: a
	// ring change may add keys or drop retired ones, never swap a key under
	// an id it already knows (that would make every row on it unreadable).
	checks map[uint32][]byte
	// afterLoad, set only by tests, runs once a call has loaded the ring:
	// it holds a Decrypt there while a Revoke lands (§4, async ordering 1).
	afterLoad func()
}

// keyRing is the server keys a Cipher holds (plans/customer-key-custody.md
// §13). Key id 0 is the legacy key: the one every install starts with, whose
// blobs carry no key id.
type keyRing struct {
	current uint32
	keys    map[uint32]cipher.AEAD
}

// keyIDMarker starts a sealed blob that names its key:
// 0xA1 || key_id (4 bytes, big endian) || nonce || ciphertext+tag. Only
// written once a key other than the legacy one is current, so a node that
// never rotates writes exactly what older builds read.
const keyIDMarker = 0xA1

// keyIDHeaderLen is the marker plus the key id.
const keyIDHeaderLen = 5

// RingKey is one key of a server-key ring, in memory. A nil Key on SetRing
// keeps the key the Cipher already holds under ID, so a re-read of the ring
// unwraps only the keys that are new to this node.
type RingKey struct {
	ID      uint32
	Key     []byte
	Current bool
}

// NewCipher constructs a Cipher from either an explicit key (base64-encoded,
// must decode to 32 bytes) or a fallback file path. If the explicit key is
// empty and the fallback path does not exist, a fresh 32-byte key is
// generated and persisted at the path with mode 0600.
func NewCipher(keyB64, fallbackPath string) (*Cipher, error) {
	keyBytes, err := loadOrGenerateKey(keyB64, fallbackPath)
	if err != nil {
		return nil, err
	}
	return NewCipherRing([]RingKey{{ID: 0, Key: keyBytes, Current: true}})
}

// NewCipherRing builds a Cipher from a key ring; exactly one key is current.
func NewCipherRing(keys []RingKey) (*Cipher, error) {
	c := &Cipher{checks: map[uint32][]byte{}}
	if err := c.SetRing(keys); err != nil {
		return nil, err
	}
	return c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm wrap: %w", err)
	}
	return gcm, nil
}

func (c *Cipher) buildRing(keys []RingKey, prev *keyRing) (*keyRing, map[uint32][]byte, error) {
	ring := &keyRing{keys: map[uint32]cipher.AEAD{}}
	checks := map[uint32][]byte{}
	currents := 0
	for _, k := range keys {
		if _, dup := ring.keys[k.ID]; dup {
			return nil, nil, fmt.Errorf("server-key ring: key id %d appears twice", k.ID)
		}
		if k.Key == nil {
			if prev == nil || prev.keys[k.ID] == nil {
				return nil, nil, fmt.Errorf("server-key ring: key id %d is not loaded on this node", k.ID)
			}
			ring.keys[k.ID] = prev.keys[k.ID]
			checks[k.ID] = c.checks[k.ID]
			if k.Current {
				ring.current = k.ID
				currents++
			}
			continue
		}
		check := serverKeyCheck(k.Key)
		if known, ok := c.checks[k.ID]; ok && !hmac.Equal(known, check) {
			return nil, nil, fmt.Errorf("server-key ring: key id %d is not the key this node already holds under that id", k.ID)
		}
		gcm, err := newGCM(k.Key)
		if err != nil {
			return nil, nil, err
		}
		ring.keys[k.ID] = gcm
		checks[k.ID] = check
		if k.Current {
			ring.current = k.ID
			currents++
		}
	}
	if currents != 1 {
		return nil, nil, fmt.Errorf("server-key ring must have exactly one current key (has %d)", currents)
	}
	return ring, checks, nil
}

// SetRing replaces the keys the Cipher holds: a staged key added, a key
// promoted to current, a retired key dropped. It never revives a revoked
// Cipher (RestoreRing does that).
func (c *Cipher) SetRing(keys []RingKey) error {
	if c == nil {
		return errors.New("cipher not initialized")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ring, checks, err := c.buildRing(keys, c.ring.Load())
	if err != nil {
		return err
	}
	if c.checks == nil {
		c.checks = map[uint32][]byte{}
	}
	for id, check := range checks {
		c.checks[id] = check
	}
	if !c.revoked.Load() {
		c.ring.Store(ring)
	}
	return nil
}

// Revoke drops every key from memory: every later seal and open returns
// ErrKeyRevoked until Restore. Go cannot promise the bytes are zeroed, so
// the docs say "dropped", not "wiped".
func (c *Cipher) Revoke() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked.Store(true)
	c.ring.Store(nil)
}

// RestoreRing takes the keys back after a revoke ends (eng D12). A key under
// an id this Cipher already knew must be the same key.
func (c *Cipher) RestoreRing(keys []RingKey) error {
	if c == nil {
		return errors.New("cipher not initialized")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ring, checks, err := c.buildRing(keys, nil)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if c.checks == nil {
		c.checks = map[uint32][]byte{}
	}
	for id, check := range checks {
		c.checks[id] = check
	}
	c.ring.Store(ring)
	c.revoked.Store(false)
	return nil
}

// Revoked reports whether Revoke dropped the keys.
func (c *Cipher) Revoked() bool { return c != nil && c.revoked.Load() }

// CurrentKeyID is the id new seals use; 0 is the legacy key.
func (c *Cipher) CurrentKeyID() uint32 {
	if r := c.loadRing(); r != nil {
		return r.current
	}
	return 0
}

// KeyIDs lists the ids the Cipher can open.
func (c *Cipher) KeyIDs() []uint32 {
	r := c.loadRing()
	if r == nil {
		return nil
	}
	out := make([]uint32, 0, len(r.keys))
	for id := range r.keys {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HoldsKey reports whether the Cipher holds key id with this check, so a
// ring re-read can skip unwrapping it again.
func (c *Cipher) HoldsKey(id uint32, check []byte) bool {
	r := c.loadRing()
	if r == nil || r.keys[id] == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return hmac.Equal(c.checks[id], check)
}

// Rotating reports whether the ring holds more than one key: a rotation is
// staged or a retired-to-be key is still readable, so rows may be on a key
// other than the current one.
func (c *Cipher) Rotating() bool {
	r := c.loadRing()
	return r != nil && len(r.keys) > 1
}

// Reseal returns sealed under the current key. A blob already on it comes
// back unchanged with changed false; any other is opened and sealed again
// with the same AAD. from is the key that opened it.
func (c *Cipher) Reseal(sealed, aad []byte) (out []byte, from uint32, changed bool, err error) {
	r, err := c.activeRing()
	if err != nil {
		return nil, 0, false, err
	}
	plain, from, err := c.OpenWithKeyID(sealed, aad)
	if err != nil {
		return nil, 0, false, err
	}
	if from == r.current {
		return sealed, from, false, nil
	}
	out, err = c.EncryptWithAAD(plain, aad)
	if err != nil {
		return nil, from, false, err
	}
	return out, from, true, nil
}

// SealedKeyID names the key a blob says it was sealed with, without opening
// it: the id after the marker, or 0 (legacy) for a blob without one. A
// legacy blob that happens to start with the marker reads as another id;
// open it to be sure.
func SealedKeyID(sealed []byte) uint32 {
	if len(sealed) > keyIDHeaderLen && sealed[0] == keyIDMarker {
		return binary.BigEndian.Uint32(sealed[1:keyIDHeaderLen])
	}
	return 0
}

func (c *Cipher) loadRing() *keyRing {
	if c == nil {
		return nil
	}
	return c.ring.Load()
}

func (c *Cipher) activeRing() (*keyRing, error) {
	if c == nil {
		return nil, errors.New("cipher not initialized")
	}
	if r := c.ring.Load(); r != nil {
		if c.afterLoad != nil {
			c.afterLoad()
		}
		return r, nil
	}
	if c.revoked.Load() {
		return nil, fmt.Errorf("%w: the server key was dropped", ErrKeyRevoked)
	}
	return nil, errors.New("cipher not initialized")
}

// Encrypt seals plaintext. Empty input is allowed and produces a non-empty
// sealed blob (the nonce alone authenticates that no plaintext was sealed).
func (c *Cipher) Encrypt(plain []byte) ([]byte, error) {
	return c.EncryptWithAAD(plain, nil)
}

func (c *Cipher) EncryptWithAAD(plain []byte, aad []byte) ([]byte, error) {
	r, err := c.activeRing()
	if err != nil {
		return nil, err
	}
	gcm := r.keys[r.current]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	var out []byte
	if r.current != 0 {
		out = make([]byte, keyIDHeaderLen, keyIDHeaderLen+len(nonce)+len(plain)+gcm.Overhead())
		out[0] = keyIDMarker
		binary.BigEndian.PutUint32(out[1:keyIDHeaderLen], r.current)
	}
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, aad), nil
}

// Decrypt opens a sealed blob produced by Encrypt. Tampering, truncation, or
// using a different key all return an error.
func (c *Cipher) Decrypt(sealed []byte) ([]byte, error) {
	return c.DecryptWithAAD(sealed, nil)
}

func (c *Cipher) DecryptWithAAD(sealed []byte, aad []byte) ([]byte, error) {
	plain, _, err := c.OpenWithKeyID(sealed, aad)
	return plain, err
}

// OpenWithKeyID opens sealed and says which key opened it. The key-id form
// is tried first; GCM authenticates the attempt, so a legacy blob that
// happens to start with the marker fails it cleanly and is then opened as
// legacy, under key id 0 (authenticated dual read, §13).
func (c *Cipher) OpenWithKeyID(sealed []byte, aad []byte) ([]byte, uint32, error) {
	r, err := c.activeRing()
	if err != nil {
		return nil, 0, err
	}
	if len(sealed) > keyIDHeaderLen && sealed[0] == keyIDMarker {
		id := binary.BigEndian.Uint32(sealed[1:keyIDHeaderLen])
		if gcm, ok := r.keys[id]; ok {
			if plain, err := openGCM(gcm, sealed[keyIDHeaderLen:], aad); err == nil {
				return plain, id, nil
			}
		}
	}
	legacy, ok := r.keys[0]
	if !ok {
		return nil, 0, errors.New("decrypt: no key in the ring opens this blob (its key may be retired)")
	}
	plain, err := openGCM(legacy, sealed, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt: %w", err)
	}
	return plain, 0, nil
}

func openGCM(gcm cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed blob too short")
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, aad)
}

func loadOrGenerateKey(keyB64, fallbackPath string) ([]byte, error) {
	if keyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(decoded))
		}
		return decoded, nil
	}

	if fallbackPath == "" {
		return nil, errors.New("no encryption key configured and no fallback path provided")
	}

	if data, err := os.ReadFile(fallbackPath); err == nil {
		decoded, decErr := base64.StdEncoding.DecodeString(string(data))
		if decErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("invalid encryption key at %s", fallbackPath)
		}
		return decoded, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key %s: %w", fallbackPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(fallbackPath), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(randReader, keyBytes); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(fallbackPath, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("write encryption key: %w", err)
	}
	return keyBytes, nil
}
