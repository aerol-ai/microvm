package cloudidentity

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// Algorithm is the only signing algorithm (D1.2).
	Algorithm = "RS256"
	// KeyBits is the RSA modulus size of a generated key, and the floor a
	// parsed key must meet.
	KeyBits = 2048
	// RetiredKeyPublishedFor is how long a rotated-out key stays in the
	// JWKS: twice the token lifetime, so every token it signed expires
	// first, with an hour to spare for clouds that cache the JWKS.
	RetiredKeyPublishedFor = 2 * time.Hour
	// MaxKeys bounds the key set, active key included. Each rotation adds
	// one key and the retired ones drop out after RetiredKeyPublishedFor,
	// so only a rotation loop reaches it; past it a rotation is refused
	// rather than growing the replicated state.
	MaxKeys = 8
)

var (
	// ErrKeySetInvalid is a key set that breaks an invariant: more than one
	// active key, a repeated key id, too many keys, or a public key that does
	// not match its id.
	ErrKeySetInvalid = errors.New("cloudidentity: invalid signing key set")
	// ErrTooManyKeys is a rotation that would hold more than MaxKeys keys.
	ErrTooManyKeys = fmt.Errorf("%w: too many keys; wait for rotated keys to expire (2 hours) before rotating again", ErrKeySetInvalid)
	// ErrWeakKey is a private key under KeyBits.
	ErrWeakKey = errors.New("cloudidentity: signing key is weaker than RSA-2048")
)

// KeyRecord is one signing key at rest: the private half sealed by the
// caller (never in the clear here), the public half as a JWK, and its life.
// It is what the store and the Raft FSM hold.
type KeyRecord struct {
	ID              string          `json:"kid"`
	SealedPrivate   []byte          `json:"sealed_private"`
	PublicJWK       json.RawMessage `json:"public_jwk"`
	CreatedUnixNano int64           `json:"created_unix_nano"`
	// RetiredUnixNano is when a rotation replaced this key; 0 while it is
	// the active key.
	RetiredUnixNano int64 `json:"retired_unix_nano,omitempty"`
}

// Active reports whether r is the key that signs.
func (r KeyRecord) Active() bool { return r.RetiredUnixNano == 0 }

// PublishedAt reports whether r belongs in the JWKS at now.
func (r KeyRecord) PublishedAt(now time.Time) bool {
	return r.Active() || now.UnixNano() < r.RetiredUnixNano+int64(RetiredKeyPublishedFor)
}

// Clone copies r's byte slices.
func (r KeyRecord) Clone() KeyRecord {
	r.SealedPrivate = append([]byte(nil), r.SealedPrivate...)
	r.PublicJWK = append(json.RawMessage(nil), r.PublicJWK...)
	return r
}

// KeySet is the deployment's signing keys. Generation counts writes: a
// writer names the generation it read and the write applies only if it is
// still current, so two nodes that both find no key, or both rotate, cannot
// both win.
type KeySet struct {
	Generation int64       `json:"generation"`
	Keys       []KeyRecord `json:"keys"`
}

// Clone copies s deeply.
func (s KeySet) Clone() KeySet {
	out := KeySet{Generation: s.Generation}
	if s.Keys != nil {
		out.Keys = make([]KeyRecord, len(s.Keys))
		for i, k := range s.Keys {
			out.Keys[i] = k.Clone()
		}
	}
	return out
}

// Active returns the key that signs.
func (s KeySet) Active() (KeyRecord, bool) {
	for _, k := range s.Keys {
		if k.Active() {
			return k, true
		}
	}
	return KeyRecord{}, false
}

// Published returns the keys the JWKS lists at now, active key first.
func (s KeySet) Published(now time.Time) []KeyRecord {
	var out []KeyRecord
	for _, k := range s.Keys {
		if k.PublishedAt(now) {
			out = append(out, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Active() != out[j].Active() {
			return out[i].Active()
		}
		return out[i].RetiredUnixNano > out[j].RetiredUnixNano
	})
	return out
}

// Validate checks the invariants every writer and the FSM apply rely on.
// An empty set is valid: it is the state before the first key.
func (s KeySet) Validate() error {
	if len(s.Keys) > MaxKeys {
		return ErrTooManyKeys
	}
	seen := make(map[string]bool, len(s.Keys))
	active := 0
	for _, k := range s.Keys {
		if k.ID == "" || seen[k.ID] {
			return fmt.Errorf("%w: missing or repeated key id", ErrKeySetInvalid)
		}
		seen[k.ID] = true
		if len(k.SealedPrivate) == 0 {
			return fmt.Errorf("%w: key %s has no sealed private key", ErrKeySetInvalid, k.ID)
		}
		pub, err := parsePublicJWK(k.PublicJWK)
		if err != nil {
			return fmt.Errorf("%w: key %s: %v", ErrKeySetInvalid, k.ID, err)
		}
		if id, err := KeyID(pub); err != nil || id != k.ID {
			return fmt.Errorf("%w: key %s: public key does not match its id", ErrKeySetInvalid, k.ID)
		}
		if k.Active() {
			active++
		}
	}
	if len(s.Keys) > 0 && active != 1 {
		return fmt.Errorf("%w: %d active keys, want exactly 1", ErrKeySetInvalid, active)
	}
	return nil
}

// Rotate returns s with next as the active key: the current active key is
// retired at now, and retired keys whose JWKS window has passed are dropped.
// Generation is left to the writer. next must be active.
func (s KeySet) Rotate(next KeyRecord, now time.Time) (KeySet, error) {
	if !next.Active() {
		return KeySet{}, fmt.Errorf("%w: the new key must be active", ErrKeySetInvalid)
	}
	out := KeySet{Generation: s.Generation}
	for _, k := range s.Keys {
		k = k.Clone()
		if k.Active() {
			k.RetiredUnixNano = now.UnixNano()
		}
		if k.PublishedAt(now) {
			out.Keys = append(out.Keys, k)
		}
	}
	out.Keys = append(out.Keys, next.Clone())
	if err := out.Validate(); err != nil {
		return KeySet{}, err
	}
	return out, nil
}

// GenerateKey makes a new RSA-2048 signing key.
func GenerateKey(rand io.Reader) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand, KeyBits)
	if err != nil {
		return nil, fmt.Errorf("cloudidentity: generate signing key: %w", err)
	}
	return key, nil
}

// KeyID is the key's RFC 7638 thumbprint, base64url: stable for a key, so
// every node derives the same id, and the JWKS never names one key twice.
func KeyID(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("cloudidentity: no public key")
	}
	sum, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("cloudidentity: key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// PublicJWK is the JWKS entry of pub under kid.
func PublicJWK(pub *rsa.PublicKey, kid string) (json.RawMessage, error) {
	if pub == nil || pub.N.BitLen() < KeyBits {
		return nil, ErrWeakKey
	}
	raw, err := (&jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: Algorithm, Use: "sig"}).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("cloudidentity: encode public key: %w", err)
	}
	return raw, nil
}

func parsePublicJWK(raw json.RawMessage) (*rsa.PublicKey, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if !jwk.IsPublic() {
		// The JWKS is served unauthenticated (D1.1): a record whose public
		// half carries private material must never be published.
		return nil, errors.New("public key record holds private material")
	}
	pub, ok := jwk.Key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	if pub.N.BitLen() < KeyBits {
		return nil, ErrWeakKey
	}
	return pub, nil
}

// MarshalPrivateKey is the private key as PKCS#8 DER, for the caller to seal
// at once. It is the only place the private key leaves memory.
func MarshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	if key == nil || key.N.BitLen() < KeyBits {
		return nil, ErrWeakKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cloudidentity: encode signing key: %w", err)
	}
	return der, nil
}

// ParsePrivateKey reads what MarshalPrivateKey wrote, after the caller
// opened the seal.
func ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("cloudidentity: decode signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("cloudidentity: signing key is not RSA")
	}
	if key.N.BitLen() < KeyBits {
		return nil, ErrWeakKey
	}
	return key, nil
}

// SealAAD binds a sealed private key to its key id, so one key's sealed
// bytes cannot be swapped in under another key's id.
func SealAAD(kid string) []byte {
	aad, _ := json.Marshal([2]string{"identity-signing-key/v1", kid})
	return aad
}

// NewKeyRecord builds the record of a freshly generated key: its id, its
// public JWK and the private key sealed by seal (which is given the AAD to
// bind). The plaintext DER is wiped once sealed.
func NewKeyRecord(key *rsa.PrivateKey, now time.Time, seal func(plain, aad []byte) ([]byte, error)) (KeyRecord, error) {
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return KeyRecord{}, err
	}
	jwk, err := PublicJWK(&key.PublicKey, kid)
	if err != nil {
		return KeyRecord{}, err
	}
	der, err := MarshalPrivateKey(key)
	if err != nil {
		return KeyRecord{}, err
	}
	sealed, err := seal(der, SealAAD(kid))
	clear(der)
	if err != nil {
		return KeyRecord{}, fmt.Errorf("cloudidentity: seal signing key: %w", err)
	}
	return KeyRecord{ID: kid, SealedPrivate: sealed, PublicJWK: jwk, CreatedUnixNano: now.UnixNano()}, nil
}

// JWKS is the public key set document of keys.
func JWKS(keys []KeyRecord) ([]byte, error) {
	doc := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: make([]json.RawMessage, 0, len(keys))}
	for _, k := range keys {
		if _, err := parsePublicJWK(k.PublicJWK); err != nil {
			return nil, fmt.Errorf("cloudidentity: key %s: %w", k.ID, err)
		}
		doc.Keys = append(doc.Keys, k.PublicJWK)
	}
	return json.Marshal(doc)
}
