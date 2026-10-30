package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Server-key custody (plans/customer-key-custody.md §3). With custody
// "wrapped" the 32-byte server key that seals env, registry, mounts, the
// egress CA and toolbox tokens exists on disk only wrapped by the customer's
// key store, and is unwrapped into memory at boot.
const (
	CustodyFile    = "file"
	CustodyWrapped = "wrapped"
)

// WrappedKeyFormat is the version of the wrapped server-key file.
const WrappedKeyFormat = 1

// serverKeyCheckLabel keys the check HMAC; serverKeyWrapContext is the
// encryption context of every server-key wrap, so a server-key wrap cannot be
// swapped with a row DEK.
const serverKeyCheckLabel = "aerolvm-server-key-check/v1"

func serverKeyWrapContext() map[string]string {
	return map[string]string{"aerolvm.purpose": "server-key", "aerolvm.format": "1"}
}

// WrappedKeyFile is the wrapped server-key file, mode 0600.
type WrappedKeyFile struct {
	Format   int    `json:"format"`
	Provider string `json:"provider"`
	KeyRef   string `json:"key_ref,omitempty"`
	Wrapped  []byte `json:"wrapped"`
	// Check is HMAC-SHA256(serverKey, serverKeyCheckLabel)[:16]: a wrong key
	// is caught before the store opens instead of failing every decrypt.
	Check []byte `json:"check"`
	// MigratedFromPlaintext marks a key that existed in plaintext before it
	// was wrapped. Old backups and bundles still hold that plaintext, so
	// `sandboxd key status` says so until `sandboxd key ack-migration`
	// (eng D24).
	MigratedFromPlaintext bool `json:"migrated_from_plaintext,omitempty"`
	// Ring is the server-key ring of a format 2 file (§13); Wrapped and
	// Check above are then the current key's.
	Ring []RingEntry `json:"ring,omitempty"`
}

// KeyVersion names what the file is wrapped under, for the custody report:
// "vault:v3", "p11:<label>", or "" when the backend does not say.
func (f WrappedKeyFile) KeyVersion() string { return WrappedKeyVersion(f.Wrapped) }

func serverKeyCheck(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(serverKeyCheckLabel))
	return m.Sum(nil)[:16]
}

// NewServerKey returns 32 fresh random bytes.
func NewServerKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(randReader, key); err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	return key, nil
}

// WrapServerKey wraps key with w under the server-key wrap context.
func WrapServerKey(ctx context.Context, w DataKeyWrapper, key []byte, provider, keyRef string) (WrappedKeyFile, error) {
	if len(key) != 32 {
		return WrappedKeyFile{}, fmt.Errorf("server key must be 32 bytes, got %d", len(key))
	}
	if w == nil {
		return WrappedKeyFile{}, fmt.Errorf("%w: no key store to wrap the server key", ErrProviderUnavailable)
	}
	wrapped, err := w.Wrap(ctx, key, serverKeyWrapContext())
	if err != nil {
		return WrappedKeyFile{}, fmt.Errorf("wrap server key: %w", err)
	}
	return WrappedKeyFile{Format: WrappedKeyFormat, Provider: provider, KeyRef: keyRef, Wrapped: wrapped, Check: serverKeyCheck(key)}, nil
}

// ErrServerKeyCheck means the key store unwrapped the file to a key whose
// check does not match: the wrong file, or a file edited by hand.
var ErrServerKeyCheck = errors.New("unwrapped server key does not match the file's check")

// UnwrapServerKey unwraps f with w and verifies its check.
func UnwrapServerKey(ctx context.Context, w DataKeyWrapper, f WrappedKeyFile) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("%w: no key store to unwrap the server key", ErrProviderUnavailable)
	}
	key, err := w.Unwrap(ctx, f.Wrapped, serverKeyWrapContext())
	if err != nil {
		return nil, fmt.Errorf("unwrap server key: %w", err)
	}
	if len(key) != 32 || !hmac.Equal(serverKeyCheck(key), f.Check) {
		return nil, ErrServerKeyCheck
	}
	return key, nil
}

// ReadWrappedKeyFile reads and validates the wrapped server-key file. A file
// others can read is refused like every secret file (eng D14), though it is
// ciphertext: the rule stays one rule.
func ReadWrappedKeyFile(path string) (WrappedKeyFile, error) {
	if err := RefuseGroupOtherBits(path); err != nil {
		return WrappedKeyFile{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return WrappedKeyFile{}, fmt.Errorf("read wrapped server key: %w", err)
	}
	var f WrappedKeyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return WrappedKeyFile{}, fmt.Errorf("wrapped server key %s is not valid JSON: %w", path, err)
	}
	if f.Format != WrappedKeyFormat && f.Format != WrappedKeyRingFormat {
		return WrappedKeyFile{}, fmt.Errorf("wrapped server key %s has format %d; this sandboxd reads formats %d and %d", path, f.Format, WrappedKeyFormat, WrappedKeyRingFormat)
	}
	if len(f.Wrapped) == 0 || len(f.Check) != 16 {
		return WrappedKeyFile{}, fmt.Errorf("wrapped server key %s is missing its wrapped key or check", path)
	}
	if f.Format == WrappedKeyRingFormat {
		if err := validateRing(f.Ring, true); err != nil {
			return WrappedKeyFile{}, fmt.Errorf("%s: %w", path, err)
		}
		if cur := currentEntry(f.Ring); !bytes.Equal(cur.Wrapped, f.Wrapped) || !bytes.Equal(cur.Check, f.Check) {
			return WrappedKeyFile{}, fmt.Errorf("wrapped server key %s: the top-level key is not the ring's current key (edited by hand?)", path)
		}
	} else if len(f.Ring) != 0 {
		return WrappedKeyFile{}, fmt.Errorf("wrapped server key %s: format %d has no ring", path, WrappedKeyFormat)
	}
	return f, nil
}

// WriteWrappedKeyFile writes f to path atomically at mode 0600.
func WriteWrappedKeyFile(path string, f WrappedKeyFile) error {
	return writeSecretJSON(path, f, ".wrapped-key-*")
}

// LoadPlaintextKey reads the plaintext server key from the env value or the
// key file, never generating one. ok is false when neither exists.
func LoadPlaintextKey(keyB64, path string) (key []byte, ok bool, err error) {
	if keyB64 != "" {
		key, err := loadOrGenerateKey(keyB64, "")
		return key, err == nil, err
	}
	if path == "" {
		return nil, false, nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	key, err = loadOrGenerateKey("", path)
	return key, err == nil, err
}

// NewCipherFromKey builds a Cipher from a 32-byte key.
func NewCipherFromKey(key []byte) (*Cipher, error) {
	return NewCipher(base64.StdEncoding.EncodeToString(key), "")
}

// CustodyInputs is everything the boot decision reads.
type CustodyInputs struct {
	Custody             string
	PlaintextEnvSet     bool
	PlaintextFileExists bool
	WrappedFileExists   bool
	ClusterMode         bool
	StateDBExists       bool
	PlaintextPath       string
	WrappedPath         string
	// RingFileExists: custody=file's ring file exists at RingPath (§13).
	RingFileExists bool
	RingPath       string
}

// CustodyAction is what boot does to get the server key.
type CustodyAction int

const (
	// ActionPlaintext is today's behavior: the env value, else the key file,
	// generated on first boot.
	ActionPlaintext CustodyAction = iota
	// ActionUnwrap reads and unwraps the wrapped file.
	ActionUnwrap
	// ActionGenerateWrapped makes a fresh key and writes only the wrapped
	// file: single node, first boot.
	ActionGenerateWrapped
	// ActionRefuse stops the boot; the reason says why and what to do.
	ActionRefuse
)

// DecideCustody is the boot decision of §3 as a pure function.
func DecideCustody(in CustodyInputs) (CustodyAction, string) {
	if in.Custody != CustodyWrapped {
		if !in.PlaintextEnvSet && !in.PlaintextFileExists && !in.RingFileExists && in.WrappedFileExists {
			// Generating a fresh plaintext key here would split this node
			// from every row sealed under the wrapped one.
			return ActionRefuse, fmt.Sprintf("SB_CREDENTIAL_KEY_CUSTODY=file, but the only server key is the wrapped one at %s; set SB_CREDENTIAL_KEY_CUSTODY=wrapped, or run `sandboxd key unwrap --to-file --i-understand-plaintext` to go back to a plaintext key", in.WrappedPath)
		}
		return ActionPlaintext, ""
	}
	// F1: a plaintext copy left behind makes the custody claim false.
	if in.PlaintextEnvSet {
		return ActionRefuse, "SB_CREDENTIAL_KEY_CUSTODY=wrapped, but SB_CREDENTIAL_ENCRYPTION_KEY is set; remove the plaintext key from the environment (for example from /etc/sandboxd/cluster.env)"
	}
	if in.PlaintextFileExists {
		return ActionRefuse, fmt.Sprintf("SB_CREDENTIAL_KEY_CUSTODY=wrapped, but a plaintext key file exists at %s; once `sandboxd key verify` succeeds, delete it", in.PlaintextPath)
	}
	if in.RingFileExists {
		return ActionRefuse, fmt.Sprintf("SB_CREDENTIAL_KEY_CUSTODY=wrapped, but a plaintext server-key ring exists at %s; once `sandboxd key verify` succeeds, delete it", in.RingPath)
	}
	if in.WrappedFileExists {
		return ActionUnwrap, ""
	}
	if in.ClusterMode {
		// The seed's key comes from `sandboxd key wrap --generate` in
		// cluster-init.sh; a node that minted its own would split the
		// cluster and orphan its rows.
		return ActionRefuse, fmt.Sprintf("no wrapped server key at %s; copy credential_encryption.key.wrapped from the seed (cluster nodes never generate a key)", in.WrappedPath)
	}
	if in.StateDBExists {
		return ActionRefuse, fmt.Sprintf("no wrapped server key at %s, but state.db exists: its rows are sealed under a key this node no longer has; restore the wrapped file from a backup", in.WrappedPath)
	}
	return ActionGenerateWrapped, ""
}

// OpenServerKey runs the boot decision and returns the Cipher. w is the
// external key store (nil for local). A key-store call gets at most
// unwrapTimeout; sandboxd.service restarts the daemon, so there is no retry
// loop here (§3 failure rule).
func OpenServerKey(ctx context.Context, in CustodyInputs, plaintextB64 string, w DataKeyWrapper, provider, keyRef string) (*Cipher, error) {
	action, reason := DecideCustody(in)
	switch action {
	case ActionRefuse:
		return nil, errors.New(reason)
	case ActionPlaintext:
		if in.RingFileExists {
			return openKeyRingFile(in, plaintextB64)
		}
		return NewCipher(plaintextB64, in.PlaintextPath)
	}
	ctx, cancel := context.WithTimeout(ctx, unwrapTimeout)
	defer cancel()
	if action == ActionUnwrap {
		f, err := ReadWrappedKeyFile(in.WrappedPath)
		if err != nil {
			return nil, err
		}
		keys, err := UnwrapRing(ctx, w, f, nil)
		if err != nil {
			return nil, err
		}
		return NewCipherRing(keys)
	}
	key, err := NewServerKey()
	if err != nil {
		return nil, err
	}
	f, err := WrapServerKey(ctx, w, key, provider, keyRef)
	if err != nil {
		return nil, err
	}
	if err := WriteWrappedKeyFile(in.WrappedPath, f); err != nil {
		return nil, err
	}
	// Read it back through the key store before trusting it.
	back, err := ReadWrappedKeyFile(in.WrappedPath)
	if err != nil {
		return nil, err
	}
	if _, err := UnwrapServerKey(ctx, w, back); err != nil {
		return nil, fmt.Errorf("verify new wrapped server key: %w", err)
	}
	return NewCipherFromKey(key)
}

// openKeyRingFile opens custody=file's ring. A legacy key still in the
// environment or the key file must be the ring's key 0 while that key is
// live: a different key there means the ring belongs to another node.
func openKeyRingFile(in CustodyInputs, plaintextB64 string) (*Cipher, error) {
	f, err := ReadKeyRingFile(in.RingPath)
	if err != nil {
		return nil, err
	}
	legacy, ok, err := LoadPlaintextKey(plaintextB64, in.PlaintextPath)
	if err != nil {
		return nil, err
	}
	if e, live := f.Entry(0); ok && live && e.State != RingStateRetired && !hmac.Equal(serverKeyCheck(legacy), e.Check) {
		return nil, fmt.Errorf("the legacy server key (SB_CREDENTIAL_ENCRYPTION_KEY or %s) is not key 0 of the ring at %s", in.PlaintextPath, in.RingPath)
	}
	return NewCipherRing(f.RingKeys())
}

// RetiredKeyStillPresent reports a plaintext legacy key left behind after
// ring key 0 was retired: the rotation's claim needs it destroyed.
func RetiredKeyStillPresent(in CustodyInputs, plaintextB64 string) bool {
	if !in.RingFileExists {
		return false
	}
	f, err := ReadKeyRingFile(in.RingPath)
	if err != nil {
		return false
	}
	e, ok := f.Entry(0)
	return ok && e.State == RingStateRetired && (plaintextB64 != "" || in.PlaintextFileExists)
}

// unwrapTimeout bounds the boot unwrap (§3: one attempt, 10 s).
const unwrapTimeout = 10 * time.Second
