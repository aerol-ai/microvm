package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Envelope / handle version constants. RefVersion is the provider handle
// version stored alongside the row; EnvelopeVersion is the on-wire AEAD
// envelope format (v3 = per-secret DEK + recipient binding).
//
// RefVersionEnv (2) marks bags that include Env. Nodes that do not support
// env merge must reject Version > MaxSupportedRefVersion loudly rather than
// recreate with a silently empty environment (plans/secrets-hardening §5c).
const (
	RefVersion             = 1
	RefVersionEnv          = 2
	MaxSupportedRefVersion = RefVersionEnv
	EnvelopeVersion        = 3
)

// HandleVersionFor returns the provider handle version for s. Env-bearing
// bags use RefVersionEnv so mixed-version clusters fail closed.
func HandleVersionFor(s Secrets) int {
	if len(s.Env) > 0 {
		return RefVersionEnv
	}
	return RefVersion
}

// sealedSecretsEnvelope is the on-wire JSON envelope for cluster secrets.
type sealedSecretsEnvelope struct {
	Version    int      `json:"version"`
	Recipients []string `json:"recipients,omitempty"`
	WrappedKey []byte   `json:"wrapped_key,omitempty"`
	Payload    []byte   `json:"payload"`
}

// SealEnvelope marshals s and seals it for recipients. Returns nil/nil when s
// is empty so callers can short-circuit without writing a row.
func SealEnvelope(c *Cipher, s Secrets, recipients []string) ([]byte, error) {
	if s.IsEmpty() {
		return nil, nil
	}
	if c == nil {
		return nil, fmt.Errorf("cluster secrets cipher is not configured")
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal cluster secrets: %w", err)
	}
	return SealRawEnvelope(c, plain, recipients)
}

// OpenEnvelope opens a sealed envelope and unmarshals the Secrets bag.
func OpenEnvelope(c *Cipher, sealed []byte, nodeID string) (Secrets, error) {
	if len(sealed) == 0 {
		return Secrets{}, nil
	}
	plain, err := OpenRawEnvelope(c, sealed, nodeID)
	if err != nil {
		return Secrets{}, err
	}
	var bag Secrets
	if err := json.Unmarshal(plain, &bag); err != nil {
		return Secrets{}, fmt.Errorf("unmarshal cluster secrets: %w", err)
	}
	return bag, nil
}

// SealRawEnvelope seals pre-marshaled plaintext into a v3 recipient envelope.
// Uses crypto/rand.Reader (not package randReader) so service tests that inject
// entropy via crypto/rand.Reader keep working.
func SealRawEnvelope(c *Cipher, plain []byte, recipients []string) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("cluster secrets cipher is not configured")
	}
	recipients = NormalizeRecipients(recipients)
	return SealRawEnvelopeWrapped(plain, recipients, func(dek []byte) ([]byte, error) {
		return c.EncryptWithAAD(dek, KeyAAD(recipients))
	})
}

// SealRawEnvelopeWrapped seals plaintext with a fresh DEK and stores wrap(dek)
// in WrappedKey. Recipients are still recorded for fan-out targeting even when
// the wrap backend (KMS) does not enforce recipient binding on Open.
func SealRawEnvelopeWrapped(plain []byte, recipients []string, wrap func(dek []byte) ([]byte, error)) ([]byte, error) {
	if wrap == nil {
		return nil, fmt.Errorf("cluster secret key wrap function is required")
	}
	recipients = NormalizeRecipients(recipients)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate cluster secret data key: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cluster secret data cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cluster secret data gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cluster secret data nonce: %w", err)
	}
	payload := append(nonce, gcm.Seal(nil, nonce, plain, PayloadAAD(recipients))...)
	wrappedKey, err := wrap(dek)
	if err != nil {
		return nil, fmt.Errorf("wrap cluster secret data key: %w", err)
	}
	envelope, err := json.Marshal(sealedSecretsEnvelope{
		Version:    EnvelopeVersion,
		Recipients: recipients,
		WrappedKey: wrappedKey,
		Payload:    payload,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal cluster secrets envelope: %w", err)
	}
	return envelope, nil
}

// OpenRawEnvelope decrypts a sealed envelope (v3, v2, or legacy raw) to plaintext bytes.
// Enforces recipient binding (WALL 2) for the local Cipher path.
func OpenRawEnvelope(c *Cipher, sealed []byte, nodeID string) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("cluster secrets cipher is not configured")
	}
	return openRawEnvelope(sealed, nodeID, true, func(wrapped []byte, recipients []string) ([]byte, error) {
		return c.DecryptWithAAD(wrapped, KeyAAD(recipients))
	}, func(payload []byte, recipients []string) ([]byte, error) {
		return c.DecryptWithAAD(payload, V2AAD(recipients))
	}, c.Decrypt)
}

// OpenRawEnvelopeExternal opens a v3 envelope by unwrapping the DEK via unwrap.
// Skips recipient binding: authorization is the wrap backend (IAM / KMS policy).
// Legacy v2/raw envelopes are not supported on this path.
func OpenRawEnvelopeExternal(sealed []byte, unwrap func(wrapped []byte) ([]byte, error)) ([]byte, error) {
	if unwrap == nil {
		return nil, fmt.Errorf("cluster secret key unwrap function is required")
	}
	return openRawEnvelope(sealed, "", false, func(wrapped []byte, _ []string) ([]byte, error) {
		return unwrap(wrapped)
	}, nil, nil)
}

func openRawEnvelope(
	sealed []byte,
	nodeID string,
	checkRecipient bool,
	unwrapV3 func(wrapped []byte, recipients []string) ([]byte, error),
	decryptV2 func(payload []byte, recipients []string) ([]byte, error),
	decryptLegacy func(sealed []byte) ([]byte, error),
) ([]byte, error) {
	var envelope sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &envelope); err == nil && len(envelope.Payload) > 0 {
		recipients := NormalizeRecipients(envelope.Recipients)
		if checkRecipient && !RecipientAllowed(recipients, nodeID) {
			return nil, fmt.Errorf("%w: recipient %q is not allowed to open this cluster secret", ErrRecipientDenied, nodeID)
		}
		switch envelope.Version {
		case EnvelopeVersion:
			if len(envelope.WrappedKey) == 0 {
				return nil, fmt.Errorf("%w: cluster secret envelope missing wrapped data key", ErrDecryptFailed)
			}
			if unwrapV3 == nil {
				return nil, fmt.Errorf("%w: cluster secret unwrap function is required", ErrDecryptFailed)
			}
			dek, err := unwrapV3(envelope.WrappedKey, recipients)
			if err != nil {
				// Preserve typed provider failures (throttle/deny/unavailable)
				// so callers can errors.Is without string-matching.
				if errors.Is(err, ErrProviderUnavailable) ||
					errors.Is(err, ErrProviderThrottled) ||
					errors.Is(err, ErrProviderDenied) {
					return nil, err
				}
				return nil, fmt.Errorf("%w: unwrap cluster secret data key: %v", ErrDecryptFailed, err)
			}
			return OpenEnvelopePayload(dek, envelope.Payload, recipients)
		case 2:
			if decryptV2 == nil {
				return nil, fmt.Errorf("%w: legacy v2 envelope not supported by this provider", ErrDecryptFailed)
			}
			plain, err := decryptV2(envelope.Payload, recipients)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
			}
			return plain, nil
		}
	}
	// Legacy raw nonce||ciphertext blob. Kept for rolling upgrades and
	// snapshots written before v2 recipient envelopes existed.
	if decryptLegacy == nil {
		return nil, fmt.Errorf("%w: legacy raw envelope not supported by this provider", ErrDecryptFailed)
	}
	plain, err := decryptLegacy(sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}
	return plain, nil
}

// OpenEnvelopePayload decrypts a v3 payload with a raw data key. Exported for
// service coverage tests that exercise the DEK/payload path directly.
func OpenEnvelopePayload(dek []byte, sealed []byte, recipients []string) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("%w: cluster secret data cipher: %v", ErrDecryptFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: cluster secret data gcm: %v", ErrDecryptFailed, err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: cluster secret payload too short", ErrDecryptFailed)
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, PayloadAAD(recipients))
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt cluster secret payload: %v", ErrDecryptFailed, err)
	}
	return plain, nil
}

// NormalizeRecipients trims, dedupes, and sorts recipient node IDs. An empty
// input becomes the legacy wildcard "*" so old envelopes keep opening.
func NormalizeRecipients(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	if len(out) == 0 {
		out = append(out, "*")
	}
	sort.Strings(out)
	return out
}

// RecipientAllowed reports whether nodeID may open an envelope sealed for recipients.
func RecipientAllowed(recipients []string, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	for _, r := range recipients {
		if r == "*" || (nodeID != "" && r == nodeID) {
			return true
		}
	}
	return false
}

// EnvelopeRecipients returns the recipient list declared in a sealed envelope
// without decrypting the payload. Used by peer-receive validation so a node
// can reject blobs that do not name it before storing ciphertext.
func EnvelopeRecipients(sealed []byte) ([]string, error) {
	if len(sealed) == 0 {
		return nil, fmt.Errorf("empty sealed payload")
	}
	var envelope sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal cluster secret envelope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return nil, fmt.Errorf("cluster secret envelope missing payload")
	}
	return NormalizeRecipients(envelope.Recipients), nil
}

// FormatRef builds the stable cluster-secret://sandbox/{id}/v{version} handle.
func FormatRef(sandboxID string, version int) string {
	return fmt.Sprintf("cluster-secret://sandbox/%s/v%d", strings.TrimSpace(sandboxID), version)
}

// V2AAD is the additional authenticated data for legacy v2 envelopes.
func V2AAD(recipients []string) []byte {
	return []byte("aerolvm-cluster-secrets-v2\x00" + strings.Join(NormalizeRecipients(recipients), "\x00"))
}

// KeyAAD authenticates the wrapped data-key for v3 envelopes.
func KeyAAD(recipients []string) []byte {
	return []byte("aerolvm-cluster-secrets-v3-key\x00" + strings.Join(NormalizeRecipients(recipients), "\x00"))
}

// PayloadAAD authenticates the ciphertext for v3 envelopes.
func PayloadAAD(recipients []string) []byte {
	return []byte("aerolvm-cluster-secrets-v3-payload\x00" + strings.Join(NormalizeRecipients(recipients), "\x00"))
}
