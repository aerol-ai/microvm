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
// version stored alongside the row; EnvelopeVersion is the identity-bound
// on-wire AEAD envelope format.
const (
	RefVersion = 1
	// EnvelopeVersion 4 binds sandbox identity into AEAD AAD (and KMS
	// EncryptionContext on the KMS path) so ciphertext cannot be relabeled
	// across sandboxes when recipient sets match.
	EnvelopeVersion = 4
)

// sealedSecretsEnvelope is the on-wire JSON envelope for cluster secrets.
type sealedSecretsEnvelope struct {
	Version    int      `json:"version"`
	Recipients []string `json:"recipients,omitempty"`
	SandboxID  string   `json:"sandbox_id,omitempty"`
	Ref        string   `json:"ref,omitempty"`
	RefVersion int      `json:"ref_version,omitempty"`
	Generation int64    `json:"generation,omitempty"`
	WrappedKey []byte   `json:"wrapped_key,omitempty"`
	Payload    []byte   `json:"payload"`
}

// SealBinding authenticates ciphertext to a specific sandbox handle.
type SealBinding struct {
	SandboxID  string
	Ref        string
	Version    int
	Generation int64
}

func (b SealBinding) normalized() SealBinding {
	b.SandboxID = strings.TrimSpace(b.SandboxID)
	b.Ref = strings.TrimSpace(b.Ref)
	if b.Version <= 0 {
		b.Version = RefVersion
	}
	if b.Generation <= 0 {
		b.Generation = 1
	}
	return b
}

func requireSealBinding(binding SealBinding) (SealBinding, error) {
	binding = binding.normalized()
	if binding.SandboxID == "" || binding.Ref == "" {
		return SealBinding{}, fmt.Errorf("cluster secret sandbox binding is required")
	}
	return binding, nil
}

func requireRecipients(recipients []string) ([]string, error) {
	recipients = NormalizeRecipients(recipients)
	if len(recipients) == 0 {
		return nil, fmt.Errorf("cluster secret recipient set is required")
	}
	for _, recipient := range recipients {
		if recipient == "*" {
			return nil, fmt.Errorf("cluster secret wildcard recipient is not allowed")
		}
	}
	return recipients, nil
}

// SealEnvelopeBound marshals s and seals it bound to sandbox identity.
func SealEnvelopeBound(c *Cipher, s Secrets, recipients []string, binding SealBinding) ([]byte, error) {
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
	return SealRawEnvelopeBound(c, plain, recipients, binding)
}

// OpenEnvelopeBound opens a sealed envelope and verifies its sandbox binding.
func OpenEnvelopeBound(c *Cipher, sealed []byte, nodeID string, expect SealBinding) (Secrets, error) {
	if len(sealed) == 0 {
		return Secrets{}, nil
	}
	plain, err := OpenRawEnvelopeBound(c, sealed, nodeID, expect)
	if err != nil {
		return Secrets{}, err
	}
	var bag Secrets
	if err := json.Unmarshal(plain, &bag); err != nil {
		return Secrets{}, fmt.Errorf("unmarshal cluster secrets: %w", err)
	}
	return bag, nil
}

// SealRawEnvelopeBound seals plaintext into a v4 identity-bound envelope.
func SealRawEnvelopeBound(c *Cipher, plain []byte, recipients []string, binding SealBinding) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("cluster secrets cipher is not configured")
	}
	var err error
	recipients, err = requireRecipients(recipients)
	if err != nil {
		return nil, err
	}
	binding, err = requireSealBinding(binding)
	if err != nil {
		return nil, err
	}
	return SealRawEnvelopeWrappedBound(plain, recipients, binding, func(dek []byte) ([]byte, error) {
		return c.EncryptWithAAD(dek, KeyAADBound(recipients, binding))
	})
}

// SealRawEnvelopeWrappedBound seals plaintext with a fresh DEK and stores wrap(dek)
// in WrappedKey. Recipients are still recorded for fan-out targeting even when
// the wrap backend (KMS) does not enforce recipient binding on Open.
func SealRawEnvelopeWrappedBound(plain []byte, recipients []string, binding SealBinding, wrap func(dek []byte) ([]byte, error)) ([]byte, error) {
	if wrap == nil {
		return nil, fmt.Errorf("cluster secret key wrap function is required")
	}
	var err error
	recipients, err = requireRecipients(recipients)
	if err != nil {
		return nil, err
	}
	binding, err = requireSealBinding(binding)
	if err != nil {
		return nil, err
	}
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
	payload := append(nonce, gcm.Seal(nil, nonce, plain, PayloadAADBound(recipients, binding))...)
	wrappedKey, err := wrap(dek)
	if err != nil {
		return nil, fmt.Errorf("wrap cluster secret data key: %w", err)
	}
	envelope, err := json.Marshal(sealedSecretsEnvelope{
		Version:    EnvelopeVersion,
		Recipients: recipients,
		SandboxID:  binding.SandboxID,
		Ref:        binding.Ref,
		RefVersion: binding.Version,
		Generation: binding.Generation,
		WrappedKey: wrappedKey,
		Payload:    payload,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal cluster secrets envelope: %w", err)
	}
	return envelope, nil
}

// OpenRawEnvelopeBound opens a v4 envelope and enforces its identity and recipient binding.
func OpenRawEnvelopeBound(c *Cipher, sealed []byte, nodeID string, expect SealBinding) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("cluster secrets cipher is not configured")
	}
	return openRawEnvelope(sealed, nodeID, true, expect, func(wrapped []byte, recipients []string, binding SealBinding) ([]byte, error) {
		return c.DecryptWithAAD(wrapped, KeyAADBound(recipients, binding))
	})
}

// OpenRawEnvelopeExternalBound opens with an expected sandbox binding for v4 AAD.
func OpenRawEnvelopeExternalBound(sealed []byte, expect SealBinding, unwrap func(wrapped []byte) ([]byte, error)) ([]byte, error) {
	if unwrap == nil {
		return nil, fmt.Errorf("cluster secret key unwrap function is required")
	}
	return openRawEnvelope(sealed, "", false, expect, func(wrapped []byte, _ []string, _ SealBinding) ([]byte, error) {
		return unwrap(wrapped)
	})
}

func openRawEnvelope(
	sealed []byte,
	nodeID string,
	checkRecipient bool,
	expect SealBinding,
	unwrap func(wrapped []byte, recipients []string, binding SealBinding) ([]byte, error),
) ([]byte, error) {
	var envelope sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		return nil, fmt.Errorf("%w: unmarshal cluster secret envelope: %v", ErrDecryptFailed, err)
	}
	if envelope.Version != EnvelopeVersion {
		return nil, fmt.Errorf("%w: unsupported cluster secret envelope version %d", ErrDecryptFailed, envelope.Version)
	}
	if len(envelope.Payload) == 0 || len(envelope.WrappedKey) == 0 {
		return nil, fmt.Errorf("%w: cluster secret envelope is incomplete", ErrDecryptFailed)
	}
	recipients, err := requireRecipients(envelope.Recipients)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}
	if checkRecipient && !RecipientAllowed(recipients, nodeID) {
		return nil, fmt.Errorf("%w: recipient %q is not allowed to open this cluster secret", ErrRecipientDenied, nodeID)
	}
	binding, err := requireSealBinding(SealBinding{
		SandboxID: envelope.SandboxID, Ref: envelope.Ref, Version: envelope.RefVersion, Generation: envelope.Generation,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}
	want, err := requireSealBinding(expect)
	if err != nil {
		return nil, fmt.Errorf("%w: expected cluster secret binding is required", ErrDecryptFailed)
	}
	if binding.SandboxID != want.SandboxID || binding.Ref != want.Ref || binding.Version != want.Version {
		return nil, fmt.Errorf("%w: cluster secret binding mismatch", ErrDecryptFailed)
	}
	if binding.Generation != want.Generation {
		return nil, fmt.Errorf("%w: cluster secret generation mismatch", ErrDecryptFailed)
	}
	dek, err := unwrap(envelope.WrappedKey, recipients, binding)
	if err != nil {
		if errors.Is(err, ErrProviderUnavailable) || errors.Is(err, ErrProviderThrottled) || errors.Is(err, ErrProviderDenied) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: unwrap cluster secret data key: %v", ErrDecryptFailed, err)
	}
	return OpenEnvelopePayloadBound(dek, envelope.Payload, recipients, binding)
}

// OpenEnvelopePayloadBound decrypts a v4 payload with a raw data key.
func OpenEnvelopePayloadBound(dek []byte, sealed []byte, recipients []string, binding SealBinding) ([]byte, error) {
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
	plain, err := gcm.Open(nil, nonce, body, PayloadAADBound(recipients, binding))
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt cluster secret payload: %v", ErrDecryptFailed, err)
	}
	return plain, nil
}

// NormalizeRecipients trims, dedupes, and sorts recipient node IDs.
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
	sort.Strings(out)
	return out
}

// RecipientAllowed reports whether nodeID may open an envelope sealed for recipients.
func RecipientAllowed(recipients []string, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	for _, r := range recipients {
		if nodeID != "" && r == nodeID {
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
	if envelope.Version != EnvelopeVersion {
		return nil, fmt.Errorf("unsupported cluster secret envelope version %d", envelope.Version)
	}
	return requireRecipients(envelope.Recipients)
}

// EnvelopeBindingFields is the authenticated identity carried on a sealed envelope.
type EnvelopeBindingFields struct {
	Version      int // wire envelope version
	SandboxID    string
	Ref          string
	VersionField int // handle version (RefVersion)
	Generation   int64
}

// EnvelopeBinding returns full wire binding metadata without decrypting.
func EnvelopeBinding(sealed []byte) (EnvelopeBindingFields, error) {
	if len(sealed) == 0 {
		return EnvelopeBindingFields{}, fmt.Errorf("empty sealed payload")
	}
	var envelope sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		return EnvelopeBindingFields{}, fmt.Errorf("unmarshal cluster secret envelope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return EnvelopeBindingFields{}, fmt.Errorf("cluster secret envelope missing payload")
	}
	if envelope.Version != EnvelopeVersion {
		return EnvelopeBindingFields{}, fmt.Errorf("unsupported cluster secret envelope version %d", envelope.Version)
	}
	if strings.TrimSpace(envelope.SandboxID) == "" || strings.TrimSpace(envelope.Ref) == "" || envelope.RefVersion <= 0 || envelope.Generation <= 0 {
		return EnvelopeBindingFields{}, fmt.Errorf("cluster secret envelope binding is incomplete")
	}
	return EnvelopeBindingFields{
		Version:      envelope.Version,
		SandboxID:    strings.TrimSpace(envelope.SandboxID),
		Ref:          strings.TrimSpace(envelope.Ref),
		VersionField: envelope.RefVersion,
		Generation:   envelope.Generation,
	}, nil
}

// FormatRef builds the stable cluster-secret://sandbox/{id}/v{version} handle.
func FormatRef(sandboxID string, version int) string {
	return fmt.Sprintf("cluster-secret://sandbox/%s/v%d", strings.TrimSpace(sandboxID), version)
}

// KeyAADBound authenticates the wrapped data-key for v4 envelopes.
func KeyAADBound(recipients []string, b SealBinding) []byte {
	b = b.normalized()
	return []byte(fmt.Sprintf("aerolvm-cluster-secrets-v4-key\x00%s\x00%s\x00%d\x00%d\x00%s",
		b.SandboxID, b.Ref, b.Version, b.Generation, strings.Join(NormalizeRecipients(recipients), "\x00")))
}

// PayloadAADBound authenticates the ciphertext for v4 envelopes.
func PayloadAADBound(recipients []string, b SealBinding) []byte {
	b = b.normalized()
	return []byte(fmt.Sprintf("aerolvm-cluster-secrets-v4-payload\x00%s\x00%s\x00%d\x00%d\x00%s",
		b.SandboxID, b.Ref, b.Version, b.Generation, strings.Join(NormalizeRecipients(recipients), "\x00")))
}

// EncryptionContextForBinding is the AWS KMS EncryptionContext for v4 wraps.
func EncryptionContextForBinding(b SealBinding) map[string]string {
	b = b.normalized()
	return map[string]string{
		"aerolvm.sandbox_id": b.SandboxID,
		"aerolvm.ref":        b.Ref,
		"aerolvm.version":    fmt.Sprintf("%d", b.Version),
		"aerolvm.generation": fmt.Sprintf("%d", b.Generation),
	}
}
