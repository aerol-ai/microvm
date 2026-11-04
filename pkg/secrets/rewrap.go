package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The rewrap sweep (plans/customer-key-custody.md §11, §12). Rotating a key
// is free; retiring the old version is not, because every row sealed earlier
// still wraps its data key under it. The sweep moves each row's WrappedKey
// onto the sealing provider's current key. The payload, its AAD, the seal
// generation and the ref stay the same.

// WrappedKeyVersion names the key a wrapped key is under: "vault:v3" for
// Vault Transit, "p11:<label>" for PKCS#11, "" for an untagged key (local or
// AWS KMS, which rotates in place and has no version to retire).
func WrappedKeyVersion(w []byte) string {
	s := string(w)
	switch {
	case strings.HasPrefix(s, tagVault):
		if i := strings.Index(s[len(tagVault):], ":"); i > 0 {
			return s[:len(tagVault)+i]
		}
	case strings.HasPrefix(s, tagPKCS11+"1:") && len(s) > len(tagPKCS11)+3:
		n := int(s[len(tagPKCS11)+2])
		if start := len(tagPKCS11) + 3; n > 0 && len(s) >= start+n {
			return tagPKCS11 + s[start:start+n]
		}
	}
	return ""
}

// KeyVersioner is a key store that names its current key in the form
// WrappedKeyVersion uses. AWS KMS does not implement it.
type KeyVersioner interface {
	CurrentKeyVersion(ctx context.Context) (string, error)
}

// CurrentKeyVersion asks w (through the limiter and the router) for the
// sealing provider's current key. ok is false when the provider has no
// versions to move between (AWS KMS).
func CurrentKeyVersion(ctx context.Context, w DataKeyWrapper) (version string, ok bool, err error) {
	v, isVersioner := w.(KeyVersioner)
	if !isVersioner {
		return "", false, nil
	}
	version, err = v.CurrentKeyVersion(ctx)
	if errors.Is(err, errNoKeyVersions) {
		return "", false, nil
	}
	return version, err == nil, err
}

// errNoKeyVersions is what a wrapper in the chain returns when the backend
// behind it has no key versions.
var errNoKeyVersions = errors.New("the key store has no key versions")

// CurrentKeyVersion implements KeyVersioner for the router: the sealing
// provider's current key.
func (r *Router) CurrentKeyVersion(ctx context.Context) (string, error) {
	if r == nil {
		return "", errNoKeyVersions
	}
	if v, ok := r.seal.(KeyVersioner); ok {
		return v.CurrentKeyVersion(ctx)
	}
	return "", errNoKeyVersions
}

// CurrentKeyVersion implements KeyVersioner for the limiter. The one call
// per sweep pass takes a background slot like the sweep's other calls.
func (l *limitedWrapper) CurrentKeyVersion(ctx context.Context) (string, error) {
	v, ok := l.inner.(KeyVersioner)
	if !ok {
		return "", errNoKeyVersions
	}
	release, err := l.acquire(ctx, callBackground)
	if err != nil {
		return "", err
	}
	defer release()
	return v.CurrentKeyVersion(ctx)
}

// RowState is a sealed row's place relative to the sealing provider.
type RowState int

const (
	// RowCurrent needs nothing.
	RowCurrent RowState = iota
	// RowStale is wrapped under an older version or label of the sealing
	// provider, or is a local row on a node that seals with a key store
	// (§12): the sweep rewraps it.
	RowStale
	// RowForeign is wrapped by a backend the node does not seal with (an
	// external to external switch, which v1 does not support). Left alone.
	RowForeign
)

// ClassifyRow places sealed relative to the sealing provider's current key
// version (current is "" for AWS KMS). local is the server key: an untagged
// row it opens is a local row.
func ClassifyRow(sealed []byte, local *Cipher, provider, current string) (RowState, error) {
	env, err := parseEnvelope(sealed)
	if err != nil {
		return RowCurrent, err
	}
	provider = NormalizeProviderName(provider)
	backend := WrappedKeyBackend(env.WrappedKey)
	if backend == "" {
		if provider != ProviderLocal && opensLocally(env, local) {
			return RowStale, nil
		}
		if provider == ProviderAWSKMS || provider == ProviderLocal {
			return RowCurrent, nil
		}
		return RowForeign, nil
	}
	if backend != provider {
		return RowForeign, nil
	}
	if current == "" || WrappedKeyVersion(env.WrappedKey) == current {
		return RowCurrent, nil
	}
	if backend == ProviderVault && vaultVersionNumber(WrappedKeyVersion(env.WrappedKey)) > vaultVersionNumber(current) {
		// Newer than what the key store just named (a rotation mid-pass):
		// not stale.
		return RowCurrent, nil
	}
	return RowStale, nil
}

func vaultVersionNumber(v string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(v, tagVault+"v"))
	return n
}

// opensLocally reports whether the server key opens env's data key: a local
// row. GCM authenticates the attempt, so a wrong guess fails cleanly.
func opensLocally(env sealedSecretsEnvelope, local *Cipher) bool {
	_, err := localDataKey(env, local)
	return err == nil
}

func localDataKey(env sealedSecretsEnvelope, local *Cipher) ([]byte, error) {
	if local == nil {
		return nil, errors.New("no server key")
	}
	recipients, binding, err := envelopeBinding(env)
	if err != nil {
		return nil, err
	}
	return local.DecryptWithAAD(env.WrappedKey, KeyAADBound(recipients, binding))
}

// RewrapEnvelope moves sealed's data key onto w's current key: the key is
// opened with the server key (a local row) or w, checked against the
// payload, and wrapped again. Everything else in the envelope is kept, so
// the result is the same secret by SameEnvelopeContent.
func RewrapEnvelope(ctx context.Context, sealed []byte, local *Cipher, w DataKeyWrapper) ([]byte, error) {
	env, err := parseEnvelope(sealed)
	if err != nil {
		return nil, err
	}
	recipients, binding, err := envelopeBinding(env)
	if err != nil {
		return nil, err
	}
	encCtx := EncryptionContextForBinding(binding)
	dek, lerr := localDataKey(env, local)
	if lerr != nil {
		if errors.Is(lerr, ErrKeyRevoked) {
			return nil, lerr
		}
		if dek, err = w.Unwrap(ctx, env.WrappedKey, encCtx); err != nil {
			return nil, fmt.Errorf("rewrap: open data key: %w", err)
		}
	}
	if _, err := OpenEnvelopePayloadBound(dek, env.Payload, recipients, binding); err != nil {
		return nil, fmt.Errorf("rewrap: data key does not open the payload: %w", err)
	}
	wrapped, err := w.Wrap(ctx, dek, encCtx)
	if err != nil {
		return nil, fmt.Errorf("rewrap: wrap data key: %w", err)
	}
	env.WrappedKey = wrapped
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("rewrap: marshal envelope: %w", err)
	}
	return out, nil
}

// SameEnvelopeContent reports whether a and b are the same sealed secret
// apart from WrappedKey (eng D3): after a rewrap two holders of one
// generation hold different bytes for the same content.
func SameEnvelopeContent(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	ea, err := parseEnvelope(a)
	if err != nil {
		return false
	}
	eb, err := parseEnvelope(b)
	if err != nil {
		return false
	}
	ea.WrappedKey, eb.WrappedKey = nil, nil
	ea.Recipients, eb.Recipients = NormalizeRecipients(ea.Recipients), NormalizeRecipients(eb.Recipients)
	ja, _ := json.Marshal(ea)
	jb, _ := json.Marshal(eb)
	return bytes.Equal(ja, jb)
}

func parseEnvelope(sealed []byte) (sealedSecretsEnvelope, error) {
	var env sealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		return env, fmt.Errorf("%w: unmarshal cluster secret envelope: %v", ErrDecryptFailed, err)
	}
	if env.Version != EnvelopeVersion || len(env.WrappedKey) == 0 || len(env.Payload) == 0 {
		return env, fmt.Errorf("%w: not a complete v%d cluster secret envelope", ErrDecryptFailed, EnvelopeVersion)
	}
	return env, nil
}

func envelopeBinding(env sealedSecretsEnvelope) ([]string, SealBinding, error) {
	recipients, err := requireRecipients(env.Recipients)
	if err != nil {
		return nil, SealBinding{}, err
	}
	binding, err := requireSealBinding(SealBinding{
		SandboxID: env.SandboxID, IncarnationID: env.IncarnationID, Ref: env.Ref,
		Version: env.RefVersion, Generation: env.Generation,
	})
	return recipients, binding, err
}
