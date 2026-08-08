package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// LocalProvider seals secrets with a node-local Cipher and persists the
// recipient-bound envelope via BlobStore. This preserves today's
// cluster_secrets SQLite behavior behind the Provider interface.
type LocalProvider struct {
	cipher *Cipher
	store  BlobStore
}

// NewLocalProvider returns a Provider backed by cipher + store.
func NewLocalProvider(cipher *Cipher, store BlobStore) *LocalProvider {
	return &LocalProvider{cipher: cipher, store: store}
}

// Put seals s for recipients and stores the envelope. Empty secrets return a
// zero Handle without writing a row (matches today's PutClusterSecrets).
func (p *LocalProvider) Put(ctx context.Context, sandboxID string, s Secrets, recipients []string) (Handle, error) {
	if s.IsEmpty() {
		return Handle{}, nil
	}
	if p == nil || p.cipher == nil {
		return Handle{}, fmt.Errorf("cluster secrets cipher is not configured")
	}
	if p.store == nil {
		return Handle{}, fmt.Errorf("cluster secret store is not configured")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return Handle{}, fmt.Errorf("cluster secret sandbox id is required")
	}
	recipients = NormalizeRecipients(recipients)
	sealed, err := SealEnvelope(p.cipher, s, recipients)
	if err != nil {
		return Handle{}, err
	}
	if len(sealed) == 0 {
		return Handle{}, nil
	}
	version := HandleVersionFor(s)
	ref := FormatRef(sandboxID, version)
	if err := p.store.Put(ctx, SecretBlob{
		Ref:           ref,
		SandboxID:     sandboxID,
		Version:       version,
		Recipients:    recipients,
		SealedPayload: sealed,
	}); err != nil {
		return Handle{}, err
	}
	return Handle{Ref: ref, Version: version}, nil
}

// Open resolves h to plaintext for nodeID. sandboxID is accepted for the
// Provider contract (audit in T6); lookup is by ref.
//
// Lookup runs before the cipher nil-check so a missing ref still surfaces as
// ErrNotFound when the store is present but the cipher is not yet wired
// (matches prior OpenClusterSecretsForNode behavior).
func (p *LocalProvider) Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error) {
	_ = sandboxID
	if h.Ref == "" {
		return Secrets{}, nil
	}
	if p == nil || p.store == nil {
		return Secrets{}, fmt.Errorf("cluster secret store is not configured")
	}
	// Loud reject for future handle versions this binary cannot re-merge
	// (env-sealed bags are v2; v3+ must fail closed, never silent env loss).
	if h.Version > MaxSupportedRefVersion {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q version %d unsupported (max %d)", ErrVersionMismatch, h.Ref, h.Version, MaxSupportedRefVersion)
	}
	rec, err := p.store.Get(ctx, h.Ref)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Secrets{}, fmt.Errorf("%w: cluster secret ref %q not found", ErrNotFound, h.Ref)
		}
		return Secrets{}, err
	}
	if rec.Version > MaxSupportedRefVersion {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q store version %d unsupported (max %d)", ErrVersionMismatch, h.Ref, rec.Version, MaxSupportedRefVersion)
	}
	if h.Version != 0 && rec.Version != h.Version {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q version mismatch: placement=%d store=%d", ErrVersionMismatch, h.Ref, h.Version, rec.Version)
	}
	if p.cipher == nil {
		return Secrets{}, fmt.Errorf("cluster secrets cipher is not configured")
	}
	bag, err := OpenEnvelope(p.cipher, rec.SealedPayload, nodeID)
	if err != nil {
		return Secrets{}, fmt.Errorf("decrypt cluster secrets: %w", err)
	}
	return bag, nil
}

// Delete removes all sealed rows for sandboxID.
func (p *LocalProvider) Delete(ctx context.Context, sandboxID string) error {
	if p == nil || p.store == nil {
		return nil
	}
	return p.store.DeleteForSandbox(ctx, sandboxID)
}
