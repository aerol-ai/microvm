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
	version := HandleVersionFor(s)
	ref := FormatRef(sandboxID, version)
	gen, err := p.store.NextSealGeneration(ctx, sandboxID)
	if err != nil {
		return Handle{}, err
	}
	binding := SealBinding{SandboxID: sandboxID, Ref: ref, Version: version, Generation: gen}
	sealed, err := SealEnvelopeBound(p.cipher, s, recipients, binding)
	if err != nil {
		return Handle{}, err
	}
	if len(sealed) == 0 {
		return Handle{}, nil
	}
	if err := p.store.Put(ctx, SecretBlob{
		Ref:            ref,
		SandboxID:      sandboxID,
		Version:        version,
		Recipients:     recipients,
		SealedPayload:  sealed,
		SealGeneration: gen,
	}); err != nil {
		return Handle{}, err
	}
	return Handle{Ref: ref, Version: version}, nil
}

// Open resolves h to plaintext for nodeID. sandboxID is verified against the
// v4 envelope binding so ciphertext cannot be relabeled across sandboxes.
func (p *LocalProvider) Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if h.Ref == "" {
		return Secrets{}, nil
	}
	if p == nil || p.store == nil {
		return Secrets{}, fmt.Errorf("cluster secret store is not configured")
	}
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
	if h.Version != 0 && rec.Version != h.Version {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q version mismatch: placement=%d store=%d", ErrVersionMismatch, h.Ref, h.Version, rec.Version)
	}
	if sandboxID != "" && rec.SandboxID != "" && sandboxID != rec.SandboxID {
		return Secrets{}, fmt.Errorf("%w: cluster secret sandbox_id mismatch", ErrDecryptFailed)
	}
	if sandboxID == "" {
		sandboxID = rec.SandboxID
	}
	if p.cipher == nil {
		return Secrets{}, fmt.Errorf("cluster secrets cipher is not configured")
	}
	binding := SealBinding{
		SandboxID:  sandboxID,
		Ref:        rec.Ref,
		Version:    rec.Version,
		Generation: rec.SealGeneration,
	}
	bag, err := OpenEnvelopeBound(p.cipher, rec.SealedPayload, nodeID, binding)
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
