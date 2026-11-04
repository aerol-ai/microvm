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
	// keyStore opens rows on a node that seals with the server key but
	// holds a key store's settings: step 1 of the two-step switch (§12,
	// eng D8), when switched peers already seal their failover copies with
	// the key store. Nil on a node with no key-store settings.
	keyStore *KMSProvider
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
	version := RefVersion
	incarnationID := IncarnationIDFromContext(ctx)
	if incarnationID == "" {
		return Handle{}, fmt.Errorf("cluster secret incarnation id is required")
	}
	ref := FormatRef(sandboxID, incarnationID, version)
	gen, err := p.store.NextSealGeneration(ctx, sandboxID)
	if err != nil {
		return Handle{}, err
	}
	binding := SealBinding{SandboxID: sandboxID, IncarnationID: incarnationID, Ref: ref, Version: version, Generation: gen}
	sealed, err := SealEnvelopeBound(p.cipher, s, recipients, binding)
	if err != nil {
		return Handle{}, err
	}
	if len(sealed) == 0 {
		return Handle{}, nil
	}
	blob := SecretBlob{
		Ref:            ref,
		SandboxID:      sandboxID,
		IncarnationID:  incarnationID,
		Version:        version,
		Recipients:     recipients,
		SealedPayload:  sealed,
		SealGeneration: gen,
	}
	if _, peers, ok := PutOutboxFromContext(ctx); ok {
		cp := append([]string(nil), peers...)
		blob.OutboxRecipients = &cp
	}
	if retired, ok := RetiredRecipientsFromContext(ctx); ok {
		cp := append([]string(nil), retired...)
		blob.RetiredRecipients = &cp
	}
	if err := p.store.Put(ctx, blob); err != nil {
		return Handle{}, err
	}
	return Handle{Ref: ref, Version: version, SealGeneration: gen}, nil
}

// Open resolves h to plaintext for nodeID. sandboxID is verified against the
// v4 envelope binding so ciphertext cannot be relabeled across sandboxes.
func (p *LocalProvider) Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error) {
	if p != nil && p.keyStore != nil {
		return p.keyStore.Open(ctx, sandboxID, h, nodeID)
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if h.Ref == "" {
		return Secrets{}, nil
	}
	if p == nil || p.store == nil {
		return Secrets{}, fmt.Errorf("cluster secret store is not configured")
	}
	if sandboxID == "" {
		return Secrets{}, fmt.Errorf("%w: cluster secret sandbox id is required", ErrDecryptFailed)
	}
	parsed, handleErr := validateCurrentHandle(sandboxID, h)
	if handleErr != nil {
		return Secrets{}, handleErr
	}
	rec, err := p.store.Get(ctx, h.Ref)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Secrets{}, fmt.Errorf("%w: cluster secret ref %q not found", ErrNotFound, h.Ref)
		}
		return Secrets{}, err
	}
	if rec.Ref != h.Ref || rec.Version != h.Version {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q version mismatch: placement=%d store=%d", ErrVersionMismatch, h.Ref, h.Version, rec.Version)
	}
	if rec.SandboxID == "" || sandboxID != rec.SandboxID {
		return Secrets{}, fmt.Errorf("%w: cluster secret sandbox_id mismatch", ErrDecryptFailed)
	}
	if rec.SealGeneration <= 0 {
		return Secrets{}, fmt.Errorf("%w: cluster secret seal generation is required", ErrDecryptFailed)
	}
	if h.SealGeneration != rec.SealGeneration {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q generation mismatch: placement=%d store=%d", ErrVersionMismatch, h.Ref, h.SealGeneration, rec.SealGeneration)
	}
	if p.cipher == nil {
		return Secrets{}, fmt.Errorf("cluster secrets cipher is not configured")
	}
	incarnationID := strings.TrimSpace(rec.IncarnationID)
	if incarnationID == "" || parsed.IncarnationID != incarnationID || parsed.Version != rec.Version {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref/incarnation binding is invalid", ErrDecryptFailed)
	}
	binding := SealBinding{
		SandboxID:     sandboxID,
		IncarnationID: incarnationID,
		Ref:           rec.Ref,
		Version:       rec.Version,
		Generation:    rec.SealGeneration,
	}
	if env, perr := parseEnvelope(rec.SealedPayload); perr == nil {
		if backend := WrappedKeyBackend(env.WrappedKey); backend != "" {
			// A peer that already switched sealed it, and this node has
			// none of that key store's settings yet (step 1 of §12 skipped).
			return Secrets{}, fmt.Errorf("%w: row wrapped by %s; node configured for %s and has no %s settings", ErrProviderUnavailable, backend, ProviderLocal, backend)
		}
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
