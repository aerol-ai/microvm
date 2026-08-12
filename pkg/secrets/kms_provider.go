package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// KMSProvider seals secrets with a per-row DEK whose wrap material lives in
// KMS (or FakeKMS). Ciphertext still lands in BlobStore — KMS never stores
// the payload. Open skips recipient binding: any node that holds the row and
// can Unwrap via IAM may decrypt (removes WALL 2). Fan-out is still required
// for WALL 1 (bytes must reach the failover node).
//
// v4 envelopes bind sandbox identity into payload AAD and KMS EncryptionContext
// so ciphertext cannot be relabeled across sandboxes.
type KMSProvider struct {
	wrapper DataKeyWrapper
	store   BlobStore
}

// NewKMSProvider returns a Provider backed by wrapper + store.
func NewKMSProvider(wrapper DataKeyWrapper, store BlobStore) *KMSProvider {
	return &KMSProvider{wrapper: wrapper, store: store}
}

// Put seals s for recipients (recorded for fan-out targeting) and stores the
// envelope. Empty secrets return a zero Handle without writing a row.
func (p *KMSProvider) Put(ctx context.Context, sandboxID string, s Secrets, recipients []string) (Handle, error) {
	if s.IsEmpty() {
		return Handle{}, nil
	}
	if p == nil || p.wrapper == nil {
		return Handle{}, fmt.Errorf("%w: secret provider wrap backend is not configured", ErrProviderUnavailable)
	}
	if p.store == nil {
		return Handle{}, fmt.Errorf("cluster secret store is not configured")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return Handle{}, fmt.Errorf("cluster secret sandbox id is required")
	}
	recipients = NormalizeRecipients(recipients)
	plain, err := json.Marshal(s)
	if err != nil {
		return Handle{}, fmt.Errorf("marshal cluster secrets: %w", err)
	}
	version := RefVersion
	incarnationID := IncarnationIDFromContext(ctx)
	ref := FormatRefInc(sandboxID, incarnationID, version)
	gen, err := p.store.NextSealGeneration(ctx, sandboxID)
	if err != nil {
		return Handle{}, err
	}
	binding := SealBinding{SandboxID: sandboxID, IncarnationID: incarnationID, Ref: ref, Version: version, Generation: gen}
	encCtx := EncryptionContextForBinding(binding)
	sealed, err := SealRawEnvelopeWrappedBound(plain, recipients, binding, func(dek []byte) ([]byte, error) {
		return p.wrapper.Wrap(ctx, dek, encCtx)
	})
	if err != nil {
		return Handle{}, mapProviderWrapError(err)
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
	if err := p.store.Put(ctx, blob); err != nil {
		return Handle{}, err
	}
	return Handle{Ref: ref, Version: version, SealGeneration: gen}, nil
}

// Open resolves h to plaintext. sandboxID is verified against the v4 binding;
// nodeID is accepted for the Provider contract (audit) but is not checked
// against the envelope recipient set — KMS IAM is the authorization boundary.
func (p *KMSProvider) Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error) {
	_ = nodeID
	sandboxID = strings.TrimSpace(sandboxID)
	if h.Ref == "" {
		return Secrets{}, nil
	}
	if p == nil || p.store == nil {
		return Secrets{}, fmt.Errorf("cluster secret store is not configured")
	}
	if h.Version != RefVersion {
		return Secrets{}, fmt.Errorf("%w: cluster secret ref %q version %d unsupported (want %d)", ErrVersionMismatch, h.Ref, h.Version, RefVersion)
	}
	if sandboxID == "" {
		return Secrets{}, fmt.Errorf("%w: cluster secret sandbox id is required", ErrDecryptFailed)
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
	if p.wrapper == nil {
		return Secrets{}, fmt.Errorf("%w: secret provider wrap backend is not configured", ErrProviderUnavailable)
	}
	incarnationID := rec.IncarnationID
	if incarnationID == "" {
		if parsed, parseErr := ParseRef(rec.Ref); parseErr == nil {
			incarnationID = parsed.IncarnationID
		}
	}
	binding := SealBinding{
		SandboxID:     sandboxID,
		IncarnationID: incarnationID,
		Ref:           rec.Ref,
		Version:       rec.Version,
		Generation:    rec.SealGeneration,
	}
	encCtx := EncryptionContextForBinding(binding)
	plain, err := OpenRawEnvelopeExternalBound(rec.SealedPayload, binding, func(wrapped []byte) ([]byte, error) {
		return p.wrapper.Unwrap(ctx, wrapped, encCtx)
	})
	if err != nil {
		return Secrets{}, mapProviderWrapError(fmt.Errorf("decrypt cluster secrets: %w", err))
	}
	var bag Secrets
	if err := json.Unmarshal(plain, &bag); err != nil {
		return Secrets{}, fmt.Errorf("unmarshal cluster secrets: %w", err)
	}
	return bag, nil
}

// Delete removes all sealed rows for sandboxID.
func (p *KMSProvider) Delete(ctx context.Context, sandboxID string) error {
	if p == nil || p.store == nil {
		return nil
	}
	return p.store.DeleteForSandbox(ctx, sandboxID)
}

func mapProviderWrapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrProviderUnavailable),
		errors.Is(err, ErrProviderThrottled),
		errors.Is(err, ErrProviderDenied),
		errors.Is(err, ErrDecryptFailed),
		errors.Is(err, ErrRecipientDenied),
		errors.Is(err, ErrNotFound),
		errors.Is(err, ErrVersionMismatch):
		return err
	default:
		return err
	}
}
