package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// secretBlobStoreAdapter maps store.ClusterSecretRecord ↔ secrets.SecretBlob
// so pkg/secrets never imports internal/store.
type secretBlobStoreAdapter struct {
	store *store.Store
}

func newSecretBlobStore(st *store.Store) secrets.BlobStore {
	if st == nil {
		return nil
	}
	return secretBlobStoreAdapter{store: st}
}

func (a secretBlobStoreAdapter) Put(ctx context.Context, rec secrets.SecretBlob) error {
	return a.store.PutClusterSecret(ctx, store.ClusterSecretRecord{
		Ref:           rec.Ref,
		SandboxID:     rec.SandboxID,
		Version:       rec.Version,
		Recipients:    rec.Recipients,
		SealedPayload: rec.SealedPayload,
	})
}

func (a secretBlobStoreAdapter) Get(ctx context.Context, ref string) (*secrets.SecretBlob, error) {
	rec, err := a.store.GetClusterSecret(ctx, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, secrets.ErrNotFound
		}
		return nil, err
	}
	return &secrets.SecretBlob{
		Ref:           rec.Ref,
		SandboxID:     rec.SandboxID,
		Version:       rec.Version,
		Recipients:    rec.Recipients,
		SealedPayload: rec.SealedPayload,
	}, nil
}

func (a secretBlobStoreAdapter) DeleteForSandbox(ctx context.Context, sandboxID string) error {
	return a.store.DeleteClusterSecretsForSandbox(ctx, sandboxID)
}
