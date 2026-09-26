package service

import (
	"context"
	"errors"
	"strings"

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
	parsed, err := secrets.ParseRef(rec.Ref)
	if err != nil || parsed.SandboxID != strings.TrimSpace(rec.SandboxID) || parsed.IncarnationID != strings.TrimSpace(rec.IncarnationID) ||
		parsed.Version != rec.Version || rec.SealGeneration <= 0 {
		return errors.New("cluster secret blob has an invalid current-format identity")
	}
	storeRec := store.ClusterSecretRecord{
		Ref:            rec.Ref,
		SandboxID:      rec.SandboxID,
		Version:        rec.Version,
		Recipients:     rec.Recipients,
		SealedPayload:  rec.SealedPayload,
		SealGeneration: rec.SealGeneration,
	}
	if rec.OutboxRecipients != nil {
		peers := append([]string(nil), *rec.OutboxRecipients...)
		storeRec.PutOutboxRecipients = &peers
		storeRec.PutOutboxIncarnationID = rec.IncarnationID
	}
	if rec.RetiredRecipients != nil {
		retired := append([]string(nil), (*rec.RetiredRecipients)...)
		storeRec.RetireRecipients = &retired
	}
	_, err = a.store.PutClusterSecret(ctx, storeRec)
	return err
}

func (a secretBlobStoreAdapter) Get(ctx context.Context, ref string) (*secrets.SecretBlob, error) {
	rec, err := a.store.GetClusterSecret(ctx, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, secrets.ErrNotFound
		}
		return nil, err
	}
	parsed, err := secrets.ParseRef(rec.Ref)
	if err != nil || parsed.SandboxID != rec.SandboxID || parsed.Version != rec.Version {
		return nil, errors.New("stored cluster secret has an invalid current-format ref")
	}
	return &secrets.SecretBlob{
		Ref:            rec.Ref,
		SandboxID:      rec.SandboxID,
		IncarnationID:  parsed.IncarnationID,
		Version:        rec.Version,
		Recipients:     rec.Recipients,
		SealedPayload:  rec.SealedPayload,
		SealGeneration: rec.SealGeneration,
	}, nil
}

func (a secretBlobStoreAdapter) DeleteForSandbox(ctx context.Context, sandboxID string) error {
	incarnationID := secrets.IncarnationIDFromContext(ctx)
	if incarnationID == "" {
		return errors.New("cluster secret delete incarnation id is required")
	}
	// Provider deletes are local row cleanup only. Originator peer-fanout
	// tombs+outbox go through DeleteClusterSecretsOriginatorWithOutbox so
	// standalone/local destroys do not leave permanent cluster_secret_tombs.
	return a.store.DeleteClusterSecretRowsForIncarnation(ctx, sandboxID, incarnationID)
}

func (a secretBlobStoreAdapter) NextSealGeneration(ctx context.Context, sandboxID string) (int64, error) {
	incarnationID := secrets.IncarnationIDFromContext(ctx)
	if incarnationID == "" {
		return 0, errors.New("cluster secret generation incarnation id is required")
	}
	return a.store.NextClusterSecretSealGenerationForIncarnation(ctx, sandboxID, incarnationID)
}
