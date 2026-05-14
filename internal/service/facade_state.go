package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Facade-state helpers. These thin wrappers around the generic store API
// exist so handlers in pkg/api/daytona and pkg/api/e2b never reach
// through to the store directly — Service stays the single seam between
// the API surface and the persistence layer.

func (s *Service) UpsertCompatState(ctx context.Context, sandboxID, facade, stateJSON string) error {
	return s.store.UpsertCompatState(ctx, sandboxID, facade, stateJSON)
}

func (s *Service) GetCompatState(ctx context.Context, sandboxID, facade string) (*models.SandboxCompatState, error) {
	return s.store.GetCompatState(ctx, sandboxID, facade)
}

func (s *Service) ListCompatState(ctx context.Context, facade string) (map[string]models.SandboxCompatState, error) {
	return s.store.ListCompatState(ctx, facade)
}

// ResolveSandboxIDByName looks up the sandbox owning the given unique
// name. Empty name returns ErrNotFound (handled inside the store).
func (s *Service) ResolveSandboxIDByName(ctx context.Context, name string) (string, error) {
	return s.store.ResolveSandboxIDByName(ctx, name)
}

// UpdateTags replaces sandboxes.tags_json for the given sandbox. Tags are
// the native key/value bag — facades use it for label-style metadata
// (Daytona labels, E2B metadata).
func (s *Service) UpdateTags(ctx context.Context, sandboxID string, tags map[string]string) error {
	return s.store.UpdateTags(ctx, sandboxID, tags)
}

func (s *Service) UpsertSnapshotAlias(ctx context.Context, alias models.SnapshotAlias) error {
	return s.store.UpsertSnapshotAlias(ctx, alias)
}

func (s *Service) GetSnapshotAlias(ctx context.Context, alias string) (*models.SnapshotAlias, error) {
	return s.store.GetSnapshotAlias(ctx, alias)
}

func (s *Service) ListSnapshotAliases(ctx context.Context, facade string) (map[string]models.SnapshotAlias, error) {
	return s.store.ListSnapshotAliases(ctx, facade)
}

func (s *Service) DeleteSnapshotAlias(ctx context.Context, alias string) error {
	return s.store.DeleteSnapshotAlias(ctx, alias)
}

func (s *Service) ClaimIdempotentRequest(ctx context.Context, scope, fingerprint string, now time.Time, pendingTTL time.Duration) (*models.IdempotentRequestRecord, bool, error) {
	return s.store.ClaimIdempotentRequest(ctx, scope, fingerprint, now, pendingTTL)
}

func (s *Service) GetIdempotentRequest(ctx context.Context, scope, fingerprint string) (*models.IdempotentRequestRecord, error) {
	return s.store.GetIdempotentRequest(ctx, scope, fingerprint)
}

func (s *Service) CompleteIdempotentRequest(ctx context.Context, scope, fingerprint, targetID string, now time.Time, replayTTL time.Duration) error {
	return s.store.CompleteIdempotentRequest(ctx, scope, fingerprint, targetID, now, replayTTL)
}

func (s *Service) DeleteIdempotentRequest(ctx context.Context, scope, fingerprint string) error {
	return s.store.DeleteIdempotentRequest(ctx, scope, fingerprint)
}
