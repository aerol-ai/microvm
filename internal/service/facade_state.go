package service

import (
	"context"
	"errors"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Facade-state helpers. These thin wrappers around the generic store API
// exist so handlers in pkg/api/daytona and pkg/api/e2b never reach
// through to the store directly — Service stays the single seam between
// the API surface and the persistence layer.

func (s *Service) UpsertCompatState(ctx context.Context, sandboxID, facade, stateJSON string) error {
	if err := s.store.UpsertCompatState(ctx, sandboxID, facade, stateJSON); err != nil {
		return err
	}
	// Carry facade state on the replicated spec so a failover recreate restores
	// it — the sandbox_compat_state rows are node-local and would otherwise go
	// with the dead owner (B11). Build a fresh map (never mutate the one the FSM
	// deep-copy shares) merging this facade's entry over any others.
	s.replicateSpecPatch(ctx, sandboxID, func(spec *models.CreateSandboxRequest) {
		merged := make(map[string]string, len(spec.CompatState)+1)
		for k, v := range spec.CompatState {
			merged[k] = v
		}
		merged[facade] = stateJSON
		spec.CompatState = merged
	})
	return nil
}

func (s *Service) GetCompatState(ctx context.Context, sandboxID, facade string) (*models.SandboxCompatState, error) {
	return s.store.GetCompatState(ctx, sandboxID, facade)
}

// ListCompatState returns the facade state for the caller's sandboxes. A user
// token only ever joins this against its own (owner-scoped) sandbox list, so a
// scoped caller reads just its own rows — not every tenant's — which both keeps
// the owner check in this shared helper (D13) and avoids a fleet-wide scan on
// each list at 100k sandboxes. Operator / internal callers (no owner scope) get
// the full map, as the fleet-list paths need.
func (s *Service) ListCompatState(ctx context.Context, facade string) (map[string]models.SandboxCompatState, error) {
	if owner, scoped := ownerScope(ctx); scoped {
		return s.store.ListCompatStateByOwner(ctx, facade, owner)
	}
	return s.store.ListCompatState(ctx, facade)
}

// ResolveSandboxIDByName looks up the caller's sandbox with the given name.
// Names are unique per owner, so the lookup runs in the namespace a create by
// this caller would use: a user token's account, or "" for operator/PAT and
// internal callers. Another owner's name reads as ErrNotFound, never as a
// conflict, so a user token cannot learn which names other tenants hold.
// Empty name returns ErrNotFound (handled inside the store).
func (s *Service) ResolveSandboxIDByName(ctx context.Context, name string) (string, error) {
	return s.store.ResolveSandboxIDByName(ctx, ownerRefForCreate(ctx), name)
}

// UpdateTags replaces sandboxes.tags_json for the given sandbox. Tags are
// the native key/value bag — facades use it for label-style metadata
// (Daytona labels, E2B metadata).
func (s *Service) UpdateTags(ctx context.Context, sandboxID string, tags map[string]string) error {
	// Owner-scope the tag write: a user token may only retag its own sandbox;
	// a cross-owner id reads as 404. Operator/internal callers pass through.
	if _, err := s.scopedGet(ctx, sandboxID); err != nil {
		return err
	}
	if err := s.store.UpdateTags(ctx, sandboxID, tags); err != nil {
		return err
	}
	// Write the tags through to the replicated spec so a failover recreate
	// restores the edited tags, not the create-time ones (B11). Tags are part
	// of CreateSandboxRequest, so the recreate already applies spec.Tags.
	replicated := make(map[string]string, len(tags))
	for k, v := range tags {
		replicated[k] = v
	}
	s.replicateSpecPatch(ctx, sandboxID, func(spec *models.CreateSandboxRequest) {
		spec.Tags = replicated
	})
	return nil
}

// Snapshot aliases are scoped through the snapshot they point at: an alias,
// and the facade state stored on it, is visible to whoever may see its
// snapshot, under the same owner rule as GetSnapshot.

// UpsertSnapshotAlias writes an alias onto a snapshot the caller may see. An
// existing row under the same alias must also point at a visible snapshot,
// or a user token could retarget (and so take over) another tenant's alias.
func (s *Service) UpsertSnapshotAlias(ctx context.Context, alias models.SnapshotAlias) error {
	if _, scoped := ownerScope(ctx); scoped {
		if err := s.requireVisibleSnapshot(ctx, alias.SnapshotName); err != nil {
			return err
		}
		existing, err := s.store.GetSnapshotAlias(ctx, alias.Alias)
		switch {
		case err == nil:
			if err := s.requireVisibleSnapshot(ctx, existing.SnapshotName); err != nil {
				return err
			}
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
	}
	return s.store.UpsertSnapshotAlias(ctx, alias)
}

// GetSnapshotAlias returns the alias row when its snapshot is visible to the
// caller, store.ErrNotFound otherwise.
func (s *Service) GetSnapshotAlias(ctx context.Context, alias string) (*models.SnapshotAlias, error) {
	got, err := s.store.GetSnapshotAlias(ctx, alias)
	if err != nil {
		return nil, err
	}
	if err := s.requireVisibleSnapshot(ctx, got.SnapshotName); err != nil {
		return nil, err
	}
	return got, nil
}

// ListSnapshotAliases returns the facade's alias rows whose snapshots the
// caller may see. A user token's list is filtered in the store, so other
// tenants' rows are never loaded.
func (s *Service) ListSnapshotAliases(ctx context.Context, facade string) (map[string]models.SnapshotAlias, error) {
	if owner, scoped := ownerScope(ctx); scoped {
		return s.store.ListSnapshotAliasesForOwner(ctx, facade, owner)
	}
	return s.store.ListSnapshotAliases(ctx, facade)
}

// DeleteSnapshotAlias removes an alias whose snapshot the caller may see.
func (s *Service) DeleteSnapshotAlias(ctx context.Context, alias string) error {
	if _, scoped := ownerScope(ctx); scoped {
		got, err := s.store.GetSnapshotAlias(ctx, alias)
		if err != nil {
			return err
		}
		if err := s.requireVisibleSnapshot(ctx, got.SnapshotName); err != nil {
			return err
		}
	}
	return s.store.DeleteSnapshotAlias(ctx, alias)
}

// requireVisibleSnapshot returns store.ErrNotFound unless the named snapshot
// exists and the caller may see it. Unscoped callers skip the read.
func (s *Service) requireVisibleSnapshot(ctx context.Context, name string) error {
	if _, scoped := ownerScope(ctx); !scoped {
		return nil
	}
	snapshot, err := s.store.GetSnapshot(ctx, name)
	if err != nil {
		return err
	}
	if !snapshotVisible(ctx, snapshot) {
		return store.ErrNotFound
	}
	return nil
}

func (s *Service) ClaimIdempotentRequest(ctx context.Context, scope, fingerprint string, now time.Time, pendingTTL time.Duration) (*models.IdempotentRequestRecord, bool, error) {
	s.maybeSweepIdempotentRequests()
	record, acquired, err := s.store.ClaimIdempotentRequest(ctx, scope, fingerprint, now, pendingTTL)
	metricScope := idempotencyScope(scope)
	if err == nil {
		scaleKey := metricScope + "." + idempotencyState(record)
		facadeIdempotencyClaims.Add(scaleKey, 1)
		if acquired {
			facadeIdempotencyAcquired.Add(metricScope, 1)
		} else if record != nil && record.State == models.RequestStateReady {
			// The facade increments replay once it has loaded and returned
			// the target. A ready claim by itself may still expire or point at
			// a deleted sandbox, so counting it here would over-report.
		} else {
			facadeIdempotencyConflicts.Add(metricScope, 1)
		}
	}
	return record, acquired, err
}

func (s *Service) GetIdempotentRequest(ctx context.Context, scope, fingerprint string) (*models.IdempotentRequestRecord, error) {
	return s.store.GetIdempotentRequest(ctx, scope, fingerprint)
}

func (s *Service) CompleteIdempotentRequest(ctx context.Context, scope, fingerprint, targetID string, now time.Time, replayTTL time.Duration) error {
	err := s.store.CompleteIdempotentRequest(ctx, scope, fingerprint, targetID, now, replayTTL)
	if err == nil {
		facadeIdempotencyComplete.Add(idempotencyScope(scope), 1)
	}
	return err
}

func (s *Service) DeleteIdempotentRequest(ctx context.Context, scope, fingerprint string) error {
	err := s.store.DeleteIdempotentRequest(ctx, scope, fingerprint)
	if err == nil {
		facadeIdempotencyDeletes.Add(idempotencyScope(scope), 1)
	}
	return err
}
