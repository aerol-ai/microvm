package service

import (
	"context"
	"errors"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// deletedViewRetention is how long a deleted sandbox's terminal view stays
// replayable. It matches the window the Runloop facade kept its in-memory
// shutdown tombstones: long enough that a retried shutdown (or a GET that
// races the delete) still sees the terminal body, short enough that the table
// tracks only recent deletions. The sweep (sweepIdempotentRequests) removes
// rows past it.
const deletedViewRetention = 10 * time.Minute

// RecordDeletedSandboxView durably stores the terminal body a facade should
// replay for a sandbox it just deleted, so a retried delete or a GET of the
// gone sandbox answers with it instead of 404 — the durable, cross-restart
// replacement for a per-process tombstone map (D6). ownerRef is the deleted
// sandbox's owner; GetDeletedSandboxView scopes reads to it.
func (s *Service) RecordDeletedSandboxView(ctx context.Context, sandboxID, facade, ownerRef, viewJSON string) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.PutDeletedSandboxView(ctx, sandboxID, facade, ownerRef, viewJSON, time.Now())
}

// GetDeletedSandboxView returns the stored terminal view for a deleted
// sandbox, or ("", false, nil) when there is none, the caller may not see it,
// or it is past the replay window. The owner check lives here, in the shared
// helper, under the same rule scopedGet applies to live rows (D13): a user
// token sees only its own account's tombstones; operator / internal callers
// see any.
func (s *Service) GetDeletedSandboxView(ctx context.Context, sandboxID, facade string) (string, bool, error) {
	if s == nil || s.store == nil {
		return "", false, nil
	}
	row, err := s.store.GetDeletedSandboxView(ctx, sandboxID, facade)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	if owner, scoped := ownerScope(ctx); scoped && owner != row.OwnerRef {
		return "", false, nil
	}
	if time.Since(row.CreatedAt) > deletedViewRetention {
		return "", false, nil
	}
	return row.ViewJSON, true, nil
}
