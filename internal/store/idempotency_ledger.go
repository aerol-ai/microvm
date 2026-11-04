package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// maxIdempotentListRows caps one ListIdempotentRequests read.
const maxIdempotentListRows = 10000

// ListIdempotentRequests returns up to limit rows of one scope in one state
// whose fingerprint sorts after afterFingerprint, in fingerprint order. It
// lets a claimer that keeps work outstanding under its pending rows (the
// Runloop execution ledger) find all of that work again after a restart: the
// caller passes the last fingerprint of each page to get the next, so no
// backlog is too large to walk. idx_request_idempotency_state makes each page
// a range seek that never touches the scope's rows in other states.
func (s *Store) ListIdempotentRequests(ctx context.Context, scope, state, afterFingerprint string, limit int) ([]*models.IdempotentRequestRecord, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil, fmt.Errorf("list idempotent requests: scope is required")
	}
	if limit <= 0 || limit > maxIdempotentListRows {
		limit = maxIdempotentListRows
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT scope, fingerprint, target_id, state, locked_until, replay_until, created_at, updated_at
		FROM request_idempotency
		WHERE scope = ? AND state = ? AND fingerprint > ?
		ORDER BY fingerprint ASC
		LIMIT ?
	`, scope, strings.TrimSpace(state), afterFingerprint, limit)
	if err != nil {
		return nil, fmt.Errorf("list idempotent requests: %w", err)
	}
	defer rows.Close()
	var items []*models.IdempotentRequestRecord
	for rows.Next() {
		record, err := scanIdempotentRequestRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan idempotent request: %w", err)
		}
		items = append(items, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate idempotent requests: %w", err)
	}
	return items, nil
}

// DeleteExpiredIdempotentRequests removes up to limit rows that
// ClaimIdempotentRequest would already treat as free: ready rows past
// replay_until and pending rows past locked_until. Deleting them changes no
// claim outcome — a later claim of the same key acquires either way — it
// only stops the table from growing with every request ever deduped.
// Batched so one sweep never holds the single writer for long.
func (s *Store) DeleteExpiredIdempotentRequests(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit <= 0 {
		return 0, nil
	}
	now = now.UTC()
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM request_idempotency
		WHERE rowid IN (
			SELECT rowid FROM request_idempotency
			WHERE (state = ? AND replay_until IS NOT NULL AND replay_until <= ?)
				OR (state = ? AND locked_until <= ?)
			LIMIT ?
		)
	`, models.RequestStateReady, now, models.RequestStatePending, now, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired idempotent requests: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired idempotent requests: %w", err)
	}
	return deleted, nil
}

// SetIdempotentRequestTarget records target on a row that is still pending,
// leaving it pending. A claimer whose work has produced its result but
// still owes follow-up (the Runloop ledger: a finished command whose session
// is not deleted yet) stores the result here first, so neither a crash nor
// a lost cache can lose it, and moves the row to ready with
// CompleteIdempotentRequest once nothing is owed. A row that is no longer
// pending is left alone and reported as ErrNotFound.
func (s *Store) SetIdempotentRequestTarget(ctx context.Context, scope, fingerprint, targetID string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE request_idempotency
		SET target_id = ?, updated_at = ?
		WHERE scope = ? AND fingerprint = ? AND state = ?
	`, strings.TrimSpace(targetID), now.UTC(), strings.TrimSpace(scope), strings.TrimSpace(fingerprint), models.RequestStatePending)
	if err != nil {
		return fmt.Errorf("set idempotent request target: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}
