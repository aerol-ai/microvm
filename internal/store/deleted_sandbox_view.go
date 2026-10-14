package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeletedSandboxView is one durable tombstone row: the terminal body a facade
// should replay for a sandbox that no longer exists, plus the owner that may
// see it and the time it was recorded (for the replay-window sweep).
type DeletedSandboxView struct {
	SandboxID string
	Facade    string
	OwnerRef  string
	ViewJSON  string
	CreatedAt time.Time
}

// PutDeletedSandboxView records (or replaces) the terminal view for a deleted
// sandbox. There is no sandbox row to key against — the point is to answer
// after the row is gone — so this is a plain upsert on (sandbox_id, facade).
func (s *Store) PutDeletedSandboxView(ctx context.Context, sandboxID, facade, ownerRef, viewJSON string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO deleted_sandbox_view (sandbox_id, facade, owner_ref, view_json, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(sandbox_id, facade) DO UPDATE SET
			owner_ref = excluded.owner_ref,
			view_json = excluded.view_json,
			created_at = excluded.created_at
	`, strings.TrimSpace(sandboxID), strings.TrimSpace(facade), strings.TrimSpace(ownerRef), viewJSON, now.UTC())
	if err != nil {
		return fmt.Errorf("put deleted sandbox view: %w", err)
	}
	return nil
}

// GetDeletedSandboxView returns the tombstone for (sandboxID, facade), or
// ErrNotFound. Owner scoping and the replay-window check are the service's
// job — the store returns the row as stored.
func (s *Store) GetDeletedSandboxView(ctx context.Context, sandboxID, facade string) (*DeletedSandboxView, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, facade, owner_ref, view_json, created_at
		FROM deleted_sandbox_view
		WHERE sandbox_id = ? AND facade = ?
	`, strings.TrimSpace(sandboxID), strings.TrimSpace(facade))
	var v DeletedSandboxView
	if err := row.Scan(&v.SandboxID, &v.Facade, &v.OwnerRef, &v.ViewJSON, &v.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get deleted sandbox view: %w", err)
	}
	return &v, nil
}

// DeleteExpiredDeletedSandboxViews removes up to limit tombstones older than
// cutoff. Batched so one sweep never holds the single writer for long; the
// created_at index makes the selection a range scan.
func (s *Store) DeleteExpiredDeletedSandboxViews(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	if limit <= 0 {
		return 0, nil
	}
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM deleted_sandbox_view
		WHERE rowid IN (
			SELECT rowid FROM deleted_sandbox_view
			WHERE created_at <= ?
			LIMIT ?
		)
	`, cutoff.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired deleted sandbox views: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired deleted sandbox views: %w", err)
	}
	return deleted, nil
}
