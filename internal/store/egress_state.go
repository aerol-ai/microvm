package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// EgressState is a sandbox's egress-gateway state (sandbox_egress).
type EgressState struct {
	SandboxID  string
	HoldReason string
	HoldSince  time.Time
}

// SetEgressHold records the fail-closed hold and its reason (CEO D16). It is
// idempotent and keeps the original hold_since on a repeated hold.
func (s *Store) SetEgressHold(ctx context.Context, sandboxID, reason string, now time.Time) error {
	if reason == "" {
		return errors.New("egress hold needs a reason")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_egress (sandbox_id, hold_reason, hold_since, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			hold_reason = excluded.hold_reason,
			hold_since = COALESCE(sandbox_egress.hold_since, excluded.hold_since),
			updated_at = excluded.updated_at
	`, sandboxID, reason, now.UTC(), now.UTC())
	if err != nil {
		return fmt.Errorf("set egress hold: %w", err)
	}
	return nil
}

// ClearEgressHold lifts the hold. Only a successful gateway attach calls it.
func (s *Store) ClearEgressHold(ctx context.Context, sandboxID string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_egress SET hold_reason = '', hold_since = NULL, updated_at = ?
		WHERE sandbox_id = ?
	`, now.UTC(), sandboxID)
	if err != nil {
		return fmt.Errorf("clear egress hold: %w", err)
	}
	return nil
}

// GetEgressState returns a sandbox's egress state; a sandbox with no row has
// the zero state (no hold).
func (s *Store) GetEgressState(ctx context.Context, sandboxID string) (EgressState, error) {
	st := EgressState{SandboxID: sandboxID}
	var since sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT hold_reason, hold_since FROM sandbox_egress WHERE sandbox_id = ?
	`, sandboxID).Scan(&st.HoldReason, &since)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("get egress state: %w", err)
	}
	if since.Valid {
		st.HoldSince = since.Time
	}
	return st, nil
}

// ListEgressHolds returns every held sandbox and its reason (reconcile
// retries, the held-sandboxes gauge). The partial index keeps it to held rows.
func (s *Store) ListEgressHolds(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sandbox_id, hold_reason FROM sandbox_egress WHERE hold_reason != ''`)
	if err != nil {
		return nil, fmt.Errorf("list egress holds: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, reason string
		if err := rows.Scan(&id, &reason); err != nil {
			return nil, fmt.Errorf("scan egress hold: %w", err)
		}
		out[id] = reason
	}
	return out, rows.Err()
}
