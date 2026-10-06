package store

import (
	"context"
	"fmt"
	"time"
)

// SetNetworkPolicy replaces a sandbox's egress policy columns
// (PUT /v1/sandboxes/{id}/network/policy, plans/egress-domain-filtering.md
// §5.8). A full replace, so the same values twice is a no-op.
func (s *Store) SetNetworkPolicy(ctx context.Context, id string, blockAll bool, allowOut, denyOut []string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET network_block_all = ?,
		    network_allow_out_json = ?,
		    network_deny_out_json = ?,
		    updated_at = ?
		WHERE id = ?
	`, blockAll, mustMarshalStringSlice(allowOut), mustMarshalStringSlice(denyOut), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set sandbox network policy: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}
