package store

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
)

// SandboxIDsClaimingContainerIP returns every sandbox that may be using ip
// right now: a creating or started sandbox row carrying it, or a claimed
// container netns slot holding it. The slot side matters because a pooled
// netns is claimed (and its rules installed) before the new sandbox's row is
// persisted. Event-driven rule clears skip when any claimant other than the
// event's own sandbox exists (egress plan P0-6).
func (s *Store) SandboxIDsClaimingContainerIP(ctx context.Context, ip string) ([]string, error) {
	if ip == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM sandboxes
		WHERE container_ip = ? AND status IN (?, ?)
		UNION
		SELECT sandbox_id FROM container_netns_slots
		WHERE container_ip = ? AND sandbox_id IS NOT NULL AND sandbox_id != ''
	`, ip, string(models.SandboxStatusCreating), string(models.SandboxStatusStarted), ip)
	if err != nil {
		return nil, fmt.Errorf("list container ip claimants: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan container ip claimant: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate container ip claimants: %w", err)
	}
	return ids, nil
}
