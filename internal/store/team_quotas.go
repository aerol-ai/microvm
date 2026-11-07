package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Per-team quotas on one node (plan item P2). This table is the single-node
// store; a cluster keeps quotas in the Raft FSM, like egress profiles. Usage
// is not stored: the service counts it from the sandboxes table and keeps the
// running total in memory, so a create writes nothing here.

// teamQuotasDDL is idempotent like every other table in Open.
const teamQuotasDDL = `CREATE TABLE IF NOT EXISTS team_quotas (
	team TEXT PRIMARY KEY,
	max_sandboxes INTEGER NOT NULL DEFAULT 0,
	max_cpu REAL NOT NULL DEFAULT 0,
	max_memory_mb INTEGER NOT NULL DEFAULT 0,
	generation INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);`

// PutTeamQuota creates or replaces a team's quota. Generation goes up only
// when a limit changes, so the same body twice is a no-op; changed says
// whether it did.
func (s *Store) PutTeamQuota(ctx context.Context, team string, limits models.TeamQuotaRequest, now time.Time) (q models.TeamQuota, changed bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return q, false, fmt.Errorf("put team quota: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	old, err := getTeamQuota(ctx, tx, team)
	switch {
	case errors.Is(err, models.ErrTeamQuotaNotFound):
		q = models.TeamQuota{Team: team, Generation: 1, CreatedAt: now.UTC()}
	case err != nil:
		return q, false, err
	case old.Limits() == limits:
		return old, false, nil
	default:
		q = old
		q.Generation++
	}
	q.MaxSandboxes, q.MaxCPU, q.MaxMemoryMB, q.UpdatedAt = limits.MaxSandboxes, limits.MaxCPU, limits.MaxMemoryMB, now.UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO team_quotas (team, max_sandboxes, max_cpu, max_memory_mb, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(team) DO UPDATE SET
			max_sandboxes = excluded.max_sandboxes,
			max_cpu = excluded.max_cpu,
			max_memory_mb = excluded.max_memory_mb,
			generation = excluded.generation,
			updated_at = excluded.updated_at
	`, team, q.MaxSandboxes, q.MaxCPU, q.MaxMemoryMB, q.Generation, q.CreatedAt, q.UpdatedAt); err != nil {
		return models.TeamQuota{}, false, fmt.Errorf("put team quota: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.TeamQuota{}, false, fmt.Errorf("put team quota: %w", err)
	}
	return q, true, nil
}

// GetTeamQuota returns a team's quota, or models.ErrTeamQuotaNotFound.
func (s *Store) GetTeamQuota(ctx context.Context, team string) (models.TeamQuota, error) {
	return getTeamQuota(ctx, s.db, team)
}

func getTeamQuota(ctx context.Context, q queryRower, team string) (models.TeamQuota, error) {
	out := models.TeamQuota{Team: team}
	err := q.QueryRowContext(ctx, `
		SELECT max_sandboxes, max_cpu, max_memory_mb, generation, created_at, updated_at
		FROM team_quotas WHERE team = ?
	`, team).Scan(&out.MaxSandboxes, &out.MaxCPU, &out.MaxMemoryMB, &out.Generation, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, models.ErrTeamQuotaNotFound
	}
	if err != nil {
		return out, fmt.Errorf("get team quota: %w", err)
	}
	return out, nil
}

// ListTeamQuotas returns every team's quota, by team. The table holds one
// row per team an admin limited, so it is small.
func (s *Store) ListTeamQuotas(ctx context.Context) ([]models.TeamQuota, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT team, max_sandboxes, max_cpu, max_memory_mb, generation, created_at, updated_at
		FROM team_quotas ORDER BY team
	`)
	if err != nil {
		return nil, fmt.Errorf("list team quotas: %w", err)
	}
	defer rows.Close()
	out := []models.TeamQuota{}
	for rows.Next() {
		var q models.TeamQuota
		if err := rows.Scan(&q.Team, &q.MaxSandboxes, &q.MaxCPU, &q.MaxMemoryMB, &q.Generation, &q.CreatedAt, &q.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan team quota: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// DeleteTeamQuota removes a team's quota. Deleting one that is already gone
// succeeds, so a retried DELETE converges.
func (s *Store) DeleteTeamQuota(ctx context.Context, team string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM team_quotas WHERE team = ?`, team); err != nil {
		return fmt.Errorf("delete team quota: %w", err)
	}
	return nil
}

// QuotaSandbox is one sandbox as a team quota counts it.
type QuotaSandbox struct {
	ID       string
	CPU      float64
	MemoryMB int
}

// TeamQuotaSandboxes lists an owner's sandboxes that are not destroyed, with
// the size each asked for. It is the single-node ledger's source of truth,
// read only when the ledger (re)loads an owner, never per create.
func (s *Store) TeamQuotaSandboxes(ctx context.Context, ownerRef string) ([]QuotaSandbox, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cpu, memory_mb FROM sandboxes WHERE owner_ref = ? AND status != ?
	`, ownerRef, string(models.SandboxStatusDestroyed))
	if err != nil {
		return nil, fmt.Errorf("list quota sandboxes: %w", err)
	}
	defer rows.Close()
	var out []QuotaSandbox
	for rows.Next() {
		var q QuotaSandbox
		if err := rows.Scan(&q.ID, &q.CPU, &q.MemoryMB); err != nil {
			return nil, fmt.Errorf("scan quota sandbox: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}
