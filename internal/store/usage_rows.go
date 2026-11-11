package store

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ListUsageRows returns this node's sandboxes for the per-owner usage
// exporter (plans/kubernetes-v2-architecture.md, C20). Only the fields it
// reads are set: ID, Status, ContainerID, OwnerRef, CPU, MemoryMB, Runtime,
// Engine, CreatedAt and UpdatedAt. Every other field is zero.
//
// Why not List: List decodes every column and every side table of every
// row, and the exporter asks every few seconds. At a thousand sandboxes on
// a worker, that is a lot of work to throw away.
//
// Destroyed rows are left out: they hold nothing. So are rows whose create
// failed but whose rollback is still pending: the client was told there is
// no sandbox, so it must not be charged for one.
func (s *Store) ListUsageRows(ctx context.Context) ([]*models.Sandbox, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT id, status, container_id, owner_ref, cpu, memory_mb, runtime, engine, created_at, updated_at
		FROM sandboxes
		WHERE status != ? AND rollback_pending = 0
	`, string(models.SandboxStatusDestroyed))
	if err != nil {
		return nil, fmt.Errorf("list usage rows: %w", err)
	}
	defer rows.Close()
	var out []*models.Sandbox
	for rows.Next() {
		var sb models.Sandbox
		if err := rows.Scan(&sb.ID, &sb.Status, &sb.ContainerID, &sb.OwnerRef, &sb.CPU, &sb.MemoryMB,
			&sb.Runtime, &sb.Engine, &sb.CreatedAt, &sb.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan usage row: %w", err)
		}
		out = append(out, &sb)
	}
	return out, rows.Err()
}
