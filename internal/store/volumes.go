package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrVolumeExists is returned by CreateVolume when the (tenant, name) pair is
// already taken. Facades map this to 409 Conflict. It is distinct from a
// generic constraint error so callers can branch on it for idempotent
// get-or-create semantics.
var ErrVolumeExists = errors.New("volume already exists for this tenant")

// CreateVolume inserts a new volume row. The (tenant, name) unique index makes
// this the idempotency boundary: a duplicate returns ErrVolumeExists rather
// than a second row. CreatedAt is stamped here when the caller leaves it zero.
func (s *Store) CreateVolume(ctx context.Context, v *models.Volume) error {
	if v == nil {
		return fmt.Errorf("create volume: nil volume")
	}
	id := strings.TrimSpace(v.ID)
	tenant := strings.TrimSpace(v.Tenant)
	name := strings.TrimSpace(v.Name)
	backend := strings.TrimSpace(v.Backend)
	if id == "" || tenant == "" || name == "" || backend == "" {
		return fmt.Errorf("create volume: id, tenant, name, and backend are required")
	}
	created := v.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO volumes (id, tenant, name, backend, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, id, tenant, name, backend, created.UTC())
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return ErrVolumeExists
		}
		return fmt.Errorf("create volume: %w", err)
	}
	v.ID, v.Tenant, v.Name, v.Backend, v.CreatedAt = id, tenant, name, backend, created.UTC()
	return nil
}

// GetVolume returns the volume named name owned by tenant, or ErrNotFound.
func (s *Store) GetVolume(ctx context.Context, tenant, name string) (*models.Volume, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant, name, backend, created_at
		FROM volumes
		WHERE tenant = ? AND name = ?
	`, strings.TrimSpace(tenant), strings.TrimSpace(name))
	return scanVolumeRow(row, "get volume")
}

// GetVolumeByID returns the volume with the given id scoped to tenant (so one
// tenant cannot resolve another's id), or ErrNotFound.
func (s *Store) GetVolumeByID(ctx context.Context, tenant, id string) (*models.Volume, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant, name, backend, created_at
		FROM volumes
		WHERE tenant = ? AND id = ?
	`, strings.TrimSpace(tenant), strings.TrimSpace(id))
	return scanVolumeRow(row, "get volume by id")
}

// ListVolumes returns all volumes owned by tenant, newest first. Empty result
// is a zero-length slice, never nil.
func (s *Store) ListVolumes(ctx context.Context, tenant string) ([]models.Volume, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant, name, backend, created_at
		FROM volumes
		WHERE tenant = ?
		ORDER BY created_at DESC, name ASC
	`, strings.TrimSpace(tenant))
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	defer rows.Close()

	out := []models.Volume{}
	for rows.Next() {
		v, err := scanVolume(rows)
		if err != nil {
			return nil, fmt.Errorf("scan volume: %w", err)
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate volumes: %w", err)
	}
	return out, nil
}

// CountVolumes returns how many volumes tenant owns. Used for per-tenant quota
// enforcement at create time.
func (s *Store) CountVolumes(ctx context.Context, tenant string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM volumes WHERE tenant = ?
	`, strings.TrimSpace(tenant)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count volumes: %w", err)
	}
	return n, nil
}

// DeleteVolume removes the volume id owned by tenant. Returns ErrNotFound when
// no such row exists so the facade can answer 404 rather than a silent 200.
// Callers MUST enforce the no-live-attacher rule before calling this; the store
// only owns the row.
func (s *Store) DeleteVolume(ctx context.Context, tenant, id string) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM volumes WHERE tenant = ? AND id = ?
	`, strings.TrimSpace(tenant), strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("delete volume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete volume rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanVolumeRow(row *sql.Row, op string) (*models.Volume, error) {
	v, err := scanVolume(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return v, nil
}

func scanVolume(scanner interface {
	Scan(dest ...any) error
}) (*models.Volume, error) {
	var v models.Volume
	if err := scanner.Scan(&v.ID, &v.Tenant, &v.Name, &v.Backend, &v.CreatedAt); err != nil {
		return nil, err
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return &v, nil
}
