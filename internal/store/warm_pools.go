package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrWarmPoolNotFound means no warm-pool entry names that image (404).
var ErrWarmPoolNotFound = errors.New("warm pool not found")

// ErrWarmPoolLimit is a PUT of a new entry when models.MaxWarmPools are
// already stored (409).
var ErrWarmPoolLimit = fmt.Errorf("at most %d warm pools may be configured", models.MaxWarmPools)

// PutWarmPool creates or replaces the entry for an image. Generation goes up
// by one only when the settings change, so the same body twice is a no-op;
// changed reports whether it did. The limit is checked in the same
// transaction as the insert, so two concurrent creates cannot both pass it.
func (s *Store) PutWarmPool(ctx context.Context, in models.WarmPool, now time.Time) (p models.WarmPool, changed bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, false, fmt.Errorf("put warm pool: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	old, err := getWarmPool(ctx, tx, in.Image)
	switch {
	case errors.Is(err, ErrWarmPoolNotFound):
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM warm_pools`).Scan(&n); err != nil {
			return p, false, fmt.Errorf("put warm pool: %w", err)
		}
		if n >= models.MaxWarmPools {
			return p, false, ErrWarmPoolLimit
		}
		p = models.WarmPool{Image: in.Image, Generation: 1, CreatedAt: now.UTC()}
	case err != nil:
		return p, false, err
	case warmPoolSettingsEqual(old, in):
		return old, false, nil
	default:
		p = old
		p.Generation++
	}
	p.Depth, p.UpdatedAt = in.Depth, now.UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO warm_pools (image, depth, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(image) DO UPDATE SET
			depth = excluded.depth,
			generation = excluded.generation,
			updated_at = excluded.updated_at
	`, p.Image, p.Depth, p.Generation, p.CreatedAt, p.UpdatedAt); err != nil {
		return models.WarmPool{}, false, fmt.Errorf("put warm pool: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.WarmPool{}, false, fmt.Errorf("put warm pool: %w", err)
	}
	return p, true, nil
}

// warmPoolSettingsEqual compares what a PUT sets, not the bookkeeping.
func warmPoolSettingsEqual(a, b models.WarmPool) bool {
	return a.Depth == b.Depth
}

// GetWarmPool returns the entry for an image.
func (s *Store) GetWarmPool(ctx context.Context, image string) (models.WarmPool, error) {
	return getWarmPool(ctx, s.db, image)
}

func getWarmPool(ctx context.Context, q queryRower, image string) (models.WarmPool, error) {
	p := models.WarmPool{Image: image}
	err := q.QueryRowContext(ctx, `
		SELECT depth, generation, created_at, updated_at FROM warm_pools WHERE image = ?
	`, image).Scan(&p.Depth, &p.Generation, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrWarmPoolNotFound
	}
	if err != nil {
		return p, fmt.Errorf("get warm pool: %w", err)
	}
	return p, nil
}

// ListWarmPools returns every entry by image. There are at most
// models.MaxWarmPools, so there is no paging.
func (s *Store) ListWarmPools(ctx context.Context) ([]models.WarmPool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT image, depth, generation, created_at, updated_at FROM warm_pools ORDER BY image
	`)
	if err != nil {
		return nil, fmt.Errorf("list warm pools: %w", err)
	}
	defer rows.Close()
	out := []models.WarmPool{}
	for rows.Next() {
		var p models.WarmPool
		if err := rows.Scan(&p.Image, &p.Depth, &p.Generation, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan warm pool: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteWarmPool removes the entry for an image. Deleting one that is
// already gone succeeds, so a retried DELETE converges.
func (s *Store) DeleteWarmPool(ctx context.Context, image string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM warm_pools WHERE image = ?`, image); err != nil {
		return fmt.Errorf("delete warm pool: %w", err)
	}
	return nil
}
