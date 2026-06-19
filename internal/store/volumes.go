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

// ErrVolumeQuotaExceeded is returned by GetOrCreateVolume when inserting a new
// row would exceed the tenant's configured volume-count cap. Existing rows are
// returned idempotently and do not consume quota again.
var ErrVolumeQuotaExceeded = errors.New("tenant volume quota exceeded")

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
	source := strings.TrimSpace(v.Source)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO volumes (id, tenant, name, backend, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, tenant, name, backend, source, created.UTC())
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return ErrVolumeExists
		}
		return fmt.Errorf("create volume: %w", err)
	}
	v.ID, v.Tenant, v.Name, v.Backend, v.Source, v.CreatedAt = id, tenant, name, backend, source, created.UTC()
	return nil
}

// GetOrCreateVolume returns the existing (tenant,name) volume or inserts v as a
// new row when absent. The existence check, quota check, and insert run in one
// transaction so concurrent creates for different names cannot both observe the
// same pre-insert count and overshoot maxPerTenant. created is true only when a
// row was inserted by this call.
func (s *Store) GetOrCreateVolume(ctx context.Context, v *models.Volume, maxPerTenant int) (*models.Volume, bool, error) {
	if v == nil {
		return nil, false, fmt.Errorf("get or create volume: nil volume")
	}
	id := strings.TrimSpace(v.ID)
	tenant := strings.TrimSpace(v.Tenant)
	name := strings.TrimSpace(v.Name)
	backend := strings.TrimSpace(v.Backend)
	if id == "" || tenant == "" || name == "" || backend == "" {
		return nil, false, fmt.Errorf("get or create volume: id, tenant, name, and backend are required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin get or create volume: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := scanVolumeRow(tx.QueryRowContext(ctx, `
		SELECT id, tenant, name, backend, source, created_at
		FROM volumes
		WHERE tenant = ? AND name = ?
	`, tenant, name), "get existing volume")
	if err == nil {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit existing volume: %w", err)
		}
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	if maxPerTenant > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM volumes WHERE tenant = ?`, tenant).Scan(&count); err != nil {
			return nil, false, fmt.Errorf("count volumes: %w", err)
		}
		if count >= maxPerTenant {
			return nil, false, ErrVolumeQuotaExceeded
		}
	}
	// Deliberately do NOT clear a pending_volume_deletions row for this
	// (tenant,name) here. The source is deterministic, so a delete-then-recreate
	// of the same name reuses the same backend coordinate; silently dropping the
	// ledger row both permanently cancels reclaim of the prior generation and can
	// resurrect not-yet-reclaimed data. The reclaim worker is responsible for
	// skipping backend deletion when a live volume row still resolves to the same
	// source, so a recreate keeps its data without the request path racing the
	// ledger.

	created := v.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	source := strings.TrimSpace(v.Source)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO volumes (id, tenant, name, backend, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, tenant, name, backend, source, created.UTC()); err != nil {
		if isSQLiteUniqueConstraint(err) {
			// A duplicate can only happen if another process wrote the same DB
			// concurrently. Return the winner so callers remain idempotent.
			existing, getErr := scanVolumeRow(tx.QueryRowContext(ctx, `
				SELECT id, tenant, name, backend, source, created_at
				FROM volumes
				WHERE tenant = ? AND name = ?
			`, tenant, name), "get raced volume")
			if getErr != nil {
				return nil, false, getErr
			}
			if err := tx.Commit(); err != nil {
				return nil, false, fmt.Errorf("commit raced volume: %w", err)
			}
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("insert volume: %w", err)
	}
	out := &models.Volume{ID: id, Tenant: tenant, Name: name, Backend: backend, Source: source, CreatedAt: created.UTC()}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit new volume: %w", err)
	}
	return out, true, nil
}

// GetVolume returns the volume named name owned by tenant, or ErrNotFound.
func (s *Store) GetVolume(ctx context.Context, tenant, name string) (*models.Volume, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant, name, backend, source, created_at
		FROM volumes
		WHERE tenant = ? AND name = ?
	`, strings.TrimSpace(tenant), strings.TrimSpace(name))
	return scanVolumeRow(row, "get volume")
}

// GetVolumeByID returns the volume with the given id scoped to tenant (so one
// tenant cannot resolve another's id), or ErrNotFound.
func (s *Store) GetVolumeByID(ctx context.Context, tenant, id string) (*models.Volume, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant, name, backend, source, created_at
		FROM volumes
		WHERE tenant = ? AND id = ?
	`, strings.TrimSpace(tenant), strings.TrimSpace(id))
	return scanVolumeRow(row, "get volume by id")
}

// ListVolumes returns all volumes owned by tenant, newest first. Empty result
// is a zero-length slice, never nil.
func (s *Store) ListVolumes(ctx context.Context, tenant string) ([]models.Volume, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant, name, backend, source, created_at
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

// PutVolumeAttachments upserts the platform-volume attachments for a sandbox.
// The volume_id and sandbox_id foreign keys make create/delete races explicit:
// if a volume is deleted before the sandbox can persist its attachment, the
// insert fails and the service rolls the sandbox create back.
func (s *Store) PutVolumeAttachments(ctx context.Context, attachments []models.VolumeAttachment) error {
	if len(attachments) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin put volume attachments: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	for i := range attachments {
		a := attachments[i]
		tenant := strings.TrimSpace(a.Tenant)
		volumeID := strings.TrimSpace(a.VolumeID)
		sandboxID := strings.TrimSpace(a.SandboxID)
		target := strings.TrimSpace(a.Target)
		source := strings.TrimSpace(a.Source)
		if tenant == "" || volumeID == "" || sandboxID == "" || target == "" || source == "" {
			return fmt.Errorf("put volume attachment: tenant, volume_id, sandbox_id, target, and source are required")
		}
		created := a.CreatedAt
		if created.IsZero() {
			created = now
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO volume_attachments (tenant, volume_id, sandbox_id, target, source, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(tenant, volume_id, sandbox_id, target) DO UPDATE SET
				source = excluded.source,
				created_at = excluded.created_at
		`, tenant, volumeID, sandboxID, target, source, created.UTC()); err != nil {
			return fmt.Errorf("put volume attachment: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit volume attachments: %w", err)
	}
	return nil
}

// CountVolumeAttachments returns how many sandbox references currently point at
// volumeID for tenant. It is backed by idx_volume_attachments_volume and is used
// on Daytona delete instead of scanning every sandbox's encrypted mounts.
func (s *Store) CountVolumeAttachments(ctx context.Context, tenant, volumeID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM volume_attachments
		WHERE tenant = ? AND volume_id = ?
	`, strings.TrimSpace(tenant), strings.TrimSpace(volumeID)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count volume attachments: %w", err)
	}
	return n, nil
}

// DeleteVolumeIfUnattached schedules backend cleanup and removes the volume row
// only when no indexed attachments remain. The pending cleanup row is inserted
// in the same transaction before the metadata row is removed, so remote data
// never loses its reconciliation coordinates.
//
// fallbackSource is used only for rows created before the source column existed
// (vol.Source == ""); the frozen vol.Source is authoritative when present, so
// reclaim always targets exactly what was created even if config later changed.
func (s *Store) DeleteVolumeIfUnattached(ctx context.Context, tenant, id, fallbackSource string) error {
	tenant = strings.TrimSpace(tenant)
	id = strings.TrimSpace(id)
	fallbackSource = strings.TrimSpace(fallbackSource)
	if tenant == "" || id == "" {
		return fmt.Errorf("delete volume if unattached: tenant and id are required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete volume: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	vol, err := scanVolumeRow(tx.QueryRowContext(ctx, `
		SELECT id, tenant, name, backend, source, created_at
		FROM volumes
		WHERE tenant = ? AND id = ?
	`, tenant, id), "get volume for delete")
	if err != nil {
		return err
	}

	var attachers int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM volume_attachments
		WHERE tenant = ? AND volume_id = ?
	`, tenant, id).Scan(&attachers); err != nil {
		return fmt.Errorf("count volume attachments: %w", err)
	}
	if attachers > 0 {
		return fmt.Errorf("%w: %d attachments", ErrVolumeInUse, attachers)
	}

	source := strings.TrimSpace(vol.Source)
	if source == "" {
		source = fallbackSource
	}
	if source == "" {
		return fmt.Errorf("delete volume if unattached: volume %q has no stored source and no fallback was provided", id)
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pending_volume_deletions (volume_id, tenant, name, backend, source, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(volume_id) DO UPDATE SET
			tenant = excluded.tenant,
			name = excluded.name,
			backend = excluded.backend,
			source = excluded.source,
			created_at = excluded.created_at
	`, vol.ID, vol.Tenant, vol.Name, vol.Backend, source, now); err != nil {
		return fmt.Errorf("schedule volume deletion: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM volumes WHERE tenant = ? AND id = ?`, tenant, id)
	if err != nil {
		return fmt.Errorf("delete volume: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete volume: %w", err)
	}
	return nil
}

// ErrVolumeInUse is returned by DeleteVolumeIfUnattached when indexed
// attachments still reference the volume.
var ErrVolumeInUse = errors.New("volume is still attached")

// ListPendingVolumeDeletions exposes the durable cleanup ledger for tests and
// future backend-specific reclaim loops.
func (s *Store) ListPendingVolumeDeletions(ctx context.Context) ([]models.PendingVolumeDeletion, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT volume_id, tenant, name, backend, source, created_at
		FROM pending_volume_deletions
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list pending volume deletions: %w", err)
	}
	defer rows.Close()
	out := []models.PendingVolumeDeletion{}
	for rows.Next() {
		var p models.PendingVolumeDeletion
		if err := rows.Scan(&p.VolumeID, &p.Tenant, &p.Name, &p.Backend, &p.Source, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pending volume deletion: %w", err)
		}
		p.CreatedAt = p.CreatedAt.UTC()
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending volume deletions: %w", err)
	}
	return out, nil
}

// DeletePendingVolumeDeletion removes a reclaim-ledger row once its backend
// bytes have been deleted (or skipped because a live volume reclaimed the
// source). Idempotent: a missing row is success, so the reclaim loop can run
// at-least-once without tracking which rows it already cleared.
func (s *Store) DeletePendingVolumeDeletion(ctx context.Context, volumeID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM pending_volume_deletions WHERE volume_id = ?
	`, strings.TrimSpace(volumeID))
	if err != nil {
		return fmt.Errorf("delete pending volume deletion: %w", err)
	}
	return nil
}

// LiveVolumeExistsForSource reports whether any current volume row resolves to
// source. The reclaim worker calls this before deleting backend bytes: because
// sources are deterministic, a delete-then-recreate of the same name produces a
// new volume row pointing at the same coordinate. When that live row exists the
// worker must NOT delete the bytes — they now belong to the recreated volume —
// and simply drops the stale ledger row instead.
func (s *Store) LiveVolumeExistsForSource(ctx context.Context, source string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM volumes WHERE source = ?
	`, strings.TrimSpace(source)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("live volume for source: %w", err)
	}
	return n > 0, nil
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
	if err := scanner.Scan(&v.ID, &v.Tenant, &v.Name, &v.Backend, &v.Source, &v.CreatedAt); err != nil {
		return nil, err
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return &v, nil
}
