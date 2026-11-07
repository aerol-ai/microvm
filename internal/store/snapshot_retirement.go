package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SnapshotRegistryRetirement is the obligation to remove one registry copy
// of a snapshot that no longer exists on this node: the manifest at
// RegistryRef@Digest. OwnerRef and Name are the snapshot it was pushed for,
// so the worker can tell when a re-created snapshot of the same name still
// has a push to land.
type SnapshotRegistryRetirement struct {
	RegistryRef string
	Digest      string
	OwnerRef    string
	Name        string
	ScheduledAt time.Time
	Attempts    int
	LastError   string
}

// DeleteSnapshotRetiringRegistryCopy deletes a snapshot row and, in the same
// transaction, records the obligation to retire its registry copy — but
// only a copy this node's push reconciler made. pushedRef is the ref the
// reconciler pushes this snapshot to ("" when no registry is configured: no
// obligation then). The obligation is written only when the row, as it is
// at the moment of the delete, carries exactly that ref with a digest, and
// its image is not that ref itself (a snapshot registered with a registry
// image names a copy someone else owns).
//
// Reading the row inside the transaction is what makes this race-free with
// the push worker: a push that completes just before the delete is seen
// here, and one that completes just after finds the row gone and records
// its own obligation (ScheduleSnapshotRegistryRetirement).
func (s *Store) DeleteSnapshotRetiringRegistryCopy(ctx context.Context, ownerRef, name, pushedRef string) (retErr error) {
	ownerRef, name, pushedRef = strings.TrimSpace(ownerRef), strings.TrimSpace(name), strings.TrimSpace(pushedRef)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete snapshot: begin: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	var image, ref, digest string
	err = tx.QueryRowContext(ctx, `
		SELECT image, image_registry_ref, image_digest FROM sandbox_snapshots
		WHERE owner_ref = ? AND name = ?
	`, ownerRef, name).Scan(&image, &ref, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete snapshot: read row: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sandbox_snapshots WHERE owner_ref = ? AND name = ?`, ownerRef, name); err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	ref, digest = strings.TrimSpace(ref), strings.TrimSpace(digest)
	if pushedRef != "" && ref == pushedRef && digest != "" && strings.TrimSpace(image) != ref {
		if err := scheduleRetirement(ctx, tx, SnapshotRegistryRetirement{RegistryRef: ref, Digest: digest, OwnerRef: ownerRef, Name: name}); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("delete snapshot: commit: %w", err)
	}
	return nil
}

// ScheduleSnapshotRegistryRetirement records a retirement obligation. An
// obligation already recorded for the same manifest is left as it is.
func (s *Store) ScheduleSnapshotRegistryRetirement(ctx context.Context, r SnapshotRegistryRetirement) error {
	return scheduleRetirement(ctx, s.db, r)
}

func scheduleRetirement(ctx context.Context, exec dbExecer, r SnapshotRegistryRetirement) error {
	ref, digest := strings.TrimSpace(r.RegistryRef), strings.TrimSpace(r.Digest)
	if ref == "" || digest == "" {
		// A copy with no digest can only be addressed by tag, and the tag
		// may already belong to a newer snapshot of the same name.
		return nil
	}
	if _, err := exec.ExecContext(ctx, `
		INSERT INTO snapshot_registry_retirements (registry_ref, digest, owner_ref, name, scheduled_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(registry_ref, digest) DO NOTHING
	`, ref, digest, strings.TrimSpace(r.OwnerRef), strings.TrimSpace(r.Name), time.Now().UTC()); err != nil {
		return fmt.Errorf("schedule snapshot registry retirement: %w", err)
	}
	return nil
}

// ListDueSnapshotRegistryRetirements returns up to limit obligations due by
// now, the longest-waiting first. A deferred or failed obligation is pushed
// to the back (DeferSnapshotRegistryRetirement), so a few that cannot finish
// never starve the rest of a bounded batch.
func (s *Store) ListDueSnapshotRegistryRetirements(ctx context.Context, now time.Time, limit int) ([]SnapshotRegistryRetirement, error) {
	if limit <= 0 {
		return nil, errors.New("list snapshot registry retirements: limit must be positive")
	}
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT registry_ref, digest, owner_ref, name, scheduled_at, attempts, last_error
		FROM snapshot_registry_retirements
		WHERE scheduled_at <= ?
		ORDER BY scheduled_at, registry_ref, digest
		LIMIT ?
	`, now.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list snapshot registry retirements: %w", err)
	}
	defer rows.Close()
	var out []SnapshotRegistryRetirement
	for rows.Next() {
		var r SnapshotRegistryRetirement
		if err := rows.Scan(&r.RegistryRef, &r.Digest, &r.OwnerRef, &r.Name, &r.ScheduledAt, &r.Attempts, &r.LastError); err != nil {
			return nil, fmt.Errorf("scan snapshot registry retirement: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot registry retirements: %w", err)
	}
	return out, nil
}

// SnapshotRegistryCopyInUse answers the two questions asked before a copy
// is retired. inUse: a snapshot row on this node still names this exact
// manifest (ref and digest) — the obligation is void. pushPending: a row of
// the same owner and name has a push still to land (pending, pushing or
// error), which can put this very digest back under the tag — wait for it.
func (s *Store) SnapshotRegistryCopyInUse(ctx context.Context, registryRef, digest, ownerRef, name string) (inUse, pushPending bool, err error) {
	err = s.rdb.QueryRowContext(ctx, `
		SELECT
			EXISTS (SELECT 1 FROM sandbox_snapshots WHERE image_registry_ref = ? AND image_digest = ?),
			EXISTS (SELECT 1 FROM sandbox_snapshots WHERE owner_ref = ? AND name = ?
				AND push_state IN ('pending', 'pushing', 'error'))
	`, strings.TrimSpace(registryRef), strings.TrimSpace(digest), strings.TrimSpace(ownerRef), strings.TrimSpace(name)).Scan(&inUse, &pushPending)
	if err != nil {
		return false, false, fmt.Errorf("check snapshot registry copy: %w", err)
	}
	return inUse, pushPending, nil
}

// DeferSnapshotRegistryRetirement moves an obligation to the back of the
// queue. A non-empty failure also counts an attempt and keeps the reason,
// for an operator wondering why a copy is still there.
func (s *Store) DeferSnapshotRegistryRetirement(ctx context.Context, registryRef, digest, failure string) error {
	query := `UPDATE snapshot_registry_retirements SET scheduled_at = ? WHERE registry_ref = ? AND digest = ?`
	args := []any{time.Now().UTC(), strings.TrimSpace(registryRef), strings.TrimSpace(digest)}
	if failure != "" {
		query = `UPDATE snapshot_registry_retirements
			SET scheduled_at = ?, attempts = attempts + 1, last_error = ?
			WHERE registry_ref = ? AND digest = ?`
		args = []any{args[0], failure, args[1], args[2]}
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("defer snapshot registry retirement: %w", err)
	}
	return nil
}

// DeleteSnapshotRegistryRetirement drops a fulfilled (or void) obligation.
func (s *Store) DeleteSnapshotRegistryRetirement(ctx context.Context, registryRef, digest string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM snapshot_registry_retirements WHERE registry_ref = ? AND digest = ?`,
		strings.TrimSpace(registryRef), strings.TrimSpace(digest)); err != nil {
		return fmt.Errorf("delete snapshot registry retirement: %w", err)
	}
	return nil
}
