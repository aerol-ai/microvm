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

// The snapshot and template push queues are worked by one reconciler per
// node, but more than one sweep can still see the same row: a sweep that
// outlives PushClaimLease, a debug trigger, a daemon restart mid-push. So a
// listed row is only a candidate. A worker owns a row from the moment its
// claim (one conditional UPDATE) matches it, until its completion (another
// conditional UPDATE, fenced by the claim's stamp) does. A second claimer of
// the same candidate matches nothing and walks away; a claimer whose lease
// ran out and was taken over finds its completion fenced off and leaves the
// row to the newer claim.

// PushClaimLease bounds how long a row may sit in 'pushing' before another
// reconciler tick may reclaim it. Longer than any realistic single artifact
// push, short enough that a crashed daemon's claims drain on the next few
// ticks rather than needing operator action. The reconcilers also cap each
// push at this long, so a push never outlives the claim it ran under.
const PushClaimLease = 30 * time.Minute

// snapshotPushColumns is the projection scanSnapshot reads.
const snapshotPushColumns = `name, image, image_id, source_sandbox_id, created_at,
	entrypoint_json, region_id, cpu, memory_mb, disk_gb, gpu,
	image_distribution_mode, image_digest, image_registry_ref, image_verified_at,
	push_state, push_error, owner_ref`

// templatePushColumns is the projection scanTemplate reads.
const templatePushColumns = `id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
	last_error, created_at, updated_at, ready_at,
	snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
	snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
	has_overlay, push_state, push_error, registry_ref, push_digest`

// snapshotPushQueued is the queue predicate, as two terms. The first is
// the literal WHERE of idx_sandbox_snapshots_push_queue, so SQLite can prove
// the partial index covers the query; the second narrows 'pushing' to rows
// whose claim has expired (its one argument is now - PushClaimLease).
const snapshotPushQueued = `push_state IN ('pending', 'error', 'pushing')
	AND (push_state <> 'pushing' OR push_claimed_at IS NULL OR push_claimed_at <= ?)`

// maxSnapshotPushPage bounds one queue read, whatever a caller asks for.
const maxSnapshotPushPage = 500

// SnapshotPushCursor is a keyset position in the snapshot push queue. Rows
// sort by (created_at, owner_ref, name) — oldest first, the primary key
// breaking ties — so the cursor taken from a page's last row stays valid
// while rows ahead of it change state or disappear. The zero value starts
// at the beginning.
type SnapshotPushCursor struct {
	CreatedAt time.Time
	OwnerRef  string
	Name      string
}

// SnapshotPushCursorAfter is the cursor that continues after snapshot.
func SnapshotPushCursorAfter(snapshot *models.SandboxSnapshot) SnapshotPushCursor {
	return SnapshotPushCursor{CreatedAt: snapshot.CreatedAt, OwnerRef: snapshot.OwnerRef, Name: snapshot.Name}
}

// snapshotPushPageSQL is ListSnapshotsPendingPushPage's statement, separate
// so a test can check that SQLite walks the partial index rather than the
// catalogue.
func snapshotPushPageSQL(after SnapshotPushCursor, limit int, now time.Time) (string, []any) {
	query := `SELECT ` + snapshotPushColumns + `
		FROM sandbox_snapshots
		WHERE ` + snapshotPushQueued + `
			AND (created_at, owner_ref, name) > (?, ?, ?)
		ORDER BY created_at, owner_ref, name
		LIMIT ?`
	return query, []any{now.Add(-PushClaimLease), after.CreatedAt.UTC(), after.OwnerRef, after.Name, limit}
}

// ListSnapshotsPendingPushPage returns up to limit queued snapshots after
// the cursor: 'pending' (fresh from a create), 'error' (a failed attempt to
// retry) and 'pushing' whose claim has expired (a worker that died or hung).
// A backlog is read page by page rather than all at once, each page a range
// scan of the partial queue index, so a recovery storm costs memory in
// proportion to the page, not to the backlog.
func (s *Store) ListSnapshotsPendingPushPage(ctx context.Context, after SnapshotPushCursor, limit int) ([]*models.SandboxSnapshot, error) {
	if limit <= 0 {
		return nil, errors.New("list snapshots pending push: limit must be positive")
	}
	query, args := snapshotPushPageSQL(after, min(limit, maxSnapshotPushPage), time.Now().UTC())
	rows, err := s.rdb.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list snapshots pending push: %w", err)
	}
	defer rows.Close()
	var items []*models.SandboxSnapshot
	for rows.Next() {
		snapshot, err := scanSnapshot(rows)
		if err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		items = append(items, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshots: %w", err)
	}
	return items, nil
}

// ClaimSnapshotPush moves one queued snapshot to 'pushing' for this caller,
// atomically: it matches only while the row is still queued (pending, error,
// or pushing under an expired claim), so of two workers holding the same
// listed row exactly one gets it. On success it returns the row as claimed —
// the image to push is read in the same statement, never from a listing
// that may predate a delete and re-create — and the claim stamp the
// completion must present. ok is false, with no error, when another claim
// owns the row or it is no longer queued (or gone).
func (s *Store) ClaimSnapshotPush(ctx context.Context, ownerRef, name string) (*models.SandboxSnapshot, time.Time, bool, error) {
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, `
		UPDATE sandbox_snapshots
		SET push_state = 'pushing', push_error = '', push_claimed_at = ?
		WHERE owner_ref = ? AND name = ? AND `+snapshotPushQueued+`
		RETURNING `+snapshotPushColumns,
		now, strings.TrimSpace(ownerRef), strings.TrimSpace(name), now.Add(-PushClaimLease))
	snapshot, err := scanSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("claim snapshot push: %w", err)
	}
	return snapshot, now, true, nil
}

// CompleteSnapshotPush records a finished push: the registry copy's mode,
// ref and digest and the 'active' state, in ONE statement, so no reader ever
// sees a row whose distribution and push state disagree. Fenced by the
// claim: it applies only while the row is still 'pushing' under claimedAt.
// applied is false when a newer claim took the row over or the row is gone;
// the caller then owns nothing and must not write again.
func (s *Store) CompleteSnapshotPush(ctx context.Context, ownerRef, name string, claimedAt time.Time, mode, registryRef, digest string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_snapshots
		SET image_distribution_mode = ?, image_registry_ref = ?, image_digest = ?, image_verified_at = ?,
			push_state = 'active', push_error = '', push_claimed_at = NULL
		WHERE owner_ref = ? AND name = ? AND push_state = 'pushing' AND push_claimed_at = ?
	`,
		strings.TrimSpace(mode), strings.TrimSpace(registryRef), strings.TrimSpace(digest), time.Now().UTC(),
		strings.TrimSpace(ownerRef), strings.TrimSpace(name), claimedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("complete snapshot push: %w", err)
	}
	return rowsChanged(result, "complete snapshot push")
}

// ReleaseSnapshotPush ends a claim without a registry copy: state 'error'
// (with the reason, retried next sweep) or 'active' (nothing to push).
// Fenced exactly like CompleteSnapshotPush.
func (s *Store) ReleaseSnapshotPush(ctx context.Context, ownerRef, name string, claimedAt time.Time, state, errMsg string) (bool, error) {
	state = strings.TrimSpace(state)
	if state == models.SnapshotPushStatePushing {
		return false, errors.New("release snapshot push: a release must leave 'pushing'")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_snapshots
		SET push_state = ?, push_error = ?, push_claimed_at = NULL
		WHERE owner_ref = ? AND name = ? AND push_state = 'pushing' AND push_claimed_at = ?
	`, state, errMsg, strings.TrimSpace(ownerRef), strings.TrimSpace(name), claimedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("release snapshot push: %w", err)
	}
	return rowsChanged(result, "release snapshot push")
}

// ClaimTemplatePush is ClaimSnapshotPush for the template artifact queue,
// whose rows are keyed by id.
func (s *Store) ClaimTemplatePush(ctx context.Context, id string) (*models.Template, time.Time, bool, error) {
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, `
		UPDATE firecracker_templates
		SET push_state = 'pushing', push_error = '', push_claimed_at = ?, updated_at = ?
		WHERE id = ? AND (push_state IN ('pending', 'error')
			OR (push_state = 'pushing' AND (push_claimed_at IS NULL OR push_claimed_at <= ?)))
		RETURNING `+templatePushColumns,
		now, now, strings.TrimSpace(id), now.Add(-PushClaimLease))
	template, err := scanTemplate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("claim template push: %w", err)
	}
	return template, now, true, nil
}

// CompleteTemplatePush is CompleteSnapshotPush for templates: registry ref,
// digest and 'active' land in one fenced statement.
func (s *Store) CompleteTemplatePush(ctx context.Context, id string, claimedAt time.Time, registryRef, digest string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET registry_ref = ?, push_digest = ?, push_state = 'active', push_error = '',
			push_claimed_at = NULL, updated_at = ?
		WHERE id = ? AND push_state = 'pushing' AND push_claimed_at = ?
	`, strings.TrimSpace(registryRef), strings.TrimSpace(digest), time.Now().UTC(), strings.TrimSpace(id), claimedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("complete template push: %w", err)
	}
	return rowsChanged(result, "complete template push")
}

// ReleaseTemplatePush is ReleaseSnapshotPush for templates.
func (s *Store) ReleaseTemplatePush(ctx context.Context, id string, claimedAt time.Time, state, errMsg string) (bool, error) {
	state = strings.TrimSpace(state)
	if state == models.TemplatePushStatePushing {
		return false, errors.New("release template push: a release must leave 'pushing'")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET push_state = ?, push_error = ?, push_claimed_at = NULL, updated_at = ?
		WHERE id = ? AND push_state = 'pushing' AND push_claimed_at = ?
	`, state, errMsg, time.Now().UTC(), strings.TrimSpace(id), claimedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("release template push: %w", err)
	}
	return rowsChanged(result, "release template push")
}

func rowsChanged(result sql.Result, op string) (bool, error) {
	n, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%s rows affected: %w", op, err)
	}
	return n > 0, nil
}
