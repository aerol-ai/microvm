package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// moved_in_rows holds, per sandbox a snapshot move imported here with its
// memory and no row of its own yet (a gVisor checkpoint move: the sandbox is
// rebuilt only after the swap), what the move's bundle carried, sealed by the
// service: the source row, its toolbox token among it, and the leader's
// recreate inputs. It is written before the import is acknowledged and
// removed by the start after the swap or a drop, so an agent restart in
// between neither loses the sandbox nor leaves its staged checkpoint behind
// (review N4). The blob is opaque here, like sandbox_env's.
const createMovedInRowsTable = `CREATE TABLE IF NOT EXISTS moved_in_rows (
	sandbox_id  TEXT PRIMARY KEY,
	sealed_blob BLOB NOT NULL,
	imported_at INTEGER NOT NULL
)`

// MovedInRow is one row of moved_in_rows.
type MovedInRow struct {
	SandboxID  string
	Sealed     []byte
	ImportedAt time.Time
}

// PutMovedInRow stores id's sealed moved-in row, replacing an earlier
// import's: the leader imports a move again after a failed attempt.
func (s *Store) PutMovedInRow(ctx context.Context, id string, sealed []byte, importedAt time.Time) error {
	if id == "" || len(sealed) == 0 {
		return errors.New("put moved-in row: id and blob are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO moved_in_rows (sandbox_id, sealed_blob, imported_at)
		VALUES (?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			sealed_blob = excluded.sealed_blob,
			imported_at = excluded.imported_at
	`, id, sealed, importedAt.UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("put moved-in row: %w", err)
	}
	return nil
}

// GetMovedInRow returns id's moved-in row, or ErrNotFound.
func (s *Store) GetMovedInRow(ctx context.Context, id string) (MovedInRow, error) {
	row := s.rdb.QueryRowContext(ctx, `SELECT sandbox_id, sealed_blob, imported_at FROM moved_in_rows WHERE sandbox_id = ?`, id)
	r, err := scanMovedInRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MovedInRow{}, ErrNotFound
	}
	if err != nil {
		return MovedInRow{}, fmt.Errorf("get moved-in row: %w", err)
	}
	return r, nil
}

// ListMovedInRows returns every moved-in row, oldest import first. A worker
// holds one per move in flight to it, so the list is short.
func (s *Store) ListMovedInRows(ctx context.Context) ([]MovedInRow, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT sandbox_id, sealed_blob, imported_at FROM moved_in_rows ORDER BY imported_at, sandbox_id`)
	if err != nil {
		return nil, fmt.Errorf("list moved-in rows: %w", err)
	}
	defer rows.Close()
	var out []MovedInRow
	for rows.Next() {
		r, err := scanMovedInRow(rows)
		if err != nil {
			return nil, fmt.Errorf("list moved-in rows: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list moved-in rows: %w", err)
	}
	return out, nil
}

// DeleteMovedInRow removes id's moved-in row. Idempotent.
func (s *Store) DeleteMovedInRow(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM moved_in_rows WHERE sandbox_id = ?`, id); err != nil {
		return fmt.Errorf("delete moved-in row: %w", err)
	}
	return nil
}

func scanMovedInRow(row interface{ Scan(...any) error }) (MovedInRow, error) {
	var r MovedInRow
	var at int64
	if err := row.Scan(&r.SandboxID, &r.Sealed, &at); err != nil {
		return MovedInRow{}, err
	}
	r.ImportedAt = time.Unix(0, at).UTC()
	return r, nil
}
