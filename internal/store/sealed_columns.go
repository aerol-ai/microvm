package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// SealedColumn is a column sealed under the server key. A server-key
// rotation reseals every one of them onto the new key before the old key is
// retired (plans/customer-key-custody.md §13 step 3).
type SealedColumn int

const (
	SealedToolboxToken SealedColumn = iota
	SealedRegistryAuth
	SealedMounts
	SealedEnv
)

// SealedColumns is every server-key-sealed column in the store. The egress
// CA record (a file) and local cluster-secret copies (envelopes) are
// resealed by the service.
var SealedColumns = []SealedColumn{SealedToolboxToken, SealedRegistryAuth, SealedMounts, SealedEnv}

// sealedColumnSQL keeps the identifiers in constants: nothing a caller
// passes reaches the SQL text.
var sealedColumnSQL = map[SealedColumn]struct{ name, list, cas string }{
	SealedToolboxToken: {"toolbox_token",
		`SELECT id, toolbox_token_sealed, '' FROM sandboxes WHERE id > ? AND length(toolbox_token_sealed) > 0 ORDER BY id LIMIT ?`,
		`UPDATE sandboxes SET toolbox_token_sealed = ? WHERE id = ? AND toolbox_token_sealed = ?`},
	SealedRegistryAuth: {"registry_auth",
		`SELECT id, registry_auth_sealed, '' FROM sandboxes WHERE id > ? AND length(registry_auth_sealed) > 0 ORDER BY id LIMIT ?`,
		`UPDATE sandboxes SET registry_auth_sealed = ? WHERE id = ? AND registry_auth_sealed = ?`},
	SealedMounts: {"mounts",
		`SELECT sandbox_id, sealed_blob, '' FROM sandbox_mounts WHERE sandbox_id > ? AND length(sealed_blob) > 0 ORDER BY sandbox_id LIMIT ?`,
		`UPDATE sandbox_mounts SET sealed_blob = ? WHERE sandbox_id = ? AND sealed_blob = ?`},
	SealedEnv: {"env",
		`SELECT e.sandbox_id, e.sealed_blob, COALESCE(s.audit_incarnation_id, '') FROM sandbox_env e LEFT JOIN sandboxes s ON s.id = e.sandbox_id
		 WHERE e.sandbox_id > ? AND length(e.sealed_blob) > 0 ORDER BY e.sandbox_id LIMIT ?`,
		`UPDATE sandbox_env SET sealed_blob = ? WHERE sandbox_id = ? AND sealed_blob = ?`},
}

func (c SealedColumn) String() string { return sealedColumnSQL[c].name }

// SealedRow is one sealed value: its sandbox, its bytes and the AAD it was
// sealed with.
type SealedRow struct {
	SandboxID string
	Sealed    []byte
	AAD       []byte
}

// ListSealedRows returns the next sandbox-ordered page of a sealed column
// after afterID. Empty values (no credentials) are skipped.
func (s *Store) ListSealedRows(ctx context.Context, col SealedColumn, afterID string, limit int) ([]SealedRow, error) {
	q, ok := sealedColumnSQL[col]
	if !ok {
		return nil, fmt.Errorf("unknown sealed column %d", col)
	}
	if limit <= 0 {
		return nil, errors.New("sealed row page limit must be positive")
	}
	rows, err := s.db.QueryContext(ctx, q.list, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list sealed %s: %w", q.name, err)
	}
	defer rows.Close()
	var out []SealedRow
	for rows.Next() {
		var r SealedRow
		var incarnation string
		if err := rows.Scan(&r.SandboxID, &r.Sealed, &incarnation); err != nil {
			return nil, fmt.Errorf("scan sealed %s: %w", q.name, err)
		}
		switch col {
		case SealedToolboxToken:
			r.AAD = toolboxTokenAAD(r.SandboxID)
		case SealedEnv:
			r.AAD = secrets.EnvAAD(r.SandboxID, incarnation)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResealedRow is a value resealed under the current key, to write only if
// the stored bytes are still Old.
type ResealedRow struct {
	SandboxID string
	Old, New  []byte
}

// ResealSealedRows writes a page of resealed values in one transaction, each
// under compare-and-swap on the exact bytes read: a write, a reseal or a
// delete that landed in between wins and the row is skipped. written[i]
// says whether rows[i] was stored.
func (s *Store) ResealSealedRows(ctx context.Context, col SealedColumn, rows []ResealedRow) (written []bool, err error) {
	q, ok := sealedColumnSQL[col]
	if !ok {
		return nil, fmt.Errorf("unknown sealed column %d", col)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("reseal %s: %w", q.name, err)
	}
	defer tx.Rollback()
	written = make([]bool, len(rows))
	for i, r := range rows {
		res, err := tx.ExecContext(ctx, q.cas, r.New, r.SandboxID, r.Old)
		if err != nil {
			return nil, fmt.Errorf("reseal %s %s: %w", q.name, r.SandboxID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("reseal %s %s: %w", q.name, r.SandboxID, err)
		}
		written[i] = n == 1
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("reseal %s: %w", q.name, err)
	}
	return written, nil
}
