package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Scoped API tokens on a single node (plans/identity-and-access.md §5.4).
// The service keeps every row in memory (identity.TokenSet) and reads this
// table only at boot and for a list; the request path never touches it.

var (
	// ErrAPITokenNameTaken is a create whose name another token in the same
	// team already holds (409).
	ErrAPITokenNameTaken = errors.New("API token name already used in this team")
	// ErrAPITokenIDTaken is a create whose random id collides with an
	// existing token's: the caller mints a new id and retries.
	ErrAPITokenIDTaken = errors.New("API token id already exists")
)

// InsertAPIToken stores a new token. It never replaces one: a duplicate id
// is ErrAPITokenIDTaken and a duplicate (team, name) ErrAPITokenNameTaken.
func (s *Store) InsertAPIToken(ctx context.Context, rec identity.TokenRecord) error {
	if err := rec.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_tokens (id, name, role, owner_ref, created_by, created_at, expires_at, secret_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, rec.ID, rec.Name, string(rec.Role), rec.OwnerRef, rec.CreatedBy, rec.CreatedAt.UnixNano(), rec.ExpiresAt.UnixNano(), rec.SecretHash)
	if err == nil {
		return nil
	}
	if isSQLiteUniqueConstraint(err) {
		// The message names the column that collided; the id is the
		// primary key, the name the (owner_ref, name) index.
		if strings.Contains(err.Error(), "api_tokens.id") {
			return fmt.Errorf("%w: %s", ErrAPITokenIDTaken, rec.ID)
		}
		return fmt.Errorf("%w: %q", ErrAPITokenNameTaken, rec.Name)
	}
	return fmt.Errorf("insert API token: %w", err)
}

// ListAPITokens returns every stored token, sorted by team and name.
func (s *Store) ListAPITokens(ctx context.Context) ([]identity.TokenRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, role, owner_ref, created_by, created_at, expires_at, secret_hash
		FROM api_tokens ORDER BY owner_ref, name, id
	`)
	if err != nil {
		return nil, fmt.Errorf("list API tokens: %w", err)
	}
	defer rows.Close()
	var out []identity.TokenRecord
	for rows.Next() {
		var (
			rec              identity.TokenRecord
			role             string
			created, expires int64
		)
		if err := rows.Scan(&rec.ID, &rec.Name, &role, &rec.OwnerRef, &rec.CreatedBy, &created, &expires, &rec.SecretHash); err != nil {
			return nil, fmt.Errorf("scan API token: %w", err)
		}
		rec.Role = controlplane.Role(role)
		rec.CreatedAt = time.Unix(0, created).UTC()
		rec.ExpiresAt = time.Unix(0, expires).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list API tokens: %w", err)
	}
	return out, nil
}

// DeleteAPIToken removes a token. A missing id is not an error (revoke is
// idempotent); removed reports whether a row went.
func (s *Store) DeleteAPIToken(ctx context.Context, id string) (removed bool, err error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete API token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("delete API token: %w", err)
	}
	return n > 0, nil
}

// DeleteAPITokensExpiredBefore removes every token that expired before
// cutoff and returns their ids, for the expiry sweep.
func (s *Store) DeleteAPITokensExpiredBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sweep API tokens: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM api_tokens WHERE expires_at < ? ORDER BY id`, cutoff.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("sweep API tokens: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("sweep API tokens: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sweep API tokens: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE expires_at < ?`, cutoff.UnixNano()); err != nil {
		return nil, fmt.Errorf("sweep API tokens: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sweep API tokens: %w", err)
	}
	return ids, nil
}
