package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Cloud identity per sandbox (plans/sandbox-cloud-identity.md). Three tables,
// all single-node state: a cluster keeps the key set and the role allow
// lists in the Raft FSM instead, and only sandbox_identity (each sandbox's
// own identity, on its owner) lives here on every node.
var identitySchema = []string{
	// identity_keys is the signing key set as one row: the set is replaced
	// whole under a generation compare-and-swap, the same rule the FSM
	// applies, so a rotation and a server-key reseal racing on one node
	// cannot both land. keys_json holds each private key sealed under the
	// server key (cloudidentity.KeyRecord), never in the clear.
	`CREATE TABLE IF NOT EXISTS identity_keys (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		generation INTEGER NOT NULL,
		keys_json TEXT NOT NULL
	);`,
	// identity_roles is each owner's role-tag allow list (D1.5): which tags a
	// sandbox may claim in its token's subject, and the least caller role
	// that may create one with it.
	`CREATE TABLE IF NOT EXISTS identity_roles (
		owner_ref TEXT NOT NULL DEFAULT '',
		tag TEXT NOT NULL,
		min_role TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY (owner_ref, tag)
	);`,
	// sandbox_identity is a sandbox's identity and the state of the token in
	// it: the refresher picks rows whose token runs out within its window
	// by the expiry index, so a pass never scans sandboxes without one. Rows
	// go with their sandbox.
	`CREATE TABLE IF NOT EXISTS sandbox_identity (
		sandbox_id TEXT PRIMARY KEY REFERENCES sandboxes(id) ON DELETE CASCADE,
		owner_ref TEXT NOT NULL DEFAULT '',
		role_tag TEXT NOT NULL,
		audience TEXT NOT NULL,
		aws_role_arn TEXT NOT NULL DEFAULT '',
		azure_client_id TEXT NOT NULL DEFAULT '',
		azure_tenant_id TEXT NOT NULL DEFAULT '',
		token_expires_unix INTEGER NOT NULL DEFAULT 0,
		token_kid TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		updated_at DATETIME NOT NULL
	);`,
	`CREATE INDEX IF NOT EXISTS idx_sandbox_identity_expiry ON sandbox_identity(token_expires_unix);`,
}

var (
	// ErrIdentityKeysConflict is a key-set write whose expected generation
	// is no longer current: another writer got there first. Re-read and
	// decide again.
	ErrIdentityKeysConflict = errors.New("identity signing keys changed concurrently")
	// ErrIdentityRoleNotFound is a role tag not on the owner's allow list.
	ErrIdentityRoleNotFound = errors.New("identity role tag not found")
)

// ReadIdentityKeys returns the signing key set; generation 0 with no keys
// before the first key is made.
func (s *Store) ReadIdentityKeys(ctx context.Context) (cloudidentity.KeySet, error) {
	return readIdentityKeys(ctx, s.rdb)
}

func readIdentityKeys(ctx context.Context, q queryRower) (cloudidentity.KeySet, error) {
	var set cloudidentity.KeySet
	var raw string
	err := q.QueryRowContext(ctx, `SELECT generation, keys_json FROM identity_keys WHERE id = 1`).Scan(&set.Generation, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return cloudidentity.KeySet{}, nil
	}
	if err != nil {
		return set, fmt.Errorf("read identity keys: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &set.Keys); err != nil {
		return set, fmt.Errorf("decode identity keys: %w", err)
	}
	return set, nil
}

// WriteIdentityKeys replaces the key set if its generation is still
// expected, and returns the stored set (generation expected+1).
func (s *Store) WriteIdentityKeys(ctx context.Context, expected int64, keys []cloudidentity.KeyRecord) (cloudidentity.KeySet, error) {
	next := cloudidentity.KeySet{Generation: expected + 1, Keys: keys}
	if err := next.Validate(); err != nil {
		return cloudidentity.KeySet{}, err
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return cloudidentity.KeySet{}, fmt.Errorf("encode identity keys: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return cloudidentity.KeySet{}, fmt.Errorf("write identity keys: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	cur, err := readIdentityKeys(ctx, tx)
	if err != nil {
		return cloudidentity.KeySet{}, err
	}
	if cur.Generation != expected {
		return cloudidentity.KeySet{}, fmt.Errorf("%w: at generation %d, not %d", ErrIdentityKeysConflict, cur.Generation, expected)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO identity_keys (id, generation, keys_json) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET generation = excluded.generation, keys_json = excluded.keys_json
	`, next.Generation, string(raw)); err != nil {
		return cloudidentity.KeySet{}, fmt.Errorf("write identity keys: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return cloudidentity.KeySet{}, fmt.Errorf("write identity keys: %w", err)
	}
	return next.Clone(), nil
}

// PutIdentityRole puts a tag on an owner's allow list, or changes its
// minimum role. The same body twice is a no-op; changed reports whether it
// wrote.
func (s *Store) PutIdentityRole(ctx context.Context, owner, tag, minRole string, now time.Time) (models.IdentityRole, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.IdentityRole{}, false, fmt.Errorf("put identity role: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	old, err := getIdentityRole(ctx, tx, owner, tag)
	switch {
	case errors.Is(err, ErrIdentityRoleNotFound):
		old = models.IdentityRole{Tag: tag, CreatedAt: now.UTC()}
	case err != nil:
		return models.IdentityRole{}, false, err
	case old.MinRole == minRole:
		return old, false, nil
	}
	role := old
	role.MinRole, role.UpdatedAt = minRole, now.UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO identity_roles (owner_ref, tag, min_role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(owner_ref, tag) DO UPDATE SET min_role = excluded.min_role, updated_at = excluded.updated_at
	`, owner, tag, minRole, role.CreatedAt, role.UpdatedAt); err != nil {
		return models.IdentityRole{}, false, fmt.Errorf("put identity role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.IdentityRole{}, false, fmt.Errorf("put identity role: %w", err)
	}
	return role, true, nil
}

// GetIdentityRole returns one tag of an owner's allow list.
func (s *Store) GetIdentityRole(ctx context.Context, owner, tag string) (models.IdentityRole, error) {
	return getIdentityRole(ctx, s.rdb, owner, tag)
}

func getIdentityRole(ctx context.Context, q queryRower, owner, tag string) (models.IdentityRole, error) {
	role := models.IdentityRole{Tag: tag}
	err := q.QueryRowContext(ctx, `
		SELECT min_role, created_at, updated_at FROM identity_roles WHERE owner_ref = ? AND tag = ?
	`, owner, tag).Scan(&role.MinRole, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return role, ErrIdentityRoleNotFound
	}
	if err != nil {
		return role, fmt.Errorf("get identity role: %w", err)
	}
	return role, nil
}

// ListIdentityRoles returns up to limit of an owner's tags, by tag, after
// the tag in after.
func (s *Store) ListIdentityRoles(ctx context.Context, owner, after string, limit int) ([]models.IdentityRole, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT tag, min_role, created_at, updated_at FROM identity_roles
		WHERE owner_ref = ? AND tag > ? ORDER BY tag LIMIT ?
	`, owner, after, limit)
	if err != nil {
		return nil, fmt.Errorf("list identity roles: %w", err)
	}
	defer rows.Close()
	out := []models.IdentityRole{}
	for rows.Next() {
		var r models.IdentityRole
		if err := rows.Scan(&r.Tag, &r.MinRole, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan identity role: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteIdentityRole takes a tag off an owner's allow list. A tag already
// gone succeeds, so a retried DELETE converges. Sandboxes created with it
// keep running but get no new token (the refresher checks the list).
func (s *Store) DeleteIdentityRole(ctx context.Context, owner, tag string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM identity_roles WHERE owner_ref = ? AND tag = ?`, owner, tag); err != nil {
		return fmt.Errorf("delete identity role: %w", err)
	}
	return nil
}

// SandboxIdentity is a sandbox's identity row: what its tokens say and the
// state of the token now in it.
type SandboxIdentity struct {
	SandboxID     string
	OwnerRef      string
	RoleTag       string
	Audience      string
	AWSRoleARN    string
	AzureClientID string
	AzureTenantID string
	// TokenExpiresUnix is the exp of the last token pushed; 0 before the
	// first push.
	TokenExpiresUnix int64
	TokenKeyID       string
	LastError        string
}

// PutSandboxIdentity records a new sandbox's identity, or replaces it (a
// recreate with the same id), clearing the token state.
func (s *Store) PutSandboxIdentity(ctx context.Context, row SandboxIdentity) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_identity (sandbox_id, owner_ref, role_tag, audience, aws_role_arn, azure_client_id, azure_tenant_id,
			token_expires_unix, token_kid, last_error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', '', ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET owner_ref = excluded.owner_ref, role_tag = excluded.role_tag,
			audience = excluded.audience, aws_role_arn = excluded.aws_role_arn, azure_client_id = excluded.azure_client_id,
			azure_tenant_id = excluded.azure_tenant_id, token_expires_unix = 0, token_kid = '', last_error = '',
			updated_at = excluded.updated_at
	`, row.SandboxID, row.OwnerRef, row.RoleTag, row.Audience, row.AWSRoleARN, row.AzureClientID, row.AzureTenantID,
		time.Now().UTC()); err != nil {
		return fmt.Errorf("put sandbox identity: %w", err)
	}
	return nil
}

// GetSandboxIdentity returns a sandbox's identity row.
func (s *Store) GetSandboxIdentity(ctx context.Context, id string) (SandboxIdentity, error) {
	rows, err := s.sandboxIdentities(ctx, `WHERE sandbox_id = ?`, id)
	if err != nil {
		return SandboxIdentity{}, err
	}
	if len(rows) == 0 {
		return SandboxIdentity{}, ErrNotFound
	}
	return rows[0], nil
}

// IdentityDueCursor is where a page of SandboxIdentitiesDue left off: the
// last row's expiry and id. The zero cursor starts at the beginning.
type IdentityDueCursor struct {
	Started   bool
	ExpiresAt int64
	SandboxID string
}

// Next is the cursor after the last row of page.
func (c IdentityDueCursor) Next(page []SandboxIdentity) IdentityDueCursor {
	if len(page) == 0 {
		return c
	}
	last := page[len(page)-1]
	return IdentityDueCursor{Started: true, ExpiresAt: last.TokenExpiresUnix, SandboxID: last.SandboxID}
}

// SandboxIdentitiesDue returns up to limit running sandboxes whose token
// expires before cutoff (or that have none yet), soonest first, after the
// cursor: the refresher's work list. It walks the expiry index, then joins
// each row's sandbox for its status.
func (s *Store) SandboxIdentitiesDue(ctx context.Context, cutoff time.Time, after IdentityDueCursor, limit int) ([]SandboxIdentity, error) {
	expires, id := int64(-1), ""
	if after.Started {
		expires, id = after.ExpiresAt, after.SandboxID
	}
	return s.sandboxIdentities(ctx, `
		JOIN sandboxes s ON s.id = i.sandbox_id
		WHERE i.token_expires_unix < ? AND s.status = ?
			AND (i.token_expires_unix > ? OR (i.token_expires_unix = ? AND i.sandbox_id > ?))
		ORDER BY i.token_expires_unix, i.sandbox_id LIMIT ?
	`, cutoff.Unix(), string(models.SandboxStatusStarted), expires, expires, id, limit)
}

func (s *Store) sandboxIdentities(ctx context.Context, where string, args ...any) ([]SandboxIdentity, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT i.sandbox_id, i.owner_ref, i.role_tag, i.audience, i.aws_role_arn, i.azure_client_id, i.azure_tenant_id,
			i.token_expires_unix, i.token_kid, i.last_error
		FROM sandbox_identity i `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list sandbox identities: %w", err)
	}
	defer rows.Close()
	var out []SandboxIdentity
	for rows.Next() {
		var r SandboxIdentity
		if err := rows.Scan(&r.SandboxID, &r.OwnerRef, &r.RoleTag, &r.Audience, &r.AWSRoleARN, &r.AzureClientID,
			&r.AzureTenantID, &r.TokenExpiresUnix, &r.TokenKeyID, &r.LastError); err != nil {
			return nil, fmt.Errorf("scan sandbox identity: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordIdentityTokenPushed notes the token now in the sandbox.
func (s *Store) RecordIdentityTokenPushed(ctx context.Context, id, kid string, expires time.Time) error {
	return s.updateSandboxIdentity(ctx, `token_expires_unix = ?, token_kid = ?, last_error = ''`, id, expires.Unix(), kid)
}

// RecordIdentityTokenFailed notes why a push failed; the token state is
// left as it was, so the next pass still finds the row due.
func (s *Store) RecordIdentityTokenFailed(ctx context.Context, id, reason string) error {
	if len(reason) > 512 {
		reason = reason[:512]
	}
	return s.updateSandboxIdentity(ctx, `last_error = ?`, id, reason)
}

func (s *Store) updateSandboxIdentity(ctx context.Context, set, id string, args ...any) error {
	args = append(args, time.Now().UTC(), id)
	result, err := s.db.ExecContext(ctx, `UPDATE sandbox_identity SET `+set+`, updated_at = ? WHERE sandbox_id = ?`, args...)
	if err != nil {
		return fmt.Errorf("update sandbox identity: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// attachSandboxSideState loads the side tables every sandbox read carries:
// egress mode and rules, and the identity view.
func (s *Store) attachSandboxSideState(ctx context.Context, byID map[string]*models.Sandbox) error {
	if err := s.attachEgressModes(ctx, byID); err != nil {
		return err
	}
	return s.attachIdentities(ctx, byID)
}

// identityAttachInLimit is the most ids one read names in an IN list; a
// bigger page reads every identity row instead (only sandboxes with an
// identity have one).
const identityAttachInLimit = 500

func (s *Store) attachIdentities(ctx context.Context, byID map[string]*models.Sandbox) error {
	if len(byID) == 0 {
		return nil
	}
	where, args := "", []any(nil)
	if len(byID) <= identityAttachInLimit {
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		var placeholders string
		placeholders, args = inClause(ids)
		where = `WHERE i.sandbox_id IN (` + placeholders + `)`
	}
	rows, err := s.sandboxIdentities(ctx, where, args...)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if sb, ok := byID[r.SandboxID]; ok {
			sb.Identity = r.View()
		}
	}
	return nil
}

// View is the row as the API shows it.
func (r SandboxIdentity) View() *models.SandboxIdentity {
	v := &models.SandboxIdentity{
		RoleTag:       r.RoleTag,
		Audience:      r.Audience,
		Subject:       cloudidentity.Subject(r.OwnerRef, r.RoleTag),
		AWSRoleARN:    r.AWSRoleARN,
		AzureClientID: r.AzureClientID,
		AzureTenantID: r.AzureTenantID,
		TokenFile:     cloudidentity.TokenFile,
		LastError:     strings.TrimSpace(r.LastError),
	}
	if r.TokenExpiresUnix > 0 {
		t := time.Unix(r.TokenExpiresUnix, 0).UTC()
		v.TokenExpiresAt = &t
	}
	return v
}
