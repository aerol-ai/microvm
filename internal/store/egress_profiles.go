package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrEgressProfileNotFound means no profile of that name exists for the owner.
var ErrEgressProfileNotFound = errors.New("egress profile not found")

// ErrEgressProfileInUse means a live sandbox still references the profile, so
// it can't be deleted (409).
var ErrEgressProfileInUse = errors.New("egress profile is referenced by sandboxes")

// ProfileRef is one sandbox's reference to a profile, with the generation of
// it that is live on the sandbox (0 until the first apply).
type ProfileRef struct {
	SandboxID         string
	OwnerRef          string
	Profile           string
	AppliedGeneration int64
}

// PutEgressProfile creates or replaces an owner's profile. Generation goes up
// by one only when the entries or description change, so the same body twice
// is a no-op; changed reports whether it did.
func (s *Store) PutEgressProfile(ctx context.Context, owner, name string, allowOut []string, description string, now time.Time) (p models.EgressProfile, changed bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, false, fmt.Errorf("put egress profile: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	old, err := getEgressProfile(ctx, tx, owner, name)
	switch {
	case errors.Is(err, ErrEgressProfileNotFound):
		p = models.EgressProfile{Name: name, Generation: 1, CreatedAt: now.UTC()}
	case err != nil:
		return p, false, err
	case slices.Equal(old.AllowOut, allowOut) && old.Description == description:
		return old, false, nil
	default:
		p = old
		p.Generation++
	}
	p.AllowOut, p.Description, p.UpdatedAt = append([]string{}, allowOut...), description, now.UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO egress_profiles (owner_ref, name, allow_out_json, description, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner_ref, name) DO UPDATE SET
			allow_out_json = excluded.allow_out_json,
			description = excluded.description,
			generation = excluded.generation,
			updated_at = excluded.updated_at
	`, owner, name, mustMarshalStringSlice(p.AllowOut), p.Description, p.Generation, p.CreatedAt, p.UpdatedAt); err != nil {
		return models.EgressProfile{}, false, fmt.Errorf("put egress profile: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.EgressProfile{}, false, fmt.Errorf("put egress profile: %w", err)
	}
	return p, true, nil
}

// GetEgressProfile returns an owner's profile.
func (s *Store) GetEgressProfile(ctx context.Context, owner, name string) (models.EgressProfile, error) {
	return getEgressProfile(ctx, s.db, owner, name)
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getEgressProfile(ctx context.Context, q queryRower, owner, name string) (models.EgressProfile, error) {
	p := models.EgressProfile{Name: name}
	var allow string
	err := q.QueryRowContext(ctx, `
		SELECT allow_out_json, description, generation, created_at, updated_at
		FROM egress_profiles WHERE owner_ref = ? AND name = ?
	`, owner, name).Scan(&allow, &p.Description, &p.Generation, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrEgressProfileNotFound
	}
	if err != nil {
		return p, fmt.Errorf("get egress profile: %w", err)
	}
	if err := json.Unmarshal([]byte(allow), &p.AllowOut); err != nil {
		return p, fmt.Errorf("decode egress profile %s: %w", name, err)
	}
	return p, nil
}

// ListEgressProfiles returns up to limit of an owner's profiles by name,
// starting after the name in after.
func (s *Store) ListEgressProfiles(ctx context.Context, owner, after string, limit int) ([]models.EgressProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, allow_out_json, description, generation, created_at, updated_at
		FROM egress_profiles WHERE owner_ref = ? AND name > ?
		ORDER BY name LIMIT ?
	`, owner, after, limit)
	if err != nil {
		return nil, fmt.Errorf("list egress profiles: %w", err)
	}
	defer rows.Close()
	out := []models.EgressProfile{}
	for rows.Next() {
		var p models.EgressProfile
		var allow string
		if err := rows.Scan(&p.Name, &allow, &p.Description, &p.Generation, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan egress profile: %w", err)
		}
		if err := json.Unmarshal([]byte(allow), &p.AllowOut); err != nil {
			return nil, fmt.Errorf("decode egress profile %s: %w", p.Name, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteEgressProfile removes an owner's profile unless a live sandbox still
// references it. Deleting a profile that is already gone succeeds, so a
// retried DELETE converges.
func (s *Store) DeleteEgressProfile(ctx context.Context, owner, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete egress profile: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var inUse int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sandbox_egress_profiles r JOIN sandboxes s ON s.id = r.sandbox_id
		WHERE r.owner_ref = ? AND r.profile = ? AND s.status != ?
	`, owner, name, string(models.SandboxStatusDestroyed)).Scan(&inUse); err != nil {
		return fmt.Errorf("delete egress profile: %w", err)
	}
	if inUse > 0 {
		return fmt.Errorf("%w: %d sandbox(es) reference %s", ErrEgressProfileInUse, inUse, name)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM egress_profiles WHERE owner_ref = ? AND name = ?`, owner, name); err != nil {
		return fmt.Errorf("delete egress profile: %w", err)
	}
	return tx.Commit()
}

// ProfileReferences returns every live sandbox's profile references, for the
// re-apply pass and its applied generations. It reads the index, not the
// sandboxes it joins only to drop destroyed rows.
func (s *Store) ProfileReferences(ctx context.Context) ([]ProfileRef, error) {
	return s.profileRefs(ctx, `
		SELECT r.sandbox_id, r.owner_ref, r.profile, r.applied_generation
		FROM sandbox_egress_profiles r JOIN sandboxes s ON s.id = r.sandbox_id
		WHERE s.status != ? ORDER BY r.sandbox_id, r.position
	`, string(models.SandboxStatusDestroyed))
}

// SandboxesReferencingProfile returns the live sandboxes that reference an
// owner's profile, by index probe.
func (s *Store) SandboxesReferencingProfile(ctx context.Context, owner, name string) ([]ProfileRef, error) {
	return s.profileRefs(ctx, `
		SELECT r.sandbox_id, r.owner_ref, r.profile, r.applied_generation
		FROM sandbox_egress_profiles r JOIN sandboxes s ON s.id = r.sandbox_id
		WHERE r.owner_ref = ? AND r.profile = ? AND s.status != ? ORDER BY r.sandbox_id
	`, owner, name, string(models.SandboxStatusDestroyed))
}

func (s *Store) profileRefs(ctx context.Context, query string, args ...any) ([]ProfileRef, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list profile references: %w", err)
	}
	defer rows.Close()
	var out []ProfileRef
	for rows.Next() {
		var r ProfileRef
		if err := rows.Scan(&r.SandboxID, &r.OwnerRef, &r.Profile, &r.AppliedGeneration); err != nil {
			return nil, fmt.Errorf("scan profile reference: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SandboxEgressProfiles is a sandbox's profile references in order, with the
// generation of each that is live, and its inline allow list. Inline is nil
// for a sandbox with no profiles: its row's list is the inline one.
type SandboxEgressProfiles struct {
	Refs   []models.EgressProfileRef
	Inline []string
}

// GetSandboxEgressProfiles returns a sandbox's profile state.
func (s *Store) GetSandboxEgressProfiles(ctx context.Context, sandboxID string) (SandboxEgressProfiles, error) {
	out, err := s.GetSandboxesEgressProfiles(ctx, []string{sandboxID})
	return out[sandboxID], err
}

// GetSandboxesEgressProfiles returns the profile state of several sandboxes
// in two queries, for list pages. Sandboxes with no profiles are absent.
func (s *Store) GetSandboxesEgressProfiles(ctx context.Context, ids []string) (map[string]SandboxEgressProfiles, error) {
	out := map[string]SandboxEgressProfiles{}
	if len(ids) == 0 {
		return out, nil
	}
	placeholders, args := inClause(ids)
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, profile, applied_generation FROM sandbox_egress_profiles
		WHERE sandbox_id IN (`+placeholders+`) ORDER BY sandbox_id, position
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("get sandbox egress profiles: %w", err)
	}
	for rows.Next() {
		var id string
		var ref models.EgressProfileRef
		if err := rows.Scan(&id, &ref.Name, &ref.Generation); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan sandbox egress profile: %w", err)
		}
		st := out[id]
		st.Refs = append(st.Refs, ref)
		out[id] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `
		SELECT sandbox_id, inline_allow_json FROM sandbox_egress
		WHERE inline_allow_json != '' AND sandbox_id IN (`+placeholders+`)
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("get sandbox inline allow list: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, inline string
		if err := rows.Scan(&id, &inline); err != nil {
			return nil, fmt.Errorf("scan sandbox inline allow list: %w", err)
		}
		st, ok := out[id]
		if !ok {
			continue
		}
		if err := json.Unmarshal([]byte(inline), &st.Inline); err != nil {
			return nil, fmt.Errorf("decode inline allow list of %s: %w", id, err)
		}
		if st.Inline == nil {
			st.Inline = []string{}
		}
		out[id] = st
	}
	return out, rows.Err()
}

func inClause(ids []string) (string, []any) {
	args := make([]any, len(ids))
	b := make([]byte, 0, 2*len(ids))
	for i, id := range ids {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
		args[i] = id
	}
	return string(b), args
}

// NetworkPolicyWrite is a sandbox's whole egress policy as stored. AllowOut
// is the effective list (inline plus every profile's), which is what
// enforcement reads from the sandboxes row; Inline and Profiles are kept
// beside it for GET and policy replays.
type NetworkPolicyWrite struct {
	BlockAll bool
	AllowOut []string
	DenyOut  []string
	Inline   []string
	Profiles []string
	OwnerRef string
	// Mode is the egress mode, "learn" or "" (enforce).
	Mode string
}

// WriteNetworkPolicy stores a sandbox's policy, its profile references and
// its inline list in one transaction, so the effective list on the row and
// the references that explain it never disagree. A reference that stays
// keeps its applied generation.
func (s *Store) WriteNetworkPolicy(ctx context.Context, id string, p NetworkPolicyWrite) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("write network policy: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		UPDATE sandboxes SET network_block_all = ?, network_allow_out_json = ?, network_deny_out_json = ?, updated_at = ?
		WHERE id = ?
	`, p.BlockAll, mustMarshalStringSlice(p.AllowOut), mustMarshalStringSlice(p.DenyOut), now, id)
	if err != nil {
		return fmt.Errorf("write network policy: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("write network policy: %w", err)
	} else if affected == 0 {
		return ErrNotFound
	}
	if err := writeEgressProfilesTx(ctx, tx, id, p, now); err != nil {
		return err
	}
	return tx.Commit()
}

// SetSandboxEgressProfiles records a new sandbox's profile references and
// inline list; the create path calls it right after the row is written.
func (s *Store) SetSandboxEgressProfiles(ctx context.Context, id string, p NetworkPolicyWrite) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set sandbox egress profiles: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := writeEgressProfilesTx(ctx, tx, id, p, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func writeEgressProfilesTx(ctx context.Context, tx *sql.Tx, id string, p NetworkPolicyWrite, now time.Time) error {
	applied := map[string]int64{}
	rows, err := tx.QueryContext(ctx, `SELECT profile, applied_generation FROM sandbox_egress_profiles WHERE sandbox_id = ?`, id)
	if err != nil {
		return fmt.Errorf("read egress profile references: %w", err)
	}
	for rows.Next() {
		var name string
		var gen int64
		if err := rows.Scan(&name, &gen); err != nil {
			rows.Close()
			return fmt.Errorf("read egress profile references: %w", err)
		}
		applied[name] = gen
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sandbox_egress_profiles WHERE sandbox_id = ?`, id); err != nil {
		return fmt.Errorf("write egress profile references: %w", err)
	}
	for i, name := range p.Profiles {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sandbox_egress_profiles (sandbox_id, owner_ref, profile, position, applied_generation)
			VALUES (?, ?, ?, ?, ?)
		`, id, p.OwnerRef, name, i, applied[name]); err != nil {
			return fmt.Errorf("write egress profile references: %w", err)
		}
	}
	inline := ""
	if len(p.Profiles) > 0 {
		inline = mustMarshalStringSlice(p.Inline)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sandbox_egress (sandbox_id, inline_allow_json, egress_mode, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET inline_allow_json = excluded.inline_allow_json,
			egress_mode = excluded.egress_mode, updated_at = excluded.updated_at
	`, id, inline, p.Mode, now); err != nil {
		return fmt.Errorf("write inline allow list: %w", err)
	}
	return nil
}

// SetEgressProfilesApplied records which generation of each referenced
// profile is live on a sandbox, after a successful apply.
func (s *Store) SetEgressProfilesApplied(ctx context.Context, id string, applied []models.EgressProfileRef) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set applied egress profiles: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, ref := range applied {
		if _, err := tx.ExecContext(ctx, `
			UPDATE sandbox_egress_profiles SET applied_generation = ? WHERE sandbox_id = ? AND profile = ?
		`, ref.Generation, id, ref.Name); err != nil {
			return fmt.Errorf("set applied egress profiles: %w", err)
		}
	}
	return tx.Commit()
}

// attachEgressModes sets NetworkEgressMode on the sandboxes that have one.
// The mode lives in sandbox_egress; loading it with every sandbox read keeps
// it on the model every path sees, like exposed ports. Only learn-mode
// sandboxes have a non-empty mode, so the query reads a handful of rows.
func (s *Store) attachEgressModes(ctx context.Context, byID map[string]*models.Sandbox) error {
	if len(byID) == 0 {
		return nil
	}
	query := `SELECT sandbox_id, egress_mode FROM sandbox_egress WHERE egress_mode != ''`
	var args []any
	if len(byID) == 1 {
		for id := range byID {
			query += ` AND sandbox_id = ?`
			args = append(args, id)
		}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("load egress modes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, mode string
		if err := rows.Scan(&id, &mode); err != nil {
			return fmt.Errorf("scan egress mode: %w", err)
		}
		if sb, ok := byID[id]; ok {
			sb.NetworkEgressMode = mode
		}
	}
	return rows.Err()
}
