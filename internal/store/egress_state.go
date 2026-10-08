package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// EgressState is a sandbox's egress-gateway state (sandbox_egress).
type EgressState struct {
	SandboxID  string
	HoldReason string
	HoldSince  time.Time
	// InspectCA: the sandbox was created trusting the node's CA (P3-1).
	InspectCA bool
	// Withheld are the env keys the sandbox holds placeholders for (P3-2).
	Withheld []string
	// Installed is the host enforcement that may be in place for the
	// sandbox; nil when it is what the stored policy installs.
	Installed *InstalledEgress
}

// InstalledEgress is the host enforcement that may be in place for a
// container sandbox: whether a gateway attachment may exist, and which CIDR
// rule sets may be installed. After a transition that didn't finish it is a
// superset (the old enforcement and the new), so the next transition tears
// down everything a partial apply left behind.
type InstalledEgress struct {
	Gateway bool        `json:"gateway,omitempty"`
	CIDR    []CIDRRules `json:"cidr,omitempty"`
}

// CIDRRules is one CIDR rule set, as ApplyEgressPolicy installs it.
type CIDRRules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// SetInstalledEgress records the host enforcement that may now be in place
// for a sandbox.
func (s *Store) SetInstalledEgress(ctx context.Context, sandboxID string, inst InstalledEgress, now time.Time) error {
	raw, err := json.Marshal(inst)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sandbox_egress (sandbox_id, installed_egress_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			installed_egress_json = excluded.installed_egress_json,
			updated_at = excluded.updated_at
	`, sandboxID, string(raw), now.UTC())
	if err != nil {
		return fmt.Errorf("set installed egress: %w", err)
	}
	return nil
}

// SetEgressHoldRanked records a hold unless the sandbox already has a
// stronger one: rank maps each reason to its strength (unknown is 0), and a
// reason is only replaced by one at least as strong, in one statement, so
// a weaker hold racing a stronger one can't overwrite it.
func (s *Store) SetEgressHoldRanked(ctx context.Context, sandboxID, reason string, rank map[string]int, now time.Time) error {
	if reason == "" {
		return errors.New("egress hold needs a reason")
	}
	var cases strings.Builder
	cases.WriteString("CASE sandbox_egress.hold_reason")
	args := []any{}
	for r, n := range rank {
		cases.WriteString(" WHEN ? THEN ?")
		args = append(args, r, n)
	}
	cases.WriteString(" ELSE 0 END")
	query := `
		INSERT INTO sandbox_egress (sandbox_id, hold_reason, hold_since, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			hold_reason = CASE WHEN (` + cases.String() + `) > ? THEN sandbox_egress.hold_reason ELSE excluded.hold_reason END,
			hold_since = COALESCE(sandbox_egress.hold_since, excluded.hold_since),
			updated_at = excluded.updated_at`
	all := append([]any{sandboxID, reason, now.UTC(), now.UTC()}, args...)
	all = append(all, rank[reason])
	if _, err := s.db.ExecContext(ctx, query, all...); err != nil {
		return fmt.Errorf("set egress hold: %w", err)
	}
	return nil
}

// SetEgressHold records the fail-closed hold and its reason (CEO D16). It is
// idempotent and keeps the original hold_since on a repeated hold.
func (s *Store) SetEgressHold(ctx context.Context, sandboxID, reason string, now time.Time) error {
	if reason == "" {
		return errors.New("egress hold needs a reason")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_egress (sandbox_id, hold_reason, hold_since, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			hold_reason = excluded.hold_reason,
			hold_since = COALESCE(sandbox_egress.hold_since, excluded.hold_since),
			updated_at = excluded.updated_at
	`, sandboxID, reason, now.UTC(), now.UTC())
	if err != nil {
		return fmt.Errorf("set egress hold: %w", err)
	}
	return nil
}

// ClearEgressHoldIf lifts a hold only if its reason is still reason, the
// one the caller resolved, and reports whether it did: a different hold
// written since is left in place.
func (s *Store) ClearEgressHoldIf(ctx context.Context, sandboxID, reason string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_egress SET hold_reason = '', hold_since = NULL, updated_at = ?
		WHERE sandbox_id = ? AND hold_reason = ? AND hold_reason != ''
	`, now.UTC(), sandboxID, reason)
	if err != nil {
		return false, fmt.Errorf("clear egress hold: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("clear egress hold: %w", err)
	}
	return n > 0, nil
}

// ClearEgressHold lifts the hold whatever its reason.
func (s *Store) ClearEgressHold(ctx context.Context, sandboxID string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_egress SET hold_reason = '', hold_since = NULL, updated_at = ?
		WHERE sandbox_id = ?
	`, now.UTC(), sandboxID)
	if err != nil {
		return fmt.Errorf("clear egress hold: %w", err)
	}
	return nil
}

// GetEgressState returns a sandbox's egress state; a sandbox with no row has
// the zero state (no hold).
func (s *Store) GetEgressState(ctx context.Context, sandboxID string) (EgressState, error) {
	st := EgressState{SandboxID: sandboxID}
	var since sql.NullTime
	var withheld, installed string
	err := s.db.QueryRowContext(ctx, `
		SELECT hold_reason, hold_since, inspect_ca, withheld_env_json, installed_egress_json FROM sandbox_egress WHERE sandbox_id = ?
	`, sandboxID).Scan(&st.HoldReason, &since, &st.InspectCA, &withheld, &installed)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("get egress state: %w", err)
	}
	if since.Valid {
		st.HoldSince = since.Time
	}
	if withheld != "" {
		if err := json.Unmarshal([]byte(withheld), &st.Withheld); err != nil {
			return st, fmt.Errorf("get egress state: withheld env keys: %w", err)
		}
	}
	if installed != "" {
		st.Installed = &InstalledEgress{}
		if err := json.Unmarshal([]byte(installed), st.Installed); err != nil {
			return st, fmt.Errorf("get egress state: installed egress: %w", err)
		}
	}
	return st, nil
}

// ListEgressHolds returns every held sandbox and its reason (reconcile
// retries, the held-sandboxes gauge). The partial index keeps it to held rows.
func (s *Store) ListEgressHolds(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sandbox_id, hold_reason FROM sandbox_egress WHERE hold_reason != ''`)
	if err != nil {
		return nil, fmt.Errorf("list egress holds: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, reason string
		if err := rows.Scan(&id, &reason); err != nil {
			return nil, fmt.Errorf("scan egress hold: %w", err)
		}
		out[id] = reason
	}
	return out, rows.Err()
}
