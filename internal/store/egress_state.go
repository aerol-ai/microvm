package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
// rule sets may be installed. It is written before a policy transition
// changes the stored policy and cleared once the transition has applied, so
// a record exists exactly while a transition is unfinished (a failure, a
// crash): it is then a superset (the old enforcement and the new), the next
// transition tears down everything a partial apply left behind, and
// recovery finds it (ListInstalledEgress).
type InstalledEgress struct {
	Gateway bool        `json:"gateway,omitempty"`
	CIDR    []CIDRRules `json:"cidr,omitempty"`
}

// CIDRRules is one CIDR rule set, as ApplyEgressPolicy installs it.
type CIDRRules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// PendingEgressRuleClear is the host egress rules that may still be
// installed at one IP of one rule scope (an engine's firewall) with no
// sandbox's enforcement accounting for them: the CIDR rule sets, and
// whether a hold DROP may be there. SandboxID is the last sandbox that left
// them, for logs only.
type PendingEgressRuleClear struct {
	Scope     string
	IP        string
	SandboxID string
	Rules     []CIDRRules
	Hold      bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Empty reports whether nothing is left to clear.
func (p PendingEgressRuleClear) Empty() bool { return len(p.Rules) == 0 && !p.Hold }

// AddPendingEgressRuleClear records that p's rules may be left at its IP,
// merged into whatever is already pending there, and returns the merged
// entry. With clearInstalledFor set it also drops that sandbox's installed
// record in the same transaction: the record's rules now belong to the IP,
// and a crash between the two writes can't leave them in neither place.
func (s *Store) AddPendingEgressRuleClear(ctx context.Context, p PendingEgressRuleClear, clearInstalledFor string, now time.Time) (PendingEgressRuleClear, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, fmt.Errorf("add pending egress rule clear: %w", err)
	}
	defer tx.Rollback()
	merged := p
	merged.CreatedAt = now.UTC()
	cur, ok, err := getPendingEgressRuleClear(ctx, tx, p.Scope, p.IP)
	if err != nil {
		return p, err
	}
	if ok {
		merged.CreatedAt = cur.CreatedAt
		merged.Hold = cur.Hold || p.Hold
		merged.Rules = mergeCIDRRules(cur.Rules, p.Rules)
	}
	merged.UpdatedAt = now.UTC()
	if err := putPendingEgressRuleClear(ctx, tx, merged); err != nil {
		return p, err
	}
	if clearInstalledFor != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE sandbox_egress SET installed_egress_json = '', updated_at = ? WHERE sandbox_id = ?
		`, now.UTC(), clearInstalledFor); err != nil {
			return p, fmt.Errorf("add pending egress rule clear: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return p, fmt.Errorf("add pending egress rule clear: %w", err)
	}
	return merged, nil
}

// SetPendingEgressRuleClear records what is left at p's IP after a clear:
// p replaces the entry, and an empty p deletes it.
func (s *Store) SetPendingEgressRuleClear(ctx context.Context, p PendingEgressRuleClear, now time.Time) error {
	if p.Empty() {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM pending_egress_rule_clears WHERE scope = ? AND ip = ?`, p.Scope, p.IP); err != nil {
			return fmt.Errorf("delete pending egress rule clear: %w", err)
		}
		return nil
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now.UTC()
	}
	p.UpdatedAt = now.UTC()
	return putPendingEgressRuleClear(ctx, s.db, p)
}

// ListPendingEgressRuleClears returns every pending rule clear.
func (s *Store) ListPendingEgressRuleClears(ctx context.Context) ([]PendingEgressRuleClear, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT scope, ip, sandbox_id, rules_json, hold, created_at, updated_at FROM pending_egress_rule_clears ORDER BY scope, ip
	`)
	if err != nil {
		return nil, fmt.Errorf("list pending egress rule clears: %w", err)
	}
	defer rows.Close()
	var out []PendingEgressRuleClear
	for rows.Next() {
		p, err := scanPendingEgressRuleClear(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func getPendingEgressRuleClear(ctx context.Context, q queryRower, scope, ip string) (PendingEgressRuleClear, bool, error) {
	p, err := scanPendingEgressRuleClear(q.QueryRowContext(ctx, `
		SELECT scope, ip, sandbox_id, rules_json, hold, created_at, updated_at FROM pending_egress_rule_clears WHERE scope = ? AND ip = ?
	`, scope, ip))
	if errors.Is(err, sql.ErrNoRows) {
		return PendingEgressRuleClear{}, false, nil
	}
	return p, err == nil, err
}

func putPendingEgressRuleClear(ctx context.Context, e execer, p PendingEgressRuleClear) error {
	raw, err := json.Marshal(p.Rules)
	if err != nil {
		return err
	}
	if _, err := e.ExecContext(ctx, `
		INSERT INTO pending_egress_rule_clears (scope, ip, sandbox_id, rules_json, hold, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scope, ip) DO UPDATE SET
			sandbox_id = excluded.sandbox_id,
			rules_json = excluded.rules_json,
			hold = excluded.hold,
			updated_at = excluded.updated_at
	`, p.Scope, p.IP, p.SandboxID, string(raw), p.Hold, p.CreatedAt.UTC(), p.UpdatedAt.UTC()); err != nil {
		return fmt.Errorf("put pending egress rule clear: %w", err)
	}
	return nil
}

func scanPendingEgressRuleClear(row interface{ Scan(...any) error }) (PendingEgressRuleClear, error) {
	var p PendingEgressRuleClear
	var raw string
	if err := row.Scan(&p.Scope, &p.IP, &p.SandboxID, &raw, &p.Hold, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, err
		}
		return p, fmt.Errorf("scan pending egress rule clear: %w", err)
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &p.Rules); err != nil {
			return p, fmt.Errorf("decode pending egress rule clear: %w", err)
		}
	}
	return p, nil
}

// mergeCIDRRules is a ∪ b, a's order first, without duplicates.
func mergeCIDRRules(a, b []CIDRRules) []CIDRRules {
	out := slices.Clone(a)
	for _, r := range b {
		if !slices.ContainsFunc(out, func(o CIDRRules) bool {
			return slices.Equal(o.Allow, r.Allow) && slices.Equal(o.Deny, r.Deny)
		}) {
			out = append(out, r)
		}
	}
	return out
}

// ClearInstalledEgress drops a sandbox's installed record: its transition
// applied, and what is installed is what its stored policy installs.
func (s *Store) ClearInstalledEgress(ctx context.Context, sandboxID string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_egress SET installed_egress_json = '', updated_at = ? WHERE sandbox_id = ?
	`, now.UTC(), sandboxID); err != nil {
		return fmt.Errorf("clear installed egress: %w", err)
	}
	return nil
}

// ListInstalledEgress returns the sandboxes with an installed record: those
// whose last policy transition hasn't finished.
func (s *Store) ListInstalledEgress(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sandbox_id FROM sandbox_egress WHERE installed_egress_json != ''`)
	if err != nil {
		return nil, fmt.Errorf("list installed egress: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list installed egress: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
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
