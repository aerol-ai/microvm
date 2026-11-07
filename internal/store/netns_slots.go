package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// Container netns pool lifecycle states. Stored as TEXT; queries use literals.
const (
	NetnsSlotStateFree     = "free"
	NetnsSlotStateReserved = "reserved"
	NetnsSlotStateRealized = "realized"
	NetnsSlotStatePooled   = "pooled"
	NetnsSlotStateAdopted  = "adopted"
	// NetnsSlotStateReleasing holds a slot whose host teardown (CNI DEL, NAT
	// chain, netns delete) failed. The row has no owner, so no sandbox can find
	// or claim it, but it keeps netns_path + container_ip: they are the
	// identity the retry needs to delete exactly what CNI ADD created. Freeing
	// such a slot instead would hand a new sandbox a slot whose lease and
	// masquerade chain still exist (host-local then refuses the slot's next
	// ADD as a duplicate, and the leftover rules pile up).
	NetnsSlotStateReleasing = "releasing"
)

// ContainerNetnsSlot is one row of container_netns_slots.
type ContainerNetnsSlot struct {
	SlotID      string
	NetnsPath   string
	ContainerIP string
	SandboxID   string
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ErrNoFreeContainerNetnsSlot is returned when the netns pool is exhausted.
// It is a capacity refusal (errors.Is matches capacity.ErrCapacityExceeded),
// so the API answers 503 + Retry-After and placement can try another node,
// instead of the catch-all 400 a full node used to look like.
var ErrNoFreeContainerNetnsSlot error = capacity.NewSlotPoolExhausted("container netns pool")

// SeedContainerNetnsSlot inserts one free pool row. Idempotent on slot_id PK.
func (s *Store) SeedContainerNetnsSlot(ctx context.Context, slotID string, now time.Time) error {
	slotID = strings.TrimSpace(slotID)
	if slotID == "" {
		return errors.New("seed container netns slot: slot_id is required")
	}
	now = now.UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO container_netns_slots
			(slot_id, state, created_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(slot_id) DO NOTHING
	`, slotID, NetnsSlotStateFree, now, now)
	if err != nil {
		return fmt.Errorf("seed container netns slot: %w", err)
	}
	return nil
}

// ReserveContainerNetnsSlot claims a free slot for sandboxID. Idempotent when
// sandboxID already owns a slot. Returns ErrNoFreeContainerNetnsSlot only
// when no free slot is left: never because another create was claiming at
// the same moment (see claimContainerNetnsSlot).
func (s *Store) ReserveContainerNetnsSlot(ctx context.Context, sandboxID string, now time.Time) (*ContainerNetnsSlot, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("reserve container netns slot: sandbox_id is required")
	}
	return s.claimContainerNetnsSlotForSandbox(ctx, sandboxID, NetnsSlotStateFree, NetnsSlotStateReserved,
		ErrNoFreeContainerNetnsSlot, now, "reserve container netns slot")
}

// ErrNoPooledContainerNetnsSlot means no prewarmed slot is available for claim.
var ErrNoPooledContainerNetnsSlot = errors.New("container netns pool: no pooled slot")

// BeginPrewarmContainerNetnsSlot reserves a free slot under its own slot_id so
// the refill ticker can CNI-realize it without a sandbox owner yet.
func (s *Store) BeginPrewarmContainerNetnsSlot(ctx context.Context, now time.Time) (*ContainerNetnsSlot, error) {
	slot, err := s.claimContainerNetnsSlot(ctx, "", NetnsSlotStateFree, NetnsSlotStateReserved, now.UTC())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoFreeContainerNetnsSlot
	}
	if err != nil {
		return nil, fmt.Errorf("begin prewarm: %w", err)
	}
	return slot, nil
}

// FinishPrewarmContainerNetnsSlot moves a refill-reserved slot into the pooled
// warm queue (network prepaid, no sandbox owner).
func (s *Store) FinishPrewarmContainerNetnsSlot(ctx context.Context, slotID, netnsPath, containerIP string, now time.Time) error {
	slotID = strings.TrimSpace(slotID)
	netnsPath = strings.TrimSpace(netnsPath)
	containerIP = strings.TrimSpace(containerIP)
	if slotID == "" || netnsPath == "" || containerIP == "" {
		return errors.New("finish prewarm: slot_id, netns_path, container_ip are required")
	}
	now = now.UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = NULL, netns_path = ?, container_ip = ?, state = ?, updated_at = ?
		WHERE slot_id = ? AND sandbox_id = ? AND state = ?
	`, netnsPath, containerIP, NetnsSlotStatePooled, now, slotID, slotID, NetnsSlotStateReserved)
	if err != nil {
		return fmt.Errorf("finish prewarm: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("finish prewarm (affected): %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimPooledContainerNetnsSlot hands a prewarmed slot to sandboxID. Idempotent
// when sandboxID already owns a slot. Returns ErrNoPooledContainerNetnsSlot on miss.
func (s *Store) ClaimPooledContainerNetnsSlot(ctx context.Context, sandboxID string, now time.Time) (*ContainerNetnsSlot, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("claim pooled netns slot: sandbox_id is required")
	}
	return s.claimContainerNetnsSlotForSandbox(ctx, sandboxID, NetnsSlotStatePooled, NetnsSlotStateAdopted,
		ErrNoPooledContainerNetnsSlot, now, "claim pooled netns slot")
}

// claimContainerNetnsSlotForSandbox claims the first unowned slot in
// fromState for sandboxID, or returns the slot sandboxID already owns.
// empty is returned when the sandbox owns none and no slot is in fromState.
func (s *Store) claimContainerNetnsSlotForSandbox(ctx context.Context, sandboxID, fromState, toState string, empty error, now time.Time, op string) (*ContainerNetnsSlot, error) {
	slot, err := s.claimContainerNetnsSlot(ctx, sandboxID, fromState, toState, now.UTC())
	if err == nil {
		return slot, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	// Nothing was claimed: either this sandbox already owns a slot (a retried
	// or duplicate create) or the pool is empty.
	existing, err := s.GetContainerNetnsSlotBySandbox(ctx, sandboxID)
	if err != nil || existing != nil {
		return existing, err
	}
	return nil, empty
}

// claimContainerNetnsSlot moves the first unowned slot in fromState to
// toState under owner (the slot's own id when owner is empty, for a prewarm),
// in ONE statement, and returns the row as written. It claims nothing, and
// returns sql.ErrNoRows, when no slot is in fromState or owner already owns
// a slot.
//
// It used to SELECT a candidate, then UPDATE it only if still free, and
// retry up to 8 times. The writer runs one statement at a time but hands
// the connection back between two statements, so concurrent callers read
// the same lowest free slot, one won, the rest retried, and with more than
// 8 callers some ran out of tries while free slots were left (32 concurrent
// reservations: 41 of 640 failed). Two calls for one sandbox could also both
// pass a separate "already own one?" check, and the second then failed on
// the unique index. A single UPDATE that picks its own target and checks
// ownership cannot lose either race: SQLite holds the write lock for the
// whole statement.
func (s *Store) claimContainerNetnsSlot(ctx context.Context, owner, fromState, toState string, now time.Time) (*ContainerNetnsSlot, error) {
	var ownerArg any // NULL for a prewarm: owned by its own slot_id
	if owner != "" {
		ownerArg = owner
	}
	row := s.db.QueryRowContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = COALESCE(?, slot_id), state = ?, updated_at = ?
		WHERE slot_id = (
			SELECT slot_id FROM container_netns_slots
			WHERE state = ? AND sandbox_id IS NULL
			ORDER BY slot_id ASC
			LIMIT 1
		)
		AND NOT EXISTS (SELECT 1 FROM container_netns_slots WHERE sandbox_id = ?)
		RETURNING slot_id, netns_path, container_ip, sandbox_id, state, created_at, updated_at
	`, ownerArg, toState, now, fromState, ownerArg)
	var slot ContainerNetnsSlot
	if err := scanContainerNetnsSlot(row, &slot); err != nil {
		return nil, err
	}
	return &slot, nil
}

// ListNonFreeContainerNetnsSlots returns rows not in the free state for reconcile.
func (s *Store) ListNonFreeContainerNetnsSlots(ctx context.Context) ([]ContainerNetnsSlot, error) {
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT slot_id, netns_path, container_ip, sandbox_id, state, created_at, updated_at
		FROM container_netns_slots
		WHERE state != ?
		ORDER BY slot_id ASC
	`, NetnsSlotStateFree)
	if err != nil {
		return nil, fmt.Errorf("list non-free netns slots: %w", err)
	}
	defer rows.Close()
	var out []ContainerNetnsSlot
	for rows.Next() {
		var slot ContainerNetnsSlot
		if err := scanContainerNetnsSlot(rows, &slot); err != nil {
			return nil, err
		}
		out = append(out, slot)
	}
	return out, rows.Err()
}

// ResetContainerNetnsSlotToFree clears a slot row back to the empty free state.
func (s *Store) ResetContainerNetnsSlotToFree(ctx context.Context, slotID string, now time.Time) error {
	slotID = strings.TrimSpace(slotID)
	if slotID == "" {
		return errors.New("reset netns slot: slot_id is required")
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = NULL, netns_path = '', container_ip = '', state = ?, updated_at = ?
		WHERE slot_id = ?
	`, NetnsSlotStateFree, now.UTC(), slotID)
	if err != nil {
		return fmt.Errorf("reset netns slot: %w", err)
	}
	return nil
}

// MarkContainerNetnsSlotReleasing parks a slot whose host teardown failed:
// owner cleared, state releasing, netns_path / container_ip set to the
// identity the teardown used so a retry deletes the same CNI state. owner is
// the sandbox_id the caller saw ("" for a row with no owner); the update only
// applies while the row still has that owner, so a stale caller can never
// park a slot that was meanwhile freed and handed to another sandbox.
// Returns ErrNotFound when the row no longer matches.
func (s *Store) MarkContainerNetnsSlotReleasing(ctx context.Context, slotID, owner, netnsPath, containerIP string, now time.Time) error {
	slotID = strings.TrimSpace(slotID)
	if slotID == "" {
		return errors.New("mark container netns releasing: slot_id is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = NULL, netns_path = ?, container_ip = ?, state = ?, updated_at = ?
		WHERE slot_id = ? AND COALESCE(sandbox_id, '') = ? AND state != ?
	`, strings.TrimSpace(netnsPath), strings.TrimSpace(containerIP), NetnsSlotStateReleasing, now.UTC(),
		slotID, strings.TrimSpace(owner), NetnsSlotStateFree)
	if err != nil {
		return fmt.Errorf("mark container netns releasing: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark container netns releasing (affected): %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// FreeReleasingContainerNetnsSlot returns a releasing slot to the free pool
// once its host teardown has finally succeeded. A no-op for any other state.
func (s *Store) FreeReleasingContainerNetnsSlot(ctx context.Context, slotID string, now time.Time) error {
	slotID = strings.TrimSpace(slotID)
	if slotID == "" {
		return errors.New("free releasing netns slot: slot_id is required")
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = NULL, netns_path = '', container_ip = '', state = ?, updated_at = ?
		WHERE slot_id = ? AND state = ?
	`, NetnsSlotStateFree, now.UTC(), slotID, NetnsSlotStateReleasing)
	if err != nil {
		return fmt.Errorf("free releasing netns slot: %w", err)
	}
	return nil
}

// MarkContainerNetnsSlotRealized records CNI ADD output for a reserved slot.
// Idempotent when already realized or adopted with the same paths.
func (s *Store) MarkContainerNetnsSlotRealized(ctx context.Context, sandboxID, netnsPath, containerIP string, now time.Time) (*ContainerNetnsSlot, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	netnsPath = strings.TrimSpace(netnsPath)
	containerIP = strings.TrimSpace(containerIP)
	if sandboxID == "" || netnsPath == "" || containerIP == "" {
		return nil, errors.New("mark container netns realized: sandbox_id, netns_path, container_ip are required")
	}
	slot, err := s.GetContainerNetnsSlotBySandbox(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, ErrNotFound
	}
	if slot.State == NetnsSlotStateRealized || slot.State == NetnsSlotStateAdopted {
		if slot.NetnsPath == netnsPath && slot.ContainerIP == containerIP {
			return slot, nil
		}
		return nil, fmt.Errorf("mark container netns realized: slot %s already %s with different network", slot.SlotID, slot.State)
	}
	if slot.State != NetnsSlotStateReserved {
		return nil, fmt.Errorf("mark container netns realized: slot %s in state %q", slot.SlotID, slot.State)
	}
	now = now.UTC()
	_, err = s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET netns_path = ?, container_ip = ?, state = ?, updated_at = ?
		WHERE sandbox_id = ? AND state = ?
	`, netnsPath, containerIP, NetnsSlotStateRealized, now, sandboxID, NetnsSlotStateReserved)
	if err != nil {
		return nil, fmt.Errorf("mark container netns realized: %w", err)
	}
	return s.GetContainerNetnsSlotBySandbox(ctx, sandboxID)
}

// AdoptContainerNetnsSlot transitions a realized slot to adopted after the
// container task is running. Idempotent when already adopted.
func (s *Store) AdoptContainerNetnsSlot(ctx context.Context, sandboxID string, now time.Time) (*ContainerNetnsSlot, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("adopt container netns slot: sandbox_id is required")
	}
	slot, err := s.GetContainerNetnsSlotBySandbox(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, ErrNotFound
	}
	if slot.State == NetnsSlotStateAdopted {
		return slot, nil
	}
	if slot.State != NetnsSlotStateRealized {
		return nil, fmt.Errorf("adopt container netns slot: slot %s in state %q", slot.SlotID, slot.State)
	}
	now = now.UTC()
	_, err = s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET state = ?, updated_at = ?
		WHERE sandbox_id = ? AND state = ?
	`, NetnsSlotStateAdopted, now, sandboxID, NetnsSlotStateRealized)
	if err != nil {
		return nil, fmt.Errorf("adopt container netns slot: %w", err)
	}
	return s.GetContainerNetnsSlotBySandbox(ctx, sandboxID)
}

// ReleaseContainerNetnsSlot returns a slot to the free pool. Idempotent.
func (s *Store) ReleaseContainerNetnsSlot(ctx context.Context, sandboxID string, now time.Time) error {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return errors.New("release container netns slot: sandbox_id is required")
	}
	now = now.UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = NULL, netns_path = '', container_ip = '', state = ?, updated_at = ?
		WHERE sandbox_id = ?
	`, NetnsSlotStateFree, now, sandboxID)
	if err != nil {
		return fmt.Errorf("release container netns slot: %w", err)
	}
	return nil
}

// ReassignContainerNetnsSandbox moves adopted slot ownership from one sandbox
// id to another (warm park → adopt). Idempotent when toSandboxID already owns.
func (s *Store) ReassignContainerNetnsSandbox(ctx context.Context, fromSandboxID, toSandboxID string, now time.Time) error {
	fromSandboxID = strings.TrimSpace(fromSandboxID)
	toSandboxID = strings.TrimSpace(toSandboxID)
	if fromSandboxID == "" || toSandboxID == "" {
		return errors.New("reassign container netns slot: from and to sandbox ids are required")
	}
	if fromSandboxID == toSandboxID {
		return nil
	}
	if existing, err := s.GetContainerNetnsSlotBySandbox(ctx, toSandboxID); err != nil {
		return err
	} else if existing != nil {
		return nil
	}
	now = now.UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE container_netns_slots
		SET sandbox_id = ?, updated_at = ?
		WHERE sandbox_id = ? AND state = ?
	`, toSandboxID, now, fromSandboxID, NetnsSlotStateAdopted)
	if err != nil {
		return fmt.Errorf("reassign container netns slot: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("reassign container netns slot (affected): %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetContainerNetnsSlotBySandbox returns the slot owned by sandboxID, or nil.
func (s *Store) GetContainerNetnsSlotBySandbox(ctx context.Context, sandboxID string) (*ContainerNetnsSlot, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("get container netns slot: sandbox_id is required")
	}
	var slot ContainerNetnsSlot
	row := s.rdb.QueryRowContext(ctx, `
		SELECT slot_id, netns_path, container_ip, sandbox_id, state, created_at, updated_at
		FROM container_netns_slots
		WHERE sandbox_id = ?
	`, sandboxID)
	if err := scanContainerNetnsSlot(row, &slot); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get container netns slot: %w", err)
	}
	return &slot, nil
}

// ListContainerNetnsSlotsByState returns all rows in the given state.
func (s *Store) ListContainerNetnsSlotsByState(ctx context.Context, state string) ([]ContainerNetnsSlot, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, errors.New("list container netns slots: state is required")
	}
	rows, err := s.rdb.QueryContext(ctx, `
		SELECT slot_id, netns_path, container_ip, sandbox_id, state, created_at, updated_at
		FROM container_netns_slots
		WHERE state = ?
		ORDER BY slot_id ASC
	`, state)
	if err != nil {
		return nil, fmt.Errorf("list container netns slots: %w", err)
	}
	defer rows.Close()
	var out []ContainerNetnsSlot
	for rows.Next() {
		var slot ContainerNetnsSlot
		if err := scanContainerNetnsSlot(rows, &slot); err != nil {
			return nil, err
		}
		out = append(out, slot)
	}
	return out, rows.Err()
}

// ContainerNetnsPoolStats reports pool occupancy.
type ContainerNetnsPoolStats struct {
	Total    int
	Free     int
	Reserved int
	Realized int
	Pooled   int
	Adopted  int
	// Releasing counts slots parked after a failed host teardown. A count that
	// stays above zero means CNI DEL keeps failing on this node.
	Releasing int
}

func (s *Store) GetContainerNetnsPoolStats(ctx context.Context) (ContainerNetnsPoolStats, error) {
	var stats ContainerNetnsPoolStats
	row := s.rdb.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN state = 'free' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN state = 'reserved' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN state = 'realized' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN state = 'pooled' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN state = 'adopted' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN state = 'releasing' THEN 1 ELSE 0 END), 0)
		FROM container_netns_slots
	`)
	if err := row.Scan(&stats.Total, &stats.Free, &stats.Reserved, &stats.Realized, &stats.Pooled, &stats.Adopted, &stats.Releasing); err != nil {
		return stats, fmt.Errorf("container netns pool stats: %w", err)
	}
	return stats, nil
}

func scanContainerNetnsSlot(scanner interface {
	Scan(dest ...any) error
}, slot *ContainerNetnsSlot) error {
	var sandboxID sql.NullString
	if err := scanner.Scan(
		&slot.SlotID,
		&slot.NetnsPath,
		&slot.ContainerIP,
		&sandboxID,
		&slot.State,
		&slot.CreatedAt,
		&slot.UpdatedAt,
	); err != nil {
		return err
	}
	if sandboxID.Valid {
		slot.SandboxID = sandboxID.String
	}
	return nil
}
