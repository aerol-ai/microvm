package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

const sqliteBusyTimeoutMS = 5000

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite has one-writer semantics. Keep one connection in this process so
	// API handlers, event handling, and background sweeps queue in database/sql
	// instead of racing separate SQLite connections into "database is locked".
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	stmts := []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA foreign_keys = ON;`,
		`CREATE TABLE IF NOT EXISTS sandboxes (
			id TEXT PRIMARY KEY,
			image TEXT NOT NULL,
			status TEXT NOT NULL,
			public_url TEXT NOT NULL,
			container_id TEXT NOT NULL,
			container_ip TEXT NOT NULL,
			cpu REAL NOT NULL,
			memory_mb INTEGER NOT NULL,
			disk_gb INTEGER NOT NULL,
			os_user TEXT NOT NULL,
			env_json TEXT NOT NULL,
			network_block_all INTEGER NOT NULL DEFAULT 0,
			toolbox_enabled INTEGER NOT NULL DEFAULT 1,
			toolbox_token TEXT NOT NULL DEFAULT '',
			ssh_public_key TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			container_command_json TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			last_active_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS exposed_ports (
			sandbox_id TEXT NOT NULL,
			port INTEGER NOT NULL,
			public_url TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY (sandbox_id, port),
			FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS sandbox_mounts (
			sandbox_id TEXT PRIMARY KEY,
			sealed_blob BLOB NOT NULL,
			created_at DATETIME NOT NULL,
			FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_status ON sandboxes(status);`,
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_last_active_at ON sandboxes(last_active_at);`,
		// idx_sandboxes_image powers HasActiveImageRef so image GC stays
		// constant-cost as the destroyed-row history grows beyond the live
		// sandbox count. Plain (image) is sufficient: SQLite filters on
		// status using the index's row pointers, and the cardinality of
		// status values is small enough that a composite buys nothing.
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_image ON sandboxes(image);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("run schema statement: %w", err)
		}
	}

	// Migrations for older DBs that pre-date columns above. Idempotent.
	// Lifecycle fields are stored as INTEGER nanoseconds — same shape Go
	// uses for time.Duration internally, so no parsing on read and no
	// format ambiguity. Zero means "disabled" for that axis.
	migrations := []string{
		`ALTER TABLE sandboxes ADD COLUMN toolbox_token TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN ssh_public_key TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN stop_if_idle_for_ns INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN destroy_if_idle_for_ns INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN stop_at_age_ns INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN destroy_at_age_ns INTEGER NOT NULL DEFAULT 0;`,
		// Per-sandbox OCI runtime selector (runc / runsc). Pre-migration rows
		// get '' and resolve to the host default at start time; new sandboxes
		// always store the resolved value so the choice cannot drift across
		// host restarts.
		`ALTER TABLE sandboxes ADD COLUMN runtime TEXT NOT NULL DEFAULT '';`,
		// GPU configuration as a JSON blob. Empty string means no GPU was
		// requested. Stored as JSON to avoid schema churn as GPU options grow.
		`ALTER TABLE sandboxes ADD COLUMN gpus_json TEXT NOT NULL DEFAULT '';`,
		// Protocol of an exposed port: "http" (Caddy HTTP reverse proxy,
		// historical behavior), "tcp" (caddy-l4 listener at host_port), or
		// "tls" (caddy-l4 SNI route on the shared TLS listener).
		`ALTER TABLE exposed_ports ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http';`,
		// Parent-host TCP port reserved for protocol="tcp" exposures from the
		// configured pool. Zero for http/tls. The partial unique index below
		// rejects two reservations on the same host_port without preventing
		// many rows at the default 0.
		`ALTER TABLE exposed_ports ADD COLUMN host_port INTEGER NOT NULL DEFAULT 0;`,
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("run migration: %w", err)
		}
	}

	// Partial unique index on host_port (only enforced when host_port > 0).
	// This is the load-bearing primitive of the random-first allocator: two
	// concurrent ExposePort calls race to INSERT a host_port row, and only
	// one wins per port. SQLite's single writer keeps the contest serialized.
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_exposed_ports_host_port ON exposed_ports(host_port) WHERE host_port > 0;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create exposed_ports host_port index: %w", err)
	}

	return &Store{db: db}, nil
}

func sqliteDSN(path string) string {
	options := url.Values{}
	options.Set("_busy_timeout", fmt.Sprintf("%d", sqliteBusyTimeoutMS))
	options.Set("_foreign_keys", "on")
	options.Set("_journal_mode", "WAL")

	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + options.Encode()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, sandbox *models.Sandbox) error {
	envJSON, err := marshalJSON(sandbox.Env, "{}")
	if err != nil {
		return err
	}
	commandJSON, err := marshalJSON(sandbox.ContainerCommand, "[]")
	if err != nil {
		return err
	}
	gpusJSON, err := marshalGPUs(sandbox.GPUs)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sandboxes (
			id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			runtime, gpus_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		sandbox.ID,
		sandbox.Image,
		string(sandbox.Status),
		sandbox.PublicURL,
		sandbox.ContainerID,
		sandbox.ContainerIP,
		sandbox.CPU,
		sandbox.MemoryMB,
		sandbox.DiskGB,
		sandbox.OSUser,
		envJSON,
		boolToInt(sandbox.NetworkBlockAll),
		boolToInt(sandbox.ToolboxEnabled),
		sandbox.ToolboxToken,
		sandbox.SSHPublicKey,
		sandbox.LastError,
		commandJSON,
		sandbox.CreatedAt.UTC(),
		sandbox.UpdatedAt.UTC(),
		sandbox.LastActiveAt.UTC(),
		int64(sandbox.Lifecycle.StopIfIdleFor),
		int64(sandbox.Lifecycle.DestroyIfIdleFor),
		int64(sandbox.Lifecycle.StopAtAge),
		int64(sandbox.Lifecycle.DestroyAtAge),
		sandbox.Runtime,
		gpusJSON,
	)
	if err != nil {
		return fmt.Errorf("insert sandbox: %w", err)
	}
	return nil
}

func (s *Store) Upsert(ctx context.Context, sandbox *models.Sandbox) error {
	envJSON, err := marshalJSON(sandbox.Env, "{}")
	if err != nil {
		return err
	}
	commandJSON, err := marshalJSON(sandbox.ContainerCommand, "[]")
	if err != nil {
		return err
	}
	gpusJSON, err := marshalGPUs(sandbox.GPUs)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sandboxes (
			id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			runtime, gpus_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			image = excluded.image,
			status = excluded.status,
			public_url = excluded.public_url,
			container_id = excluded.container_id,
			container_ip = excluded.container_ip,
			cpu = excluded.cpu,
			memory_mb = excluded.memory_mb,
			disk_gb = excluded.disk_gb,
			os_user = excluded.os_user,
			env_json = excluded.env_json,
			network_block_all = excluded.network_block_all,
			toolbox_enabled = excluded.toolbox_enabled,
			toolbox_token = excluded.toolbox_token,
			ssh_public_key = excluded.ssh_public_key,
			last_error = excluded.last_error,
			container_command_json = excluded.container_command_json,
			updated_at = excluded.updated_at,
			last_active_at = excluded.last_active_at,
			stop_if_idle_for_ns = excluded.stop_if_idle_for_ns,
			destroy_if_idle_for_ns = excluded.destroy_if_idle_for_ns,
			stop_at_age_ns = excluded.stop_at_age_ns,
			destroy_at_age_ns = excluded.destroy_at_age_ns,
			runtime = excluded.runtime,
			gpus_json = excluded.gpus_json
	`,
		sandbox.ID,
		sandbox.Image,
		string(sandbox.Status),
		sandbox.PublicURL,
		sandbox.ContainerID,
		sandbox.ContainerIP,
		sandbox.CPU,
		sandbox.MemoryMB,
		sandbox.DiskGB,
		sandbox.OSUser,
		envJSON,
		boolToInt(sandbox.NetworkBlockAll),
		boolToInt(sandbox.ToolboxEnabled),
		sandbox.ToolboxToken,
		sandbox.SSHPublicKey,
		sandbox.LastError,
		commandJSON,
		sandbox.CreatedAt.UTC(),
		sandbox.UpdatedAt.UTC(),
		sandbox.LastActiveAt.UTC(),
		int64(sandbox.Lifecycle.StopIfIdleFor),
		int64(sandbox.Lifecycle.DestroyIfIdleFor),
		int64(sandbox.Lifecycle.StopAtAge),
		int64(sandbox.Lifecycle.DestroyAtAge),
		sandbox.Runtime,
		gpusJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert sandbox: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (*models.Sandbox, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			runtime, gpus_json
		FROM sandboxes
		WHERE id = ?
	`, id)

	sandbox, err := scanSandbox(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	ports, err := s.loadPorts(ctx, id)
	if err != nil {
		return nil, err
	}
	sandbox.ExposedPorts = ports

	return sandbox, nil
}

func (s *Store) List(ctx context.Context) ([]*models.Sandbox, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			runtime, gpus_json
		FROM sandboxes
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list sandboxes: %w", err)
	}
	defer rows.Close()

	var sandboxes []*models.Sandbox
	byID := map[string]*models.Sandbox{}
	for rows.Next() {
		sandbox, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		sandboxes = append(sandboxes, sandbox)
		byID[sandbox.ID] = sandbox
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sandboxes: %w", err)
	}

	// Single query for all exposed ports across all sandboxes in the result
	// set, then attach by sandbox_id. Avoids the N+1 pattern that would do
	// 10k individual SELECTs at large table sizes. Empty sandboxes table is
	// a fast no-op because we skip the query entirely.
	if len(sandboxes) > 0 {
		if err := s.attachPortsBulk(ctx, byID); err != nil {
			return nil, err
		}
	}

	return sandboxes, nil
}

// attachPortsBulk reads every exposed_ports row for any sandbox in byID with
// one query and writes it onto the matching sandbox. Sandboxes with no ports
// keep their nil slice — callers must not assume non-nil. The query scans
// the whole exposed_ports table, which is fine because that table only has
// rows for sandboxes that have ever exposed a port (a small fraction in
// practice). If exposed_ports ever grows large enough that this scan
// dominates, switch to a chunked WHERE sandbox_id IN (...) with parameter
// batches; the in-memory join below stays the same shape.
func (s *Store) attachPortsBulk(ctx context.Context, byID map[string]*models.Sandbox) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, port, protocol, host_port, public_url, created_at
		FROM exposed_ports
		ORDER BY sandbox_id, port ASC
	`)
	if err != nil {
		return fmt.Errorf("load exposed ports: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var exposure models.ExposedPort
		if err := rows.Scan(&exposure.SandboxID, &exposure.Port, &exposure.Protocol, &exposure.HostPort, &exposure.PublicURL, &exposure.CreatedAt); err != nil {
			return fmt.Errorf("scan exposed port: %w", err)
		}
		if sb, ok := byID[exposure.SandboxID]; ok {
			sb.ExposedPorts = append(sb.ExposedPorts, exposure)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate exposed ports: %w", err)
	}
	return nil
}

// HasActiveImageRef reports whether any sandbox row references image with a
// status other than destroyed. Used by image GC: when this returns false the
// caller may safely remove the image from Docker. Single indexed query —
// constant cost regardless of how many destroyed rows have accumulated, so
// 10k destroyed historical rows do not slow the destroy hot path. Returns
// true on empty image as a conservative default (caller treats it as "still
// in use, do not delete").
func (s *Store) HasActiveImageRef(ctx context.Context, image string) (bool, error) {
	if image == "" {
		return true, nil
	}
	var present int
	err := s.db.QueryRowContext(ctx, `
		SELECT 1 FROM sandboxes
		WHERE image = ? AND status != ?
		LIMIT 1
	`, image, string(models.SandboxStatusDestroyed)).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check image references: %w", err)
	}
	return true, nil
}

// UpdateLifecycle replaces the four lifecycle timer fields on a sandbox row
// and bumps updated_at. Other fields are untouched. Returns ErrNotFound if
// no row matches id. The caller must validate the Lifecycle first; the
// store does not re-validate (it would couple two layers for no gain).
func (s *Store) UpdateLifecycle(ctx context.Context, id string, l models.Lifecycle) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET stop_if_idle_for_ns = ?,
		    destroy_if_idle_for_ns = ?,
		    stop_at_age_ns = ?,
		    destroy_at_age_ns = ?,
		    updated_at = ?
		WHERE id = ?
	`,
		int64(l.StopIfIdleFor),
		int64(l.DestroyIfIdleFor),
		int64(l.StopAtAge),
		int64(l.DestroyAtAge),
		time.Now().UTC(),
		id,
	)
	if err != nil {
		return fmt.Errorf("update sandbox lifecycle: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sandboxes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete sandbox: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateStatus(ctx context.Context, id string, status models.SandboxStatus, lastError string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET status = ?, last_error = ?, updated_at = ?
		WHERE id = ?
	`, string(status), lastError, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update sandbox status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateRuntime(ctx context.Context, id, containerID, containerIP, publicURL string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET container_id = ?, container_ip = ?, public_url = ?, updated_at = ?
		WHERE id = ?
	`, containerID, containerIP, publicURL, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update sandbox runtime: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Touch(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET last_active_at = ?, updated_at = ?
		WHERE id = ?
	`, at.UTC(), at.UTC(), id)
	if err != nil {
		return fmt.Errorf("touch sandbox: %w", err)
	}
	return nil
}

func (s *Store) UpsertPort(ctx context.Context, exposure models.ExposedPort) error {
	if exposure.Protocol == "" {
		exposure.Protocol = models.ExposedPortProtocolHTTP
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO exposed_ports (sandbox_id, port, protocol, host_port, public_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(sandbox_id, port) DO UPDATE SET
			protocol = excluded.protocol,
			host_port = excluded.host_port,
			public_url = excluded.public_url,
			created_at = excluded.created_at
	`, exposure.SandboxID, exposure.Port, exposure.Protocol, exposure.HostPort, exposure.PublicURL, exposure.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("upsert exposed port: %w", err)
	}
	return nil
}

// ReserveHostPortResult is the three-state outcome of TryReserveHostPort.
// Exactly one of Reserved/Existing/(neither) is set:
//   - Reserved: the row was inserted; the candidate host port is now ours.
//   - Existing != nil: a row for (sandbox_id, port) already exists. The
//     allocator MUST stop walking the pool — no other host_port will satisfy
//     the (sandbox_id, port) primary key. Caller decides whether to reuse
//     the existing exposure or surface an error.
//   - both zero: the partial unique index on host_port rejected this
//     candidate (some other sandbox owns it). Caller may retry.
type ReserveHostPortResult struct {
	Reserved bool
	Existing *models.ExposedPort
}

// TryReserveHostPort attempts to claim hostPort for (sandboxID, containerPort)
// in a single INSERT OR IGNORE. The OR IGNORE swallows two distinct UNIQUE
// failures — the (sandbox_id, port) primary key AND the partial index on
// host_port — so on a no-op insert we follow up with a SELECT to disambiguate.
// Without that disambiguation, retrying expose for an already-exposed port
// looks identical to a host_port collision and walks the whole allocator pool
// before failing with "exhausted".
func (s *Store) TryReserveHostPort(ctx context.Context, sandboxID string, containerPort, hostPort int, protocol, publicURL string, now time.Time) (ReserveHostPortResult, error) {
	if hostPort <= 0 {
		return ReserveHostPortResult{}, errors.New("host port must be positive")
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO exposed_ports (sandbox_id, port, protocol, host_port, public_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sandboxID, containerPort, protocol, hostPort, publicURL, now.UTC())
	if err != nil {
		return ReserveHostPortResult{}, fmt.Errorf("reserve host port: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ReserveHostPortResult{}, fmt.Errorf("reserve host port (affected): %w", err)
	}
	if affected == 1 {
		return ReserveHostPortResult{Reserved: true}, nil
	}
	existing, err := s.getPort(ctx, sandboxID, containerPort)
	if err != nil {
		return ReserveHostPortResult{}, fmt.Errorf("reserve host port (lookup existing): %w", err)
	}
	if existing != nil {
		return ReserveHostPortResult{Existing: existing}, nil
	}
	return ReserveHostPortResult{}, nil
}

// getPort returns the exposure row for (sandboxID, port), or nil if absent.
func (s *Store) getPort(ctx context.Context, sandboxID string, port int) (*models.ExposedPort, error) {
	var exposure models.ExposedPort
	err := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, port, protocol, host_port, public_url, created_at
		FROM exposed_ports
		WHERE sandbox_id = ? AND port = ?
	`, sandboxID, port).Scan(&exposure.SandboxID, &exposure.Port, &exposure.Protocol, &exposure.HostPort, &exposure.PublicURL, &exposure.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &exposure, nil
}

// ListAllExposedPorts returns every row in exposed_ports across every
// sandbox. Used by reconcile to GC zombie caddy routes / layer4 servers
// without N+1 per-sandbox lookups.
func (s *Store) ListAllExposedPorts(ctx context.Context) ([]models.ExposedPort, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, port, protocol, host_port, public_url, created_at
		FROM exposed_ports
		ORDER BY sandbox_id, port ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list all exposed ports: %w", err)
	}
	defer rows.Close()

	var ports []models.ExposedPort
	for rows.Next() {
		var exposure models.ExposedPort
		if err := rows.Scan(&exposure.SandboxID, &exposure.Port, &exposure.Protocol, &exposure.HostPort, &exposure.PublicURL, &exposure.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan exposed port: %w", err)
		}
		ports = append(ports, exposure)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exposed ports: %w", err)
	}
	return ports, nil
}

func (s *Store) DeletePort(ctx context.Context, sandboxID string, port int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM exposed_ports WHERE sandbox_id = ? AND port = ?`, sandboxID, port)
	if err != nil {
		return fmt.Errorf("delete exposed port: %w", err)
	}
	return nil
}

func (s *Store) loadPorts(ctx context.Context, sandboxID string) ([]models.ExposedPort, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, port, protocol, host_port, public_url, created_at
		FROM exposed_ports
		WHERE sandbox_id = ?
		ORDER BY port ASC
	`, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("load exposed ports: %w", err)
	}
	defer rows.Close()

	var ports []models.ExposedPort
	for rows.Next() {
		var exposure models.ExposedPort
		if err := rows.Scan(&exposure.SandboxID, &exposure.Port, &exposure.Protocol, &exposure.HostPort, &exposure.PublicURL, &exposure.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan exposed port: %w", err)
		}
		ports = append(ports, exposure)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exposed ports: %w", err)
	}

	return ports, nil
}

func scanSandbox(scanner interface {
	Scan(dest ...any) error
}) (*models.Sandbox, error) {
	var sandbox models.Sandbox
	var envJSON string
	var networkBlocked int
	var toolboxEnabled int
	var commandJSON string
	var gpusJSON string
	var stopIfIdleNs, destroyIfIdleNs, stopAtAgeNs, destroyAtAgeNs int64

	err := scanner.Scan(
		&sandbox.ID,
		&sandbox.Image,
		&sandbox.Status,
		&sandbox.PublicURL,
		&sandbox.ContainerID,
		&sandbox.ContainerIP,
		&sandbox.CPU,
		&sandbox.MemoryMB,
		&sandbox.DiskGB,
		&sandbox.OSUser,
		&envJSON,
		&networkBlocked,
		&toolboxEnabled,
		&sandbox.ToolboxToken,
		&sandbox.SSHPublicKey,
		&sandbox.LastError,
		&commandJSON,
		&sandbox.CreatedAt,
		&sandbox.UpdatedAt,
		&sandbox.LastActiveAt,
		&stopIfIdleNs,
		&destroyIfIdleNs,
		&stopAtAgeNs,
		&destroyAtAgeNs,
		&sandbox.Runtime,
		&gpusJSON,
	)
	if err != nil {
		return nil, err
	}

	if envJSON != "" {
		if err := json.Unmarshal([]byte(envJSON), &sandbox.Env); err != nil {
			return nil, fmt.Errorf("decode sandbox env: %w", err)
		}
	}
	if commandJSON != "" {
		if err := json.Unmarshal([]byte(commandJSON), &sandbox.ContainerCommand); err != nil {
			return nil, fmt.Errorf("decode container command: %w", err)
		}
	}
	if gpusJSON != "" {
		var gpu models.GPURequest
		if err := json.Unmarshal([]byte(gpusJSON), &gpu); err != nil {
			return nil, fmt.Errorf("decode sandbox gpus: %w", err)
		}
		sandbox.GPUs = &gpu
	}

	sandbox.NetworkBlockAll = networkBlocked == 1
	sandbox.ToolboxEnabled = toolboxEnabled == 1
	sandbox.Lifecycle = models.Lifecycle{
		StopIfIdleFor:    time.Duration(stopIfIdleNs),
		DestroyIfIdleFor: time.Duration(destroyIfIdleNs),
		StopAtAge:        time.Duration(stopAtAgeNs),
		DestroyAtAge:     time.Duration(destroyAtAgeNs),
	}

	return &sandbox, nil
}

func marshalJSON(value any, fallback string) (string, error) {
	if value == nil {
		return fallback, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(encoded), nil
}

// marshalGPUs serializes a GPURequest pointer. Nil (no GPU) returns an empty
// string, which the column default also holds for pre-GPU rows.
func marshalGPUs(g *models.GPURequest) (string, error) {
	if g == nil {
		return "", nil
	}
	encoded, err := json.Marshal(g)
	if err != nil {
		return "", fmt.Errorf("marshal gpus: %w", err)
	}
	return string(encoded), nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

var ErrNotFound = errors.New("sandbox not found")

// PutMounts stores an encrypted mount blob for a sandbox. The blob is opaque
// to the store layer; encryption / decryption happens in the service layer.
func (s *Store) PutMounts(ctx context.Context, sandboxID string, sealed []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_mounts (sandbox_id, sealed_blob, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			sealed_blob = excluded.sealed_blob,
			created_at = excluded.created_at
	`, sandboxID, sealed, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("upsert sandbox mounts: %w", err)
	}
	return nil
}

// GetMounts returns the encrypted mount blob, or ErrNotFound if no row exists.
func (s *Store) GetMounts(ctx context.Context, sandboxID string) ([]byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT sealed_blob FROM sandbox_mounts WHERE sandbox_id = ?`, sandboxID)
	var blob []byte
	if err := row.Scan(&blob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get sandbox mounts: %w", err)
	}
	return blob, nil
}

// DeleteMounts removes mount config for a sandbox. The cascade on the
// sandboxes table handles this when a sandbox is destroyed; explicit deletes
// are useful for replacing mounts.
func (s *Store) DeleteMounts(ctx context.Context, sandboxID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sandbox_mounts WHERE sandbox_id = ?`, sandboxID)
	if err != nil {
		return fmt.Errorf("delete sandbox mounts: %w", err)
	}
	return nil
}
