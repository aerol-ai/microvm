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
	sqlite3 "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

const sqliteBusyTimeoutMS = 5000

func Open(path string) (*Store, error) {
	// The DB stores secrets (env_json, toolbox_token, sealed mount blobs).
	// Lock the directory and file to owner-only so a custom DBPath, a dev
	// run on a shared host, or any setup that doesn't go through the
	// installer can't leak them via the default 0o755 / umask-derived modes.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	// MkdirAll leaves a pre-existing directory's mode untouched, so chmod
	// explicitly to tighten dirs created by older builds at 0o755.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod db directory: %w", err)
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
		`CREATE TABLE IF NOT EXISTS daytona_sandboxes (
			sandbox_id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			snapshot TEXT NOT NULL DEFAULT '',
			user_name TEXT NOT NULL DEFAULT '',
			labels_json TEXT NOT NULL DEFAULT '{}',
			target TEXT NOT NULL DEFAULT '',
			network_allow_list TEXT NOT NULL DEFAULT '',
			auto_stop_interval_minutes REAL,
			auto_archive_interval_minutes REAL,
			auto_delete_interval_minutes REAL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS e2b_sandboxes (
			sandbox_id TEXT PRIMARY KEY,
			template_id TEXT NOT NULL DEFAULT '',
			template_alias TEXT NOT NULL DEFAULT '',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			timeout_seconds INTEGER NOT NULL DEFAULT 0,
			on_timeout TEXT NOT NULL DEFAULT 'kill',
			auto_resume INTEGER NOT NULL DEFAULT 0,
			secure INTEGER NOT NULL DEFAULT 1,
			allow_internet_access INTEGER,
			network_allow_out_json TEXT NOT NULL DEFAULT '[]',
			network_deny_out_json TEXT NOT NULL DEFAULT '[]',
			allow_public_traffic INTEGER,
			mask_request_host TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS e2b_snapshots (
			snapshot_id TEXT PRIMARY KEY,
			snapshot_name TEXT NOT NULL,
			names_json TEXT NOT NULL DEFAULT '[]',
			source_sandbox_id TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sandbox_snapshots (
			name TEXT PRIMARY KEY,
			image TEXT NOT NULL,
			image_id TEXT NOT NULL DEFAULT '',
			source_sandbox_id TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_status ON sandboxes(status);`,
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_last_active_at ON sandboxes(last_active_at);`,
		// idx_sandboxes_image powers HasActiveImageRef so image GC stays
		// constant-cost as the destroyed-row history grows beyond the live
		// sandbox count. Plain (image) is sufficient: SQLite filters on
		// status using the index's row pointers, and the cardinality of
		// status values is small enough that a composite buys nothing.
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_image ON sandboxes(image);`,
		`CREATE INDEX IF NOT EXISTS idx_e2b_snapshots_source_sandbox_id ON e2b_snapshots(source_sandbox_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sandbox_snapshots_source_sandbox_id ON sandbox_snapshots(source_sandbox_id);`,
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

	// SQLite materialized the DB file (and the WAL/SHM sidecars on the
	// first write) using the process umask — typically 0o644, leaving
	// env_json and toolbox_token world-readable. Tighten to owner-only.
	// Sidecars may not exist on a fresh DB if no transaction has run yet;
	// ignore not-found and let the next writer create them with the now
	// owner-only directory mode protecting them in transit.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, fmt.Errorf("chmod db file %s: %w", p, err)
		}
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

func (s *Store) UpsertDaytonaMetadata(ctx context.Context, meta models.DaytonaSandboxMetadata) error {
	labelsJSON, err := marshalJSON(meta.Labels, "{}")
	if err != nil {
		return fmt.Errorf("marshal daytona labels: %w", err)
	}
	name := strings.TrimSpace(meta.Name)
	if name == "" {
		name = strings.TrimSpace(meta.SandboxID)
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO daytona_sandboxes (
			sandbox_id, name, snapshot, user_name, labels_json, target, network_allow_list,
			auto_stop_interval_minutes, auto_archive_interval_minutes, auto_delete_interval_minutes,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			name = excluded.name,
			snapshot = excluded.snapshot,
			user_name = excluded.user_name,
			labels_json = excluded.labels_json,
			target = excluded.target,
			network_allow_list = excluded.network_allow_list,
			auto_stop_interval_minutes = excluded.auto_stop_interval_minutes,
			auto_archive_interval_minutes = excluded.auto_archive_interval_minutes,
			auto_delete_interval_minutes = excluded.auto_delete_interval_minutes,
			updated_at = excluded.updated_at
	`,
		strings.TrimSpace(meta.SandboxID),
		name,
		strings.TrimSpace(meta.Snapshot),
		strings.TrimSpace(meta.User),
		labelsJSON,
		strings.TrimSpace(meta.Target),
		strings.TrimSpace(meta.NetworkAllowList),
		nullableFloat32(meta.AutoStopIntervalMinutes),
		nullableFloat32(meta.AutoArchiveIntervalMinutes),
		nullableFloat32(meta.AutoDeleteIntervalMinutes),
		now,
		now,
	)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return ErrDaytonaNameConflict
		}
		return fmt.Errorf("upsert daytona metadata: %w", err)
	}
	return nil
}

func (s *Store) GetDaytonaMetadata(ctx context.Context, sandboxID string) (*models.DaytonaSandboxMetadata, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, name, snapshot, user_name, labels_json, target, network_allow_list,
			auto_stop_interval_minutes, auto_archive_interval_minutes, auto_delete_interval_minutes
		FROM daytona_sandboxes
		WHERE sandbox_id = ?
	`, sandboxID)
	meta, err := scanDaytonaMetadata(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get daytona metadata: %w", err)
	}
	return meta, nil
}

func (s *Store) UpsertE2BSandboxMetadata(ctx context.Context, meta models.E2BSandboxMetadata) error {
	metadataJSON, err := marshalJSON(meta.Metadata, "{}")
	if err != nil {
		return fmt.Errorf("marshal e2b metadata: %w", err)
	}
	allowOutJSON, err := marshalJSON(meta.NetworkAllowOut, "[]")
	if err != nil {
		return fmt.Errorf("marshal e2b allowOut: %w", err)
	}
	denyOutJSON, err := marshalJSON(meta.NetworkDenyOut, "[]")
	if err != nil {
		return fmt.Errorf("marshal e2b denyOut: %w", err)
	}
	now := time.Now().UTC()
	createdAt := meta.CreatedAt.UTC()
	if meta.CreatedAt.IsZero() {
		createdAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO e2b_sandboxes (
			sandbox_id, template_id, template_alias, metadata_json, timeout_seconds,
			on_timeout, auto_resume, secure, allow_internet_access,
			network_allow_out_json, network_deny_out_json, allow_public_traffic,
			mask_request_host, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sandbox_id) DO UPDATE SET
			template_id = excluded.template_id,
			template_alias = excluded.template_alias,
			metadata_json = excluded.metadata_json,
			timeout_seconds = excluded.timeout_seconds,
			on_timeout = excluded.on_timeout,
			auto_resume = excluded.auto_resume,
			secure = excluded.secure,
			allow_internet_access = excluded.allow_internet_access,
			network_allow_out_json = excluded.network_allow_out_json,
			network_deny_out_json = excluded.network_deny_out_json,
			allow_public_traffic = excluded.allow_public_traffic,
			mask_request_host = excluded.mask_request_host,
			updated_at = excluded.updated_at
	`,
		strings.TrimSpace(meta.SandboxID),
		strings.TrimSpace(meta.TemplateID),
		strings.TrimSpace(meta.TemplateAlias),
		metadataJSON,
		meta.TimeoutSeconds,
		firstNonEmptyString(strings.TrimSpace(meta.OnTimeout), "kill"),
		boolToInt(meta.AutoResume),
		boolToInt(meta.Secure),
		nullableBool(meta.AllowInternetAccess),
		allowOutJSON,
		denyOutJSON,
		nullableBool(meta.AllowPublicTraffic),
		strings.TrimSpace(meta.MaskRequestHost),
		createdAt,
		now,
	)
	if err != nil {
		return fmt.Errorf("upsert e2b sandbox metadata: %w", err)
	}
	return nil
}

func (s *Store) GetE2BSandboxMetadata(ctx context.Context, sandboxID string) (*models.E2BSandboxMetadata, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, template_id, template_alias, metadata_json, timeout_seconds,
			on_timeout, auto_resume, secure, allow_internet_access,
			network_allow_out_json, network_deny_out_json, allow_public_traffic,
			mask_request_host, created_at, updated_at
		FROM e2b_sandboxes
		WHERE sandbox_id = ?
	`, sandboxID)
	meta, err := scanE2BSandboxMetadata(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get e2b sandbox metadata: %w", err)
	}
	return meta, nil
}

func (s *Store) ListE2BSandboxMetadata(ctx context.Context) (map[string]models.E2BSandboxMetadata, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, template_id, template_alias, metadata_json, timeout_seconds,
			on_timeout, auto_resume, secure, allow_internet_access,
			network_allow_out_json, network_deny_out_json, allow_public_traffic,
			mask_request_host, created_at, updated_at
		FROM e2b_sandboxes
		ORDER BY sandbox_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list e2b sandbox metadata: %w", err)
	}
	defer rows.Close()

	items := map[string]models.E2BSandboxMetadata{}
	for rows.Next() {
		meta, err := scanE2BSandboxMetadata(rows)
		if err != nil {
			return nil, fmt.Errorf("scan e2b sandbox metadata: %w", err)
		}
		items[meta.SandboxID] = *meta
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate e2b sandbox metadata: %w", err)
	}
	return items, nil
}

func (s *Store) UpsertE2BSnapshot(ctx context.Context, meta models.E2BSnapshotMetadata) error {
	namesJSON, err := marshalJSON(meta.Names, "[]")
	if err != nil {
		return fmt.Errorf("marshal e2b snapshot names: %w", err)
	}
	now := time.Now().UTC()
	createdAt := meta.CreatedAt.UTC()
	if meta.CreatedAt.IsZero() {
		createdAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO e2b_snapshots (
			snapshot_id, snapshot_name, names_json, source_sandbox_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(snapshot_id) DO UPDATE SET
			snapshot_name = excluded.snapshot_name,
			names_json = excluded.names_json,
			source_sandbox_id = excluded.source_sandbox_id,
			updated_at = excluded.updated_at
	`,
		strings.TrimSpace(meta.SnapshotID),
		strings.TrimSpace(meta.SnapshotName),
		namesJSON,
		strings.TrimSpace(meta.SourceSandboxID),
		createdAt,
		now,
	)
	if err != nil {
		return fmt.Errorf("upsert e2b snapshot metadata: %w", err)
	}
	return nil
}

func (s *Store) GetE2BSnapshot(ctx context.Context, snapshotID string) (*models.E2BSnapshotMetadata, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT snapshot_id, snapshot_name, names_json, source_sandbox_id, created_at, updated_at
		FROM e2b_snapshots
		WHERE snapshot_id = ?
	`, strings.TrimSpace(snapshotID))
	meta, err := scanE2BSnapshotMetadata(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get e2b snapshot metadata: %w", err)
	}
	return meta, nil
}

func (s *Store) ListE2BSnapshots(ctx context.Context) (map[string]models.E2BSnapshotMetadata, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT snapshot_id, snapshot_name, names_json, source_sandbox_id, created_at, updated_at
		FROM e2b_snapshots
		ORDER BY created_at DESC, snapshot_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list e2b snapshot metadata: %w", err)
	}
	defer rows.Close()

	items := map[string]models.E2BSnapshotMetadata{}
	for rows.Next() {
		meta, err := scanE2BSnapshotMetadata(rows)
		if err != nil {
			return nil, fmt.Errorf("scan e2b snapshot metadata: %w", err)
		}
		items[meta.SnapshotID] = *meta
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate e2b snapshot metadata: %w", err)
	}
	return items, nil
}

func (s *Store) DeleteE2BSnapshot(ctx context.Context, snapshotID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM e2b_snapshots WHERE snapshot_id = ?`, strings.TrimSpace(snapshotID))
	if err != nil {
		return fmt.Errorf("delete e2b snapshot metadata: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateSnapshot(ctx context.Context, snapshot *models.SandboxSnapshot) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_snapshots (name, image, image_id, source_sandbox_id, created_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		strings.TrimSpace(snapshot.Name),
		strings.TrimSpace(snapshot.Image),
		strings.TrimSpace(snapshot.ImageID),
		strings.TrimSpace(snapshot.SourceSandboxID),
		snapshot.CreatedAt.UTC(),
	)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return ErrSnapshotNameConflict
		}
		return fmt.Errorf("create snapshot: %w", err)
	}
	return nil
}

func (s *Store) GetSnapshot(ctx context.Context, name string) (*models.SandboxSnapshot, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT name, image, image_id, source_sandbox_id, created_at
		FROM sandbox_snapshots
		WHERE name = ?
	`, strings.TrimSpace(name))
	snapshot, err := scanSnapshot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get snapshot: %w", err)
	}
	return snapshot, nil
}

func (s *Store) ListSnapshots(ctx context.Context) ([]*models.SandboxSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, image, image_id, source_sandbox_id, created_at
		FROM sandbox_snapshots
		ORDER BY created_at DESC, name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
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

func (s *Store) DeleteSnapshot(ctx context.Context, name string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sandbox_snapshots WHERE name = ?`, strings.TrimSpace(name))
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListDaytonaMetadata(ctx context.Context) (map[string]models.DaytonaSandboxMetadata, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, name, snapshot, user_name, labels_json, target, network_allow_list,
			auto_stop_interval_minutes, auto_archive_interval_minutes, auto_delete_interval_minutes
		FROM daytona_sandboxes
		ORDER BY sandbox_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list daytona metadata: %w", err)
	}
	defer rows.Close()

	items := map[string]models.DaytonaSandboxMetadata{}
	for rows.Next() {
		meta, err := scanDaytonaMetadata(rows)
		if err != nil {
			return nil, fmt.Errorf("scan daytona metadata: %w", err)
		}
		items[meta.SandboxID] = *meta
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate daytona metadata: %w", err)
	}
	return items, nil
}

func (s *Store) ResolveDaytonaSandboxID(ctx context.Context, name string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT sandbox_id FROM daytona_sandboxes WHERE name = ?`, strings.TrimSpace(name))
	var sandboxID string
	if err := row.Scan(&sandboxID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("resolve daytona sandbox id: %w", err)
	}
	return sandboxID, nil
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

func scanDaytonaMetadata(scanner interface {
	Scan(dest ...any) error
}) (*models.DaytonaSandboxMetadata, error) {
	var meta models.DaytonaSandboxMetadata
	var labelsJSON string
	var autoStop sql.NullFloat64
	var autoArchive sql.NullFloat64
	var autoDelete sql.NullFloat64
	err := scanner.Scan(
		&meta.SandboxID,
		&meta.Name,
		&meta.Snapshot,
		&meta.User,
		&labelsJSON,
		&meta.Target,
		&meta.NetworkAllowList,
		&autoStop,
		&autoArchive,
		&autoDelete,
	)
	if err != nil {
		return nil, err
	}
	if labelsJSON != "" {
		if err := json.Unmarshal([]byte(labelsJSON), &meta.Labels); err != nil {
			return nil, fmt.Errorf("decode daytona labels: %w", err)
		}
	}
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	meta.AutoStopIntervalMinutes = nullableFloat32Ptr(autoStop)
	meta.AutoArchiveIntervalMinutes = nullableFloat32Ptr(autoArchive)
	meta.AutoDeleteIntervalMinutes = nullableFloat32Ptr(autoDelete)
	return &meta, nil
}

func scanE2BSandboxMetadata(scanner interface {
	Scan(dest ...any) error
}) (*models.E2BSandboxMetadata, error) {
	var meta models.E2BSandboxMetadata
	var metadataJSON string
	var allowOutJSON string
	var denyOutJSON string
	var autoResume int
	var secure int
	var allowInternetAccess sql.NullInt64
	var allowPublicTraffic sql.NullInt64
	err := scanner.Scan(
		&meta.SandboxID,
		&meta.TemplateID,
		&meta.TemplateAlias,
		&metadataJSON,
		&meta.TimeoutSeconds,
		&meta.OnTimeout,
		&autoResume,
		&secure,
		&allowInternetAccess,
		&allowOutJSON,
		&denyOutJSON,
		&allowPublicTraffic,
		&meta.MaskRequestHost,
		&meta.CreatedAt,
		&meta.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &meta.Metadata); err != nil {
			return nil, fmt.Errorf("decode e2b metadata: %w", err)
		}
	}
	if meta.Metadata == nil {
		meta.Metadata = map[string]string{}
	}
	if allowOutJSON != "" {
		if err := json.Unmarshal([]byte(allowOutJSON), &meta.NetworkAllowOut); err != nil {
			return nil, fmt.Errorf("decode e2b allowOut: %w", err)
		}
	}
	if meta.NetworkAllowOut == nil {
		meta.NetworkAllowOut = []string{}
	}
	if denyOutJSON != "" {
		if err := json.Unmarshal([]byte(denyOutJSON), &meta.NetworkDenyOut); err != nil {
			return nil, fmt.Errorf("decode e2b denyOut: %w", err)
		}
	}
	if meta.NetworkDenyOut == nil {
		meta.NetworkDenyOut = []string{}
	}
	meta.AutoResume = autoResume != 0
	meta.Secure = secure != 0
	meta.AllowInternetAccess = nullableBoolPtr(allowInternetAccess)
	meta.AllowPublicTraffic = nullableBoolPtr(allowPublicTraffic)
	return &meta, nil
}

func scanE2BSnapshotMetadata(scanner interface {
	Scan(dest ...any) error
}) (*models.E2BSnapshotMetadata, error) {
	var meta models.E2BSnapshotMetadata
	var namesJSON string
	err := scanner.Scan(
		&meta.SnapshotID,
		&meta.SnapshotName,
		&namesJSON,
		&meta.SourceSandboxID,
		&meta.CreatedAt,
		&meta.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if namesJSON != "" {
		if err := json.Unmarshal([]byte(namesJSON), &meta.Names); err != nil {
			return nil, fmt.Errorf("decode e2b snapshot names: %w", err)
		}
	}
	if meta.Names == nil {
		meta.Names = []string{}
	}
	return &meta, nil
}

func scanSnapshot(scanner interface {
	Scan(dest ...any) error
}) (*models.SandboxSnapshot, error) {
	var snapshot models.SandboxSnapshot
	err := scanner.Scan(
		&snapshot.Name,
		&snapshot.Image,
		&snapshot.ImageID,
		&snapshot.SourceSandboxID,
		&snapshot.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
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

func nullableFloat32(value *float32) any {
	if value == nil {
		return nil
	}
	return float64(*value)
}

func nullableFloat32Ptr(value sql.NullFloat64) *float32 {
	if !value.Valid {
		return nil
	}
	v := float32(value.Float64)
	return &v
}

func nullableBool(value *bool) any {
	if value == nil {
		return nil
	}
	if *value {
		return 1
	}
	return 0
}

func nullableBoolPtr(value sql.NullInt64) *bool {
	if !value.Valid {
		return nil
	}
	v := value.Int64 != 0
	return &v
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func isSQLiteUniqueConstraint(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code == sqlite3.ErrConstraint && (sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique || sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey)
}

var ErrNotFound = errors.New("sandbox not found")

var ErrDaytonaNameConflict = errors.New("daytona sandbox name already in use")

var ErrSnapshotNameConflict = errors.New("snapshot name already in use")

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
