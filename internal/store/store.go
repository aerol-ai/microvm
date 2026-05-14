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
		// sandboxes is the canonical per-sandbox row. name and tags_json are
		// native first-class fields used by every facade — they are NOT
		// Daytona- or E2B-specific. Lifecycle is stored as four INTEGER
		// nanosecond fields (matches Go's time.Duration shape), gpus_json
		// is a JSON blob to absorb future GPU options without schema churn.
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
			name TEXT NOT NULL DEFAULT '',
			tags_json TEXT NOT NULL DEFAULT '{}',
			stop_if_idle_for_ns INTEGER NOT NULL DEFAULT 0,
			destroy_if_idle_for_ns INTEGER NOT NULL DEFAULT 0,
			stop_at_age_ns INTEGER NOT NULL DEFAULT 0,
			destroy_at_age_ns INTEGER NOT NULL DEFAULT 0,
			runtime TEXT NOT NULL DEFAULT '',
			gpus_json TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			last_active_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS exposed_ports (
			sandbox_id TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'http',
			host_port INTEGER NOT NULL DEFAULT 0,
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
		`CREATE TABLE IF NOT EXISTS sandbox_snapshots (
			name TEXT PRIMARY KEY,
			image TEXT NOT NULL,
			image_id TEXT NOT NULL DEFAULT '',
			source_sandbox_id TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		// sandbox_compat_state holds opaque facade-private state that has
		// no native meaning. One row per (sandbox, facade). state_json is
		// owned by the facade — the store does not interpret it. FK cascade
		// guarantees facade state is removed when the sandbox is destroyed.
		`CREATE TABLE IF NOT EXISTS sandbox_compat_state (
			sandbox_id TEXT NOT NULL,
			facade TEXT NOT NULL,
			state_json TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (sandbox_id, facade),
			FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
		);`,
		// snapshot_aliases lets a native sandbox_snapshots row be addressed
		// by facade-shaped alternate identifiers (e.g. E2B's base64 token).
		// FK cascade fixes the orphan-row bug where /v1/snapshots delete
		// would leave a facade alias dangling.
		`CREATE TABLE IF NOT EXISTS snapshot_aliases (
			alias TEXT PRIMARY KEY,
			snapshot_name TEXT NOT NULL,
			facade TEXT NOT NULL,
			extra_names_json TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY (snapshot_name) REFERENCES sandbox_snapshots(name) ON DELETE CASCADE
		);`,
		// request_idempotency is the generic claim/replay primitive for
		// caller-retry dedupe. scope is a caller-defined namespace string
		// ("e2b.create" today; "daytona.create" or "v1.create" later) so
		// the same fingerprint hash can be reused across facades without
		// colliding. The state machine is: pending → ready, with
		// locked_until bounding the in-flight wait and replay_until
		// bounding the replay window after success.
		`CREATE TABLE IF NOT EXISTS request_idempotency (
			scope TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			target_id TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT 'pending',
			locked_until DATETIME NOT NULL,
			replay_until DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (scope, fingerprint)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_status ON sandboxes(status);`,
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_last_active_at ON sandboxes(last_active_at);`,
		// idx_sandboxes_image powers HasActiveImageRef so image GC stays
		// constant-cost as the destroyed-row history grows beyond the live
		// sandbox count. Plain (image) is sufficient: SQLite filters on
		// status using the index's row pointers, and the cardinality of
		// status values is small enough that a composite buys nothing.
		`CREATE INDEX IF NOT EXISTS idx_sandboxes_image ON sandboxes(image);`,
		// Partial unique index on sandboxes.name. The default '' is allowed
		// many times (for sandboxes created without a name); any non-empty
		// name is unique across the table. Daytona depends on this for
		// name-based lookup; everyone else benefits from collision-free
		// names by default.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sandboxes_name ON sandboxes(name) WHERE name <> '';`,
		`CREATE INDEX IF NOT EXISTS idx_snapshot_aliases_snapshot_name ON snapshot_aliases(snapshot_name);`,
		`CREATE INDEX IF NOT EXISTS idx_snapshot_aliases_facade ON snapshot_aliases(facade);`,
		`CREATE INDEX IF NOT EXISTS idx_request_idempotency_replay_until ON request_idempotency(replay_until);`,
		`CREATE INDEX IF NOT EXISTS idx_sandbox_snapshots_source_sandbox_id ON sandbox_snapshots(source_sandbox_id);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("run schema statement: %w", err)
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
	tagsJSON, err := marshalJSON(sandbox.Tags, "{}")
	if err != nil {
		return err
	}
	if err := s.ensureSandboxLookupNameAvailable(ctx, sandbox.ID, sandbox.Name); err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sandboxes (
			id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, name, tags_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			runtime, gpus_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		strings.TrimSpace(sandbox.Name),
		tagsJSON,
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
		if isSandboxNameConflict(err, sandbox.Name) {
			return ErrSandboxNameConflict
		}
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
	tagsJSON, err := marshalJSON(sandbox.Tags, "{}")
	if err != nil {
		return err
	}
	if err := s.ensureSandboxLookupNameAvailable(ctx, sandbox.ID, sandbox.Name); err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sandboxes (
			id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, name, tags_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			runtime, gpus_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			name = excluded.name,
			tags_json = excluded.tags_json,
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
		strings.TrimSpace(sandbox.Name),
		tagsJSON,
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
		if isSandboxNameConflict(err, sandbox.Name) {
			return ErrSandboxNameConflict
		}
		return fmt.Errorf("upsert sandbox: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (*models.Sandbox, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, name, tags_json, created_at, updated_at, last_active_at,
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
			last_error, container_command_json, name, tags_json, created_at, updated_at, last_active_at,
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

// UpdateTags replaces sandboxes.tags_json on the row matching id and bumps
// updated_at. Used by facades that want to mutate the native tags field
// without round-tripping the entire sandbox struct through Upsert. Returns
// ErrNotFound if no row matches.
func (s *Store) UpdateTags(ctx context.Context, id string, tags map[string]string) error {
	tagsJSON, err := marshalJSON(tags, "{}")
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET tags_json = ?, updated_at = ?
		WHERE id = ?
	`, tagsJSON, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update sandbox tags: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
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

// ensureSandboxLookupNameAvailable keeps the user-facing sandbox lookup
// namespace unambiguous. Handlers resolve by id first and name second, so a
// name that equals another sandbox's id would otherwise be permanently
// shadowed. The inverse is also rejected for caller-supplied ids.
func (s *Store) ensureSandboxLookupNameAvailable(ctx context.Context, id, name string) error {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	if name != "" {
		var existingID string
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM sandboxes
			WHERE id = ? AND id <> ?
			LIMIT 1
		`, name, id).Scan(&existingID)
		if err == nil {
			return ErrSandboxNameConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check sandbox name against ids: %w", err)
		}
	}
	if id != "" {
		var existingID string
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM sandboxes
			WHERE name = ? AND id <> ?
			LIMIT 1
		`, id, id).Scan(&existingID)
		if err == nil {
			return ErrSandboxNameConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check sandbox id against names: %w", err)
		}
	}
	return nil
}

// UpsertCompatState writes the facade-private state blob for (sandboxID,
// facade). stateJSON is opaque to the store — each facade defines its own
// schema inside it. created_at is preserved on update so list ordering
// stays stable.
func (s *Store) UpsertCompatState(ctx context.Context, sandboxID, facade, stateJSON string) error {
	if strings.TrimSpace(sandboxID) == "" {
		return fmt.Errorf("upsert compat state: sandbox_id is required")
	}
	if strings.TrimSpace(facade) == "" {
		return fmt.Errorf("upsert compat state: facade is required")
	}
	body := strings.TrimSpace(stateJSON)
	if body == "" {
		body = "{}"
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_compat_state (sandbox_id, facade, state_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(sandbox_id, facade) DO UPDATE SET
			state_json = excluded.state_json,
			updated_at = excluded.updated_at
	`, strings.TrimSpace(sandboxID), strings.TrimSpace(facade), body, now, now)
	if err != nil {
		return fmt.Errorf("upsert compat state: %w", err)
	}
	return nil
}

// GetCompatState returns the state blob for (sandboxID, facade), or
// ErrNotFound when no row exists. Callers unmarshal state_json themselves.
func (s *Store) GetCompatState(ctx context.Context, sandboxID, facade string) (*models.SandboxCompatState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, facade, state_json, created_at, updated_at
		FROM sandbox_compat_state
		WHERE sandbox_id = ? AND facade = ?
	`, strings.TrimSpace(sandboxID), strings.TrimSpace(facade))
	state, err := scanCompatState(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get compat state: %w", err)
	}
	return state, nil
}

// ListCompatState returns every row for the given facade keyed by
// sandbox_id. Empty result is map of length zero, not nil — callers can
// always index into it.
func (s *Store) ListCompatState(ctx context.Context, facade string) (map[string]models.SandboxCompatState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, facade, state_json, created_at, updated_at
		FROM sandbox_compat_state
		WHERE facade = ?
		ORDER BY sandbox_id ASC
	`, strings.TrimSpace(facade))
	if err != nil {
		return nil, fmt.Errorf("list compat state: %w", err)
	}
	defer rows.Close()

	items := map[string]models.SandboxCompatState{}
	for rows.Next() {
		state, err := scanCompatState(rows)
		if err != nil {
			return nil, fmt.Errorf("scan compat state: %w", err)
		}
		items[state.SandboxID] = *state
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate compat state: %w", err)
	}
	return items, nil
}

// ResolveSandboxIDByName returns the sandbox ID owning the given name, or
// ErrNotFound if no row matches. Empty input is rejected so an accidental
// "" lookup does not match a no-name sandbox via the partial unique
// index's escape hatch.
func (s *Store) ResolveSandboxIDByName(ctx context.Context, name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT id FROM sandboxes WHERE name = ?`, trimmed)
	var sandboxID string
	if err := row.Scan(&sandboxID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("resolve sandbox id by name: %w", err)
	}
	return sandboxID, nil
}

// UpsertSnapshotAlias maps a facade-shaped alternate identifier onto a
// native sandbox_snapshots row. created_at is preserved on update.
func (s *Store) UpsertSnapshotAlias(ctx context.Context, alias models.SnapshotAlias) error {
	if strings.TrimSpace(alias.Alias) == "" {
		return fmt.Errorf("upsert snapshot alias: alias is required")
	}
	if strings.TrimSpace(alias.SnapshotName) == "" {
		return fmt.Errorf("upsert snapshot alias: snapshot_name is required")
	}
	extraNamesJSON, err := marshalJSON(alias.ExtraNames, "[]")
	if err != nil {
		return fmt.Errorf("marshal snapshot alias names: %w", err)
	}
	now := time.Now().UTC()
	createdAt := alias.CreatedAt.UTC()
	if alias.CreatedAt.IsZero() {
		createdAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO snapshot_aliases (alias, snapshot_name, facade, extra_names_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(alias) DO UPDATE SET
			snapshot_name = excluded.snapshot_name,
			facade = excluded.facade,
			extra_names_json = excluded.extra_names_json,
			updated_at = excluded.updated_at
	`,
		strings.TrimSpace(alias.Alias),
		strings.TrimSpace(alias.SnapshotName),
		strings.TrimSpace(alias.Facade),
		extraNamesJSON,
		createdAt,
		now,
	)
	if err != nil {
		return fmt.Errorf("upsert snapshot alias: %w", err)
	}
	return nil
}

// GetSnapshotAlias returns the alias row, or ErrNotFound if the alias
// does not exist.
func (s *Store) GetSnapshotAlias(ctx context.Context, alias string) (*models.SnapshotAlias, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT alias, snapshot_name, facade, extra_names_json, created_at, updated_at
		FROM snapshot_aliases
		WHERE alias = ?
	`, strings.TrimSpace(alias))
	got, err := scanSnapshotAlias(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get snapshot alias: %w", err)
	}
	return got, nil
}

// ListSnapshotAliases returns all alias rows for the given facade keyed
// by alias. Pass empty facade to fetch every alias regardless of facade.
func (s *Store) ListSnapshotAliases(ctx context.Context, facade string) (map[string]models.SnapshotAlias, error) {
	var rows *sql.Rows
	var err error
	trimmed := strings.TrimSpace(facade)
	if trimmed == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT alias, snapshot_name, facade, extra_names_json, created_at, updated_at
			FROM snapshot_aliases
			ORDER BY created_at DESC, alias ASC
		`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT alias, snapshot_name, facade, extra_names_json, created_at, updated_at
			FROM snapshot_aliases
			WHERE facade = ?
			ORDER BY created_at DESC, alias ASC
		`, trimmed)
	}
	if err != nil {
		return nil, fmt.Errorf("list snapshot aliases: %w", err)
	}
	defer rows.Close()

	items := map[string]models.SnapshotAlias{}
	for rows.Next() {
		alias, err := scanSnapshotAlias(rows)
		if err != nil {
			return nil, fmt.Errorf("scan snapshot alias: %w", err)
		}
		items[alias.Alias] = *alias
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot aliases: %w", err)
	}
	return items, nil
}

// DeleteSnapshotAlias removes the alias row. FK cascade also drops the
// row when its underlying sandbox_snapshots row is deleted, so explicit
// deletes are only needed when the facade wants to forget an alias
// without removing the native snapshot.
func (s *Store) DeleteSnapshotAlias(ctx context.Context, alias string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM snapshot_aliases WHERE alias = ?`, strings.TrimSpace(alias))
	if err != nil {
		return fmt.Errorf("delete snapshot alias: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimIdempotentRequest is the generic claim/replay primitive for
// caller-retry dedupe. scope is a facade-defined namespace string
// ("e2b.create" today; "daytona.create" or "v1.create" later) so the
// same fingerprint can be reused across facades without colliding.
//
// Three outcomes per call:
//  1. INSERTed a fresh pending row → acquired=true, caller owns the work.
//  2. Found a Ready row whose ReplayUntil has not expired → acquired=false,
//     caller replays the TargetID instead of running the work again.
//  3. Found a Pending row whose LockedUntil has not expired → acquired=false,
//     caller waits.
//
// Stale Pending or Ready rows past their TTLs are reclaimed as a fresh
// Pending row (acquired=true), so a crashed claimer cannot block future
// retries indefinitely.
func (s *Store) ClaimIdempotentRequest(ctx context.Context, scope, fingerprint string, now time.Time, pendingTTL time.Duration) (*models.IdempotentRequestRecord, bool, error) {
	scope = strings.TrimSpace(scope)
	fingerprint = strings.TrimSpace(fingerprint)
	if scope == "" {
		return nil, false, fmt.Errorf("claim idempotent request: scope is required")
	}
	if fingerprint == "" {
		return nil, false, fmt.Errorf("claim idempotent request: fingerprint is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("claim idempotent request: begin tx: %w", err)
	}
	defer tx.Rollback()

	record := &models.IdempotentRequestRecord{
		Scope:       scope,
		Fingerprint: fingerprint,
		State:       models.RequestStatePending,
		LockedUntil: now.Add(pendingTTL),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO request_idempotency (scope, fingerprint, target_id, state, locked_until, replay_until, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scope, fingerprint) DO NOTHING
	`, record.Scope, record.Fingerprint, "", record.State, record.LockedUntil, nil, record.CreatedAt, record.UpdatedAt)
	if err != nil {
		return nil, false, fmt.Errorf("claim idempotent request: insert: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("claim idempotent request: inspect insert: %w", err)
	}
	if inserted > 0 {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("claim idempotent request: commit insert: %w", err)
		}
		return record, true, nil
	}

	record, err = scanIdempotentRequestRecord(tx.QueryRowContext(ctx, `
		SELECT scope, fingerprint, target_id, state, locked_until, replay_until, created_at, updated_at
		FROM request_idempotency
		WHERE scope = ? AND fingerprint = ?
	`, scope, fingerprint))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, fmt.Errorf("claim idempotent request: missing row after insert conflict")
		}
		return nil, false, fmt.Errorf("claim idempotent request: query: %w", err)
	}

	if record.State == models.RequestStateReady && !record.ReplayUntil.IsZero() && record.ReplayUntil.After(now) && strings.TrimSpace(record.TargetID) != "" {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("claim idempotent request: commit ready: %w", err)
		}
		return record, false, nil
	}
	if record.State == models.RequestStatePending && record.LockedUntil.After(now) {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("claim idempotent request: commit pending: %w", err)
		}
		return record, false, nil
	}

	record.TargetID = ""
	record.State = models.RequestStatePending
	record.LockedUntil = now.Add(pendingTTL)
	record.ReplayUntil = time.Time{}
	record.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `
		UPDATE request_idempotency
		SET target_id = '', state = ?, locked_until = ?, replay_until = NULL, updated_at = ?
		WHERE scope = ? AND fingerprint = ?
	`, record.State, record.LockedUntil, record.UpdatedAt, record.Scope, record.Fingerprint); err != nil {
		return nil, false, fmt.Errorf("claim idempotent request: refresh: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("claim idempotent request: commit refresh: %w", err)
	}
	return record, true, nil
}

// GetIdempotentRequest returns the row for (scope, fingerprint), or
// ErrNotFound when no row exists.
func (s *Store) GetIdempotentRequest(ctx context.Context, scope, fingerprint string) (*models.IdempotentRequestRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT scope, fingerprint, target_id, state, locked_until, replay_until, created_at, updated_at
		FROM request_idempotency
		WHERE scope = ? AND fingerprint = ?
	`, strings.TrimSpace(scope), strings.TrimSpace(fingerprint))
	record, err := scanIdempotentRequestRecord(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get idempotent request: %w", err)
	}
	return record, nil
}

// CompleteIdempotentRequest moves a Pending row to Ready, recording the
// target ID the work produced and extending the lock-and-replay window
// out to replayTTL from now. Returns ErrNotFound if no row matched —
// indicating either a programming error or a too-aggressive cleanup that
// removed the row mid-flight.
func (s *Store) CompleteIdempotentRequest(ctx context.Context, scope, fingerprint, targetID string, now time.Time, replayTTL time.Duration) error {
	now = now.UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE request_idempotency
		SET target_id = ?, state = ?, locked_until = ?, replay_until = ?, updated_at = ?
		WHERE scope = ? AND fingerprint = ?
	`, strings.TrimSpace(targetID), models.RequestStateReady, now, now.Add(replayTTL), now, strings.TrimSpace(scope), strings.TrimSpace(fingerprint))
	if err != nil {
		return fmt.Errorf("complete idempotent request: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteIdempotentRequest drops the row outright. Used by failure paths
// where the in-flight write rolled back and the next retry should run
// the work again from scratch instead of waiting for LockedUntil.
func (s *Store) DeleteIdempotentRequest(ctx context.Context, scope, fingerprint string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM request_idempotency WHERE scope = ? AND fingerprint = ?`, strings.TrimSpace(scope), strings.TrimSpace(fingerprint))
	if err != nil {
		return fmt.Errorf("delete idempotent request: %w", err)
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
	var tagsJSON string
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
		&sandbox.Name,
		&tagsJSON,
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
	if tagsJSON != "" {
		if err := json.Unmarshal([]byte(tagsJSON), &sandbox.Tags); err != nil {
			return nil, fmt.Errorf("decode sandbox tags: %w", err)
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

func scanCompatState(scanner interface {
	Scan(dest ...any) error
}) (*models.SandboxCompatState, error) {
	var state models.SandboxCompatState
	err := scanner.Scan(
		&state.SandboxID,
		&state.Facade,
		&state.StateJSON,
		&state.CreatedAt,
		&state.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	state.CreatedAt = state.CreatedAt.UTC()
	state.UpdatedAt = state.UpdatedAt.UTC()
	return &state, nil
}

func scanSnapshotAlias(scanner interface {
	Scan(dest ...any) error
}) (*models.SnapshotAlias, error) {
	var alias models.SnapshotAlias
	var extraNamesJSON string
	err := scanner.Scan(
		&alias.Alias,
		&alias.SnapshotName,
		&alias.Facade,
		&extraNamesJSON,
		&alias.CreatedAt,
		&alias.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if extraNamesJSON != "" {
		if err := json.Unmarshal([]byte(extraNamesJSON), &alias.ExtraNames); err != nil {
			return nil, fmt.Errorf("decode snapshot alias extra names: %w", err)
		}
	}
	if alias.ExtraNames == nil {
		alias.ExtraNames = []string{}
	}
	alias.CreatedAt = alias.CreatedAt.UTC()
	alias.UpdatedAt = alias.UpdatedAt.UTC()
	return &alias, nil
}

func scanIdempotentRequestRecord(scanner interface {
	Scan(dest ...any) error
}) (*models.IdempotentRequestRecord, error) {
	var record models.IdempotentRequestRecord
	var replayUntil sql.NullTime
	err := scanner.Scan(
		&record.Scope,
		&record.Fingerprint,
		&record.TargetID,
		&record.State,
		&record.LockedUntil,
		&replayUntil,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if replayUntil.Valid {
		record.ReplayUntil = replayUntil.Time.UTC()
	}
	record.LockedUntil = record.LockedUntil.UTC()
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return &record, nil
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

func isSQLiteUniqueConstraint(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code == sqlite3.ErrConstraint && (sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique || sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey)
}

func isSandboxNameConflict(err error, name string) bool {
	if strings.Contains(err.Error(), ErrSandboxNameConflict.Error()) {
		return true
	}
	return strings.TrimSpace(name) != "" && isSQLiteUniqueConstraint(err)
}

var ErrNotFound = errors.New("sandbox not found")

// ErrSandboxNameConflict is returned by Create/Upsert when the sandbox's
// name collides with an existing row's name or id. Names are unique across
// the sandboxes table; empty names skip the name uniqueness check but ids
// still cannot collide with existing non-empty names.
var ErrSandboxNameConflict = errors.New("sandbox name already in use")

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
