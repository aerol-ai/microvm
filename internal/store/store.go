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
			failover_policy TEXT NOT NULL DEFAULT '',
			runtime TEXT NOT NULL DEFAULT '',
			gpus_json TEXT NOT NULL DEFAULT '',
			net_bytes_in INTEGER NOT NULL DEFAULT 0,
			net_bytes_out INTEGER NOT NULL DEFAULT 0,
			net_bytes_in_limit INTEGER NOT NULL DEFAULT 0,
			net_bytes_out_limit INTEGER NOT NULL DEFAULT 0,
			net_quota_exceeded INTEGER NOT NULL DEFAULT 0,
			net_quota_exceeded_at DATETIME,
			auto_import_pending INTEGER NOT NULL DEFAULT 0,
			serverless INTEGER NOT NULL DEFAULT 0,
			wake_armed INTEGER NOT NULL DEFAULT 0,
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
		// sandbox_custom_domains attaches operator-provided public hostnames
		// to a sandbox. hostname is the PRIMARY KEY: a hostname maps to
		// exactly one sandbox at a time, and the PK rejects concurrent
		// inserts the same way the host_port partial unique index does for
		// the L4 TCP pool. status is the per-domain lifecycle state
		// (pending_dns → issuing → ready / failed) surfaced through the API;
		// last_error carries the surfaced reason on failed. FK CASCADE so
		// destroying the sandbox releases every hostname in the same write.
		// target_port is the in-container TCP port the ingress route dials
		// for this hostname. 0 (the default) means "fall back to the
		// daemon-wide toolbox port" — the legacy behavior from before
		// per-domain target ports existed. Non-zero pins the route to a
		// specific app port (e.g. 3333). Changing the value for an
		// already-attached hostname is forbidden at the service layer
		// (detach + re-add required) so live traffic cannot silently
		// redirect.
		`CREATE TABLE IF NOT EXISTS sandbox_custom_domains (
			hostname TEXT PRIMARY KEY,
			sandbox_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending_dns',
			last_error TEXT NOT NULL DEFAULT '',
			target_port INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
		);`,
		// cluster_secrets is the local secret-reference backend used by
		// cluster placement state. Placement rows store only ref/version; this
		// table stores the opaque encrypted payload and recipient metadata.
		// There is intentionally no FK to sandboxes: cluster reservations may
		// be written before a local sandbox row exists, and cleanup is explicit
		// by sandbox_id on rollback/destroy.
		`CREATE TABLE IF NOT EXISTS cluster_secrets (
			ref TEXT PRIMARY KEY,
			sandbox_id TEXT NOT NULL,
			version INTEGER NOT NULL,
			recipients_json TEXT NOT NULL DEFAULT '[]',
			sealed_payload BLOB NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sandbox_snapshots (
			name TEXT PRIMARY KEY,
			image TEXT NOT NULL,
			image_id TEXT NOT NULL DEFAULT '',
			source_sandbox_id TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			entrypoint_json TEXT NOT NULL DEFAULT '[]',
			region_id TEXT NOT NULL DEFAULT '',
			cpu REAL NOT NULL DEFAULT 0,
			memory_mb INTEGER NOT NULL DEFAULT 0,
			disk_gb INTEGER NOT NULL DEFAULT 0,
			gpu REAL NOT NULL DEFAULT 0,
			image_distribution_mode TEXT NOT NULL DEFAULT '',
			image_digest TEXT NOT NULL DEFAULT '',
			image_registry_ref TEXT NOT NULL DEFAULT '',
			image_verified_at DATETIME,
			push_state TEXT NOT NULL DEFAULT 'active',
			push_error TEXT NOT NULL DEFAULT ''
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
		`CREATE INDEX IF NOT EXISTS idx_cluster_secrets_sandbox_id ON cluster_secrets(sandbox_id);`,
		`CREATE INDEX IF NOT EXISTS idx_snapshot_aliases_snapshot_name ON snapshot_aliases(snapshot_name);`,
		`CREATE INDEX IF NOT EXISTS idx_snapshot_aliases_facade ON snapshot_aliases(facade);`,
		`CREATE INDEX IF NOT EXISTS idx_request_idempotency_replay_until ON request_idempotency(replay_until);`,
		`CREATE INDEX IF NOT EXISTS idx_sandbox_snapshots_source_sandbox_id ON sandbox_snapshots(source_sandbox_id);`,
		// Lookups by sandbox_id for ListCustomDomains and for the
		// attachCustomDomainsBulk join. The PK on hostname already covers
		// the ResolveCustomDomain hot path.
		`CREATE INDEX IF NOT EXISTS idx_sandbox_custom_domains_sandbox_id ON sandbox_custom_domains(sandbox_id);`,
		// pending_image_gc is the ledger the image janitor sweeps. Destroy
		// paths upsert (image, now); runPendingImageGC removes rows whose
		// scheduled_at is older than ImageBuildGCTTL once HasActiveImageRef
		// confirms nothing references the image. Image is the PK so repeat
		// destroys of sandboxes sharing an image collapse to one row and
		// the TTL clock resets to the most recent destroy.
		`CREATE TABLE IF NOT EXISTS pending_image_gc (
			image TEXT PRIMARY KEY,
			scheduled_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_pending_image_gc_scheduled_at ON pending_image_gc(scheduled_at);`,
		// firecracker_tap_pool is the pre-populated network-slot pool for
		// the native Firecracker runtime. Each row is one "slot" — a
		// (TAP-device, host-IP, guest-IP, /30 CIDR, vsock-CID) tuple. The
		// daemon seeds the table at boot from SB_FIRECRACKER_TAP_BASE_CIDR
		// / SB_FIRECRACKER_TAP_POOL_SIZE; sandbox creates claim one slot,
		// destroys release it. The seed is idempotent (INSERT OR IGNORE
		// on tap_name PK) so warm restarts do not re-shuffle assignments.
		//
		// sandbox_id is NULL when the slot is free, set to the owning
		// sandbox when claimed. The partial unique index below enforces
		// exactly one allocated slot per sandbox — the load-bearing
		// idempotency primitive for the Firecracker boot path (mirrors
		// the host_port partial unique index in shape and purpose; see
		// pr-review.md §5 + plans/snapshot-clone-fast-boot.md).
		`CREATE TABLE IF NOT EXISTS firecracker_tap_pool (
			tap_name TEXT PRIMARY KEY,
			cidr TEXT NOT NULL,
			host_ip TEXT NOT NULL,
			guest_ip TEXT NOT NULL,
			vsock_cid INTEGER NOT NULL,
			sandbox_id TEXT,
			created_at DATETIME NOT NULL,
			allocated_at DATETIME
		);`,
		// Partial unique index — exactly one row per sandbox at a time.
		// Two concurrent Allocate calls race to UPDATE a free slot, and
		// the index rejects a second claim under the same sandbox_id.
		// SQLite's single writer serializes the contest; the index
		// guarantees correctness if a future change ever moves us off it.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_firecracker_tap_pool_sandbox
			ON firecracker_tap_pool(sandbox_id) WHERE sandbox_id IS NOT NULL;`,
		// vsock CIDs are globally unique per host (the AF_VSOCK guest_cid
		// space is host-flat). Unique-not-partial because every row carries
		// a non-null CID — the pool is pre-allocated with monotonic CIDs
		// starting at 3 (CIDs 0/1/2 are reserved by the virtio-vsock spec).
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_firecracker_tap_pool_vsock_cid
			ON firecracker_tap_pool(vsock_cid);`,
		// firecracker_vmm_pool is the Phase 4 warm-VMM pool: one row per
		// pre-spawned, snapshot-loaded, paused Firecracker process kept
		// ready to be PATCH'd onto a per-sandbox TAP + overlay and Resumed.
		// The row IS the slot's source of truth — status transitions live
		// here, not in goroutine state, so a daemon restart can rediscover
		// what's spawning vs. loaded vs. allocated without trawling /proc.
		//
		// Lifecycle (see plans/snapshot-clone-fast-boot.md §"Piece 4 — The
		// VMM pool" and the PR-A foundation plan):
		//
		//   INSERT 'spawning' → 'loaded'    (refill goroutine, PR 4-B)
		//                     → 'released'  (spawner failed)
		//   'loaded'          → 'allocated' (sandbox create claims it)
		//   'allocated'       → 'released'  (sandbox destroyed)
		//   'released'        → row deleted (GC sweep after TTL)
		//
		// sandbox_id is NULL except in 'allocated'. The partial unique
		// index below enforces exactly one allocated slot per sandbox —
		// the load-bearing idempotency primitive for the snapshot-clone
		// boot path, mirroring firecracker_tap_pool's idx_..._sandbox in
		// shape and purpose (pr-review.md §5).
		//
		// template_id is the snapshot lineage, not a foreign key
		// constraint — a soft reference so the template-GC sweep can
		// proceed while loaded slots remain in flight; the pool GC drops
		// stragglers separately.
		`CREATE TABLE IF NOT EXISTS firecracker_vmm_pool (
			id TEXT PRIMARY KEY,
			template_id TEXT NOT NULL,
			status TEXT NOT NULL,
			sandbox_id TEXT,
			api_socket TEXT NOT NULL DEFAULT '',
			run_dir TEXT NOT NULL DEFAULT '',
			vsock_cid INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			loaded_at DATETIME,
			allocated_at DATETIME,
			released_at DATETIME,
			last_error TEXT NOT NULL DEFAULT ''
		);`,
		// Partial unique on sandbox_id — exactly one 'allocated' row per
		// sandbox at a time. Two concurrent Allocate calls race to UPDATE
		// a free 'loaded' row, and the index rejects a second claim under
		// the same sandbox_id. SQLite's single writer serializes the
		// contest; the index keeps correctness if a future change moves
		// us off it. Mirrors idx_firecracker_tap_pool_sandbox exactly.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_firecracker_vmm_pool_sandbox
			ON firecracker_vmm_pool(sandbox_id) WHERE sandbox_id IS NOT NULL;`,
		// Compound index on (template_id, status) drives the two hot
		// reads: "give me one loaded row for this template" (Allocate)
		// and "how many non-released rows does this template have?"
		// (refill goroutine in PR 4-B). Without this, both become full
		// scans once the pool grows past a handful of slots.
		`CREATE INDEX IF NOT EXISTS idx_firecracker_vmm_pool_template_status
			ON firecracker_vmm_pool(template_id, status);`,
		// Partial index on released_at keeps the GC sweep cheap even when
		// the steady-state count of released rows is zero. Predicate is
		// the GC selector verbatim so SQLite can use the index without a
		// post-filter.
		`CREATE INDEX IF NOT EXISTS idx_firecracker_vmm_pool_released_at
			ON firecracker_vmm_pool(released_at) WHERE status = 'released';`,
		// firecracker_templates is the Phase 2 catalogue: one row per
		// pre-built rootfs.ext4 the operator has registered via
		// POST /v1/templates. The build is async — the row lands in
		// status='pending' first and the background goroutine transitions
		// it to 'ready' (with rootfs_size_bytes populated and ready_at
		// stamped) or 'failed' (with last_error). The GC sweep drops rows
		// that are no longer referenced by any sandbox and have been idle
		// past FirecrackerTemplateGCTTL — see ListGCEligibleTemplates.
		`CREATE TABLE IF NOT EXISTS firecracker_templates (
			id TEXT PRIMARY KEY,
			image TEXT NOT NULL,
			status TEXT NOT NULL,
			rootfs_path TEXT NOT NULL DEFAULT '',
			rootfs_size_bytes INTEGER NOT NULL DEFAULT 0,
			min_size_mib INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			ready_at DATETIME,
			snapshot_memory_path TEXT NOT NULL DEFAULT '',
			snapshot_state_path TEXT NOT NULL DEFAULT '',
			snapshot_size_bytes INTEGER NOT NULL DEFAULT 0,
			snapshot_checksum TEXT NOT NULL DEFAULT '',
			snapshot_vsock_cid INTEGER NOT NULL DEFAULT 0,
			snapshot_error TEXT NOT NULL DEFAULT '',
			has_snapshot INTEGER NOT NULL DEFAULT 0,
			has_overlay INTEGER NOT NULL DEFAULT 0
		);`,
		// Drives the GC sweep's "find rows older than X" query without a
		// full scan once the catalogue grows beyond a handful of entries.
		`CREATE INDEX IF NOT EXISTS idx_firecracker_templates_updated_at
			ON firecracker_templates(updated_at);`,
		// wasm_modules mirrors firecracker_templates for WASM module catalogue
		// (plans/wasm-runtime.md Phase 6). One row per registered module ref.
		`CREATE TABLE IF NOT EXISTS wasm_modules (
			id TEXT PRIMARY KEY,
			module_ref TEXT NOT NULL,
			status TEXT NOT NULL,
			module_path TEXT NOT NULL DEFAULT '',
			module_size_bytes INTEGER NOT NULL DEFAULT 0,
			digest TEXT NOT NULL DEFAULT '',
			entrypoint TEXT NOT NULL DEFAULT '_start',
			has_warm INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			ready_at DATETIME
		);`,
		`CREATE INDEX IF NOT EXISTS idx_wasm_modules_updated_at
			ON wasm_modules(updated_at);`,
		`CREATE INDEX IF NOT EXISTS idx_wasm_modules_status_ref
			ON wasm_modules(status, module_ref);`,
		// Cache GC probes catalogued digests by content digest every sweep; without
		// this index that degrades to a full wasm_modules scan per cache file at
		// large cache/catalogue sizes (codex P1).
		`CREATE INDEX IF NOT EXISTS idx_wasm_modules_digest
			ON wasm_modules(digest) WHERE digest <> '';`,
		// wasm_state_kv backs the durable host-KV capability (§4.6).
		`CREATE TABLE IF NOT EXISTS wasm_state_kv (
			sandbox_id TEXT NOT NULL,
			key TEXT NOT NULL,
			value BLOB NOT NULL,
			updated_at DATETIME NOT NULL,
			PRIMARY KEY (sandbox_id, key)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_wasm_state_kv_sandbox
			ON wasm_state_kv(sandbox_id);`,
		// wasm_checkpoint_pushes tracks AOCR push history for keep-last-N (§4.8).
		//
		// Deliberate deviation from plan §4.8's "reuse sandbox_snapshots" note:
		// sandbox_snapshots models user-invoked, named snapshots (one row per
		// snapshot name, surfaced over the snapshot API). This table instead
		// records the *rolling, automatic* boundary-checkpoint pushes a durable
		// WASM sandbox emits on drain/periodic cadence — unnamed, content-addressed
		// by digest, and pruned to keep-last-N. Folding both into sandbox_snapshots
		// would mean a type discriminator column plus snapshot-API rows the user
		// never asked for. Kept separate on purpose; revisit if the two histories
		// ever need to share retention/GC machinery.
		`CREATE TABLE IF NOT EXISTS wasm_checkpoint_pushes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sandbox_id TEXT NOT NULL,
			registry_ref TEXT NOT NULL,
			digest TEXT NOT NULL,
			pushed_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_wasm_checkpoint_pushes_sandbox
			ON wasm_checkpoint_pushes(sandbox_id, pushed_at DESC);`,
		// account_mappings records the identities resolved by the optional
		// fleet control plane (managed builds only). owner_ref is the stable
		// account key stamped onto sandboxes; external_id is informational.
		// Empty on the open-source build — nothing writes here unless a
		// validator is wired. first_seen/last_seen bound an account's activity
		// window for the managed side without the open-source code needing to
		// know what they mean.
		`CREATE TABLE IF NOT EXISTS account_mappings (
			owner_ref TEXT PRIMARY KEY,
			external_id TEXT NOT NULL DEFAULT '',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("run schema statement: %w", err)
		}
	}

	// Additive migrations for sandboxes columns introduced after the original
	// schema landed. Each ALTER TABLE is run unconditionally; SQLite returns
	// "duplicate column name" when the column already exists, which we
	// swallow so cold installs (where CREATE TABLE above already includes
	// the column) and warm upgrades (where the column is new) both succeed.
	migrations := []string{
		`ALTER TABLE sandboxes ADD COLUMN toolbox_token TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN ssh_public_key TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN stop_if_idle_for_ns INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN destroy_if_idle_for_ns INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN stop_at_age_ns INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN destroy_at_age_ns INTEGER NOT NULL DEFAULT 0;`,
		// Per-sandbox owner-death policy. Empty/none means orphan on owner
		// death; "recreate" opts into best-effort cluster recreation.
		`ALTER TABLE sandboxes ADD COLUMN failover_policy TEXT NOT NULL DEFAULT '';`,
		// Per-sandbox OCI runtime selector (runc / runsc). Pre-migration rows
		// get '' and resolve to the host default at start time; new sandboxes
		// always store the resolved value so the choice cannot drift across
		// host restarts.
		`ALTER TABLE sandboxes ADD COLUMN runtime TEXT NOT NULL DEFAULT '';`,
		// GPU configuration as a JSON blob. Empty string means no GPU was
		// requested. Stored as JSON to avoid schema churn as GPU options grow.
		`ALTER TABLE sandboxes ADD COLUMN gpus_json TEXT NOT NULL DEFAULT '';`,
		// AES-GCM-sealed RegistryAuth (server, username, password) from the
		// create request. Empty blob means no credentials were supplied (public
		// registry). Sealed bytes only; the encryption key never touches this
		// table. Required for cluster failover to re-pull private images on a
		// new owner — the runtime layer drops creds after the initial pull.
		`ALTER TABLE sandboxes ADD COLUMN registry_auth_sealed BLOB NOT NULL DEFAULT X'';`,
		// Protocol of an exposed port: "http" (Caddy HTTP reverse proxy,
		// historical behavior), "tcp" (caddy-l4 listener at host_port), or
		// "tls" (caddy-l4 SNI route on the shared TLS listener).
		`ALTER TABLE exposed_ports ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http';`,
		// Parent-host TCP port reserved for protocol="tcp" exposures from the
		// configured pool. Zero for http/tls. The partial unique index below
		// rejects two reservations on the same host_port without preventing
		// many rows at the default 0.
		`ALTER TABLE exposed_ports ADD COLUMN host_port INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN net_bytes_in INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN net_bytes_out INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN net_bytes_in_limit INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN net_bytes_out_limit INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN net_quota_exceeded INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN net_quota_exceeded_at DATETIME;`,
		// Snapshot-from-image columns. Pre-existing rows (committed from a
		// running sandbox) get zero values, which scanSnapshot decodes as
		// "no extra metadata" — preserving the legacy shape.
		`ALTER TABLE sandbox_snapshots ADD COLUMN entrypoint_json TEXT NOT NULL DEFAULT '[]';`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN region_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN cpu REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN memory_mb INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN disk_gb INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN gpu REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN image_distribution_mode TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN image_digest TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN image_registry_ref TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN image_verified_at DATETIME;`,
		// Background-push lifecycle for the SB_SNAPSHOT_PUSH_ENABLED feature.
		// Default 'active' so warm-upgrade rows (created before this feature
		// existed) are treated as terminal — the reconciler ignores them.
		// New rows that need push start at 'pending' and transition through
		// 'pushing' to 'active' or 'error'.
		`ALTER TABLE sandbox_snapshots ADD COLUMN push_state TEXT NOT NULL DEFAULT 'active';`,
		`ALTER TABLE sandbox_snapshots ADD COLUMN push_error TEXT NOT NULL DEFAULT '';`,
		// auto_import_pending is set when the post-pull AOCR auto-import
		// (F21) failed and a background reconciler should retry. It is
		// local-node bookkeeping only — never replicated, never user-visible.
		// The partial index below makes the reconciler scan cheap even when
		// the steady-state count of pending rows is zero.
		`ALTER TABLE sandboxes ADD COLUMN auto_import_pending INTEGER NOT NULL DEFAULT 0;`,
		// serverless opts the sandbox into HTTP-wake behavior (see
		// models.Lifecycle.Serverless). wake_armed is internal-only
		// bookkeeping: it tracks whether the sandbox is currently stopped
		// in a state where the next inbound HTTP request should
		// transparently start it back up. Manual StopSandbox clears the
		// flag; lifecycle-driven and involuntary stops set it when
		// serverless is true. Defaults are 0 so warm-upgrade rows behave
		// exactly as before.
		`ALTER TABLE sandboxes ADD COLUMN serverless INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN wake_armed INTEGER NOT NULL DEFAULT 0;`,
		// Phase 2 — Firecracker template lineage. Default '' so warm-upgrade
		// rows (including every Docker sandbox) read as "no template
		// reference" without further migration. The partial index below is
		// what the template GC uses to answer "is anyone still using this
		// template?" without scanning the whole sandboxes table.
		`ALTER TABLE sandboxes ADD COLUMN template_id TEXT NOT NULL DEFAULT '';`,
		// Phase 3 — snapshot-clone fast-boot columns. All default to the
		// "no snapshot" zero values so a warm-upgraded Phase 2 row reads as
		// HasSnapshot=false and the runtime falls back to cold-boot. The
		// snapshot phase writes them via UpdateTemplateSnapshotReady once
		// snapshot.memory + snapshot.state are on disk.
		`ALTER TABLE firecracker_templates ADD COLUMN snapshot_memory_path TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE firecracker_templates ADD COLUMN snapshot_state_path TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE firecracker_templates ADD COLUMN snapshot_size_bytes INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE firecracker_templates ADD COLUMN snapshot_checksum TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE firecracker_templates ADD COLUMN snapshot_vsock_cid INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE firecracker_templates ADD COLUMN snapshot_error TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE firecracker_templates ADD COLUMN has_snapshot INTEGER NOT NULL DEFAULT 0;`,
		// Phase 3 PR-B — per-sandbox overlay drive plumbing. has_overlay on
		// templates lets the runtime reject snapshot-load+overlay requests
		// against PR-A templates (which lack the placeholder drive in their
		// snapshot state) with a clear "rebuild template" error rather than
		// failing mid-PATCH. overlay_size_gb on sandboxes is mirrored from
		// the create request so the runtime cleanup path knows whether
		// overlay.ext4 was allocated in the per-sandbox runDir.
		`ALTER TABLE firecracker_templates ADD COLUMN has_overlay INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE sandboxes ADD COLUMN overlay_size_gb INTEGER NOT NULL DEFAULT 0;`,
		// Phase 6 PR 6-B.1 — background push of Firecracker template
		// artifacts to AOCR. Mirrors the sandbox_snapshots push_state
		// migration above (ALTER ... ADD push_state at line ~444). Default
		// 'active' so warm-upgrade rows (built before this feature existed)
		// are treated as terminal — the reconciler ignores them. New rows
		// that need push start at 'pending' and transition through
		// 'pushing' to 'active' or 'error'. registry_ref + push_digest are
		// populated on success and read by PR 6-B.2's consumer-side pull.
		`ALTER TABLE firecracker_templates ADD COLUMN push_state TEXT NOT NULL DEFAULT 'active';`,
		`ALTER TABLE firecracker_templates ADD COLUMN push_error TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE firecracker_templates ADD COLUMN registry_ref TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE firecracker_templates ADD COLUMN push_digest TEXT NOT NULL DEFAULT '';`,
		// Per-custom-domain target port — 0 keeps the legacy toolbox-port
		// behavior for rows attached before this column existed, so the
		// upgrade is silent.
		`ALTER TABLE sandbox_custom_domains ADD COLUMN target_port INTEGER NOT NULL DEFAULT 0;`,
		// Fleet control plane (managed builds). owner_ref is the account key a
		// sandbox is attributed to; empty means operator/PAT-created (the only
		// possibility on the open-source build, where no validator resolves
		// user tokens). fleet_suspended marks a sandbox stopped by a standing
		// directive so recovery can restart exactly those — distinguishing a
		// fleet-suspend from an operator/user stop. Both default to the
		// open-source baseline so warm upgrades are silent.
		`ALTER TABLE sandboxes ADD COLUMN owner_ref TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN fleet_suspended INTEGER NOT NULL DEFAULT 0;`,
		// Durability class (plans/wasm-runtime.md D7). Pre-migration rows default
		// to passivatable — container/VM runtimes survive restarts natively.
		// durability is a shared concept (every runtime declares one) so it lives
		// on the sandboxes row.
		`ALTER TABLE sandboxes ADD COLUMN durability TEXT NOT NULL DEFAULT 'passivatable';`,
		// The columns below are WASM-only: they are empty for docker/firecracker
		// rows. They live on the shared sandboxes row (rather than a 1:1
		// wasm_sandbox_state side-table) for phase 1 because reconcile, the
		// failover/clone-generation fencing path, and rehydrate all read them on
		// the hot list/scan path, and a per-row LEFT JOIN there is not worth it at
		// this column count. Empty TEXT columns are ~free in SQLite. If the
		// WASM-specific column set keeps growing, migrate these into a side-table
		// keyed by sandbox_id (same shape as wasm_state_kv). Note module_ref
		// overlaps the image column (the start path falls back to image when
		// module_ref is empty) and clone_generation mirrors the toolboxd clonegen
		// token.
		`ALTER TABLE sandboxes ADD COLUMN module_ref TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN module_digest TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN checkpoint_path TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN clone_generation TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN wasm_registry_ref TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sandboxes ADD COLUMN wasm_registry_digest TEXT NOT NULL DEFAULT '';`,
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("apply schema migration %q: %w", stmt, err)
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

	// Partial index keeps the auto-import reconciler scan O(pending), not
	// O(sandboxes). Steady-state count is zero so the index footprint is
	// negligible; spikes happen when AOCR is briefly unreachable.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sandboxes_auto_import_pending ON sandboxes(id) WHERE auto_import_pending = 1;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create sandboxes auto_import_pending index: %w", err)
	}

	// Partial index on the new template_id column. The template GC and
	// DELETE-template both call IsTemplateReferenced (a SELECT 1 ... WHERE
	// template_id = ? LIMIT 1) which becomes an index probe instead of a
	// table scan. Predicate keeps the index empty for Docker sandboxes and
	// for Firecracker sandboxes built from ad-hoc images.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sandboxes_template_id ON sandboxes(template_id) WHERE template_id <> '';`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create sandboxes template_id index: %w", err)
	}

	// WASM module GC checks whether any sandbox still references a catalogue
	// row by module_ref or module_digest. These columns are compatibility
	// migrations, so create the indexes after the ALTER loop above.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sandboxes_module_ref ON sandboxes(module_ref) WHERE module_ref <> '';`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create sandboxes module_ref index: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sandboxes_module_digest ON sandboxes(module_digest) WHERE module_digest <> '';`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create sandboxes module_digest index: %w", err)
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
			failover_policy,
			runtime, gpus_json,
			net_bytes_in, net_bytes_out, net_bytes_in_limit, net_bytes_out_limit,
			net_quota_exceeded, net_quota_exceeded_at,
			registry_auth_sealed,
			auto_import_pending,
			serverless, wake_armed,
			template_id,
			overlay_size_gb,
			durability,
			module_ref, module_digest,
			checkpoint_path, clone_generation,
			wasm_registry_ref, wasm_registry_digest,
			owner_ref, fleet_suspended
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		sandboxFailoverPolicy(sandbox),
		sandbox.Runtime,
		gpusJSON,
		sandbox.NetworkBytesIn,
		sandbox.NetworkBytesOut,
		sandbox.NetworkBytesInLimit,
		sandbox.NetworkBytesOutLimit,
		boolToInt(sandbox.NetworkQuotaExceeded),
		nullableTime(sandbox.NetworkQuotaExceededAt),
		nullableBlob(sandbox.RegistryAuthSealed),
		boolToInt(sandbox.AutoImportPending),
		boolToInt(sandbox.Lifecycle.Serverless),
		boolToInt(sandbox.WakeArmed),
		strings.TrimSpace(sandbox.TemplateID),
		sandbox.OverlaySizeGB,
		sandboxDurability(sandbox),
		strings.TrimSpace(sandbox.ModuleRef),
		strings.TrimSpace(sandbox.ModuleDigest),
		strings.TrimSpace(sandbox.CheckpointPath),
		strings.TrimSpace(sandbox.CloneGeneration),
		strings.TrimSpace(sandbox.WasmRegistryRef),
		strings.TrimSpace(sandbox.WasmRegistryDigest),
		strings.TrimSpace(sandbox.OwnerRef),
		boolToInt(sandbox.FleetSuspended),
	)
	if err != nil {
		if isSandboxNameConflict(err, sandbox.Name) {
			return ErrSandboxNameConflict
		}
		return fmt.Errorf("insert sandbox: %w", err)
	}
	return nil
}

// nullableBlob normalizes a nil byte slice to an empty one so SQLite stores
// X” rather than NULL for the registry_auth_sealed column.
func nullableBlob(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func sandboxDurability(sandbox *models.Sandbox) string {
	if sandbox == nil || strings.TrimSpace(sandbox.Durability) == "" {
		return models.DurabilityPassivatable
	}
	return strings.TrimSpace(sandbox.Durability)
}

func sandboxFailoverPolicy(sandbox *models.Sandbox) string {
	if sandbox == nil || sandbox.Failover == nil {
		return ""
	}
	policy, err := models.NormalizeFailoverPolicy(sandbox.Failover.Policy)
	if err != nil || policy == models.FailoverPolicyNone {
		return ""
	}
	return policy
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
			failover_policy,
			runtime, gpus_json,
			net_bytes_in, net_bytes_out, net_bytes_in_limit, net_bytes_out_limit,
			net_quota_exceeded, net_quota_exceeded_at,
			registry_auth_sealed,
			auto_import_pending,
			serverless, wake_armed,
			template_id,
			overlay_size_gb,
			durability,
			module_ref, module_digest,
			checkpoint_path, clone_generation,
			wasm_registry_ref, wasm_registry_digest,
			owner_ref, fleet_suspended
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			failover_policy = excluded.failover_policy,
			runtime = excluded.runtime,
			gpus_json = excluded.gpus_json,
			net_bytes_in_limit = excluded.net_bytes_in_limit,
			net_bytes_out_limit = excluded.net_bytes_out_limit,
			registry_auth_sealed = excluded.registry_auth_sealed,
			auto_import_pending = excluded.auto_import_pending,
			serverless = excluded.serverless,
			wake_armed = excluded.wake_armed,
			template_id = excluded.template_id,
			overlay_size_gb = excluded.overlay_size_gb,
			durability = excluded.durability,
			module_ref = excluded.module_ref,
			module_digest = excluded.module_digest,
			checkpoint_path = excluded.checkpoint_path,
			clone_generation = excluded.clone_generation,
			wasm_registry_ref = excluded.wasm_registry_ref,
			wasm_registry_digest = excluded.wasm_registry_digest,
			owner_ref = excluded.owner_ref,
			fleet_suspended = excluded.fleet_suspended
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
		sandboxFailoverPolicy(sandbox),
		sandbox.Runtime,
		gpusJSON,
		sandbox.NetworkBytesIn,
		sandbox.NetworkBytesOut,
		sandbox.NetworkBytesInLimit,
		sandbox.NetworkBytesOutLimit,
		boolToInt(sandbox.NetworkQuotaExceeded),
		nullableTime(sandbox.NetworkQuotaExceededAt),
		nullableBlob(sandbox.RegistryAuthSealed),
		boolToInt(sandbox.AutoImportPending),
		boolToInt(sandbox.Lifecycle.Serverless),
		boolToInt(sandbox.WakeArmed),
		strings.TrimSpace(sandbox.TemplateID),
		sandbox.OverlaySizeGB,
		sandboxDurability(sandbox),
		strings.TrimSpace(sandbox.ModuleRef),
		strings.TrimSpace(sandbox.ModuleDigest),
		strings.TrimSpace(sandbox.CheckpointPath),
		strings.TrimSpace(sandbox.CloneGeneration),
		strings.TrimSpace(sandbox.WasmRegistryRef),
		strings.TrimSpace(sandbox.WasmRegistryDigest),
		strings.TrimSpace(sandbox.OwnerRef),
		boolToInt(sandbox.FleetSuspended),
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
			failover_policy,
			runtime, gpus_json,
			net_bytes_in, net_bytes_out, net_bytes_in_limit, net_bytes_out_limit,
			net_quota_exceeded, net_quota_exceeded_at,
			registry_auth_sealed,
			auto_import_pending,
			serverless, wake_armed,
			template_id,
			overlay_size_gb,
			durability,
			module_ref, module_digest,
			checkpoint_path, clone_generation,
			wasm_registry_ref, wasm_registry_digest,
			owner_ref, fleet_suspended
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

	customDomains, err := s.loadCustomDomains(ctx, id)
	if err != nil {
		return nil, err
	}
	sandbox.CustomDomains = customDomains

	return sandbox, nil
}

func (s *Store) List(ctx context.Context) ([]*models.Sandbox, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, name, tags_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			failover_policy,
			runtime, gpus_json,
			net_bytes_in, net_bytes_out, net_bytes_in_limit, net_bytes_out_limit,
			net_quota_exceeded, net_quota_exceeded_at,
			registry_auth_sealed,
			auto_import_pending,
			serverless, wake_armed,
			template_id,
			overlay_size_gb,
			durability,
			module_ref, module_digest,
			checkpoint_path, clone_generation,
			wasm_registry_ref, wasm_registry_digest,
			owner_ref, fleet_suspended
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
		if err := s.attachCustomDomainsBulk(ctx, byID); err != nil {
			return nil, err
		}
	}

	return sandboxes, nil
}

// ListByOwner returns the sandboxes attributed to ownerRef, newest first. It is
// the owner-scoped counterpart of List: the API edge uses it to fence a user
// token to its own sandboxes, and the fleet enforcement loop uses it to fan a
// standing directive (stop/restore/delete) across one account. An empty
// ownerRef matches operator/PAT-created rows; callers that want the whole fleet
// use List instead. Ports and custom domains are intentionally not attached
// here — the current callers (scoping filter, enforcement) only need identity
// and lifecycle fields, so we skip the bulk joins.
func (s *Store) ListByOwner(ctx context.Context, ownerRef string) ([]*models.Sandbox, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb,
			os_user, env_json, network_block_all, toolbox_enabled, toolbox_token, ssh_public_key,
			last_error, container_command_json, name, tags_json, created_at, updated_at, last_active_at,
			stop_if_idle_for_ns, destroy_if_idle_for_ns, stop_at_age_ns, destroy_at_age_ns,
			failover_policy,
			runtime, gpus_json,
			net_bytes_in, net_bytes_out, net_bytes_in_limit, net_bytes_out_limit,
			net_quota_exceeded, net_quota_exceeded_at,
			registry_auth_sealed,
			auto_import_pending,
			serverless, wake_armed,
			template_id,
			overlay_size_gb,
			durability,
			module_ref, module_digest,
			checkpoint_path, clone_generation,
			wasm_registry_ref, wasm_registry_digest,
			owner_ref, fleet_suspended
		FROM sandboxes
		WHERE owner_ref = ?
		ORDER BY created_at DESC
	`, strings.TrimSpace(ownerRef))
	if err != nil {
		return nil, fmt.Errorf("list sandboxes by owner: %w", err)
	}
	defer rows.Close()

	var sandboxes []*models.Sandbox
	for rows.Next() {
		sandbox, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		sandboxes = append(sandboxes, sandbox)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sandboxes by owner: %w", err)
	}
	return sandboxes, nil
}

// SetFleetSuspended flips the fleet-suspend marker on a sandbox. The
// enforcement loop sets it true when a standing=suspend directive stops a
// running sandbox, and clears it on recovery so only fleet-suspended sandboxes
// are auto-restarted (a user/operator stop is left alone). Idempotent: writing
// the same value twice is a harmless no-op UPDATE. Returns ErrNotFound if the
// row is gone (already deleted), which callers treat as success — there is
// nothing left to converge.
func (s *Store) SetFleetSuspended(ctx context.Context, id string, suspended bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sandboxes SET fleet_suspended = ?, updated_at = ? WHERE id = ?`,
		boolToInt(suspended), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set fleet_suspended: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set fleet_suspended rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertAccountMapping records (or refreshes) an identity resolved by the fleet
// control plane. first_seen is preserved across calls; last_seen advances to
// now. Idempotent by owner_ref PK. Open-source builds never call this (no
// validator resolves user tokens); managed builds call it at create time, not
// per request, to keep the auth hot path write-free.
func (s *Store) UpsertAccountMapping(ctx context.Context, ownerRef, externalID string) error {
	ownerRef = strings.TrimSpace(ownerRef)
	if ownerRef == "" {
		return fmt.Errorf("upsert account mapping: empty owner_ref")
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO account_mappings (owner_ref, external_id, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(owner_ref) DO UPDATE SET
			external_id = excluded.external_id,
			last_seen = excluded.last_seen
	`, ownerRef, strings.TrimSpace(externalID), now, now)
	if err != nil {
		return fmt.Errorf("upsert account mapping: %w", err)
	}
	return nil
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

// SchedulePendingImageGC records (or refreshes) a pending image-deletion
// row. UPSERT on the image PK means concurrent or repeated destroys
// collapse to one row and the TTL clock restarts from the most recent
// destroy — so a busy churn pattern on the same image keeps deferring
// removal instead of racing the janitor. Empty image is a no-op.
func (s *Store) SchedulePendingImageGC(ctx context.Context, image string, at time.Time) error {
	if image == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_image_gc(image, scheduled_at)
		VALUES (?, ?)
		ON CONFLICT(image) DO UPDATE SET scheduled_at = excluded.scheduled_at
	`, image, at.UTC())
	if err != nil {
		return fmt.Errorf("schedule pending image gc: %w", err)
	}
	return nil
}

// PendingImageGCEntry is one row from the pending_image_gc ledger.
// scheduled_at travels with the image so the janitor can pin its
// remove/delete decision to the exact row it observed — see
// DeletePendingImageGCIfScheduledAt for the refresh-race rationale.
type PendingImageGCEntry struct {
	Image       string
	ScheduledAt time.Time
}

// ListPendingImageGCDue returns rows whose scheduled_at is at or before
// cutoff (the janitor passes now - ImageBuildGCTTL). Ordered by
// scheduled_at so the oldest entries get GC'd first within a sweep.
// `limit` caps the batch so a backlog (janitor disabled for a while
// then re-enabled, or just thousands of destroyed sandboxes sharing a
// few images) doesn't fan out into one huge serial Docker spike per
// tick — pass 0 for unbounded. scheduled_at is returned so the caller
// can guard the conditional delete in DeletePendingImageGCIfScheduledAt.
func (s *Store) ListPendingImageGCDue(ctx context.Context, cutoff time.Time, limit int) ([]PendingImageGCEntry, error) {
	query := `
		SELECT image, scheduled_at FROM pending_image_gc
		WHERE scheduled_at <= ?
		ORDER BY scheduled_at
	`
	args := []any{cutoff.UTC()}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list pending image gc due: %w", err)
	}
	defer rows.Close()
	var out []PendingImageGCEntry
	for rows.Next() {
		var entry PendingImageGCEntry
		if err := rows.Scan(&entry.Image, &entry.ScheduledAt); err != nil {
			return nil, fmt.Errorf("scan pending image gc row: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending image gc rows: %w", err)
	}
	return out, nil
}

// DeletePendingImageGC removes the ledger row for an image
// unconditionally. Used when the janitor decides the image is back in
// use (HasActiveImageRef = true) and the row should be dropped
// regardless of timestamp — the destroy path will re-schedule with a
// fresh timestamp if the image goes idle again. Missing rows are not
// an error.
func (s *Store) DeletePendingImageGC(ctx context.Context, image string) error {
	if image == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM pending_image_gc WHERE image = ?`, image); err != nil {
		return fmt.Errorf("delete pending image gc: %w", err)
	}
	return nil
}

// RefreshPendingImageGCIfExists pushes the row's scheduled_at forward
// when (and only when) a row for image is already present. The Create
// path calls this after store.Create succeeds, so a freshly-used image
// that previously had a pending GC gets its deadline reset from "now"
// instead of inheriting the original destroy's old timestamp.
//
// UPDATE-only (not UPSERT) on purpose: a row should only ever exist
// when a destroy has scheduled an image for cleanup. We do NOT want
// the create path inserting one — that would turn pending_image_gc
// into a one-row-per-image-ever-used table. The row-count stays
// bounded by "images destroyed in the last TTL window". Returns
// whether a row was touched, so callers can distinguish "deadline
// pushed forward" from "no pending GC, nothing to push".
func (s *Store) RefreshPendingImageGCIfExists(ctx context.Context, image string, at time.Time) (bool, error) {
	if image == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_image_gc
		SET scheduled_at = ?
		WHERE image = ?
	`, at.UTC(), image)
	if err != nil {
		return false, fmt.Errorf("refresh pending image gc: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
}

// DeletePendingImageGCIfScheduledAt removes the row only if its
// scheduled_at still matches `at` — i.e. nobody has refreshed the row
// since the janitor observed it. Returns whether the delete actually
// happened so the caller can detect the refresh race.
//
// Why this exists: the sweep does (list, [check active, remove image,
// delete row]). If a destroy of another sandbox sharing the image
// upserts the row with a fresh timestamp between the list and the
// delete, an unconditional delete would silently throw away the
// extended TTL that destroy was supposed to buy. The janitor uses this
// to keep the "TTL clock restarts from the most recent destroy"
// contract under churn.
func (s *Store) DeletePendingImageGCIfScheduledAt(ctx context.Context, image string, at time.Time) (bool, error) {
	if image == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM pending_image_gc
		WHERE image = ? AND scheduled_at = ?
	`, image, at.UTC())
	if err != nil {
		return false, fmt.Errorf("conditional delete pending image gc: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
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

// UpdateLifecycle replaces the lifecycle fields on a sandbox row (the four
// timers plus the serverless opt-in) and bumps updated_at. Other fields are
// untouched. Returns ErrNotFound if no row matches id. The caller must
// validate the Lifecycle first; the store does not re-validate (it would
// couple two layers for no gain). wake_armed is intentionally NOT touched
// here — it transitions on stop/wake events, not on lifecycle edits.
func (s *Store) UpdateLifecycle(ctx context.Context, id string, l models.Lifecycle) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET stop_if_idle_for_ns = ?,
		    destroy_if_idle_for_ns = ?,
		    stop_at_age_ns = ?,
		    destroy_at_age_ns = ?,
		    serverless = ?,
		    updated_at = ?
		WHERE id = ?
	`,
		int64(l.StopIfIdleFor),
		int64(l.DestroyIfIdleFor),
		int64(l.StopAtAge),
		int64(l.DestroyAtAge),
		boolToInt(l.Serverless),
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

// UpdateSandboxNetCounters bumps the cumulative ingress/egress counters by
// the given deltas. Both values are non-negative byte counts measured since
// the last sample. Concurrent calls are serialized by SQLite's single
// writer, and the UPDATE is atomic so a failed sample never partially
// applies. Returns ErrNotFound if the sandbox row was deleted between the
// poller's snapshot and this write — the netstats poller treats that as a
// cleanup signal and drops the in-memory baseline.
func (s *Store) UpdateSandboxNetCounters(ctx context.Context, id string, deltaIn, deltaOut int64) error {
	if deltaIn < 0 || deltaOut < 0 {
		return fmt.Errorf("net counter deltas must be non-negative (in=%d out=%d)", deltaIn, deltaOut)
	}
	if deltaIn == 0 && deltaOut == 0 {
		return nil
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET net_bytes_in = net_bytes_in + ?,
		    net_bytes_out = net_bytes_out + ?,
		    updated_at = ?
		WHERE id = ?
	`, deltaIn, deltaOut, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update sandbox net counters: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNetworkLimits replaces the per-sandbox network byte caps. Zero means
// unlimited; negative values are rejected. The handler validates first so
// the store does not re-validate. Returns ErrNotFound if no row matches id.
func (s *Store) SetNetworkLimits(ctx context.Context, id string, bytesInLimit, bytesOutLimit int64) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET net_bytes_in_limit = ?,
		    net_bytes_out_limit = ?,
		    updated_at = ?
		WHERE id = ?
	`, bytesInLimit, bytesOutLimit, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set sandbox net limits: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkNetworkQuotaExceeded flips the flag on. detectedAt records when the
// crossover was first observed so the API can surface it to the SDK. Calls
// when already-exceeded preserve the original detectedAt — the trigger time
// is the interesting one, not the most recent re-observation.
func (s *Store) MarkNetworkQuotaExceeded(ctx context.Context, id string, detectedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET net_quota_exceeded = 1,
		    net_quota_exceeded_at = COALESCE(net_quota_exceeded_at, ?),
		    updated_at = ?
		WHERE id = ?
	`, detectedAt.UTC(), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("mark sandbox network quota exceeded: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearNetworkQuotaExceeded resets the flag and the detection timestamp.
// Used when an operator raises the limit (or sets it to unlimited) and the
// counter is no longer over the new ceiling.
func (s *Store) ClearNetworkQuotaExceeded(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET net_quota_exceeded = 0,
		    net_quota_exceeded_at = NULL,
		    updated_at = ?
		WHERE id = ?
	`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("clear sandbox network quota exceeded: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetWakeArmed toggles the wake_armed flag and bumps updated_at. The flag
// is set when the sandbox stops in a way that should auto-resume on the
// next inbound HTTP request (lifecycle idle / involuntary exit, both
// while Lifecycle.Serverless is true). It is cleared on a manual stop and
// after a successful wake. Returns ErrNotFound if no row matches id.
//
// This is a dedicated setter rather than going through Upsert so the
// stop-event path and wake completion don't race the rest of the runtime
// state on the row (status, container_id, container_ip, etc.).
func (s *Store) SetWakeArmed(ctx context.Context, id string, armed bool) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET wake_armed = ?,
		    updated_at = ?
		WHERE id = ?
	`, boolToInt(armed), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set wake_armed: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAutoImportPending toggles the AOCR auto-import retry flag. The post-pull
// auto-import path sets it to true on failure; the reconciler clears it after
// a successful import. The reconciler must call this rather than Upsert to
// avoid racing the runtime-state machine on the rest of the sandbox row.
func (s *Store) SetAutoImportPending(ctx context.Context, id string, pending bool) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET auto_import_pending = ?,
		    updated_at = ?
		WHERE id = ?
	`, boolToInt(pending), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set auto_import_pending: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAutoImportPendingIDs returns the IDs of sandboxes whose post-pull
// auto-import has not yet succeeded. Returns IDs only (not full Sandbox
// rows) so the reconciler can fetch+retry one at a time and skip rows that
// have meanwhile been deleted without holding a large in-memory snapshot.
// Hits the partial index on (auto_import_pending = 1).
func (s *Store) ListAutoImportPendingIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM sandboxes
		WHERE auto_import_pending = 1
		ORDER BY updated_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list auto_import_pending sandboxes: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan auto_import_pending id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
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
	entrypointJSON, err := marshalJSON(snapshot.Entrypoint, "[]")
	if err != nil {
		return err
	}
	var imageVerifiedAt any
	if snapshot.ImageVerifiedAt != nil {
		imageVerifiedAt = snapshot.ImageVerifiedAt.UTC()
	}
	pushState := strings.TrimSpace(snapshot.PushState)
	if pushState == "" {
		pushState = models.SnapshotPushStateActive
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sandbox_snapshots (name, image, image_id, source_sandbox_id, created_at,
			entrypoint_json, region_id, cpu, memory_mb, disk_gb, gpu,
			image_distribution_mode, image_digest, image_registry_ref, image_verified_at,
			push_state, push_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		strings.TrimSpace(snapshot.Name),
		strings.TrimSpace(snapshot.Image),
		strings.TrimSpace(snapshot.ImageID),
		strings.TrimSpace(snapshot.SourceSandboxID),
		snapshot.CreatedAt.UTC(),
		entrypointJSON,
		strings.TrimSpace(snapshot.RegionID),
		snapshot.CPU,
		snapshot.MemoryMB,
		snapshot.DiskGB,
		snapshot.GPU,
		strings.TrimSpace(snapshot.ImageDistributionMode),
		strings.TrimSpace(snapshot.ImageDigest),
		strings.TrimSpace(snapshot.ImageRegistryRef),
		imageVerifiedAt,
		pushState,
		strings.TrimSpace(snapshot.PushError),
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
		SELECT name, image, image_id, source_sandbox_id, created_at,
			entrypoint_json, region_id, cpu, memory_mb, disk_gb, gpu,
			image_distribution_mode, image_digest, image_registry_ref, image_verified_at,
			push_state, push_error
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
		SELECT name, image, image_id, source_sandbox_id, created_at,
			entrypoint_json, region_id, cpu, memory_mb, disk_gb, gpu,
			image_distribution_mode, image_digest, image_registry_ref, image_verified_at,
			push_state, push_error
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

// CreateTemplate inserts a freshly-allocated template row. Callers set
// status=pending and an empty rootfs_path; the build goroutine flips both
// via UpdateTemplateStatus once mkfs returns. A PK collision becomes
// ErrTemplateIDConflict so an operator pipeline that retries POST with an
// explicit ID gets a 409 instead of a 500.
func (s *Store) CreateTemplate(ctx context.Context, template *models.Template) error {
	if template == nil {
		return errors.New("create template: nil template")
	}
	id := strings.TrimSpace(template.ID)
	if id == "" {
		return errors.New("create template: id is required")
	}
	image := strings.TrimSpace(template.Image)
	if image == "" {
		return errors.New("create template: image is required")
	}
	status := string(template.Status)
	if status == "" {
		status = string(models.TemplateStatusPending)
	}
	var readyAt any
	if template.ReadyAt != nil {
		readyAt = template.ReadyAt.UTC()
	}
	// push_state defaults to "active" when the caller leaves it blank so
	// CreateTemplate stays backward-compatible with code paths that don't
	// know about the Phase 6 PR 6-B.1 push pipeline. The build success
	// hook in template.go flips it to "pending" after the row is in
	// status=ready, so the reconciler never sees a half-built row.
	pushState := strings.TrimSpace(template.PushState)
	if pushState == "" {
		pushState = models.TemplatePushStateActive
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO firecracker_templates (
			id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		id,
		image,
		status,
		strings.TrimSpace(template.RootfsPath),
		template.RootfsSizeBytes,
		template.MinSizeMiB,
		template.LastError,
		template.CreatedAt.UTC(),
		template.UpdatedAt.UTC(),
		readyAt,
		strings.TrimSpace(template.SnapshotMemoryPath),
		strings.TrimSpace(template.SnapshotStatePath),
		template.SnapshotSizeBytes,
		strings.TrimSpace(template.SnapshotChecksum),
		template.SnapshotVsockCID,
		template.SnapshotError,
		boolToInt(template.HasSnapshot),
		boolToInt(template.HasOverlay),
		pushState,
		template.PushError,
		strings.TrimSpace(template.RegistryRef),
		strings.TrimSpace(template.PushDigest),
	)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return ErrTemplateIDConflict
		}
		return fmt.Errorf("create template: %w", err)
	}
	return nil
}

func (s *Store) GetTemplate(ctx context.Context, id string) (*models.Template, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		FROM firecracker_templates
		WHERE id = ?
	`, strings.TrimSpace(id))
	template, err := scanTemplate(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get template: %w", err)
	}
	return template, nil
}

func (s *Store) ListTemplates(ctx context.Context) ([]*models.Template, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		FROM firecracker_templates
		ORDER BY created_at DESC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	defer rows.Close()

	var items []*models.Template
	for rows.Next() {
		template, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan template: %w", err)
		}
		items = append(items, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate templates: %w", err)
	}
	return items, nil
}

// UpdateTemplateStatus is the rootfs-phase seam the build goroutine uses
// to transition between pending / building_rootfs / ready / ready_no_snapshot
// / failed. rootfsPath, sizeBytes, and lastError are overwritten
// unconditionally (including to empty on the success path) so a retried
// build that succeeds doesn't have to remember to clear stale error text.
// ready_at is stamped on the ready and ready_no_snapshot transitions
// (both are terminal-and-usable states); the GC sweep treats "no ready_at"
// as "never finished building" and leaves the row alone for the build
// goroutine to finish or fail.
//
// The snapshot phase uses UpdateTemplateSnapshotReady / Failed instead so
// the snapshot columns and the ready transition land in one row update —
// readers never observe "status=ready but has_snapshot=0".
func (s *Store) UpdateTemplateStatus(ctx context.Context, id string, status models.TemplateStatus, rootfsPath, lastError string, sizeBytes int64) error {
	now := time.Now().UTC()
	var readyAt any
	if status == models.TemplateStatusReady || status == models.TemplateStatusReadyNoSnapshot {
		readyAt = now
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET status = ?, rootfs_path = ?, rootfs_size_bytes = ?, last_error = ?,
			updated_at = ?, ready_at = COALESCE(?, ready_at)
		WHERE id = ?
	`,
		string(status),
		strings.TrimSpace(rootfsPath),
		sizeBytes,
		lastError,
		now,
		readyAt,
		strings.TrimSpace(id),
	)
	if err != nil {
		return fmt.Errorf("update template status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTemplateSnapshotReady is the terminal-success seam for the
// snapshot phase. Writes the snapshot artifact metadata and flips
// status=ready / has_snapshot=1 / has_overlay=hasOverlay in one UPDATE
// so a concurrent reader (CreateSandbox racing the build goroutine)
// never observes "status=ready but the snapshot fields are still zero".
// snapshot_error is unconditionally cleared so a retried build that
// finally succeeds doesn't carry a stale message. hasOverlay is true
// for every PR-B-built template (the snapshot capture path always
// includes the overlay placeholder); kept as a parameter so a future
// "snapshot without overlay" build profile (e.g. a tiny boot-only
// template) does not require a schema change.
func (s *Store) UpdateTemplateSnapshotReady(ctx context.Context, id, memPath, statePath string, sizeBytes int64, checksum string, vsockCID uint32, hasOverlay bool) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET status = ?, snapshot_memory_path = ?, snapshot_state_path = ?,
			snapshot_size_bytes = ?, snapshot_checksum = ?, snapshot_vsock_cid = ?,
			snapshot_error = '', has_snapshot = 1, has_overlay = ?,
			updated_at = ?, ready_at = COALESCE(?, ready_at)
		WHERE id = ?
	`,
		string(models.TemplateStatusReady),
		strings.TrimSpace(memPath),
		strings.TrimSpace(statePath),
		sizeBytes,
		strings.TrimSpace(checksum),
		vsockCID,
		boolToInt(hasOverlay),
		now,
		now,
		strings.TrimSpace(id),
	)
	if err != nil {
		return fmt.Errorf("update template snapshot ready: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTemplateSnapshotFailed records the snapshot-phase error and flips
// status to ready_no_snapshot. The rootfs columns are untouched — the
// caller has already populated them via UpdateTemplateStatus during the
// rootfs phase, and the cold-boot fallback still needs the rootfs path
// intact. has_snapshot stays 0 (column default) so readers correctly skip
// the snapshot-load path.
func (s *Store) UpdateTemplateSnapshotFailed(ctx context.Context, id, snapshotError string) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET status = ?, snapshot_error = ?, has_snapshot = 0,
			updated_at = ?, ready_at = COALESCE(?, ready_at)
		WHERE id = ?
	`,
		string(models.TemplateStatusReadyNoSnapshot),
		snapshotError,
		now,
		now,
		strings.TrimSpace(id),
	)
	if err != nil {
		return fmt.Errorf("update template snapshot failed: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkTemplateUnhealthy is the Phase 6 PR-A transition for "snapshot
// was ready, now corrupt at load time". The WHERE status='ready' guard
// is the idempotency primitive: many concurrent Creates can hit the
// same corrupt snapshot in a burst, and only the first call's UPDATE
// affects a row — subsequent calls return (false, nil). Callers gate
// the async rebuild kick on changed=true so exactly one rebuild fires
// per corruption event.
//
// has_snapshot is cleared in the same row update so the resolver and
// the warm-pool lister both see HasSnapshot=false on the next read —
// the cold-boot fallback fires until the rebuild succeeds. The
// snapshot artifact paths are kept on the row for forensic inspection;
// the rebuild overwrites them in place.
//
// snapshot_error captures the corruption reason for operator-facing
// surfaces (the GET /v1/templates/{id} payload, future runbooks). The
// status itself is the alertable signal; the message is the
// human-readable detail.
func (s *Store) MarkTemplateUnhealthy(ctx context.Context, id, reason string) (bool, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET status = ?, snapshot_error = ?, has_snapshot = 0, updated_at = ?
		WHERE id = ? AND status = ?
	`,
		string(models.TemplateStatusUnhealthy),
		reason,
		now,
		strings.TrimSpace(id),
		string(models.TemplateStatusReady),
	)
	if err != nil {
		return false, fmt.Errorf("mark template unhealthy: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mark template unhealthy rows affected: %w", err)
	}
	return affected == 1, nil
}

// MarkTemplatePushPending is the kickTemplateBuild success-path seam
// for Phase 6 PR 6-B.1. Idempotent and state-guarded: the WHERE clause
// only flips rows whose push_state is currently "active", so a row
// that the reconciler is already working on (pending|pushing) is left
// alone. push_error is cleared because a freshly-built artifact is a
// fresh attempt — any prior failure no longer applies.
//
// Returns (true, nil) when the row moved, (false, nil) when the row
// did not exist OR was already pending/pushing/error. Callers can
// gate their reconciler-kick on changed=true so a no-op transition
// doesn't fire an extra reconciler tick.
func (s *Store) MarkTemplatePushPending(ctx context.Context, id string) (bool, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET push_state = ?, push_error = '', updated_at = ?
		WHERE id = ? AND push_state = ?
	`,
		models.TemplatePushStatePending,
		now,
		strings.TrimSpace(id),
		models.TemplatePushStateActive,
	)
	if err != nil {
		return false, fmt.Errorf("mark template push pending: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mark template push pending rows affected: %w", err)
	}
	return affected == 1, nil
}

// ListTemplatesPendingPush returns the templates the reconciler should
// retry: push_state IN ('pending', 'error'). 'pushing' is intentionally
// excluded so a row currently being processed by another reconciler
// tick is not re-claimed before its terminal state lands. Mirrors
// ListSnapshotsPendingPush exactly.
//
// The status precondition (must be ready) keeps half-built templates
// from sneaking into the push queue if someone manually flipped
// push_state. The reconciler enforces the same guard defensively, but
// filtering at the source means we never even materialize the row.
func (s *Store) ListTemplatesPendingPush(ctx context.Context) ([]*models.Template, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		FROM firecracker_templates
		WHERE push_state IN ('pending', 'error') AND status = ?
		ORDER BY created_at ASC, id ASC
	`, string(models.TemplateStatusReady))
	if err != nil {
		return nil, fmt.Errorf("list templates pending push: %w", err)
	}
	defer rows.Close()

	var items []*models.Template
	for rows.Next() {
		template, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan template: %w", err)
		}
		items = append(items, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate templates: %w", err)
	}
	return items, nil
}

// ListUnhealthyTemplates returns every template row sitting in
// status='unhealthy'. The daemon-start scanner in
// service.RekickUnhealthyTemplatesAtStart sweeps this list once at boot
// and kicks RebuildTemplateSnapshot for each row, closing the
// crash-mid-rebuild gap: if sandboxd died after MarkTemplateUnhealthy
// flipped the row but before the in-process kicker finished, the row
// would otherwise be stuck unhealthy forever — every create against
// that template would fail with a confusing "template unhealthy"
// error and only operator intervention would resolve it.
//
// Mirrors ListTemplatesPendingPush in shape (same SELECT projection,
// different WHERE) so the scan path is uniform with the existing push
// reconciler. No status precondition beyond status='unhealthy' itself
// — the rebuild path inside RebuildTemplateSnapshot re-checks the row
// under its own read, so a row that another caller already recovered
// between this list and the rebuild kick is handled cleanly.
func (s *Store) ListUnhealthyTemplates(ctx context.Context) ([]*models.Template, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		FROM firecracker_templates
		WHERE status = ?
		ORDER BY created_at ASC, id ASC
	`, string(models.TemplateStatusUnhealthy))
	if err != nil {
		return nil, fmt.Errorf("list unhealthy templates: %w", err)
	}
	defer rows.Close()

	var items []*models.Template
	for rows.Next() {
		template, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan template: %w", err)
		}
		items = append(items, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate templates: %w", err)
	}
	return items, nil
}

// ListTemplatesReadyBefore returns the `ready` templates whose
// `ready_at` is older than the cutoff. Used by the Phase 6 PR-E
// rotation reconciler to find rebuild candidates. Only `ready` (not
// `ready_no_snapshot`) qualifies — rotating a ready_no_snapshot row
// would just re-burn build budget without delivering the rotation's
// goal (refreshing the snapshot's kernel + toolbox bytes).
//
// Returns rows sorted oldest-first so a reconcile sweep that hits its
// per-tick fanout cap rotates the most-overdue templates first.
func (s *Store) ListTemplatesReadyBefore(ctx context.Context, cutoff time.Time) ([]*models.Template, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		FROM firecracker_templates
		WHERE status = ?
		  AND ready_at IS NOT NULL
		  AND ready_at < ?
		ORDER BY ready_at ASC, id ASC
	`, string(models.TemplateStatusReady), cutoff.UTC())
	if err != nil {
		return nil, fmt.Errorf("list rotation candidates: %w", err)
	}
	defer rows.Close()

	var items []*models.Template
	for rows.Next() {
		template, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan template: %w", err)
		}
		items = append(items, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate templates: %w", err)
	}
	return items, nil
}

// ListReadyTemplateIDs returns the IDs of every template whose
// artifacts are usable on this host: `status IN ('ready',
// 'ready_no_snapshot')`. The Phase 6 PR-D capacity heartbeat hands this
// list to peers so placement can prefer the node that already has the
// template's artifacts cached.
//
// Returns IDs only (no payload columns) — the snapshot is gossiped
// every few seconds and a full row projection would balloon heartbeats
// once a cluster has hundreds of templates. The unknown-allow rule in
// placement.go nodeFits means a momentary "empty list" mid-startup is
// safe: peers fall back to "any host" placement until the heartbeat
// catches up.
func (s *Store) ListReadyTemplateIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id
		FROM firecracker_templates
		WHERE status IN (?, ?)
		ORDER BY id ASC
	`, string(models.TemplateStatusReady), string(models.TemplateStatusReadyNoSnapshot))
	if err != nil {
		return nil, fmt.Errorf("list ready template ids: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan template id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate template ids: %w", err)
	}
	return ids, nil
}

// SetTemplatePushState is a narrow single-column update used by the
// push reconciler. errMsg is overwritten unconditionally (including
// to empty on success transitions) so callers don't have to remember
// to clear it. Mirrors SetSnapshotPushState.
func (s *Store) SetTemplatePushState(ctx context.Context, id, state, errMsg string) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET push_state = ?, push_error = ?, updated_at = ?
		WHERE id = ?
	`, strings.TrimSpace(state), errMsg, now, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("set template push state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTemplatePushDistribution stamps the registry destination
// metadata after a successful AOCR push. ref is the canonical repo:tag
// the daemon pushed; digest is the manifest digest the registry
// surfaced via the push stream's `aux` payload (may be empty). Called
// from the reconciler success path together with SetTemplatePushState.
//
// Written in one statement so a crash between the two fields cannot
// land a half-filled row — the consumer-side pull in PR 6-B.2 sees
// either both fields populated or both empty.
func (s *Store) UpdateTemplatePushDistribution(ctx context.Context, id, ref, digest string) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_templates
		SET registry_ref = ?, push_digest = ?, updated_at = ?
		WHERE id = ?
	`,
		strings.TrimSpace(ref),
		strings.TrimSpace(digest),
		now,
		strings.TrimSpace(id),
	)
	if err != nil {
		return fmt.Errorf("update template push distribution: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteTemplate(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM firecracker_templates WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// IsTemplateReferenced reports whether any sandbox row still names this
// template_id. Used by DeleteTemplate (so an operator gets a 409 instead
// of yanking the rootfs out from under a live sandbox) and by the GC
// sweep (so it skips rows that are still in use). Backed by the partial
// index idx_sandboxes_template_id — constant cost regardless of the
// destroyed-row history.
func (s *Store) IsTemplateReferenced(ctx context.Context, id string) (bool, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return false, nil
	}
	var present int
	err := s.db.QueryRowContext(ctx, `
		SELECT 1 FROM sandboxes
		WHERE template_id = ?
		LIMIT 1
	`, trimmed).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check template references: %w", err)
	}
	return true, nil
}

// IsTemplateReferencedByVMM reports whether any warm-VMM pool row still
// names this template. This intentionally includes released rows: even a
// released row is still persistent state that references the template, and
// template GC should not leave dangling pool rows behind. Once the VMM-pool
// GC deletes the row, template GC can remove the template on a later pass.
func (s *Store) IsTemplateReferencedByVMM(ctx context.Context, id string) (bool, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return false, nil
	}
	var present int
	err := s.db.QueryRowContext(ctx, `
		SELECT 1 FROM firecracker_vmm_pool
		WHERE template_id = ?
		LIMIT 1
	`, trimmed).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check template vmm references: %w", err)
	}
	return true, nil
}

// ListGCEligibleTemplates returns ready/failed templates not referenced by
// any sandbox and last touched before olderThan. Pending rows are skipped
// — they have an in-flight build goroutine that owns the row's terminal
// transition. The anti-join against sandboxes uses the
// idx_sandboxes_template_id partial index so the subquery is cheap.
func (s *Store) ListGCEligibleTemplates(ctx context.Context, olderThan time.Time) ([]*models.Template, error) {
	// Phase 3: in-flight statuses now include building_rootfs and
	// snapshotting on top of the original pending. All three mean
	// "build goroutine still owns this row, do not GC" — same reason
	// as pending. We explicitly enumerate so a stray status string
	// (older build, manual SQL) doesn't get silently swept.
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, image, status, rootfs_path, rootfs_size_bytes, min_size_mib,
			last_error, created_at, updated_at, ready_at,
			snapshot_memory_path, snapshot_state_path, snapshot_size_bytes,
			snapshot_checksum, snapshot_vsock_cid, snapshot_error, has_snapshot,
			has_overlay, push_state, push_error, registry_ref, push_digest
		FROM firecracker_templates
		WHERE status NOT IN (?, ?, ?) AND updated_at < ? AND id NOT IN (
			SELECT template_id FROM sandboxes WHERE template_id <> ''
		) AND id NOT IN (
			SELECT template_id FROM firecracker_vmm_pool WHERE template_id <> ''
		)
		ORDER BY updated_at ASC
	`,
		string(models.TemplateStatusPending),
		string(models.TemplateStatusBuildingRootfs),
		string(models.TemplateStatusSnapshotting),
		olderThan.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("list gc-eligible templates: %w", err)
	}
	defer rows.Close()

	var items []*models.Template
	for rows.Next() {
		template, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan template: %w", err)
		}
		items = append(items, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate templates: %w", err)
	}
	return items, nil
}

// ListSnapshotsPendingPush returns snapshots the reconciler should retry —
// 'pending' is the brand-new state set by the snapshot-create path, 'error'
// is what a failed previous attempt left behind. 'pushing' is intentionally
// excluded so a row currently being processed by another reconciler tick
// (or a still-running goroutine kicked off by snapshot-create) is not
// re-claimed before its terminal state lands.
func (s *Store) ListSnapshotsPendingPush(ctx context.Context) ([]*models.SandboxSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, image, image_id, source_sandbox_id, created_at,
			entrypoint_json, region_id, cpu, memory_mb, disk_gb, gpu,
			image_distribution_mode, image_digest, image_registry_ref, image_verified_at,
			push_state, push_error
		FROM sandbox_snapshots
		WHERE push_state IN ('pending', 'error')
		ORDER BY created_at ASC, name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list snapshots pending push: %w", err)
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

// SetSnapshotPushState is a narrow single-column update used by the push
// reconciler. errMsg is overwritten unconditionally (including to empty
// on success transitions) so callers don't have to remember to clear it.
func (s *Store) SetSnapshotPushState(ctx context.Context, name, state, errMsg string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_snapshots
		SET push_state = ?, push_error = ?
		WHERE name = ?
	`, strings.TrimSpace(state), errMsg, strings.TrimSpace(name))
	if err != nil {
		return fmt.Errorf("set snapshot push state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateSnapshotImageDistribution flips the distribution metadata on a
// snapshot row after a successful AOCR push — local_only → aocr. Called
// from the reconciler success path together with SetSnapshotPushState.
// VerifiedAt records when the push completed; cluster placement on other
// nodes uses this together with the new mode to decide the snapshot is
// fan-outable.
func (s *Store) UpdateSnapshotImageDistribution(ctx context.Context, name, mode, registryRef, digest string) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_snapshots
		SET image_distribution_mode = ?, image_registry_ref = ?, image_digest = ?, image_verified_at = ?
		WHERE name = ?
	`,
		strings.TrimSpace(mode),
		strings.TrimSpace(registryRef),
		strings.TrimSpace(digest),
		now,
		strings.TrimSpace(name),
	)
	if err != nil {
		return fmt.Errorf("update snapshot image distribution: %w", err)
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

// GetPortByHostPort returns the raw-TCP exposure bound to hostPort, or nil if
// no exposure owns it. The L4 wake listener uses this to map Caddy's PROXY
// protocol destination port back to a sandbox/container port.
func (s *Store) GetPortByHostPort(ctx context.Context, hostPort int) (*models.ExposedPort, error) {
	var exposure models.ExposedPort
	err := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, port, protocol, host_port, public_url, created_at
		FROM exposed_ports
		WHERE host_port = ?
	`, hostPort).Scan(&exposure.SandboxID, &exposure.Port, &exposure.Protocol, &exposure.HostPort, &exposure.PublicURL, &exposure.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get exposed port by host port: %w", err)
	}
	return &exposure, nil
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

// ErrCustomDomainConflict is returned by AddCustomDomain when the hostname
// is already owned by a different sandbox. Surfaced through the API as 409.
// Same hostname for the same sandbox is idempotent (not a conflict) — that
// lets retries and reconcile re-converge without surfacing spurious errors.
var ErrCustomDomainConflict = errors.New("custom domain hostname already taken")

// CustomDomainRow is the per-row representation read out of
// sandbox_custom_domains. ListAllCustomDomains returns these so the
// reconcile loop and the cluster FSM hydration can walk the full set.
type CustomDomainRow struct {
	Hostname   string
	SandboxID  string
	Status     models.CustomDomainStatus
	LastError  string
	TargetPort int
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ErrCustomDomainPortMismatch surfaces an idempotent re-add of an
// already-attached hostname that carries a different target_port than the
// stored row. We never silently change the dial target — that would redirect
// live traffic without the caller knowing. The service layer translates this
// to HTTP 409 so the caller can detach + re-add deliberately.
var ErrCustomDomainPortMismatch = errors.New("custom domain target_port mismatch on re-add")

// AddCustomDomain inserts a hostname → sandbox mapping. Returns
// ErrCustomDomainConflict when the hostname is already owned by a different
// sandbox; returns ErrCustomDomainPortMismatch when the row exists for the
// same sandbox but with a different targetPort; returns nil when the same
// (hostname, sandbox, targetPort) tuple already exists (idempotent — the
// caller may retry safely). targetPort=0 is the toolbox-default sentinel.
// New rows start in CustomDomainPendingDNS.
func (s *Store) AddCustomDomain(ctx context.Context, sandboxID, hostname string, targetPort int) error {
	if sandboxID == "" {
		return errors.New("sandbox id is required")
	}
	if hostname == "" {
		return errors.New("hostname is required")
	}
	now := time.Now().UTC()
	// INSERT OR IGNORE collapses the "same pair already exists" case into a
	// silent no-op so we can disambiguate cross-sandbox conflict from
	// idempotent re-add with one follow-up SELECT. Same shape as the host_port
	// reservation path — see TryReserveHostPort for the canonical rationale.
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO sandbox_custom_domains (
			hostname, sandbox_id, status, last_error, target_port, created_at, updated_at
		) VALUES (?, ?, ?, '', ?, ?, ?)
	`, hostname, sandboxID, string(models.CustomDomainPendingDNS), targetPort, now, now)
	if err != nil {
		return fmt.Errorf("insert sandbox_custom_domains: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 1 {
		return nil
	}
	// IGNORE swallowed a PK conflict. The existing row may belong to the same
	// sandbox (idempotent re-add) or a different one (true conflict).
	var owner string
	var existingPort int
	if err := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id, target_port FROM sandbox_custom_domains WHERE hostname = ?
	`, hostname).Scan(&owner, &existingPort); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Row vanished between INSERT IGNORE and SELECT (cascade delete).
			// Treat as conflict so the caller does not assume success.
			return ErrCustomDomainConflict
		}
		return fmt.Errorf("disambiguate custom domain insert: %w", err)
	}
	if owner != sandboxID {
		return ErrCustomDomainConflict
	}
	if existingPort != targetPort {
		return ErrCustomDomainPortMismatch
	}
	return nil
}

// RemoveCustomDomain deletes the (sandbox, hostname) row. Cross-sandbox
// removal is rejected — the API gets ErrNotFound rather than silently
// stealing a hostname from another sandbox.
func (s *Store) RemoveCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	if sandboxID == "" || hostname == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM sandbox_custom_domains WHERE hostname = ? AND sandbox_id = ?
	`, hostname, sandboxID)
	if err != nil {
		return fmt.Errorf("delete sandbox_custom_domains: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListCustomDomains returns the canonical-ordered rows for one sandbox.
// Empty slice (nil) when the sandbox has no custom domains.
func (s *Store) ListCustomDomains(ctx context.Context, sandboxID string) ([]models.CustomDomain, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT hostname, status, last_error, target_port, created_at, updated_at
		FROM sandbox_custom_domains
		WHERE sandbox_id = ?
		ORDER BY hostname ASC
	`, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("list custom domains: %w", err)
	}
	defer rows.Close()

	var out []models.CustomDomain
	for rows.Next() {
		var cd models.CustomDomain
		var status string
		if err := rows.Scan(&cd.Hostname, &status, &cd.LastError, &cd.TargetPort, &cd.CreatedAt, &cd.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan custom domain: %w", err)
		}
		cd.Status = models.CustomDomainStatus(status)
		out = append(out, cd)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate custom domains: %w", err)
	}
	return out, nil
}

// ListAllCustomDomains returns every row in the table. Used by the reconcile
// loop's matcher-GC pass and by the cluster FSM hydration on cold start.
// Ordered by hostname so reconcile diffs are stable across calls.
func (s *Store) ListAllCustomDomains(ctx context.Context) ([]CustomDomainRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT hostname, sandbox_id, status, last_error, target_port, created_at, updated_at
		FROM sandbox_custom_domains
		ORDER BY hostname ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list all custom domains: %w", err)
	}
	defer rows.Close()

	var out []CustomDomainRow
	for rows.Next() {
		var r CustomDomainRow
		var status string
		if err := rows.Scan(&r.Hostname, &r.SandboxID, &status, &r.LastError, &r.TargetPort, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan custom domain row: %w", err)
		}
		r.Status = models.CustomDomainStatus(status)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate all custom domains: %w", err)
	}
	return out, nil
}

// ResolveCustomDomain is the hot path for the TLSAsk handler — single PK
// lookup, no scan. Returns ErrNotFound for unknown hostnames so the handler
// can fold it into a 403 without an error log on the success path. We do not
// surface target_port here because the routing dial target is already baked
// into the per-domain Caddy route at install time (see
// IngressCustomDomainHTTPRouteID); TLSAsk only needs the ownership signal.
func (s *Store) ResolveCustomDomain(ctx context.Context, hostname string) (string, error) {
	if hostname == "" {
		return "", ErrNotFound
	}
	var sandboxID string
	err := s.db.QueryRowContext(ctx, `
		SELECT sandbox_id FROM sandbox_custom_domains WHERE hostname = ?
	`, hostname).Scan(&sandboxID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("resolve custom domain: %w", err)
	}
	return sandboxID, nil
}

// SetCustomDomainStatus updates the per-domain state machine. Idempotent —
// repeated calls with the same (status, lastError) are still write-once on
// updated_at, which the caller may use as a heartbeat for "we saw an ask for
// this host". Returns ErrNotFound when the hostname is unknown so a caller
// observing an issuance failure for a since-removed host gets a clean signal.
func (s *Store) SetCustomDomainStatus(ctx context.Context, hostname string, status models.CustomDomainStatus, lastError string) error {
	if hostname == "" {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE sandbox_custom_domains
		SET status = ?, last_error = ?, updated_at = ?
		WHERE hostname = ?
	`, string(status), lastError, time.Now().UTC(), hostname)
	if err != nil {
		return fmt.Errorf("update custom domain status: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// loadCustomDomains is the single-sandbox sibling of attachCustomDomainsBulk,
// called from Get. Mirrors loadPorts's shape so callers can read the two
// collections side-by-side without thinking about transaction nesting.
func (s *Store) loadCustomDomains(ctx context.Context, sandboxID string) ([]models.CustomDomain, error) {
	return s.ListCustomDomains(ctx, sandboxID)
}

// attachCustomDomainsBulk reads every sandbox_custom_domains row for any
// sandbox in byID with one query and writes it onto the matching sandbox.
// Same shape as attachPortsBulk: the table only carries rows for sandboxes
// that have ever attached a custom domain, so the full-table scan is cheap
// in practice. Switch to a chunked WHERE sandbox_id IN (...) if the table
// ever crosses ~100k rows.
func (s *Store) attachCustomDomainsBulk(ctx context.Context, byID map[string]*models.Sandbox) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandbox_id, hostname, status, last_error, target_port, created_at, updated_at
		FROM sandbox_custom_domains
		ORDER BY sandbox_id, hostname ASC
	`)
	if err != nil {
		return fmt.Errorf("load custom domains: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var sandboxID string
		var cd models.CustomDomain
		var status string
		if err := rows.Scan(&sandboxID, &cd.Hostname, &status, &cd.LastError, &cd.TargetPort, &cd.CreatedAt, &cd.UpdatedAt); err != nil {
			return fmt.Errorf("scan custom domain: %w", err)
		}
		cd.Status = models.CustomDomainStatus(status)
		if sb, ok := byID[sandboxID]; ok {
			sb.CustomDomains = append(sb.CustomDomains, cd)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate custom domains: %w", err)
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
	var failoverPolicy string
	var stopIfIdleNs, destroyIfIdleNs, stopAtAgeNs, destroyAtAgeNs int64
	var netQuotaExceeded int
	var netQuotaExceededAt sql.NullTime
	var registryAuthSealed []byte
	var autoImportPending int
	var serverless int
	var wakeArmed int
	var fleetSuspended int

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
		&failoverPolicy,
		&sandbox.Runtime,
		&gpusJSON,
		&sandbox.NetworkBytesIn,
		&sandbox.NetworkBytesOut,
		&sandbox.NetworkBytesInLimit,
		&sandbox.NetworkBytesOutLimit,
		&netQuotaExceeded,
		&netQuotaExceededAt,
		&registryAuthSealed,
		&autoImportPending,
		&serverless,
		&wakeArmed,
		&sandbox.TemplateID,
		&sandbox.OverlaySizeGB,
		&sandbox.Durability,
		&sandbox.ModuleRef,
		&sandbox.ModuleDigest,
		&sandbox.CheckpointPath,
		&sandbox.CloneGeneration,
		&sandbox.WasmRegistryRef,
		&sandbox.WasmRegistryDigest,
		&sandbox.OwnerRef,
		&fleetSuspended,
	)
	if err != nil {
		return nil, err
	}
	sandbox.FleetSuspended = fleetSuspended == 1
	sandbox.NetworkQuotaExceeded = netQuotaExceeded == 1
	if netQuotaExceededAt.Valid {
		t := netQuotaExceededAt.Time.UTC()
		sandbox.NetworkQuotaExceededAt = &t
	}
	sandbox.RegistryAuthSealed = nullableBlob(registryAuthSealed)
	sandbox.AutoImportPending = autoImportPending == 1
	sandbox.WakeArmed = wakeArmed == 1

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
		Serverless:       serverless == 1,
	}
	if policy, err := models.NormalizeFailoverPolicy(failoverPolicy); err == nil && policy == models.FailoverPolicyRecreate {
		sandbox.Failover = &models.Failover{Policy: policy}
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
	var entrypointJSON string
	var imageVerifiedAt sql.NullTime
	err := scanner.Scan(
		&snapshot.Name,
		&snapshot.Image,
		&snapshot.ImageID,
		&snapshot.SourceSandboxID,
		&snapshot.CreatedAt,
		&entrypointJSON,
		&snapshot.RegionID,
		&snapshot.CPU,
		&snapshot.MemoryMB,
		&snapshot.DiskGB,
		&snapshot.GPU,
		&snapshot.ImageDistributionMode,
		&snapshot.ImageDigest,
		&snapshot.ImageRegistryRef,
		&imageVerifiedAt,
		&snapshot.PushState,
		&snapshot.PushError,
	)
	if err != nil {
		return nil, err
	}
	if imageVerifiedAt.Valid {
		verifiedAt := imageVerifiedAt.Time.UTC()
		snapshot.ImageVerifiedAt = &verifiedAt
	}
	if entrypointJSON != "" && entrypointJSON != "[]" {
		if err := json.Unmarshal([]byte(entrypointJSON), &snapshot.Entrypoint); err != nil {
			return nil, fmt.Errorf("decode snapshot entrypoint: %w", err)
		}
	}
	return &snapshot, nil
}

func scanTemplate(scanner interface {
	Scan(dest ...any) error
}) (*models.Template, error) {
	var template models.Template
	var readyAt sql.NullTime
	var hasSnapshot int
	var hasOverlay int
	err := scanner.Scan(
		&template.ID,
		&template.Image,
		&template.Status,
		&template.RootfsPath,
		&template.RootfsSizeBytes,
		&template.MinSizeMiB,
		&template.LastError,
		&template.CreatedAt,
		&template.UpdatedAt,
		&readyAt,
		&template.SnapshotMemoryPath,
		&template.SnapshotStatePath,
		&template.SnapshotSizeBytes,
		&template.SnapshotChecksum,
		&template.SnapshotVsockCID,
		&template.SnapshotError,
		&hasSnapshot,
		&hasOverlay,
		&template.PushState,
		&template.PushError,
		&template.RegistryRef,
		&template.PushDigest,
	)
	if err != nil {
		return nil, err
	}
	template.CreatedAt = template.CreatedAt.UTC()
	template.UpdatedAt = template.UpdatedAt.UTC()
	if readyAt.Valid {
		t := readyAt.Time.UTC()
		template.ReadyAt = &t
	}
	template.HasSnapshot = hasSnapshot != 0
	template.HasOverlay = hasOverlay != 0
	return &template, nil
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

// nullableTime maps a *time.Time to a sql.NullTime so a nil pointer becomes
// NULL on disk. Used by columns where "absent" is a meaningful state distinct
// from the zero time (e.g. net_quota_exceeded_at — sandboxes under quota
// have NULL, not 0001-01-01).
func nullableTime(t *time.Time) sql.NullTime {
	if t == nil || t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
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

// ErrTemplateIDConflict is returned by CreateTemplate when a row with the
// caller-supplied ID already exists. Operators that retry POST /v1/templates
// with an explicit id get a 409 instead of a 500 — the standard idempotency
// shape the v1 API uses everywhere else.
var ErrTemplateIDConflict = errors.New("template id already in use")

// ErrTemplateInUse is the service-layer sentinel for "cannot delete: an
// active sandbox still names this template_id". DeleteTemplate returns it
// after IsTemplateReferenced returns true; the API translates it to 409.
// Held in the store package only because the SQL probe lives here.
var ErrTemplateInUse = errors.New("template is referenced by an active sandbox")

// ClusterSecretRecord is an opaque cluster-secret payload addressed by ref.
// The store never decrypts SealedPayload; service owns the envelope format.
type ClusterSecretRecord struct {
	Ref           string
	SandboxID     string
	Version       int
	Recipients    []string
	SealedPayload []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (s *Store) PutClusterSecret(ctx context.Context, rec ClusterSecretRecord) error {
	rec.Ref = strings.TrimSpace(rec.Ref)
	rec.SandboxID = strings.TrimSpace(rec.SandboxID)
	if rec.Ref == "" {
		return errors.New("cluster secret ref is required")
	}
	if rec.SandboxID == "" {
		return errors.New("cluster secret sandbox_id is required")
	}
	if rec.Version <= 0 {
		return errors.New("cluster secret version must be positive")
	}
	if len(rec.SealedPayload) == 0 {
		return errors.New("cluster secret sealed payload is required")
	}
	recipientsJSON, err := json.Marshal(rec.Recipients)
	if err != nil {
		return fmt.Errorf("marshal cluster secret recipients: %w", err)
	}
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cluster_secrets (
			ref, sandbox_id, version, recipients_json, sealed_payload, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ref) DO UPDATE SET
			sandbox_id = excluded.sandbox_id,
			version = excluded.version,
			recipients_json = excluded.recipients_json,
			sealed_payload = excluded.sealed_payload,
			updated_at = excluded.updated_at
	`, rec.Ref, rec.SandboxID, rec.Version, string(recipientsJSON), rec.SealedPayload, rec.CreatedAt.UTC(), rec.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("put cluster secret: %w", err)
	}
	return nil
}

func (s *Store) GetClusterSecret(ctx context.Context, ref string) (*ClusterSecretRecord, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT ref, sandbox_id, version, recipients_json, sealed_payload, created_at, updated_at
		FROM cluster_secrets
		WHERE ref = ?
	`, ref)
	var rec ClusterSecretRecord
	var recipientsJSON string
	if err := row.Scan(&rec.Ref, &rec.SandboxID, &rec.Version, &recipientsJSON, &rec.SealedPayload, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get cluster secret: %w", err)
	}
	if recipientsJSON != "" {
		if err := json.Unmarshal([]byte(recipientsJSON), &rec.Recipients); err != nil {
			return nil, fmt.Errorf("unmarshal cluster secret recipients: %w", err)
		}
	}
	rec.SealedPayload = nullableBlob(rec.SealedPayload)
	return &rec, nil
}

func (s *Store) DeleteClusterSecretsForSandbox(ctx context.Context, sandboxID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cluster_secrets WHERE sandbox_id = ?`, sandboxID); err != nil {
		return fmt.Errorf("delete cluster secrets: %w", err)
	}
	return nil
}

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

// FirecrackerTapSlot is one pre-seeded row of the firecracker_tap_pool.
// Mirrors the table shape. SandboxID is empty when the slot is free,
// set to the owning sandbox when allocated; AllocatedAt is the zero
// time when free.
type FirecrackerTapSlot struct {
	TapName     string
	CIDR        string
	HostIP      string
	GuestIP     string
	VsockCID    uint32
	SandboxID   string
	CreatedAt   time.Time
	AllocatedAt time.Time
}

// SeedFirecrackerTapSlot inserts one slot row into the pool. Idempotent:
// the tap_name PRIMARY KEY makes re-seeding with the same name a no-op,
// so the daemon's boot path can call this for every configured slot
// without coordinating across restarts. Two distinct slots with the
// same vsock_cid would trip the unique index — callers must precompute
// non-colliding CIDs (the wrapper in internal/network/tap does this).
func (s *Store) SeedFirecrackerTapSlot(ctx context.Context, slot FirecrackerTapSlot, now time.Time) error {
	if slot.TapName == "" || slot.CIDR == "" || slot.HostIP == "" || slot.GuestIP == "" {
		return errors.New("seed firecracker tap slot: tap_name/cidr/host_ip/guest_ip are required")
	}
	if slot.VsockCID < 3 {
		// CIDs 0/1/2 are reserved by the virtio-vsock spec (hypervisor,
		// host, any). Catch this at the store layer because allocations
		// flow through here and a buggy seed would only fail on the
		// first sandbox create otherwise.
		return fmt.Errorf("seed firecracker tap slot: vsock_cid must be >= 3 (got %d)", slot.VsockCID)
	}
	// ON CONFLICT(tap_name) DO NOTHING is narrower than INSERT OR IGNORE:
	// it only swallows tap_name PK conflicts (the idempotent re-seed
	// case). A duplicate vsock_cid on a different tap_name surfaces as
	// a UNIQUE constraint error, which is the desired loud failure —
	// the seed config is wrong and the operator should fix it before
	// the first sandbox create discovers the clash.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO firecracker_tap_pool
			(tap_name, cidr, host_ip, guest_ip, vsock_cid, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(tap_name) DO NOTHING
	`, slot.TapName, slot.CIDR, slot.HostIP, slot.GuestIP, slot.VsockCID, now.UTC())
	if err != nil {
		return fmt.Errorf("seed firecracker tap slot: %w", err)
	}
	return nil
}

// AllocateFirecrackerTapSlot claims a free slot for sandboxID and
// returns it. Idempotent: if sandboxID already owns a slot, that slot
// is returned without changes (the partial unique index guarantees at
// most one). If no slot is free, returns ErrNoFreeFirecrackerTapSlot.
//
// The implementation is a two-step inside the SQLite single-writer
// window:
//
//  1. SELECT a row WHERE sandbox_id IS NULL LIMIT 1.
//  2. UPDATE that row SET sandbox_id = ?, allocated_at = ? WHERE
//     tap_name = ? AND sandbox_id IS NULL.
//
// The WHERE clause on UPDATE re-checks sandbox_id IS NULL so a race
// with a concurrent allocate of the same row updates RowsAffected=0
// and we loop. SQLite's single-writer model makes this contest rare
// in practice but the code stays correct under any future change.
func (s *Store) AllocateFirecrackerTapSlot(ctx context.Context, sandboxID string, now time.Time) (*FirecrackerTapSlot, error) {
	if sandboxID == "" {
		return nil, errors.New("allocate firecracker tap slot: sandbox_id is required")
	}
	// Idempotency check first — if the sandbox already owns a slot,
	// return it. Doing this before the allocate loop avoids a
	// pessimistic UPDATE attempt that the partial unique index would
	// reject (which would also work, but produces a noisier error).
	if existing, err := s.GetFirecrackerTapSlotBySandbox(ctx, sandboxID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}

	// Bounded retry — under the SQLite single-writer model the contest
	// resolves in one or two passes. The cap exists to prevent a buggy
	// caller from spinning forever if every UPDATE fights for the same
	// row; in practice the loop fires at most twice.
	for attempt := 0; attempt < 8; attempt++ {
		var candidate FirecrackerTapSlot
		row := s.db.QueryRowContext(ctx, `
			SELECT tap_name, cidr, host_ip, guest_ip, vsock_cid, created_at
			FROM firecracker_tap_pool
			WHERE sandbox_id IS NULL
			ORDER BY tap_name ASC
			LIMIT 1
		`)
		if err := row.Scan(&candidate.TapName, &candidate.CIDR, &candidate.HostIP, &candidate.GuestIP, &candidate.VsockCID, &candidate.CreatedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNoFreeFirecrackerTapSlot
			}
			return nil, fmt.Errorf("allocate firecracker tap slot (select): %w", err)
		}

		res, err := s.db.ExecContext(ctx, `
			UPDATE firecracker_tap_pool
			SET sandbox_id = ?, allocated_at = ?
			WHERE tap_name = ? AND sandbox_id IS NULL
		`, sandboxID, now.UTC(), candidate.TapName)
		if err != nil {
			return nil, fmt.Errorf("allocate firecracker tap slot (update): %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("allocate firecracker tap slot (affected): %w", err)
		}
		if n == 1 {
			candidate.SandboxID = sandboxID
			candidate.AllocatedAt = now.UTC()
			return &candidate, nil
		}
		// Lost the race; loop and pick another free slot.
	}
	return nil, errors.New("allocate firecracker tap slot: pool contested after 8 attempts (likely allocator livelock)")
}

// ReleaseFirecrackerTapSlot returns a sandbox's slot to the pool by
// clearing sandbox_id + allocated_at. Idempotent: releasing a sandbox
// that owns no slot is a no-op.
func (s *Store) ReleaseFirecrackerTapSlot(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return errors.New("release firecracker tap slot: sandbox_id is required")
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_tap_pool
		SET sandbox_id = NULL, allocated_at = NULL
		WHERE sandbox_id = ?
	`, sandboxID)
	if err != nil {
		return fmt.Errorf("release firecracker tap slot: %w", err)
	}
	return nil
}

// GetFirecrackerTapSlotBySandbox returns the slot currently owned by
// sandboxID, or nil if it owns none. Used by both the idempotent
// allocate path and the runtime driver's Inspect/Destroy paths.
func (s *Store) GetFirecrackerTapSlotBySandbox(ctx context.Context, sandboxID string) (*FirecrackerTapSlot, error) {
	if sandboxID == "" {
		return nil, errors.New("get firecracker tap slot: sandbox_id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT tap_name, cidr, host_ip, guest_ip, vsock_cid, created_at, allocated_at
		FROM firecracker_tap_pool
		WHERE sandbox_id = ?
	`, sandboxID)
	var slot FirecrackerTapSlot
	var allocated sql.NullTime
	if err := row.Scan(&slot.TapName, &slot.CIDR, &slot.HostIP, &slot.GuestIP, &slot.VsockCID, &slot.CreatedAt, &allocated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get firecracker tap slot: %w", err)
	}
	if allocated.Valid {
		slot.AllocatedAt = allocated.Time
	}
	slot.SandboxID = sandboxID
	return &slot, nil
}

// FirecrackerTapPoolStats reports the current pool occupancy. Used by
// /healthz and the admission controller — a near-empty pool blocks new
// Firecracker creates upstream of the failing Allocate call, which is
// a better operator experience than discovering the exhaustion on the
// next user request.
type FirecrackerTapPoolStats struct {
	Total     int
	Allocated int
	Free      int
}

func (s *Store) GetFirecrackerTapPoolStats(ctx context.Context) (FirecrackerTapPoolStats, error) {
	var stats FirecrackerTapPoolStats
	row := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COUNT(CASE WHEN sandbox_id IS NOT NULL THEN 1 END)
		FROM firecracker_tap_pool
	`)
	if err := row.Scan(&stats.Total, &stats.Allocated); err != nil {
		return stats, fmt.Errorf("firecracker tap pool stats: %w", err)
	}
	stats.Free = stats.Total - stats.Allocated
	return stats, nil
}

// ErrNoFreeFirecrackerTapSlot is returned by AllocateFirecrackerTapSlot
// when every slot is claimed. The Firecracker create path translates
// this into a 503-ish admission error upstream — operators see "pool
// exhausted" before the customer sees a confusing timeout.
var ErrNoFreeFirecrackerTapSlot = errors.New("firecracker tap pool: no free slot")

// Firecracker warm-VMM pool status constants. Kept as bare strings
// rather than a typed enum because SQLite stores them as TEXT and the
// store-layer queries WHERE status='...' literals — a typed wrapper
// would just force every call site to string()-coerce. The state
// machine is documented inline in the CREATE TABLE statement above.
const (
	FirecrackerVMMSlotStatusSpawning  = "spawning"
	FirecrackerVMMSlotStatusLoaded    = "loaded"
	FirecrackerVMMSlotStatusAllocated = "allocated"
	FirecrackerVMMSlotStatusReleased  = "released"
)

// FirecrackerVMMSlot is one row of firecracker_vmm_pool. Mirrors the
// table shape; nullable DATETIME columns map to zero-valued time.Time
// when absent so the policy wrapper (internal/pool/vmm) doesn't have
// to plumb sql.NullTime through its API.
type FirecrackerVMMSlot struct {
	ID          string
	TemplateID  string
	Status      string
	SandboxID   string
	APISocket   string
	RunDir      string
	VsockCID    uint32
	CreatedAt   time.Time
	LoadedAt    time.Time
	AllocatedAt time.Time
	ReleasedAt  time.Time
	LastError   string
}

// FirecrackerVMMPoolStats is the per-template breakdown by status used
// by /healthz and PR 4-B's refill goroutine to decide how many new
// slots to spawn. Total is the count of all non-deleted rows for the
// template; the sum of the per-status counters equals Total.
type FirecrackerVMMPoolStats struct {
	Total     int
	Spawning  int
	Loaded    int
	Allocated int
	Released  int
}

// ErrNoFreeFirecrackerVMMSlot is returned by AllocateFirecrackerVMMSlot
// when no 'loaded' slot exists for the requested template. PR 4-B's
// caller treats this as the cold-spawn fallback signal, not an error
// state — the pool being momentarily empty is the expected behavior
// under load between spawn-and-load passes.
var ErrNoFreeFirecrackerVMMSlot = errors.New("firecracker vmm pool: no loaded slot")

// InsertFirecrackerVMMSlot reserves a new row in status='spawning'.
// PR 4-B's refill goroutine calls this BEFORE launching firecracker so
// a crash mid-spawn leaves a 'spawning' row the GC sweep can clean up
// rather than a silently-leaked process with no row to find it by.
//
// Validation is strict because a malformed insert is always a bug in
// the caller — the refill goroutine should hand us a freshly-generated
// id and an actual template id, not the zero value.
func (s *Store) InsertFirecrackerVMMSlot(ctx context.Context, slot FirecrackerVMMSlot, now time.Time) error {
	if strings.TrimSpace(slot.ID) == "" {
		return errors.New("insert firecracker vmm slot: id is required")
	}
	if strings.TrimSpace(slot.TemplateID) == "" {
		return errors.New("insert firecracker vmm slot: template_id is required")
	}
	// The pool's external API never inserts a row in any other state —
	// the spawner is the only thing that knows when the snapshot is
	// loaded, and it transitions the row via MarkFirecrackerVMMSlotLoaded.
	// Reject anything else loudly so a future caller can't sneak a
	// pre-loaded row past the spawner.
	if slot.Status != "" && slot.Status != FirecrackerVMMSlotStatusSpawning {
		return fmt.Errorf("insert firecracker vmm slot: status must be %q (got %q)",
			FirecrackerVMMSlotStatusSpawning, slot.Status)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO firecracker_vmm_pool
			(id, template_id, status, created_at)
		VALUES (?, ?, ?, ?)
	`, slot.ID, slot.TemplateID, FirecrackerVMMSlotStatusSpawning, now.UTC())
	if err != nil {
		return fmt.Errorf("insert firecracker vmm slot: %w", err)
	}
	return nil
}

// MarkFirecrackerVMMSlotLoaded flips 'spawning' → 'loaded' and stamps
// the per-slot artifact paths the allocator will hand to the sandbox
// create path. The WHERE clause asserts the current state so a retried
// call (or a racing GC) can't accidentally walk a slot backwards from
// 'allocated' to 'loaded'. apiSocket and runDir live in the row so
// PR 4-B's runtime adapter can adopt a pre-spawned firecracker process
// across daemon restarts without re-deriving them.
func (s *Store) MarkFirecrackerVMMSlotLoaded(ctx context.Context, slotID, apiSocket, runDir string, vsockCID uint32, now time.Time) error {
	if strings.TrimSpace(slotID) == "" {
		return errors.New("mark firecracker vmm slot loaded: slot id is required")
	}
	if strings.TrimSpace(apiSocket) == "" || strings.TrimSpace(runDir) == "" {
		return errors.New("mark firecracker vmm slot loaded: api_socket and run_dir are required")
	}
	if vsockCID < 3 {
		// Same guard as the TAP pool's seed: 0/1/2 are reserved and a
		// snapshot keyed on one of those CIDs is corrupt by definition.
		return fmt.Errorf("mark firecracker vmm slot loaded: vsock_cid must be >= 3 (got %d)", vsockCID)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_vmm_pool
		SET status = ?, api_socket = ?, run_dir = ?, vsock_cid = ?, loaded_at = ?
		WHERE id = ? AND status = ?
	`, FirecrackerVMMSlotStatusLoaded, apiSocket, runDir, vsockCID, now.UTC(),
		slotID, FirecrackerVMMSlotStatusSpawning)
	if err != nil {
		return fmt.Errorf("mark firecracker vmm slot loaded: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark firecracker vmm slot loaded (affected): %w", err)
	}
	if n == 0 {
		// Zero rows means either the slot id doesn't exist or it's no
		// longer in 'spawning'. Both are caller-side bugs the spawner
		// should surface rather than retry silently.
		return ErrNotFound
	}
	return nil
}

// MarkFirecrackerVMMSlotFailed records that the spawner could not
// produce a paused-and-loaded VMM for this slot and moves the row
// directly to 'released' so the GC sweep cleans it up after the TTL.
// Skipping the 'loaded' intermediate is intentional: a failed slot was
// never claimable, and a transient 'loaded' state on a row whose VMM
// is actually missing would let the next Allocate hand out a dead
// process. last_error is preserved on the row for operator triage.
func (s *Store) MarkFirecrackerVMMSlotFailed(ctx context.Context, slotID, errMsg string, now time.Time) error {
	if strings.TrimSpace(slotID) == "" {
		return errors.New("mark firecracker vmm slot failed: slot id is required")
	}
	// last_error gets truncated to keep an unbounded spawner stderr
	// from blowing up the row size. 1 KiB is enough to capture a
	// firecracker boot panic line + the call site.
	const errCap = 1024
	if len(errMsg) > errCap {
		errMsg = errMsg[:errCap]
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_vmm_pool
		SET status = ?, last_error = ?, released_at = ?
		WHERE id = ? AND status = ?
	`, FirecrackerVMMSlotStatusReleased, errMsg, now.UTC(),
		slotID, FirecrackerVMMSlotStatusSpawning)
	if err != nil {
		return fmt.Errorf("mark firecracker vmm slot failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark firecracker vmm slot failed (affected): %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AllocateFirecrackerVMMSlot claims one 'loaded' slot for templateID +
// sandboxID. Idempotent: if sandboxID already owns a slot, that slot
// is returned without re-allocation (the partial unique index makes a
// duplicate claim a hard error, but the pre-check yields a cleaner
// happy path). If no 'loaded' slot for templateID exists, returns
// ErrNoFreeFirecrackerVMMSlot — PR 4-B's caller falls back to cold
// spawn rather than failing the create.
//
// The allocator shape is lifted from AllocateFirecrackerTapSlot:
// SELECT one free row, UPDATE WHERE row is still free. The UPDATE's
// WHERE re-checks status='loaded' AND sandbox_id IS NULL so a race
// against a concurrent allocator updates RowsAffected=0 and we loop.
// SQLite's single writer makes the contest rare, but the loop keeps
// correctness if the locking model ever changes.
func (s *Store) AllocateFirecrackerVMMSlot(ctx context.Context, templateID, sandboxID string, now time.Time) (*FirecrackerVMMSlot, error) {
	if strings.TrimSpace(templateID) == "" {
		return nil, errors.New("allocate firecracker vmm slot: template_id is required")
	}
	if strings.TrimSpace(sandboxID) == "" {
		return nil, errors.New("allocate firecracker vmm slot: sandbox_id is required")
	}
	if existing, err := s.GetFirecrackerVMMSlotBySandbox(ctx, sandboxID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}

	for attempt := 0; attempt < 8; attempt++ {
		var candidate FirecrackerVMMSlot
		var loadedAt sql.NullTime
		row := s.db.QueryRowContext(ctx, `
			SELECT id, template_id, status, api_socket, run_dir, vsock_cid, created_at, loaded_at
			FROM firecracker_vmm_pool
			WHERE template_id = ? AND status = ? AND sandbox_id IS NULL
			ORDER BY loaded_at ASC
			LIMIT 1
		`, templateID, FirecrackerVMMSlotStatusLoaded)
		if err := row.Scan(&candidate.ID, &candidate.TemplateID, &candidate.Status,
			&candidate.APISocket, &candidate.RunDir, &candidate.VsockCID,
			&candidate.CreatedAt, &loadedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNoFreeFirecrackerVMMSlot
			}
			return nil, fmt.Errorf("allocate firecracker vmm slot (select): %w", err)
		}
		if loadedAt.Valid {
			candidate.LoadedAt = loadedAt.Time
		}

		res, err := s.db.ExecContext(ctx, `
			UPDATE firecracker_vmm_pool
			SET status = ?, sandbox_id = ?, allocated_at = ?
			WHERE id = ? AND status = ? AND sandbox_id IS NULL
		`, FirecrackerVMMSlotStatusAllocated, sandboxID, now.UTC(),
			candidate.ID, FirecrackerVMMSlotStatusLoaded)
		if err != nil {
			return nil, fmt.Errorf("allocate firecracker vmm slot (update): %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("allocate firecracker vmm slot (affected): %w", err)
		}
		if n == 1 {
			candidate.Status = FirecrackerVMMSlotStatusAllocated
			candidate.SandboxID = sandboxID
			candidate.AllocatedAt = now.UTC()
			return &candidate, nil
		}
		// Lost the race; loop and pick another 'loaded' row.
	}
	return nil, errors.New("allocate firecracker vmm slot: pool contested after 8 attempts (likely allocator livelock)")
}

// ReleaseFirecrackerVMMSlot moves a sandbox's slot from 'allocated' to
// 'released'. Idempotent in two senses: releasing a sandbox that never
// owned a slot is a no-op (RowsAffected=0 returns nil), and releasing a
// slot already in 'released' is a no-op for the same reason. The
// WHERE-on-status keeps a malformed retry from resurrecting a slot
// that the spawner failed and already marked released.
func (s *Store) ReleaseFirecrackerVMMSlot(ctx context.Context, sandboxID string, now time.Time) error {
	if strings.TrimSpace(sandboxID) == "" {
		return errors.New("release firecracker vmm slot: sandbox_id is required")
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_vmm_pool
		SET status = ?, sandbox_id = NULL, released_at = ?
		WHERE sandbox_id = ? AND status = ?
	`, FirecrackerVMMSlotStatusReleased, now.UTC(), sandboxID, FirecrackerVMMSlotStatusAllocated)
	if err != nil {
		return fmt.Errorf("release firecracker vmm slot: %w", err)
	}
	return nil
}

// ReleaseOrphanedFirecrackerVMMSlots marks any warm-pool slot left in
// 'spawning' or 'loaded' with no sandbox claim as 'released'. The
// daemon calls this once at startup before refilling so rows stranded
// by the previous process do not stay invisible to GC forever.
func (s *Store) ReleaseOrphanedFirecrackerVMMSlots(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE firecracker_vmm_pool
		SET status = ?, released_at = ?
		WHERE sandbox_id IS NULL AND status IN (?, ?)
	`, FirecrackerVMMSlotStatusReleased, now.UTC(),
		FirecrackerVMMSlotStatusSpawning, FirecrackerVMMSlotStatusLoaded)
	if err != nil {
		return 0, fmt.Errorf("release orphaned firecracker vmm slots: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("release orphaned firecracker vmm slots (affected): %w", err)
	}
	return int(n), nil
}

// GetFirecrackerVMMSlotBySandbox returns the slot currently claimed by
// sandboxID, or nil if it owns none. Used by the idempotent Allocate
// pre-check and by PR 4-B's destroy path to find the slot whose VMM
// process needs to be torn down.
func (s *Store) GetFirecrackerVMMSlotBySandbox(ctx context.Context, sandboxID string) (*FirecrackerVMMSlot, error) {
	if strings.TrimSpace(sandboxID) == "" {
		return nil, errors.New("get firecracker vmm slot: sandbox_id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, template_id, status, api_socket, run_dir, vsock_cid,
			created_at, loaded_at, allocated_at, released_at, last_error
		FROM firecracker_vmm_pool
		WHERE sandbox_id = ?
	`, sandboxID)
	slot, err := scanFirecrackerVMMSlot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get firecracker vmm slot: %w", err)
	}
	slot.SandboxID = sandboxID
	return slot, nil
}

// GetFirecrackerVMMSlotByID returns the slot row whose id matches, or
// nil if not found. Lets PR 4-B's refill goroutine re-read its own
// freshly-inserted row to inspect the row's authoritative status
// (the daemon may have raced a GC between InsertFirecrackerVMMSlot and
// the spawner attempt). Unlike GetFirecrackerVMMSlotBySandbox, the
// row's sandbox_id is unknown to the caller — we project the column
// explicitly so an 'allocated' slot reads back with its claimant.
func (s *Store) GetFirecrackerVMMSlotByID(ctx context.Context, slotID string) (*FirecrackerVMMSlot, error) {
	if strings.TrimSpace(slotID) == "" {
		return nil, errors.New("get firecracker vmm slot by id: slot id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, template_id, status, sandbox_id, api_socket, run_dir, vsock_cid,
			created_at, loaded_at, allocated_at, released_at, last_error
		FROM firecracker_vmm_pool
		WHERE id = ?
	`, slotID)
	var (
		slot                              FirecrackerVMMSlot
		sandboxID                         sql.NullString
		loadedAt, allocatedAt, releasedAt sql.NullTime
	)
	if err := row.Scan(&slot.ID, &slot.TemplateID, &slot.Status, &sandboxID,
		&slot.APISocket, &slot.RunDir, &slot.VsockCID,
		&slot.CreatedAt, &loadedAt, &allocatedAt, &releasedAt, &slot.LastError); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get firecracker vmm slot by id: %w", err)
	}
	if sandboxID.Valid {
		slot.SandboxID = sandboxID.String
	}
	if loadedAt.Valid {
		slot.LoadedAt = loadedAt.Time
	}
	if allocatedAt.Valid {
		slot.AllocatedAt = allocatedAt.Time
	}
	if releasedAt.Valid {
		slot.ReleasedAt = releasedAt.Time
	}
	return &slot, nil
}

// ListFirecrackerVMMSlotsForRefill returns every non-released slot
// owned by templateID. PR 4-B's refill goroutine calls this once per
// tick to compute "desired_depth - len(non_released)" — the spawn
// budget for the next pass. Released rows are excluded so a slow GC
// doesn't inflate the count and starve refills.
func (s *Store) ListFirecrackerVMMSlotsForRefill(ctx context.Context, templateID string) ([]FirecrackerVMMSlot, error) {
	if strings.TrimSpace(templateID) == "" {
		return nil, errors.New("list firecracker vmm slots: template_id is required")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, template_id, status, sandbox_id, api_socket, run_dir, vsock_cid,
			created_at, loaded_at, allocated_at, released_at, last_error
		FROM firecracker_vmm_pool
		WHERE template_id = ? AND status <> ?
		ORDER BY created_at ASC
	`, templateID, FirecrackerVMMSlotStatusReleased)
	if err != nil {
		return nil, fmt.Errorf("list firecracker vmm slots: %w", err)
	}
	defer rows.Close()
	return collectFirecrackerVMMSlots(rows)
}

// ListReleasedFirecrackerVMMSlots is the GC sweep selector: every row
// in status='released' whose released_at is older than olderThan. The
// partial index on released_at WHERE status='released' covers this
// query exactly so the sweep is cheap even when the steady-state
// count is zero.
func (s *Store) ListReleasedFirecrackerVMMSlots(ctx context.Context, olderThan time.Time) ([]FirecrackerVMMSlot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, template_id, status, sandbox_id, api_socket, run_dir, vsock_cid,
			created_at, loaded_at, allocated_at, released_at, last_error
		FROM firecracker_vmm_pool
		WHERE status = ? AND released_at IS NOT NULL AND released_at <= ?
		ORDER BY released_at ASC
	`, FirecrackerVMMSlotStatusReleased, olderThan.UTC())
	if err != nil {
		return nil, fmt.Errorf("list released firecracker vmm slots: %w", err)
	}
	defer rows.Close()
	return collectFirecrackerVMMSlots(rows)
}

// DeleteFirecrackerVMMSlot drops the row. PR 4-B's GC sweep calls this
// after the VMM process for the slot is confirmed gone, so there is
// no on-disk runDir or live socket the row was the last reference to.
// Returns ErrNotFound when the row was already deleted — idempotent on
// double-call.
func (s *Store) DeleteFirecrackerVMMSlot(ctx context.Context, slotID string) error {
	if strings.TrimSpace(slotID) == "" {
		return errors.New("delete firecracker vmm slot: slot id is required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM firecracker_vmm_pool WHERE id = ?`, slotID)
	if err != nil {
		return fmt.Errorf("delete firecracker vmm slot: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete firecracker vmm slot (affected): %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetFirecrackerVMMPoolStats returns per-template occupancy by status.
// Single GROUP BY scan covered by idx_firecracker_vmm_pool_template_status.
// /healthz and PR 4-C's metrics exporter both call this; PR 4-B's
// refill goroutine prefers ListFirecrackerVMMSlotsForRefill which
// gives it the row ids it may want to act on.
func (s *Store) GetFirecrackerVMMPoolStats(ctx context.Context, templateID string) (FirecrackerVMMPoolStats, error) {
	var stats FirecrackerVMMPoolStats
	if strings.TrimSpace(templateID) == "" {
		return stats, errors.New("firecracker vmm pool stats: template_id is required")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT status, COUNT(*)
		FROM firecracker_vmm_pool
		WHERE template_id = ?
		GROUP BY status
	`, templateID)
	if err != nil {
		return stats, fmt.Errorf("firecracker vmm pool stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return stats, fmt.Errorf("firecracker vmm pool stats (scan): %w", err)
		}
		switch status {
		case FirecrackerVMMSlotStatusSpawning:
			stats.Spawning = count
		case FirecrackerVMMSlotStatusLoaded:
			stats.Loaded = count
		case FirecrackerVMMSlotStatusAllocated:
			stats.Allocated = count
		case FirecrackerVMMSlotStatusReleased:
			stats.Released = count
		}
		stats.Total += count
	}
	if err := rows.Err(); err != nil {
		return stats, fmt.Errorf("firecracker vmm pool stats (rows): %w", err)
	}
	return stats, nil
}

// scanFirecrackerVMMSlot decodes a single row from any SELECT that
// returns the canonical 11-column projection. Centralized so the
// nullable-DATETIME and nullable-sandbox-id handling is in one place;
// every caller projects the same columns in the same order.
func scanFirecrackerVMMSlot(row interface {
	Scan(...any) error
}) (*FirecrackerVMMSlot, error) {
	var (
		slot                              FirecrackerVMMSlot
		sandboxID                         sql.NullString
		loadedAt, allocatedAt, releasedAt sql.NullTime
	)
	if err := row.Scan(&slot.ID, &slot.TemplateID, &slot.Status,
		&slot.APISocket, &slot.RunDir, &slot.VsockCID,
		&slot.CreatedAt, &loadedAt, &allocatedAt, &releasedAt, &slot.LastError); err != nil {
		return nil, err
	}
	if sandboxID.Valid {
		slot.SandboxID = sandboxID.String
	}
	if loadedAt.Valid {
		slot.LoadedAt = loadedAt.Time
	}
	if allocatedAt.Valid {
		slot.AllocatedAt = allocatedAt.Time
	}
	if releasedAt.Valid {
		slot.ReleasedAt = releasedAt.Time
	}
	return &slot, nil
}

// collectFirecrackerVMMSlots walks a *sql.Rows from the list queries.
// These project the full 12-column shape — including sandbox_id —
// because list callers can't recover the value from a WHERE clause
// the way GetFirecrackerVMMSlotBySandbox does. Centralized so the
// nullable-column handling stays in one place.
func collectFirecrackerVMMSlots(rows *sql.Rows) ([]FirecrackerVMMSlot, error) {
	var out []FirecrackerVMMSlot
	for rows.Next() {
		var (
			slot                              FirecrackerVMMSlot
			sandboxID                         sql.NullString
			loadedAt, allocatedAt, releasedAt sql.NullTime
		)
		if err := rows.Scan(&slot.ID, &slot.TemplateID, &slot.Status, &sandboxID,
			&slot.APISocket, &slot.RunDir, &slot.VsockCID,
			&slot.CreatedAt, &loadedAt, &allocatedAt, &releasedAt, &slot.LastError); err != nil {
			return nil, fmt.Errorf("scan firecracker vmm slot row: %w", err)
		}
		if sandboxID.Valid {
			slot.SandboxID = sandboxID.String
		}
		if loadedAt.Valid {
			slot.LoadedAt = loadedAt.Time
		}
		if allocatedAt.Valid {
			slot.AllocatedAt = allocatedAt.Time
		}
		if releasedAt.Valid {
			slot.ReleasedAt = releasedAt.Time
		}
		out = append(out, slot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter firecracker vmm slot rows: %w", err)
	}
	return out, nil
}

// WasmModuleRecord is one row in wasm_modules.
type WasmModuleRecord struct {
	ID              string
	ModuleRef       string
	Status          string
	ModulePath      string
	ModuleSizeBytes int64
	Digest          string
	Entrypoint      string
	HasWarm         bool
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ReadyAt         *time.Time
}

// UpsertWasmModule inserts or updates a wasm_modules catalogue row.
func (s *Store) UpsertWasmModule(ctx context.Context, rec WasmModuleRecord) error {
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO wasm_modules (
			id, module_ref, status, module_path, module_size_bytes, digest,
			entrypoint, has_warm, last_error, created_at, updated_at, ready_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			module_ref = excluded.module_ref,
			status = excluded.status,
			module_path = excluded.module_path,
			module_size_bytes = excluded.module_size_bytes,
			digest = excluded.digest,
			entrypoint = excluded.entrypoint,
			has_warm = excluded.has_warm,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at,
			ready_at = excluded.ready_at
	`,
		rec.ID,
		strings.TrimSpace(rec.ModuleRef),
		rec.Status,
		rec.ModulePath,
		rec.ModuleSizeBytes,
		rec.Digest,
		rec.Entrypoint,
		boolToInt(rec.HasWarm),
		rec.LastError,
		rec.CreatedAt.UTC(),
		rec.UpdatedAt.UTC(),
		nullableTime(rec.ReadyAt),
	)
	if err != nil {
		return fmt.Errorf("upsert wasm module: %w", err)
	}
	return nil
}

// UpdateWasmCheckpoint persists passivation metadata on a sandbox row.
func (s *Store) UpdateWasmCheckpoint(ctx context.Context, sandboxID, status, checkpointPath, cloneGen, lastError string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET status = ?, checkpoint_path = ?, clone_generation = ?, last_error = ?, updated_at = ?
		WHERE id = ?
	`, status, strings.TrimSpace(checkpointPath), strings.TrimSpace(cloneGen), lastError, now, sandboxID)
	if err != nil {
		return fmt.Errorf("update wasm checkpoint: %w", err)
	}
	return nil
}

// PutWasmStateKV upserts one durable host-KV row (§4.6).
func (s *Store) PutWasmStateKV(ctx context.Context, sandboxID, key string, value []byte) error {
	sandboxID = strings.TrimSpace(sandboxID)
	key = strings.TrimSpace(key)
	if sandboxID == "" || key == "" {
		return fmt.Errorf("wasm state kv: sandbox id and key required")
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO wasm_state_kv (sandbox_id, key, value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(sandbox_id, key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at
	`, sandboxID, key, value, now)
	if err != nil {
		return fmt.Errorf("put wasm state kv: %w", err)
	}
	return nil
}

// GetWasmStateKV returns one durable host-KV value.
func (s *Store) GetWasmStateKV(ctx context.Context, sandboxID, key string) ([]byte, bool, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	key = strings.TrimSpace(key)
	row := s.db.QueryRowContext(ctx, `
		SELECT value FROM wasm_state_kv WHERE sandbox_id = ? AND key = ?`,
		sandboxID, key)
	var value []byte
	err := row.Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get wasm state kv: %w", err)
	}
	return value, true, nil
}

// DeleteWasmStateKV removes one durable host-KV row.
func (s *Store) DeleteWasmStateKV(ctx context.Context, sandboxID, key string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	key = strings.TrimSpace(key)
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM wasm_state_kv WHERE sandbox_id = ? AND key = ?`,
		sandboxID, key)
	if err != nil {
		return fmt.Errorf("delete wasm state kv: %w", err)
	}
	return nil
}

// DeleteAllWasmStateKV removes every durable host-KV row for sandboxID.
func (s *Store) DeleteAllWasmStateKV(ctx context.Context, sandboxID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM wasm_state_kv WHERE sandbox_id = ?`,
		sandboxID)
	if err != nil {
		return fmt.Errorf("delete all wasm state kv: %w", err)
	}
	return nil
}

// ListWasmStateKVKeys lists keys for a sandbox.
func (s *Store) ListWasmStateKVKeys(ctx context.Context, sandboxID string) ([]string, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	rows, err := s.db.QueryContext(ctx, `
		SELECT key FROM wasm_state_kv WHERE sandbox_id = ? ORDER BY key`,
		sandboxID)
	if err != nil {
		return nil, fmt.Errorf("list wasm state kv keys: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// WasmCheckpointPushRecord is one AOCR push history row.
type WasmCheckpointPushRecord struct {
	ID          int64
	SandboxID   string
	RegistryRef string
	Digest      string
	PushedAt    time.Time
}

// InsertWasmCheckpointPush records a successful AOCR push for keep-last-N retention.
func (s *Store) InsertWasmCheckpointPush(ctx context.Context, sandboxID, registryRef, digest string) (int64, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO wasm_checkpoint_pushes (sandbox_id, registry_ref, digest, pushed_at)
		VALUES (?, ?, ?, ?)`,
		strings.TrimSpace(sandboxID), strings.TrimSpace(registryRef), strings.TrimSpace(digest), now)
	if err != nil {
		return 0, fmt.Errorf("insert wasm checkpoint push: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ListWasmCheckpointPushes returns push history newest-first.
func (s *Store) ListWasmCheckpointPushes(ctx context.Context, sandboxID string) ([]WasmCheckpointPushRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, sandbox_id, registry_ref, digest, pushed_at
		FROM wasm_checkpoint_pushes
		WHERE sandbox_id = ?
		ORDER BY pushed_at DESC, id DESC`, strings.TrimSpace(sandboxID))
	if err != nil {
		return nil, fmt.Errorf("list wasm checkpoint pushes: %w", err)
	}
	defer rows.Close()
	var out []WasmCheckpointPushRecord
	for rows.Next() {
		var rec WasmCheckpointPushRecord
		if err := rows.Scan(&rec.ID, &rec.SandboxID, &rec.RegistryRef, &rec.Digest, &rec.PushedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DeleteWasmCheckpointPush removes one push history row by id.
func (s *Store) DeleteWasmCheckpointPush(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM wasm_checkpoint_pushes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete wasm checkpoint push: %w", err)
	}
	return nil
}

// DeleteAllWasmCheckpointPushes removes all retained AOCR push-history rows for sandboxID.
func (s *Store) DeleteAllWasmCheckpointPushes(ctx context.Context, sandboxID string) error {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM wasm_checkpoint_pushes WHERE sandbox_id = ?`, sandboxID)
	if err != nil {
		return fmt.Errorf("delete all wasm checkpoint pushes: %w", err)
	}
	return nil
}

// UpdateWasmRegistryPush records the AOCR ref/digest after a durable checkpoint push.
func (s *Store) UpdateWasmRegistryPush(ctx context.Context, sandboxID, registryRef, digest string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE sandboxes
		SET wasm_registry_ref = ?, wasm_registry_digest = ?, updated_at = ?
		WHERE id = ?
	`, strings.TrimSpace(registryRef), strings.TrimSpace(digest), now, sandboxID)
	if err != nil {
		return fmt.Errorf("update wasm registry push: %w", err)
	}
	return nil
}

// ListReadyWasmModuleRefs returns module_ref values for ready catalogue rows.
func (s *Store) ListReadyWasmModuleRefs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT module_ref FROM wasm_modules
		WHERE status = 'ready' AND module_ref != ''
		ORDER BY module_ref`)
	if err != nil {
		return nil, fmt.Errorf("list ready wasm module refs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// ListWasmModulesOlderThan returns catalogue rows not updated since cutoff.
func (s *Store) ListWasmModulesOlderThan(ctx context.Context, cutoff time.Time) ([]WasmModuleRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, module_ref, status, module_path, module_size_bytes, digest,
			entrypoint, has_warm, last_error, created_at, updated_at, ready_at
		FROM wasm_modules
		WHERE updated_at < ?
		ORDER BY updated_at ASC`, cutoff.UTC())
	if err != nil {
		return nil, fmt.Errorf("list wasm modules older than: %w", err)
	}
	defer rows.Close()
	var out []WasmModuleRecord
	for rows.Next() {
		rec, err := scanWasmModule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// IsWasmModuleReferenced reports whether any sandbox still names moduleRef or digest id.
// IsWasmModuleReferenced reports whether any sandbox row still depends on this
// module. The check spans ref, id, AND the resolved content digest: two
// aliases/tags can share the same bytes, so deleting/evicting purely by ref
// would yank a digest still in use by another sandbox (codex C5). A blank
// moduleDigest simply contributes no extra match.
func (s *Store) IsWasmModuleReferenced(ctx context.Context, moduleID, moduleRef, moduleDigest string) (bool, error) {
	moduleID = strings.TrimSpace(moduleID)
	moduleRef = strings.TrimSpace(moduleRef)
	moduleDigest = strings.TrimSpace(moduleDigest)
	row := s.db.QueryRowContext(ctx, `
		SELECT 1 FROM sandboxes
		WHERE module_ref = ? OR module_ref = ? OR module_digest = ? OR
		      (? <> '' AND module_digest = ?)
		LIMIT 1`, moduleRef, moduleID, moduleID, moduleDigest, moduleDigest)
	var one int
	err := row.Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// IsWasmDigestCatalogued reports whether any wasm_modules row pins this content
// digest. The cache evictor consults it (alongside IsWasmModuleReferenced) so a
// digest that backs a catalogue id — resolvable later by a fresh create — is
// never reclaimed out from under the catalogue, even with no live sandbox.
func (s *Store) IsWasmDigestCatalogued(ctx context.Context, digest string) (bool, error) {
	digest = strings.TrimSpace(digest)
	if digest == "" {
		return false, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM wasm_modules WHERE digest = ? LIMIT 1`, digest)
	var one int
	err := row.Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// WasmDigestsInUse returns the subset of digests that are still referenced by a
// live sandbox OR pinned by a catalogue row. The cache evictor calls this ONCE
// per sweep with every candidate digest instead of two probes per file, so a
// large cache no longer issues O(files) serialized queries against the
// single-writer DB (codex P1). Digests are chunked to stay under SQLite's bound
// parameter limit.
func (s *Store) WasmDigestsInUse(ctx context.Context, digests []string) (map[string]struct{}, error) {
	inUse := make(map[string]struct{})
	const chunk = 400 // half the 999 bound-param limit (used twice per row)
	for start := 0; start < len(digests); start += chunk {
		end := start + chunk
		if end > len(digests) {
			end = len(digests)
		}
		batch := digests[start:end]
		ph := make([]string, len(batch))
		// One arg list reused for both the sandboxes and wasm_modules predicate.
		args := make([]any, 0, len(batch)*2)
		for i, d := range batch {
			ph[i] = "?"
			args = append(args, d)
		}
		for _, d := range batch {
			args = append(args, d)
		}
		in := strings.Join(ph, ",")
		q := `SELECT module_digest FROM sandboxes WHERE module_digest IN (` + in + `)
		      UNION
		      SELECT digest FROM wasm_modules WHERE digest IN (` + in + `)`
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("wasm digests in use: %w", err)
		}
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				rows.Close()
				return nil, err
			}
			inUse[d] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return inUse, nil
}

// ErrWasmModuleIDConflict is returned when POST /v1/wasm-modules reuses an id
// bound to a different module_ref.
var ErrWasmModuleIDConflict = errors.New("wasm module id already in use")

// ErrWasmModuleInUse blocks DELETE while a sandbox still references the module.
var ErrWasmModuleInUse = errors.New("wasm module is referenced by an active sandbox")

func scanWasmModule(row interface {
	Scan(dest ...any) error
}) (WasmModuleRecord, error) {
	var rec WasmModuleRecord
	var hasWarm int
	var readyAt sql.NullTime
	if err := row.Scan(
		&rec.ID, &rec.ModuleRef, &rec.Status, &rec.ModulePath, &rec.ModuleSizeBytes,
		&rec.Digest, &rec.Entrypoint, &hasWarm, &rec.LastError,
		&rec.CreatedAt, &rec.UpdatedAt, &readyAt,
	); err != nil {
		return WasmModuleRecord{}, err
	}
	rec.HasWarm = hasWarm != 0
	if readyAt.Valid {
		t := readyAt.Time
		rec.ReadyAt = &t
	}
	return rec, nil
}

// GetWasmModule returns one wasm_modules row by catalogue id.
func (s *Store) GetWasmModule(ctx context.Context, id string) (WasmModuleRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return WasmModuleRecord{}, errors.New("get wasm module: id required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, module_ref, status, module_path, module_size_bytes, digest,
			entrypoint, has_warm, last_error, created_at, updated_at, ready_at
		FROM wasm_modules WHERE id = ?`, id)
	rec, err := scanWasmModule(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WasmModuleRecord{}, ErrNotFound
		}
		return WasmModuleRecord{}, fmt.Errorf("get wasm module: %w", err)
	}
	return rec, nil
}

// ListWasmModules returns all catalogue rows newest-first.
func (s *Store) ListWasmModules(ctx context.Context) ([]WasmModuleRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, module_ref, status, module_path, module_size_bytes, digest,
			entrypoint, has_warm, last_error, created_at, updated_at, ready_at
		FROM wasm_modules
		ORDER BY created_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list wasm modules: %w", err)
	}
	defer rows.Close()
	var out []WasmModuleRecord
	for rows.Next() {
		rec, err := scanWasmModule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DeleteWasmModule removes a wasm_modules catalogue row.
func (s *Store) DeleteWasmModule(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("delete wasm module: id required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM wasm_modules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete wasm module: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CompareCloneGeneration rejects stale snapshot writes when wantGen is older
// than the row's current clone_generation (§4.8 fencing).
func (s *Store) CompareCloneGeneration(ctx context.Context, sandboxID, snapshotGen string) error {
	row := s.db.QueryRowContext(ctx, `SELECT clone_generation FROM sandboxes WHERE id = ?`, sandboxID)
	var current string
	if err := row.Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	current = strings.TrimSpace(current)
	snapshotGen = strings.TrimSpace(snapshotGen)
	if current == "" || snapshotGen == "" || current == snapshotGen {
		return nil
	}
	return fmt.Errorf("clone generation mismatch (row=%s snapshot=%s): %w", current, snapshotGen, models.ErrSnapshotFenced)
}
