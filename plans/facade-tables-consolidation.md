# Consolidating the Daytona and E2B Facade Tables

## Context

`internal/store/store.go` today creates **four** tables that exist purely to
back the compatibility facades:

- `daytona_sandboxes` — extra fields for `/daytona/...` responses
- `e2b_sandboxes` — extra fields for `/e2b/...` responses
- `e2b_snapshots` — E2B-shaped snapshot ID / alias on top of native snapshots
- `e2b_create_requests` — request-fingerprint idempotency state for the
  `POST /e2b/sandboxes` create path (added after the first revision of this
  plan)

The native tables are `sandboxes`, `exposed_ports`, `sandbox_mounts`, and
`sandbox_snapshots`. No other facade-specific tables exist.

The first three tables are per-sandbox metadata (one row per sandbox). The
fourth is structurally different: it's a request-level state machine
(`pending` → `ready`, with `locked_until` / `replay_until` TTLs) keyed on
a SHA-256 fingerprint of the canonicalised create request. Same architectural
smell — facade-named schema — but a different fix.

Worth calling out alongside the data-model work: the recent `/e2b/runtime`
gateway in `pkg/api/e2b/runtime_proxy.go` and the toolboxd `/envd` namespace
in `cmd/toolboxd/envd.go` are *exactly* the pattern this plan endorses —
pure translation layers with no new schema. The data-model work below is
what's left to bring into the same shape.

This document answers three things the user asked:

1. Are these tables compatible with the rest of the API surface?
2. Why were they introduced (what is each column actually doing)?
3. Can they be merged, and what would that take?

The user's stated direction is that **AerolVM owns the data model**, and the
Daytona / E2B endpoints are translation facades, not parallel products. The
recommendation below is consistent with that direction.

## Are these tables compatible with other APIs?

Yes — but only in the weak sense that they do not break anything. The native
`/v1` API does not read or write any of them; the facades are the only
writers. Cross-API behavior today:

| Path | Reads native `sandboxes` | Reads facade tables |
|---|---|---|
| `/v1/sandboxes/...` | yes | never |
| `/daytona/...` | yes | `daytona_sandboxes` |
| `/e2b/...` | yes | `e2b_sandboxes`, `e2b_snapshots`, `e2b_create_requests` |
| `/e2b/runtime/...` | yes (to resolve `E2b-Sandbox-Id`) | none — proxies through to toolboxd `/envd` |

Consequences worth flagging:

- A sandbox created via `/v1` is visible in `/daytona/sandboxes` and
  `/e2b/sandboxes` list responses with **default** facade metadata
  (empty name, empty labels, empty template alias). That is a quietly
  surprising user-facing behavior — a Daytona client sees E2B sandboxes
  with `name == id`, and an E2B client sees `/v1` sandboxes with the raw
  AerolVM image as the `templateID`.
- `FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE`
  is set on both `daytona_sandboxes` and `e2b_sandboxes`, so destroying
  a sandbox through any API surface cleans both metadata rows. Good.
- `e2b_snapshots` does **not** have a foreign key back to
  `sandbox_snapshots(name)`. Deleting via `/v1/snapshots/{name}` would
  orphan an `e2b_snapshots` row. The facade compensates by calling
  `DeleteE2BSnapshot` in the same handler, but a `/v1` delete bypasses
  that path. This is a latent inconsistency, not a hot bug.
- `daytona_sandboxes.name` has a `UNIQUE` constraint and is consulted by
  `ResolveDaytonaSandboxID`. This effectively gives sandboxes a
  **Daytona-only** name namespace that `/v1` callers cannot see or
  collide with — also surprising, since names feel global.

Net: nothing is broken, but the tables encode a worldview where "Daytona
sandboxes" and "E2B sandboxes" are first-class species. That is exactly the
worldview the user rejected.

## Why each column exists (column-by-column verdict)

The columns fall into three categories. The label in `[brackets]` is the
proposed disposition.

### `daytona_sandboxes`

| Column | What it stores | Verdict |
|---|---|---|
| `sandbox_id` | FK to `sandboxes.id` | `[join key — needed only if a table survives]` |
| `name` | User-supplied Daytona sandbox name | `[promote to native]` — name lookup is a generic capability, not a Daytona quirk |
| `snapshot` | The Daytona `Snapshot` field, remembered verbatim | `[drop, derive]` — the resolved image is already in `sandboxes.image`; if we need the original wire-level snapshot ref, it belongs in a generic metadata bag, not a column |
| `user_name` | The `User` field from the request | `[drop, derive]` — `sandboxes.os_user` already stores this |
| `labels_json` | Free-form key/value labels | `[promote to native]` — labels are a feature every API will eventually want |
| `target` | Daytona region/target string | `[drop or generic bag]` — AerolVM is single-host, this is pure echo-back; remember only if a Daytona client expects round-tripping |
| `network_allow_list` | Daytona-shaped allowlist (single string) | `[drop or generic bag]` — AerolVM's real network policy is `network_block_all`; this column is just echo-back |
| `auto_stop_interval_minutes` | Daytona's wire-format interval | `[drop, derive]` — `sandboxes.stop_if_idle_for_ns` already stores this; convert on read |
| `auto_archive_interval_minutes` | Daytona's archive interval | `[drop or generic bag]` — AerolVM has no archive concept; this is echo-back |
| `auto_delete_interval_minutes` | Daytona's destroy interval | `[drop, derive]` — `sandboxes.destroy_if_idle_for_ns` already stores this |
| `created_at` / `updated_at` | Row timestamps | `[drop]` — redundant with `sandboxes` |

### `e2b_sandboxes`

| Column | What it stores | Verdict |
|---|---|---|
| `sandbox_id` | FK to `sandboxes.id` | `[join key]` |
| `template_id` | The E2B template token the client sent | `[generic bag]` — opaque wire string, no native equivalent |
| `template_alias` | Friendly alias resolved from template map | `[generic bag]` — same |
| `metadata_json` | Free-form key/value metadata | `[promote to native]` — same shape as Daytona labels; one table can serve both |
| `timeout_seconds` | E2B-shaped timeout | `[drop, derive]` — `sandboxes.stop_at_age_ns` / `destroy_at_age_ns` already encode this |
| `on_timeout` | `"kill"` vs `"pause"` semantics | `[generic bag]` — controls which lifecycle axis the facade writes; not a native concept but needed to round-trip |
| `auto_resume` | E2B auto-resume flag | `[generic bag]` — pure wire echo |
| `secure` | E2B `secure` flag | `[generic bag]` — pure wire echo |
| `allow_internet_access` | E2B internet flag (nullable) | `[drop, derive]` — inverse of `sandboxes.network_block_all`; reconstruct on read |
| `network_allow_out_json` | E2B allow-out CIDR list | `[generic bag]` — AerolVM has no per-sandbox allow-out today |
| `network_deny_out_json` | E2B deny-out CIDR list | `[drop, derive]` — collapses to `network_block_all` per existing handler logic |
| `allow_public_traffic` | E2B public flag | `[generic bag]` |
| `mask_request_host` | E2B host masking | `[generic bag]` |
| `created_at` / `updated_at` | Row timestamps | `[drop]` |

### `e2b_snapshots`

| Column | What it stores | Verdict |
|---|---|---|
| `snapshot_id` | E2B-shaped opaque ID (base64-ish) | `[generic alias table]` — a snapshot can have alternate IDs in any facade |
| `snapshot_name` | Native `sandbox_snapshots.name` it aliases | `[join key into native]` |
| `names_json` | Extra Daytona/E2B-visible names | `[generic alias table]` |
| `source_sandbox_id` | Already on `sandbox_snapshots` | `[drop]` |
| `created_at` / `updated_at` | Already on `sandbox_snapshots` | `[drop]` |

### `e2b_create_requests`

This one is not per-sandbox metadata — it's a per-request idempotency state
machine. Fingerprint is the canonical SHA-256 hash of the normalized create
inputs (`pkg/api/e2b/meta.go`'s `createRequestFingerprint`). The facade
claims a row, runs `CreateSandbox`, then moves the row from `pending` to
`ready` with a 10-second replay window.

| Column | What it stores | Verdict |
|---|---|---|
| `fingerprint` | Canonical hash of normalized create body | `[generic idempotency table]` — keying primitive |
| `sandbox_id` | The sandbox eventually produced (empty while pending) | `[generic idempotency table]` |
| `state` | `pending` or `ready` | `[generic idempotency table]` |
| `locked_until` | TTL preventing duplicate creates while one is in flight | `[generic idempotency table]` |
| `replay_until` | TTL during which retries get the same response | `[generic idempotency table]` |
| `created_at` / `updated_at` | Row timestamps | `[keep]` — non-redundant here |

Verdict: this is a **generic request-idempotency primitive** that we should
not bake into an E2B-named table. The same shape will be useful for
`/daytona/sandboxes` if Daytona retries become a problem, and arguably for
`/v1/sandboxes` too — the native API has zero create-side dedupe today.

Importantly, the design itself is right (state machine, replay window,
fingerprint-based key). Only the naming and table location are facade-shaped.
The handler logic in `pkg/api/e2b/handlers.go` does not need to change in
spirit, only in what table it talks to.

## Summary of the verdict

Across the four tables, the columns reduce to five real categories:

1. **Truly duplicated native state.** Lifecycle intervals, OS user, internet
   access, snapshot-via-image. These should be derived from `sandboxes`
   on read. Storing them twice is the bug — they can drift on partial
   failures (the handler updates `Lifecycle` and then the metadata row;
   a crash between the two leaves them inconsistent).

2. **Genuinely useful generic capabilities AerolVM should own natively.**
   - `name` (with uniqueness) — `daytona_sandboxes.name`
   - tag/label map — `daytona_sandboxes.labels_json` and
     `e2b_sandboxes.metadata_json` are the same shape

3. **Opaque wire-only state that has no native meaning.**
   - Daytona: `target`, `network_allow_list`, `auto_archive_interval_minutes`,
     `snapshot` echo.
   - E2B: `template_id`, `template_alias`, `on_timeout`, `auto_resume`,
     `secure`, `allow_public_traffic`, `mask_request_host`,
     `network_allow_out`.
   - These exist only so a client that wrote `X` reads `X` back. They are
     facade-private state.

4. **Alias / alternate-ID mappings.** `e2b_snapshots` is mostly this.
   Daytona currently has no snapshot aliases but is likely to need
   something similar.

5. **Request-idempotency state.** `e2b_create_requests` is this whole
   category by itself. Not metadata, not sandbox-scoped — it's transient
   state about an in-flight request and its replay window. Belongs in a
   facade-agnostic idempotency table that any route family can use.

## Recommended target shape

Goal: zero facade-named tables. AerolVM owns the data model; each facade
keeps only an opaque "remember-what-the-client-said" bag for round-tripping.

### 1. Promote `name` to a native first-class field

Add `name TEXT NOT NULL DEFAULT '' UNIQUE COLLATE NOCASE` (or with a partial
unique index on `name <> ''` to keep older rows valid) to `sandboxes`.

- Native API can ignore it for now; SDKs can opt in later.
- `ResolveDaytonaSandboxID` becomes `ResolveSandboxIDByName` in `service`.
- Daytona creates pass `req.Name` straight to `models.CreateSandboxRequest`.

This is the only change that touches `pkg/models/types.go` and the SDK
transport. Worth doing because Daytona+E2B both lean on name-like lookup
anyway, and the user has stated this should not be Daytona-specific.

### 2. Promote labels/metadata to one native table

Replace `daytona_sandboxes.labels_json` and `e2b_sandboxes.metadata_json`
with one of:

a. `sandboxes.tags_json TEXT NOT NULL DEFAULT '{}'` — simplest, mirrors
   how `env_json`/`gpus_json` already live as JSON columns.
b. `sandbox_tags(sandbox_id, key, value)` — better for filtering at scale,
   but list filtering today is in-memory anyway.

Recommendation: **(a)**. AerolVM list endpoints already iterate in memory;
the JSON column is consistent with the existing pattern and is the
smallest change. Filtering on labels in `/daytona/sandboxes?labels=...`
keeps working unchanged.

### 3. Collapse remaining wire-only state into one generic table

Add a single facade-agnostic table:

```sql
CREATE TABLE sandbox_compat_state (
    sandbox_id TEXT NOT NULL,
    facade TEXT NOT NULL,                -- 'daytona' | 'e2b'
    state_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (sandbox_id, facade),
    FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
);
```

The `state_json` blob is opaque to the store layer. Each facade defines
its own JSON shape — Daytona stores `{target, snapshot_ref,
network_allow_list, auto_archive_interval_minutes}`, E2B stores
`{template_id, template_alias, on_timeout, auto_resume, secure,
allow_public_traffic, mask_request_host, network_allow_out}`.

Result:

- `daytona_sandboxes` → gone.
- `e2b_sandboxes` → gone.
- Adding a third facade later (e.g. Modal, Replit) needs zero schema
  changes.
- The store stays facade-agnostic; the schema name `sandbox_compat_state`
  describes a category, not a vendor.

### 4. Replace `e2b_create_requests` with a generic request-idempotency table

The fingerprint-based dedupe is well-designed and worth keeping. Just give
it a facade-agnostic home:

```sql
CREATE TABLE request_idempotency (
    fingerprint TEXT NOT NULL,
    scope TEXT NOT NULL,                 -- 'e2b.create' | 'daytona.create' | ...
    target_id TEXT NOT NULL DEFAULT '',  -- sandbox id, snapshot id, etc.
    state TEXT NOT NULL DEFAULT 'pending',
    locked_until DATETIME NOT NULL,
    replay_until DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (scope, fingerprint)
);
CREATE INDEX idx_request_idempotency_replay_until
    ON request_idempotency(replay_until);
```

Notes:

- The composite primary key `(scope, fingerprint)` means E2B and Daytona
  fingerprints don't share a namespace, so we don't have to worry about
  cross-facade collisions even though both use SHA-256.
- `target_id` is intentionally generic — it's currently always a sandbox
  ID, but the same machinery works for snapshot create idempotency later
  without schema churn.
- Store helpers stay the same shape (`ClaimRequest`, `CompleteRequest`,
  `GetRequest`, `DeleteRequest`) and just take an extra `scope` argument.
  The E2B handler passes `"e2b.create"`.
- Eventually `/v1/sandboxes` POST could opt in to the same primitive
  behind an `Idempotency-Key` header. That work is out of scope here, but
  the table shape is designed so we don't have to migrate again to enable
  it.

### 5. Collapse `e2b_snapshots` into a generic alias table

Replace with:

```sql
CREATE TABLE snapshot_aliases (
    alias TEXT PRIMARY KEY,
    snapshot_name TEXT NOT NULL,         -- FK to sandbox_snapshots.name
    facade TEXT NOT NULL,                -- 'e2b' (others later)
    extra_names_json TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (snapshot_name) REFERENCES sandbox_snapshots(name) ON DELETE CASCADE
);
CREATE INDEX idx_snapshot_aliases_snapshot_name ON snapshot_aliases(snapshot_name);
```

Adding the missing FK to `sandbox_snapshots` also fixes the orphan-row
bug where `/v1/snapshots/{name}` delete leaves an `e2b_snapshots` row
behind.

### 6. Derive everything else on read

Eliminate the duplicated columns. The facade response layer recomputes
them from `sandboxes`:

- Daytona `autoStopInterval` ← `Lifecycle.StopIfIdleFor / time.Minute`
- Daytona `autoDeleteInterval` ← `Lifecycle.DestroyIfIdleFor / time.Minute`
- Daytona `user` ← `sandboxes.os_user`
- E2B `timeoutSeconds` ← `Lifecycle.StopAtAge` or `Lifecycle.DestroyAtAge`
  (whichever is non-zero, choose by `state.on_timeout`)
- E2B `allowInternetAccess` ← `!sandboxes.network_block_all`

This is exactly what the handlers already do as a fallback when the
metadata row is missing (`durationMinutesPtr(sandbox.Lifecycle.StopIfIdleFor)`,
etc.) — the consolidation just makes that the **only** path.

## End-state schema

After the consolidation:

```text
sandboxes(
    ...existing columns...,
    name TEXT UNIQUE,                    -- NEW (native)
    tags_json TEXT DEFAULT '{}'          -- NEW (native, generic)
)
exposed_ports(...)                       -- unchanged
sandbox_mounts(...)                      -- unchanged
sandbox_snapshots(...)                   -- unchanged
sandbox_compat_state(                    -- NEW (one row per (sandbox,facade))
    sandbox_id, facade, state_json,
    created_at, updated_at
)
snapshot_aliases(                        -- NEW (replaces e2b_snapshots)
    alias, snapshot_name, facade,
    extra_names_json, created_at, updated_at
)
request_idempotency(                     -- NEW (replaces e2b_create_requests)
    scope, fingerprint, target_id, state,
    locked_until, replay_until,
    created_at, updated_at
)
```

Seven tables, none named after a third-party product.

## Migration plan

The data lives in the dev DB only; AerolVM is self-hosted, so we control
the upgrade. Migrations should be idempotent and additive in one release,
destructive in a follow-up.

### Phase A — additive (one release)

1. `ALTER TABLE sandboxes ADD COLUMN name TEXT NOT NULL DEFAULT '';`
2. `CREATE UNIQUE INDEX idx_sandboxes_name ON sandboxes(name) WHERE name <> '';`
3. `ALTER TABLE sandboxes ADD COLUMN tags_json TEXT NOT NULL DEFAULT '{}';`
4. Create `sandbox_compat_state`, `snapshot_aliases`, and
   `request_idempotency`.
5. Backfill from existing tables (one-shot at startup, idempotent):
   - `sandboxes.name` ← `daytona_sandboxes.name`
   - `sandboxes.tags_json` ← `daytona_sandboxes.labels_json` (and merge
     with `e2b_sandboxes.metadata_json` for sandboxes that have both)
   - `sandbox_compat_state` rows derived from leftover Daytona/E2B columns
   - `snapshot_aliases` rows from `e2b_snapshots`
   - `request_idempotency` rows from `e2b_create_requests` with
     `scope = 'e2b.create'`
6. Switch reads in `pkg/api/daytona` and `pkg/api/e2b` to the new
   tables. Writes go to both old and new until Phase B.
7. Keep `/v1` unchanged. Internally everyone reads from `sandboxes` +
   the new generic tables.

### Phase B — destructive (next release)

1. Stop writing to `daytona_sandboxes`, `e2b_sandboxes`, `e2b_snapshots`,
   `e2b_create_requests`.
2. `DROP TABLE daytona_sandboxes;`
3. `DROP TABLE e2b_sandboxes;`
4. `DROP TABLE e2b_snapshots;`
5. `DROP TABLE e2b_create_requests;`
6. Delete the old store helpers (`UpsertDaytonaMetadata`,
   `GetDaytonaMetadata`, …, `DeleteE2BSnapshot`,
   `ClaimE2BCreateRequest`, `CompleteE2BCreateRequest`,
   `GetE2BCreateRequest`, `DeleteE2BCreateRequest`).
7. Rename `ResolveDaytonaSandboxID` → `ResolveSandboxIDByName` (now in
   the native service surface, not a Daytona-named helper).
8. Rename the idempotency service methods to drop the `E2B` prefix
   (`ClaimRequest`, `CompleteRequest`, `GetRequest`, `DeleteRequest`)
   and take a `scope` argument.

Splitting it in two releases keeps the dev DB safe across a downgrade and
lets us run tests against the new path while the old path is still
authoritative.

## Files that change

- `internal/store/store.go` — schema, helpers, scanners, the `Resolve*`
  function rename, generic `request_idempotency` helpers.
- `internal/store/store_test.go` — new tests for `name` uniqueness, the
  generic `sandbox_compat_state` upsert path, and the
  `request_idempotency` claim/complete/reclaim cycle (port the existing
  `e2b_create_request_claim_complete_and_reclaim` test to the generic
  scope keying).
- `internal/service/daytona.go` — collapse to wrappers around
  `sandbox_compat_state`.
- `internal/service/e2b.go` — same, plus rename
  `Claim/Complete/Get/DeleteE2BCreateRequest` to scope-aware generic
  methods.
- `pkg/models/daytona.go`, `pkg/models/e2b.go` — keep the structs for
  facade-internal use, but they no longer have a 1:1 column mapping;
  the facade serializes them into `state_json`.
- `pkg/models/e2b.go` — `E2BCreateRequestRecord` becomes a generic
  `IdempotentRequestRecord` (or stays E2B-named but is just an alias
  over the generic record; either is fine).
- `pkg/models/types.go` — add `Name` and `Tags` to `Sandbox` and
  `CreateSandboxRequest`. SDKs follow when ready.
- `pkg/api/daytona/handlers.go`, `pkg/api/e2b/handlers.go` — read derived
  fields from `sandbox` first, fall back to facade state for opaque
  wire-only bits. Most of this logic already exists as the
  "metadata-not-found fallback" branches.
- `pkg/api/e2b/meta.go` — `createRequestFingerprint` stays put; the
  handler passes its output to the generic idempotency primitive with
  `scope = "e2b.create"`.

## What's already in the right shape

These pieces of the recent E2B work do not need to change:

- `pkg/api/e2b/runtime_proxy.go` — pure HTTP gateway, no schema.
- `cmd/toolboxd/envd.go` — Connect-RPC translation layer in toolboxd;
  no native model assumptions leak in.
- `pkg/api/e2b/meta.go` `createRequestFingerprint` — canonicalisation is
  facade-specific *by design* (E2B's create body shape) and that's fine.
  Only the table it writes to is wrong.
- The handler's `pending`/`ready`/replay state machine in
  `pkg/api/e2b/handlers.go` `createSandbox` — semantics are right;
  only the underlying store call changes.

## Open questions before coding

1. Do we want `name` exposed in `/v1` now, or only stored and reserved
   for SDK plumbing later? Recommendation: store it now, expose in `/v1`
   when SDKs catch up. The schema change is the irreversible part.
2. Do we want `tags`/`labels` exposed in `/v1` now? Same answer.
3. For `e2b_snapshots`, the current schema lets one native snapshot have
   one E2B ID. Do we ever expect to expose the same snapshot under
   multiple facades simultaneously? If yes, `snapshot_aliases` keyed on
   `alias` is correct. If no, a per-snapshot JSON column would suffice
   and is even simpler.
4. Are we willing to do the two-phase migration, or do we want to drop
   the old tables in the same release? Self-hosted means we can usually
   afford the one-shot — but two phases makes test/rollback trivial.

## Why this is a real cleanup, not just churn

- Eliminates the drift class: `Lifecycle` and `auto_*_interval_minutes`
  can no longer disagree because only `Lifecycle` exists.
- Eliminates the orphan-row bug for `e2b_snapshots` by adding the
  missing FK to `sandbox_snapshots`.
- Removes the "Daytona-named, but actually generic" capabilities (name
  lookup, labels, create idempotency) from a facade silo and gives them
  to the whole API surface.
- Specifically for idempotency: the create-dedupe machinery that landed
  for E2B is the right design to eventually offer on `/v1` as well. A
  generic table makes that a 2-line handler change later instead of
  another schema migration.
- Adding a third facade later (Modal, Replit, anything) becomes a wire
  translation patch, not a schema change — which is the whole point of
  the user's framing: **AerolVM is the product; the facades are
  translation**.

## Out of scope

- SDK changes. The native SDKs can pick up `name` and `tags` whenever
  they want; nothing in this plan forces them to.
- Network policy. The fact that AerolVM's per-sandbox allow-out / deny-out
  is weaker than E2B's wire contract is a separate question — for now,
  the facade just remembers what the client sent in the generic state
  bag and refuses requests AerolVM cannot honor.
- Snapshot lifecycle reform. `sandbox_snapshots` itself is fine; we only
  touch `e2b_snapshots`.
