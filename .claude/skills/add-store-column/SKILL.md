---
name: add-store-column
description: Add a column or table to the SQLite store at internal/store/store.go. Covers idempotent CREATE/ALTER, scanner updates, Create/Upsert wiring, and the mandatory regression test for host-port pool changes. Use when the user asks to "add a column to the store", "persist X for sandboxes", "store this in the database", or any schema change. Proactively suggest when a feature needs durable per-sandbox state.
---

# Add a column / table to the store

## Architecture constraints

- **SQLite: one writer plus a read-only pool.** `open()` keeps one writer connection (`Store.db`, `MaxOpenConns=1`) for every write and transaction, so writers queue in `database/sql` instead of racing into "database is locked". Plain reads outside a transaction use the `query_only` pool (`Store.rdb`). Don't open another writable `*sql.DB`; a statement that writes (including `UPDATE … RETURNING`) and every claim path uses `s.db` (see CLAUDE.md and `TestClaimPathsReadOnWriter`).
- **Numbered migrations (`internal/store/schema_migrations.go`).** Every schema change is an entry in `newerSchemaMigrations` with the next number and an `n1Safe` flag, recorded in `schema_migrations`. `n1Safe: true` = only adds tables or columns the previous release ignores; it runs at open. Anything else (rebuild a table, backfill or rewrite data, a new constraint) is one-way: it waits for `Store.RunOneWayMigrations` (cluster finalize; right after open with cluster mode off), and the code that ships it must still work on the old schema until `PendingOneWayMigrations` is empty. Never renumber or remove an entry. The inline `stmts` / `migrations` lists in `open()` are the frozen legacy steps 1 and 2; don't grow them. A build refuses a database with an applied one-way number it doesn't know (plans/kubectl-style-cluster-ops.md §6.5).
- **Indexes.** A new `CREATE INDEX IF NOT EXISTS` is an `n1Safe: true` entry in `newerSchemaMigrations` (a non-unique index is additive: the previous release ignores it; a unique index is a constraint, so one-way). SQLite uses a partial index (`… WHERE name <> ''`) only when the query repeats that condition; a bound parameter does not prove it. Check the plan with the `queryPlan` test helper (see `TestSandboxIDAsNameCheckSeeksAnIndex`).
- **Secrets on disk.** `env_json`, `toolbox_token`, and sealed mount blobs live in this DB. `Open()` chmods the directory and file to 0700. Don't loosen those modes.

## Steps

1. **Append a migration to `newerSchemaMigrations` in `internal/store/schema_migrations.go`:**
   - **New table:** `{number: N, name: "...", n1Safe: true, applyTx: ...}` running `CREATE TABLE IF NOT EXISTS …`.
   - **New column on existing table:** an `n1Safe: true` entry running `ALTER TABLE … ADD COLUMN … DEFAULT …` (tolerate "duplicate column name" if the column is also in a `CREATE TABLE`). Adding a column with a `DEFAULT` is safe on existing rows.
   - **Rebuild / backfill / drop:** `n1Safe: false`; list its number in the PR as a one-way migration (release.json `one_way_migrations` picks it up via `store.OneWayMigrations`).
   - **Foreign keys:** keep `PRAGMA foreign_keys = ON;` (already set).

2. **Read path:** update the matching `scan*` function (`scanSandbox`, `scanDaytonaMetadata`, `scanE2BSandboxMetadata`, `scanE2BSnapshotMetadata`, `scanSnapshot`, …) so the new column is loaded into the model.

3. **Write path:** update `Create` and/or `Upsert` so the new column is inserted/updated. For sandboxes that's `Store.Create` and `Store.Upsert`.

4. **Models:** if the column belongs on a wire DTO, mirror it on `pkg/models/*.go`. Be aware that `pkg/models` is shared between the server, the facades, and the SDKs' internal Go transport — a field added there ripples widely. Keep DTOs lean.

5. **Tests:** add a regression test in `internal/store/store_test.go`; for a one-way migration, also prove the code works before `RunOneWayMigrations` (see `schema_migrations_test.go`).

## Mandatory regression tests

A regression test in `internal/store/store_test.go` is **required** (not optional) if your change touches any of:

- `Store.TryReserveHostPort` semantics
- The partial unique index on `exposed_ports.host_port`
- `Service.allocateHostPort` allocator loop

Filling in the PR template's "L4 / host-port-pool changes" section linking the test is also required. See `pr-review.md` §7.

## Common scanner functions (current)

`store.go` has scanners around line 1115+: `scanSandbox`, `scanDaytonaMetadata`, `scanE2BSandboxMetadata`, `scanE2BSnapshotMetadata`, `scanSnapshot`. If you add a new table, add a `scan<NewType>` next to the others.
