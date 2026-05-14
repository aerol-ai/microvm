---
name: add-store-column
description: Add a column or table to the SQLite store at internal/store/store.go. Covers idempotent CREATE/ALTER, scanner updates, Create/Upsert wiring, and the mandatory regression test for host-port pool changes. Use when the user asks to "add a column to the store", "persist X for sandboxes", "store this in the database", or any schema change. Proactively suggest when a feature needs durable per-sandbox state.
---

# Add a column / table to the store

## Architecture constraints

- **SQLite, single-writer in-process.** `Open()` sets `MaxOpenConns=1` so API handlers, the event monitor, and background sweeps queue through `database/sql` instead of racing separate SQLite connections into "database is locked". Don't add a second `*sql.DB`.
- **No migrations framework.** The schema is additive + idempotent on startup: `CREATE TABLE IF NOT EXISTS` and additive `ALTER TABLE` only. Renames and drops are not supported.
- **Secrets on disk.** `env_json`, `toolbox_token`, and sealed mount blobs live in this DB. `Open()` chmods the directory and file to 0700. Don't loosen those modes.

## Steps

1. **Edit `internal/store/store.go`:**
   - **New table:** add a `CREATE TABLE IF NOT EXISTS …` statement to the `stmts` slice in `Open()`.
   - **New column on existing table:** add an `ALTER TABLE … ADD COLUMN … DEFAULT …` after the `CREATE TABLE IF NOT EXISTS` for that table. Adding a column with a `DEFAULT` is safe on existing rows.
   - **Foreign keys:** keep `PRAGMA foreign_keys = ON;` (already set).

2. **Read path:** update the matching `scan*` function (`scanSandbox`, `scanDaytonaMetadata`, `scanE2BSandboxMetadata`, `scanE2BSnapshotMetadata`, `scanSnapshot`, …) so the new column is loaded into the model.

3. **Write path:** update `Create` and/or `Upsert` so the new column is inserted/updated. For sandboxes that's `Store.Create` and `Store.Upsert`.

4. **Models:** if the column belongs on a wire DTO, mirror it on `pkg/models/*.go`. Be aware that `pkg/models` is shared between the server, the facades, and the SDKs' internal Go transport — a field added there ripples widely. Keep DTOs lean.

5. **Tests:** add a regression test in `internal/store/store_test.go`.

## Mandatory regression tests

A regression test in `internal/store/store_test.go` is **required** (not optional) if your change touches any of:

- `Store.TryReserveHostPort` semantics
- The partial unique index on `exposed_ports.host_port`
- `Service.allocateHostPort` allocator loop

Filling in the PR template's "L4 / host-port-pool changes" section linking the test is also required. See `pr-review.md` §7.

## Common scanner functions (current)

`store.go` has scanners around line 1115+: `scanSandbox`, `scanDaytonaMetadata`, `scanE2BSandboxMetadata`, `scanE2BSnapshotMetadata`, `scanSnapshot`. If you add a new table, add a `scan<NewType>` next to the others.
