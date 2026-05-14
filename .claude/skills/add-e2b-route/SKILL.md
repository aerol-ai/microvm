---
name: add-e2b-route
description: Add an E2B-SDK-compatible route under /e2b/... by mirroring the Daytona facade pattern. The /e2b package does not exist yet — copy pkg/api/daytona/ as the template. Forces the open create-idempotency design question to be answered before coding. Use when the user asks to "build the e2b facade", "add an /e2b route", "make E2B Python SDK work with X", or work on plans/sdk-compatibility/e2b/. Proactively suggest when an E2B SDK call needs server-side support.
---

# Add an E2B compatibility route

E2B compatibility is **planned, not yet built**. The canonical design is in [`plans/sdk-compatibility/e2b/facade-plan.md`](../../plans/sdk-compatibility/e2b/facade-plan.md). Read it before coding — the open design questions there are not optional polish, they're blockers.

## Status

- `pkg/api/e2b/` does **not exist yet**. The first PR that adds an `/e2b` route creates it.
- `internal/service/e2b.go` exists and currently holds metadata-storage helpers (Upsert/Get/List/Delete for sandbox metadata and snapshots).
- `pkg/models/e2b.go` exists with `E2BSandboxMetadata` and `E2BSnapshotMetadata`.
- Store helpers exist on `*Store`: `UpsertE2BSandboxMetadata`, `GetE2BSandboxMetadata`, `ListE2BSandboxMetadata`, `UpsertE2BSnapshot`, `GetE2BSnapshot`, `ListE2BSnapshots`, `DeleteE2BSnapshot`.

## Steps

1. **Create the package.** Copy the file shape of `pkg/api/daytona/`:
   ```
   pkg/api/e2b/
     routes.go        const PathPrefix = "/e2b"; RegisterRoutes(mux, Deps)
     handlers.go      newHandlers(Deps); thin wire ↔ service translation
     dto.go           E2B-shaped DTOs
     contract_test.go E2B SDK wire-shape contracts
     handlers_test.go
   ```
2. **Wire into the server.** In `pkg/api/server.go` `routes()`, add `e2b.RegisterRoutes(s.mux, e2b.Deps{...})` next to the existing `daytona.RegisterRoutes` and `apiv1.RegisterRoutes` calls. The Deps shape is the same (`Service`, `Logger`, `Auth`).
3. **Service-layer helpers** go in `internal/service/e2b.go`. Keep `internal/service` version-agnostic — no `if facade == "e2b"`.
4. **Store helpers** go in `internal/store/store.go`. Mirror the existing `Daytona*` and `E2B*` shapes. Use additive schema only.
5. **Update** `plans/sdk-compatibility/e2b/facade-plan.md` support tables when you mark a route done.

## Blocker: create-path idempotency

`POST /e2b/sandboxes` is the open design question.

The upstream E2B create body has `templateID`, timeout/lifecycle inputs, metadata, env vars, network options, secure mode, and volume mounts — but **no caller-supplied sandbox name, alias, or request ID**. There is no natural stable key for retry deduplication.

You must pick a deterministic retry story before coding the create handler. Options (in order of preference):

1. **Persisted request fingerprint.** Hash the canonical form of the create body, persist `(fingerprint, sandbox_id)` in a new table, and dedupe within a TTL window. Survives daemon restarts. Required schema change in `internal/store/store.go`.
2. **Explicit `Idempotency-Key` header.** E2B SDK doesn't send one today, but the facade can accept one and propagate it. Sandbox under the assumption that clients without the header get a documented "may double-create on retry" warning.
3. **Best-effort dedupe in memory.** Simplest; loses guarantees across daemon restarts. Not acceptable for production per `pr-review.md` §1 — listed only to be argued against.

Whichever you pick, write it down in the facade-plan.md and the PR description.

## Idempotency for other E2B routes

Each of these needs an explicit retry story (`pr-review.md` §1):

- `POST /e2b/sandboxes/{id}/connect`
- `POST /e2b/sandboxes/{id}/pause`
- `POST /e2b/sandboxes/{id}/timeout`
- `POST /e2b/sandboxes/{id}/snapshots`
- `DELETE /e2b/templates/{id}`

Pattern from the existing facades: lookups return the existing resource on retry; state transitions are no-ops if already in the target state.
