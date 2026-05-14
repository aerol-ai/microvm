---
name: touch-tcp-pool
description: Make changes to the TCP host-port pool or L4 bootstrap safely. Highest-risk area in the repo — PR #16 was a live incident here. Mandates a regression test in store_test.go or layer4_bootstrap_test.go and the matching PR call-out. Use when the user asks to "change the port allocator", "fix TCP routing", "touch host_port", "change EnsureLayer4", or any code path involving TryReserveHostPort / allocateHostPort / l4Ready. Proactively block-suggest before any patch that touches these symbols.
---

# Change the TCP host-port pool or L4 bootstrap

**Highest-risk area in the repo. Read `pr-review.md` §7 in full before editing.**

## What counts as "touching" this area

Any change to:

- `Store.TryReserveHostPort` semantics (`internal/store/store.go`)
- The partial unique index on `exposed_ports.host_port`
- `Service.allocateHostPort` allocator loop (`internal/service/`)
- `Service.EnsureLayer4` / `Service.EnsureLayer4Ready` (`internal/service/service.go`)
- The `l4Ready` `atomic.Bool` latch or the `l4Mu` mutex
- `allocatorRandomAttempts` constant (`internal/service/service.go:37`)
- `pkg/caddy/client.go` L4 route installation

## What you MUST do

1. **Regression test, required, not optional:**
   - Pool / allocator / `TryReserveHostPort` changes → `internal/store/store_test.go`.
   - `EnsureLayer4` / `EnsureLayer4Ready` / latch changes → `internal/service/layer4_bootstrap_test.go`.
   - The existing tests give you the shape — copy and adapt.
2. **PR call-out:** fill in the **"L4 / host-port-pool changes"** section of the PR template with a link to the regression test.
3. **Never collapse `ReserveHostPortResult` back into a `bool`.** The three states (`Reserved` / `Existing` / neither) are what prevents pool walks on PK collisions. Look up the type before editing — the middle state matters.

## Why this area is fragile

- The allocator is randomized-first (`allocatorRandomAttempts = 16` random tries) then falls back to a linear scan. Removing the random phase makes p95 spike under load; removing the fallback fails near pool exhaustion.
- The partial unique index lets multiple sandboxes "use" port 0 (sentinel) while still uniquing real allocations. Don't replace it with a non-partial unique constraint.
- L4 bootstrap is **best-effort at daemon start**. Caddy may not be reachable on a cold restart, so the expose path retries under `l4Mu` when the latch is still false. Failure must leave the latch unset so the next caller retries. Success latches forever.

## Worked anti-patterns

- Walking the host-port pool on a primary-key conflict during re-expose → caused the live incident in PR #16.
- Retrying L4 bootstrap on every request instead of behind the latch → thundering herd on the caddy admin API.
- Failing the daemon outright on a transient bootstrap error → makes the daemon un-restartable after a caddy hiccup.
- Logging-and-forgetting an L4 bootstrap error → the user's first TCP expose gets a confusing "layer4 server not found" from caddy.

## Reference reading

- `pr-review.md` §3 (lazy-bootstrap pattern) — canonical shape mirrored from `EnsureLayer4Ready`.
- `pr-review.md` §7 (this area specifically) — the rules above are summarized from here.
- `internal/service/layer4_bootstrap_test.go` — read the existing test names; they describe the invariants you must preserve.
