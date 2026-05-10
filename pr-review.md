# PR Review Checklist

Every PR touching `internal/service`, `internal/store`, `pkg/caddy`, `pkg/api`, or the SDKs must be reviewed against the rules below. The PR description must explicitly call out each rule it touches — silence is not acceptable on these axes.

The fill-in template lives at [`.github/pull_request_template.md`](./.github/pull_request_template.md) and is auto-populated by GitHub when a PR is opened. This file is the rationale and the reviewer's reference; the template is what authors fill in.

## 1. Idempotency

All sandbox APIs MUST be idempotent.

- Retrying the same request with the same inputs MUST yield the same result.
- A retry MUST NOT cause resource leaks, double allocations, or "already exists" errors.
- Worked example: `expose_port` for an already-exposed `(sandbox, port)` pair must return the existing public URL, not allocate a new host port. The TCP path specifically must NOT walk the host-port pool on a PK conflict.
- Cross-protocol re-expose on the same port should fail fast with a clear "unexpose first" error rather than silently overwriting and leaking the prior caddy route.

**Reviewer asks:** what happens if this exact request is retried 5 times? 50 times? Concurrently from two callers?

## 2. Sandbox boot / `CreateSandbox` latency

Sandbox creation latency is a load-bearing UX metric. Treat the boot path as protected.

- No new work — even lazy or amortized — gets added to `CreateSandbox` or anything it calls without an explicit call-out in the PR description.
- The call-out must state: what was added, expected added latency, conditions under which it fires, whether it's bounded.
- "It's only on the first call" is still an impact and must be called out.

**Reviewer asks:** does this PR add ANY work — DB query, HTTP round-trip, file I/O, lock acquisition — to the sandbox boot path? If yes, is it documented?

## 3. Bootstrap belongs at daemon start, not on hot APIs

When daemon-start bootstrap is best-effort (e.g., depends on Caddy being reachable on a cold restart), the recovery pattern is:

- A lazy single-flight retry that fires only on the API path that needs it (e.g., the first L4 expose).
- Behind an `atomic.Bool` fast-path latch, so the steady-state hot path is a single atomic load.
- A `sync.Mutex` around the slow path so a thundering herd of concurrent first-callers issues exactly one bootstrap, not N.
- Failure leaves the latch unset so the next caller retries; success latches forever.

The L4 bootstrap (`Service.EnsureLayer4Ready`) is the canonical shape. Mirror it for any future best-effort daemon-start work.

**Anti-patterns:** retrying bootstrap on every request; failing the daemon outright on a transient bootstrap error; logging-and-forgetting so the first user request gets a confusing "X not found" from the underlying system.

## 4. Failure-path state consistency

Any expose / unexpose / reconcile path that touches BOTH caddy and the store can leave the system inconsistent on partial failure.

- Decide and document the rollback rule: if caddy succeeds and store fails, what cleans up? If store succeeds and caddy fails, who owns the rollback?
- Do not delete a row that another caller (race) just installed. Track "did I create this?" with an explicit flag (see `allocateHostPort`'s `reused` return) before issuing rollback deletes.
- The reconcile loop is the safety net, not the primary cleanup path. Don't lean on it to cover routine error handling.

**Reviewer asks:** if step 2 of 3 fails, what state is the system in? Is the next request to the same sandbox going to succeed, fail confusingly, or leak resources?

## 5. Mount inputs run on the host

Mount fields (`source`, `options.opts` for NFS, `options.extra_args` for S3, mount-tool flags generally) are passed verbatim into commands that execute on the host as the daemon user — outside the microVM isolation boundary. PAT holders are assumed to be host operators; the threat model treats their input as already-trusted.

If you change who holds a PAT (sub-accounts, hosted offering, external CI), this assumption inverts and these fields become a host attack surface. Before that move:

- Allowlist `options.opts` / `extra_args` keys instead of pass-through.
- Isolate mount helpers (dedicated low-priv user, network namespace scoped to the declared endpoint, seccomp/AppArmor, or a helper VM).
- Re-validate `source` schemes and reject control characters.

**Reviewer asks:** does this PR widen what a PAT holder can pass into a host-side mount command? If yes, is it still safe under the "PAT == operator" assumption, and is the assumption still accurate?

## 6. API versioning (v1 soft freeze)

The HTTP API is split into version subpackages: every `/v1/...` route is owned by `pkg/api/v1`, and SDK call sites build URLs through a `versioned()` helper / `apiVersion` option (see each SDK's `internal/api/v1/` module). The split exists so v1 and v2 can coexist on the same daemon and so SDK consumers can pin a wire version independently of the SDK package version.

To preserve that property, v1 is **soft-frozen**:

- **No behavioral changes** to v1 wire bodies, status codes, header semantics, or path shapes once shipped. Adding a new field to a v1 response, changing an error status, or renaming a path counts as a behavioral change. Land those in a new version package (`pkg/api/v2/...`) instead.
- **Bug and security fixes that preserve wire compatibility are allowed** — clarifying an error message, fixing a 500 that should have been a 4xx for invalid input the server already rejected, plugging a panic.
- **No version-leakage into `internal/`.** The service layer (`internal/service`) stays version-agnostic; v1 handlers translate v1 DTOs ↔ `models.*`. If you find yourself wanting `if version == "v1"` in `internal/`, stop and put the branch in the handler instead.
- SDK changes follow the same rule per-SDK: do not alter what an `apiVersion: "v1"` client sends or how it deserializes a v1 response. Add capabilities by introducing a `v2` transport.

**Reviewer asks:** does this PR change anything a `/v1` client (server-side or SDK-side) can observe? If yes, does it belong in v2 instead?

## 7. TCP host-port pool & L4 bootstrap

These two areas are particularly fragile and have produced live incidents (PR #16):

- Any change to `TryReserveHostPort` semantics, the partial unique index on `host_port`, or the allocator loop in `allocateHostPort` requires a regression test in `internal/store/store_test.go` AND a call-out in the PR description.
- Any change to `EnsureLayer4` / `EnsureLayer4Ready` / the `l4Ready` latch requires a regression test in `internal/service/layer4_bootstrap_test.go` AND a call-out.
- Do not collapse the three-state `ReserveHostPortResult` (`Reserved` / `Existing` / neither) back into a `bool`. The middle state is what prevents pool walks on PK collisions.

## PR description template

Lives at [`.github/pull_request_template.md`](./.github/pull_request_template.md). GitHub auto-fills new PRs with it. Authors must answer every section; "N/A — <one-line reason>" is valid, empty is not.
