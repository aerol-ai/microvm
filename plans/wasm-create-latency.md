# WASM create latency: 5.4s → warm hits in the double-digit-ms class

Status: **Implemented** (2026-07-04). Phases 0–4 landed in one change set. Baseline numbers
are from the 2026-07-01 `cluster-hetero` UC-94 run
(`integration-tests/reports/cluster-hetero-bench.json`).

Owner rules that apply: this plan changes `CreateSandbox` callees
(`/touch-create-sandbox`), the WASM warm-worker pool (`internal/pool/wasm/` —
regression tests mandatory next to the file, same bar as the TCP host-port
pool), and needs boot-path latency call-outs in every PR description per
`pr-review.md` §2. The worker wire protocol (`pkg/wasm/worker/`) changes in
Phase 1 — both ends ship in the same binary (`sandboxd --wasm-worker` is a
re-exec of the daemon), so there is no cross-version compatibility window,
but say so in the PR.

Sibling plan: `plans/firecracker-create-latency.md`. Phase 2 here is the
same disease that plan's Phase 1 cured for Firecracker (per-create hashing
of an immutable artifact) — mirror its verify-once design, do not invent a
new one.

---

## Problem

The `cluster-hetero` benchmark (UC-94, run 2026-07-01) measured WASM creates
at:

| metric | docker | wasm |
|---|---|---|
| api p50 (client round-trip) | 1047ms | 6659ms |
| server p50 (Server-Timing) | 291ms | **5832ms** |
| server mean / p90 / p99 | 745 / 2450 / 2690ms | 5416 / 6645 / **7806ms** |

The docs promise "<70ms sandbox startup" (`docs/src/content/docs/comparison.md`)
and the folklore number is ~60ms. Two observations frame the analysis:

1. **The distribution is uniformly slow** — every one of the 10 samples sits
   between ~5.4s and ~8.6s API-side. There is no fast mode. The pool was
   enabled on every worker (`SB_WASM_POOL_ENABLED=true`, depth 2) and the
   end-of-run `systemctl status` snapshot shows 8 warmed slot processes per
   node (4 module digests × depth 2) — the pool was populated and it made
   **zero** difference. Warm hits are not fast today; that is the smoking gun.
2. **Docker's 291ms server p50 bounds the shared scaffolding** (admission,
   SQLite row, Raft placement + forward hop, caddy). Everything above ~300ms
   is WASM-driver cost.

### Root-cause ledger (all verified in code, file:line at HEAD)

| # | Defect | Where | Per-create cost (python.wasm, t3.medium) | Mechanism |
|---|---|---|---|---|
| A | **Recompile inside `Instantiate` — defeats the warm pool AND double-compiles the cold path** | `pkg/wasm/engine_wazero.go:92-98` → `initRuntime` → `CompileModule` at `engine_wazero.go:66` | **~2.5s on warm hit; ~5s cold (two compiles)** | Pool slots are warmed via `LoadModule` only (`internal/pool/wasm/spawner.go:57`); the worker engine is built with `initRuntime(ctx, 0)` = **0 memory-limit pages**. Every create then calls `Instantiate` with the sandbox's memory cap (default 256MB → 4096 pages, `SB_WASM_DEFAULT_MEMORY_MB`, `internal/config/config.go:1364`). `ensureMemoryLimit` sees `4096 != 0`, tears down the whole wazero runtime and **recompiles the module from bytes** inside the create request. Warm hit = compile once anyway. Cold = compile in `LoadModule`, then compile AGAIN in `Instantiate`. |
| B | **SHA-256 of the full module file on every create** | `pkg/wasmmod/resolver.go:41` (`fileDigest`, `resolver.go:66-78`) | ~30–60ms (≈30MB CPython module) | Reserved-alias (`python`) and file refs re-hash the entire `.wasm` per create to produce the digest the pool is keyed on. Identical bug family to the Firecracker per-create snapshot hash fixed in commit `077789b` — that fix is FC-only (`internal/runtime/firecracker/snapshot_verify_cache.go`); `pkg/wasmmod` got nothing. |
| C | **No compilation cache anywhere** | `pkg/wasm/engine_wazero.go:53` (`NewRuntimeConfig()` without `WithCompilationCache`) | compile cost never amortizes | Each pool slot / sandbox worker is a separate `sandboxd --wasm-worker` process; each pays the full wazero compile of the same bytes. Refill of one depth-2 pool for CPython burns ~2×2.5s of CPU per tick it runs. |
| D | **25ms readiness-poll quantization on cold spawns** | `internal/runtime/wasm/lifecycle.go:296-303` (`sleepBrief`), `internal/pool/wasm/spawner.go:54` | up to +25ms | First `Ping` fires before the worker has bound its socket, then the loop sleeps a flat 25ms — worker readiness rounds up to the next 25ms tick. Same shape the FC plan's Phase 2 trimmed for `WaitSocket`/vsock. |
| E | **`oci://` refs pay 2+ registry round-trips per create even on full cache hit** | `pkg/wasmmod/resolve.go:172` (credentialed manifest resolve: token + HEAD over TLS) | ~30–100ms in-VPC | Deliberate (it's the per-tenant auth check + cache key), but it belongs on the ledger; the bench and standard-alias paths avoid it. |

Arithmetic check against the measured 5.4s server mean: cold create =
B (hash ~50ms) + spawn/poll (~50–100ms) + **two** CPython compiles
(A + `LoadModule`, ~2×2.5s) + instantiate + scaffolding (~300ms) ≈ 5.4s. ✔
The flat distribution (no bimodal split despite 8 warm slots) is exactly what
defect A predicts: warm or cold, every create compiles.

### Why "60ms" was never reachable end-to-end on this cluster

The 60ms budget describes the **driver stage of a warm hit**: acquire slot +
ping + instantiate a pre-compiled module. On `cluster-hetero`, every create
additionally pays the ~300ms shared scaffolding floor (docker's measured
291ms server p50: Raft placement, forward hop, SQLite, caddy). So the honest
post-fix targets are: driver stage ≤ 60–100ms, cluster server p50 ≈ 350–500ms,
single-node (no cluster) end-to-end ≈ 60–120ms. Anyone gating this work on
"60ms server p50 in the cluster bench" will be disappointed by arithmetic,
not by the fixes.

---

## Targets

All WASM server-side p50 via UC-94 on `cluster-hetero` (t3.medium gvisor
workers run wasm; staged `python` module via `AEROL_WASM_MODULE_REF`;
pool enabled, depth 2), client in-VPC per the FC plan's methodology section.
Estimates until Phase 0 measures stages — same STOP discipline as the FC plan.

| Milestone | Committed | Stretch | What changes |
|---|---|---|---|
| Baseline (measured 2026-07-01) | — | — | server p50 **5832ms**, no warm/cold distinction visible |
| Phase 0: instrumentation | no latency change | — | per-stage Server-Timing (`wasm_*`), warm-hit marker, bench stage block |
| Phase 1: kill the Instantiate recompile | warm-hit server p50 **≤ 1000ms**; overall p50 ≤ 3200ms | warm ≤ 600ms | removes A: warm hits stop compiling; cold path compiles once, not twice |
| Phase 2: verify-once module digest cache | warm-hit **≤ 900ms** | ≤ 550ms | removes B after first resolve |
| Phase 3: shared wazero compilation cache | cold p50 **≤ 1500ms**; overall p50 ≤ 1000ms | cold ≤ 800ms | removes C: compiles amortize across workers + restarts; refill gets cheap enough to keep up, so most creates are warm |
| Phase 4 (optional): poll backoff + miss-kicked refill | warm-hit driver stage ≤ 100ms | ≤ 60ms | trims D; pool refills on demand instead of 5s ticks |

Regression guard for every phase: docker and gvisor server p50 within 10% of
baseline in the same run; UC-26/UC-44/UC-85 (wasm correctness) keep passing;
`make test` coverage for every touched package stays ≥ ~85%
(`/maintain-coverage` before each PR).

---

## Phase 0 — Instrumentation (1 small PR)

Reuse `pkg/createtiming` (already extracted by the FC plan's Phase 0 — the
recorder is runtime-neutral and the v1 handler + bench harness already
surface arbitrary `<name>;dur=` stages into `latency[].stages`).

### Work

1. Record stages inside `Driver.Create` (`internal/runtime/wasm/create.go`):
   `wasm_resolve` (module resolve incl. hash), `wasm_warm;desc=hit|miss`,
   `wasm_spawn` (supervisor Ensure → first successful ping, cold only),
   `wasm_load` (LoadModule RPC, cold only), `wasm_instantiate`, and a
   `wasm_driver` total. Record on failure too (handler already sets
   Server-Timing on error responses).
2. Nothing to change in `pkg/api/v1/handlers.go` or the bench harness if the
   FC Phase 0 generic stage plumbing landed as designed — verify, don't assume.
3. **Validation experiment W1** (operator-run, no code): rerun UC-94 twice on
   the same cluster, `SB_WASM_POOL_ENABLED=true` vs `false`. Expected today:
   statistically indistinguishable (defect A predicts the pool is a no-op for
   latency). This is the falsifiable pre-registration for Phase 1: if the
   pool-enabled run is already meaningfully faster, the recompile attribution
   is wrong — STOP and re-read the Phase 0 stage data.

### Files

| File | Change |
|---|---|
| `internal/runtime/wasm/create.go` | record the six stages |
| `internal/runtime/wasm/create_timing_test.go` (new) | stage presence/omission table tests |

### Tests

Table-driven, in the driver's existing fake-seam style: a warm-hit Create
records `wasm_warm;desc=hit` and zero `wasm_spawn`/`wasm_load`; a cold Create
records all stages non-negative; a failed Create still records `wasm_driver`.

### Exit criteria

A cluster-hetero run where wasm per-stage p50s sum to within 15% of the
`create` total, and W1's result is pasted into this file's status table.

---

## Phase 1 — Kill the Instantiate recompile (1 PR, the big one)

### Design

The memory limit is wazero **runtime**-config, so the fix is to compile under
the right limit in the first place, and to treat "limit differs" as a pool
miss instead of a silent multi-second recompile.

1. **Protocol:** `loadModulePayload` (`pkg/wasm/worker/payload.go`) gains
   `MemoryMB int`. `MsgLoadModule` handling (`pkg/wasm/worker/server.go:156`)
   applies it before compiling.
2. **Engine:** extend the `Engine` interface (`pkg/wasm/engine.go`) —
   `LoadModule(ctx, path)` becomes `LoadModule(ctx, path, opts LoadOptions)`
   with `LoadOptions{MemoryMB int}` (a struct so Phase 3 can add the cache
   handle without another signature ripple). `engine_wazero.go` builds the
   runtime with `MemoryLimitPages(opts.MemoryMB)` **before** `CompileModule`;
   `ensureMemoryLimit` keeps existing semantics (a genuinely different limit
   at Instantiate still rebuilds — correctness backstop) but should now never
   fire on the standard path. `engine_wasmtime.go` (build-tagged) gets the
   analogous change.
3. **Pool spawner:** `SupervisorSpawner.Warm` (`internal/pool/wasm/spawner.go`)
   gains the memory parameter; `pkg/daemon/wasm_wiring.go` passes
   `cfg.WasmDefaultMemoryMB`. `wasmpool.Slot` (`internal/pool/wasm/pool.go`)
   carries `MemoryMB` it was warmed with.
4. **Acquire keying:** `tryAcquireWarm` (`internal/runtime/wasm/warmacquire.go`)
   computes the request's effective memory (req.MemoryMB or default,
   the same expression `Create` uses — extract it, don't duplicate) and only
   accepts a slot whose `MemoryMB` matches; mismatch = miss → cold path. A
   non-default-memory create is thus exactly as fast as today, never slower,
   and the common case stops recompiling. (Keying `ready` by
   `(digest, memoryMB)` is the fuller design; not needed while all warmed
   slots use one default — note it as the follow-up if non-default memory
   becomes common.)
5. **Cold path:** `Driver.Create` (`internal/runtime/wasm/create.go:110`)
   passes the effective memory in its `LoadModule` call — this alone halves
   cold-create compile cost (one compile, not two).

### Files

| File | Change |
|---|---|
| `pkg/wasm/engine.go` | `LoadOptions`, signature change |
| `pkg/wasm/engine_wazero.go` | compile under the requested limit |
| `pkg/wasm/engine_wasmtime.go` | same, behind `//go:build wasmtime` |
| `pkg/wasm/worker/payload.go`, `server.go`, `client.go` | `MemoryMB` through the wire |
| `internal/pool/wasm/spawner.go`, `pool.go` | memory-aware Warm + Slot |
| `internal/runtime/wasm/warmacquire.go`, `create.go` | match-or-miss acquire; effective-memory helper |
| `pkg/daemon/wasm_wiring.go` | pass `cfg.WasmDefaultMemoryMB` to the spawner |

### Tests (fragile-area bar: regression tests next to every file touched)

Needs a countable compile seam in `engine_wazero.go` (package-level
`var compileModule = ...` indirection, mirroring the FC hash seam) so tests
count compilations instead of timing them.

| Test | Asserts |
|---|---|
| `pkg/wasm/engine_wazero_test.go` `TestLoadThenInstantiate_CompilesOnce` | LoadModule(default MB) + Instantiate(default MB) → exactly one compile |
| `TestInstantiate_DifferentLimitStillRebuilds` | mismatched limit → recompile (backstop preserved) |
| `internal/pool/wasm/spawner_test.go` `TestWarm_PassesMemoryMB` | wire payload carries the configured default |
| `internal/runtime/wasm/warmacquire_test.go` `TestAcquire_MemoryMismatchMisses` | slot warmed at 256, create asks 512 → miss, cold path taken, create still succeeds |
| `internal/runtime/wasm/create_test.go` `TestCreate_WarmHitNoLoadModule_NoRecompile` | warm hit → zero LoadModule RPCs and one compile total across warm+create (worker fake counts) |
| `TestCreate_ColdCompilesOnce` | cold create → exactly one compile |

### Validation benchmark

Rerun UC-94 + W1. **Merge gate: warm-hit samples (identified by
`wasm_warm;desc=hit`) server p50 ≤ 1000ms; `wasm_instantiate` p50 on warm
hits ≤ 300ms; overall wasm p50 ≤ 3200ms; docker/gvisor within 10%.** Record
the JSON under `integration-tests/reports/` and update this file.

---

## Phase 2 — Verify-once module digest cache (1 small PR)

Mirror of `internal/runtime/firecracker/snapshot_verify_cache.go` for
`pkg/wasmmod`. Staged modules are immutable in practice; re-hashing per
create is pure waste.

### Design

- New `pkg/wasmmod/digest_cache.go`: map keyed by file identity
  (`path` + `dev`, `inode`, `size`, `mtime` from `os.Stat` at hash time) →
  content digest. Stat drift → miss → re-hash. Single-flight per path
  (canonical `sync.Mutex` + done-channel latch, per
  `Service.EnsureLayer4Ready`); a failed hash is not cached.
- `Resolver.Resolve` (`pkg/wasmmod/resolver.go:41`) consults it. The
  `oci://` path is untouched (already content-addressed: cache hits do a
  stat, not a hash — `resolve.go:212-227`). The catalogue path already
  returns a pinned digest without hashing.
- Invalidation: stat mismatch; explicit drop when a module is
  deleted/replaced (wire the same hook that calls `Pool.DropModule`);
  in-memory only, so every daemon boot re-verifies once (deliberate, same
  trade as FC — state it in the PR).
- Config: `SB_WASM_MODULE_DIGEST_MODE` = `once` (default) | `always`
  (escape hatch, current behavior). Same naming shape as
  `SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE`.

### Files

| File | Change |
|---|---|
| `pkg/wasmmod/digest_cache.go` (new) + `digest_cache_test.go` (new) | cache + single-flight |
| `pkg/wasmmod/resolver.go` | consult cache in `Resolve` |
| `internal/config/config.go` + `config_test.go` | `SB_WASM_MODULE_DIGEST_MODE` |
| `pkg/daemon/wasm_wiring.go` | wire the mode |

### Tests

Same table as the FC verify-cache suite, transposed:
`TestDigestCache_SecondResolveSkipsHash` (hash seam called once across two
Resolves), `_SingleFlight` (N concurrent → one hash), `_FailureNotCached`,
`_InvalidatesOnFileChange` (rewrite file → re-hash), `_ModeAlways`,
`_DropOnModuleDelete`. Plus: `seedStandardModules`
(`pkg/daemon/wasm_wiring.go:119`) still seeds correct digests (it resolves
through the same path at boot — it should *prime* the cache, which is a
feature: the first tenant create skips the hash too).

### Validation benchmark

UC-94: `wasm_resolve` p50 ≤ 5ms on samples 2–10; warm-hit server p50 ≤ 900ms.

---

## Phase 3 — Shared wazero compilation cache (1 PR)

### Design

- Build the wazero runtime with
  `wazero.NewRuntimeConfig().WithCompilationCache(...)` using
  `wazero.NewCompilationCacheWithDir(dir)`; dir from new config
  `SB_WASM_COMPILE_CACHE_DIR` (default `<SB_WASM_CACHE_DIR>/wazero-compile`,
  empty string = disabled). Workers are separate processes: pass the dir via
  env in `DefaultSpawner` (`pkg/wasm/worker/supervisor.go:18`) — the same
  pattern `AEROL_WASM_ENGINE` already uses (`wasm_wiring.go:71-73`).
- **Verify before trusting:** wazero's file cache is documented for
  cross-process sharing, but prove it in a test (two engines in two
  subprocesses, second compile measurably skips codegen / hits the cache
  dir). If it can't be proven, scope the cache to per-process and say so.
- Cache eviction: entries are keyed by module + wazero version; wire module
  GC (`Pool.DropModule` / module delete) to best-effort remove the entry, and
  document that the dir is bounded by (modules × wazero versions) — small.
- `initRuntime`'s rebuild (the Phase-1 backstop) also uses the cache, making
  the residual mismatch path cheap too.

### Files

| File | Change |
|---|---|
| `pkg/wasm/engine_wazero.go` | `WithCompilationCache` from `LoadOptions`/env |
| `pkg/wasm/worker/supervisor.go` | propagate cache-dir env to workers |
| `internal/config/config.go` + `config_test.go` | `SB_WASM_COMPILE_CACHE_DIR` |
| `pkg/daemon/wasm_wiring.go` | wire dir, create it at boot |
| `pkg/wasm/engine_wazero_test.go` | cache-hit test incl. cross-process proof |

### Validation benchmark

UC-94: cold-create (`wasm_warm;desc=miss`) server p50 ≤ 1500ms; overall
p50 ≤ 1000ms; **refill keep-up check** — after sample 3, no cold fallbacks at
the bench's sequential rate (the FC plan's Phase 3 gate shape). Also rerun
the density benchmark (UC-95 currently runs docker only — extend the sweep or
note it): 8 pre-warmed workers per node must not regress admission headroom.

---

## Phase 4 — Poll backoff + miss-kicked refill (optional, 1 tiny PR)

- `sleepBrief` (`internal/runtime/wasm/lifecycle.go:296`): first retry 2ms,
  double to a 25ms cap — same shape as FC Phase 2's `WaitSocket` trim.
  Identical change in `SupervisorSpawner.Warm`'s loop
  (`internal/pool/wasm/spawner.go:41-56`).
- Refill responsiveness: `Pool.Acquire` miss sends a non-blocking kick on a
  buffered chan that `Run` (`internal/pool/wasm/refill.go:31`) selects on
  alongside the 5s ticker, so a drained pool starts re-warming immediately
  instead of up to `SB_WASM_POOL_REFILL_INTERVAL` later. Budget logic
  (`SpawnBudget`) is unchanged — the kick only advances the tick.

Tests: backoff-sequence assertions (attempt-counter seam, existing style);
`TestRefill_KickOnMiss` (miss → refill observed without ticker firing);
`TestRefill_KickCoalesces` (N misses → no spawn-budget overshoot — the
`spawning` counter already guards this, assert it).

---

## Consolidated file map

**New files:** `internal/runtime/wasm/create_timing_test.go`,
`pkg/wasmmod/digest_cache.go`, `pkg/wasmmod/digest_cache_test.go`.

**Modified:** `internal/runtime/wasm/{create.go, warmacquire.go, lifecycle.go}`,
`internal/pool/wasm/{pool.go, spawner.go, refill.go}` + their `_test.go`s,
`pkg/wasm/{engine.go, engine_wazero.go, engine_wasmtime.go}` + tests,
`pkg/wasm/worker/{payload.go, server.go, client.go, supervisor.go}` + tests,
`pkg/wasmmod/resolver.go`, `internal/config/config.go` + test,
`pkg/daemon/wasm_wiring.go`.

**Not touched:** `internal/cluster/` (placement is driver-agnostic — state
the single-node no-op confirmation in each PR per hard rule 6),
`internal/store/` (no schema change), `pkg/api/` (Phase 0 rides the existing
Server-Timing plumbing).

---

## Benchmark methodology

Inherit the FC plan's methodology section wholesale (in-VPC client, same
tfvars, warm page cache, artifacts committed per phase gate), plus
WASM-specific rules:

1. **Module ref hygiene.** The bench must use the staged standard module
   (`AEROL_WASM_MODULE_REF=python` or a clean `oci://` ref). The 2026-07-01
   failure log shows earlier suite creates using a stale
   `snapshots/python:latest--ttl-1h` image ref; `staleSnapshotModuleRef`
   (`integration-tests/suite/wasm_ref_test.go`) already guards UC-94 — keep it.
2. **n ≥ 20 for Phase 1+** (warm/cold mix needs the larger n; FC Phase 3
   precedent) and report warm-hit and cold subsets separately using the
   `wasm_warm` marker — the overall p50 is a function of pool keep-up, not
   of the fix under test.
3. **Pool state is part of the experiment.** Record `expvar` pool counters
   (hits/misses/refills/spawn-fails) before and after each bench run in the
   artifact; a phase gate that passes with `hits=0` is measuring the wrong
   thing.

### New integration UCs (`integration-tests/suite/`; UC-97 and UC-98x are
reserved by the docker-readiness and FC plans)

| UC | Title | Gate |
|---|---|---|
| UC-99 | Warm-pool hit: wasm create server p50 ≤ 1000ms (Phase 1) / ≤ 900ms (Phase 2) with `wasm_warm;desc=hit` | `CapCluster, CapWasm, CapBenchmark` |
| UC-99b | Pool drained by burst → creates fall back cold and all succeed (correctness, not speed) | parallel creates > depth |
| UC-99c | Non-default `memory_mb` create bypasses the warm pool and succeeds (Phase 1 keying) | assert `desc=miss` + success |
| UC-99d | Compile cache survives worker restart: kill a pool worker, next warm spawn's `wasm_load` p50 ≤ 500ms (Phase 3) | requires cache-dir proof |

---

## Risks

| Risk | Mitigation |
|---|---|
| Compile-cost attribution wrong (something else burns the 5s) | Phase 0 W1 pre-registration: pool on/off must be indistinguishable today; stage data before Phase 1 merges. STOP rule if `wasm_instantiate` cold p50 < 1.5s. |
| Engine interface change ripples (wasmtime build tag rots silently) | CI doesn't build `-tags wasmtime` — add a build-only step or compile it locally in the PR; call out in description |
| Memory-mismatch keying quietly sends real traffic cold | UC-99c + expvar miss counter in the bench artifact; follow-up: key `ready` by `(digest, memoryMB)` if miss rate is material |
| wazero file cache misbehaves cross-process | Phase 3's explicit proof test; fall back to per-process cache (still fixes refill/restart cost within a worker's lifetime — smaller win, still a win) |
| Digest cache serves a stale digest after in-place module replace | stat-identity key (dev/inode/size/mtime) + explicit drop on module delete/replace; `once`→`always` escape hatch |
| Pre-warmed 256MB-limit slots inflate idle RSS interpretation | limit ≠ allocation (wazero grows linear memory on demand); verify RSS-per-parked-worker in the Phase 1 bench notes; capacity admission already samples RSS |
| Wire-protocol change during rolling upgrade | worker is a re-exec of the same binary — no mixed-version window; assert in PR description |

## Out of scope (deliberately)

- The ~300ms shared scaffolding floor (placement, forward, caddy, SQLite) —
  same exclusion as the FC plan; a cross-runtime follow-up owns it or nobody.
- Registry round-trips on `oci://` refs (ledger item E) — it is the tenant
  auth check; any TTL-based softening is a security decision, not a latency
  patch.
- Switching default engine to wasmtime, streaming/lazy compilation, module
  size reduction (smaller CPython builds), checkpoint/restore-path latency.
- SDK/client RTT.
