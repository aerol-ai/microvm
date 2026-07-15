# WASM cold-load: resident compiled-module host (compile-once, instantiate-many)

Status: **Proposed / design** (2026-07-15). Phase 0 (measurement) is implemented;
Phases 1–4 are unbuilt and gated on the Phase 0 numbers + an eng-review, because
this changes the WASM isolation model.

Owner rules that apply: this plan changes `CreateSandbox` callees
(`/touch-create-sandbox`) and the WASM warm-worker pool (`internal/pool/wasm/` —
regression tests mandatory next to the file, same bar as the TCP host-port
pool), and it needs a boot-path latency call-out in every PR per `pr-review.md`
§2. The worker wire protocol (`pkg/wasm/worker/`) changes in Phase 2 — both ends
ship in the same binary (`sandboxd --wasm-worker` re-execs the daemon), so there
is no cross-version window, but say so in the PR. **It also changes the process
isolation model (co-tenancy), so it MUST ship behind a default-off flag and go
through `/plan-eng-review` before the default flips** — same discipline the
docker warm pool (`SB_DOCKER_POOL_ENABLED`) and pause-netns pool used.

Sibling plans: `plans/wasm-create-latency.md` (the warm-pool work that already
put warm creates in the 23ms class), `plans/firecracker-create-latency.md` (the
"measure the stage before you build the lever" lesson this plan opens with).

---

## Problem

The 2026-07-15 `cluster-3-mixed-wasm` bench (release v0.7.8, warm depth 2, 10
samples, 0 failures) measured:

| metric | value |
|---|---|
| server p50 (warm hit) | **23ms** |
| server p90 / p99 | 2633ms / 2862ms |
| `wasm_load` p50 (cold miss) | **2814ms** (2 of 10 samples) |
| `wasm_instantiate` p50 | 10ms |
| `wasm_warm` p50 | 0ms (pool hit) |

The warm path is already best-in-class (23ms — beats docker warm 43ms and
firecracker 34ms). The entire tail is the handful of creates that MISS the warm
pool and fall through to the cold `wasm_load` path. That path
(`internal/runtime/wasm/create.go:124-145` → worker `MsgLoadModule`
`pkg/wasm/worker/server.go` → `pkg/wasm/engine_wazero.go:116`) rebuilds
everything from scratch in a **fresh per-sandbox worker process**:

1. `NewEngineFor` — build a wazero runtime + instantiate WASI.
2. `initRuntime` (again, at the target memory limit) — a second runtime build.
3. `os.ReadFile` — read the module bytes (~25MB for CPython).
4. `CompileModule` — turn bytes into an executable image (compile-cache
   assisted: a full cold compile is ~10s, a cache hit ~seconds of deserialize).

None of this is shared: every cold create pays it in full.

## Phase 0 — measure which sub-step owns the 2.8s (IMPLEMENTED 2026-07-15)

Before building any lever, split the single `wasm_load` timer. The firecracker
episode proved that guessing the dominant sub-cost (there: the hash / the warm
pool) wastes effort — the real cost (a vsock over-read) only showed up once the
stage was instrumented per-step.

Shipped: `pkg/wasm/load_timings.go` (`LoadTimings` + optional
`LoadTimingReporter`), sub-stage timing inside `wazeroEngine.LoadModule`, the
worker measuring `NewEngineFor` and returning `LoadTimings` over the
`MsgLoadModule` reply, and `create.go` emitting `wasm_load_newengine`,
`wasm_load_runtime`, `wasm_load_read`, `wasm_load_compile` Server-Timing
entries. Regression test:
`pkg/wasm/worker/load_timings_test.go`.

**Gate:** the next `cluster-3-mixed-wasm` bench (or a local Docker cold create)
must show the breakdown before Phase 1 starts. Interpretation → lever:

| dominant sub-stage | correct lever |
|---|---|
| `wasm_load_compile` | resident **compiled module** (this plan) |
| `wasm_load_runtime` + `_newengine` | resident **runtime** (a lighter variant of this plan — reuse the runtime, still re-`InstantiateModule`) |
| `wasm_load_read` | mmap / keep module bytes resident (small, separate change) |

**Gate result — GREEN (2026-07-15, `cluster-3-mixed-wasm`, v0.7.9, 10 samples,
0 failures).** The breakdown of the cold miss (`wasm_load` p50 2843ms, n=2):

| sub-stage | p50 | share |
|---|---|---|
| `wasm_load_compile` | **2768ms** | **~97%** |
| `wasm_load_read` (25MB ReadFile) | 56ms | ~2% |
| `wasm_load_newengine` | 1ms | ~0% |
| `wasm_load_runtime` | 1ms | ~0% |

`CompileModule` owns the cold load almost entirely — and note this is *with* the
on-disk compile cache populated, so 2.77s is the cache-hit **deserialize** cost
of a 25MB CPython image per fresh process, not a from-scratch 10s compile. A
resident in-process `CompiledModule` skips even the deserialize, so a cold
create collapses to `wasm_instantiate` (**9ms** in the same run). This plan (the
resident compiled module) is confirmed the right lever; Phase 1 may start.

## Core insight

wazero is **compile-once, instantiate-many**: `CompileModule` returns a
`CompiledModule` that `InstantiateModule` can turn into many independent
instances, each with its own linear memory. The engine already instantiates
from a resident `e.compiled` (`engine_wazero.go:167`), and `wasm_instantiate` is
only ~10ms. The 2.8s exists purely because the cold path **rebuilds** the
compiled module per sandbox instead of instantiating a resident one.

The compiled module cannot be shared cheaply **across processes** — the on-disk
compile cache is the cross-process mechanism, and its deserialize IS the 2.8s.
So the fast path requires reusing the compiled module **in-process**: a
long-lived worker process holds the resident runtime + compiled module and
services many instantiate requests. Ceiling: **`wasm_load` 2814ms → ~10ms** for
any create that lands on a host already holding the module.

## The hard constraint: memory limit is per-runtime, so bucket by (digest, memoryMB)

wazero sets the memory limit at the **runtime** level
(`WithMemoryLimitPages`, `engine_wazero.go:57-61`), and a `CompiledModule` is
bound to the runtime it was compiled in. Therefore all co-tenant instances
sharing one compiled module share one memory limit. A resident host is keyed by
**(module digest, memoryMB)**, not digest alone. In practice standard modules
all use `SB_WASM_DEFAULT_MEMORY_MB` (256), so they bucket together; a create
with a non-default `memory_mb` that has no matching host falls back to the cold
path (correct, and rare). This is also why `ensureMemoryLimit`
(`engine_wazero.go:108`) rebuilds the runtime today — the resident-host design
makes that rebuild impossible for co-tenants, which is fine because the bucket
key guarantees a matching limit.

## Isolation tradeoff (why this is default-off + eng-review-gated)

Today: one sandbox per worker process → OS-level crash/OOM isolation. Co-tenancy
shrinks the blast radius from "one sandbox" to "the co-tenants on one host
process." What still isolates co-tenants:

- **Per-instance linear memory** — wazero gives each `InstantiateModule` its own
  memory; no shared memory unless explicitly configured (we don't).
- **Per-instance memory cap** (`MemoryLimitPages`) and **fuel metering** bound a
  single instance's resource use.
- **Bounded instances per host** (`SB_WASM_RESIDENT_HOST_MAX_INSTANCES`) caps the
  blast radius and lets the pool spread load across host processes.

Residual risk to enumerate in the eng-review: a panic in a host function (or a
wazero bug) runs on a shared process and takes down all co-tenants; a runaway
guest that exhausts host RAM (not guest linear memory) affects co-tenants. These
are why the default stays process-per-sandbox and this mode is strictly opt-in.

## Design

A **resident module host** is a long-lived worker process that:

1. On first use for a (digest, memoryMB) bucket, loads + compiles the module
   once (pays `wasm_load` once).
2. Holds the resident runtime + `CompiledModule`.
3. Services many `Instantiate` requests, each creating an isolated instance
   keyed by `sandboxID`; a create that routes here costs ~`wasm_instantiate`.

### Engine (Phase 1) — IMPLEMENTED 2026-07-15

`pkg/wasm/engine_multi.go`: `MultiInstanceEngine` wraps `{runtime, compiled,
map[sandboxID]api.Module}` — compile-once (`LoadModule`), instantiate-many
(`Instantiate(sandboxID, caps)` with a per-instance `WithName(sandboxID)` so
co-tenants don't collide on one runtime), plus `StopInstance`, `InvokeExport`,
`HasInstance`, `InstanceCount`, `Close`, and `LastLoadTimings`
(`LoadTimingReporter`). MemoryMB is fixed at construction (the bucketing
constraint above). The base `Engine` interface is untouched — `wasmtime` and the
mocks are unaffected; the runtime builder + module/fs config helpers were
extracted to free functions (`newBaseRuntime`, `moduleConfigFor`, `fsConfigFor`)
so both engines share identical config (notably the compile cache), and the
single-instance `wazeroEngine` delegates to them unchanged.

Tests (`pkg/wasm/engine_multi_test.go`, offline): compile happens once across N
instantiates (resident `compiled` pointer unchanged); two instances of the same
module cannot read each other's linear memory (write to A, B stays zero);
StopInstance on one leaves the co-tenant running and uncorrupted; duplicate
sandboxID rejected; Instantiate-before-Load and empty-ID fail cleanly;
`LoadTimingReporter` satisfied. Full `pkg/wasm` + driver + pool suites still
green (the extraction did not disturb the single-instance path).

**Deferred to Phase 2 (worker wiring), NOT in the Phase 1 engine:** per-instance
networking (the worker's `NetMediator` is already sandboxID-keyed), IO-capturing
`Run`, snapshot/restore, and wasip1 listeners (`expose_port`/HTTP — resident-host
mode initially serves non-listen sandboxes; HTTP falls back to the cold path).

### Worker protocol (Phase 2) — IMPLEMENTED 2026-07-15

`pkg/wasm/worker/resident_server.go`: `ResidentServer` backed by a
`MultiInstanceEngine`, spawned via `--wasm-resident-host <socket>`
(`RunCLIResident` → `cmd/sandboxd/main.go`). It reuses the existing wire
protocol + `Client` unchanged — only the server interprets the messages
multi-instance:

- `MsgLoadModule` → lazily builds the engine at the payload's `memoryMB` on
  first call, compiles once, returns the existing `LoadTimings`; idempotent for
  the same path; **refuses a second distinct module** (a bucket is one module).
- `MsgInstantiate` / `MsgExec` / `MsgInvoke` / `MsgStopInstance` → per-`sandboxID`
  on the resident engine (`MultiInstanceEngine.{Instantiate,Run,InvokeExport,
  StopInstance}`).
- Listener (`caps.ListenEnabled()`), checkpoint/restore, network/netstats →
  **rejected** with a clear error, so a misrouted request fails loudly.

Tests (`pkg/wasm/worker/resident_server_test.go`, offline): load-once →
instantiate+exec two sandboxes on the resident module; re-load same path is a
no-op; a second distinct module is refused; per-sandbox StopInstance; a
listener Instantiate is rejected.

**Scope limit (unchanged):** resident-host mode serves **non-listen** sandboxes
only; `expose_port`/HTTP guests fall back to the cold per-process path.

**Remaining Phase 2 (eng-review-gated): per-instance egress isolation.** The
engine's `wazeroNetHost` (`wazero_network.go`) holds ONE hook + a GLOBAL conn
table, read by all three WASI host modules at call time. Co-tenancy needs it
keyed by `mod.Name()` (= sandboxID, since instances are named) plus conn
ownership so guest B can't touch guest A's socket. Until that lands, resident
instances get base WASI + FS only (no mediated egress), so networking modules
are not yet served here. This is the security-sensitive change that must go
through review.

### Config (Phase 3) — flag IMPLEMENTED 2026-07-15

- `SB_WASM_RESIDENT_HOST_ENABLED` (bool, **default false**) → `cfg.WasmResidentHostEnabled`
  (`internal/config/config.go`). Gates the whole path; false = today's behavior
  exactly. **DONE.**
- `SB_WASM_RESIDENT_HOST_MAX_INSTANCES` (int, per-host cap) — TODO with the
  routing below.
- Interplay with `SB_WASM_POOL_ENABLED` + `setup/config-defaults.md` — TODO.

### Pool + driver routing (Phase 3b) — IMPLEMENTED 2026-07-15 (gated, offline-tested)

Gated by `cfg.WasmResidentHostEnabled` (default false) so flag-off is a
byte-for-byte no-op — the existing per-sandbox `Driver.Create` path is left
completely untouched (verified: full `internal/runtime/wasm` suite still green).
Shipped (`internal/runtime/wasm/resident.go` + edits to `driver.go`,
`create.go`, `lifecycle.go`, `config.go`, `pkg/daemon/wasm_wiring.go`,
`pkg/wasm/worker/supervisor.go`):

1. Resident-host state on the driver + `SetResidentHostSupervisor` (a second
   supervisor using `worker.DefaultResidentSpawner` → `--wasm-resident-host`),
   `ensureResidentHost` keyed by bucket `residentBucketID(digest, memoryMB)`
   with per-bucket single-flight (`residentBucket.mu`) on host spawn + one
   host-level `LoadModule`.
2. `create.go`: an early branch — when `residentHostEnabled()`, the create is
   not public-expose (`createWantsPublicExpose`), and the digest is known —
   returns `createOnResidentHost` (Ensure → waitWorker → host LoadModule →
   `Instantiate(sandboxID)`), setting `fromResidentHost`, `socketPath`=bucket
   socket, `workerKey`=bucket. Instantiate failure resets the bucket (respawn
   safety) and rolls back.
3. `lifecycle.go` Destroy: `fromResidentHost` → `client.StopInstance(sandboxID)`,
   never `supervisor.Stop` (the shared host stays up). (Stop already calls
   StopInstance, so it was already correct.)
4. `driver.go` `refreshWorkerInstanceState`: short-circuits for
   `fromResidentHost` (per-sandbox spawn-count liveness doesn't apply).
5. Daemon wiring: the resident supervisor is constructed only when the flag is
   set; nil/no-op otherwise.

Tests (`internal/runtime/wasm/resident_test.go`, offline): create routes to the
resident host (resident supervisor ensured, per-sandbox untouched, host-level
load + instantiate, `fromResidentHost` + bucket workerKey); Destroy StopInstances
without killing the host; flag-off takes the cold path; public-expose create
takes the cold path.

This also sidesteps the miss/refill race in `project_wasm_create_latency`: no
separate per-sandbox cold spawn to race — creates instantiate into a resident host.

**Remaining before the flag can flip ON (eng-review-gated):**
- **Per-instance egress isolation** — resident instances currently get base
  WASI + FS only; wasi-sockets/http egress needs the net host keyed by
  `mod.Name()` + conn ownership (see Phase 2 note). Until then, networking
  modules (likely CPython) aren't served by the resident host, so the live
  CPython cold-load win still can't be benched.
- **expose_port after create** on a private resident sandbox errors (resident
  host rejects listeners). Document, or migrate-to-cold-on-expose.
- **Host lifecycle**: idle-TTL teardown of resident hosts, capacity/admission
  accounting for host-shared RAM, `SB_WASM_RESIDENT_HOST_MAX_INSTANCES` cap.

### Validation (Phase 4)

`make integration-benchmark-wasm` on `cluster-3-mixed-wasm` with the flag on:
target is cold-miss `wasm_load` collapsing toward `wasm_instantiate` (~10ms) and
the p99 tail flattening. Stays default-off; eng-review + the isolation risk
enumeration gate the default flip.

## Expected outcome

- Cold-miss `wasm_load`: **2814ms → ~10ms** on a host already holding the module
  (first create per bucket still pays one compile, amortized across all later
  instances).
- p99 tail (2.6–2.9s) flattens because burst creates instantiate into resident
  hosts instead of each forking + compiling.
- Warm p50 (23ms) unchanged — this is about the tail, not the median.

## Risks / open questions

- Per-instance invocation deadline / fuel cancellation inside a shared runtime
  (today `WithInvocationDeadline` is per-call; verify it cancels only the target
  instance's call).
- Checkpoint/restore + clone-generation fencing (`pkg/wasm/snapshot_codec.go`
  `FenceCloneGeneration`) under co-tenancy — snapshots are per-instance; confirm
  the fence still keys correctly.
- Host-process lifecycle: when do resident hosts get torn down (idle TTL?),
  and how does drain/passivate interact with co-tenants still live on the host.
- Memory accounting for admission control (`pkg/capacity`) — a resident host's
  RAM is shared across instances; the admitter's per-sandbox model needs to
  understand host-shared cost.
