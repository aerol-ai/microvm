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

The config note (`~10s` cold compile vs `~2.8s` cached) strongly implies
`_compile` dominates, i.e. this plan is the right lever — but confirm, don't
assume.

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

### Engine (Phase 1)

Add a multi-instance capability WITHOUT touching the base `Engine` interface
(which `wasmtime` + several mocks implement). Preferred: a new
`MultiInstanceEngine` in `pkg/wasm` wrapping `{runtime, compiled,
map[sandboxID]api.Module}` with per-instance `Instantiate/StopInstance/Run/
CaptureSnapshot/RestoreSnapshot/ResolvedListenPort`. The existing
single-instance `wazeroEngine` stays the default path untouched. Offline unit
tests: two instances of the same compiled module cannot read each other's
linear memory; StopInstance on one leaves the other running; compile happens
exactly once across N instantiates.

### Worker protocol (Phase 2)

The worker `Server` today holds one `s.eng` + one `s.lastCaps`
(`server.go:16-24`). Make instance state per-`sandboxID` (the network mediator
and byte counters are **already** keyed by sandboxID — `netUsageFor`,
`mediator()` — so that half is done). Split the messages:

- `MsgLoadModule` → load/compile the host's shared module once (idempotent per
  bucket); returns the existing `LoadTimings`.
- `MsgInstantiate` / `MsgStopInstance` / `MsgCheckpoint` / `MsgRestore` /
  `MsgSetListenPort` → operate on the per-`sandboxID` instance.

**Scope limit for Phase 2:** wasip1 TCP listeners (`expose_port` / HTTP guests)
resolve one listener fd per instance and the server tracks a single
`lastCaps.WASIListenPort`. Multiplexing many listeners in one process is extra
complexity, so the first cut supports resident-host mode **only for
non-listen sandboxes** (one-shot exec / no `expose_port`); HTTP guests fall back
to the cold per-process path. Lift this in a later phase if the bench shows
HTTP guests need it.

### Pool + routing (Phase 3)

`internal/pool/wasm` shifts from "pool of pre-instantiated slots" to "pool of
resident hosts per (digest, memoryMB)." `Acquire` returns a host to instantiate
into rather than a slot to adopt. Refill keeps `min` hosts compiled per hot
bucket. This also naturally fixes the miss/refill race noted in
`project_wasm_create_latency` — there is no separate per-sandbox cold spawn to
race, because the create instantiates into a resident host.

### Config (Phase 3)

- `SB_WASM_RESIDENT_HOST_ENABLED` (bool, **default false**) — gates the whole
  path; when false, behavior is exactly today's.
- `SB_WASM_RESIDENT_HOST_MAX_INSTANCES` (int, default e.g. 32) — per-host
  instance cap (blast-radius bound + load spreading).
- Interplay: when enabled, the resident host is the warm mechanism, so
  `SB_WASM_POOL_ENABLED` semantics fold into host pre-compilation. Document
  which wins in `setup/config-defaults.md`.

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
