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
- **Per-instance memory cap** (`MemoryLimitPages`) bounds a single instance's
  memory. CPU-bound guests are bounded by **wall-clock cancellation**
  (`WithInvocationDeadline`), NOT fuel — fuel accounting is wasmtime-only in this
  codebase (Codex, eng-review 2026-07-17), so the resident (wazero) host relies
  on the invocation deadline for CPU bounding. See the co-tenancy deadline
  hardening in Phase 2b.
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

**Phase 2 remainder (per-instance egress isolation) — IMPLEMENTED 2026-07-17
(PR-A).** `multiNetHost` keys hooks + conns by `mod.Name()`; ResidentServer binds
a per-sandbox `NetworkHook` via `NetMediator`. See Phase 2b §1.

### Config (Phase 3) — flag IMPLEMENTED 2026-07-15

- `SB_WASM_RESIDENT_HOST_ENABLED` (bool, **default false**) → `cfg.WasmResidentHostEnabled`
  (`internal/config/config.go`). Gates the whole path; false = today's behavior
  exactly. **DONE.**
- `SB_WASM_RESIDENT_HOST_MAX_INSTANCES` (int, per-host cap, default 32) —
  **DONE in PR-A** (spill to `<bucket>-2.sock` when full).
- Interplay with `SB_WASM_POOL_ENABLED` + `setup/config-defaults.md` — TODO
  (PR-C / docs).

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

**Remaining before the flag can flip ON (eng-review-gated) — designed in Phase 2b below:**
- **Per-instance egress isolation** — **DONE (PR-A, 2026-07-17).**
- **expose_port after create** on a private resident sandbox — PR-B (migrate-on-expose).
- **Host lifecycle**: idle-TTL teardown + capacity/admission accounting — PR-C
  (`SB_WASM_RESIDENT_HOST_MAX_INSTANCES` shipped in PR-A).

## Phase 2b — egress isolation + expose + capacity (design, 2026-07-17, eng-review)

The three items above are what stand between "shipped, default-off" and "safe to
flip the default on." They are independent workstreams and ship as **three
stacked PRs** (see staging at the end). Item 1 is the only security-sensitive
one and gates the other two.

### 1. Per-instance egress isolation (PR-A, the blocker)

**The gap.** Outbound TCP for a wasip1 guest goes through the custom
`aerol/vm/net` host module (`tcp_dial`/`tcp_read`/`tcp_write`/`tcp_close`) — NOT
wasip1 sockets (wasi-preview1 has no outbound `sock_connect`; only
accept/recv/send on an already-listening fd, which resident-host mode doesn't
serve). That host module lives in `wazeroNetHost` (`pkg/wasm/wazero_network.go`),
which today holds **one** `hook *NetworkHook` and **one global**
`conns map[uint64]net.Conn`. It is correct for the single-instance engine (one
sandbox per process) and is **not instantiated at all** on `MultiInstanceEngine`,
so resident instances get base WASI + FS only.

Two things break if we naively instantiate the existing host on the shared
runtime: (a) one hook can't represent N co-tenant sandboxes' dialers/meters, and
(b) a global conn table lets guest B pass a `conn_id` that belongs to guest A and
read/write A's socket — a cross-tenant data leak.

**The fix — key everything by `mod.Name()`.** `MultiInstanceEngine.Instantiate`
already sets `WithName(sandboxID)` (engine_multi.go:131), so every host-function
call carries the caller's identity in `mod.Name()`. A new multi-tenant net host:

```
                     one resident runtime, one "aerol/vm/net" host module
                     ┌───────────────────────────────────────────────────┐
 guest A (mod.Name   │  tcp_dial(mod, addr):                              │
   = "sbx-A") ───────┼─►  sid := mod.Name()          // "sbx-A"           │
                     │    hook := hooks[sid]          // A's dialer+meter  │
 guest B (mod.Name   │    if hook==nil||blocked → errBlocked              │
   = "sbx-B") ───────┼─►  conn := hook.Dial(addr)     // A's NetMediator   │
                     │    id := nextID++                                  │
                     │    conns[sid][id] = conn      // OWNED by sbx-A     │
                     │                                                     │
                     │  tcp_read(mod, id, buf):                           │
                     │    sid := mod.Name()                               │
                     │    conn := conns[sid][id]     // B can't see A's id │
                     │    if conn==nil → errClosed                        │
                     │    n := conn.Read(buf); hooks[sid].Meter.AddIn(n)  │
                     └───────────────────────────────────────────────────┘
   hooks:  map[sandboxID]*NetworkHook          (per-tenant dialer + meter)
   conns:  map[sandboxID]map[uint64]net.Conn   (per-tenant conn table = ownership)
```

- `hooks map[string]*NetworkHook` replaces the single `hook`. Every host fn reads
  `mod.Name()` and looks up that sandbox's hook; a missing hook → `errBlocked`
  (fail closed, never fall through to another tenant's dialer).
- `conns map[string]map[uint64]net.Conn` replaces the global table. A `conn_id`
  is only resolvable inside its owner's inner map, so B passing A's id finds
  nothing → `errClosed`. This is the conn-ownership guarantee, enforced by data
  structure, not by a check that can be forgotten.
- Bytes meter through `hooks[sid].Meter` (per-tenant), so `NetstatsTick` stays
  per-sandbox.

The single-instance `wazeroEngine` keeps its existing one-hook host untouched
(it is correct there and flag-off must stay byte-for-byte identical). The
multi-tenant host is a **new type** (`multiNetHost` in a new
`pkg/wasm/engine_multi_network.go`), instantiated lazily on the resident runtime
the first time any instance binds a hook. `MultiInstanceEngine` gains
`SetNetworkHook(sandboxID, *NetworkHook)` / `ClearNetworkHook(sandboxID)`
mirroring `NetworkAwareEngine`.

**Decisions locked (eng-review 2026-07-17):**
- **Bucket by `(ownerRef, digest, memoryMB)`, not just `(digest, memoryMB)`**
  (D7 — AerolVM is SaaS + multi-tenant, [[project_saas_multitenant]], not only
  self-hosted). When a create carries a **non-operator `OwnerRef`** (control-plane
  resolved — `models.Sandbox.OwnerRef` / `ownerRefForCreate(ctx)`), the owner is
  mixed into `residentBucketID`, so a customer's sandboxes never co-locate in one
  process with another customer's — no cross-customer socket/blast-radius sharing.
  An **empty/operator `OwnerRef`** (the only case on the open-source build) keeps
  today's fully-shared global bucket, preserving max compile amortization for the
  self-hosted case. This is **in code, not docs** — `ownerRef` is a real
  dimension of `residentBucketID`. Wiring: thread `ownerRef` into the wasm
  `Driver.Create` path (the 4th `Create` arg is currently unused `_ string`, or
  read it from the create ctx as `ownerRefForCreate` does).
- **Conn ownership = structural nested map** `conns map[sandboxID]map[uint64]net.Conn`
  (D3-A). A `conn_id` is unresolvable outside its owner's inner map, so a
  cross-tenant read is unrepresentable, not merely guarded. `nextID` stays a
  global atomic (ids are unscoped-unusable, need not be secret).
- **DRY the socket body** (D5-A): factor `conn.Read`/`Write` + meter +
  error-mapping into a helper taking an already-resolved `(conn, meter)`; the
  single-instance host and `multiNetHost` differ ONLY in the resolve step
  (one field vs `mod.Name()` lookup). Security logic stays single-sourced.
- **Thread the invocation deadline into the dial** (D6-A): pass the host-fn
  call's ctx into `DialContext` instead of `context.Background()`, in BOTH the
  multi host and the existing single host (`wazero_network.go:106`, same one-line
  bug). Bounds a dial by min(invocation deadline, 30s dialer timeout).
- Missing hook or blocked egress → `errBlocked` (**fail closed**); never fall
  through to another tenant's dialer.

**Worker wiring** (`resident_server.go`) mirrors the single-instance `Server`,
which already has all the per-sandbox pieces:
- `ResidentServer` gets its own `*NetMediator` (already sandboxID-keyed:
  `SetBlocks`/`DrainUsage`/`DialContext` all take a sandboxID).
- `MsgInstantiate` → after `eng.Instantiate`, bind
  `eng.SetNetworkHook(sandboxID, &NetworkHook{SandboxID: sandboxID,
  Dial: mediatorDialer{m, sandboxID}, Meter: workerByteMeter{usageFor(sandboxID)}})`
  — identical to `Server.bindNetworkHook`, just keyed.
- `MsgSetNetworkBlocks` → `mediator().SetBlocks(sandboxID, …)` (was rejected).
- `MsgNetstatsTick` → `mediator().DrainUsage(sandboxID)` (was rejected).
- `MsgStopInstance` → `eng.ClearNetworkHook(sandboxID)` + drop mediator usage.

Once wired, the driver's existing egress-policy plumbing (the service layer
sends `SetNetworkBlocks` after create) flows to resident sandboxes unchanged, so
the `createOnResidentHost` caps no longer need to be networking-stripped.

**Residual co-tenancy risk to enumerate:** a single mutex guards `hooks`/`conns`
lookups (released before the blocking `conn.Read`/`Write`, so no head-of-line
blocking across tenants). A panic inside a host fn still runs on the shared
process (existing co-tenancy risk, already documented). A hung dial is bounded
by `NetMediator`'s 30s dialer timeout, but note `tcp_dial` currently dials with
`context.Background()` (wazero_network.go:106) — it ignores the invocation
deadline. Pre-existing, but worth fixing under co-tenancy so one tenant's slow
dial can't pin a goroutine indefinitely.

### 1b. Co-tenancy correctness hardening (PR-A, D8 — from Codex outside voice)

Shared-process correctness that a naive multi-tenant net host would miss. All in
PR-A because the flag flip depends on them.

- **Per-instance call/lifecycle lock or refcount.** `MultiInstanceEngine.InvokeExport`
  (engine_multi.go:215) releases the engine lock before `fn.Call`, while
  `StopInstance`/`Run` can `Close`/replace the same `api.Module` concurrently →
  use-after-close. Add a per-instance guard (refcount or per-instance mutex) so a
  Stop waits for in-flight calls (or cancels them) and a call sees a stable
  module. **Plus a stress test** proving wazero permits parallel `Call` across
  *different* modules on one runtime under load (the design's core unproven
  assumption).
- **Connection cleanup on teardown.** `StopInstance`, `Run` (which drops+replaces
  the module at engine_multi.go:162), and `ClearNetworkHook(sid)` must **close +
  delete `conns[sid]`**. This frees sockets AND is the lever that unblocks a
  pinned `tcp_read`/`tcp_write` (closing the conn makes the blocked Read return)
  — so it doubles as the fix for reads/writes having no deadline (D6 only covered
  dial).
- **Resident `MsgInvoke` invocation deadline.** `resident_server.go` calls
  `eng.InvokeExport(ctx, …)` with `ctx=context.Background()` (resident_server.go:56)
  — no deadline, unlike the single-instance `Server` which wraps invoke with
  `WithInvocationDeadline`. Bug in already-merged code; fix here. (`MsgExec` is
  fine — `Run` wraps it internally.)
- **Respawn / idempotency hardening (P2, merged-code gaps):**
  - `refreshWorkerInstanceState` short-circuits `fromResidentHost` instances
    without checking host liveness (driver.go:137) → after a host crash,
    `Inspect`/`List` report `started` for gone instances. Verify the host socket
    (or a generation token) for resident instances.
  - `ensureResidentHost` skips health/load when `bucket.ready` (resident.go:81);
    if the supervisor restarted the host behind the same socket, `ready` is stale
    until an instantiate fails. Health-check (Ping + `InstanceStatus.Loaded`) on
    reuse, or track a host generation.
  - `ResidentServer.LoadModule` reads `loadedPath` unlocked then loads then writes
    it — two concurrent different-path loads can both pass `prev==""`. Hold the
    lock across check+load (or single-flight per path in the server), so the
    one-module-per-host invariant holds even without the driver single-flight.

### 2. expose_port after create (PR-B)

With private-by-default (`project_private_by_default`), a normal create is
private → routes to the resident host, and the caller exposes a port **later**.
The resident host can't add a wasip1 listener to an already-instantiated shared
runtime (the listener is configured per-instance via `experimentalsock.WithConfig`
at instantiate time, engine_wazero.go withNetworkContext). So expose-after-create
on a resident sandbox is **the normal flow now, not a rare edge** — a plain error
is not acceptable.

**Design: migrate-on-expose, cold-up-then-stop-resident (D4-A, eng-review
2026-07-17).** When `expose_port` (→ `SyncGuestListenPorts`,
`internal/runtime/wasm/guest_http.go:20`) hits a `fromResidentHost` sandbox:
1. Instantiate the sandbox on a **fresh cold per-process worker WITH** the
   listener config, preserving sandboxID + workDir + env + digest.
2. Only after the cold instance is confirmed up, `StopInstance` on the resident
   host and flip `inst.fromResidentHost=false` + `inst.socketPath` to the cold
   worker.
There is **no window with zero instances**: if step 1 fails, the resident copy
is still serving and expose returns an error (failure-path consistency,
pr-review §4). Costs a bit of transient RAM during the swap. The first expose
pays a cold `wasm_load` once (acceptable — expose is not the hot create path);
subsequent traffic is normal. Rejected: stop-then-recreate (real zero-instance
window + a rollback that can itself fail), and routing every possibly-exposing
create to cold up front (defeats the latency win — private-by-default means
almost everything could expose).

**IMPLEMENTED 2026-07-17.** `Driver.migrateResidentToCold` (`resident.go`) does
the cold-up-then-stop dance (spawn dedicated worker → waitWorker → LoadModule →
Instantiate listener-disabled → then StopInstance on the resident host +
`releaseResidentSlotFor` + flip `socketPath`/`workerKey`/`fromResidentHost` +
`noteWorkerSpawnCount`); a cold-bring-up failure Stops the half-spawned worker
and leaves the sandbox resident. `SyncGuestListenPorts` (`guest_http.go`) calls
it before the listener sync when the sandbox is `fromResidentHost` and the
request enables a listener (an unexpose on a still-resident sandbox is a no-op).
Tests: `resident_test.go` `TestMigrateResidentToCold` (routing flip + slot
release + resident stop) and `TestExposeMigrationFailureLeavesResident`
(cold-instantiate failure keeps the sandbox resident, slot retained, error
surfaced). Not on the `CreateSandbox` boot path; first expose pays one cold
compile.

### 3. Host lifecycle + capacity (PR-C)

- **Idle-TTL reaper.** A resident host with `InstanceCount()==0` for
  `SB_WASM_RESIDENT_HOST_IDLE_TTL` (default e.g. 5m) is torn down to reclaim RAM
  (a bucket holds the ~25MB compiled image + runtime resident). Boot pre-warm
  re-creates standard-module hosts, so the reaper must not fight pre-warm — skip
  reaping pre-warmed standard-module buckets, or let pre-warm re-spawn on next
  demand. Reaper is a ticker goroutine on the driver, gated by the flag.
- **`SB_WASM_RESIDENT_HOST_MAX_INSTANCES`.** Cap instances per host process; when
  a bucket's host is full, spawn a second host for the same bucket
  (`<bucket>-2.sock`) and route there. Bounds blast radius per the isolation
  section.
- **Capacity/admission.** `pkg/capacity` Admitter models per-sandbox RAM. A
  resident bucket's cost is `compiled image + runtime` **once per bucket** plus
  per-instance linear memory (≤ `memoryMB`). The admitter needs a host-shared
  cost model so it doesn't over- or under-count resident instances. This is the
  fuzziest item; if it can't be made correct quickly, gate the flag flip on a
  conservative over-count (treat each resident instance as full `memoryMB`) and
  refine later.

**IMPLEMENTED 2026-07-17 (PR-C).**
- **Idle-TTL reaper** — `Driver.RunResidentReaper` (daemon goroutine, gated by
  the flag; stops on ctx cancel) scans every `SB_WASM_RESIDENT_HOST_IDLE_TTL/4`
  (clamped 5s–1m; default TTL 5m, 0 disables) and `reapIdleResidentHosts` tears
  down any host with `live==0` idle ≥ TTL. Pre-warmed standard-module hosts are
  `pinned` (set when `ensureResidentHost` runs with `reserve=false`) and never
  reaped. Idle tracking: `residentHost.idleSince` set when `releaseResidentSlot`
  drops `live` to 0, cleared on the next reserve. Buckets use a **monotonic
  `nextIndex`** so a reaped-then-respawned host can't collide sockets. Selection
  is under `bucket.mu` (a concurrent create that takes the host wins and it's
  kept); `supervisor.Stop` runs outside the lock. Tests:
  `TestResidentReaperReapsIdleHost`, `TestResidentReaperKeepsPinnedAndActive`.
- **`MAX_INSTANCES`** — shipped in PR-A (`SB_WASM_RESIDENT_HOST_MAX_INSTANCES`,
  default 32, spill-to-second-host).
- **Capacity — conservative + observability** (D-decision 2026-07-17). No
  admission-path change: each sandbox is already admitted at full `memoryMB` (an
  over-count that cushions the guest's actual linear memory), and the shared
  per-bucket base (compiled image + runtime) is treated as uncounted headroom
  operators reserve via `MemoryFloorRatio`/`MemoryReservationRatio`. To make that
  sizeable, `Driver.ResidentHostStats` (buckets/hosts/instances) is published as
  the `aerolvm_wasm_resident_hosts` expvar (test `TestResidentHostStats`). Exact
  per-bucket-base reservation via a driver→`pkg/capacity` seam is deferred until
  a real deployment shows the base RAM bites.

### Test plan (eng-review 2026-07-17)

**PR-A (egress isolation) — offline, 100% of new branches:**
- `pkg/wasm/engine_multi_network_test.go`:
  - **★★★ IRON-RULE isolation regression (security boundary + fragile area):**
    two co-tenant instances on one `MultiInstanceEngine`; A dials → conn_id; B
    `tcp_read`/`tcp_write`/`tcp_close` with A's conn_id → `errClosed`, A's conn
    stays usable. Proves the cross-tenant deny the whole PR exists for.
  - per-tenant metering attribution (A's bytes ≠ B's bytes);
  - `SetBlocks(A)` blocks A's egress, B still dials (per-tenant policy);
  - fail-closed: no hook / blocked → `errBlocked`;
  - `ClearNetworkHook(A)` leaves B's networking live;
  - dial honors the invocation deadline (D6-A) — a canceled ctx aborts the dial.
- `pkg/wasm/worker/resident_server_test.go` (extend): `MsgSetNetworkBlocks` /
  `MsgNetstatsTick` now succeed keyed per-sandbox (were rejected);
  `MsgInstantiate` binds a hook so a dial works; `MsgStopInstance` clears it.
- `internal/runtime/wasm/resident_test.go` (extend): `createOnResidentHost` caps
  no longer strip networking; `Driver.SetNetworkBlocks` on a `fromResidentHost`
  sandbox reaches the bucket socket and is honored; a **non-operator `OwnerRef`
  buckets to a distinct host** from the operator/empty case (D7); host-crash →
  `refreshWorkerInstanceState` no longer reports a gone instance as `started`.
- Correctness cluster (D8): **concurrency stress test** — N goroutines
  Instantiate/Invoke/StopInstance across distinct sandboxIDs on one
  `MultiInstanceEngine` with `-race`, asserting no use-after-close and that
  parallel `Call`s across modules actually run; conn cleanup — `StopInstance`
  closes owned conns and a blocked `tcp_read` returns; `MsgInvoke` respects the
  invocation deadline; `LoadModule` two-concurrent-different-paths keeps one
  module.
- **Live (Phase 4, `[→E2E]`):** CPython egress on the resident host,
  `make integration-benchmark-wasm` on `cluster-3-mixed-wasm` — the win that
  couldn't be benched until egress works.

**PR-B (migrate-on-expose):** `expose_port` on a `fromResidentHost` sandbox
migrates to cold + listener works; cold-create failure leaves the resident copy
serving + returns an error (no zero-instance window); idempotent re-expose.

**PR-C (lifecycle):** idle-TTL reaps a 0-instance host but NOT a pre-warmed
standard bucket; `MAX_INSTANCES` spills to a second host; admitter counts a
resident instance's host-shared cost.

### Staging (3 stacked PRs)

- **PR-A — egress isolation + hard cap** — **IMPLEMENTED 2026-07-17**.
  `pkg/wasm/engine_multi_network.go` (new), `engine_multi.go`,
  `wazero_network.go` (shared helper + dial-ctx), `worker/resident_server.go`,
  `internal/runtime/wasm/resident.go` (+ owner bucketing + max-instances spill +
  host liveness) + tests. **Includes `SB_WASM_RESIDENT_HOST_MAX_INSTANCES`**
  (default 32; spill to `<bucket>-2.sock` when full). Still default-off after this.
- **PR-B — migrate-on-expose.** `internal/runtime/wasm/guest_http.go` +
  `resident.go` + tests.
- **PR-C — host lifecycle + capacity. DONE 2026-07-17.** idle-TTL reaper
  (`RunResidentReaper` + `SB_WASM_RESIDENT_HOST_IDLE_TTL`, pinned prewarm hosts,
  monotonic host index) + conservative capacity stance with the
  `aerolvm_wasm_resident_hosts` expvar footprint metric + tests.
  (`MAX_INSTANCES` shipped in PR-A; exact Admitter reservation deferred.)
- **Flag flip** (`SB_WASM_RESIDENT_HOST_ENABLED` default → true) is a **4th,
  separate** change, only after A+B+C land and the live CPython bench is green.
  **Live bench GREEN (2026-07-17, v0.7.12)** — see Validation below. Still one
  pre-flip cleanup: enabling the resident host should **skip the warm pool**, not
  just supersede it at create time (see Validation).

### Validation (Phase 4)

`make integration-benchmark-wasm` on `cluster-3-mixed-wasm` with the flag on:
target is cold-miss `wasm_load` collapsing toward `wasm_instantiate` (~10ms) and
the p99 tail flattening. Stays default-off; eng-review + the isolation risk
enumeration gate the default flip.

**Result — GREEN (2026-07-17, v0.7.12, `cluster-3-mixed-wasm`, flag on via
`extra_user_data`, 10 samples, 0 failures):** every create took the resident
path — the only create stage recorded is `wasm_instantiate` (p50 **11ms**), with
NO `wasm_load`/`wasm_load_compile` and NO `wasm_warm` (the cold/warm-pool
signatures). Server latency **p50 22ms · p90 46ms · p99 50ms** (mean 26ms),
`cluster_promote` 7ms. Versus the flag-off warm-pool baseline (p90/p99
2722/3042ms from cold-compile misses) the ~3s tail is **gone (~98% p99
reduction)** — flat ~20–50ms across all samples. 0 failures confirms
standard-module creates succeed co-tenant on the shared resident host with the
per-tenant net host active. Artifact: `wasm-bench-v0712-t3large.json`.

**Two operational findings from the bench (pre-flag-flip):**
1. **Resident + warm pool are redundant and double-consume RAM.** With the flag
   on, non-listen creates take the resident path and never touch the warm pool,
   yet the pool still pre-spawns workers. On a t3.medium (~4GB) that + boot
   pre-warm (4 standard modules resident) starved the box — the live-memory floor
   correctly rejected creates at 274MB free. The bench needed a t3.large. **Fix
   before flip:** when `SB_WASM_RESIDENT_HOST_ENABLED` is on, skip/short-circuit
   the warm pool (`SB_WASM_POOL_ENABLED`) for the modules the resident host
   serves, so operators don't pay double memory.
2. **`SB_WASM_POOL_DEPTH_DEFAULT=0` is rejected when the pool is enabled** — not a
   way to disable the pool; use `SB_WASM_POOL_ENABLED=false`.

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

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 13 findings, all folded/resolved |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | clean | 6 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** 13 findings. P1 cluster (per-instance call/lifecycle lock + refcount + parallel-call stress test, conn cleanup on teardown, `MsgInvoke` invocation deadline) + P2 respawn hardening (host-liveness in `refreshWorkerInstanceState`, `bucket.ready` health-check, `LoadModule` check-then-load race) all folded into PR-A (D8). Fuel-framing doc corrected (wazero = wall-time only).
- **CROSS-MODEL:** two tensions, both resolved. Sharing granularity → bucket by `(ownerRef, digest, memoryMB)` (multi-tenant SaaS isolation, operator/empty keeps global bucket). Capacity sequencing → `MAX_INSTANCES` moved from PR-C into PR-A. No residual disagreement.
- **VERDICT:** ENG CLEARED — design locked across PR-A (egress isolation + hard cap + co-tenancy correctness), PR-B (migrate-on-expose), PR-C (idle-TTL + capacity), then a separate flag flip. **PR-A implemented 2026-07-17;** next is PR-B.

NO UNRESOLVED DECISIONS
