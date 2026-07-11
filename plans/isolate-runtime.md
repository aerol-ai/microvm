# V8-Isolate Sandboxes (Deno/Workers model) — Design & Implementation Plan

Status: **Proposed** (not started) · Owner: TBD · Created: 2026-07-10

This plan adds a **fifth runtime** to AerolVM — **V8 isolates** (the
Deno-Deploy / Cloudflare-Workers model) — as a peer to `docker`, `gvisor`,
`firecracker`, and `wasm`. The design principle is the one every prior runtime
followed: **reuse the existing ecosystem as much as possible.** The WASM
runtime is the near-exact template — it is already an out-of-process,
host-mediated, warm-pooled, `Runtime`-only (not `ContainerRuntime`) driver.
An isolate runtime is *the WASM runtime with a different engine*: the worker is
a V8/`workerd` host instead of a wazero host, and the "module" is a JS/TS
bundle instead of a `.wasm`.

The isolate runtime is the **fast-JS, high-density tier**: ~5ms cold start,
thousands of sandboxes per host, JS/TS/WASM only, weaker-than-VM isolation.
It is the complement to the Firecracker tier (arbitrary binaries, real VM
isolation) — the same two-tier split Deno itself arrived at when it paired
Workers (isolates) with Deno Sandbox (microVMs).

---

## 0. Review history

Not yet reviewed. Run `/plan-eng-review` + an independent outside-voice review
before Phase 1. Open questions are collected in §13. The load-bearing decision
to settle first is **§2.1 (isolate-group blast radius)** — it is to this plan
what the worker-crash isolation gate (D10) was to the WASM plan.

---

## 1. How the runtime abstraction works today (the reuse surface)

The service layer drives every sandbox through `internal/runtime.Runtime`
(`internal/runtime/runtime.go`). Two facts make the isolate runtime cheap:

1. **`Runtime` vs `ContainerRuntime` are already split.** `Runtime` is the core
   contract (Create/Start/Stop/Destroy/CreateSnapshot/Resize/Inspect/
   ListManaged/Ping/RemoveImage). `ContainerRuntime` adds per-IP iptables +
   toolbox-allowlist methods. `runtime.AsContainerRuntime(rt)` returns `false`
   for host-mediated runtimes. **WASM implements only `Runtime`** and uses
   host-mediated sockets instead of a TAP/veth. **The isolate runtime does the
   same** — isolates never get an IP, so there is nothing for iptables to
   pin.

2. **Dispatch is a single string switch.** `Service.runtimeForSandbox`
   (`internal/service/service.go:500`) maps `sandbox.Runtime` → the registered
   driver. `runtimeRef` (line 518) returns `sandbox.ID` for host-mediated
   runtimes (Firecracker/WASM) instead of a container ref. Adding a driver =
   one field, one setter, one branch.

The WASM driver (`internal/runtime/wasm/driver.go`) is the shape to copy:

```go
type Driver struct {
    cfg    Config
    logger *slog.Logger
    resolver        ModuleResolver      // ref → local artifact
    supervisor      WorkerSupervisor    // owns per-sandbox worker subprocesses
    newWorkerClient WorkerClientFactory // IPC to a worker over a UDS
    net             *networkGateway     // host-mediated HTTP proxy + egress policy
    warmPool        WarmPool            // pre-spawned workers
    stateKV         statekv.Store       // durable per-sandbox KV
    mu   sync.Mutex
    byID map[string]*sandboxInstance
}
```

Every one of those seams has a direct isolate analog (§7). The driver-dispatch
diagram, post-isolate:

```
service.runtimeForSandbox(sandbox.Runtime)
  ├─ "docker"      → pkg/docker.Client        (ContainerRuntime)
  ├─ "gvisor"      → pkg/docker.Client        (ContainerRuntime, runsc)
  ├─ "firecracker" → internal/runtime/firecracker.Driver (ContainerRuntime)
  ├─ "wasm"        → internal/runtime/wasm.Driver         (Runtime only)
  └─ "isolate"     → internal/runtime/isolate.Driver      (Runtime only)  ← NEW
```

---

## 2. Engine choice: **`workerd`** (out-of-process host)

"Deno-style" means the **Workers model**: isolates + a `fetch` handler +
capability-scoped permissions. The open-source, production-grade host for
exactly that model is Cloudflare's **`workerd`**. We *wrap the engine process*
— the same posture we use for `firecracker` (external process + API) and
`wasm` (worker subprocess + IPC) — rather than rebuilding V8.

| Option | What you get | Cost |
|---|---|---|
| **`workerd`** ✅ default | Real Workers semantics, isolate-groups, Spectre mitigations built in, `fetch` handler, capnp config | Ship a C++ binary; opinionated API; capnp config generation |
| `v8go` (CGo) behind a build tag | Full control, plain-Go host | Reimplement isolate lifecycle, resource limits, **and security hardening** — a project on its own |
| Node/Deno `worker_threads` pool | Easiest to stand up | Weakest cross-tenant boundary — not real isolate isolation |

Decision: **`workerd` as the default engine**, behind a `pkg/isolate` engine
seam so a `v8go` backend can be added later under `//go:build v8go` — mirroring
how `pkg/wasm` selects wazero by default and wasmtime behind `-tags wasmtime`
via `NewEngineFor`.

### 2.1 The isolate-group model & blast radius (load-bearing decision)

**This is the decision the whole plan rests on.** Unlike a microVM, isolates
share an OS process, so a V8 escape (JIT bug) or an unbounded-memory isolate is
a *cross-tenant* event within its host process. WASM sidesteps this by running
**one worker subprocess per sandbox** (strong, low density). Isolates would
throw away their density advantage if we did the same.

The chosen middle path is the one Cloudflare uses in production —
**isolate-groups**:

- Pack many isolates into one `workerd` process, but **group by tenant / trust
  level**. Density *within* a trust boundary; an OS-process boundary *across*
  tenants.
- Make group granularity **configurable**, down to **one isolate per process**
  for a paranoid tier (e.g. regulated / adversarial workloads). This is the
  isolate analog of choosing Firecracker over gVisor.
- **Jail the `workerd` process** — reuse the Firecracker jailer thinking
  (chroot + cgroups + drop-priv) for defense-in-depth, so even a process-level
  escape is contained to a jail with no host filesystem access.

**P0 release gate (§11):** a cross-tenant isolation test — a hostile isolate
(OOM, tight CPU loop, attempted host-fs/network access outside granted caps)
must not (a) read another tenant's memory, (b) take down `sandboxd`, (c) starve
co-tenant isolates beyond their configured CPU/mem caps. Without this test,
Phase 1 cannot ship — it is the test that verifies the property the whole
isolate tier depends on.

---

## 3. The exec/toolbox problem (isolates have no shell)

Docker/Firecracker sandboxes run an in-container `toolboxd` that serves
files/exec/sessions. WASM already broke that assumption and serves the toolbox
**from the host** (`internal/runtime/wasm/toolhost/`). Isolates go one step
further: **an isolate has no POSIX process, no shell, no filesystem** — only a
JS runtime with a `fetch` entrypoint.

Consequences, to be stated plainly in the docs (same honesty as the WASM
"residual limits"):

- **`exec` degrades to "invoke the handler."** On this runtime, "run a command"
  means *issue an HTTP request to the isolate's `fetch` handler* (or invoke a
  named export). There is no PTY / shell semantics.
- **Filesystem** is virtual — the module bundle plus any host-KV state
  (§4). No arbitrary file I/O.
- **Sessions** map to a long-lived isolate (or are N/A). Decide per §13.

The host-mediated toolbox surface (`toolhost`) is reused for the parts that
*do* map (code-run, HTTP proxy), and returns a clean `501`-style
"not-supported-on-this-runtime" for the parts that don't — exactly how the WASM
interpreter routes already handle unsupported toolboxd verbs.

---

## 4. Networking, warm pool, snapshots, durability

**Networking — host-mediated, no iptables (why it's `Runtime` not
`ContainerRuntime`).** Reuse the `networkGateway` + `ProxyHTTP` seam that WASM
already exposes on its `WorkerClient`:
- outbound `fetch()` is routed through a **host-side proxy** the driver
  controls, so egress allowlist / CIDR policy / byte-counting still apply — the
  same knobs iptables gives Docker, enforced at the proxy layer;
- inbound HTTP is proxied by the driver to the isolate's `fetch` handler;
- Caddy L7 routing to the host-mediated listener is reused wholesale (the WASM
  path already does this — see `wasm-networking-finish.md`).

**Warm pool — the whole point (`internal/pool/isolate/`).** Copy
`internal/pool/wasm/` (`pool.go`/`refill.go`/`spawner.go`/`metrics.go`):
pre-spawn `workerd` hosts with the runtime loaded so a create just injects the
tenant bundle into a fresh isolate → **~5ms**. Same expvar hit/miss/orphan
metrics and ticker refill as the `vmm` and `wasm` pools.

**Snapshots — cheaper than Firecracker's.** No memory image; instead a **V8
startup/heap snapshot** of the loaded-bundle isolate so a cold isolate resumes
already-parsed/compiled. Maps to `CreateSnapshot`. In practice the warm pool
matters more than snapshots for this tier.

**Durability — already built (`statekv`).** Cloudflare pairs Workers (isolates)
with Durable Objects (state). AerolVM already has the analog: the WASM
runtime's `statekv` durable per-sandbox KV. Reuse it: stateless isolates are
`DurabilityEphemeral`; stateful ones lean on `statekv`. Isolate + `statekv` =
Workers + Durable Objects. The `Durability` field, `ValidDurability`, and the
store column already exist from the WASM work — the isolate driver just applies
the same policy per class (§4.2/§4.5 of `wasm-runtime.md`).

**Resource limits.** CPU-time / wall-clock / memory caps per isolate are
enforced by `workerd`; map `CreateSandboxRequest.CPU`/`MemoryMB` onto isolate
limits at create time.

---

## 5. Features V8-isolate sandboxes enable

- **~5ms cold start, thousands/host** — per-request functions, edge-style
  fan-out, bursty AI-tool execution where boot latency dominates.
- **Deploy a file, not an image** — push a JS/TS bundle; no Dockerfile, no
  image build, no registry pull on the hot path.
- **Capability-scoped untrusted JS** — plugins, third-party scripts,
  AI-generated snippets run with only the fetch/env/KV caps you grant.
- **Cheapest possible multi-tenancy** — enables free-tier / per-invocation
  billing economics a container tier can't match.
- **A genuine two-tier product** — isolates for high-volume JS; Firecracker for
  arbitrary untrusted binaries. Same complementary pair Deno ships.

---

## 6. Use cases (target ≥40, mirroring the WASM plan's bar)

Grouped; each traces to a component in §12. (Fill to ≥40 during review — seed
set below.)

- **Per-request compute:** UC-I01 webhook transform, UC-I02 API gateway
  middleware, UC-I03 edge A/B logic, UC-I04 image-URL signer.
- **AI/agent tools:** UC-I05 run AI-generated JS tool, UC-I06 sandboxed
  eval for a chat tool-call, UC-I07 per-user plugin execution.
- **Multi-tenant SaaS:** UC-I08 customer-authored hooks, UC-I09 form-logic
  scripts, UC-I10 scheduled JS jobs (idle-to-zero).
- **Platform:** UC-I11 idempotent create under retry, UC-I12 warm-pool hit,
  UC-I13 egress allowlist enforced at proxy, UC-I14 byte-quota enforcement,
  UC-I15 durable KV state across resume, UC-I16 mixed-runtime host (5 drivers
  coexist), UC-I17 cross-tenant isolation (P0 gate), UC-I18 custom domain to a
  fetch handler, UC-I19 5-SDK `runtime:"isolate"` parity, UC-I20
  Daytona/E2B facade passthrough.

---

## 7. Packages to CREATE

```
internal/runtime/isolate/        # the Driver (mirror internal/runtime/wasm/)
  driver.go        # Driver struct + Runtime methods + dispatch registry
  create.go        # createIsolateSandbox: resolve bundle → acquire host → load
  lifecycle.go     # Start/Stop/Destroy/Resize/Inspect/ListManaged/Ping
  network.go       # networkGateway wiring (host-mediated)
  guest_http.go    # inbound HTTP → fetch handler proxy
  ports.go         # expose-port parity (host-mediated, pool NOT walked)
  warmacquire.go   # claim a warm workerd host + inject bundle
  exec.go          # "exec" = invoke handler / 501 for unsupported verbs
  seams.go         # BundleResolver, HostSupervisor, HostClient(+Factory), WarmPool
  config.go        # Config + SB_ENABLE_ISOLATE + group-granularity knob

internal/pool/isolate/           # warm pool (copy internal/pool/wasm/)
  pool.go refill.go spawner.go metrics.go errors.go

pkg/isolate/                     # engine wrapper (analog to pkg/wasm/)
  host.go          # manage workerd process + capnp config generation
  engine.go        # NewEngineFor(name): "workerd" default, "v8go" behind tag
  snapshot.go      # V8 heap snapshot codec (Phase 4)
  worker/          # IPC client/server + protocol (mirror pkg/wasm/worker)

pkg/jsbundle/                    # bundle resolver (analog to pkg/wasmmod/)
  resolve.go       # ref (path/file://) → local bundle; validate
  build.go         # esbuild entrypoint → single bundle
  oras_push.go oras_pull.go   # optional: bundles in the same OCI registry
```

Every new package ships with `_test.go` next to it at the ~85% bar (§11).

---

## 8. Files to CREATE outside new packages

- `internal/service/isolate.go` — `createIsolateSandbox` (version-agnostic
  service helper; mirrors `internal/service/wasm.go`), reusing
  `request_idempotency` + `CreateSandboxWithID`.
- `docs/src/content/docs/isolate-sandbox.mdx` — feature page, five-tab SDK
  examples, registered in `content.config.ts` (see `/add-docs-page`).
- `docs/src/content/docs/isolate-architecture.mdx` — architecture deep-dive
  (optional; the "Engine, Chassis, Runtime" engineering page already frames the
  isolate tier).

---

## 9. Files to MODIFY

- **`pkg/models/types.go`** — add `RuntimeIsolate = "isolate"` next to
  `RuntimeWasm`; add to `ValidRuntime` (accept ahead of impl); `CreateSandbox`
  rejects with `ErrRuntimeNotImplemented` until `SB_ENABLE_ISOLATE` is set AND
  the driver has landed. Verify the `runtime` column has no CHECK/enum
  constraint so no store migration is needed for the new value.
- **`internal/service/service.go`** — add `isolate runtime.Runtime` field +
  `SetIsolateRuntime`; add the `RuntimeIsolate` branch in `runtimeForSandbox`
  (line ~500) and `runtimeRef` (line ~518, returns `sandbox.ID`); add an
  `isIsolateSandbox` helper. Any change here is a **boot-path touch** — call
  out latency in the PR (`/touch-create-sandbox`).
- **`internal/config/`** — add `EnableIsolate` (`SB_ENABLE_ISOLATE`) and the
  isolate-group granularity / jail knobs.
- **`pkg/daemon/daemon.go`** — when `cfg.EnableIsolate`: construct the driver +
  warm pool, `svc.SetIsolateRuntime(...)`, and
  `appendRuntimeIfMissing(runtimes, models.RuntimeIsolate)` (line ~1458).
- **`pkg/capacity/`** — teach admission the isolate footprint (isolates are
  cheap; density-bound, not CPU/mem-bound like VMs).
- **`internal/service/platform_volumes.go`** — isolates don't take platform
  volumes (host-mediated); add `RuntimeIsolate` to the reject set beside
  `RuntimeFirecracker`/`RuntimeWasm` (line ~45).
- **The 5 SDKs** — add the `isolate` runtime constant in lockstep
  (`/add-sdk-method` discipline); no new method, just the enum value + docs.

---

## 10. Phasing (mirrors the Firecracker/WASM rollout)

- **Phase 1 — Skeleton + dispatch + the P0 isolation gate.** Land
  `RuntimeIsolate`, `ValidRuntime`, `SB_ENABLE_ISOLATE`, an
  `internal/runtime/isolate.Driver` whose methods return
  `ErrRuntimeNotImplemented`, service dispatch, daemon wiring. Stand up
  `pkg/isolate/host.go` + `worker/` skeleton (manage one `workerd`, capnp
  config, UDS IPC). **The §2.1 cross-tenant isolation test lands here, not
  later — without it no further phase ships.** Proves the 5th `Runtime` holds.
- **Phase 2 — Cold path.** `pkg/jsbundle` resolve+build; `Create/Start/Stop/
  Destroy/Inspect/Ping/ListManaged` against one isolate; capability config
  (env/fetch/KV grants); service helper `internal/service/isolate.go`.
- **Phase 3 — Host toolbox + HTTP.** `guest_http.go` inbound fetch proxy;
  `exec` = invoke-handler; Caddy L7 route to the host-mediated listener; port
  allowlist (pool NOT walked); custom domains.
- **Phase 4 — Warm pool + density + snapshots.** `internal/pool/isolate`
  pre-spawn; isolate-group packing + per-group jail; V8 heap snapshot; CPU/mem
  limit mapping; per-invocation billing export.
- **Phase 5 — Durability + cluster + facades + docs + SDKs.** `statekv`
  durability policy per class; cluster placement/forwarding/failover parity
  (no-op when `EnableCluster` false); Daytona/E2B passthrough carrying
  `runtime:"isolate"`; docs page(s); 5-SDK constants.

Each phase is independently mergeable because the `Runtime` surface stays
stable — the property every prior skeleton was landed to prove.

---

## 11. Non-negotiables checklist (pr-review.md alignment)

- **Cross-tenant isolation (P0 RELEASE GATE, §2.1).** A test MUST run a hostile
  isolate (OOM / CPU spin / out-of-cap host access) and assert: (a) no
  cross-tenant memory read, (b) `sandboxd` survives, (c) co-tenants are not
  starved beyond configured caps, (d) the offending isolate/group is torn down
  and the slot recreated. **Phase 1 cannot ship without it.** PR description
  must confirm it exists and passes.
- **Idempotency.** `createIsolateSandbox` reuses `request_idempotency` +
  `CreateSandboxWithID`; bundle resolution is content-addressed so a retry
  resolves to the same digest. `expose_port` is host-mediated — returns the
  existing URL, **does not walk the host-port pool**.
- **Boot-path latency.** Bundle compile+instantiate is on the cold create path;
  the warm pool (Phase 4) removes it for the common case. First-call cost is
  called out explicitly, mirroring the Firecracker/WASM notes.
- **Lazy bootstrap.** Engine warmup + bundle cache use the `atomic.Bool` latch
  + `sync.Mutex` single-flight pattern (canonical: `EnsureLayer4Ready`).
- **Failure-path consistency.** `createIsolateSandbox` unwinds via
  `Driver.Destroy` on every post-create error — no reliance on reconcile for
  routine cleanup.
- **Host-mediated only.** Implements `Runtime`, **not** `ContainerRuntime`;
  `AsContainerRuntime` returns false. No TAP/veth, no per-IP iptables.
- **Restart correctness.** Isolate hosts do not survive a daemon restart;
  reconcile is redefined per durability class (reuse the WASM §4.5 policy).
  Regression test: a restart with live `ephemeral`/`durable` rows lands each in
  the right terminal/rehydrated state; flipping `EnableIsolate=false` between
  restarts preserves durable rows.
- **Coverage.** Every new package (`pkg/isolate`, `pkg/jsbundle`,
  `internal/runtime/isolate`, `internal/pool/isolate`) ships table-driven tests
  at ~85% (`/maintain-coverage` before the PR).
- **Cluster.** All `internal/cluster` changes are no-ops when `EnableCluster`
  is false; placement counts isolate footprint; regression tests next to the
  files changed.

---

## 12. Use-case → component traceability matrix (seed)

| UC | Delivered by |
|---|---|
| I01–I04, I05–I07 | `internal/runtime/isolate/{create,lifecycle,guest_http}.go`, `internal/service/isolate.go`, `pkg/jsbundle` |
| I08–I10 | lifecycle idle-stop + `internal/service/isolate.go` (scale-to-zero) |
| I11 | `internal/service/isolate.go` reusing `request_idempotency` + content-addressed `pkg/jsbundle` |
| I12 | `internal/pool/isolate/` |
| I13, I14 | `internal/runtime/isolate/network.go` + host-side proxy (byte accounting) |
| I15 | `internal/runtime/wasm/statekv` (reuse) |
| I16 | `internal/service/service.go` dispatch (5 drivers coexist) |
| I17 | `pkg/isolate/host.go` isolate-group + jail; the P0 gate test |
| I18 | `pkg/caddy` (reuse) + `internal/runtime/isolate/{network,guest_http}.go` |
| I19 | 5 SDKs `runtime:"isolate"` + `docs/.../isolate-sandbox.mdx` |
| I20 | Daytona/E2B facade translation carrying `runtime:"isolate"` |

Expand to ≥40 during `/plan-eng-review`.

---

## 13. Open questions for review

1. **Engine default** — `workerd` (Workers semantics, C++ binary) vs a Deno
   `deno_core`-based host (Deno semantics) vs `v8go` (plain Go, most work)?
   Plan assumes `workerd` default + a `pkg/isolate` engine seam.
2. **Isolate-group granularity default** — one process per tenant, per
   trust-tier, or per sandbox? Plan makes it configurable; default TBD (lean
   per-tenant for density, per-sandbox for the paranoid tier).
3. **Bundle build location** — build (esbuild) on the host at create time, or
   require a pre-built bundle pushed to OCI? Plan seeds both (`build.go` +
   `oras_*`); pick the hot-path default.
4. **`exec` semantics** — is "invoke the fetch handler" enough, or do we expose
   a named-export invoke API too? Affects the toolbox/Daytona `/process`
   parity surface.
5. **Sessions** — map to a long-lived isolate, or declare N/A on this runtime?
6. **Snapshot value** — is a V8 heap snapshot worth Phase 4 effort given the
   warm pool already delivers ~5ms, or defer indefinitely?
7. **Durability scope** — reuse the WASM `Durability` field verbatim, or does
   the isolate + `statekv` (Durable-Objects) model want its own class names?
8. **Capability surface** — which grants do we expose in
   `CreateSandboxRequest` (fetch allowlist, env, KV, timers) and how do they
   map onto `workerd`'s capnp bindings?
9. **Billing** — per-invocation vs per-wall-second vs per-CPU-ms for this tier;
   what does the expvar/OTEL export record?
10. **Do we advertise it as `isolate`, `v8`, or `js`** in the public runtime
    enum? Plan uses `isolate` (engine-neutral); confirm before SDK lockstep.
