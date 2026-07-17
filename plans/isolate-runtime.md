# V8-Isolate Sandboxes (Deno/Workers model) — Design & Implementation Plan

Status: **Proposed — reviewed & amended** · Owner: TBD · Created: 2026-07-10 · Amended: 2026-07-17

This plan adds a **fifth runtime** to AerolVM — **V8 isolates** (the
Deno-Deploy / Cloudflare-Workers model) — as a peer to `docker`, `gvisor`,
`firecracker`, and `wasm`. The design principle is the one every prior runtime
followed: **reuse the existing ecosystem as much as possible.** The WASM
runtime is the near-exact template — it is already an out-of-process,
host-mediated, warm-pooled, `Runtime`-only (not `ContainerRuntime`) driver.
An isolate runtime is *the WASM runtime with a different engine*: the worker is
a V8/`workerd` host instead of a wazero host, and the "module" is a JS/TS
bundle instead of a `.wasm`.

The isolate runtime is the **Workers-model tier**: push a JS/TS bundle, get a
`fetch` handler with capability-scoped grants — no image build, no external
registry, near-zero per-sandbox footprint, thousands of sandboxes per host.
Create latency (~5ms warm target) is a supporting stat, not the headline: the
resident-WASM host already creates at a flat ~21ms, so what this tier uniquely
adds is the **deployment model and density economics**, not raw speed. It is
the complement to the Firecracker tier (arbitrary binaries, real VM isolation)
— the same two-tier split Deno arrived at when it paired Workers (isolates)
with Deno Sandbox (microVMs).

---

## 0. Review history

- **2026-07-17 — `/office-hours` + `/plan-eng-review` (this amendment).**
  Approved design doc:
  `~/.gstack/projects/aerol-ai-microvm/sumansaurabh-plans-isolate-runtime-design-20260717-111513.md`
  (survived 3 adversarial review rounds, 9/10). Key decisions folded into this
  file: Approach B (full plan) chosen over a minimal per-tenant-only variant;
  security posture re-scoped (§2.1) after upstream's own guidance; demand
  checkpoint added (§10.1); workerd distribution pulled into Phase 1; tenant
  identity schema defined; bundle-injection feasibility spike added; P0 gate
  reworded and moved to end of Phase 3; per-tenant group single-flight
  mandated. Capture demand-pitch verbatim reactions in this section as they
  arrive.

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

2. **Dispatch is a single helper-per-runtime switch.** `Service.runtimeForSandbox`
   (`internal/service/service.go:555`) checks `isFirecrackerSandbox` /
   `isWasmSandbox` and falls through to `ociEngineForSandbox`; the isolate
   branch adds an `isIsolateSandbox` helper in the same shape. `runtimeRef`
   (line 573) returns `sandbox.ID` for host-mediated runtimes
   (Firecracker/WASM) instead of a container ref. Adding a driver = one field,
   one setter, one branch.

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
| **`workerd`** ✅ default | Real Workers semantics, isolate-groups, `fetch` handler, capnp config | Ship a C++ binary; opinionated API; capnp config generation; **hostile-code safety requires OUR outer boundary (§2.1), not workerd's** |
| `v8go` (CGo) behind a build tag | Full control, plain-Go host | Reimplement isolate lifecycle, resource limits, **and security hardening** — a project on its own. **Deferred until after the demand checkpoint (§10.1)** |
| Node/Deno `worker_threads` pool | Easiest to stand up | No capability model; weakest cross-tenant boundary — rejected (would also invalidate the Workers-specific capability API surface) |

Decision: **`workerd` as the default engine**, behind a `pkg/isolate` engine
seam. The seam exists primarily for **test fakes and version pinning**
(mirroring `pkg/wasm`), NOT as a promise that arbitrary engines swap in — the
capability surface is Workers-model-specific, so only a Workers-semantics
backend could ever slot in.

**Security reality check (upstream's own words):** open-source `workerd` does
*not* include Cloudflare production's defense-in-depth for possibly-malicious
code — their V8 memory-protection-key patches, trust-level "cordons," and
kernel-level mitigations are not in the binary, and upstream tells self-hosters
to wrap hostile code in "an appropriate secure sandbox, such as a virtual
machine." Spectre between co-resident tenants cannot be proven absent by any
CI test. §2.1 is written from that premise.

### 2.1 The isolate-group model & blast radius (load-bearing decision)

**This is the decision the whole plan rests on.** Unlike a microVM, isolates
share an OS process, so a V8 escape (JIT bug) or an unbounded-memory isolate is
a *cross-tenant* event within its host process. WASM sidesteps this by running
**one worker subprocess per sandbox** (strong, low density). Isolates would
throw away their density advantage if we did the same.

The chosen posture (amended per review):

- **The OS-process boundary is the REQUIRED cross-tenant boundary** — not
  defense-in-depth garnish. Isolate-groups buy density *within* a trust
  boundary only. **Default group granularity = one `workerd` process per
  tenant.** Hostile-code tiers use per-sandbox processes (a granularity value
  of the same group key, not a separate mechanism). Docs state plainly that
  this tier is weaker than the VM tier.
- **Tenant identity (the group key).** The platform has no `TenantID` today.
  Phase 1 adds: optional `TenantID string` on `CreateSandboxRequest` + a
  nullable `tenant_id` store column (`/add-store-column` discipline). When
  unset, the group key falls back to the authenticated API identity, so
  single-tenant self-hosters get one group with zero config.
  **Security-critical (outside-voice catch): `TenantID` is server-authorized,
  never a free-form client value.** A caller who can choose an arbitrary group
  key can force co-residency inside another tenant's process or evade
  isolation policy. The value must match or be authorized by the
  authenticated identity (or come from the controlplane); unauthorized values
  are rejected at create. Regression test required. Final identity source is
  a Phase-1 decision (§13 Q1) — the authorization rule is not open.
- **Group acquisition is single-flight per tenant key.** A group-router step
  runs BEFORE any warm-pool claim: first create for a tenant builds the group;
  concurrent duplicate first-creates wait and join it (same latch discipline
  as `EnsureLayer4Ready`, `internal/service/service.go:190-367`). Without
  this, two concurrent first-creates each claim a warm host and the tenant
  ends up with two group processes — silently breaking the one-process-per-
  tenant invariant the security posture is stated in terms of. **Regression
  test required (§11).**
- **Jail the `workerd` process — as a first-class Phase-1 deliverable.**
  Reuses the Firecracker jailer's chroot + cgroups + drop-priv pattern; the
  new work is a seccomp allowlist for a JIT-heavy V8 process (W^X pages,
  memfd, thread spawn) — a known subproject, budgeted as such. The jail spike
  also evaluates **V8 `--jitless`** for the per-sandbox paranoid tier (a much
  smaller syscall surface at a large throughput cost — if the JIT allowlist
  gets broad enough to be weak, jitless is the honest alternative).
  **Resource caps are group-level** (the jail's cgroups bound the tenant's
  process), plus a per-isolate V8 heap limit where workerd config exposes
  one; OSS workerd does not provide per-isolate CPU enforcement, so the
  enforced blast radius is the tenant's group — one hot-looping sandbox can
  degrade its tenant's siblings, and the docs say so. The §2.2 spike also
  evaluates workerd's per-request CPU-time limit config as a mitigation.
- **Group lifecycle & teardown semantics.** Resident group processes carry an
  idle TTL (mirroring the WASM resident-host reaper); destroying the last
  member sandbox tears the group process down (Phase 2). On hostile teardown,
  healthy co-resident sandboxes of that tenant die with the process: in-flight
  requests get 503 + Retry-After; the driver recreates the group and
  rehydrates members by durability class (§4).

**P0 release gate (re-scoped, §11):** a hostile-isolate test — OOM, tight CPU
loop, attempted access outside granted capabilities — must not (a) exceed
group-level resource caps, (b) touch undeclared capabilities, (c) take down
`sandboxd`; and (d) the offending group is torn down and members rehydrated
per the teardown semantics. **The gate makes NO cross-tenant memory-safety
claim — Spectre is untestable; the process boundary is the answer.** The gate
is *specified* in Phase 1 and *executes* at the end of Phase 3, when create,
capability enforcement, and the egress proxy all exist to be attacked.

### 2.2 Bundle injection — Phase-1 feasibility spike

The warm-create story assumes a bundle can be loaded into a *running* workerd
without bouncing co-resident isolates. Stock workerd loads workers from capnp
config at process start; the dynamic worker-loading API is beta. **Phase 1
includes a spike with measured exit criteria:** inject a new worker into a
running workerd in ≤10ms p50 without disrupting in-flight requests of other
workers, AND injected workers must support per-sandbox inbound attribution and
per-sandbox `globalOutbound` — a winning injection path that breaks either
routing property fails the spike. Recorded fallbacks: (a) per-sandbox process
from a warm pool of blank processes (density cost, correctness kept) or
(b) config regeneration + graceful drain (latency cost). The ≤10ms warm-create
target is **provisional on this spike**.

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
- **Rehydration restores code + durable KV, never in-flight state.** Timers,
  open requests, and loaded module globals do not survive a group teardown or
  daemon restart; `ephemeral` sandboxes come back blank. Stated plainly in
  docs — per-request handlers are the honest fit for this tier.
- **Semantics are Cloudflare-Workers semantics, not Deno.** Docs and SDK
  copy say "Workers model"; users hitting Node-polyfill/timers/crypto/module
  differences get a compatibility page, not a surprise.

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
- **per-sandbox egress attribution (Phase-3 deliverable):** capability
  manifests are per-sandbox but the proxy is shared per group, so each
  worker's `globalOutbound` is bound to a **per-sandbox UDS endpoint** on the
  host proxy — ownership known at accept time; the proxy applies that
  sandbox's allowlist/CIDR/byte-count. This is the exact connection-ownership
  problem that delayed the WASM resident-host flag; it lands with a regression
  test, not mid-implementation. Byte counters are per-connection atomics — no
  shared mutex on the data path (the netrules-Manager head-of-line lesson,
  PR #306). Non-network grants (env, KV, timers) are config-time workerd
  bindings, not proxy-enforced;
- inbound HTTP is proxied by the driver to the isolate's `fetch` handler via
  driver-attributed routing — per-worker sockets where the injection path
  supports them, or a trusted dispatcher entrypoint otherwise; never client
  host-header parsing;
- Caddy L7 routing to the host-mediated listener is reused wholesale (the WASM
  path already does this — see `wasm-networking-finish.md`). Creates default
  to `allow_public_traffic=false`; `expose_port` opts in and returns the
  existing URL on retry (host-mediated; the TCP host-port pool is never
  walked).

**Warm pool (`internal/pool/isolate/`).** Copy the pattern of
`internal/pool/wasm/` (`pool.go`/`refill.go`/`spawner.go`/`metrics.go`):
pre-spawn blank `workerd` hosts so a first-create for a tenant claims one and
injects the bundle. The **group router runs before the pool** (§2.1): only a
tenant's FIRST create claims from the pool; subsequent creates route to the
tenant's existing group process. Same expvar hit/miss/orphan metrics and
ticker refill as the `vmm` and `wasm` pools, **plus an initial fill at daemon
boot** — the wasm prewarm lesson (PR #337: boot-time prewarm is what killed
the p99 tail; ticker-only refill leaves the first creates cold). Basic
per-tenant warm pool lands in Phase 3; density packing is Phase 4
(post-checkpoint). **Group-router lookups are in-memory** (driver-owned
registry, `byID`-map pattern): SQLite is single-writer, so the hot create
path never queries the store for group membership — the store is source of
truth only at restart/reconcile.

**Snapshots — deferred, expectation corrected.** The in-session hope of
mmap-rehydrating a running isolate's heap is **unverified and likely
unsupported**: V8 startup snapshots are embedder-build-time artifacts, not
running-isolate serialization; neither V8 nor OSS workerd exposes "serialize
this isolate's heap and mmap it back." The warm pool is the plan of record;
any snapshot phase requires an upstream feasibility spike first (§13 Q6).
`CreateSnapshot` maps accordingly or returns not-supported until then.

**Durability — already built (`statekv`).** Cloudflare pairs Workers (isolates)
with Durable Objects (state). AerolVM already has the analog: the WASM
runtime's `statekv` durable per-sandbox KV. Reuse it. **Durability set for
`runtime:"isolate"`:** default `ephemeral` (recreated blank from
content-addressed bundles); `passivatable` rejected at create (the bundle is
the image — nothing to passivate); `durable` (statekv reattach) enabled in
Phase 5, which owns the `NormalizeCreateDurability` change
(`pkg/models/types.go:232` — it rejects `durable` for every runtime today;
that enablement work is named Phase-5 scope). Isolate + `statekv` = Workers +
Durable Objects.

**Resource limits.** CPU-time / wall-clock / memory caps are enforced at the
**group level** via the jail's cgroups (§2.1), plus per-isolate V8 heap limits
where workerd config exposes them; map `CreateSandboxRequest.CPU`/`MemoryMB`
onto those at create time and document the group-level granularity.

---

## 5. What this tier uniquely enables (model first, speed second)

- **Deploy a file, not an image** — push a JS/TS bundle; no Dockerfile, no
  image build, no external registry on the hot path. This is the capability
  none of the four existing runtimes offer, and the tier's headline.
- **Capability-scoped untrusted-ish JS** — plugins, third-party scripts,
  AI-generated snippets run with only the fetch/env/KV caps you grant.
- **Cheapest possible multi-tenancy** — density economics (thousands of
  isolates/host within trust boundaries) enable free-tier / per-invocation
  billing a container tier can't match.
- **A genuine two-tier product** — isolates for high-volume JS; Firecracker
  for arbitrary untrusted binaries. Same complementary pair Deno ships.
- **~5ms warm create, supporting stat** — nice, but the resident-WASM host
  already does ~21ms; latency alone would not justify this tier.

---

## 6. Use cases (seed; expand from demand-pitch evidence)

Grouped; each traces to a component in §12. Expansion to ≥40 happens as the
§10.1 demand conversations name real workloads — real UCs beat brainstormed
ones.

- **Per-request compute:** UC-I01 webhook transform, UC-I02 API gateway
  middleware, UC-I03 edge A/B logic, UC-I04 image-URL signer.
- **AI/agent tools:** UC-I05 run AI-generated JS tool, UC-I06 sandboxed
  eval for a chat tool-call, UC-I07 per-user plugin execution.
- **Multi-tenant SaaS:** UC-I08 customer-authored hooks, UC-I09 form-logic
  scripts, UC-I10 scheduled JS jobs (idle-to-zero).
- **Platform:** UC-I11 idempotent create under retry, UC-I12 warm-pool hit,
  UC-I13 egress allowlist enforced at proxy (per-sandbox attribution),
  UC-I14 byte-quota enforcement, UC-I15 durable KV state across resume,
  UC-I16 mixed-runtime host (5 drivers coexist), UC-I17 hostile-isolate
  containment (P0 gate), UC-I18 custom domain to a fetch handler (Phase 5),
  UC-I19 5-SDK `runtime:"isolate"` parity, UC-I20 Daytona facade passthrough,
  UC-I21 concurrent first-create single-flight, UC-I22 group idle-TTL reap,
  UC-I23 bundle push via /v1/js-bundles.

---

## 7. Packages to CREATE

```
internal/runtime/isolate/        # the Driver (mirror internal/runtime/wasm/)
  driver.go        # Driver struct + Runtime methods + dispatch registry
  create.go        # createIsolateSandbox: resolve bundle → group router → load
  grouprouter.go   # per-tenant group lookup + single-flight acquisition (§2.1)
  lifecycle.go     # Start/Stop/Destroy/Resize/Inspect/ListManaged/Ping
                   # + group idle-TTL reaper + last-member teardown
  network.go       # networkGateway wiring (host-mediated, per-sandbox
                   # egress attribution via per-sandbox UDS endpoints)
  guest_http.go    # inbound HTTP → fetch handler proxy (driver-attributed)
  ports.go         # expose-port parity (host-mediated, pool NOT walked)
  warmacquire.go   # claim a warm workerd host + inject bundle (behind router)
  exec.go          # "exec" = invoke handler / 501 for unsupported verbs
  jail.go          # workerd jail: chroot+cgroups+drop-priv+seccomp (Phase 1)
  seams.go         # BundleResolver, HostSupervisor, HostClient(+Factory), WarmPool
  config.go        # Config + SB_ENABLE_ISOLATE + group-granularity knob

internal/pool/poolcore/          # NEW: shared warm-pool core (rule of three:
  pool.go refill.go metrics.go   # vmm + wasm + isolate). Generic ticker-refill,
                                 # hit/miss/orphan expvar metrics, claim/return
                                 # bookkeeping. Each runtime keeps its own thin
                                 # spawner. internal/pool/vmm and
                                 # internal/pool/wasm migrate onto it in
                                 # separate follow-up PRs AFTER the isolate
                                 # tier stabilizes (Phase 4+, cross-model
                                 # blast-radius call) — protected by their
                                 # existing test suites + parity tests.

internal/pool/isolate/           # isolate spawner on poolcore
  spawner.go errors.go

pkg/isolate/                     # engine wrapper (analog to pkg/wasm/)
  host.go          # manage workerd process + capnp config generation
  engine.go        # engine seam: workerd default (test fakes + version pin)
  inject.go        # dynamic worker loading (outcome of the §2.2 spike)
  worker/          # IPC client/server + protocol (mirror pkg/wasm/worker)

pkg/jsbundle/                    # bundle resolver (analog to pkg/wasmmod/)
  resolve.go       # ref (path/file:// /uploaded name/digest) → local bundle
  store.go         # content-addressed bundle store behind /v1/js-bundles
  build.go         # esbuild entrypoint → single bundle (hot-path default: §13 Q2)
  oras_push.go oras_pull.go   # optional: bundles in the same OCI registry
```

Every new package ships with `_test.go` next to it at the ~85% bar (§11).

---

## 8. Files to CREATE outside new packages

- `internal/service/isolate.go` — `createIsolateSandbox` (version-agnostic
  service helper; mirrors `internal/service/wasm.go`), reusing
  `request_idempotency` + `CreateSandboxWithID`.
- `pkg/api/v1/` routes — **`POST /v1/js-bundles`** (+ list/delete), mirroring
  the existing `/v1/wasm-modules` push/catalogue routes
  (`pkg/api/v1/routes.go:127-131`). This is what makes "no image, no external
  registry" true for remote tenants; `path`/`file://` refs remain for
  operators, OCI refs optional. **Marked experimental until the §10.1
  checkpoint passes** (documented as subject to change; no SDK helper beyond
  raw HTTP until then). Ships with abuse controls from day one: bundle size
  cap, per-tenant bundle quota, build timeout (if host-build lands per §13
  Q2), and content-addressed GC/eviction for unreferenced bundles.
- `docs/src/content/docs/isolate-sandbox.mdx` — feature page, five-tab SDK
  examples, registered in `content.config.ts` (see `/add-docs-page`).
- `docs/src/content/docs/isolate-architecture.mdx` — architecture deep-dive
  (optional; the "Engine, Chassis, Runtime" engineering page already frames the
  isolate tier).

---

## 9. Files to MODIFY

- **`pkg/models/types.go`** — add `RuntimeIsolate = "isolate"` next to
  `RuntimeWasm` (:95); add to `ValidRuntime` (accept ahead of impl);
  `CreateSandbox` rejects with `ErrRuntimeNotImplemented` (:109) until
  `SB_ENABLE_ISOLATE` is set AND the driver has landed (same pattern as the
  reserved `kata` runtime). Add optional `TenantID` to `CreateSandboxRequest`
  (server-authorized, §2.1); the bundle ref **reuses the existing `module_ref`
  field (:634)** — zero further DTO ripple pre-checkpoint. If demand
  validates, Phase 5's SDK lockstep may add a typed `bundle_ref` alias for
  clarity (outside-voice point, deferred deliberately). Each sandbox pins a
  workerd **`compatibility_date`** (the Workers versioning mechanism) so
  engine upgrades don't change bundle behavior silently. Verify the `runtime`
  column has no CHECK/enum constraint so no store migration is needed for the
  new value.
- **`internal/store/store.go`** — nullable `tenant_id` column
  (`/add-store-column` discipline).
- **`internal/service/service.go`** — add `isolate runtime.Runtime` field +
  `SetIsolateRuntime`; add the `isIsolateSandbox` branch in `runtimeForSandbox`
  (line 555) and `runtimeRef` (line 573, returns `sandbox.ID`). Any change
  here is a **boot-path touch** — call out latency in the PR
  (`/touch-create-sandbox`).
- **`internal/config/`** — add `EnableIsolate` (`SB_ENABLE_ISOLATE`), the
  isolate-group granularity knob (default: per-tenant), jail knobs, and
  `SB_ISOLATE_WORKERD_PATH`.
- **`pkg/daemon/daemon.go`** — when `cfg.EnableIsolate`: construct the driver +
  warm pool, `svc.SetIsolateRuntime(...)`, and
  `appendRuntimeIfMissing(runtimes, models.RuntimeIsolate)` (line 1492).
- **`pkg/capacity/`** — single-node density-bound footprint lands in
  **Phase 4** with the density bench (the Admitter budgets CPU/mem per create
  today and would wall the bench); cluster capacity-gossip side in Phase 5.
- **`internal/service/platform_volumes.go`** — isolates don't take platform
  volumes (host-mediated); add `RuntimeIsolate` to the reject set beside
  `RuntimeFirecracker`/`RuntimeWasm` (line 45).
- **`scripts/install.sh` + Ansible role + Terraform user-data** — **workerd
  binary distribution (Phase 1):** version-pinned, checksummed download, same
  recipe as the runsc shim; upgrades documented in setup/runbooks.
- **The 5 SDKs** — `runtime:"isolate"` enum + optional `tenant_id` in lockstep
  (`/add-sdk-method` discipline); **nothing else pre-checkpoint** (the bundle
  ref reuses `module_ref`).

---

## 10. Phasing (amended)

- **Phase 1 — Skeleton + dispatch + feasibility gates.** Land
  `RuntimeIsolate`, `ValidRuntime`, `SB_ENABLE_ISOLATE`, `tenant_id` schema,
  an `internal/runtime/isolate.Driver` whose methods return
  `ErrRuntimeNotImplemented`, service dispatch, daemon wiring, **workerd
  binary distribution**, **jail spec + regression test**, **the §2.2 injection
  spike**, and the **P0 gate specification**. Proves the 5th `Runtime` holds
  and the two feasibility risks are retired before feature work.
- **Phase 2 — Cold path + demand pitch.** `/v1/js-bundles` catalogue;
  `pkg/jsbundle` resolve+build; `Create/Start/Stop/Destroy/Inspect/Ping/
  ListManaged` against one isolate (group router + single-flight); capability
  config (grants map onto existing request fields — `Env`,
  `NetworkAllowOut`/`NetworkDenyOut`, `NetworkBlockAll`; net-new grant fields
  wait for the checkpoint); durability default; group idle-TTL + last-member
  lifecycle; service helper `internal/service/isolate.go`. **The §10.1 demand
  pitch runs during this phase.**
- **Phase 3 — Inbound HTTP + toolbox + P0 gate execution.** `guest_http.go`
  fetch proxy with driver-attributed routing; per-sandbox egress attribution;
  `exec` = invoke-handler; Caddy L7 route (expose_port opt-in, pool NOT
  walked); basic per-tenant warm pool; **P0 gate executes**; capability-denied
  egress test.
- **Phase 4 — Density (GATED on §10.1 checkpoint results).** Isolate-group
  packing beyond per-tenant granularity where trust allows; CPU/mem limit
  mapping; single-node admission footprint + density bench; per-invocation
  billing export; snapshot spike only if warm-pool numbers justify it.
- **Phase 5 — Durability + cluster + facades + docs + SDKs.** `durable`
  enablement (statekv reattach + `NormalizeCreateDurability`); cluster
  placement with tenant-affinity / forwarding / failover parity (no-op when
  `EnableCluster` false; group failover rehydrates from bundles + statekv);
  facade parity where facades exist (Daytona today; E2B is a separate planned
  program this depends on); custom domains; docs page(s); 5-SDK constants.

Each phase is independently mergeable because the `Runtime` surface stays
stable — the property every prior skeleton was landed to prove.

### 10.1 Demand checkpoint (gates Phase 4)

During Phase 2, pitch to 5–10 credible prospects (agent-infra teams,
E2B/Daytona-adjacent users, existing AerolVM operators): **"Push a JS handler
with scoped capabilities to your own infra — no image, no external registry,
invoke it over HTTP in milliseconds."** Capture verbatim reactions in §0.
**≥3 "we would use this now" reactions with a named workload** → Phase 4
proceeds; weaker → hold at per-tenant granularity (Phases 1–3 scope) and
re-scope Phases 4–5. For each positive reaction, capture (outside-voice bar):
the named workload, expected invocation volume, required APIs/grants, their
threat model (whose code runs), and explicit acceptance of no-shell /
no-filesystem semantics — "sounds cool" without those five does not count.

---

## 11. Non-negotiables checklist (pr-review.md alignment)

- **Hostile-isolate containment (P0 RELEASE GATE, §2.1 — re-scoped).** A test
  MUST run a hostile isolate (OOM / CPU spin / out-of-cap access) and assert:
  (a) group-level resource caps hold, (b) undeclared capabilities are
  untouchable, (c) `sandboxd` survives, (d) the offending group is torn down
  and members rehydrated per §2.1 teardown semantics. **No cross-tenant
  memory-safety claim** (Spectre is untestable; the per-tenant process
  boundary is the answer). Specified in Phase 1, executes end of Phase 3.
  **Placement: tag-gated CI job** (`go test -tags=integration`, pinned workerd
  binary fetched in the job) — the `wasm-integration`/`test-acme-e2e`
  precedent; `make test` stays offline. PR description must confirm it exists
  and passes.
- **Idempotency.** `createIsolateSandbox` reuses `request_idempotency` +
  `CreateSandboxWithID`; bundle resolution is content-addressed so a retry
  resolves to the same digest and returns the existing sandbox. **Concurrent
  first-creates for one tenant are single-flighted by the group router —
  regression test required.** `expose_port` is host-mediated — returns the
  existing URL, **does not walk the host-port pool**.
- **Boot-path latency.** Bundle resolve+inject is on the cold create path; the
  warm pool (Phase 3) plus resident group processes remove it for the common
  case. First-call cost per tenant (group spawn) is called out explicitly,
  mirroring the Firecracker/WASM notes.
- **Lazy bootstrap.** Engine warmup + bundle cache use the `atomic.Bool` latch
  + `sync.Mutex` single-flight pattern (canonical: `EnsureLayer4Ready`).
- **Failure-path consistency.** `createIsolateSandbox` unwinds via
  `Driver.Destroy` + store-row delete on every post-create error (committed-
  flag LIFO, the Firecracker Create pattern); the bundle cache is
  content-addressed (no cleanup needed); no caddy route exists until
  `expose_port`, and a failed expose deletes the route it created.
  **Empty-group rule:** if THIS create spawned the tenant's group process and
  the unwind leaves it with zero members, tear the process down synchronously
  — never leave it to the idle-TTL reaper. A concurrent create that was
  single-flight-waiting on that group handles "group vanished" by retrying
  the spawn (one branch in the group router). Regression test: fail injection
  on a first create → assert no workerd process remains. No reliance on
  reconcile for routine cleanup.
- **Host-mediated only.** Implements `Runtime`, **not** `ContainerRuntime`;
  `AsContainerRuntime` returns false. No TAP/veth, no per-IP iptables.
- **Restart correctness.** Isolate hosts do not survive a daemon restart;
  reconcile is redefined per durability class (§4: `ephemeral` recreated from
  bundles, `durable` reattaches statekv — Phase 5, `passivatable` rejected).
  Regression test: a restart with live `ephemeral`/`durable` rows lands each
  in the right terminal/rehydrated state; flipping `EnableIsolate=false`
  between restarts preserves durable rows.
- **Per-sandbox egress attribution.** Shared group proxy must know which
  isolate originated each connection (per-sandbox UDS endpoints, §4);
  regression test required — this is the WASM resident-host lesson applied
  ahead of time.
- **Coverage.** Every new package (`pkg/isolate`, `pkg/jsbundle`,
  `internal/runtime/isolate`, `internal/pool/isolate`) ships table-driven tests
  at ~85% (`/maintain-coverage` before the PR). Named regression tests: group
  single-flight race, injection path, egress attribution, idle-TTL reaper,
  empty-group teardown on failed first-create, restart per durability class,
  jail profile, poolcore migration parity (vmm/wasm behavior unchanged).
  **Full test map (every planned branch ships with its test — from the
  2026-07-17 review's coverage trace):**
  - `pkg/api/v1/handlers_test.go` additions: js-bundles push/list/delete;
    duplicate push returns the same digest.
  - `pkg/jsbundle/resolve_test.go`: table-driven ref forms (path / file:// /
    uploaded name / digest / OCI), invalid-artifact rejection, digest
    stability under retry.
  - `internal/runtime/isolate/create_test.go`: join-existing-group; resolve
    failure spawns NO group; tenant_id-unset falls back to auth-identity key;
    group-vanished waiter retries spawn.
  - `internal/service/isolate_test.go`: duplicate deploy via
    `request_idempotency` returns the existing sandbox (mirror
    `internal/service/wasm.go` tests).
  - `internal/runtime/isolate/lifecycle_test.go`: destroy-last-member tears
    the group down; teardown returns 503 + Retry-After to in-flight requests.
  - `internal/runtime/isolate/network_test.go`: byte-count accuracy under
    concurrent connections (per-conn atomics); inbound request routes to the
    correct worker (never host-header trust).
  - `internal/runtime/isolate/ports_test.go`: expose_port retry returns the
    existing URL, host-port pool never walked (pr-review §1).
  - `internal/runtime/isolate/exec_test.go`: invoke-handler happy path; 501
    for unsupported toolboxd verbs (mirror the wasm interpreter routes).
  - `pkg/models/runtime_test.go` additions: `ValidRuntime("isolate")`;
    create rejects `ErrRuntimeNotImplemented` when `SB_ENABLE_ISOLATE` unset
    (kata-pattern).
  - `internal/store/store_test.go` additions: `tenant_id` column CRUD +
    null-tenant back-compat.
  - Per-SDK (×5): `runtime:"isolate"` + optional `tenant_id` round-trip.
  - `integration-tests/suite/`: deploy→invoke end-to-end UC (new scenario,
    `integration` build tag).
- **Observability (Phase 2–3, not polish).** Per-sandbox console/log capture,
  uncaught-exception reporting, kill reasons (cap exceeded / capability
  denied / hostile teardown), request traces with bundle-digest correlation,
  and per-group + per-sandbox expvar/OTEL metrics. Without these, supporting
  a no-shell runtime is guesswork (outside-voice point).
- **Warm-pool sizing.** The blank-host pool only serves FIRST creates per
  tenant — depth is sized to tenant-arrival rate, not create rate; expvar
  metrics make the distinction visible.
- **Cluster.** All `internal/cluster` changes are no-ops when `EnableCluster`
  is false; placement gains tenant-affinity constraints (Phase 5); regression
  tests next to the files changed.

---

## 12. Use-case → component traceability matrix (seed)

| UC | Delivered by |
|---|---|
| I01–I04, I05–I07 | `internal/runtime/isolate/{create,lifecycle,guest_http}.go`, `internal/service/isolate.go`, `pkg/jsbundle` |
| I08–I10 | lifecycle idle-stop + `internal/service/isolate.go` (scale-to-zero) |
| I11 | `internal/service/isolate.go` reusing `request_idempotency` + content-addressed `pkg/jsbundle` |
| I12 | `internal/pool/isolate/` |
| I13, I14 | `internal/runtime/isolate/network.go` per-sandbox UDS attribution + host proxy (atomic byte accounting) |
| I15 | `internal/runtime/wasm/statekv` (reuse; Phase 5) |
| I16 | `internal/service/service.go` dispatch (5 drivers coexist) |
| I17 | `internal/runtime/isolate/jail.go` + group teardown; the re-scoped P0 gate test |
| I18 | `pkg/caddy` (reuse) + `internal/runtime/isolate/{network,guest_http}.go` (Phase 5) |
| I19 | 5 SDKs `runtime:"isolate"` + `docs/.../isolate-sandbox.mdx` |
| I20 | Daytona facade translation carrying `runtime:"isolate"` |
| I21 | `internal/runtime/isolate/grouprouter.go` single-flight + regression test |
| I22 | `internal/runtime/isolate/lifecycle.go` idle-TTL reaper |
| I23 | `pkg/api/v1` js-bundles routes + `pkg/jsbundle/store.go` |

Expand alongside §6 as demand-pitch evidence names real workloads.

---

## 13. Open questions (tagged with the phase that must answer them)

Settled during the 2026-07-17 review: engine = workerd behind a test seam;
group default = per-tenant; security posture = §2.1; egress enforcement =
host-side proxy with per-sandbox connection ownership (capnp bindings as later
optimization); non-network grants = config-time bindings; public enum name =
**`isolate`** (engine-neutral; SDKs ship it verbatim); bundle wire field =
reuse `module_ref`; durability default = `ephemeral`.

1. **[Phase 1]** Tenant identity source — explicit `TenantID` field vs
   auth-derived vs controlplane-provided (schema shape fixed in §2.1).
2. **[Phase 2]** Bundle build pipeline — esbuild on host at create vs
   pre-built only (pick the hot-path default), and the scope that comes with
   it: npm resolution policy, ESM/CJS behavior, TypeScript, source maps,
   size limits, native-addon rejection, deterministic builds, Node-compat
   messaging. "Use esbuild" alone is not an answer (outside-voice point).
3. **[Phase 2]** Which capability grants surface in `CreateSandboxRequest` —
   pre-checkpoint constraint: map onto existing fields (`Env`,
   `NetworkAllowOut`/`NetworkDenyOut`, `NetworkBlockAll`); net-new grant
   fields (KV, timers) wait for the checkpoint.
4. **[Phase 3]** `exec` semantics — fetch-handler invoke only, or named-export
   invoke API too? Affects the toolbox/Daytona `/process` parity surface.
5. **[Phase 3]** Sessions — map to a long-lived isolate, or declare N/A on
   this runtime?
6. **[Phase 4]** Snapshot value — V8 heap snapshot vs warm pool; requires an
   upstream feasibility spike first (§4 — mmap-rehydration of a running
   isolate is likely unsupported).
7. **[Phase 5]** Durability class names — reuse the WASM `Durability` field
   verbatim, or isolate-specific class names (default/rejection set settled).
8. **[Phase 4]** Billing — per-invocation vs per-wall-second vs per-CPU-ms for
   this tier; what does the expvar/OTEL export record?

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR (PLAN) | 21 issues, 0 critical gaps — all folded into this file |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CROSS-MODEL:** Outside voice (Codex, 2026-07-17) raised 24 points; 14
  absorbed (sharpest: server-authorized `TenantID` to block forced
  co-residency; observability as Phase 2–3 scope; abuse controls on bundle
  push; stronger demand-checkpoint evidence bar; poolcore migration deferred
  to Phase 4+). 10 rejected as re-litigating settled decisions (Approach B,
  DTO freeze, Phase-5 cluster deferral) — recorded, not silently dropped.
- **VERDICT:** ENG CLEARED — ready to implement. Preceded by `/office-hours`
  (approved design doc, 3 adversarial rounds, 9/10):
  `~/.gstack/projects/aerol-ai-microvm/sumansaurabh-plans-isolate-runtime-design-20260717-111513.md`

NO UNRESOLVED DECISIONS
