# WASM-based Sandboxes — Design & Implementation Plan

Status: **Mostly implemented** (Phases 1–7 core landed including cluster migrate/drain, UC-39 durable recreate/failover + multi-node owner-watcher WASM soak, UC-43 worker NetMediator + engine NetworkHook (`aerol/vm/net` egress + wasip1 listener context) + IPC byte accounting + gateway merge, UC-44 RemoveImage/module GC + warm-pool eviction, AOCR tag prune, wasm OTEL spans, toolhost sessions/exec-stream/code-run + Daytona `/process/session*` parity, UC-42b wasmtime CGo engine behind `-tags wasmtime` + `SB_WASM_ENGINE`, interpreter routes matching toolboxd 501, **UC-31/32/33 HTTP networking** (driver lifecycle + host mediator preview URLs + WASM custom-domain dial routes — see [`wasm-networking-finish.md`](./wasm-networking-finish.md)), and **wazero listen/preopen fd fix** (`/work`+listen now run concurrently via the `AEROL_WASM_LISTEN_FD` contract), **wasmtime ingress rejected loudly** (`SupportsListen()==false`)) · **wazero pinned at v1.12.0** (latest stable 1.x; bump on routine dep updates) · **Still open (engine):** native WASI P2/component model (wazero 1.x — upstream defers), real wasmtime wasip1 listen impl · Owner: TBD · Created: 2026-06-07

This plan adds a **fourth runtime** to AerolVM — WebAssembly (WASM/WASI) — as a
peer to `docker`, `gvisor`, and `firecracker`. The design principle is the one
the task set: **reuse the existing ecosystem as much as possible**, mirroring how
Firecracker was introduced as the second `runtime.Runtime` implementation behind
the same service-layer contract.

---

## 0. Review history

This plan went through `/plan-eng-review` + an independent Codex outside-voice
review on **2026-06-07**. Nineteen decisions (D1–D19) were resolved and have
been inlined into §1–§13 below; this plan reads as a single consistent
document with no separate binding overlay.

The decisions, by section:

| Section | Decisions inlined |
|---|---|
| §1 (runtime abstraction) | D17 (interface split), D6 (4-driver dispatch diagram) |
| §2 (engine choice) + new §2.1 (worker model) | D1 (worker-subprocess pool, the load-bearing architectural choice), D11 (one module per worker), D15 (no-Docker-on-boot-path caveat), D6 (worker pool diagram) |
| §3 (toolbox) | unchanged |
| §4 (durability) — opening + §4.3 + §4.4 + §4.5 + §4.8 + new §4.8.1 + new §4.9 | D3 (versioned codec contract), D4 (live-migration phrasing fix), D5 (failure modes & invariants), D6 (lifecycle + AOCR diagrams), D12 (parallel local checkpoint + AOCR-gated-to-durable), the critical `awaiting_runtime` state |
| §5 (features) | D11 + D19 (density re-scope), D15 (Docker-dep fix), D1 reframe |
| §6 (use cases) | UC-10, UC-13 rescoped; UC-42 split into 42a/42b; UC-43 worker-side metering |
| §7 (packages) | D1 (`pkg/wasm/worker/`), D2 (`pkg/wasmmod/oras_push.go`+`oras_pull.go`), D8 (`snapshot_codec.go` rename), D9 (`pkg/clonegen` extraction) |
| §9 (files to modify) | D7 (unified `Durability` field + `awaiting_runtime` status), D14 (service-layer rewrites), D16 (parallel WASM netstats), D17 (interface split — also affects this section) |
| §10 (phasing) | D1 + D9 + D17 + D7 as Phase-1 prerequisites; D14 in Phase 2; D2 + D18 in Phase 6 |
| §11 (non-negotiables) | D10 (P0 release gate: worker-crash isolation test) |

**Single load-bearing test** before any phase can ship: §11's worker-crash
isolation test (D10). It is the test that verifies the architectural property
the entire WASM plan rests on (§2.1). Without it, the in-process panic risk
is unmitigated — an unrecovered host-function panic would take down `sandboxd`
and with it every docker, firecracker, and WASM sandbox on the host plus the
control plane.

---

## 1. How the runtime abstraction works today (the reuse surface)

Everything hangs off one interface and one dispatch point. The WASM runtime
slots into exactly the same seams:

| Concern | Where it lives today | What WASM reuses vs. replaces |
|---|---|---|
| Runtime contract | `internal/runtime/runtime.go` (`Runtime` interface) | **Reuse** — implement it verbatim |
| Runtime identifiers | `pkg/models/types.go` (`RuntimeDocker/Gvisor/Kata/Firecracker`, `ValidRuntime`, `ResolveOCIRuntime`) | **Extend** — add `RuntimeWasm` |
| Service dispatch | `internal/service/service.go` (`runtimeForSandbox`, `isFirecrackerSandbox`, `createFirecrackerSandbox`) | **Extend** — add `isWasmSandbox`, `createWasmSandbox`, register a 3rd driver |
| Per-host enablement | `internal/config/config.go` (`EnableFirecracker` + ~40 `SB_FIRECRACKER_*`) | **Extend** — `SB_ENABLE_WASM` + `SB_WASM_*` |
| Wiring / adapters | `pkg/daemon/daemon.go` (`if cfg.EnableFirecracker { … SetFirecrackerRuntime }`) | **Extend** — parallel `if cfg.EnableWasm { … SetWasmRuntime }` block |
| Low-level engine client | `pkg/firecracker/` (VMM REST client) | **Replace** — `pkg/wasm/` (engine wrapper) |
| Artifact build pipeline | `pkg/oci/` (OCI image → `rootfs.ext4`) | **Replace** — `pkg/wasmmod/` (OCI/registry → `.wasm` module/component) |
| Network slot allocator | `internal/network/tap/` (TAP/IP/CID pool) | **Drop** — WASM has no TAP; capability config instead |
| Warm pool | `internal/pool/vmm/` (paused snapshot-loaded VMMs) | **Adapt** — `internal/pool/wasm/` (compiled-module + pre-instantiated cache) |
| Driver + host seams | `internal/runtime/firecracker/` (`seams.go` injects `RootfsBuilder`, `TapHost`, `VsockDialer`, `VMMClient`, `WarmPool`, `RSSSampler`) | **Mirror** — `internal/runtime/wasm/` with its own seam set |
| Templates/snapshots | `internal/service/template*.go`, store table `firecracker_templates` | **Adapt** — module catalogue + pre-instantiation, store table `wasm_modules` |
| Public routing | `pkg/caddy` (L7 route to guest IP) | **Reuse** — route to an in-process host-mediated listener |
| In-sandbox agent | `cmd/toolboxd/` reached over vsock/TCP | **Replace model** — host-served toolbox (see §3) |
| SDK surface | 5 SDKs, `runtime` field already wire-level | **Reuse** — `runtime: "wasm"` needs no new transport |

**Honest scope of the reuse.** The core lifecycle methods (`Create / Start /
Stop / Destroy / Inspect / CreateSnapshot / Resize / ListManaged / Ping /
RemoveImage`) map cleanly onto a WASM engine and are genuinely reused. The
network-rule methods (`PushAllowedPorts`, `ClearNetworkRules`,
`ApplyNetworkBlockAll`, `ApplyNetworkBlockIngress`, `ClearNetworkBlockIngress`,
`ClearNetworkBlockEgress`) encode container-era assumptions (per-IP iptables
rules, in-container toolbox over TCP) and **do not map cleanly** onto a
host-mediated mediated-socket model. The `runtime.Runtime` interface must be
split into a core `Runtime` + a `ContainerRuntime` sub-interface that carries
the network-rule methods; docker + firecracker satisfy both, WASM satisfies
only the core. This is a Phase-1 prerequisite refactor that touches the docker
and firecracker drivers (see §9 + §10 Phase 1).

**4-driver dispatch (after Phase 1):**

```
                   POST /v1/sandboxes  {runtime: "docker"|"gvisor"|"firecracker"|"wasm"}
                                            │
                                            ▼
                            internal/service/service.go
                                  runtimeForSandbox(sb)
                                    │
                                    ▼
        ┌──────────────────────────────────────────────────────────┐
        │                runtime.Runtime  (core)                   │
        │   Create / Start / Stop / Destroy / Inspect /            │
        │   CreateSnapshot / Resize / ListManaged / Ping /         │
        │   RemoveImage                                            │
        └──────────────┬──────────────┬─────────────┬──────────────┘
                       │              │             │
        ┌──────────────┴───┐  ┌───────┴───────┐  ┌──┴──────────────────┐
        │ docker driver    │  │ firecracker   │  │ wasm driver         │
        │ pkg/docker       │  │ driver        │  │ internal/runtime/   │
        │                  │  │ internal/     │  │   wasm              │
        │ also: Container- │  │   runtime/    │  │                     │
        │   Runtime (net   │  │   firecracker │  │ core Runtime only   │
        │   rules, ports)  │  │               │  │ (no Container-      │
        │                  │  │ also: Cont.-  │  │  Runtime methods)   │
        │                  │  │   Runtime     │  │                     │
        │                  │  │               │  │ ─────────────────── │
        │                  │  │               │  │ talks to worker     │
        │                  │  │               │  │ pool over UDS       │
        │                  │  │               │  │ (see §2.1)          │
        └──────────────────┘  └───────────────┘  └──┬──────────────────┘
                                                    │
                                          worker pool: one wazero
                                          per worker, one module per worker
```

---

## 2. Engine choice: **wazero** (pure-Go), run inside a worker-subprocess pool

**Recommendation: [wazero](https://wazero.io) as the default engine, behind an
engine seam so `wasmtime`/`WasmEdge` can be slotted later — executed inside a
pool of `sandboxd`-spawned worker subprocesses, NOT in the daemon process.**
The worker model is non-negotiable; see §2.1.

Why wazero is the engine choice:

- **Pure Go, zero CGo on the daemon side.** wazero compiles into the worker
  binary directly; no skopeo / umoci / mkfs subprocess chain, no jailer, no
  TAP pool, no vsock dialer (the Firecracker host-wiring tax doesn't apply).
- **Runs anywhere sandboxd runs** — Linux, macOS, Windows, arm64/amd64. Unlike
  Firecracker (Linux + KVM only), WASM sandboxes work on a developer laptop and
  in CI. This removes the `SB_CONTAINER_RUNTIME=firecracker is not allowed as
  host default` class of restriction.
- **No root, no kernel features.** No KVM, no `/dev/kvm`, no `CAP_NET_ADMIN`.
- **Deterministic + interruption-metered.** wazero supports context-cancellation
  and epoch-style interruption for hard wall-clock timeouts. *Instruction-level
  fuel accounting* (precise CPU billing) requires the wasmtime engine seam — see
  §5 feature #6 and UC-42a/b.

Tradeoff to call out in the PR: wazero is an **interpreter + optimizing
compiler** (no full JIT to native like wasmtime's Cranelift in all cases).
Compute-bound numeric workloads run slower than native. For the AerolVM use
cases (agent tool calls, code interpreters, per-request functions, untrusted
plugins) this is the right tradeoff — startup latency and density dominate.
The engine seam (`pkg/wasm.Engine`) keeps `wasmtime-go` (CGo, Cranelift JIT) a
drop-in for compute-heavy operators who accept the CGo build.

**Version policy (2026-06-07):** Pin `github.com/tetratelabs/wazero` at the
latest stable **1.x** release (currently **v1.12.0** in `go.mod`). Bump on
routine dependency updates — not because wazero will gain native Preview 2 /
Component Model support (upstream explicitly defers that to other runtimes).

**Networking on wazero (shipped in `pkg/wasm/`):**

- **Egress:** custom `aerol/vm/net` host module (TCP connect/read/write) with
  `NetworkHook` policy + byte metering; wasmtime path implements the same hook.
- **Ingress (HTTP preview URL):** wasip1 `sock_*` listener on a pre-open fd
  (`WASIListenPort`); worker `ProxyHTTP` bridges to the guest. Guest must run an
  HTTP server on that fd (e.g. wazero's Go `wasi http` test guest).
- **P2-shaped compat:** Aerol host modules `wasi:sockets` / `wasi:http` map to
  `aerol/vm/net` for guests compiled against Preview 2 import names — **not**
  spec-faithful WASI P2 or the Component Model.
- **Driver lifecycle (shipped):** `internal/runtime/wasm` cold-instantiates with
  listen disabled (no blocking `_start` on create). `SyncGuestListenPorts`
  (called from `expose_port` via `touchAllowedPorts`) enables ephemeral wasip1
  listen (`0` in caps), resolves the host port, starts `_start` in the background,
  and waits for TCP accept. `guestHTTPProxy` dials via `ProxyHTTP(...,
  guestPort=0)` using the resolved port. Driver e2e:
  `TestDriverWasip1HTTPExposeEndToEnd` (create → expose → proxy).
- **Wazero fd ordering + `/work`+listen concurrently (shipped):** wazero assigns
  directory preopens before TCP listeners (`InitFSContext`), so with `/work`
  mounted the wasip1 listener lands at `FdPreopen + len(preopens)`, not fd 3.
  `engine_wazero.fsConfigForCaps` now mounts dir preopens *even while listening*,
  and `moduleConfig` injects `AEROL_WASM_LISTEN_FD` (= `ListenerFD(caps)`) so
  AerolVM-aware guests accept on the right fd; guests with no dir preopens still
  get fd 3 (bare-wasip1 convention). The host's `ResolvedListenPort` already
  scans fds dynamically. Test guest: `pkg/wasm/testdata/aerolhttp` (reads the env,
  serves `/work` files). E2e: `TestDriverWasip1HTTPServeWhileWorkPreopen`.
- **wasmtime ingress rejected loudly (shipped):** the wasmtime engine does not yet
  wire a wasip1 listener (`SupportsListen()==false`); enabling a listener on it now
  returns a clear `SB_WASM_ENGINE=wazero` error at the worker instead of silently
  failing to resolve a port. Test: `TestSetListenPortRejectedWhenEngineLacksListen`.
- **Still open:** `expose_port` API guest-port `0` as a routing key (service
  rejects `port <= 0` today — exposed port numbers are Caddy routing keys only;
  guest bind is always ephemeral via wasip1); a real wasmtime wasip1 listen
  implementation; native P2/components on wazero (upstream defers — use wasmtime).

**What is NOT possible / changes vs. firecracker** (honest limits, per the ask):

1. **Arbitrary unmodified Linux binaries don't run.** A WASM sandbox runs a
   `.wasm` module/component, not an OCI image's ELF userland. `image:
   "python:3.11"` is meaningless to wazero. We support: (a) WASI modules
   compiled from Rust/Go/C/Zig, (b) language runtimes shipped as WASM
   (Python via [CPython-on-WASI], JS via [Javy]/SpiderMonkey, Ruby via
   `ruby.wasm`), and (c) OCI-*wrapped* wasm artifacts (`wasm-to-oci`/ORAS).
   This is documented as the runtime's contract, not a bug.
2. **No separate in-guest agent process.** WASI Preview 1 has no threads, no
   `fork`, no second process. `cmd/toolboxd` cannot run "next to" the
   workload. We move the toolbox file/exec/session semantics to the **host**
   (see §3) — the host runtime driver owns the WASI virtual FS and the module
   lifecycle, so it can serve `/v1/.../files`, `/exec`, `/sessions` directly.
3. **Full POSIX networking is limited.** Inbound HTTP works via **wasip1**
   `sock_*` on a pre-open listener fd (`WASIListenPort` + worker `ProxyHTTP`);
   outbound TCP via **`aerol/vm/net`** (not kernel sockets inside the guest).
   Guests that import **`wasi:http` / `wasi:sockets`** (Preview 2 names) are
   served by **Aerol compat host modules** (`wazero_wasi_compat.go`) — not
   native wazero P2. wazero 1.x will not ship Component Model support; use
   wasmtime (`-tags wasmtime`) if true P2/components are required later. Raw
   netfilter byte-quotas become host-counted byte meters on the mediated socket,
   not iptables rules.
4. **GPU passthrough: not supported** initially (same as Firecracker Phase 1).
   WASI-NN is a future axis for ML inference.

Everything else — public URLs, snapshots/clone, lifecycle timers, env injection,
secrets, mounts (as WASI preopens), cluster placement, admission, observability
— maps onto the existing ecosystem.

### 2.1 The worker-subprocess model (architectural prerequisite)

**Why this section exists.** The naive "wazero is pure-Go, just compile it into
`sandboxd`" approach would make WASM the highest-blast-radius runtime in the
codebase. A host-function panic, a guest-triggered `runtime.Throw`, an
unbounded allocation hitting the Go runtime's OOM killer — any of these in
the daemon process would kill `sandboxd` and *every* docker, firecracker, and
WASM sandbox on the host, plus the control plane and the API. **Firecracker
exists specifically to avoid that failure mode.** Reintroducing it via WASM is
not acceptable; one-line "we'll add `recover()`" hand-waves don't catch
scheduler-level panics, cgo failures, or OOM.

**The model.** `sandboxd` spawns a pool of small worker processes (`sandboxd
--wasm-worker`). Each worker hosts **exactly one** wazero instance (see §11
density tradeoff). The driver in `internal/runtime/wasm` communicates with
workers over per-worker Unix-domain sockets. A worker crash kills one sandbox;
`sandboxd` keeps running; the supervisor respawns the slot from the failed
sandbox's last boundary checkpoint (or marks `dead` if `ephemeral`).

```
        sandboxd (daemon process)
        ├── docker driver       (Runtime.Runtime)
        ├── firecracker driver  (Runtime.Runtime)
        └── wasm driver         (Runtime.Runtime)
              │
              │ Unix-domain socket per worker
              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐   each worker:
        │ worker 1 │  │ worker 2 │  │ worker N │     - one sandboxd --wasm-worker subprocess
        │ wazero   │  │ wazero   │  │ wazero   │     - one wazero Engine
        │ 1 module │  │ 1 module │  │ 1 module │     - one sandbox at a time
        └──────────┘  └──────────┘  └──────────┘     - crash → supervisor respawns
```

**IPC shape.** Length-prefixed framed CBOR over Unix-domain sockets. Message
types: `Invoke{args}`, `InvokeResult{stdout, stderr, exit}`, `Checkpoint{}`,
`CheckpointResult{snapshot_blob}`, `Restore{snapshot_blob}`,
`SetCapability{...}`, `NetstatsTick{bytes_in, bytes_out}`,
`HealthPing{}`/`Pong`. Worker stdout/stderr are streamed to the driver as
control-plane messages, NOT inherited from the daemon (so a `println` in the
guest can't pollute `sandboxd`'s log stream).

**Density cost (D11).** One sandbox per worker = one Go process per sandbox.
Each worker is ~5–10 MB resident before any module memory. Realistic per-host
ceiling is **~500–2000 sandboxes** (process limit + per-process RSS), not the
10k figure that an in-process model would imply. This is the honest density
floor; see §5 feature #2 and UC-10, UC-13. Higher fan-in (N modules per worker)
is a future axis with explicit operator opt-in, accepting the proportional
crash blast radius.

**Worker binary.** Same binary as `sandboxd` (`go build ./cmd/sandboxd`)
invoked with a `--wasm-worker` flag — no separate binary to distribute or
version-skew. The driver records the worker's `sandboxd --version` at spawn
time; a daemon restart that revs the binary triggers per-worker restart on the
next boundary (or queued checkpoint+rehydrate for `passivatable`/`durable`).

**Release gate.** A test that spawns a WASM module which panics inside a host
function, asserts `sandboxd` stays up, and asserts only the affected worker is
recreated, is a release-blocking P0 (§11). Without that test, the architectural
property this section rests on is unverified.

**Anything else** — public URLs, snapshots/clone, lifecycle timers, env
injection, secrets, mounts (as WASI preopens), cluster placement, admission,
observability — maps onto the existing ecosystem.

---

## 3. The toolbox problem and its solution (host-served toolbox)

Today the toolbox (`cmd/toolboxd`) is a Go agent inside the sandbox; the docker
path reaches it over TCP/eth0, the firecracker path over AF_VSOCK
(`cmd/toolboxd/vsock.go`). WASM Preview 1 cannot host a second process, so we
invert the model:

- **`internal/runtime/wasm/toolhost/`** — a host-side implementation of the
  toolbox surface (file read/write/list, exec/spawn-sub-invocation, session
  recording, code-run). Because the driver *owns* the module's WASI filesystem
  (a host directory preopen) and *is* the thing that instantiates+invokes the
  module, it can implement files/exec/sessions natively without a guest agent.
- Existing v1 toolbox routes (`pkg/api/v1/`) and the in-process proxy keep their
  shape; the driver exposes a `ToolboxHost` that the service calls instead of
  HTTP-dialing a guest. Behind the same handlers the SDKs already use → **no SDK
  transport change**.
- "exec" in a WASM sandbox = invoke an exported function / re-instantiate the
  module with new args (CLI-style WASI `_start`), captured stdout/stderr
  streamed back. Long-running "sessions" = a persistent instance with a
  host-driven stdin pipe.

This is strictly *less* moving infrastructure than the vsock handshake.

---

## 4. Durability, snapshots & restart survivability

This is the section the naive "treat a WASM sandbox like a microVM" model gets
wrong. Two distinct problems are usually conflated:

- **Snapshot/restore** of instance state, and
- **Surviving a daemon restart / rolling update** (in-process instances die with
  the process — Docker containers and Firecracker VMs do not).

Neither is solved by "dump linear memory," and **no WASM engine — wazero *or*
wasmtime — supports faithful mid-execution instance capture** (the live call
stack is not serializable). We solve both honestly with three design rules.

**WASM sandbox lifecycle** (the picture the rest of this section refers to):

```
   CreateSandboxRequest{runtime:"wasm", module_ref, durability, capabilities}
        │
        ▼
   ┌──────────┐     resolver       ┌───────────────┐
   │ service  │ ─────────────────► │ pkg/wasmmod   │  pulls .wasm by digest,
   │ dispatch │                    │ cache (CAS)   │  validates magic+WASI ver
   └────┬─────┘                    └───────┬───────┘  + checksum
        │                                   │
        ▼                                   ▼
   ┌──────────────┐  spawn worker    ┌─────────────────────────────┐
   │ wasm.Driver  │ ───────────────► │ sandboxd --wasm-worker (N)  │
   │ (in daemon)  │ ◄─────────────── │   one wazero Engine         │
   └──────┬───────┘   UDS framed     │   one Module instantiated   │
          │            CBOR          │   capabilities applied:     │
          │                          │     preopens, env, sockets  │
          │                          └──────────────┬──────────────┘
          │ Invoke{args}                            │
          ├──────────────────────────────────────► call _start / export
          │ stdout/stderr/exit                      │
          │ ◄─────────────────────────────── run to next host-return boundary
          │                                          │
          │            ┌────────────────────────────┴───────────────────┐
          │            ▼                                                ▼
          │   (a) idle/serve next                       (b) drain / lifecycle / kill
          │       invocation                                │
          │                                                 ▼
          │                                    ┌───────────────────────────────┐
          │                                    │ ephemeral    │ passivatable / │
          │                                    │              │ durable        │
          │                                    │ kill worker  │ Checkpoint{}   │
          │                                    │ row=stopped  │ → mem.snap     │
          │                                    │              │ + (durable)    │
          │                                    │              │   AOCR push    │
          │                                    │              │ row=passivated │
          │                                    └──────────────┴────────────────┘
          │
          │  on next sandboxd restart (passivatable/durable):
          ▼
   ┌──────────────────┐  Restore{snapshot}   ┌─────────────────────────────┐
   │ reconcile        │ ───────────────────► │ new worker, codec verified  │
   │ passivate.go     │                      │ (§4.8.1), row=running       │
   └──────────────────┘                      └─────────────────────────────┘
```

### 4.1 Snapshots are valid only at host-return boundaries

We **forbid stack-bearing snapshots by design.** A WASM workload has zero guest
frames on the stack — and is therefore fully capturable — exactly when you want
to snapshot it:

- **post-init, pre-request** (the "primed interpreter" fork), and
- **between requests** in a request/response function.

At those boundaries a snapshot is just:

```
linear-memory pages  +  guest globals  +  host-side WASI state (fd/preopen table, clock offset, RNG seed)
```

The detail that makes this clean *in this codebase*: **the host implements WASI**
(the `toolhost` from §3 owns the file/clock/socket host functions), so the fd
table, preopens, clock, and RNG state already live host-side and serialize
trivially. wazero exposes `Memory().Read()` + global accessors, so memory and
globals serialize directly. The only hard piece — the call stack — is the one we
contractually exclude. Mid-execution snapshot stays **unsupported on purpose**;
promising it would be dishonest, and every production WASM platform works this
way. This is why UC-27/28 are scoped to *boundary* snapshots, not arbitrary
point-in-time capture.

### 4.2 A per-sandbox durability class makes the tradeoff explicit

A new `durability` field on the create request turns the limitation into a
**declared contract** instead of a silent gap. Each class has a defined
restart + reconcile policy:

| Class | Daemon restart | Reconcile policy | Target workloads |
|---|---|---|---|
| `ephemeral` (default) | instance is lost | row → `stopped`; caller recreates | LLM tool calls, per-request functions (UC-21, 24) |
| `passivatable` | graceful-restart-survivable | rehydrate from on-disk checkpoint | primed interpreters, sessions (UC-22, 26) |
| `durable` | crash-survivable | re-instantiate; guest re-hydrates from host state API | stateful services (UC-39) |

The system now *knows* which sandboxes can survive a restart, rather than
pretending all of them can.

### 4.3 Drain → checkpoint → rehydrate closes the rolling-update outage

For `passivatable`, the daemon's graceful-shutdown path becomes:

1. **SIGTERM** → stop admitting new invocations.
2. **Drain**: wait for in-flight invocations to reach a host boundary (bounded by
   a timeout; same single-flight discipline as the warm pool).
3. **Checkpoint**: write each active sandbox's `{memory, globals, WASI state}` to
   `SB_WASM_MODULES_DIR/<id>/mem.snap`; flip the store row to `status=passivated`
   with a snapshot pointer.
4. **Restart** the new binary.
5. **Rehydrate**: reconcile sees `passivated` rows and reloads them — lazily on
   first access (the request is held at the caddy upstream so the client sees
   latency, not a 5xx) or eagerly for hot sandboxes.

Per-sandbox unavailability is the checkpoint+reload window — sub-second for
typical MB-scale linear memories. **A hard outage becomes a brief latency blip.**
`pkg/wasmmod/validate.go`'s integrity check gates rehydration: a corrupt
`mem.snap` falls back to cold re-instantiation, mirroring the Firecracker
`ErrSnapshotCorrupt` → rebuild intercept.

**Execution model.** Drain runs **parallel local checkpoints** across all
`passivatable`+`durable` sandboxes (bounded by `SB_WASM_DRAIN_TIMEOUT`). AOCR
push is **gated to `durable` only** — pushing every passivatable sandbox to a
registry at drain time would turn rolling updates into multi-minute outages at
density. Local checkpoint stays on disk; AOCR push happens on graceful drain
for the smaller `durable` subset (§4.8 cadence).

### 4.4 Zero-outage variant (cluster mode): live migration off the draining node

In cluster mode, at drain time we can **ship the memory image to a sibling node
and resume there** instead of checkpointing locally. This **models after** the
cross-node forwarding pattern in `internal/cluster/forward.go` and the
placement-reassign cycle from `recovery_store.go` — it does NOT reuse
`recovery_replication.go` (that's template-replication, a different shape from a
live memory stream). The new piece is a streaming endpoint:

```
POST /cluster/wasm-migrate    Streams a §4.8.1 snapshot artifact from drain
                              source to receiving owner; receiver atomically
                              promotes to owner via the existing Raft placement
                              path once the resume succeeds; fenced by the
                              §4.8 clone-generation token to reject zombie
                              writes from the source if it un-drains.
```

This is *feasible for WASM precisely because the images are small and
host-portable* — a WASM linear-memory image is typically single-digit MB and
arch-independent, versus a multi-GB, arch-pinned Firecracker memory snapshot.
Live workload migration off a node being updated is a genuine WASM **advantage**
here, not a liability.

### 4.5 Reconcile contract, redefined for worker-process instances

`ListManaged` for the WASM driver returns the **in-memory live set** (empty after
a restart). Reconcile compares it against the **store rows**, which persist, and
applies the per-row `durability` policy from §4.2: `passivated`+valid-snapshot →
rehydrate; `durable` → re-instantiate (guest re-hydrates from the host state
API); `ephemeral` or missing/corrupt snapshot → mark `stopped`/`dead` and let
the SDK/caller recreate.

**Critical exception — `awaiting_runtime`.** Today's reconcile has exactly one
narrow exception for missing-live-set state (Firecracker + stopped + missing
instance). Adding `passivated` introduces a second class. There's a third: a
`passivated` or `durable` WASM row found when `EnableWasm=false` (operator
flipped the flag off between restarts). Reconcile MUST NOT destroy these — that
would silently delete user work the moment WASM is disabled. The store row
transitions to a new **`awaiting_runtime`** status (with the original
durability + checkpoint pointer preserved) and reconcile treats this status as
"hold, do not touch." Flipping `EnableWasm=true` later moves the row back
through the normal rehydrate path. Status-set additions: `passivated`,
`awaiting_runtime`. Every call site that branches on missing-live-set state
needs an explicit handler for both (the audit step called out in §10 Phase 6).

### 4.6 `durable`: externalized state via a host KV capability

For crash-survivability (ungraceful kill -9 / kernel OOM / power loss), linear
memory is a **cache, not the source of truth**. Expose a `wasi-keyvalue`-style
host function backed by the existing store / `pkg/mounts` (S3/NFS). The guest
writes durable state through it and re-hydrates on any restart. Not transparent —
the workload must be written for it — but that non-transparency is inherent to
WASM and matches the Cloudflare Durable Objects / Fermyon model.

### 4.7 Honest residual limits

- **Ungraceful crash** loses work since the last checkpoint for `passivatable`
  (bounded by an opt-in periodic boundary-checkpoint interval) and loses
  non-externalized state for `durable`. `ephemeral` accepts the loss by
  definition. This is the same guarantee any checkpoint system gives — including
  Firecracker without continuous snapshotting.
- **Mid-execution snapshot** remains unsupported by design (§4.1).

### 4.8 AOCR-backed snapshots, durability tiers & cross-node failover

The local `mem.snap` of §4.3 is the single-node case. Promoting the same blob to
**AOCR** (the AerolVM OCI Registry the daemon already pushes to) makes it a
portable, content-addressed checkpoint that any node can pull — which is what
unlocks `durable` durability *and* failover. **Honest reuse audit:**

- `CreateSnapshot(ctx, containerRef, imageRef)` is on the `runtime.Runtime`
  interface (`internal/runtime/runtime.go`) and after the §1 interface split
  stays on the core interface. The WASM driver implements it as a §4.1 boundary
  capture. **Reused: yes.**
- `internal/service/snapshot_push.go`'s `SnapshotPusher` requires a
  `SnapshotPushDocker` interface (`PushImage` over `*docker.Client`). A WASM
  artifact is NOT a Docker image. **Reused: no — new `SnapshotPushWasm`
  interface + ORAS-Go pusher in `pkg/wasmmod` is required.** The *surrounding*
  machinery (`snapshot_push_retry.go`, `image_distribution.go`,
  `sandbox_snapshots` table, `POST /v1/sandboxes/{id}/snapshot` /
  `POST /v1/snapshots` routes) is reused.
- `internal/cluster/recovery_replication.go` externalizes create-spec + secret
  material for failover; it does NOT carry runtime memory state. **Reused: no
  — failover-from-snapshot is a new distributed-state protocol that uses the
  existing Raft placement reassign path + a new pull-and-restore step in the
  WASM driver.** Modeled after, not copied from.

**Artifact shape** (OCI manifest, single-digit MB, arch-independent) — full
specification with media types lives in §4.8.1 below:

```
manifest
 ├─ layer: compiled module — or just its digest, deduped against the base module
 ├─ layer: linear-memory image (zstd)
 ├─ layer: globals + host-side WASI state (fd table, clock offset, RNG seed) as CBOR
 └─ config: entrypoint, base-module digest, durability class, checksum, clone-generation marker
```

A pushed "primed interpreter" snapshot **is** a reusable warm template, so AOCR
snapshots collapse *templates + warm pool + durability + failover* into one
artifact type (no separate snapshot-build pipeline like Firecracker needs).

**Durability tiers** (extends §4.2):

| Class | Checkpoint target | Survives |
|---|---|---|
| `ephemeral` | none | nothing (recreated) |
| `passivatable` | local `mem.snap` (§4.3) | daemon restart on same node |
| `durable` | **AOCR / object store** (this) + opt-in host-KV (§4.6) | full node loss |

Cadence: AOCR push on **graceful drain always** (gated to `durable` only — see
§4.3 execution model), plus an **opt-in periodic boundary push** for crash
tolerance. You cannot push per-request (registry latency) — between pushes the
host-KV capability (§4.6) carries can't-lose data.

**Failover** (models after the existing Raft placement reassign in
`internal/cluster/recovery_store.go`, but the runtime-state handoff is new
because `recovery_replication.go` only replicates create-spec, not memory):

1. Owner dies → Raft placement reassigns the sandbox (existing).
2. New owner **pulls the latest snapshot artifact from AOCR and restores** via
   the WASM driver's restore path → the sandbox resumes at its last boundary
   checkpoint (loss bounded by the push cadence — identical to Firecracker
   failover-from-snapshot).

Two correctness guards:

- **Split-brain fencing.** A zombie old-owner must not clobber newer checkpoints.
  Use the **clone-generation token mechanism** — same pattern as
  `cmd/toolboxd/clonegen.go` (the vmgenid-style work already in this repo). For
  WASM the mechanism is extracted into `pkg/clonegen` so both toolboxd and the
  WASM driver depend on it without one importing `cmd/`. Store-side
  compare-and-swap on the generation column rejects writes from a stale
  generation.
- **Single active owner.** Raft owner-sharding already guarantees one node runs
  a given sandbox at a time; the AOCR snapshot is the handoff blob, not a live
  memory stream.

**Limits unchanged:** restores to the last *boundary* checkpoint, not live state;
zero-loss would need synchronous replication (too costly for the density story)
or the externalized host-KV path for the critical subset.

**AOCR retention.** Periodic pushes for `durable` workloads create many
artifacts per sandbox over time. Existing snapshot/image GC is local-image only;
AOCR-side retention is new work. Policy: **keep-last-N** (default N=3,
operator-tunable per `SB_WASM_AOCR_KEEP_PER_SANDBOX`), invoked by the existing
snapshot-rotation goroutine after a successful push. Old artifacts are deleted
by digest via the registry's manifest-delete API; the local image GC path is
unchanged.

**Push and failover flow:**

```
   PUSH (node A, owner of sandbox X)
   ─────────────────────────────────────────────
   driver.CreateSnapshot                            (Runtime.Runtime interface)
        │
        ▼
   worker quiesces to boundary
        │
        ▼
   pkg/wasm/snapshot_codec.go::Capture
   builds {config v1+json, module-ref, memory.zstd, globals.cbor, wasi-state.cbor}
        │
        ▼
   internal/service/wasm_snapshot.go
   ├── registers row in sandbox_snapshots (existing)
   ├── snapshot_push_retry.go schedules push (existing)
   └── pkg/wasmmod/oras_push.go (NEW)
            │
            │   NOT internal/service/snapshot_push.go — that path is Docker-image
            │   shaped (PushImage over *docker.Client). WASM artifacts go through
            │   ORAS-Go natively as OCI artifacts with the §4.8.1 media types.
            ▼
        ┌─────────┐
        │  AOCR   │  manifest digest: sha256:...
        │ registry│  config + 4 layers, single-digit MB total
        └─────────┘


   FAILOVER (node A dies, node B takes over)
   ─────────────────────────────────────────────
        ┌─────────┐
        │  AOCR   │
        └────┬────┘
             │ pull-by-digest
             ▼
   pkg/wasmmod/oras_pull.go
        │
        ▼
   pkg/wasm/snapshot_codec.go::Restore
   validates schema_version, engine, engine_version
   on mismatch → ErrSnapshotCorrupt → service-layer cold re-instantiate
        │
        ▼
   wasm.Driver (node B) spawns worker, Restore{snapshot}
        │
        ▼
   row updated: owner=B, clone_generation bumped (fences A if it un-drains),
   status=running


   FENCING (zombie node A tries to push after failover)
   ─────────────────────────────────────────────
   node A push w/ clone_generation = G_old
        │
        ▼
   store-side compare-and-swap rejects (current generation = G_new)
        │
        ▼
   node A driver receives FENCED error, kills the orphan worker
```

### 4.8.1 Snapshot codec — versioned media-type contract

The artifact shape in §4.8 is a sketch. The on-the-wire contract is:

**Config descriptor:**

```
media type: application/vnd.aerolvm.wasm-snapshot.v1+json
content:
  {
    "schema_version": 1,                              // bump on breaking change
    "engine":         "wazero" | "wasmtime",          // engine identifier
    "engine_version": "v1.8.0",                       // engine version pin
    "wasi_version":   "preview1" | "preview2",        // WASI ABI
    "base_module": {                                  // template the clone forked from
      "digest": "sha256:...",                         // content-addressed; resolves via pkg/wasmmod cache
      "size":   1048576                               // bytes
    },
    "entrypoint":      "_start" | "<export-name>",
    "durability":      "ephemeral" | "passivatable" | "durable",
    "captured_at":     "2026-06-07T15:53:23Z",        // UTC, RFC3339
    "clone_generation": "0xa1b2...",                  // §4.8 fencing token at capture time
    "memory_checksum": "sha256:...",                  // over the decompressed memory layer
    "wasi_state_checksum": "sha256:...",              // over the wasi-state layer
    "globals_count":  N                               // sanity check for the globals blob
  }
```

**Per-layer media types** (each layer is a separate blob in the manifest):

| Layer | Media type | Contents |
|---|---|---|
| Base module reference | `application/vnd.aerolvm.wasm-snapshot.v1.module-ref` | Empty (digest in config); module pulled separately via `pkg/wasmmod` cache |
| Linear memory | `application/vnd.aerolvm.wasm-snapshot.v1.memory.zstd` | zstd-compressed linear-memory image |
| Globals | `application/vnd.aerolvm.wasm-snapshot.v1.globals.cbor` | CBOR-encoded `[{type, value}, ...]` |
| WASI state | `application/vnd.aerolvm.wasm-snapshot.v1.wasi-state.cbor` | CBOR-encoded `{fd_table, preopens, clock_offset, rng_seed, env}` |

**Restore-time validation** (`pkg/wasm/snapshot_codec.go::Restore`):

1. Parse config; reject unknown `schema_version` with a typed error wrapping
   `models.ErrSnapshotCorrupt`.
2. Engine compatibility check: `engine` must match the running engine; major
   `engine_version` must match (minor mismatch allowed with a warning).
   Mismatch → reject with `models.ErrSnapshotCorrupt`; service layer falls
   through to cold re-instantiate from `base_module.digest`, mirroring the
   Firecracker `ErrSnapshotCorrupt` → rebuild intercept.
3. Pull base module by digest via `pkg/wasmmod` cache; verify size matches
   `base_module.size`.
4. Decompress memory layer; verify `memory_checksum`.
5. Decode globals + WASI state CBOR; verify `wasi_state_checksum` +
   `globals_count`.
6. Hand all four to the engine for instance reconstruction.
7. If `clone_generation` is older than the row's current generation in the
   store (§4.8 fencing), reject and let the caller decide — this is the
   zombie-write guard.

**Version policy.** `schema_version` is the breaking-change axis. A `v1` reader
MUST refuse a `v2` artifact and vice versa. Restore failure is non-fatal: the
service layer falls back to cold re-instantiate, so a partial fleet upgrade
(some nodes on v1, some on v2) degrades to cold-boots, not corruption. Adding
new optional config fields does NOT bump the version; removing or repurposing
any existing field does.

### 4.9 Failure modes & invariants

Each new file in §7 has a single concurrency- or failure-mode invariant. Naming
them here so the implementer doesn't reinvent them under pressure.

| Concern | File | Invariant |
|---|---|---|
| Drain timeout fires mid-checkpoint | `internal/runtime/wasm/checkpoint.go` | **Kill-after-timeout, never block-forever.** When `SB_WASM_DRAIN_TIMEOUT` elapses with the sandbox still mid-exec (no host boundary reached), terminate the worker, mark the store row `passivate_failed` with the original `durability` preserved, log loudly. Better to lose this sandbox's state than to stall a rolling update. |
| Concurrent Start + reconciler rehydrate of same `passivated` row | `internal/runtime/wasm/passivate.go` | **Single-flight via `sync.Mutex` + `atomic.Bool` latch.** Canonical example: `Service.EnsureLayer4Ready` in `internal/service/service.go`. First caller wins; second blocks on the latch and observes the resulting instance. No double-instantiation, no race on the checkpoint file. |
| `statekv` write during a checkpoint | `internal/runtime/wasm/statekv/statekv.go` + `checkpoint.go` | **Synchronous-before-checkpoint.** A `statekv.Set` returns to the guest only after the durable write succeeds. The checkpoint then captures a consistent KV-vs-memory view: any KV value present in memory at checkpoint time is also durable in the store. Without this guarantee, restore can see a memory state that references a KV value not yet persisted. |
| Guest crash mid-write to a preopen file | `internal/runtime/wasm/toolhost/files.go` | **`os.Rename` atomic-write discipline.** All file writes through the host-served toolbox go through a temp file in the same directory + `os.Rename`. Mirrors `cmd/toolboxd/clonegen.go`'s existing pattern. Readers (other sandboxes, the host) never see partial writes. |
| Module cache fills disk | `pkg/wasmmod/cache.go` | **Capped at `SB_WASM_CACHE_MAX_BYTES` with LRU eviction**, separate from the module-GC TTL. Referenced modules (any sandbox row points at them) are pinned and skipped by eviction; the worst case is "cache misses" not "host disk full." |
| Worker process panics inside a host function | `pkg/wasm/worker/supervisor.go` (§7) | **Supervised respawn, no daemon impact.** One module per worker (§2.1) means one crash = one sandbox killed; the supervisor logs and recreates the slot. This is the load-bearing property the entire architecture rests on; see §11 release gate. |

---

## 5. Features WASM-based sandboxes enable

1. **Sub-millisecond cold start** — instantiate a pre-compiled module in µs–low-ms vs. ~125 ms Firecracker snapshot-resume and seconds for cold Docker.
2. **Higher density than microVMs, gated by control plane.** Per-worker RSS is ~5–10 MB before module memory (one module per worker, see §2.1) → realistic per-host runtime ceiling ~500–2000 sandboxes vs. low-hundreds for microVMs. **Sustained creates/sec is independently capped by the control plane** (SQLite single-writer + Caddy admin churn) regardless of runtime; combined 10k+ density is a separate workstream that scales those out, not a property WASM unlocks by itself.
3. **Host-portable** — same `sandboxd` runs WASM sandboxes on Linux/macOS/Windows, any CPU arch, no KVM.
4. **Unprivileged operation** — no root, no `/dev/kvm`, no `CAP_NET_ADMIN`; runs in restricted/serverless hosts and inside other containers.
5. **Capability-based security** — deny-by-default; a module gets only the FS preopens, env, clocks, and sockets it's granted (no ambient authority).
6. **Hard CPU/time limits** — epoch-style interruption (wazero) gives instant, deterministic timeouts; instruction-level *fuel* accounting for precise CPU billing requires the wasmtime engine seam (call this out — wazero gives timeouts, not per-instruction counts).
7. **Instant fork/clone at a boundary** — fork a *quiescent* instance (memory + globals + host-side WASI state) in µs. Mid-execution capture is not supported by any WASM engine — see §4.1.
8. **Deterministic execution** — reproducible runs for testing, replay, and audit.
9. **Single portable artifact** — one `.wasm` runs on every host/arch; no per-arch image builds.
10. **No Docker daemon on the WASM boot path** — the WASM driver does not call Docker (no skopeo / umoci / mkfs / VMM subprocess / jailer); fewer failure modes on the boot path. (Note: `sandboxd` itself still initializes a Docker client at boot today — `pkg/daemon/daemon.go:148`. A WASM-only deployment would need that init to become lazy / conditional on `EnableDocker`; flagged as a Phase-1 implementation choice.)
11. **Polyglot** — Rust, Go (TinyGo), C/C++, Zig, plus WASM-packaged Python/JS/Ruby interpreters.
12. **Per-call billing granularity** — meter and bill at the function-invocation level, not the VM-uptime level.
13. **Worker-isolated multi-tenancy** — one wazero module per worker subprocess (§2.1). Crash blast radius is one sandbox, matching Firecracker's failure-domain model, without per-tenant VMs.
14. **Component composition** — WASI Preview 2 components can be linked on the
    **wasmtime** engine path only; wazero remains wasip1 + Aerol compat shims.
15. **Boundary snapshot = small, portable image** — a host-boundary snapshot (memory + globals + WASI state) is single-digit MB and arch-independent, enabling fast checkpoint/rehydrate and cross-node live migration (§4.3–4.4). Not a faithful mid-execution VM snapshot.

---

## 6. Use cases (56 — exceeds the 40 minimum)

Each use case is tagged with the plan component(s) that deliver it (see §12 for
the full traceability matrix). UC = use case.

**Core lifecycle**
1. UC-01 Create a WASM sandbox from a `.wasm` module reference.
2. UC-02 Create from an OCI-wrapped wasm artifact (`registry/foo:wasm`).
3. UC-03 Start / Stop / Destroy a WASM sandbox via the same v1 API.
4. UC-04 Inspect a WASM sandbox (status, memory, CPU usage).
5. UC-05 List all WASM-managed sandboxes (reconcile parity).
6. UC-06 Resize a running WASM sandbox's memory/CPU-fuel caps.
7. UC-07 Idempotent create under retry / concurrent duplicate calls.
8. UC-08 `runtime: "wasm"` rejected cleanly when host hasn't opted in.

**Performance / density**
9. UC-09 Sub-millisecond warm-start from the pre-instantiated module pool.
10. UC-10 Run ~500–2000 concurrent WASM sandboxes on one mid-size host (per-worker RSS ceiling; one module per worker, §2.1). Combined-fleet density above this requires control-plane scaling (SQLite, Caddy), out of WASM-runtime scope.
11. UC-11 Compile-once / instantiate-many: one compiled module, N instances.
12. UC-12 Scale-to-zero serverless function (no idle cost).
13. UC-13 Burst-create sandboxes for a fan-out workload at the runtime's instantiation cost (sub-ms warm, low-ms cold). Sustained creates/sec is bounded by control-plane throughput (SQLite single-writer + Caddy admin churn), not the WASM runtime — measure those bottlenecks before promising a per-second number to users.

**Security / isolation**
14. UC-14 Untrusted user-submitted code runs with zero host filesystem access.
15. UC-15 Capability-scoped FS: grant only `/work` as a preopen.
16. UC-16 Deny-by-default network; explicitly allow one outbound host:port.
17. UC-17 Run an untrusted third-party plugin inside a trusted app.
18. UC-18 Hard wall-clock timeout that always fires (epoch interruption).
19. UC-19 Hard memory ceiling; OOM is contained, not host-fatal.
20. UC-20 No-ambient-authority guarantee (no env/clock unless granted).

**AI / agent workloads**
21. UC-21 LLM tool-call execution sandbox (per-call, sub-ms, throwaway).
22. UC-22 Code interpreter for Python via WASM-packaged CPython.
23. UC-23 JavaScript eval sandbox via Javy/SpiderMonkey-on-WASM.
24. UC-24 Per-request isolation for an agent that runs 1000s of tool calls.
25. UC-25 Deterministic replay of an agent run for debugging.
26. UC-26 Fork a "primed" interpreter (libs loaded) to skip re-init per call.

**Snapshots / clone** (boundary-only — see §4.1)
27. UC-27 Snapshot a WASM sandbox **at a host-return boundary** and restore later.
28. UC-28 Instant clone of a **quiescent** sandbox (fork memory + globals + WASI state).
29. UC-29 Clone-RNG-reseed correctness parity with the Firecracker clone work.
30. UC-30 Build a reusable WASM "module template" (warm, pre-instantiated).

**Platform integration**
31. UC-31 Public preview URL for a WASM sandbox serving HTTP (`wasi-http`).
32. UC-32 Port allowlist / expose_port idempotency on the WASM path.
33. UC-33 Custom domain routing to a WASM sandbox.
34. UC-34 Lifecycle timers (idle-stop, age-destroy) on WASM sandboxes.
35. UC-35 Env-var + secret injection (sealed) into a WASM sandbox.
36. UC-36 Attach external storage as a WASI preopen (S3/NFS via mounts mgr).
37. UC-37 Cluster-mode placement of WASM sandboxes (power-of-two choices).
38. UC-38 Cross-node forwarding to a WASM sandbox owned by another node.
39. UC-39 Failover recreate of a WASM sandbox on owner loss.
40. UC-40 Admission control counts WASM footprint in capacity accounting.

**Observability / ops / billing**
41. UC-41 OTEL traces + expvar metrics for WASM create/instantiate latency.
42. UC-42a / UC-42b — Per-invocation usage exported for billing. **42a:** wall-clock + memory on wazero (the default engine). **42b:** instruction-level fuel accounting on the wasmtime engine seam (CGo opt-in). 42b is NOT deliverable on wazero; the engine seam must be selected to get it.
43. UC-43 Network byte metering on the host-mediated socket (worker-side counter, reported to driver over IPC; quota enforcement via socket pause/close, not iptables — see §9 netstats subsection).
44. UC-44 Module GC: drop unreferenced compiled-module artifacts on TTL.
45. UC-45 Module integrity verification (checksum) before instantiation.
46. UC-46 Graceful host shutdown drains in-flight WASM invocations.

**Developer experience / SDK / docs**
47. UC-47 Create a WASM sandbox from each of the 5 SDKs (`runtime: "wasm"`).
48. UC-48 Daytona/E2B facade requests transparently land on WASM when selected.
49. UC-49 Docs page with five-language tab examples for WASM sandboxes.
50. UC-50 Mixed fleet: Docker + Firecracker + WASM sandboxes on one host.

**Durability / restart survivability** (see §4)
51. UC-51 Declare a sandbox's `durability` class (`ephemeral`/`passivatable`/`durable`).
52. UC-52 Rolling host-software update with **no hard outage** for `passivatable` sandboxes (drain → checkpoint → rehydrate).
53. UC-53 Live-migrate a running WASM sandbox to a sibling node before draining (cluster, zero-outage).
54. UC-54 `durable` sandbox survives an ungraceful crash via externalized host KV state.
55. UC-55 Snapshot an **intermediate (primed) state** and push it to AOCR as a reusable, content-addressed artifact (§4.8).
56. UC-56 **Cross-node failover-from-snapshot**: a new owner pulls the latest AOCR checkpoint and resumes at the last boundary (§4.8).

---

## 7. Packages to CREATE

```
pkg/clonegen/                     Generation-token primitive extracted from cmd/toolboxd/clonegen.go (D9)
  clonegen.go                       Monotonic generation token + atomic file publish + nil-safe accessors
  *_test.go                         (lifted verbatim from cmd/toolboxd/clonegen_test.go)
                                    cmd/toolboxd now imports this package; WASM driver does too (§4.8 fencing)

pkg/wasm/                         Low-level engine wrapper (analog of pkg/firecracker/)
  engine.go                         Engine interface + wazero impl; Compile/Instantiate/Invoke/Close
  engine_wazero.go                  wazero-backed Engine (build tag default)
  module.go                         Compiled-module handle + linear-memory snapshot/restore
  instance.go                       Instance handle: stdin/stdout/stderr pipes, fuel, epoch deadline
  capabilities.go                   WASI capability config: preopens, env, clocks, sockets, args
  fuel.go                           CPU-fuel / epoch-interruption metering helpers
  net_meter.go                      Inbound/outbound byte counters (NetworkHook.Meter)
  network_hook.go                   NetworkHook interface (policy + metering)
  wazero_network.go                 wazero `aerol/vm/net` host module + tcp_read/write
  wazero_wasi_compat.go             P2-shaped `wasi:sockets` / `wasi:http` → aerol/vm/net
  wazero_wasip1_meter.go              Function listeners on sock_recv/send/accept
  wazero_listen.go                  ResolvedListenPort via wasip1 listener context
  wasmtime_network.go               wasmtime NetworkHook (SetNetworkHook/ClearNetworkHook)
  snapshot.go                       Boundary snapshot: capture {memory,globals,WASI state}, checksum, restore, clone (§4.1)
  snapshot_codec.go                 Pack/unpack a §4.8.1 versioned OCI artifact for AOCR (renamed from snapshot_oci.go per D8)
                                    File-header doc comment enumerates the contract for both snapshot.go and snapshot_codec.go
                                    to prevent the 9-file sprawl the Firecracker driver fell into
  types.go                          ModuleConfig, InstanceConfig, RunResult, ResourceCaps
  worker/                           Worker-subprocess pool (D1, §2.1)
    supervisor.go                     Spawn/respawn workers; one wazero per worker; crash isolation
    client.go                         Driver-side: per-worker UDS client; CBOR framing
    server.go                         Worker-side: UDS server; runs as `sandboxd --wasm-worker`
    protocol.go                       Message types: Invoke, InvokeResult, Checkpoint, Restore, SetCapability, SetListenPort, NetstatsTick, HealthPing
    proxy_http.go                     Worker-side HTTP reverse proxy to guest wasip1 listener
    *_test.go                         Includes the D10 release-gate test (panic in host func → daemon survives)
  engine_wasmtime.go                (optional, build tag `wasmtime`) CGo Cranelift engine for UC-42b fuel
  *_test.go

pkg/wasmmod/                      Artifact resolver/builder (analog of pkg/oci/)
  resolver.go                       Resolve a module ref → local .wasm path
  oci_pull.go                       OCI-wrapped wasm via ORAS-Go (NOT skopeo; skopeo's path is Docker-image shaped)
  registry.go                       Plain HTTP(S)/file:// module fetch
  oras_push.go                      ORAS-Go push of §4.8.1 snapshot artifacts to AOCR (D2)
                                    Implements a parallel SnapshotPushWasm interface — NOT pkg/docker.PushImage
  oras_pull.go                      ORAS-Go pull of snapshot artifacts for failover-from-snapshot (D2, §4.8 failover)
  validate.go                       Magic-byte + WASI-version + checksum validation
  cache.go                          Content-addressed on-disk module cache; capped at SB_WASM_CACHE_MAX_BYTES with LRU eviction (§4.9 D5e)
  types.go
  *_test.go

internal/runtime/wasm/            The Runtime.Runtime driver (analog of internal/runtime/firecracker/)
  driver.go                         Driver implementing runtime.Runtime; registry of instances
  create.go                         Create: resolve module → compile → configure caps → instantiate
  lifecycle.go                      Start/Stop/Destroy/Inspect/ListManaged/Ping/Resize
  snapshot.go                       CreateSnapshot (boundary capture) + load/clone
  checkpoint.go                     Drain → checkpoint quiescent instances to mem.snap (§4.3); periodic opt-in
  passivate.go                      Rehydrate passivated rows on start (lazy/eager); corrupt-snapshot fallback (§4.5)
  migrate.go                        Cluster live-migration: ship image to sibling node + resume (§4.4)
  seams.go                          Host seams: ModuleResolver, Engine, ToolboxHost, WarmPool, Meter, StateStore
  network.go                        Host-mediated socket meter + capability block/allow (Net* methods)
  config.go                         Driver Config + FromDaemonConfig(cfg)
  statekv/                          host KV capability for `durable` workloads (§4.6), backed by store/mounts
    statekv.go                        wasi-keyvalue-style host functions; get/set/list/delete
  toolhost/                         Host-served toolbox (replaces in-guest agent)
    files.go                          file read/write/list over the WASI preopen dir
    exec.go                           invoke export / re-instantiate as exec; stream stdout/stderr
    sessions.go                       persistent-instance sessions + recording (reuse recorder shape)
    coderun.go                        daytona/e2b code-run semantics on WASM
  *_test.go

internal/pool/wasm/               Warm pool (analog of internal/pool/vmm/)
  pool.go                           Pre-compiled + pre-instantiated module cache
  refill.go                         Background refill to DepthDefault per module
  metrics.go                        Pool hit/miss + warm-depth metrics
  spawner.go                        Constructs warm instances via the engine seam
  *_test.go
```

## 8. Files to CREATE outside new packages

```
internal/service/wasm.go              createWasmSandbox + isWasmSandbox + dispatch helpers
internal/service/wasm_module.go       module catalogue lifecycle (build/ready/failed/GC) — mirrors template.go
internal/service/wasm_module_health.go  integrity + rebuild-on-corrupt (mirrors template_health.go)
internal/service/wasm_snapshot.go     service-side snapshot/clone orchestration for WASM
pkg/daemon/wasm_wiring.go             cfg.EnableWasm block: construct engine, resolver, pool, adapters, SetWasmRuntime
docs/src/content/docs/wasm-sandbox.mdx       five-language tabbed docs page (UC-49)
docs/src/content/docs/wasm-modules.mdx       module/template catalogue docs page
docs/src/content/docs/wasm-architecture.mdx  architecture/limits page (mirrors firecracker-architecture)
agentic_docs/wasm-runtime-map.md      agent reference: WASM request flow + idempotency timeline
setup/runbooks/wasm-runtime-health.md operator runbook (mirrors firecracker-template-health.md)
```

## 9. Files to MODIFY

```
pkg/models/types.go
  • Add RuntimeWasm = "wasm" constant (next to RuntimeFirecracker).
  • ValidRuntime: accept "wasm".
  • ResolveOCIRuntime: return ErrRuntimeNotImplemented (WASM isn't an OCI runtime;
    the service must dispatch away before this is reached — same pattern as firecracker).
  • CreateSandboxRequest: add ModuleRef (optional; falls back to Image as the ref),
    WasmEntrypoint (export name, default "_start"), Capabilities (preopens/env/net allow).
  • CreateSandboxRequest: add Durability ("ephemeral"|"passivatable"|"durable",
    default depends on runtime — see below) — the §4.2 class. Add ValidDurability()
    validator (fail-fast at the API boundary, same shape as ValidRuntime).
  • **Unified field (D7):** Durability is a first-class field across ALL runtimes,
    not WASM-only. Defaults per runtime: docker/firecracker/gvisor default to
    "passivatable" (they survive restarts natively); WASM defaults to "ephemeral"
    (D7). Non-WASM paths reject "durable" until they implement it (returns
    ErrRuntimeNotImplemented-style error).
  • Sandbox: persist ModuleRef + resolved module digest + entrypoint + Durability +
    CheckpointPath (for WASM passivatable/durable).
  • Reuse existing TemplateID/OverlaySizeGB? OverlaySizeGB is FS-shaped → ignored on WASM;
    TemplateID is reused to point at a wasm_modules row (warm/pre-compiled).
  • Add status constants "passivated" (checkpoint-on-disk, awaiting rehydrate — §4.3)
    AND "awaiting_runtime" (passivated row found when EnableWasm=false — §4.5),
    alongside the existing lifecycle statuses. Generalize the
    models.ErrSnapshotCorrupt doc comment to describe the contract, not just
    Firecracker (the WASM codec validation in §4.8.1 reuses it).

pkg/models/runtime.go (or wherever ValidRuntime lives if split) + runtime_test.go
  • Table-driven test: "wasm" valid; ResolveOCIRuntime("wasm") → ErrRuntimeNotImplemented.

internal/config/config.go
  • EnableWasm bool (SB_ENABLE_WASM, default false).
  • SB_WASM_ENGINE (wazero|wasmtime, default wazero).
  • SB_WASM_MODULES_DIR (compiled-module + artifact cache dir).
  • SB_WASM_MAX_INSTANCES (per-host density cap → admission).
  • SB_WASM_DEFAULT_FUEL / SB_WASM_DEFAULT_MEMORY_MB / SB_WASM_DEFAULT_TIMEOUT.
  • SB_WASM_POOL_ENABLED / SB_WASM_POOL_DEPTH_DEFAULT / SB_WASM_POOL_*_INTERVAL.
  • SB_WASM_MODULE_GC_ENABLED / _INTERVAL / _TTL.
  • SB_WASM_ALLOW_OUTBOUND (default false; capability default).
  • Durability/restart (§4.3): SB_WASM_DEFAULT_DURABILITY (default "ephemeral"),
    SB_WASM_DRAIN_TIMEOUT (graceful-shutdown drain budget before forced checkpoint),
    SB_WASM_CHECKPOINT_INTERVAL (0 = off; opt-in periodic boundary checkpoint for
    crash-loss bounding), SB_WASM_REHYDRATE_ON_START ("lazy"|"eager").
    Checkpoints land under SB_WASM_MODULES_DIR/<id>/mem.snap.
  • AOCR durability (§4.8): `durable` checkpoints reuse the EXISTING SnapshotPushConfig
    (snapshot_push.go: Host/ClusterID/PATPath) — no new registry knobs. Add only
    SB_WASM_DURABLE_PUSH_ON_DRAIN (default true) + SB_WASM_DURABLE_PUSH_INTERVAL
    (0 = drain-only) to gate when the WASM path pushes to AOCR.
  • Validation block mirroring the `if cfg.EnableFirecracker { … }` validator:
    require modules dir writable, engine recognized; reject SB_CONTAINER_RUNTIME=wasm
    as host default (per-sandbox opt-in only, same rule as firecracker).

internal/runtime/runtime.go  (D17 PREREQUISITE)
  • Split `Runtime` into a core `Runtime` (Create/Start/Stop/Destroy/CreateSnapshot/
    Resize/Inspect/ListManaged/Ping/RemoveImage) + a `ContainerRuntime` sub-interface
    that adds the network-rule methods (PushAllowedPorts, ClearNetworkRules,
    ApplyNetworkBlockAll, ApplyNetworkBlockIngress, ClearNetworkBlockIngress,
    ClearNetworkBlockEgress). Docker (pkg/docker.Client) + Firecracker
    (internal/runtime/firecracker.Driver) satisfy both; WASM satisfies only the
    core. Service-layer call sites that invoke network-rule methods type-assert
    to ContainerRuntime; a wasm sandbox returns false on that assertion and the
    caller skips (already a no-op semantically for WASM). Audit every such call
    site as part of this refactor.

internal/service/service.go
  • Add `wasm runtime.Runtime` field + SetWasmRuntime(r) (mirror SetFirecrackerRuntime).
  • isWasmSandbox(sb) + extend runtimeForSandbox to route wasm → s.wasm.
  • In Create dispatch: chosenRuntime == RuntimeWasm → guard EnableWasm + driver registered,
    then createWasmSandbox (mirrors the firecracker branch at service.go:~880).
  • **D14 — req.Image / ModuleRef.** `createSandbox` currently hard-requires
    `req.Image` (service.go ~786). When `runtime=wasm`, accept `req.ModuleRef`
    in place of (or alongside) `req.Image`. Add validation at the API boundary,
    not deep in the runtime. NOT a thin dispatch swap.
  • **D14 — toolbox-proxy resolution.** The existing proxy (service.go ~2616 +
    custom_domains.go:78) resolves to `http://{ContainerIP}:{ToolboxPort}`.
    When `runtime=wasm`, route to the host-served toolbox
    (`internal/runtime/wasm/toolhost`) via an in-process call instead of
    HTTP-dialing a guest IP. The handlers stay thin; the resolver picks the
    impl by runtime.
  • Reject FS/VM-only options on the WASM path with clear errors (GPUs, raw mounts
    that aren't preopen-compatible) — same shape as createFirecrackerSandbox's rejections.
  • Reconcile path: apply the §4.5 per-row durability policy for WASM rows whose
    driver live-set entry is missing after a restart (rehydrate `passivated`,
    re-instantiate `durable`, mark `ephemeral` stopped, preserve `awaiting_runtime`).
    **Per-row branch must handle ALL of these classes plus the
    `awaiting_runtime` case** — D18 reconcile audit, time-boxed ~1 day.
  • Snapshot→AOCR (§4.8): the WASM driver implements CreateSnapshot as a boundary
    capture; the service routes the artifact through `pkg/wasmmod/oras_push.go`
    (NOT `snapshot_push.go` — that's Docker-image shaped; see D2 in §0).
    Reuses surrounding machinery (`snapshot_push_retry.go`, `image_distribution.go`,
    `sandbox_snapshots` table, `/v1/snapshots` routes). Failover restore pulls
    the latest artifact via `pkg/wasmmod/oras_pull.go` and calls the driver's
    restore path, fenced by the clone-generation token (from `pkg/clonegen`,
    extracted per D9) via store-side compare-and-swap.

internal/service/netstats.go  (D16 — parallel WASM accounting)
  • The existing netstats is Docker-IP-shaped: it scrapes `docker stats` and
    blocks/unblocks per-IP via iptables. Neither applies to WASM.
  • New WASM-side accounting (lives in `internal/runtime/wasm/network.go`):
    byte counters on the host-mediated listener live IN THE WORKER PROCESS
    (where the socket actually is), reported back to the driver over IPC
    (`NetstatsTick` messages, see §2.1 protocol). Driver aggregates and surfaces
    via the same `service.NetStats` interface so callers (idle/wake hook, quota
    enforcer) don't care which runtime backed the numbers.
  • Quota enforcement: when `net_bytes_in_limit` / `net_bytes_out_limit` is
    crossed, the driver tells the worker to pause/close the mediated socket
    (NOT iptables). Idle/wake hook reuses the existing service-level signal
    (`l4wake.go`) but reads from the new counter.

internal/store/store.go  (use /add-store-column discipline + regression test)
  • New table wasm_modules (mirror firecracker_templates): id, module_ref, status,
    module_path, module_size_bytes, digest/checksum, entrypoint, has_warm, last_error,
    created_at, updated_at, ready_at. Plus idx on updated_at for GC.
  • Sandboxes table: ensure runtime column already carries "wasm". VERIFY there is no
    CHECK constraint / enum coercion on `runtime` before assuming "wasm" rows are
    accepted (the plan's earlier "free-text, no migration" claim is unverified — confirm
    against the live CREATE TABLE in store.go). Add module_ref + module_digest +
    durability + checkpoint_path columns via idempotent ALTER (scanner + Create/Upsert).
  • Status: persist "passivated" rows (§4.3) so reconcile can find them after restart.
  • Optional wasm_instance_pool table only if warm pool needs durable slot identity
    across restarts (likely NOT needed — instances are in-process and cheap to rebuild;
    document the decision either way).

pkg/daemon/daemon.go
  • Add `if cfg.EnableWasm { wasmWiring(...) }` next to the EnableFirecracker block.
    (Body lives in pkg/daemon/wasm_wiring.go to keep daemon.go readable.)
  • Construct: engine (pkg/wasm), module resolver (pkg/wasmmod), warm pool
    (internal/pool/wasm), driver (internal/runtime/wasm), adapters for ModuleResolver/
    Meter/ToolboxHost, then svc.SetWasmRuntime(driver).
  • Gate module-GC + pool-refill goroutines on EnableWasm (mirror firecracker goroutines).

pkg/capacity/capacity.go
  • Teach the Admitter a WASM footprint dimension (instance count + memory),
    distinct from VM vCPU/MB so a host can run a dense WASM fleet under one cap.
    (UC-40, UC-10.)

pkg/api/v1/routes.go + handlers.go
  • No new routes for core lifecycle (create/start/stop/destroy/inspect already
    runtime-agnostic). Add module-catalogue routes /v1/wasm-modules (mirror /v1/templates)
    ONLY if we expose pre-build; otherwise modules are resolved lazily on create.
  • Wire toolbox file/exec/session handlers to call the host-served toolbox when the
    sandbox runtime is wasm (the handlers stay thin; the service picks the impl).

pkg/api/daytona/* and pkg/api/e2b/*
  • No facade table changes (per memory: facades are translation layers). Ensure the
    facade→models translation can carry runtime:"wasm" so UC-48 works for free.

docs/src/content.config.ts
  • Register wasm-sandbox.mdx, wasm-modules.mdx, wasm-architecture.mdx in the sidebar
    (under the existing "Sandbox" / "Create Sandbox" group, next to Firecracker entries).

sdk/{typescript,python,go,rust,java}/...
  • `runtime` is already a free-form string on the create DTO — transport itself
    is unchanged.
  • Add typed constants/enums (Runtime.Wasm) + the new create fields
    (moduleRef, wasmEntrypoint, capabilities, durability) across all five SDKs
    in lockstep via the /add-sdk-method discipline. Update the one synced docs
    example. `durability` is unified across runtimes (D7), so this addition
    isn't WASM-only on the SDK side — every SDK gets the enum.

Makefile
  • Optional `build-wasm-examples` target to compile the sample modules used in docs/tests.
  • Ensure `make test` covers the new packages (it already runs ./...).
```

---

## 10. Phasing (mirrors the Firecracker rollout)

- **Phase 1 — Skeleton + dispatch + prerequisite refactors.**
  - **Interface split (D17, prerequisite):** split `runtime.Runtime` into a core
    `Runtime` + a `ContainerRuntime` sub-interface carrying
    `PushAllowedPorts`/`ClearNetworkRules`/`ApplyNetworkBlockAll`/
    `ApplyNetworkBlockIngress`/`ClearNetworkBlockIngress`/`ClearNetworkBlockEgress`.
    Docker + Firecracker drivers satisfy both; service-layer call sites that
    invoke the network-rule methods route through `ContainerRuntime`. Audit
    every such call site. This refactor touches docker + firecracker drivers
    and is the gate for everything else in this plan.
  - **Extract `pkg/clonegen` (D9, prerequisite):** lift `cmd/toolboxd/clonegen.go`
    into a shared package so the WASM driver can fence checkpoint writes via
    the same primitive (§4.8) without importing `cmd/`.
  - **Unified `Durability` field (D7, prerequisite):** add `Durability` to
    `pkg/models/types.go` with `ValidDurability()` validator; persist as a
    `sandboxes` column via idempotent ALTER + regression test (per
    `/add-store-column` discipline); surface in all 5 SDKs in lockstep.
    Non-WASM runtimes default to `passivatable`; `durable` rejected on
    docker/firecracker until those paths implement it.
  - **Skeleton + dispatch:** land `RuntimeWasm`, `ValidRuntime`, config flag,
    an `internal/runtime/wasm.Driver` whose methods return
    `ErrRuntimeNotImplemented`, service dispatch, daemon wiring guarded by
    `EnableWasm`. Proves the 3rd `Runtime` holds.
  - **Worker-subprocess foundation (D1):** `pkg/wasm/worker/` skeleton
    (supervisor + UDS client/server + protocol). The D10 release-gate test
    (panic in host function → `sandboxd` survives, only that worker
    recreated) is part of this phase, not deferred. **Without it, no further
    phase can ship.** (UC-08, UC-51.)
- **Phase 2 — Cold path.** `pkg/wasm` engine (wazero) wired into the worker
  pool + `pkg/wasmmod` resolver; `Create/Start/Stop/Destroy/Inspect/Ping/
  ListManaged` on a single module. Capability config (preopens/env).
  Service-layer rewrites for `req.Image` and toolbox-proxy resolution (D14)
  land in this phase. (UC-01..05, 07, 14, 15, 20.)
- **Phase 3 — Toolbox host.** `internal/runtime/wasm/toolhost` — files/exec/
  sessions served from the host; wire v1 toolbox handlers. (UC-21..24, 36.)
- **Phase 4 — Public + platform.** Caddy routing to host-mediated listener,
  port allowlist, custom domains, lifecycle timers, secrets/env injection,
  Resize, admission footprint. (UC-06, 12, 31..35, 40, 50.)
- **Phase 5 — Warm pool + density.** `internal/pool/wasm` pre-instantiation;
  fuel/epoch metering; per-invocation billing export. (UC-09..13, 18, 19, 42, 43.)
- **Phase 6 — Boundary snapshot/clone + durability + AOCR + module catalogue.**
  Host-boundary snapshot, instant clone (+ clone-RNG-reseed parity reusing
  `pkg/clonegen`), the unified `durability` field, drain→checkpoint→rehydrate
  (`checkpoint.go`/`passivate.go`), the redefined reconcile policy, **§4.5
  reconcile audit step** (walk every call site that branches on missing-live-set
  state; explicit handling for `passivated`, `awaiting_runtime`, `durable_offline`,
  `ephemeral` — time-box ~1 day per D18), **snapshot→AOCR push via new
  `pkg/wasmmod/oras_push.go`** (NOT `snapshot_push.go` — see D2), `snapshot_codec.go`
  v1 contract (§4.8.1), `wasm_modules` catalogue, module GC + AOCR keep-last-N
  retention + integrity. (UC-25..30, 44, 45, 51, 52, 54, 55.)
- **Phase 7 — Cluster + facades + docs + SDKs.** Cluster placement/forwarding/
  failover parity, **failover-from-AOCR-snapshot** with clone-generation fencing,
  **live migration off a draining node** (`migrate.go`), Daytona/E2B passthrough,
  three docs pages, 5-SDK constants. (UC-37..39, 47..49, 53, 56.)

Each phase is independently mergeable because the `Runtime` surface stays stable
— exactly the property the Firecracker skeleton was landed to prove.

---

## 11. Non-negotiables checklist (pr-review.md alignment)

- **Idempotency (UC-07).** `createWasmSandbox` reuses the existing
  `request_idempotency` table and the `CreateSandboxWithID` path; module
  resolution is content-addressed so a retry resolves to the same digest.
  `expose_port` parity uses the existing idempotent host-port logic — but WASM
  inbound is host-mediated, so the port pool is *not* walked (returns existing
  URL).
- **Boot-path latency.** `createWasmSandbox` adds compile+instantiate to the
  boot path; warm pool (Phase 5) removes it for the common case. First-call
  (cold-compile) cost is called out explicitly, mirroring the firecracker
  first-call note.
- **Lazy bootstrap.** Engine + module cache use the `atomic.Bool` latch +
  `sync.Mutex` single-flight pattern (canonical: `EnsureLayer4Ready`) for
  one-time per-host setup (cache dir, engine warmup).
- **Failure-path consistency.** `createWasmSandbox` unwinds via
  `wasm.Driver.Destroy` on every post-create error, mirroring the firecracker
  cleanup contract (§4 of pr-review.md). No reliance on reconcile for routine
  cleanup.
- **Cluster (UC-37..39).** All `internal/cluster` changes are no-ops when
  `cfg.EnableCluster` is false; placement counts WASM footprint; regression
  tests next to the files changed.
- **Store fragility.** New `wasm_modules` table + ALTERs land via
  `/add-store-column` with a regression test in `store_test.go`.
- **Restart correctness (§4).** WASM workers do not survive a daemon restart,
  so reconcile is redefined per durability class (§4.5) and rolling updates
  use drain→checkpoint→rehydrate (§4.3). This is the load-bearing correctness
  property for WASM and needs explicit regression tests: a restart with live
  `ephemeral`/`passivatable`/`durable` rows must land each in the right
  terminal/rehydrated state. The new `awaiting_runtime` state (§4.5) needs
  its own test: flip `EnableWasm=false` between restarts and verify
  `passivated` rows are preserved, not destroyed.
- **Worker-crash isolation (D10, P0 RELEASE GATE).** A test MUST spawn a WASM
  module that triggers a panic inside a host function. The test asserts
  (a) `sandboxd` survives, (b) only the affected worker process is killed,
  (c) the supervisor recreates the slot, (d) the sandbox row transitions to
  the correct state per its `durability` class. **This is non-negotiable: it
  is the single test that verifies the architectural property the entire
  WASM plan rests on (§2.1).** Without it, Phase 1 cannot ship and no later
  phase is meaningful — an in-process panic would take down `sandboxd` and
  with it every docker + firecracker + WASM sandbox on the host plus the
  control plane. PR description must explicitly confirm this test exists
  and passes.

---

## 12. Use-case → component traceability matrix

| UC | Delivered by |
|---|---|
| 01,02,03,04,05 | `internal/runtime/wasm/{create,lifecycle}.go`, `internal/service/wasm.go`, `pkg/wasmmod` |
| 06 | `Resize` in `internal/runtime/wasm/lifecycle.go` + `pkg/wasm/fuel.go` |
| 07 | `internal/service/wasm.go` reusing `request_idempotency` + content-addressed `pkg/wasmmod/cache.go` |
| 08 | `pkg/models/types.go` (ValidRuntime), `internal/service/service.go` dispatch, `internal/config` gate |
| 09,11,30 | `internal/pool/wasm/`, `internal/service/wasm_module.go` |
| 10,13,40 | `pkg/capacity/capacity.go` WASM footprint + `internal/pool/wasm` |
| 12,34 | existing lifecycle sweep + `internal/service/wasm.go` (scale-to-zero = idle-stop) |
| 14,15,16,17,20 | `pkg/wasm/capabilities.go`, `internal/runtime/wasm/network.go` |
| 18,19 | `pkg/wasm/fuel.go` (epoch interruption) + engine memory caps |
| 21,22,23,24,26 | `internal/runtime/wasm/toolhost/`, `pkg/wasmmod` (interpreter modules), `internal/pool/wasm` |
| 25,29 | `pkg/wasm/snapshot.go` determinism + reuse of `cmd/toolboxd/clonegen.go` reseed model |
| 27,28 | `pkg/wasm/snapshot.go` (boundary capture, §4.1), `internal/service/wasm_snapshot.go` |
| 31,32 | `pkg/caddy` (reuse) + `internal/runtime/wasm/{network,guest_listen,guest_http}.go` + `pkg/wasm/{wazero_network,wazero_listen,worker/proxy_http}.go` — **shipped** (see [`wasm-networking-finish.md`](./wasm-networking-finish.md) for UC-33) |
| 33 | UC-33 custom domains — **shipped** (`wasm_custom_domains.go`, `UpsertCustomDomainHTTPRouteWithDial`) |
| 35 | `pkg/secrets` (reuse) + env injection in `internal/runtime/wasm/create.go` |
| 36 | `pkg/mounts` (reuse) surfaced as WASI preopens in `pkg/wasm/capabilities.go` |
| 37,38 | `internal/cluster` (reuse) + WASM footprint in placement |
| 39 | `internal/cluster` failover + `durable` re-hydrate from host KV (§4.6); `passivatable`/`ephemeral` recreate per §4.5 |
| 41,42,43 | `internal/observability` (reuse) + `internal/runtime/wasm` + `pkg/wasm/{fuel,net_meter,wazero_wasip1_meter}.go` |
| 44,45 | `internal/service/wasm_module.go` GC + `pkg/wasmmod/validate.go` |
| 46 | graceful drain in `internal/runtime/wasm/driver.go` + `checkpoint.go` (ctx cancel + drain to boundary) |
| 47,48 | 5 SDKs + Daytona/E2B facade translation carrying `runtime:"wasm"` |
| 49 | `docs/src/content/docs/wasm-*.mdx` + `content.config.ts` |
| 50 | mixed dispatch in `internal/service/service.go` (3 drivers coexist) |
| 51 | `Durability` field in `pkg/models/types.go` + store column + driver policy (§4.2) |
| 52 | `internal/runtime/wasm/{checkpoint,passivate}.go` + reconcile policy (§4.3, §4.5) |
| 53 | `internal/runtime/wasm/migrate.go` + `internal/cluster/recovery_replication.go` reuse (§4.4) |
| 54 | `internal/runtime/wasm/statekv/` host KV capability backed by store/`pkg/mounts` (§4.6) |
| 55 | `wasm.Driver.CreateSnapshot` (boundary capture) + `pkg/wasm/snapshot_oci.go` codec + existing `internal/service/snapshot_push.go` (AOCR) — §4.8 |
| 56 | AOCR pull+restore on failover via `internal/cluster/recovery_*.go` + clone-generation fencing (`cmd/toolboxd/clonegen.go`) — §4.8 |

All 56 use cases trace to a concrete component; the 40-minimum bar is exceeded.

---

## 13. Open questions for review

1. **Engine default**: wazero (pure-Go, ship-everywhere) vs. offer wasmtime CGo
   build for compute-heavy operators? Plan assumes wazero default + seam.
2. **Module catalogue scope**: lazy-resolve-on-create only, or also expose
   `POST /v1/wasm-modules` pre-build like `/v1/templates`? Plan keeps catalogue
   internal first, exposes later if needed.
3. **WASI Preview 1 vs Preview 2 (Components) — decided (2026-06-07):**
   Ship **wasip1 first** plus Aerol **P2-shaped compat host modules**
   (`wazero_wasi_compat.go`) and **`aerol/vm/net`** for egress. Do **not**
   block on wazero native P2 — upstream will not implement it. Track wazero
   **latest 1.x** (v1.12.0) for wasip1 fixes only. True Component Model /
   spec-faithful `wasi-http` is a **wasmtime** (`-tags wasmtime`) or
   lower-to-core-wasm axis if needed later.
4. **Do we persist a warm-instance pool table?** Plan says no (in-process,
   cheap to rebuild) — flag if durable slot identity is wanted for metrics
   continuity across daemon restarts.
5. **Default durability class.** Plan defaults to `ephemeral` (max density, loss
   on restart) — confirm that's the right default vs. `passivatable`, given a
   rolling update silently drops `ephemeral` workloads.
6. **Should `durability` be WASM-only?** Non-WASM runtimes already survive
   restarts; plan treats the field as a WASM-only axis (ignored or rejected
   elsewhere). Confirm we don't want a unified durability contract across runtimes.
7. **Crash-loss tolerance for `passivatable`.** Periodic boundary checkpointing
   (`SB_WASM_CHECKPOINT_INTERVAL`) bounds loss but adds overhead. Default off
   (graceful-only) or on with a sane interval?
8. **Verify the `runtime` column has no CHECK/enum constraint** before relying on
   "wasm" rows needing no migration (flagged in §9 store changes).
9. **AOCR snapshot-artifact lifecycle (§4.8).** Each `durable` checkpoint push
   creates an AOCR artifact; periodic pushes create many. Need a retention/GC
   policy (keep-last-N or TTL) so the registry doesn't grow unbounded — does the
   existing snapshot/image GC cover registry-side artifacts, or only local images?
10. **Loss-window SLO.** `SB_WASM_DURABLE_PUSH_INTERVAL` trades crash-loss window
    against AOCR write load. What's the default — drain-only (cheapest, loses all
    work on hard crash) or a bounded interval — and is it per-sandbox overridable?
```

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 9 misses, 6 with cross-model tension resolved in §0 (D14–D19) |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | issues_open | 19 decisions (D1–D19) inlined throughout §1–§13; 1 P0 critical gap = release gate (D10 worker-crash isolation) |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** caught 6 substantive misses this review didn't (D14–D19); all resolved in §0. Strong cross-model agreement on blast-radius (D1), SnapshotPusher reuse (D2), and "overbuilt for likely value" (Step 0 scope question).
- **CROSS-MODEL:** both reviewers independently flagged the in-process blast-radius problem and the SnapshotPusher non-reuse as the two most important gaps. High-confidence signal.
- **UNRESOLVED:** 0 (all 19 D-decisions answered).
- **VERDICT:** ENG CLEARED — review decisions inlined throughout the plan; worker-crash isolation test (D10) is a release-blocking gate; implementation MUST land that test in Phase 1.

