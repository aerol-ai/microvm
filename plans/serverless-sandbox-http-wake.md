# Serverless Sandboxes: Auto-Stop + HTTP Wake

## 20 use cases first

The target shape is not "generic sleeping containers." It is a specific
product behavior: an HTTP-addressable sandbox can stop after idle time,
preserve its filesystem state, and wake when the next HTTP request arrives.

### 1. Preview apps and product surfaces

| # | Use case | Why HTTP wake matters | Main HTTP surface |
|---:|---|---|---|
| 1 | Pull-request preview app | A preview that costs money while idle is much less useful than one that wakes on demand. | `exposePort(3000)` |
| 2 | Feature-branch admin panel | Engineers only open it occasionally; scale-to-zero keeps long-tail branches cheap. | `exposePort(3000)` |
| 3 | Per-customer demo environment | Sales or success teams need it to feel instantly available without paying for 24/7 uptime. | `exposePort(8080)` |
| 4 | White-label customer portal replica | Every tenant can have an isolated server without every tenant holding live CPU/RAM. | `exposePort(3000)` |
| 5 | Support repro UI with seeded data | The environment can sit dormant until a support engineer opens the bug URL. | `exposePort(3000)` |

### 2. Agent-facing HTTP tools and MCP-style servers

| # | Use case | Why HTTP wake matters | Main HTTP surface |
|---:|---|---|---|
| 6 | MCP server for a coding agent | Agents call the tool sporadically; idle periods should not hold a whole sandbox open. | HTTP server inside sandbox |
| 7 | Internal agent tool server | Tool sandboxes should wake per task instead of burning resources between jobs. | HTTP API |
| 8 | Eval harness callback server | The harness only receives traffic during a run; outside the run it should sleep. | HTTP API |
| 9 | RAG query API per workspace | Each workspace can keep its own isolated retrieval stack without permanent runtime cost. | HTTP API |
| 10 | Workflow automation webhook target | An agent or SaaS product can hit a webhook URL that wakes the sandboxed worker. | HTTP webhook |

### 3. Customer and internal APIs

| # | Use case | Why HTTP wake matters | Main HTTP surface |
|---:|---|---|---|
| 11 | Per-customer REST backend | Tenant isolation becomes cheaper when idle tenants fall to zero. | HTTP API |
| 12 | Internal admin API per environment | Rarely used operator surfaces should not stay hot all day. | HTTP API |
| 13 | Secure contractor integration backend | External collaborators can have isolated APIs without persistent host cost. | HTTP API |
| 14 | Third-party callback receiver | Many integrations are bursty; the receiver should wake only when callbacks arrive. | HTTP webhook |
| 15 | Sales demo API with seeded records | Demo environments can look live while actually sleeping most of the day. | HTTP API |

### 4. Data and processing services exposed over HTTP

| # | Use case | Why HTTP wake matters | Main HTTP surface |
|---:|---|---|---|
| 16 | Document conversion or OCR API | CPU-heavy but bursty workloads are a natural fit for wake-on-request. | HTTP API |
| 17 | Image resize or PDF render worker | Requests are sporadic; the worker should not stay running between conversions. | HTTP API |
| 18 | Notebook or report publishing service | A user opens a report URL a few times a day; the service can sleep otherwise. | HTTP app |
| 19 | Lightweight embedding or inference API | Small model-serving sandboxes can scale to zero when traffic disappears. | HTTP API |
| 20 | Staging control-plane replica | A low-traffic internal service can preserve state while avoiding constant runtime cost. | HTTP API |

## Context

The current codebase is already close to a serverless-style stop/start model:

- Per-sandbox lifecycle timers already exist in `pkg/models/types.go` and the
  minute sweep in `internal/service/service.go` already auto-stops or
  auto-destroys sandboxes.
- `StartSandbox` and `StopSandbox` already preserve the container's writable
  layer and reapply mounts, network rules, and Caddy routes on restart.
- The Docker runtime already waits for the in-container `toolboxd` health
  endpoint before reporting a sandbox as started.
- The E2B facade already proves the basic pattern: `connect` explicitly starts
  a stopped sandbox before handing back runtime access.

What is missing is not lifecycle control. What is missing is wake-aware HTTP
 ingress:

- toolbox/session/runtime HTTP paths fail if `ToolboxTarget(...)` sees no
  `ContainerIP`.
- exposed HTTP ports are routed directly by Caddy to the container IP.
- `StopSandbox` and docker stop events tear those routes down.
- public HTTP traffic does not update `last_active_at`, so a busy preview app
  can still look idle to the lifecycle sweep.

## Goal

Support a first-class "resource server" mode where a sandbox:

1. can auto-stop after idle time,
2. keeps its filesystem state,
3. wakes when the next HTTP request arrives,
4. preserves manual stop semantics, and
5. works in both single-node and cluster mode.

## Non-goals (this plan)

- Memory snapshot, VM hibernation, or process-memory resume. This is Docker
  stop/start, not Firecracker suspend.
- Raw TCP or TLS-SNI wake in the first cut. `protocol: "tcp"` and
  `protocol: "tls"` stay as live-only surfaces.
- Multi-instance autoscaling or load balancing for one sandbox.
- Billing, quotas, or tenancy policy beyond the wake mechanics.
- Browser-desktop wake semantics separate from normal HTTP routing.

## Product contract

### What "serverless" means here

In AerolVM, "serverless sandbox" means:

- the sandbox container is stopped when idle,
- no host CPU or memory reservation is held while stopped,
- the writable filesystem and mounted state are restored on start,
- the next HTTP request can trigger a start and then be proxied.

It does **not** mean memory resume or zero-latency cold starts.

### Single public knob: `serverless: true`

Users see exactly one field. Everything else is internal.

```
lifecycle: { serverless: true }
```

`serverless: true` implies:

- `stop_if_idle_for` defaults to 5 minutes if the user did not set one,
- wake-on-HTTP is enabled for all HTTP exposed ports on the sandbox,
- toolbox/session/runtime control-plane HTTP paths also auto-wake.

Users who want a different idle window still set `stop_if_idle_for` themselves.
We do not ship a separate `wakeOnHttp` flag, a `wake_armed` flag, or any
wake-timeout knob in the SDK. The internals exist; the API does not expose
them.

### Three stop classes (internal)

The platform must distinguish three things, not two:

- **manual stop**: operator/user explicitly stopped the sandbox via API.
  Inbound HTTP must not auto-wake it. User must explicitly start.
- **lifecycle sleep**: idle-timeout sweep stopped a serverless sandbox.
  Inbound HTTP wakes it.
- **involuntary stop**: docker stop/die event fired without sandboxd
  initiating it (OOM kill, container exit, host restart, manual `docker
  stop` outside sandboxd). Wake behavior must be a deliberate choice, not
  an accident of which code path noticed first.

The current `stopped` status alone cannot represent these three. We add
`wake_armed` (internal store column, never surfaced in SDK) and an explicit
classification in `internal/service/events.go` for the involuntary case.

Default policy for involuntary stops on a `serverless: true` sandbox: treat
as lifecycle sleep (arm wake). Rationale: a crashed app under load should
come back when traffic arrives, not stay dark until an operator notices.
Operators who need the opposite behavior can disable wake by setting
`serverless: false`.

### First-request behavior

Recommended behavior:

- sandboxd waits up to `SB_HTTP_WAKE_TIMEOUT` for the sandbox to start,
  then proxies the same HTTP request through.
- if the start does not complete in time, return `503 Service Unavailable`
  with `Retry-After: 2`.

This gives the cleanest UX for normal GET/POST requests while still bounding
request hold time.

## Proposed architecture

### A1. Add a public serverless flag and an internal armed-state bit

Two different concepts:

1. **Public intent**: `Lifecycle.Serverless bool`
   - user-facing, persisted, SDK-visible
   - means "this sandbox auto-stops when idle and wakes on HTTP"
   - implies a default `stop_if_idle_for` when none is set
2. **Internal runtime state**: `wake_armed bool`
   - store-only, never surfaced in SDKs or wire types
   - means "this specific stopped sandbox is currently asleep and should wake
     on HTTP"

Why both are needed:

- `Serverless` is durable policy on the sandbox.
- `wake_armed` distinguishes lifecycle sleep from manual stop without
  burdening the user with a second flag.

Rules:

- manual `StopSandbox` sets `wake_armed = false` (stays stopped on HTTP)
- lifecycle auto-stop for a `Serverless` sandbox sets `wake_armed = true`
- involuntary stop (docker event without sandboxd intent) for a `Serverless`
  sandbox sets `wake_armed = true`
- `StartSandbox` clears `wake_armed`
- destroy clears everything

### A2. Route wake-enabled HTTP traffic through sandboxd, not directly to the container

This is the key architectural choice.

For ordinary HTTP exposed ports today, Caddy routes directly to
`containerIP:port`. That is incompatible with serverless behavior because:

- Caddy cannot decide whether to start the sandbox,
- public HTTP requests do not touch `last_active_at`,
- stop currently tears the route down entirely.

For wake-enabled HTTP exposures, Caddy should instead proxy to a new
**loopback-only internal ingress handler in sandboxd**.

That handler will:

1. resolve the sandbox and port,
2. forward to the owner in cluster mode if needed,
3. `TouchSandbox(...)` for activity accounting,
4. if stopped and `wake_armed == true`, single-flight `StartSandbox(...)`,
5. proxy the same request to the sandbox's target port,
6. return `503 + Retry-After` on wake timeout or capacity rejection.

This is the only design in the current architecture that solves **both** wake
and accurate HTTP idle accounting.

### A3. Keep live-only routing for raw TCP and TLS

`protocol: "tcp"` and `protocol: "tls"` stay on the current direct Caddy-l4
paths in the first cut.

Reason:

- they do not have an HTTP request to intercept,
- buffering and replay semantics are different,
- the current host-port and SNI routing code is already a fragile area.

### A4. Auto-wake toolbox/session/runtime HTTP paths inside sandboxd

The control-plane HTTP proxies already pass through sandboxd, so they only
need wake-aware resolution:

- `pkg/api/v1/proxy.go`
- `pkg/api/daytona/toolbox.go`
- `pkg/api/e2b/runtime_proxy.go`

Instead of calling `ToolboxTarget(...)` directly and failing on empty
`ContainerIP`, these paths should call a new helper such as
`EnsureSandboxAwakeForHTTP(...)` and then resolve the toolbox endpoint.

### A5. Preserve the current Docker start contract

Do not invent a new runtime contract. Reuse the existing one:

- `StartSandbox(...)` re-admits capacity,
- re-establishes mounts,
- starts the container,
- waits for `toolboxd` health,
- reapplies network rules,
- republishes routes.

The wake path should be a thin wrapper around the existing start path, with a
single-flight guard so concurrent HTTP requests do not race multiple starts.

## State machine

Recommended internal state model:

```text
started
  -> manual stop            => stopped, wake_armed=false
  -> lifecycle auto-stop    => stopped, wake_armed=true  (only if Serverless && HTTP surfaces exist)
  -> involuntary stop       => stopped, wake_armed=Serverless
  -> destroy                => destroyed

stopped, wake_armed=true
  -> HTTP request           => start -> started
  -> manual start           => started
  -> destroy                => destroyed

stopped, wake_armed=false
  -> manual start           => started
  -> HTTP request           => no wake
```

The status enum can stay `started/stopped/error/destroyed`; the new behavior
is carried by `wake_armed`.

## Design decisions

These are the questions the first draft of this plan left unanswered. They
shape C2, C4, C5, C6, C8, and C9 below — pin them down before implementation.

### D1. Cluster routing: forwarding happens at sandboxd, not Caddy

In cluster mode, a public HTTP request can land on any node's Caddy. The
sandbox is owned by exactly one node at any time.

Decision: Caddy on every node routes wake-enabled HTTP requests to its **own**
loopback ingress listener. The ingress handler then checks ownership in the
local cluster state, and if this node is not the owner, it reverse-proxies the
full request to the owner's loopback listener over the existing in-cluster
mTLS/auth path (the same channel `internal/cluster/forward.go` already uses
for control-plane forwarding).

Consequences:

- Caddy on each node only ever dials `127.0.0.1:21213`. It does not need to
  know about cross-node sandbox placement. Caddy route generation stays
  identical on every node.
- The owner runs the single-flight start. Non-owners never start sandboxes.
- `wake_armed` is local to the owner's SQLite. After an owner change
  (`internal/cluster/recovery_replication.go`), the new owner reconstructs
  `wake_armed` from `Serverless && status=stopped` — i.e., a serverless sandbox
  that is stopped on a new owner is treated as wake-armed by default. This
  matches the involuntary-stop policy.
- No new Caddy cross-node routes, no new public listener, no new auth
  surface. The existing cluster-internal forward channel is reused.

### D2. Request body buffering: bounded buffer, 413 above the cap

A POST/PUT with a body during cold start cannot be safely streamed without
buffering: if start fails after the body is partially read, the request
cannot be retried and the client sees a half-applied write.

Decision: when the sandbox is `stopped + wake_armed=true`, the ingress
handler buffers the request body up to **8 MiB** (configurable via
`SB_HTTP_WAKE_MAX_BUFFER`, operator-only). If the body exceeds the cap, the
handler returns `413 Payload Too Large` immediately, without starting the
sandbox. If the body fits, it is buffered, the sandbox is started, then the
buffered body is replayed to the container.

When the sandbox is already running, no buffering — pass-through proxy.

This is a deliberate UX cliff: serverless sandboxes are not appropriate for
large uploads. Document it.

### D3. Capacity-full wake: bounded retries, then circuit-break

A wake that fails admission must not silently stick. Today's plan would
leave the sandbox `stopped + wake_armed=true` and return 503 on every
subsequent request indefinitely.

Decision: per-sandbox failure counter (`wake_consecutive_failures`,
in-memory only). After 5 consecutive admission failures within a 60s window,
the ingress handler short-circuits: returns `503 + Retry-After: 60` without
attempting to wake, for 60 seconds. After 60s the counter resets and wakes
resume. A `aerolvm_wake_circuit_open` metric exposes the state.

This bounds the failure-mode blast radius without introducing a new
"stuck-asleep" sandbox status.

### D4. Long-lived connections (WebSocket, SSE, streaming): explicit support

The ingress proxy must support `Upgrade` (WebSocket) and streaming response
bodies (SSE, chunked). The reverse proxy implementation uses
`httputil.ReverseProxy` with a configured `Transport` that handles `Upgrade`
correctly, and `FlushInterval: -1` for unbuffered streaming.

Activity accounting: `TouchSandbox` fires at request *start* AND on a 30s
ticker for the duration of an open connection. Without the ticker, a
long-lived MCP/WebSocket session would only touch activity at handshake and
the lifecycle sweep could auto-stop a busy connection.

### D5. Failure-path consistency for wake-armed transitions

When lifecycle sweep arms wake on a sandbox, two writes must succeed:

1. Store: `status=stopped, wake_armed=true`
2. Caddy: wake route is upserted (loopback target instead of containerIP)

Rule: write Caddy first, then store. If Caddy upsert fails, abort the stop —
sandbox keeps running, sweep retries next minute. If Caddy succeeds but
store write fails, reconcile will rebuild from `Serverless && status=stopped`
on next sweep (D1's reconstruction rule).

The inverse order would leave a window where the sandbox is recorded as
sleeping but the wake route does not exist, so wake requests would 502
through Caddy. Caddy-first is the safer order.

### D6. Wake timeout is hardcoded, not configured

The plan's earlier `SB_HTTP_WAKE_TIMEOUT` knob is removed. The ingress
handler waits a fixed **15 seconds** for a cold start before returning
`503 + Retry-After: 2`. 15s fits inside most default HTTP client timeouts
(curl: 0, Go default: 0 / explicit, browsers: ~30s but variable) and matches
the existing `StartSandbox` end-to-end latency budget.

If operators need a different value later, add the knob then.

## Configuration changes

Operator-only. No user-visible config additions.

1. `SB_ENABLE_SERVERLESS` (default `false`)
   - temporary global rollout gate, removed before GA
   - sandbox-level `Serverless` is ignored unless this is enabled
2. `SB_INTERNAL_INGRESS_ADDR` (default `127.0.0.1:21213`)
   - loopback-only listener Caddy uses for wake-aware HTTP port routes
3. `SB_HTTP_WAKE_MAX_BUFFER` (default `8388608` — 8 MiB)
   - body buffer cap for cold-start requests (see D2)

Removed from the earlier draft: `SB_HTTP_WAKE_TIMEOUT` is hardcoded to 15s
(see D6). No user-facing SDK or wire knobs are added.

## Code changes

### C1. Extend the lifecycle model and store schema

**Files:**

- `pkg/models/types.go`
- `internal/store/store.go`
- `internal/store/store_test.go`

**Changes:**

- add `Serverless bool` to `models.Lifecycle`
- add `serverless` column to `sandboxes`
- add `wake_armed` column to `sandboxes` (internal, not surfaced)
- thread both fields through create, upsert, get, list, and `UpdateLifecycle`
- in `CreateSandbox` / `UpdateLifecycle`: if `Serverless=true` and the user
  did not set `stop_if_idle_for`, default it to 5 minutes
- keep zero/default behavior identical for old rows (Serverless=false,
  wake_armed=false)

Why this is the root fix:

- policy and runtime state become durable across daemon restart and reconcile
- one user-facing flag (`Serverless`) controls both stop and wake behavior

### C2. Add a loopback-only internal ingress proxy package

**Files:**

- `pkg/api/ingressproxy/routes.go` (new)
- `pkg/api/ingressproxy/handlers.go` (new)
- `pkg/api/ingressproxy/bodybuffer.go` (new — see D2)
- `pkg/api/server.go`

**Changes:**

- add a new unversioned internal route family covering all HTTP verbs:
  - `/__ingress/http/{id}/{port}`
  - `/__ingress/http/{id}/{port}/{path...}`
- these routes are mounted only on the internal loopback listener, not on the
  public API listener
- handler order:
  1. resolve sandbox by ID
  2. if cluster mode and this node is not the owner: forward to owner's
     loopback ingress over the existing in-cluster channel (D1), and stop
  3. `TouchSandbox(...)` for activity accounting
  4. if `stopped + wake_armed=true`: buffer body up to cap (D2), then
     single-flight `EnsureSandboxAwakeForHTTP(...)`
  5. reverse proxy to the sandbox's target port; `httputil.ReverseProxy`
     with `FlushInterval: -1` and `Upgrade` handling for WebSocket/SSE (D4)
  6. start a 30s activity ticker for the request duration if the response
     is long-lived (D4)
- return `503 + Retry-After: 2` on wake timeout, `503 + Retry-After: 60`
  when the per-sandbox circuit is open (D3), `413` when body exceeds the
  buffer cap during cold start (D2)

Why a separate listener:

- no new public unauthenticated wake endpoint
- no Caddy-shared bearer token required
- easy to reason about deployment: local Caddy always talks to local sandboxd

### C3. Start a second HTTP server in sandboxd for the loopback ingress proxy

**Files:**

- `cmd/sandboxd/main.go`
- `internal/config/config.go`
- `internal/config/config_test.go`

**Changes:**

- load the new config knobs (`SB_ENABLE_SERVERLESS`,
  `SB_INTERNAL_INGRESS_ADDR`, `SB_HTTP_WAKE_MAX_BUFFER`)
- start a second `http.Server` on `SB_INTERNAL_INGRESS_ADDR`
- wire graceful shutdown for both servers
- only enable the listener when Caddy is enabled and `SB_ENABLE_SERVERLESS`
  is on

### C4. Add wake-aware HTTP route builders in the Caddy client

**Files:**

- `pkg/caddy/client.go`
- `pkg/caddy/client_test.go`

**Changes:**

- add helpers for wake-enabled HTTP routes, for example:
  - `UpsertWakeHTTPPortRoute(...)`
  - `DeleteWakeHTTPPortRoute(...)`
- these routes match the existing public host/path but dial the internal
  ingress listener instead of `containerIP:port`
- preserve the existing direct route helpers for non-wake HTTP exposures
- add route-ID helpers so reconcile keeps wake routes instead of garbage
  collecting them as zombies

### C5. Classify stop into three modes

**Files:**

- `internal/service/service.go`
- `internal/service/events.go`
- `internal/service/lifecycle_test.go`
- `internal/service/service_runtime_flow_test.go`

**Changes:**

- refactor stop flow into an internal helper that accepts an explicit stop
  mode:
  - `stopModeManual` — explicit API call, sets `wake_armed=false`
  - `stopModeLifecycle` — idle-sweep auto-stop, sets `wake_armed=Serverless`
  - `stopModeInvoluntary` — docker stop/die event without sandboxd intent,
    sets `wake_armed=Serverless` (D-section default)
- lifecycle and involuntary stops upsert the wake-enabled Caddy route
  **before** flipping the store row, per D5
- docker event handler in `internal/service/events.go` distinguishes
  involuntary stops from sandboxd-initiated ones via an "expected stop" set
  populated by `StopSandbox` and the lifecycle sweep
- reconcile must rebuild wake routes for `stopped + wake_armed=true` rows
  AND for `Serverless && stopped` rows where `wake_armed` was lost across
  daemon restart (defensive: matches D1's reconstruction rule)

Why this matters:

- without explicit classification, a crashed container looks identical to a
  manual stop, and the wake route gets torn down by accident
- D5's "Caddy first, store second" ordering needs a single chokepoint, not
  three parallel call sites

### C6. Add single-flight wake helpers in the service layer

**Files:**

- `internal/service/service.go`
- `internal/service/metrics.go`

**Changes:**

- add a per-sandbox single-flight helper `EnsureSandboxAwakeForHTTP`
  (canonical pattern: `Service.EnsureLayer4Ready` — `atomic.Bool` latch +
  `sync.Mutex` single-flight)
- if sandbox is already running: no-op
- if sandbox is stopped but `wake_armed=false`: return a sentinel error so
  the ingress handler can respond appropriately (do not start)
- if sandbox is stopped and `wake_armed=true`: call `StartSandbox` under
  the per-sandbox single-flight; on admission failure increment the
  per-sandbox circuit counter (D3); on 5 failures inside 60s, open the
  circuit and return circuit-open sentinel for 60s
- record wake metrics:
  - `aerolvm_wake_requests_total`
  - `aerolvm_wake_cold_starts_total`
  - `aerolvm_wake_failures_total{reason=...}`
  - `aerolvm_wake_duration_seconds` (histogram)
  - `aerolvm_wake_circuit_open` (gauge, per-sandbox)

### C7. Make API toolbox/session/runtime proxies wake-aware

**Files:**

- `pkg/api/v1/proxy.go`
- `pkg/api/daytona/toolbox.go`
- `pkg/api/e2b/runtime_proxy.go`
- `pkg/api/e2b/handlers.go`
- `pkg/api/e2b/meta.go`

**Changes:**

- replace direct `ToolboxTarget(...)` resolution with wake-aware resolution
  (calls `EnsureSandboxAwakeForHTTP` before resolving)
- keep E2B `connect` behavior. **Do not** map E2B `autoResume` onto
  `Serverless` — they mean different things:
  - `autoResume` is an SDK convenience flag for `connect()` that resumes a
    paused sandbox if needed; it does not opt the sandbox into
    server-driven HTTP wake
  - `Serverless` is server-side policy that auto-stops on idle and wakes on
    any HTTP request from any client
  - the E2B facade should continue to honor `autoResume` for its own
    connect-time semantics and separately accept `serverless` in the
    AerolVM-native metadata field for opt-in serverless behavior
- make Daytona and v1 toolbox proxies honor the native `Serverless` policy

### C8. Publish HTTP exposed ports differently when wake is enabled

**Files:**

- `internal/service/service.go`
- `internal/service/port_start_additional_test.go`
- `internal/service/cluster_exposure_test.go`

**Changes:**

- update `upsertExposedPortRoute(...)` so HTTP exposure chooses between:
  - direct Caddy -> `containerIP:port` route when `Serverless=false`
  - wake-aware Caddy -> internal ingress proxy route when `Serverless=true`
- `deleteExposedPortRoute(...)` must delete the correct route family
- per D5: when transitioning a route from direct to wake-aware (or vice
  versa during `UpdateLifecycle`), upsert the new route first, then delete
  the old
- do **not** change raw TCP or TLS route behavior in this plan

### C9. Keep reconcile and zombie-GC aware of sleeping routes

**Files:**

- `internal/service/service.go`
- `internal/cluster/recovery_replication.go`
- `pkg/caddy/client.go`

**Changes:**

- `gcZombieCaddyEntries(...)` must treat wake HTTP route IDs as live when the
  sandbox row is `stopped + wake_armed=true` OR `Serverless && stopped`
  (defensive — covers the case where `wake_armed` was not persisted)
- stopped sleeping sandboxes must not lose their wake routes on reconcile
- started serverless sandboxes keep the same ingress-proxy route shape so
  every request flows through sandboxd and `last_active_at` updates. The
  per-request loopback hop is the tax for accurate idle accounting; measure
  the overhead before committing to this for non-serverless sandboxes
- cluster recovery (`recovery_replication.go`): when a node becomes the new
  owner of a serverless sandbox in `stopped` state, set `wake_armed=true`
  and install the wake route (per D1's reconstruction rule)

### C10. Extend SDKs and docs after the server contract is stable

**Files:**

- `sdk/typescript/src/internal/client.ts`
- `sdk/typescript/src/internal/client.test.ts`
- `sdk/python/...`
- `sdk/go/...`
- `sdk/rust/...`
- `sdk/java/...`
- `docs/src/content/docs/...` (new top-level page)
- `docs/src/content.config.ts`

**Changes:**

- expose `serverless` boolean in create/update lifecycle calls across all
  five SDKs (TypeScript, Python, Go, Rust, Java)
- add a single docs page (e.g. `serverless.mdx`) covering the serverless
  model end-to-end, with five-tab examples (`syncKey="lang"`) per the
  project rule
- document:
  - what `serverless: true` does (auto-stop + wake on HTTP)
  - the default 5-minute idle window and how to override
  - cold-start latency expectations (~hundreds of ms to seconds)
  - the 8 MiB body cap during cold start (D2)
  - that TCP/TLS exposures stay always-on in phase 1
  - that manual `stop` keeps the sandbox stopped — HTTP will not wake it
- register the new page in `docs/src/content.config.ts` (file is
  `content.config.ts`, not `content/config.ts`)

## Tests

### Server-side unit

- `internal/store/store_test.go`
  - migration compatibility for `serverless` and `wake_armed` columns
  - full replace semantics for `UpdateLifecycle`
  - default `stop_if_idle_for` applied when `Serverless=true` and idle is unset
- `internal/service/lifecycle_test.go`
  - lifecycle sleep on a serverless sandbox arms `wake_armed`
  - manual stop never arms it (even on serverless sandboxes)
  - involuntary docker stop on a serverless sandbox arms it
  - involuntary docker stop on a non-serverless sandbox does not arm it
  - reconcile rebuilds `wake_armed` for `Serverless && stopped` rows after
    daemon restart (D1 reconstruction)
- `internal/service/service_runtime_flow_test.go`
  - sleeping sandbox wakes on HTTP helper
  - concurrent wake requests single-flight to one start
  - capacity failure returns error without mutating store state
  - D3: 5 consecutive capacity failures open the circuit; circuit reopens
    after 60s
- `pkg/caddy/client_test.go`
  - wake HTTP route uses internal ingress listener target
  - route IDs are stable in domain and path mode
  - D5 ordering: route upsert happens before store transition

### API and ingress tests

- `pkg/api/v1/..._test.go`
  - toolbox proxy wakes sleeping serverless sandbox
  - toolbox proxy does not wake manually stopped sandbox
- `pkg/api/e2b/handlers_test.go`
  - `autoResume` keeps its existing connect-time semantics (does not
    auto-enable serverless)
  - explicit `serverless` metadata field opts in correctly
- `pkg/api/e2b/runtime_proxy_test.go` (new if needed)
  - runtime proxy wakes sleeping sandbox
- `pkg/api/ingressproxy/..._test.go`
  - GET/POST/PUT requests survive wake and proxy correctly
  - wake timeout returns `503 + Retry-After: 2`
  - D2: POST body within 8 MiB is buffered and replayed after wake
  - D2: POST body exceeding 8 MiB returns 413 without starting the sandbox
  - D4: WebSocket Upgrade survives wake and stays open
  - D4: SSE streaming responses are not buffered (FlushInterval=-1)
  - D4: 30s activity ticker fires for long-lived connections

### Cluster tests

- D1: ingress request arriving on non-owner forwards to owner's loopback
  ingress, then wakes there
- D1: after owner change, the new owner reconstructs `wake_armed=true` from
  `Serverless && stopped` and accepts subsequent wake requests
- orphaned owner still returns the current 410/503 semantics
- sleeping wake routes survive cluster reconcile on ingress nodes
- cluster-mode regression: `cfg.EnableCluster=false` keeps all new cluster
  code paths as no-ops (`Noop` contract)

### End-to-end manual run

1. Create sandbox with `serverless: true` (no explicit idle timeout —
   verify it defaults to 5 minutes).
2. Start an HTTP app and `exposePort(3000)`.
3. Hit the public URL successfully.
4. Wait for lifecycle auto-stop.
5. Hit the same URL again and verify wake + successful response within 15s.
6. Send a POST with a 1 MiB body to a sleeping sandbox — verify wake +
   correct delivery.
7. Send a POST with a 16 MiB body to a sleeping sandbox — verify `413`
   without starting the sandbox.
8. Open a WebSocket to a sleeping sandbox — verify upgrade survives wake
   and the connection stays open across the 5-minute mark.
9. Manually stop the sandbox; hit the URL and verify it does **not** wake.
10. Repeat steps 5 and 8 in cluster mode through a non-owner ingress node.
11. Kill the owner mid-session; verify the new owner accepts wake requests
    after recovery.

## Failure modes and invariants

### Invariants

1. Manual stop must never silently become wake-enabled.
2. Destroyed sandboxes never wake.
3. Wake requests must not bypass admission control.
4. Only one cold start runs per sandbox at a time (single-flight).
5. Wake-enabled HTTP routes must survive reconcile and daemon restart while
   the sandbox sleeps.
6. TCP host-port and TLS-SNI behavior stay byte-identical in this plan.
7. Caddy route upsert always precedes the store transition that flips
   `wake_armed` (D5 ordering).
8. The SDK surface for serverless is exactly one boolean: `serverless`. No
   additional knobs are added at the user-facing layer.

### Expected failure behavior

- If admission rejects the wake, return `503`.
- If start times out, return `503` with `Retry-After`.
- If the owner is orphaned in cluster mode, keep existing 410 behavior.
- If the sandbox row exists but the container is gone and start fails, surface
  the existing store/runtime error rather than inventing a new status.

## Rollout

### Phase 1

- ship store fields (`serverless`, `wake_armed`), service wake helper, the
  three stop-mode classification, and toolbox/runtime auto-wake only
- gate behind `SB_ENABLE_SERVERLESS=false` by default
- no public HTTP port wake yet

### Phase 2

- ship internal ingress listener and wake-aware HTTP exposure routes
- enable on a single-node staging environment first
- verify idle accounting by hitting an exposed HTTP route repeatedly and
  confirming the lifecycle sweep does not stop an active sandbox

### Phase 3

- enable in one cluster environment
- verify non-owner ingress wake, reconcile stability, and route GC behavior
- only then expose the SDK and docs surface publicly

## Files that change

### Core server

- `cmd/sandboxd/main.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/service/service.go`
- `internal/service/events.go`
- `internal/service/metrics.go`
- `internal/store/store.go`
- `internal/store/store_test.go`
- `internal/cluster/recovery_replication.go` (D1 reconstruction)
- `pkg/models/types.go`

### API and ingress

- `pkg/api/server.go`
- `pkg/api/ingressproxy/routes.go` (new)
- `pkg/api/ingressproxy/handlers.go` (new)
- `pkg/api/ingressproxy/bodybuffer.go` (new — D2)
- `pkg/api/v1/proxy.go`
- `pkg/api/daytona/toolbox.go`
- `pkg/api/e2b/runtime_proxy.go`
- `pkg/api/e2b/handlers.go`
- `pkg/api/e2b/meta.go`

### Routing

- `pkg/caddy/client.go`
- `pkg/caddy/client_test.go`

### SDKs and docs

- `sdk/typescript/...`
- `sdk/python/...`
- `sdk/go/...`
- `sdk/rust/...`
- `sdk/java/...`
- `docs/src/content/docs/...` (new top-level page)
- `docs/src/content.config.ts`

## Estimated scope

- **Phase 1:** medium server change
- **Phase 2:** large server/routing change
- **Phase 3:** medium SDK/docs pass

Roughly, this is one meaningful server feature, not a one-file tweak. The
main complexity is not waking a container; it is making wake semantics coexist
with Caddy routing, lifecycle stop logic, docker event handling, reconcile,
and cluster forwarding.

## What this plan does not close

- raw TCP/TLS wake-on-connect (always-on in phase 1)
- memory snapshot or near-zero cold starts (Docker stop/start only)
- per-sandbox autoscaling beyond one instance
- request bodies larger than 8 MiB during cold start (intentional D2 cliff)
- billing or tenancy metering for sleeping versus running time
- per-request loopback hop overhead for non-serverless sandboxes (only
  serverless sandboxes pay the hop tax; non-serverless keep direct routing)

## Recommendation

Build this in two server phases:

1. wake-aware control-plane HTTP paths first,
2. then wake-aware exposed HTTP ingress via a loopback sandboxd proxy.

That order keeps the first cut narrow, proves the lifecycle/state model,
and avoids starting with the fragile Caddy/TCP surfaces.