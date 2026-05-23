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

### Manual stop vs sleeping stop

The platform must distinguish between:

- **manual stop**: operator/user explicitly stopped the sandbox; inbound HTTP
  must not auto-wake it.
- **sleeping stop**: lifecycle auto-stop armed wake-on-HTTP; inbound HTTP may
  wake it.

The current `stopped` status alone is not enough to represent both.

### First-request behavior

Recommended behavior:

- sandboxd waits up to `SB_HTTP_WAKE_TIMEOUT` for the sandbox to start,
  then proxies the same HTTP request through.
- if the start does not complete in time, return `503 Service Unavailable`
  with `Retry-After: 2`.

This gives the cleanest UX for normal GET/POST requests while still bounding
request hold time.

## Proposed architecture

### A1. Add a public wake policy and an internal armed-state bit

Add two different concepts:

1. **Public intent**: `Lifecycle.WakeOnHTTP bool`
   - user-facing, persisted, SDK-visible
   - means "this sandbox may wake from HTTP after an auto-stop"
2. **Internal runtime state**: `wake_armed bool`
   - store-only
   - means "this specific stopped sandbox is currently asleep and should wake
     on HTTP"

Why both are needed:

- `WakeOnHTTP` is durable policy.
- `wake_armed` distinguishes lifecycle sleep from manual stop.

Rules:

- manual `StopSandbox` sets `wake_armed = false`
- lifecycle auto-stop for a wake-enabled HTTP sandbox sets `wake_armed = true`
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
  -> lifecycle auto-stop    => stopped, wake_armed=true  (only if WakeOnHTTP && HTTP surfaces exist)
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

## Configuration changes

Add three config knobs:

1. `SB_ENABLE_HTTP_WAKE` (default `false`)
   - global rollout gate
   - sandbox-level `WakeOnHTTP` is ignored unless this is enabled

2. `SB_INTERNAL_INGRESS_ADDR` (default `127.0.0.1:21213`)
   - loopback-only listener Caddy uses for wake-aware HTTP port routes

3. `SB_HTTP_WAKE_TIMEOUT` (default `30s`)
   - max time the ingress proxy waits for a sleeping sandbox to start before
     returning `503 + Retry-After`

## Code changes

### C1. Extend the lifecycle model and store schema

**Files:**

- `pkg/models/types.go`
- `internal/store/store.go`
- `internal/store/store_test.go`

**Changes:**

- add `WakeOnHTTP bool` to `models.Lifecycle`
- add `wake_on_http` column to `sandboxes`
- add `wake_armed` column to `sandboxes`
- thread both fields through create, upsert, get, list, and `UpdateLifecycle`
- keep zero/default behavior identical for old rows

Why this is the root fix:

- policy and runtime state become durable across daemon restart and reconcile

### C2. Add a loopback-only internal ingress proxy package

**Files:**

- `pkg/api/ingressproxy/routes.go` (new)
- `pkg/api/ingressproxy/handlers.go` (new)
- `pkg/api/server.go`

**Changes:**

- add a new unversioned internal route family such as:
  - `GET /__ingress/http/{id}/{port}`
  - `GET /__ingress/http/{id}/{port}/{path...}`
  - same for other HTTP verbs
- these routes are mounted only on the internal loopback listener, not on the
  public API listener
- handler resolves owner, touches activity, optionally wakes, then reverse
  proxies to the sandbox port

Why a separate listener is recommended:

- no new public unauthenticated wake endpoint
- no Caddy-shared bearer token required
- easy to reason about deployment: local Caddy talks to local sandboxd only

### C3. Start a second HTTP server in sandboxd for the loopback ingress proxy

**Files:**

- `cmd/sandboxd/main.go`
- `internal/config/config.go`
- `internal/config/config_test.go`

**Changes:**

- load the new config knobs
- start a second `http.Server` on `SB_INTERNAL_INGRESS_ADDR`
- wire graceful shutdown for both servers
- only enable the listener when Caddy is enabled and `SB_ENABLE_HTTP_WAKE`
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

### C5. Split stop behavior into manual stop vs lifecycle sleep

**Files:**

- `internal/service/service.go`
- `internal/service/events.go`
- `internal/service/lifecycle_test.go`
- `internal/service/service_runtime_flow_test.go`

**Changes:**

- refactor stop flow into an internal helper that accepts a stop mode:
  - manual stop
  - lifecycle sleep
- lifecycle sleep sets `wake_armed=true` before container stop
- manual stop sets `wake_armed=false`
- docker stop/die event handling must preserve wake-enabled HTTP routes when
  `wake_armed=true`, and delete them otherwise
- reconcile must rebuild wake routes for `stopped + wake_armed=true` rows

Why this matters:

- without event-path changes, the docker stop event will tear wake routes down
  even if the lifecycle sweep intended to keep them active

### C6. Add single-flight wake helpers in the service layer

**Files:**

- `internal/service/service.go`
- `internal/service/metrics.go`

**Changes:**

- add a per-sandbox single-flight helper such as `EnsureSandboxAwakeForHTTP`
- if sandbox is already running: no-op
- if sandbox is stopped but `wake_armed=false`: do not start
- if sandbox is stopped and `wake_armed=true`: call `StartSandbox`
- record wake metrics:
  - requests
  - cold starts
  - failures
  - wake duration

### C7. Make API toolbox/session/runtime proxies wake-aware

**Files:**

- `pkg/api/v1/proxy.go`
- `pkg/api/daytona/toolbox.go`
- `pkg/api/e2b/runtime_proxy.go`
- `pkg/api/e2b/handlers.go`
- `pkg/api/e2b/meta.go`

**Changes:**

- replace direct `ToolboxTarget(...)` resolution with wake-aware resolution
- keep E2B `connect` behavior, but map E2B `autoResume` onto the new native
  `WakeOnHTTP` lifecycle field
- make Daytona and v1 toolbox proxies honor the same native wake policy

### C8. Publish HTTP exposed ports differently when wake is enabled

**Files:**

- `internal/service/service.go`
- `internal/service/port_start_additional_test.go`
- `internal/service/cluster_exposure_test.go`

**Changes:**

- update `upsertExposedPortRoute(...)` so HTTP exposure chooses between:
  - direct Caddy -> `containerIP:port` route when `WakeOnHTTP=false`
  - wake-aware Caddy -> internal ingress proxy route when `WakeOnHTTP=true`
- `deleteExposedPortRoute(...)` must delete the correct route family
- do **not** change raw TCP or TLS route behavior in this plan

### C9. Keep reconcile and zombie-GC aware of sleeping routes

**Files:**

- `internal/service/service.go`
- `pkg/caddy/client.go`

**Changes:**

- `gcZombieCaddyEntries(...)` must treat wake HTTP route IDs as live when the
  sandbox row is `stopped + wake_armed=true`
- stopped sleeping sandboxes should not lose their wake routes on reconcile
- started wake-enabled sandboxes should keep the same ingress-proxy route
  shape so `last_active_at` keeps updating on every request

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

- expose `wakeOnHttp` in create/update lifecycle calls across all five SDKs
- add a docs page specifically for serverless HTTP sandboxes and wake-on-
  request behavior
- document the cold-start contract and the fact that TCP/TLS are not included
  in phase 1

## Tests

### Server-side unit

- `internal/store/store_test.go`
  - migration compatibility for `wake_on_http` and `wake_armed`
  - full replace semantics for `UpdateLifecycle`
- `internal/service/lifecycle_test.go`
  - wake-enabled lifecycle sleep arms `wake_armed`
  - manual stop does not arm it
  - stopped/manual rows do not auto-wake
- `internal/service/service_runtime_flow_test.go`
  - sleeping sandbox wakes on HTTP helper
  - concurrent wake requests single-flight to one start
  - capacity failure returns error without mutating state
- `pkg/caddy/client_test.go`
  - wake HTTP route uses internal ingress listener target
  - route IDs are stable in domain and path mode

### API and ingress tests

- `pkg/api/v1/..._test.go`
  - toolbox proxy wakes sleeping sandbox
  - toolbox proxy does not wake manually stopped sandbox
- `pkg/api/e2b/handlers_test.go`
  - `autoResume` maps to native wake policy
- `pkg/api/e2b/runtime_proxy_test.go` (new if needed)
  - runtime proxy wakes sleeping sandbox
- `pkg/api/ingressproxy/..._test.go`
  - GET/POST/PUT requests survive wake and proxy correctly
  - wake timeout returns `503 + Retry-After`

### Cluster tests

- ingress request arriving on non-owner forwards to owner, then wakes there
- orphaned owner still returns the current 410/503 semantics
- sleeping wake routes survive cluster reconcile on ingress nodes

### End-to-end manual run

1. Create sandbox with `stop_if_idle_for` and `wake_on_http=true`.
2. Start an HTTP app and `exposePort(3000)`.
3. Hit the public URL successfully.
4. Wait for lifecycle auto-stop.
5. Hit the same URL again and verify wake + successful response.
6. Manually stop the sandbox.
7. Hit the same URL and verify it does **not** wake.
8. Repeat in cluster mode through a non-owner ingress node.

## Failure modes and invariants

### Invariants

1. Manual stop must never silently become wake-enabled.
2. Destroyed sandboxes never wake.
3. Wake requests must not bypass admission control.
4. Only one cold start runs per sandbox at a time.
5. Wake-enabled HTTP routes must survive reconcile while the sandbox sleeps.
6. TCP host-port and TLS-SNI behavior stay byte-identical in this plan.

### Expected failure behavior

- If admission rejects the wake, return `503`.
- If start times out, return `503` with `Retry-After`.
- If the owner is orphaned in cluster mode, keep existing 410 behavior.
- If the sandbox row exists but the container is gone and start fails, surface
  the existing store/runtime error rather than inventing a new status.

## Rollout

### Phase 1

- ship store fields, service wake helper, and toolbox/runtime auto-wake only
- gate behind `SB_ENABLE_HTTP_WAKE=false` by default
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
- `pkg/models/types.go`

### API and ingress

- `pkg/api/server.go`
- `pkg/api/ingressproxy/routes.go` (new)
- `pkg/api/ingressproxy/handlers.go` (new)
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

- raw TCP/TLS wake-on-connect
- memory snapshot or near-zero cold starts
- per-sandbox autoscaling beyond one instance
- request buffering guarantees for extremely long uploads during cold start
- billing or tenancy metering for sleeping versus running time

## Recommendation

Build this in two server phases:

1. wake-aware control-plane HTTP paths first,
2. then wake-aware exposed HTTP ingress via a loopback sandboxd proxy.

That order keeps the first cut narrow, proves the lifecycle/state model,
and avoids starting with the fragile Caddy/TCP surfaces.