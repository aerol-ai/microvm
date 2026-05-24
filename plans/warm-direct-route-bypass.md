# Warm Direct-Route Bypass for Serverless HTTP Ingress

## 15 use cases first

The target shape is not "speed up the proxy." It is a specific scaling
property: at high concurrent warm traffic per node (10k–100k RPS), every
hop sandboxd adds on the warm path becomes a CPU, memory, FD, and SQLite
bottleneck. The fix is to put Caddy in direct contact with the container
the moment a sandbox is awake, and pull it back to the wake-aware shape
the moment it is not.

### 1. High-throughput preview / customer surfaces

| # | Use case | Why direct routing matters | Symptom without it |
|---:|---|---|---|
| 1 | Pull-request preview that goes viral after a launch | Once warm, a preview can sustain thousands of RPS; routing every byte through sandboxd doubles socket count and adds a hop of latency. | Tail latency spikes once a single preview crosses ~500 RPS, even though the container has headroom. |
| 2 | Per-tenant customer portal handling steady internal traffic | Each warm tenant pays the ingress-proxy hop forever; on a node hosting 1k warm tenants the hop dominates CPU. | Node sandboxd CPU sits above 60% under load that the containers themselves barely notice. |
| 3 | White-label customer surface serving static assets through the container | Every asset request pays the extra hop; large pages amplify the overhead by their asset count. | First-paint timing for warm tenants is 30–80 ms slower than the direct measurement suggests it should be. |
| 4 | Sales demo environment under a load test | The demo is warm for the whole demo; the proxy hop becomes the variable the demo wasn't designed to test. | Demo numbers don't match the "real" perf the product team measured directly against the container. |
| 5 | Notebook publishing surface streaming large outputs | Streaming response bodies are double-buffered through the ingress proxy's reverse-proxy goroutine. | Throughput on a single warm notebook tops out at ~80% of the container's direct rate. |

### 2. Agent and integration backends

| # | Use case | Why direct routing matters | Symptom without it |
|---:|---|---|---|
| 6 | Agent-facing tool sandbox running a long warm session | Per-call latency adds up over a multi-turn agent loop; the ingress hop is a hidden tax. | Agent end-to-end loops are noticeably slower than a direct curl against the same container. |
| 7 | RAG query API under a steady warm workload | Every retrieval pays the proxy hop; pages of vectors flow through sandboxd's goroutine pool. | sandboxd memory footprint grows linearly with RAG concurrency even though the data lives in the container. |
| 8 | Webhook receiver handling a burst from an upstream SaaS | The burst arrives all at once; the ingress proxy's pending caps shed load that the warm container could have absorbed. | 503 responses to webhook deliveries during bursts when the container is idle and ready. |
| 9 | Eval harness callback URL under a long run | Every call traverses sandboxd; the harness sees jitter that doesn't exist when the eval is run locally. | Eval timing graphs show a sandboxd-correlated stair pattern unrelated to the model. |
| 10 | Workflow automation worker behind an internal HTTP queue | The worker is warm and busy; the proxy hop adds queueing where there should be none. | Queue depth grows under load even though the worker is not the bottleneck. |

### 3. Data, processing, and streaming services

| # | Use case | Why direct routing matters | Symptom without it |
|---:|---|---|---|
| 11 | Document conversion API processing large uploads | Upload bytes are buffered/streamed through sandboxd; large files double the memory footprint. | sandboxd memory grows with the largest concurrent upload, not with the count of concurrent uploads. |
| 12 | Image / PDF render worker streaming binary responses | Response bytes are streamed through sandboxd's reverse proxy; FlushInterval has overhead per chunk. | Throughput on warm renders is consistently below what the container can produce directly. |
| 13 | Inference API serving model responses to a hot tenant | Every prediction pays the hop; for small-payload high-RPS inference the hop dominates. | p50 latency on a hot inference tenant is 15–40 ms above the container's own p50. |
| 14 | SSE / long-poll endpoint with thousands of concurrent connections | Each open SSE connection holds a sandboxd goroutine + downstream + upstream sockets. | sandboxd FD count climbs into the hundreds of thousands; LimitNOFILE has to be raised aggressively. |
| 15 | WebSocket app with many simultaneous warm clients | WebSocket Upgrade pins a goroutine + sockets per connection across sandboxd for the connection's lifetime. | sandboxd is the FD / goroutine bottleneck on the node, not the container. |

## Scope — what is and is not changing

AerolVM carries two completely separate kinds of HTTP traffic. This plan
touches exactly one of them.

### Path A — SDK control-plane traffic — UNCHANGED

When an SDK call runs `sandbox.files.write(...)`,
`sandbox.commands.run(...)`, `sandbox.sessions.create(...)`, or any
other `/v1/sandboxes/{id}/...` operation, the traffic goes:

```
SDK
  └─ HTTPS POST https://<api-host>/v1/sandboxes/{id}/fs/write
       └─ Caddy
            route: API route, fixed upstream sandboxd:21212
            └─ sandboxd HTTP API (pkg/api/v1/routes.go)
                 • Auth middleware (PAT token check)
                 • Resolver.WakeAwareToolboxTarget(id)
                      └─ EnsureSandboxAwakeForHTTP — wakes if stopped
                 • Reverse proxy to in-container toolboxd (port 2280)
                      └─ toolboxd (cmd/toolboxd) inside container
                           • executes the fs / commands / sessions op
```

This path **always** terminates at sandboxd because sandboxd:
- validates the PAT token,
- owns the wake decision (`EnsureSandboxAwakeForHTTP` is the chokepoint
  that triggers cold-start if the sandbox is stopped),
- knows the current container IP (it may have changed after a
  Stop→Start cycle),
- forwards to `toolboxd` — the in-container agent that actually
  performs the filesystem write or command execution.

This plan does NOT change one line of Path A. `cmd/toolboxd`,
`WakeAwareToolboxTarget`, the `/v1/sandboxes/{id}/...` mux entries,
the PAT middleware, the Daytona / E2B facade routes, and every
toolbox / session / runtime proxy all keep working exactly as they
do today. Bypassing sandboxd here is not an option — it would expose
`toolboxd` to the public without authentication, and there is no
mechanism that would let stock Caddy validate the PAT or pick the
right ContainerIP after a wake.

### Path B — User-exposed port traffic — CHANGES IN PHASE 1

When end-users hit the customer's app running inside the sandbox via
`sandbox.exposePort(3000)`, the traffic goes:

```
End user
  └─ HTTPS GET https://{id}-3000.{domain}/api/whatever
       └─ Caddy
            today:    route → sandboxd ingress proxy → container:3000
            bypass:   route → container:3000 directly (when warm)
                 └─ Customer's Node / Python / Go process inside container
```

There is no PAT, no SDK involvement, no `toolboxd` involvement — it
is the customer's *own* HTTP server addressed by the public per-port
hostname. This is the traffic that the bypass eliminates the
sandboxd hop for. Wake-on-request still happens (next section), but
once warm, Caddy talks straight to the container.

### Why bypassing Path B is safe and Path A is not

| Concern | Path A (SDK) | Path B (exposed port) |
|---|---|---|
| Authentication | PAT validated by sandboxd | None — customer app owns its own auth |
| Target inside container | `toolboxd` on port 2280 | Customer app on its exposed port |
| Public reachability of the target | Must NEVER be public (would let anyone exec into the sandbox) | *Must* be public — that is the whole point of exposePort |
| Wake-on-request mechanism | sandboxd at the API layer | Route shape (see next section) |
| Plan changes this? | No | Yes (HTTP in Phase 1) |

### Operations that stay in sandboxd's hands

Even after Phase 1 of the bypass lands, sandboxd still owns:

1. Every SDK call (Path A above).
2. Every Daytona / E2B facade call (`/daytona/...`, `/e2b/...`,
   same shape as Path A with different URL prefixes).
3. Cold-start wake — sandboxd is still the only thing that knows
   how to invoke `StartSandbox`.
4. Lifecycle — Create / Stop / Start / Destroy / Snapshot all go
   through sandboxd's HTTP API.
5. Caddy admin writes that install / remove / flip route shapes.
6. Cluster placement — Raft FSM, owner-routing, recovery replicas.
7. Activity-floor signal — sandboxd's netstats poller still observes
   per-sandbox bytes-in to keep the idle sweep correct (this is how
   we replace the per-request `TouchSandbox` that the bypass removes
   from Path B).

## Context — what is in place today

### Warm-aware ingress flow

A serverless HTTP sandbox today follows this path on every request:

```
Internet
   │
   ▼
Caddy (public HTTPS)
   │  match host: {id}-{port}.{domain}
   │  route: "{id}-{port}-wake" (wake-aware shape)
   ▼
sandboxd ingress proxy (loopback InternalIngressAddr, e.g. 127.0.0.1:21213)
   │  /__ingress/http/{id}/{port}{path}
   │  IsSandboxStarted preflight     ─── SQLite, single-conn pool
   │  acquirePending / acquireBuffer ─── admission counters
   │  WakeAwarePortTarget            ─── store.Get + (cold path) StartSandbox
   │  probeOnce                      ─── TCP dial to verify upstream readiness
   │  TouchSandbox                   ─── debounced last_active_at flush
   │  activity ticker                ─── periodic touch for long streams
   │  httputil.ReverseProxy          ─── one goroutine + 2 sockets per request
   ▼
Container IP : port
```

The route shape is installed by `installHTTPPortRoute` in
`internal/service/service.go:1762`, which calls
`pkg/caddy.UpsertWakeHTTPPortRoute` (`pkg/caddy/client.go:266`). The
wake-aware route's upstream is the loopback `InternalIngressAddr`, so
Caddy's reverse proxy goes through sandboxd for every request — warm or
cold — for the lifetime of the route.

The same shape exists for TCP (`UpsertWakeTCPRoute` → `InternalL4WakeAddr`)
and TLS-SNI (`UpsertWakeTLSSNIRoute` → per-exposure Unix socket).
`internal/service/l4wake.go` implements the L4 wake proxy; the same
"every byte traverses sandboxd" property applies.

### Today's bypass: non-serverless sandboxes only

Non-serverless HTTP exposures already use a direct Caddy → container
route shape: `UpsertPortRoute` (`pkg/caddy/client.go:204`) installs
`{id}-{port}.{domain}` → `containerIP:port` and stays that way until
Stop / Destroy tears it down. There is no sandboxd hop. This is the
shape we want serverless to converge to *while warm*, then snap back
to the wake-aware shape on stop.

### Why every byte traverses sandboxd today

The wake-aware shape exists because Caddy itself does not know:
- whether the sandbox is currently running (so where to dial),
- whether to wake the sandbox first if it is not,
- how to update `last_active_at` so the idle sweep doesn't stop a busy
  sandbox mid-conversation,
- how to apply per-sandbox admission control during cold-start storms.

sandboxd owns all of that knowledge. Threading every request through
`pkg/api/ingressproxy/handlers.go` is the simple way to apply it.

## The cost at 100k sandboxes / 10k concurrent

Even after the scale-out fixes already landed on `proxy-serverless-wait`
(admission caps, probe single-flight, buffer-byte budget, start-storm
sem, warm-preflight cache), every warm request still pays:

1. **One SQLite preflight** (`IsSandboxStarted`) — now cached, but cache
   misses still serialize through the single-writer pool.
2. **One reverse-proxy goroutine** per in-flight request in sandboxd.
3. **Two sockets** per in-flight request (Caddy↔sandboxd, sandboxd↔container).
4. **One in-process hop of latency** — 0.5–2 ms typical, more under CPU
   pressure.
5. **An activity ticker** (`scheduleActivityTouch`) for long-lived
   connections — a `time.AfterFunc` chain per active stream.
6. **Reverse-proxy bookkeeping** — `httputil.ReverseProxy` allocates,
   `FlushInterval=-1` flushes per chunk for streaming, headers are
   rewritten on each hop.

At 100k concurrent warm requests this is:

| Resource | At 100k concurrent warm |
|---|---|
| FDs on sandboxd | 200k (downstream + upstream pair per request) |
| Goroutines on sandboxd | ~100k |
| Memory | ~300 MiB just for goroutine stacks (8 KiB each), plus per-request RP buffers and pending body buffers |
| CPU | Linear in request rate; profile shows `net/http.Handler` / `httputil.ReverseProxy` dominating |
| SQLite reads | 100k/s preflight (cache-miss case) through a single conn — the documented "single-writer" rule (`internal/store/store.go:47`, `MaxOpenConns=1`) means even reads serialize |

The warm path doesn't *need* any of this. Once the container is up and
listening, Caddy can dial it directly — exactly what non-serverless
exposures do today.

## Goal

Make the warm path identical to the non-serverless direct path:

```
Internet → Caddy → Container IP : port
```

…while preserving every serverless guarantee that the wake-aware path
provides today on the *cold* path: wake-on-request, manual-stop
semantics, idle sweep correctness, admission control during cold
storms, activity tracking, and lifecycle-event-driven route management.

The transition between the two shapes is what this plan is about.

## Challenges this plan solves

### C1 — Atomic route swap with no dropped requests

The route shape transitions on every Start (wake-aware → direct) and
every Stop (direct → wake-aware). Today there is no "in between" state:
Caddy serves one or the other. If we naively delete-then-upsert, requests
landing in the gap hit the Caddy fallback 404. If we upsert-then-delete,
requests landing in the gap may hit either shape — fine for the start
direction, dangerous for the stop direction (a direct route pointing at
a freshly-killed container IP returns 502 instead of the wake-aware
auto-resume).

The plan: borrow `installHTTPPortRoute`'s existing install-then-delete
ordering and apply it to the *direction-aware* case. For warm (Start
side), install direct then delete wake. For cold (Stop side), install
wake then delete direct — but pay the cost that wake must be installed
**before** `docker stop` actually fires, the same ordering D5 of the
serverless plan already enforces for the API stop path.

### C2 — Activity tracking without the per-request `TouchSandbox`

Today every warm request calls `TouchSandbox` (debounced via
`touchCoalescer`) so `last_active_at` reflects current traffic and the
minute-sweep idle detector doesn't stop a busy sandbox. With the proxy
hop gone, sandboxd never sees the request.

Two existing mechanisms already give us activity-detection without the
hop:

- **`pkg/docker/netstats`** already polls per-sandbox `rx_bytes` /
  `tx_bytes` on a `NetstatsPollInterval` (default 10s). A delta > 0 is
  the most authoritative signal that a sandbox is doing work — it
  captures *any* network activity, not just HTTP. The `Sample` struct
  already carries `BytesIn`, `BytesOut`, `SampledAt`.
- **`netstatsLastTick`** on Service captures the last successful tick.

The plan: the idle sweep treats `max(LastActiveAt,
LastBytesInDeltaAt)` as the activity floor. The netstats sink updates
a per-sandbox "last delta" timestamp whenever a non-zero `BytesIn`
sample arrives; the sweep reads it. No per-request work in sandboxd.

### C3 — Cold-start admission and circuit breaker still apply

`acquirePending` / `acquireBuffer` / `wakeFlight` circuit breakers live
in sandboxd. The wake-aware shape funnels cold traffic through them.
We keep all of that — the wake-aware route is still the route that
serves cold traffic. The only change is that warm traffic no longer
shares the path with cold.

### C4 — Lifecycle-event-driven route management

Today the only callsite that flips the route shape is
`installHTTPPortRoute`. It's invoked from StartSandbox, RecreateSandbox,
ExposePort, the reconcile sweep, the docker `start` event handler, and
the cluster placement replay. Each one currently writes the wake-aware
shape because `serverlessWakeEnabled` is true; the same callsites will
need to write the direct shape when the sandbox is currently Started
and the wake-aware shape when it is Stopped.

The plan: `installHTTPPortRoute` becomes status-aware. The serverless
mode still controls *whether* a wake-aware shape exists; the sandbox
*status* now controls *which* shape is currently published.

### C5 — Docker `die` / `stop` event arrives milliseconds *after* the container is already dead

When a container dies, Caddy currently has a wake-aware route pointing
at the ingress proxy — the proxy detects the dead container and either
wakes it or returns 503. After the bypass change, a warm sandbox has a
direct route pointing at the container IP. If the container dies *and*
Caddy still has the direct route, the next request gets a 502 (TCP
RST or timeout to a now-dead container).

The plan: route teardown on a `die` event must run *before* any new
request can arrive at the old direct route. Two layers of defense:

1. The existing `tearDownPortRoutesForStop` already runs on every stop
   path; we make it the first thing the die-event handler does.
2. The wake-aware shape is installed in its place before the route flip
   completes, so any request landing mid-window resurrects the sandbox
   instead of 502-ing.

A residual race exists: a request arrives between the container exit
and the event-handler's route swap (sub-millisecond to ~10 ms window).
Caddy's default proxy retry on dial failure mitigates this; we add
`load_balancing.try_duration` and `lb_try_interval` to the direct route
JSON so Caddy retries the dial for a brief budget before failing.
Failures past that retry budget still become 502 from Caddy's
perspective; that is identical to the failure mode every direct-route
service today has, and is the right tradeoff.

### C6 — Cluster mode: owner-side bypass

In cluster mode an ingress node forwards to the owning worker
(`internal/cluster/forward.go`), and the owner runs the ingress proxy.
The bypass change applies on the owner side: when the worker installs
its local Caddy routes for a sandbox it owns, those routes get the
status-aware shape. Ingress nodes still forward to the owner's
data-plane address; the bypass shaves the *owner-side* hop, which is
where the 100k-concurrent cost lives.

`internal/cluster/forward.go` and the ingress reconciler
(`internal/service/ingress_delta.go`) need no behavior change beyond
threading the warm-route shape through. The forward path is still
"ingress node → owner node"; what's different is the owner node's
Caddy now points at the container instead of the loopback proxy.

### C7 — TCP / TLS bypass is harder; HTTP first

For HTTP the bypass is clean: Caddy's reverse proxy talks plain HTTP
to the container. For TCP (`UpsertWakeTCPRoute` →
`InternalL4WakeAddr`) the wake proxy currently consumes the PROXY
protocol v1 header Caddy sends, then reverse-proxies bytes. Bypassing
that for warm L4 means caddy-l4 must dial the container directly,
which it already can (`UpsertTCPRoute`). Same install-then-delete
ordering, same status-aware decision. **HTTP-only in v1** of this
plan; L4 bypass is a stage 2 follow-up so the v1 surface is small
and the L4 fragility constraints in `pr-review.md` get focused
attention.

### C8 — Reconcile must converge

The reconcile sweep (`Reconcile` in `internal/service/`) already
re-applies the wake-aware shape for every serverless sandbox. After
the change, it must re-apply the *correct* shape for the current
status, not unconditionally the wake shape. Reconcile is the safety
net that fixes drift if Caddy and the store disagree — it must not
*introduce* drift by writing the wrong shape.

### C9 — Caddy admin API write contention

Today the wake-aware shape is install-once-then-never-changed for the
lifetime of the sandbox's HTTP exposure. After the change, every
Start and every Stop writes Caddy twice (install new shape, delete old
shape). For a node with high churn (100k sandboxes, 1k starts/stops
per minute) that doubles admin writes. Caddy admin is single-threaded
for writes; we batch where possible (the reconciler already diffs
against `ingressRouteCache`) and rely on the existing
`ClusterCapacityGossipInterval`-style backoff.

### C10 — Backwards compatibility with non-serverless sandboxes

Non-serverless sandboxes already use the direct shape — nothing
changes for them. The status-aware change only affects sandboxes
with `Lifecycle.Serverless=true` and the rollout gate
`EnableServerless=true`. Existing tests for direct routing remain
valid; new tests target the *transitions* on the serverless path.

## Design

### How wake-on-request works when Caddy talks directly to the container

This is the question the bypass design has to answer convincingly: if
Caddy goes straight to the container, *how does anyone know to start
the container when it is stopped?* The short answer is: **the published
route shape encodes the wake decision**, and sandboxd is the thing that
publishes the route. Caddy is never asked to know anything; it just
forwards to whatever upstream the currently-published route names.

Two routes can exist for the same `{id}-{port}` exposure:

- **Direct route** (`{id}-{port}` `@id`) → upstream is `containerIP:port`.
  Caddy forwards bytes straight to the container.
- **Wake-aware route** (`{id}-{port}-wake` `@id`) → upstream is sandboxd's
  loopback ingress proxy. Caddy forwards bytes to sandboxd, which runs
  cold-start admission, calls `EnsureSandboxAwakeForHTTP`, probes for
  upstream readiness, and reverse-proxies the request to the now-warm
  container.

Sandboxd publishes exactly one of those two at any given moment for a
given exposure. The choice is a pure function of the sandbox's current
`Status`:

| Sandbox `Status` | Route published | What Caddy does with a request |
|---|---|---|
| `Started` | Direct | Goes straight to container |
| `Stopped` + `WakeArmed=true` (serverless) | Wake-aware | Goes to sandboxd ingress proxy → triggers wake |
| `Stopped` + `WakeArmed=false` | Neither (route removed) | Hits Caddy fallback → 404 (operator manually stopped) |
| `Destroyed` | Neither | 404 |

So **the wake trigger is not "sandboxd inspects every request and
decides."** The wake trigger is **"Caddy delivers the request to
sandboxd because the wake-aware route is currently published."** Whether
that route is published is decided once per lifecycle transition, not
per request.

#### Lifecycle: a sandbox going cold

1. Sandbox is `Started`; Caddy has the **direct** route published.
2. Idle sweep observes `now - max(LastActiveAt, netstatsRecentBytesInAt) > StopIfIdleFor`.
3. Sandbox enters the `stopSandboxInternal(stopModeLifecycle)` path.
4. `tearDownPortRoutesForStop` runs *before* `docker.Stop`:
   - **Install** the wake-aware route (upstream: sandboxd loopback).
   - **Delete** the direct route.
   - This is the D5 "install then delete" ordering already required by
     the original wake plan — at no point is there a window with
     neither route published.
5. `docker.Stop` executes; container exits.
6. Sandbox row in store flips to `Stopped` + `WakeArmed=true`.
7. From this moment on, every new request lands on the wake-aware
   route and goes to sandboxd.

#### Lifecycle: a request waking a cold sandbox

1. Sandbox is `Stopped` + `WakeArmed=true`; Caddy has the **wake-aware**
   route published.
2. Request arrives → Caddy forwards to sandboxd ingress proxy.
3. Ingress proxy (`pkg/api/ingressproxy/handlers.go`):
   - `IsSandboxStarted` returns false → enters cold path.
   - `acquirePending` (per-sandbox + global cap).
   - `acquireBuffer` (global byte budget) if the request has a body.
   - `WakeAwarePortTarget` → `EnsureSandboxAwakeForHTTP` →
     single-flighted `StartSandbox` (gated by `wakeStartSem`).
4. `StartSandbox` succeeds → container is up, ContainerIP is known.
5. As part of StartSandbox, `upsertExposedPortRoute` runs and
   `installHTTPPortRoute` now observes `Status == Started`:
   - **Install** the direct route (upstream: ContainerIP:port).
   - **Delete** the wake-aware route.
6. Back in the ingress proxy: `probeOnce` confirms the in-container
   service is listening, then `httputil.ReverseProxy` finishes the
   *original* request through the loopback connection that is still
   open. This request rides the wake-aware path all the way through
   — that is fine, the connection is already established and Caddy
   route changes do not drop in-flight connections.
7. Every *subsequent* request lands on the direct route and goes
   straight to the container. The cold-start cost is paid exactly
   once per cold→warm transition, by the request that triggered the
   wake.

#### Why this is correct

- **No request ever lands on a stale route.** The install-then-delete
  ordering means there is always exactly one route published for an
  exposure (or zero, for `WakeArmed=false` / `Destroyed`).
- **No request ever bypasses wake for a stopped sandbox.** When
  `Status != Started`, the direct route does not exist; Caddy has only
  the wake-aware route, so every request gets the cold-start treatment.
- **No request ever pays the proxy hop when warm.** When `Status ==
  Started`, the wake-aware route does not exist; Caddy has only the
  direct route, so every request goes straight to the container.
- **The cold-start absorber stays in the cold path.** All the
  protections that exist today — `acquirePending`, `acquireBuffer`,
  `probeOnce`, `wakeFlight` circuit breaker, `wakeStartSem` — apply
  exactly when they need to apply (during a wake), and never burn
  cycles on warm traffic.

#### What if the route flip hasn't happened yet when a second request arrives during wake?

A convoy of cold-start requests is the existing behavior already
protected by `probeOnce`'s single-flight: all waiters share one wake.
The route flip happens once `StartSandbox` returns; during that wake
window every concurrent waiter is still on the wake-aware route in
the ingress proxy. Once the flip lands, *new* requests arriving after
that point use the direct route. No correctness gap, no extra wake.

#### What if the sandbox is forcibly killed (e.g. `docker kill`) while a direct route is published?

This is C5 in the Challenges section. The docker `die` event handler
runs `markSandboxStopped`, which calls `tearDownPortRoutesForStop`,
which installs the wake-aware route *before* deleting the direct one.
For the ~10ms window between container exit and the event firing,
requests on the direct route hit `ECONNREFUSED` / TCP RST; Caddy's
`load_balancing.try_duration` (2s default) absorbs that window by
retrying. Beyond the retry window, Caddy returns 502 — the same
failure mode every direct-route service has today.

#### What if sandboxd itself is down?

This is a free improvement from the bypass:

- A **warm** sandbox is unaffected — Caddy talks straight to its
  container, no sandboxd in the request path.
- A **stopped** sandbox is unreachable — the wake-aware route's
  upstream (sandboxd loopback) is unreachable, so Caddy returns 502.
  Same as today, but the blast radius is now limited to cold sandboxes
  instead of all serverless traffic.

#### Where in the code the flip is triggered

Every transition that changes `sandbox.Status` already calls
`upsertExposedPortRoute` (or its tear-down counterpart) for every
exposed port:

- `StartSandbox` (`internal/service/service.go:933`) — calls upsert
  after the container starts and the new IP is written.
- `stopSandboxInternal` (`internal/service/serverless.go:141`) —
  calls `tearDownPortRoutesForStop` before docker.Stop.
- `markSandboxStopped` (`internal/service/events.go:137`) — calls
  `tearDownPortRoutesForStop` on the docker die/stop/oom event path.
- `handleStartEvent` (out-of-band `docker start`) — republishes
  routes.
- `RecreateSandbox`, `Reconcile`, cluster placement replay — all
  funnel through the same helper.

Today every one of these writes the wake-aware shape unconditionally
because the sandbox is serverless. After the change, every one of
them passes through the same `installHTTPPortRoute` switch shown
below and writes whichever shape the *current* `Status` calls for.
No new callsites; existing callsites carry the new branching
implicitly because they pass the sandbox row in.

### High level

`installHTTPPortRoute` becomes:

```go
func (s *Service) installHTTPPortRoute(ctx context.Context, sandbox *models.Sandbox, port int) error {
    serverless := s.serverlessWakeEnabled(sandbox)
    warm := sandbox.Status == models.SandboxStatusStarted && sandbox.ContainerIP != ""

    switch {
    case serverless && warm:
        // Direct shape, wake-aware fallback present nowhere.
        // Install direct, then delete wake.
        if err := s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port); err != nil {
            return err
        }
        _ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, port)
        return nil
    case serverless && !warm:
        // Wake-aware shape, container is down (or coming up).
        // Install wake, then delete direct.
        if err := s.caddy.UpsertWakeHTTPPortRoute(ctx, sandbox.ID, s.cfg.InternalIngressAddr, port); err != nil {
            return err
        }
        _ = s.caddy.DeletePortRoute(ctx, sandbox.ID, port)
        return nil
    default:
        // Non-serverless — direct shape, unchanged.
        if err := s.caddy.UpsertPortRoute(ctx, sandbox.ID, sandbox.ContainerIP, port); err != nil {
            return err
        }
        _ = s.caddy.DeleteWakeHTTPPortRoute(ctx, sandbox.ID, port)
        return nil
    }
}
```

The same shape extends to `installTCPPortRoute` and `installTLSPortRoute`
in stage 2.

### Idle-sweep activity floor

Add `LastObservedActiveAt` derivation in the sweep:

```go
// Activity floor: max(LastActiveAt, netstatsRecentBytesInAt)
floor := sb.LastActiveAt
if observed := s.netstatsRecentBytesInAt(sb.ID); !observed.IsZero() && observed.After(floor) {
    floor = observed
}
idle := now.Sub(floor)
```

The `netstatsRecentBytesInAt` lookup is a single in-memory map read
populated by the existing netstats sink. No new per-request cost.

### Cold-start storm protection — unchanged

`acquirePending`, `acquireBuffer`, `probeOnce`, `wakeFlight`, and
`wakeStartSem` all live in the wake-aware path. The cold path keeps
flowing through them; this plan doesn't touch them.

### Direct route JSON: brief dial retry

The direct route gets a small retry window in case the route is
published a few ms before the container's listening socket is fully
bound:

```json
{
  "handler": "reverse_proxy",
  "upstreams": [{"dial": "10.0.0.10:3000"}],
  "load_balancing": {
    "try_duration": "2s",
    "try_interval": "100ms"
  }
}
```

This is the same protection the L4 wake retry loop provides; it's a
small JSON addition with no extra admin write.

### Status transitions and route writes

| Transition | Route writes | Ordering |
|---|---|---|
| Stopped (wake-armed) → Started (cold-start completes) | install direct, delete wake | direct first |
| Started → Stopped (manual / lifecycle / die) | install wake, delete direct | wake first (D5 rule preserved) |
| Started → Destroyed | delete both | direct first, then wake |
| Reconcile observes Started + serverless | install direct, delete wake | direct first |
| Reconcile observes Stopped + serverless + WakeArmed | install wake, delete direct | wake first |

The "wake first" rule on the stop side is the same rule
`stopSandboxInternal` already enforces (`tearDownPortRoutesForStop`);
we extend the same helper to do the install-then-delete pair.

### Activity tracking — what the sweep actually does

After the change, `idle = now - max(LastActiveAt, netstatsRecentBytesInAt(id))`.
`LastActiveAt` is still updated by:

- Toolbox / session / runtime HTTP proxies that route *through* sandboxd
  (these are unrelated to the public ingress).
- The SSH gateway.
- StartSandbox / RecreateSandbox / ExposePort (write-path operations
  on the sandbox itself).

`netstatsRecentBytesInAt(id)` is the new floor for "I have not seen
this sandbox accept traffic in N seconds." With `NetstatsPollInterval`
at 10s and the sweep at 60s, the worst-case false-idle window is
~70s — well inside the typical `Lifecycle.StopIfIdleFor` minimums.

## Phases

### Phase 1 — HTTP-only bypass

Smallest possible change: status-aware HTTP route shape, idle-sweep
activity floor, route-transition tests.

### Phase 2 — TCP / TLS bypass

Same principle as Phase 1 — the published route shape encodes the wake
decision, and the shape is chosen by `sandbox.Status` at every
lifecycle transition — but the mechanics differ per protocol because
each one lives in a different Caddy admin entity. Stage gated
separately because the TCP / TLS wake paths are flagged as "fragile"
in `CLAUDE.md` and `/touch-tcp-pool` applies.

#### TCP bypass — `installTCPPortRoute` becomes status-aware

Today, raw-TCP exposures use a per-host-port caddy-l4 server
(`pkg/caddy/client.go:666` `UpsertTCPRoute`, `:704` `UpsertWakeTCPRoute`).
Both shapes POST the *entire server config* to
`/config/apps/layer4/servers/{tcpServerID(hostPort)}`, so the swap is
**atomic at the server level** — POST replaces the whole server
in one Caddy admin call, no install-then-delete window like HTTP needs.
This is structurally cleaner than HTTP and Phase 1's
install-then-delete ordering does not apply here.

| Status | Server config published | Caddy-l4 behavior |
|---|---|---|
| `Started` | Direct: `proxy` → `containerIP:port`, no PROXY protocol | Bytes flow Caddy → container |
| `Stopped` + `WakeArmed=true` | Wake-aware: `proxy` with `proxy_protocol: v1` → `cfg.InternalL4WakeAddr` | Caddy sends PROXY v1 header → sandboxd reads `hostPort` from header → `s.store.GetPortByHostPort` → `WakeAwareL4PortTarget` triggers wake |
| `Stopped` + `WakeArmed=false` | Server removed entirely (`DeleteTCPRoute`) | Listener closed, kernel returns RST on connect |
| `Destroyed` | Server removed | Listener closed |

The in-container TCP service sees **plain bytes in both shapes** —
the PROXY v1 header is consumed by sandboxd in the wake-aware shape
and never emitted by Caddy in the direct shape. The container is
agnostic to which shape is live.

Updated decision logic:

```go
func (s *Service) installTCPPortRoute(ctx context.Context, sandbox *models.Sandbox, port, hostPort int) error {
    if err := s.EnsureLayer4Ready(ctx); err != nil {
        return err
    }
    serverless := s.serverlessWakeEnabled(sandbox)
    warm := sandbox.Status == models.SandboxStatusStarted && sandbox.ContainerIP != ""

    switch {
    case serverless && warm:
        return s.caddy.UpsertTCPRoute(ctx, sandbox.ID, sandbox.ContainerIP, port, hostPort)
    case serverless && !warm:
        return s.caddy.UpsertWakeTCPRoute(ctx, sandbox.ID, port, hostPort, s.cfg.InternalL4WakeAddr)
    default:
        return s.caddy.UpsertTCPRoute(ctx, sandbox.ID, sandbox.ContainerIP, port, hostPort)
    }
}
```

TCP-specific edge cases:

- **Long-lived warm connections (SOCKS proxy, DB tunnel) survive route flips.** Caddy keeps in-flight L4 connections alive across server-config replacements; only *new* connections see the new shape. A warm sandbox that goes through a Stop while a TCP connection is open keeps that connection alive until the container actually exits — same as today.
- **Container crash with direct shape live.** Same C5 race as HTTP. The docker `die` event handler republishes the wake-aware server config. caddy-l4 does not have an `lb_try_duration` equivalent for raw TCP, so the ~10ms window between exit and event delivery surfaces as a single `connect` failure to the client, who must reconnect. This is the same failure surface every non-serverless TCP exposure has today.
- **L4 active-connection accounting** (`tryAcquireL4Active` /  `releaseL4Active` / `touchDuringL4Activity`) lives in `internal/service/l4wake.go`. When warm traffic stops flowing through `proxyL4WakeConn`, none of that accounting runs for warm connections. The activity-floor netstats signal (Phase 1) covers warm-traffic detection for the idle sweep; the active-connection counter becomes a *cold-path-only* counter, which matches its actual purpose (gating wake fan-out, not warm steady-state).
- **L4 pending caps** (`tryAcquireL4Pending`) remain on the wake-aware path only — exactly the right place.

#### TLS+SNI bypass — `installTLSPortRoute` becomes status-aware

TLS+SNI is the trickiest of the three because the wake mechanism today
relies on **one Unix domain socket per `(id, port)` exposure**, created
by `ensureTLSWakeListener` (`internal/service/l4wake.go:399`). The socket
exists because after Caddy terminates TLS at the edge, the cleartext
stream carries no SNI anymore — sandboxd would have no way to know which
sandbox the connection is for without the socket path encoding that
identity. The direct shape needs no such socket; Caddy terminates TLS
and dials `containerIP:port` directly.

Both shapes are routes inside the shared TLS mux server
(`tlsMuxServerID`) and use the same `@id` (`tlsRouteID(id, port)`).
PATCH `/id/{routeID}` **atomically replaces one route in place** without
touching sibling SNI routes, so like TCP this is a single Caddy admin
call per flip — no install-then-delete window.

| Status | Route handle chain | Unix socket on host |
|---|---|---|
| `Started` | `[tls, proxy → containerIP:port]` | Closed (none) |
| `Stopped` + `WakeArmed=true` | `[tls, proxy → unix:/run/sandboxd/l4wake/{id}-{port}.sock]` | Open, accept-looped by `acceptL4WakeTLS` |
| `Stopped` + `WakeArmed=false` | Route deleted (`DeleteTLSSNIRoute`) | Closed |
| `Destroyed` | Route deleted | Closed |

The container sees **plaintext TCP in both shapes** — Caddy always
terminates TLS at the edge using the shared wildcard cert manager.
That part of the design does not change.

Updated decision logic (note the socket lifecycle is intertwined with
the route shape):

```go
func (s *Service) installTLSPortRoute(ctx context.Context, sandbox *models.Sandbox, port int) error {
    if err := s.EnsureLayer4Ready(ctx); err != nil {
        return err
    }
    sniHost := s.caddy.SNIHost(sandbox.ID, port)
    serverless := s.serverlessWakeEnabled(sandbox)
    warm := sandbox.Status == models.SandboxStatusStarted && sandbox.ContainerIP != ""

    switch {
    case serverless && warm:
        // Direct shape — TLS terminates at edge, proxies straight to container.
        // The wake-listener socket is no longer needed; close it AFTER the
        // route flip so a request landing mid-window still has a working
        // socket if it happened to take the wake-aware path.
        if err := s.caddy.UpsertTLSSNIRoute(ctx, sandbox.ID, sniHost, sandbox.ContainerIP, port); err != nil {
            return err
        }
        s.closeTLSWakeListener(sandbox.ID, port)
        return nil
    case serverless && !warm:
        // Wake-aware shape — create the per-exposure Unix socket FIRST
        // (so the route's upstream is reachable the instant we publish it),
        // then PATCH the route. Roll back the socket on PATCH failure to
        // avoid leaking a listener with no live route pointing at it.
        socketPath, err := s.ensureTLSWakeListener(sandbox.ID, port)
        if err != nil {
            return err
        }
        if err := s.caddy.UpsertWakeTLSSNIRoute(ctx, sandbox.ID, sniHost, socketPath, port); err != nil {
            s.closeTLSWakeListener(sandbox.ID, port)
            return err
        }
        return nil
    default:
        if err := s.caddy.UpsertTLSSNIRoute(ctx, sandbox.ID, sniHost, sandbox.ContainerIP, port); err != nil {
            return err
        }
        s.closeTLSWakeListener(sandbox.ID, port)
        return nil
    }
}
```

This is essentially the existing `installTLSPortRoute` with one
additional `warm` branch — the same socket-create-before-patch and
socket-close-after-patch primitives are already in place. The
ordering matters because the route's upstream must be reachable
before Caddy can use it, and the socket must outlive any connection
that may have started against the wake-aware shape.

TLS+SNI specific edge cases:

- **Cert manager is shared, never changes.** The wildcard cert for `*.{domain}` is issued once at boot via DNS-01 and held by the global cert manager. Neither shape touches certs. A handshake completing during a route flip uses whichever upstream config was current at handshake completion — both lead somewhere correct.
- **SNI passthrough on non-owner cluster ingress nodes.** `UpsertSNIPassthroughRoute` (`pkg/caddy/client.go:931`) is unrelated to this plan — non-owners forward the original ClientHello to the owner without terminating TLS. The owner-side route is the one that flips between direct and wake-aware. The passthrough shape stays unchanged.
- **The Unix socket lives on the host filesystem** (`cfg.InternalL4WakeDir`, default `/run/sandboxd/l4wake`). With the bypass enabled, only stopped serverless sandboxes have sockets — a node hosting 100k warm serverless TLS exposures pays zero socket FDs for them. This is a direct improvement over today.
- **TLS handshake mid-stop is identical to TCP mid-stop.** The container exits, the next handshake may still terminate (cert manager is alive) but the proxy step fails, client sees a transport error and retries. The die-event handler installs the wake-aware shape and reopens the socket; the retry wakes the sandbox.

#### Why TCP and TLS are structurally less risky to flip than HTTP

The HTTP wake plan needed strict install-then-delete ordering across
*two separate route entries* (`{id}-{port}` and `{id}-{port}-wake`)
because Caddy's HTTP server treats them as independent routes. TCP and
TLS both use the **same `@id`** for both shapes — a single Caddy admin
operation atomically swaps the upstream, so the "two routes coexist"
class of bug from D5 of the original wake plan cannot occur here.
That's why the C1 challenge (atomic route swap) is a stronger concern
in HTTP than in L4: the L4 admin API gives us atomicity for free.

#### What does NOT change in Phase 2

- `internal/service/l4wake.go` proxying logic — `proxyL4WakeConn`,
  `dialL4Upstream`, `handleL4WakeTCPConn`, `acceptL4WakeTLS` —  is the
  cold-path absorber and stays exactly as is. Phase 1's
  ECONNREFUSED-retry + jitter + admission-cap work continues to
  protect cold-start storms.
- `internal/service/l4wake.go` `ensureTLSWakeListener` /
  `closeTLSWakeListener` — same primitives, just called from new
  branches of `installTLSPortRoute`.
- PROXY protocol v1 reader (`readProxyV1DestinationPort`) — only fires
  on the wake-aware TCP path, unchanged.
- TLS cert manager configuration in `pkg/caddy/client.go` — wildcard
  issuance, shared cert manager, SNI fallback to local HTTPS — all
  unchanged.

#### Activity tracking for L4

Same answer as Phase 1: the netstats poller observes per-sandbox
`BytesIn`/`BytesOut` deltas regardless of which layer carried the
bytes. A warm SOCKS proxy with steady TCP traffic and a warm Postgres
TLS connection both register as non-zero `BytesIn` deltas, and the
idle sweep's activity floor accepts both as recent activity. No new
mechanism, no per-protocol special-casing.

#### Phase 2 gate

`SB_L4_WAKE_DIRECT_BYPASS_ENABLED` (separate from
`SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED`). Phase 2 may ship after Phase 1
has been the default in production for at least two release cycles
*and* the L4 active-connection counter has been re-examined to
confirm it does not break under "warm bypass means I never see this
connection" semantics.

### Phase 3 — Caddy admin write reduction

Once the dust settles, look at whether the route-write doubling under
high churn warrants a Caddy admin batching layer. The reconciler
already diffs against an in-memory cache; this would be a per-tick
buffering of pending writes. Out of scope for v1; tracked as a
follow-up if Caddy admin shows up in flamegraphs.

## Files to modify

### Phase 1 — HTTP-only

| File | Change |
|---|---|
| `internal/service/service.go` | `installHTTPPortRoute` becomes status-aware. Idle sweep (`sweepIdleSandboxes` or equivalent) reads from a new activity-floor helper that consults `netstatsRecentBytesInAt`. Service struct gains `netstatsActivityMu sync.RWMutex` + `netstatsActivity map[string]int64` (id → last bytes-in delta unix nano). |
| `internal/service/serverless.go` | `tearDownPortRoutesForStop` extends its install-then-delete pattern to cover the direct-shape teardown case (install wake, delete direct). On the start-side, after StartSandbox completes (in `EnsureSandboxAwakeForHTTP`), the convoy of waiters will see the now-warm route via reconcile or via the explicit route flip we trigger inside StartSandbox. |
| `internal/service/events.go` | `markSandboxStopped` already calls `tearDownPortRoutesForStop`; needs to keep doing so but with the new direct-aware behavior. `handleStartEvent` (out-of-band docker start) republishes routes; must publish the direct shape now. |
| `internal/service/scaleobs_sink.go` *(or wherever the netstats sink lives)* | The existing `HandleSamples` sink that updates `network_bytes_in` in the store gets a new side-effect: if `sample.BytesIn > 0`, write `s.netstatsActivity[id] = sample.SampledAt.UnixNano()`. |
| `pkg/caddy/client.go` | `UpsertPortRoute` accepts an optional retry-budget setting (defaults preserve current behavior). Or — add `UpsertPortRouteWithRetry` for the explicit warm-bypass callsite to keep the existing one byte-for-byte. Prefer the latter for minimum blast radius. |
| `internal/service/service.go` (`Reconcile` / `reconcileStaleOwnership`) | Reconcile's drift fix must call `installHTTPPortRoute` with the *current* sandbox row so the new status-aware code picks the right shape. May already be the case; verify. |
| `internal/service/touch_coalescer.go` | No change. `TouchSandbox` still works; it just stops being the only signal. |

### Phase 1 — Cluster integration

| File | Change |
|---|---|
| `internal/cluster/forward.go` | No change — owner-side forward target is the data-plane host; what *that host's* Caddy does is up to the worker. |
| `internal/service/ingress_delta.go` | Cluster ingress reconciler installs cross-node placement routes; the same status-aware decision applies when the owner has the sandbox Started vs. Stopped. The ingress node still calls into the owner's data plane; the owner's local Caddy chooses the shape. |

### Phase 1 — Config

| File | Change |
|---|---|
| `internal/config/config.go` | New field `HTTPWakeDirectBypassEnabled bool` (env `SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED`). Default false in v1 of this plan so the change is opt-in; flip to true in a follow-up once Phase 1 has soaked. New field `HTTPWakeDirectRouteRetryDuration` (default 2s) controls the Caddy `load_balancing.try_duration` on the direct route. |
| `cmd/sandboxd/main.go` | Thread the new config fields into `service.New` / wherever they're consumed. |
| `packaging/sandboxd.service` | No change. |

### Phase 1 — Documentation

| File | Change |
|---|---|
| `docs/src/content/docs/serverless-direct-routing.mdx` *(new)* | New top-level docs page covering the warm-bypass behavior. Per CLAUDE.md "new top-level feature → new `.mdx` file", with all-five-SDK examples in `<Tabs syncKey="lang">` blocks (the SDK surface doesn't change, but the operator-facing config and behavior do). |
| `docs/src/content.config.ts` | Register the new sidebar entry. |
| `plans/serverless-sandbox-http-wake.md` | Add a short cross-reference at the bottom pointing to this plan. |

### Phase 1 — Tests

| File | Change |
|---|---|
| `internal/service/serverless_test.go` | New cases: `TestInstallHTTPPortRouteWarmInstallsDirect`, `TestInstallHTTPPortRouteStoppedInstallsWake`, `TestStopArmingFlipsDirectToWake`, `TestStartFlipsWakeToDirect`. Asserts ordering (direct upsert before wake delete on start; wake upsert before direct delete on stop). |
| `internal/service/reconcile_test.go` (existing or new) | `TestReconcileDriftFixesShape` — store says Started but Caddy has wake route, reconcile installs direct. Mirror for the reverse case. |
| `internal/service/wake_scale_test.go` | `TestIdleSweepUsesNetstatsFloor` — sandbox with stale `LastActiveAt` but recent netstats delta is NOT swept. Mirror for genuinely idle. |
| `internal/service/events_test.go` (existing or new) | `TestDieEventInstallsWakeBeforeDirectDelete` — simulate die event, assert ordering on the caddy fake. |
| `pkg/caddy/client_test.go` | New case: direct route JSON includes `load_balancing.try_duration` when the retry-budget upsert is used. |
| `pkg/api/ingressproxy/handlers_test.go` | No change — the wake-aware path is still the cold path, still tested. |

### Phase 2 — TCP / TLS

| File | Change |
|---|---|
| `internal/service/service.go` | `installTCPPortRoute` becomes status-aware (3-arm switch); `installTLSPortRoute` becomes status-aware with the socket-lifecycle ordering shown in the Phase 2 design (socket-before-route on warm→cold, route-before-socket-close on cold→warm). |
| `internal/service/serverless.go` | `tearDownPortRoutesForStop` (already extended in Phase 1) handles the TCP/TLS install-before-stop pair. TCP is a single POST replacing the server, TLS is a single PATCH replacing the route — no install-then-delete window for either. |
| `internal/service/events.go` | `markSandboxStopped` republishes the wake-aware shape for TCP and TLS exposures on every stop event (already invokes the same `tearDownPortRoutesForStop` helper; no new callsite). `handleStartEvent` republishes direct shapes for TCP and TLS on out-of-band docker start. |
| `internal/service/l4wake.go` | No proxy-logic changes. `ensureTLSWakeListener` / `closeTLSWakeListener` continue to be the socket-lifecycle primitives — they are now called from the new `warm` and `!warm` branches of `installTLSPortRoute`. L4 active-connection counters become cold-path-only by virtue of warm traffic no longer flowing through `proxyL4WakeConn`. |
| `pkg/caddy/client.go` | No new methods needed for TCP — `UpsertTCPRoute` and `UpsertWakeTCPRoute` already exist and POST-replace the server atomically. Same for TLS — `UpsertTLSSNIRoute` and `UpsertWakeTLSSNIRoute` already PATCH the route atomically. Phase 2 reuses both existing surfaces. |
| `internal/config/config.go` | New field `L4WakeDirectBypassEnabled bool` (env `SB_L4_WAKE_DIRECT_BYPASS_ENABLED`), independent of the HTTP gate. |
| `cmd/sandboxd/main.go` | Thread the new field through. |

### Phase 2 — Tests

| File | Change |
|---|---|
| `internal/service/serverless_test.go` | TCP: `TestInstallTCPPortRouteWarmInstallsDirect`, `TestInstallTCPPortRouteStoppedInstallsWake`, `TestTCPServerConfigSwapIsAtomic` (asserts a single POST replaces the entire layer4 server, no two-route window). TLS: `TestInstallTLSPortRouteWarmInstallsDirect`, `TestInstallTLSPortRouteStoppedInstallsWake`, `TestTLSSocketCreatedBeforeWakeRoutePatched`, `TestTLSSocketClosedAfterDirectRoutePatched`. |
| `internal/service/l4wake_test.go` (existing) | `TestUnixSocketAbsentWhenWarm` — after a transition to Started, the per-exposure socket file does not exist on disk. `TestUnixSocketPresentWhenWakeArmed` — after Stop, the socket exists and accepts. |
| `internal/service/events_test.go` | TCP/TLS variants of `TestDieEventInstallsWakeBeforeDirectDelete` — die event during warm L4 traffic flips routes (and recreates the TLS socket where applicable). |
| `pkg/caddy/client_test.go` | Existing TCP / TLS tests already cover the JSON shapes for both directions; verify no Phase 2 regression. |

## Files to create

| File | Purpose |
|---|---|
| `plans/warm-direct-route-bypass.md` | This document. |
| `docs/src/content/docs/serverless-direct-routing.mdx` | Operator-facing docs page covering: when the bypass kicks in, the new env vars, how to verify a warm sandbox is bypassed (via Caddy admin `/config/`), and how to roll back via `SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED=false`. |
| `internal/service/route_shape.go` | *(optional, decided in implementation)* A small helper file housing the status→shape decision so multiple callsites share one source of truth. Inline in `service.go` is also fine; this file would be created only if the decision branches grow beyond ~30 lines. |

## Rollout

1. Land Phase 1 behind `SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED=false` so the
   build is no-op by default.
2. Enable on one canary node, run the load profile from
   `scripts/load/`, compare:
   - sandboxd CPU at 10k warm RPS,
   - p50 / p99 latency on a warm endpoint,
   - FD count on sandboxd,
   - 503 rate during a forced burst (idle → warm storm),
   - 502 rate during a forced kill (warm container `docker kill`).
3. Flip the default to `true` in a follow-up commit once the canary
   profile is clean for at least a week.
4. Stage Phase 2 (TCP / TLS) only after Phase 1 has been the default
   for two release cycles.

## Non-goals

- Removing the wake-aware ingress proxy. It remains the cold-path entry
  point and the only place that holds the wake breaker / admission caps.
- Per-request authn / authz in Caddy. If we add it, it stays in sandboxd
  on the cold path; the warm path is for "the container is the
  authority on the response."
- Eliminating the SQLite preflight entirely. The warm cache already
  cuts it; this plan removes the *warm* preflight as a side effect by
  removing the proxy hop, but cold requests still preflight.
- A Caddy plugin. The change works with stock Caddy because the
  direct shape already exists for non-serverless sandboxes.

## Cross-references

- `plans/serverless-sandbox-http-wake.md` — the original wake plan; D5
  ordering is the ancestor of the install-then-delete pattern this
  plan extends.
- `pr-review.md` — non-negotiables for boot-path latency, failure-path
  consistency, and TCP-pool / L4 bootstrap fragility. Phase 2 of this
  plan must pass `/touch-tcp-pool`.
- `agentic_docs/E2B-SDK-method-map.md` — confirms no SDK behavior
  change is required; the URL surface stays identical.
