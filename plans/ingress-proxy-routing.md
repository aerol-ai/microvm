# Ingress routing without per-sandbox Caddy reloads

Status: **ENG-REVIEWED 2026-09-28**. The review report is at the end; this plan
is the build contract.

**Decisions:**

- **User:** route through sandboxd instead of coalescing writes or an upstream
  Caddy fix.
- **Review D2:** keep TLS end-to-end on ingress; do not terminate it.
- **Review T1:** spike keeping the data path in Caddy. It **passed**, so bytes
  stay in Caddy and sandboxd only answers **where**.
- **T2:** raw TCP host ports are **in scope**.

## 1. Problem

Every per-sandbox route change is a Caddy admin-API write, and every write
reloads Caddy's **whole** config. That drops new connections that have not sent
a request: the handshake completes, then the connection closes with 0 bytes.
The layer4 `tls-mux` in front of :443 adds resets on top.

- **Reproduced** with the production build (Caddy v2.11.4 + caddy-l4) using
  `scripts/dev/caddy-reload-repro.py`: **0 failures in ~40k requests without
  churn, ~2.6% of new connections fail under route churn.**
- **No built-in fix:** `grace_period=10s` plus `shutdown_delay=2s` measured
  2.6%, unchanged.
- **Seen live:** T19 S6 UC-09, where the TLS dial was reset 0.41 s after
  another test's route DELETE, and hetero-lite UC-31, where an `expose_port`
  POST got EOF during a burst of 3 reloads.
- **At 2,000 nodes × 100k sandboxes × 100 ingress** this is continuous
  connection loss.

**Where the writes come from:**

- Owners write http routes: `syncSandboxPublicRoute`, `installHTTPPortRoute`,
  the serverless direct↔wake flips, in-flux routes, and custom-domain routes.
- Every ingress writes an SNI passthrough per sandbox
  (`UpsertSNIPassthroughRoute`) and a TCP proxy server per host port
  (`UpsertTCPProxyRoute`, ingress_delta.go:191-201).
- Owners write TCP and TLS-port layer4 routes.

There are **55 call sites in 9 files** for the HTTP/SNI routes alone.

## 2. Goal and non-goals

**Goal:** sandbox lifecycle, exposure, custom-domain and failover changes make
**zero Caddy config writes** on owners and ingress, for HTTP(S), SNI **and raw
TCP** (T2). Caddy config changes only at boot and on operator action.
Decisions move to sandboxd. Bytes stay in Caddy wherever possible, so a
sandboxd restart or crash never resets established HTTP(S) connections
(T1 / outside #3).

**Non-goals:**

- **IP mode** (path routing on :80, no domain) keeps its current behaviour.
- **Owner-side `protocol=tls` port routes** (the owner's layer4 terminates
  non-HTTP TLS) keep one rare write per expose (TODO).

## 3. Design (spike-validated, 2026-09-28)

```
 client ─TLS─▶ INGRESS :443 caddy-l4 tls-mux                    OWNER :443 → http app (Caddy terminates TLS)
               ├─ SNI = apex/API ─────────▶ local API               ┌──────────── ONE static route ─────────────┐
               ├─ SNI *.{domain} or custom ─▶ proxy dial           │ map: {http.request.host} → {sbport}          │
               │    "{l4.tls.server_name}.rt.internal:443"         │   ^[^.]+-(\d+)\.  → $1, default toolbox port  │
               │    resolved by the node resolver → sandboxd       │ reverse_proxy dynamic a                       │
               │    responder (routing domain ~rt.internal)        │   name={http.request.host} port={sbport}      │
               │      owner known  → A owner.DataPlaneHost ───────▶│   resolver 127.0.0.1:{SB_ROUTE_DNS_PORT}      │
               │      owner = self → A 127.0.0.2 (local 443)       │   refresh 1s                                  │
               │      unroutable   → A 127.0.0.2 (local, *.domain  │   static fallback upstream → 127.0.0.1:21213  │
               │                     only; custom → NXDOMAIN=close)│   (sandboxd router, used on NXDOMAIN)         │
               └─ bytes: Caddy ↔ owner, TLS end-to-end (D2)        └───────────────────────────────────────────────┘
 sandboxd: route responder (miekg/dns, loopback) + index    sandboxd router :21213: wake (stopped), 503 in-flux,
                                                                    421 not-local (cluster), 404 unknown/single-node
 raw TCP: sandboxd-owned host-port listeners (T2) — shared L4 primitives (3A), zero-copy splice (7A), restart handoff
```

**Spike evidence** (local, production Caddy build, scratchpad `l4repro/`):

1. **Owner:** `map` + `dynamic a` routed `sb1-18001.example` to backend 1 and
   `sb2-18002.example` to backend 2, with **no per-sandbox config**. A remap
   took effect within `refresh` (1 s) **with no reload**. Responder down gave
   new requests an instant 503; established connections are unaffected because
   the bytes are in Caddy. `dynamic srv` is unusable: Go rejects IP-literal SRV
   targets and resolves hostname targets through the system resolver.
2. **Ingress:** caddy-l4 expands `{l4.tls.server_name}` in `dial`, including
   concatenation (`sb1.example.rt.internal:18001` was dialled). Resolution goes
   through the node's system resolver, so the node needs a routing domain.
3. **"Leak" was a misread (corrected in T3).** The `lookup … on 8.8.8.8` text
   is how Go formats a resolver error: it names the resolv.conf server while
   Caddy's Dial override actually sends every query to the responder. The
   responder's log showed the retry was a **search-domain expansion**
   (`sb3.example.local`) going to the responder itself.
   `TestCaddyStyleResolverNeverLeavesTheResponder` proves no query leaves the
   node. The static route must still name the host **fully qualified**
   (`{http.request.host}.`) to skip search expansion, and the responder is
   authoritative with SOA minimum 1 s.

### 3.1 Static Caddy config (boot-time, idempotent, latch pattern)

- **Owner http app.** One route, `@id sandbox-ingress-proxy`, after the
  apex/API routes. It runs the `map` step, then `reverse_proxy` with
  `dynamic_upstreams {source a, name {http.request.host}, port {sbport},
  resolver 127.0.0.1:$SB_ROUTE_DNS_PORT, refresh 1s}` and one static fallback
  upstream, `127.0.0.1:21213`. The `{sbport}` default is the toolbox/preview
  port. Custom hosts map to their bound port through a responder SRV-free
  path: the responder returns the owner-local target IP, and the custom port
  comes from a per-host `map` entry. Custom-domain binding is rare (an attach),
  so a `map` write there is acceptable; alternatively the router handles it via
  the static fallback. **Decide during implementation, and measure it.**
  (Rare writes are allowed by the goal; per-sandbox lifecycle writes are not.)
- **Ingress `tls-mux`.** One route, `@id sandbox-sni-route`, after the apex
  route. It proxies to `{l4.tls.server_name}.rt.internal:443`.
- **Ingress local listener.** The http app binds `127.0.0.2:443` for
  owner = self and the unroutable fallback: the wildcard cert, then the same
  static route.
- **Node DNS.** A systemd-resolved routing domain, `~rt.internal`, points to
  `127.0.0.1:$SB_ROUTE_DNS_PORT`. It is configured by `install.sh`, Terraform
  and Ansible, and verified at boot. If resolution fails, the node refuses the
  flag, so the flag cannot be half-configured.

### 3.2 sandboxd route responder (new, `internal/service/route_dns.go`)

- `miekg/dns`, already in `go.mod`, listening on loopback UDP and TCP. It is
  authoritative for `rt.internal` and the owner's local zone, so it answers
  SOA/NODATA and never lets a query recurse outward (spike leak, item 3).
- Answers come from the in-memory index (§3.4). **No store read on the query
  path** (outside #2).
- **Ingress answers:** the owner's data-plane host; `127.0.0.2` for
  owner = self or unroutable `*.{domain}` (1A, wildcard only, T5); NXDOMAIN for
  unroutable custom domains, so the connection closes (T5).
- **Owner answers:** the sandbox's container or loopback upstream IP (WASM and
  isolate loopback included) for started, public, exposed targets; NXDOMAIN
  otherwise, which falls back to the router for wake, 503 or 421.
- TTL 1 s, matching `refresh`. Per-query cost is one map lookup.

### 3.2a How the tables are fed (T3)

- **The owner table is maintained through the 4A choke point.**
  SB_INGRESS_PROXY_ROUTING installs `indexRouteWriter` as the
  `publicRouteWriter`. The 77 existing route-intent call sites then write the
  responder's `OwnerTable` instead of Caddy, with exactly the semantics of the
  routes they replace (root, ports, custom hosts, wake, in-flux, by-ID GC). No
  store read is added anywhere.
- **Routes that need per-route behaviour take the router:**
  - a static Caddy route can't rewrite the upstream Host per sandbox, so any
    route with `MaskRequestHost` (E2B `maskRequestHost`) is marked
    `TargetRouter`;
  - WASM and isolate loopback mediators, and custom domains on a port the
    static `map` can't derive, get NXDOMAIN and so fall back to the router.
- **The ingress index is incremental.** `IngressIndex` tracks the hosts per
  sandbox. `cluster.PlacementChangeWatcher` streams the changes:
  - Agents feed it from the delta feed;
  - servers feed it from their own change log in-process.

  Updates cost O(changes), not a 100k-row rebuild per change.
- **Exact-host keys.** Both tables are keyed by the exact hostname Caddy's
  matchers used. Sandbox IDs are only parsed from a host as *candidates* for
  the on-miss placement read, never to route.

### 3.3 sandboxd router (`pkg/api/ingressproxy`, reached only on fallback)

| Case | Answer |
|---|---|
| stopped, serverless | wake, then proxy (existing `WakeAwarePortTarget`) |
| in flux (owner) / unroutable `*.{domain}` (ingress) | 503 + `Retry-After: 2` (1A) |
| well-formed host not local, cluster mode | **421** (2A, T6), with no lookup and no existence oracle |
| unknown, single-node | 404 |
| private or not exposed | 404 |

The router also serves WebSocket and streaming. The daemon mounts it whenever
caddy runs in domain mode.

### 3.4 Placement index and freshness (T3, T4)

- **Every ingress indexes ALL placements for routing (T3).** That is about
  100–150 B per entry, so ~15 MB at 100k placements. The shard filter stays for
  reconcile work only; routing no longer depends on an external shard-aware
  load balancer.
- **Versioned delta feed for Agents (T4), built in T2:**
  `internal/cluster/placement_changelog.go` holds the bounded ring,
  `agent_placement_feed.go` the Agent consumer. The cursor is the Raft index,
  so it is valid against any server; a lagging server waits instead of
  resnapshotting. Merges keep the higher `Placement.Version`, because page
  walks are not a consistent snapshot. A new long-poll
  `GET /v1/cluster/internal/placements/changes?since=N` returns the changes
  since FSM index N, or `resnapshot` when N is older than the retained change
  log. The Agent keeps the index current in about a second. The per-ingress
  full 5 s poll, 100 × 100k rows, goes away. This is in `internal/cluster`, a
  fragile area: it needs regression tests (version gaps, leader change, a
  too-old N) and a PR call-out.
- **On-miss lookup:** one single-flight lookup through the existing
  internal placement point read (`Agent.PlacementOf` →
  `GET /v1/cluster/internal/placement/{id}`), with a negative cache of about
  2 s, so a brand-new sandbox's first connection resolves. *(Corrected during
  T2: `/v1/cluster/ingress-route/{id}` returns ingress ring owners, not the
  placement, so it cannot answer "which owner, which host".)*
- The index is an immutable snapshot behind `atomic.Pointer`. Readers never
  lock; there is one writer.

### 3.5 Raw TCP host ports (T2, built as T7: kernel DNAT)

caddy-l4 can listen on a port range, but it has no port-only placeholder
(`{l4.conn.local_addr}` expands to ip:port), so raw TCP can't stay in a static
Caddy config. **Decision (T7, user):** the kernel forwards it, not sandboxd
user space. The forwarding state lives in conntrack, so a sandboxd restart
never resets an established session, and no bytes pass through sandboxd.

- `internal/network/hostport` keeps one rule set per host port, tagged with
  the comment `aerolvm-hp-<hp>`:
  - nat `AEROLVM-HOSTPORT` (jumped from PREROUTING and OUTPUT for
    `dst-type LOCAL`): DNAT to the target, or REDIRECT to the sandboxd listener.
  - nat `AEROLVM-HOSTPORT-POST`: MASQUERADE for the ingress→owner hop, so the
    owner replies through the ingress.
  - filter `AEROLVM-HOSTPORT-FWD` (FORWARD, position 1): ACCEPT for the DNATed
    flow.
  - `Ensure` is idempotent, and a changed target swaps the rules. `Remove`
    flushes the port's conntrack entries, so a removed exposure stops
    forwarding at once. `Reconcile(desired)` compares rules semantically
    (iptables normalizes its listings) and prunes rules nobody asserted.
- What each intent installs (`indexRouteWriter`, behind the 4A choke point):
  - Owner, started container: DNAT to `container:port`.
  - Owner, stopped serverless sandbox or WASM/isolate loopback mediator:
    REDIRECT to the sandboxd listener (`StartL4RedirectListener`). It reads
    the original host port with `SO_ORIGINAL_DST`, because there is no PROXY
    header, then runs the existing wake/splice path (`proxyL4WakeConn`).
  - Ingress: DNAT to `owner:hostPort`, with masquerade. A DNS-name owner is
    resolved to IPv4 once per upsert.
- The host-port pool (`TryReserveHostPort`, the partial unique index) is
  **unchanged**. Only who forwards changes. pr-review §6 therefore applies
  only as a call-out.

### 3.6 One choke point for per-sandbox route writes (4A)

All per-sandbox HTTP, SNI and TCP route writes go through a `publicRouteWriter`
interface on `Service`: caddy when the flag is off, no-op when it is on. That
covers the 55 HTTP/SNI call sites plus the TCP ones. A counting writer enforces
"zero writes" in tests.

### 3.7 Trust boundary: unchanged (D2)

The ingress reads only the cleartext SNI. Caddy splices TLS to the owner, who
terminates it with its own certs, including on-demand certs for custom
domains. Ingress-only roles do **not** enable on-demand TLS (T5), so tenant
keys stay on owners.

## 4. What disappears / boot-path impact

- **Owner:** every per-sandbox http route, the direct↔wake flips, the in-flux
  routes, and `tcp-port-{hp}` servers.
- **Ingress:** every `…-ingress-sni` route and every TCP proxy server.

**Boot path (pr-review §2):** a public `CreateSandbox` loses its Caddy
write(s). It **gains an index update**, an in-memory O(1) snapshot swap with no
I/O, on every create. **Net: faster.** The first call on a node pays nothing
extra, because the responder starts with the daemon.

## 5. Rollout

- **Flag:** `SB_INGRESS_PROXY_ROUTING`, default **false**. Its rationale goes in
  `setup/config-defaults.md`.
- **Per-node, no flag-day.** Owner and ingress flags are independent; the
  matrix is tested (6A).
- **Flag on:** verify the resolver routing domain, install the static routes,
  make one batched load that removes that node's per-sandbox routes, then
  start the responder and the TCP listeners.
- **Flag off: one batched load** reinstalls everything (T7). It never runs N
  reconcile writes.
- **Ordering:** the delta-feed endpoint and the router ship dark first. The
  resolver config ships before any flip.

## 6. pr-review axes

1. **Idempotency.** There are no route writes, so retries are safe.
   `expose_port` is a store write plus the index update, and returns the
   existing URL.
2. **Boot path.** Less work; one O(1) index update (§4).
3. **Lazy bootstrap.** Static installs and the responder start use the
   `atomic.Bool` + `sync.Mutex` latch pattern.
4. **Failure-path consistency.** The Caddy+store multi-step writes disappear
   for HTTP, SNI and TCP.
5. **TCP pool / L4.** The pool is unchanged. Listener ownership moves, and
   `tls-mux` has static routes only. This needs regression tests in
   `store_test.go` / `layer4_bootstrap_test.go` plus call-outs.
6. **Cluster.** The FSM gets a read-only change-log query; no apply change.
   Leader change: the delta cursor re-snapshots. The index is never guessed:
   an unknown owner falls back (§3.2). Single-node: `Noop` means the node is
   its own owner and the router answers 404.

## 7. Performance

- **Ingress:** caddy-l4 does one DNS lookup to loopback per **new connection**
  (cached `refresh` 1 s per name), then a kernel-level proxy. No sandboxd hop.
- **Owner:** one cached loopback A lookup per request host (1 s TTL); the hot
  path is Caddy → upstream directly. The router hop happens only on fallback.
- **Index:** an atomic load plus a map read. Memory ~15 MB per ingress at
  100k.
- **Delta feed:** control-plane load scales with churn, not with ingress count
  × fleet size.
- **Before any default flip:** the repro harness (0% target) plus a
  latency/throughput A/B.

## 8. Test plan (build contract)

- **Responder:**
  - the answer matrix (ingress: owner / self / unroutable wildcard /
    unroutable custom; owner: started / stopped / private / not exposed /
    WASM / isolate);
  - authoritative NODATA with **no outward recursion**, asserted by capturing
    that no query leaves loopback (spike leak, item 3);
  - TTL;
  - concurrency (`-race`).
- **Router:** wake, 503 in-flux, 421 not-local (cluster), 404 unknown
  single-node, private/not-exposed 404, WebSocket and streaming.
- **Index plus delta feed:**
  - snapshot atomicity (`-race`);
  - delta apply;
  - a gap or too-old N triggers `resnapshot`;
  - leader change;
  - on-miss single-flight plus the negative cache;
  - **cluster regression tests next to the files changed**.
- **Static config:** the golden JSON for owner and ingress routes; idempotent
  re-install; no config writes during lifecycle (counting writer, 4A).
- **TCP listeners:**
  - accept, splice, half-close;
  - caps (the shared `connLimiter`);
  - the zero-copy benchmark (7A);
  - **a rolling-restart test with established sessions surviving**;
  - the pool fragile-area tests.
- **Regression (mandatory):** flag off gives golden writes, identical to today.
- **Rollout matrix (6A):** 4 flag combinations route correctly; flag-on and
  flag-off are **each one batched load** (T7).
- **Custom domains (T5):** the ingress never requests ACME; unroutable custom
  domains close; `EnsureOnDemandTLS` is gated off on ingress-only roles.
- **Coalescing (2A):** two hosts on one h2 connection to the wrong owner give
  421, then reconnect and reach the right owner. **SDK retry-on-421 in all 5
  SDKs.**
- **Repro gate:** churn HTTP **and TCP** routes through the API with the flag
  on and expect **0 failures**; flag off, about 2.6%.
- **Integration:**
  - a new UC for zero connection failures under concurrent expose/unexpose
    churn (HTTP and TCP);
  - a sandboxd-restart UC: established WebSocket and TCP sessions survive;
  - UC-09, 29, 31, custom-domain, serverless and TCP/TLS-port UCs with the
    flag on (hetero-lite + flagship).
- **Coverage:** 85% or higher per package.

## 9. Follow-ups (TODOS)

- Owner-side `protocol=tls` port routes behind a static route.
- IP mode on the router.
- Delete the old per-sandbox route code after the default flips.

## NOT in scope

- **IP mode:** no churn problem at scale there. TODO.
- **Owner `protocol=tls` port routes:** rare writes, and a separate L4 static
  design. TODO.
- **Upstream Caddy fix:** not needed now that no reloads happen per sandbox.
- **Replacing Caddy** for API/apex TLS: out of scope; Caddy remains the TLS
  front.

## What already exists (reused, not rebuilt)

- `pkg/api/ingressproxy`: wake, admission caps, readiness single-flight,
  WASM/isolate upstreams. This becomes the router.
- `internal/service/l4wake.go`: PROXY v1, caps and copy loop. Extracted into
  shared L4 primitives (3A).
- `clusterAwareDomainResolver` plus the ask endpoint: custom-domain
  resolution.
- `/v1/cluster/ingress-route/{id}`: the on-miss lookup.
- `miekg/dns` (in `go.mod`), Caddy `map` + `dynamic a` upstreams, and caddy-l4
  placeholder dial: stock features, validated by the spike.
- `EnsureLayer4Ready`: the latch pattern for the static installs.

## Failure modes

| New codepath | Realistic failure | Test | Handling | User sees |
|---|---|---|---|---|
| Responder down (sandboxd restart) | new owner requests fail | router/restart UC | static fallback upstream; established connections unaffected | 502/503 for ~restart duration on new requests; open sessions survive |
| Resolver routing domain missing | ingress dial NXDOMAIN | boot check | refuse the flag at boot | nothing: the node stays on the old path |
| Stale index after failover | splice to the old owner | coalescing/421 test | the owner answers 421 and the client reconnects | one retry |
| Delta cursor too old | missed changes | resnapshot test | full resnapshot | nothing |
| NXDOMAIN recursion to public DNS | hostname leak | no-egress test | authoritative NODATA | nothing |
| TCP listener restart | sessions reset | rolling-restart test | SO_REUSEPORT / socket passing | nothing |
| Flag-off rollback | reload storm | batched-load test | one load | nothing |
| Custom domain in flux on ingress | TLS close, not 503 | custom-domain test | NXDOMAIN, then close (T5) | a client retry |

No critical gaps: every row has a test and handling.

## Worktree parallelization

| Step | Modules | Depends on |
|---|---|---|
| A. Shared L4 primitives refactor (3A, 7A) | internal/service (l4wake) | — |
| B. Delta feed + Agent index (T4) | internal/cluster, pkg/api/v1 | — |
| C. Route responder + index consumer | internal/service (route_dns) | B |
| D. Static Caddy routes + resolver config | pkg/caddy, scripts/, Terraform/, Ansible/ | — |
| E. publicRouteWriter choke point (4A) | internal/service | — |
| F. Router extensions (421/503/404) + SDK 421 retry | pkg/api/ingressproxy, sdk/* | — |
| G. TCP listeners (T2) | internal/service, internal/network? | A |
| H. Flag wiring, batched load, rollout matrix | internal/service, pkg/daemon | C, D, E, F, G |

**Lanes:**

- **Launch in parallel:** Lane 1 = B → C, Lane 2 = A → G, Lane 3 = D,
  Lane 4 = F.
- **Lane 5 = E:** it shares internal/service with A, C and G, so sequence it
  after A or coordinate.
- **Then H.**
- **Conflict flag:** A, C, E and G all touch `internal/service`, so land them
  sequentially or use careful file separation.

## Implementation Tasks

- [ ] **T1 (P1, human: ~4h / CC: ~30min):** internal/service. Extract the
  shared L4 primitives from l4wake.go, with zero-copy both ways.
  - Surfaced by: Code quality issue 3 (3A) and Performance issue 7 (7A).
  - Verify: the l4wake tests pass, plus a splice benchmark.
- [ ] **T2 (P1, human: ~3d / CC: ~2h):** internal/cluster. Versioned
  placement delta feed for Agents, plus resnapshot.
  - Surfaced by: Outside #4 (T4).
  - Verify: cluster regression tests (gap, leader change, too-old N).
- [ ] **T3 (P1, human: ~2d / CC: ~1.5h):** internal/service. Route responder
  (miekg/dns) plus the all-placement index (T3) and on-miss lookup.
  - Surfaced by: the spike, T3 and T4.
  - Verify: responder answer matrix plus the no-egress test.
- [ ] **T4 (P1, human: ~1d / CC: ~1h):** pkg/caddy plus deploy. Static
  owner/ingress routes, the 127.0.0.2 listener, the resolved routing domain,
  and the boot check.
  - Surfaced by: the spike.
  - Verify: golden config plus a boot-check test.
- [ ] **T5 (P1, human: ~1d / CC: ~45min):** internal/service.
  publicRouteWriter choke point.
  - Surfaced by: Code quality issue 4 (4A).
  - Verify: counting-writer zero writes plus the flag-off golden.
- [ ] **T6 (P1, human: ~1d / CC: ~1h):** ingressproxy plus sdk/*. Router
  421/503/404 and retry-on-421 in 5 SDKs.
  - Surfaced by: Architecture issues 1 and 2, and T6.
  - Verify: router table tests plus the SDK tests.
- [x] **T7 (P1, human: ~2w / CC: ~1d):** internal/network/hostport +
  internal/service. Kernel DNAT forwarding for raw TCP host ports (user
  decision, replacing sandboxd listeners with restart handoff), plus the
  REDIRECT listener for wake and mediator targets. See §3.5.
  - Surfaced by: T2.
  - Verify: forwarder tests (iptables-normalizing fake backend), writer TCP
    intent tests, redirect listener tests. The live session-survives-restart
    check is T10.
- [ ] **T8 (P1, human: ~4h / CC: ~30min):** pkg/daemon. Gate on-demand TLS
  off on ingress-only roles; wildcard-only local fallback.
  - Surfaced by: T5.
  - Verify: the custom-domain tests.
- [x] **T9 (P1, human: ~1d / CC: ~45min):** internal/service + pkg/daemon +
  pkg/caddy. Flag wiring, batched flag-on and flag-off loads, rollout matrix.
  - `caddy.Client.Batch`: every admin call in the window goes to an
    in-memory copy of the config, and the whole window becomes ONE
    `/load`, including concurrent writers.
  - Boot runs Start (before the reconciles, which fill the tables), then
    Commit (once the router serves: static install + prune in one load,
    then the host-port prune). A rollback uses the marker file and is one
    load, re-asserting through the boot reconcile. A failed commit rolls
    back rather than sit half-switched.
  - Surfaced by: Test issue 6 (6A) and T7.
  - Verify: the owner cycle test (engage 0 writes → commit 1 load →
    lifecycle 0 writes → rollback 1 load), the daemon boot matrix (flag ×
    marker × role × failure), batch tests.
- [ ] **T10 (P2, human: ~1d / CC: ~1h):** integration-tests. Churn UC
  (HTTP+TCP), restart UC, and the repro gate with the flag on.
  - Code DONE:
    - `CapIngressProxyRouting` capability;
    - UC-171 churn gate (0 failed fresh HTTP/TCP connections while
      sandboxes churn);
    - UC-172 established TCP + HTTP keep-alive sessions survive a sandboxd
      restart on the ingress and the owner;
    - UC-173 no per-sandbox Caddy routes on any node;
    - scenarios `cluster-3-mixed-routing` and `cluster-hetero-lite-routing`
      (`default_ingress_proxy_routing`, threaded through Terraform to
      `install.sh --ingress-proxy-routing`);
    - `make integration-routing[-hetero-lite]`.
  - Live runs outstanding (AWS spend, operator-run).
  - Surfaced by: the §8 integration line.
  - Verify: hetero-lite plus flagship with the flag on.

## GSTACK REVIEW REPORT

| Review | Runs | Status | Findings |
|---|---|---|---|
| Eng Review (PLAN) | 1 | CLEAR after revisions | Step 0: 1 scope decision (D2), a built-in check (Caddy grace knobs: no fix). Architecture 2, Code quality 2, Tests 2 (+1 mandatory regression), Performance 1: all resolved (1A–7A; 5A superseded by the spike) |
| Outside Voice | 1 | issues_found → resolved | Claude subagent (Codex unavailable: model_unusable). 10 findings: #3/#10 led to the Caddy-native spike (PASSED); #1, #4, #5, #6, #7, #9 were decided as T2–T7; #2 and #8 are resolved by the spike design and this rewrite |

- **Cross-model tension:** the outside voice disagreed with the reviewed
  design, which put sandboxd in the data path. The user chose to spike; the
  spike passed and the design changed.

VERDICT: ENG CLEARED (PLAN): build per the Implementation Tasks. T2 and T7
are fragile-area work (internal/cluster, TCP pool) and need regression tests
plus PR call-outs.

NO UNRESOLVED DECISIONS
