# Ingress proxy routing: stop reloading Caddy per sandbox

Status: DRAFT for eng review (2026-09-28). Decision: the user chose "route via
the sandboxd proxy" over coalescing writes or an upstream Caddy fix
(TODOS.md, "Ingress route changes reset in-flight TLS connections on :443").

## 1. Problem

Every per-sandbox HTTP route change is a Caddy admin-API write, and every write
reloads Caddy's **whole** config. A reload drops new connections that have not
yet sent a request: the TLS handshake completes, then the connection closes with
zero bytes. The layer4 `tls-mux` in front of :443 adds hard resets on top.

- Reproduced with the production build (Caddy v2.11.4 + caddy-l4),
  `scripts/dev/caddy-reload-repro.py`: **0 failures in ~40k requests without
  churn; ~2.6% of new connections fail under route churn** (2.2% straight to the
  http server).
- Seen live: T19 S6 UC-09, where a TLS dial was reset 0.41s after another
  test's route DELETE, and hetero-lite UC-31, where an `expose_port` POST got
  EOF during a 3-reload burst.
- At the target scale (2,000 nodes × 100k sandboxes × 100 ingress), expose,
  unexpose, stop, wake and failover churn is continuous. So this is a steady
  loss of client connections on every ingress, not a test flake.

Today each public sandbox's HTTP route is written **twice**:

- an http route on the owner, installed by `syncSandboxPublicRoute` /
  `installHTTPPortRoute`;
- an SNI passthrough on every ingress node (`UpsertSNIPassthroughRoute`,
  driven by `ReconcileClusterIngress`), which forwards raw TLS to
  `owner:443`.

Serverless stop and wake flip routes between the direct and wake shapes, which
is two more writes per cycle.

## 2. Goal and non-goals

**Goal:** a sandbox lifecycle or exposure change makes **zero** Caddy writes
for HTTP(S) traffic. Caddy holds static config that changes only at boot and on
operator actions. Routing decisions move into `sandboxd`, which already has the
state, and are made per request from in-memory indexes.

**Non-goals for this plan (they stay in Caddy, unchanged):**

- **Raw TCP host-port servers** (`tcp-port-{hp}`). Each one is its own
  listener, and a listener cannot be added without a config write. Moving them
  means sandboxd owns the listeners itself; the :21214 L4 wake listener is the
  precedent. That is a separate plan.
- **`protocol=tls` port SNI routes** (`…-port-{p}-tls` and their ingress
  passthroughs). These are non-HTTP TLS streams, which an HTTP proxy cannot
  handle.
- **IP mode** (no domain; path routing on :80). It keeps the current behaviour;
  domain mode is where the churn and the scale are.

These remaining writes are rare compared with HTTP route churn, and they are
listed in §9 as follow-ups.

## 3. Design

### 3.1 Static Caddy config (installed once at boot)

On every node that serves sandbox traffic (the owner/worker, and ingress when
`SB_INGRESS_PROXY_ROUTING=true`):

- **http app, `127.0.0.1:8443`** (behind `tls-mux`, as today). There is ONE
  sandbox route, `@id sandbox-ingress-proxy`. It matches host `*.{domain}` plus
  a catch-all for custom domains, ordered after the apex/API routes, and
  proxies to `127.0.0.1:21213` with `X-Forwarded-Host`/`-Proto` preserved,
  `flush_interval -1`, and WebSocket upgrades.
- **TLS:** unchanged. The DNS-01 wildcard covers `*.{domain}`, the apex covers
  the API, and the on-demand policy plus the ask endpoint cover custom domains.
- **`tls-mux`** keeps only the fallback route plus the `protocol=tls` port
  routes (non-goal above). The per-sandbox `…-ingress-sni` passthroughs **go
  away**.

### 3.2 `ingressproxy` becomes the host router

Add a host-dispatch handler alongside the existing `/__ingress/http/...` path,
which stays for wake routes during rollout.

| Host | Target |
|---|---|
| `{id}.{domain}` | the sandbox's toolbox/preview port (what `UpsertSandboxRoute` did) |
| `{id}-{p}.{domain}` | exposed port `p` (HTTP-protocol exposures only) |
| custom hostname | its bound (sandbox, port), via the existing `clusterAwareDomainResolver` |
| anything else | 404 (no information leak about which ids exist) |

For each request:

1. **Parse the host.** Refuse ids that fail `models` validation. Reuse the
   existing `SNIHost`/`PortPublicURL` formats as the single source of the
   naming scheme.
2. **Local owner?** Use `WakeAwarePortTarget`, which already wakes on demand,
   applies admission caps, single-flights readiness, and resolves WASM and
   isolate upstreams. Extend it to also enforce `allow_public_traffic` and
   "port is exposed" for non-serverless sandboxes. Today Caddy enforced that by
   the route existing.
3. **Not local, cluster mode:** look up the owner in the placement index
   (§3.3):
   - owner known and alive: forward over the existing cluster internal mTLS
     channel (`internal/cluster/forward.go` `ForwardHTTP`), with a loop-guard
     header as in `clusterForwardWrap`;
   - owner unknown, or the placement is orphaned/in flux: **503 with
     `Retry-After: 2`**, the same contract the in-flux Caddy routes gave;
   - private placement: 404.
4. **Streaming and upgrades:** keep `FlushInterval=-1`, and support WebSocket
   and h2c-to-upstream as the wake path already does. Per-request timeouts
   follow the current Caddy route settings.

### 3.3 Placement index on ingress nodes (O(1) per request)

Ingress nodes run `cluster.Agent`, which holds no Raft state. It keeps a
placement cache, but `cachedPlacementsForShards` **clones the whole slice on
every call**, which is fine for a reconcile loop and wrong for a per-request
path.

- Add `ingressproxy.PlacementIndex`: a `map[sandboxID]ownerEntry` plus
  `map[customHost]binding`, behind an `atomic.Pointer` to an immutable
  snapshot. Readers never lock, and there is one writer.
- It is fed by the **same** `SubscribePlacement` stream and shard filter that
  `ReconcileClusterIngress` uses today. The delta path updates the map; the
  unchanged-hash short-circuit applies here too.
- **Memory at 100k placements:** roughly 100–150 B/entry, so ~15 MB per ingress
  node. Measured placement wire size is 751 B/placement
  (`project_fleet_scale_read_paths`); the index keeps only id, owner node id,
  data-plane host, public flag, version and state.
- The reconciler's ingress route writes are **deleted**. Its keep-set/GC for
  `…-ingress-sni` becomes a one-time cleanup (§5).

### 3.4 Trust boundary change (call-out)

Today an ingress node passes TLS through to the owner (end-to-end TLS, and the
ingress never sees plaintext). Under this design **the ingress terminates TLS**
and forwards over the cluster's internal mTLS. The client-facing traffic
therefore:

- is decrypted on the ingress (the ingress already holds the wildcard key via
  the shared S3 cert store, `setup/multi-node-cert-sharing.md`);
- is re-encrypted with node mTLS on the hop to the owner. It is never
  plaintext on the wire.

The ingress nodes become part of the trusted computing base for sandbox HTTP
traffic. They are operator-controlled cluster members already, and hold the
same certs. This must be stated in the security docs, and reviewed against
plans/secrets-hardening.md.

Custom domains: ingress nodes need the custom cert. On-demand TLS on the
ingress, with the existing ask endpoint and the shared S3 storage, issues or
loads it. The first request per custom host pays the ACME cost once per
cluster, not once per node, because storage is shared.

## 4. What disappears

- **On the owner/worker** (all shapes and their deletes): `UpsertSandboxRoute` /
  `ToPeer`, `UpsertPortRoute*`, `UpsertWakeHTTPPortRoute`,
  `UpsertInFlux{Sandbox,Port}Route`, and the custom-domain HTTP routes.
- **On ingress:** `UpsertSNIPassthroughRoute` for sandbox roots, HTTP ports and
  custom domains, plus their GC.
- The serverless direct↔wake route flips: the proxy decides per request.
- The `caddyCoalescer` HTTP path. It stays for the TCP/TLS writes that remain.

**Boot-path latency (pr-review §2):** a public `CreateSandbox` loses its Caddy
write, so it gets faster. Private creates are unchanged at zero writes. Nothing
is added to the create path.

## 5. Rollout and version skew

- **Flag:** `SB_INGRESS_PROXY_ROUTING`, default **false**. Its rationale goes in
  `setup/config-defaults.md`.
- **Phase A** (ships dark): the proxy's host router, the placement index, the
  owner-side acceptance of forwarded requests, and the metrics. Off by default.
  All nodes must run a Phase A build before any node flips the flag, because an
  ingress that forwards needs every owner to accept the forwarded request.
- **Phase B** (flag on, per node):
  - boot installs `sandbox-ingress-proxy` and **skips** per-sandbox HTTP route
    writes;
  - a one-time GC deletes existing per-sandbox HTTP routes and `…-ingress-sni`
    routes. This is ONE batched `/load`, so one reload, not N;
  - flag off reverses it: the reconcile loop reinstalls routes as today.
- **Mixed cluster during a rolling flip:** an ingress node with the flag off
  still passes TLS through to `owner:443`. An owner with the flag on serves
  that via its own static route, because the owner terminates TLS for its own
  sandboxes exactly as before. So each node flips independently, with no
  flag-day.

## 6. The pr-review axes

1. **Idempotency.** There are no route writes, so retries are trivially safe.
   `expose_port` becomes a store write plus the index update; it still returns
   the existing URL.
2. **Boot path.** Strictly less work (§4).
3. **Lazy bootstrap.** The static route install uses the `atomic.Bool` +
   `sync.Mutex` latch pattern (`EnsureLayer4Ready` is the model), and is
   retried from reconcile if Caddy is not up yet.
4. **Failure-path consistency.** The Caddy+store multi-step writes for HTTP
   routes disappear. Only the TCP/TLS paths keep their existing rollback rules.
5. **L4 pool / `EnsureLayer4`.** `tls-mux` loses its per-sandbox passthroughs,
   and the fallback route is unchanged. A regression test is needed in
   `layer4_bootstrap_test.go` for "static route present, no per-sandbox
   routes".
6. **Cluster.** No FSM change. The index is read-only over the existing
   placement stream. For leader changes and stale placements, the proxy
   returns 503 + `Retry-After` while the owner is unknown, never a wrong-owner
   forward, because the owner's version fence is checked on the forward.
   Single-node: `Noop` means the index is empty and every request is local.

## 7. Performance budget

- **Added hop:** Caddy to `127.0.0.1:21213` over loopback HTTP/1.1 with
  keep-alive, target **< 0.3 ms p50** added. Cross-node forwarding reuses
  pooled mTLS connections per owner.
- **Index lookup:** an atomic load plus a map read, O(1) with no allocation.
- **Throughput:** Go `httputil.ReverseProxy` on the proxy. Benchmark it against
  a Caddy-only baseline with the repro harness before Phase B.

## 8. Test plan

- **Unit:**
  - host-dispatch table (root, port, custom, unknown, invalid id, private,
    not exposed);
  - index delta apply and snapshot atomicity (`-race`);
  - the forward loop guard;
  - in-flux 503;
  - WebSocket and streaming passthrough.
- **Service:** the flag-on path makes zero Caddy HTTP writes across create,
  expose, stop/wake, custom-domain attach and failover, asserted against the
  fake Caddy (the `ingress_*_test.go` harness). Flag-off stays byte-identical.
- **Repro gate:** `scripts/dev/caddy-reload-repro.py`, adapted to churn
  sandboxes through the API with the flag on, must show **0 failures** where
  flag-off shows ~2.6%.
- **Integration:** a new UC. Under concurrent expose/unexpose churn, N×
  requests to a stable sandbox see 0 connection failures. Plus UC-09, UC-29,
  UC-31 and the custom-domain and serverless UCs with the flag on, in the
  hetero-lite and flagship scenarios.
- **Coverage:** the package stays at 85% or above (CLAUDE.md).

## 9. Follow-ups (separate plans)

- Raw TCP host ports served by sandboxd-owned listeners, which removes the
  `tcp-port-{hp}` writes.
- `protocol=tls` ports behind a static SNI rule into a sandboxd L4 proxy.
- IP mode on the same router (path dispatch).

## 10. Open questions for review

1. **Trust boundary (§3.4).** Is ingress-terminated TLS with mTLS to the owner
   acceptable for the security posture in plans/secrets-hardening.md, or must
   the ingress keep passthrough (which would mean a sandboxd L4 SNI proxy in
   Phase A instead of an HTTP proxy)?
2. **Custom-domain ACME on ingress.** Should the ingress issue certs (shared
   storage), or keep custom domains on per-sandbox passthrough as an exception?
   The exception would retain a rare write, only on attach/detach.
3. **Is the owner still terminating TLS for its own sandboxes** via the static
   route, and does anything else need owner-side Caddy routes? (The agent map
   found none besides TCP/TLS ports.)
