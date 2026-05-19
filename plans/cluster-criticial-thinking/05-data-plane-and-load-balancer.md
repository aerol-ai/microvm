# 05 — Data Plane & Load Balancer

The data plane is everything that's **not** the SDK API:

- `https://<id>.sandbox.example.com` — sandbox HTTP URL
- `https://<id>-<port>.sandbox.example.com` — exposed HTTP/TLS port
- `<node-ip>:23xxx` — raw TCP exposed port
- (`ssh user@gateway:2220` for SSH, separate plane — fine as-is)

The control plane (SDK API) has a working forwarding shim
(`clusterForwardWrap`). The data plane does **not**. This is the
biggest functional gap in the cluster design.

This page:

1. Restates the problem against the 200×50 target.
2. Pressure-tests the four candidate shapes for an ingress tier.
3. Picks one and sketches what shipping it looks like.

---

## 1. The problem, restated for 200×50

Today's recommended deployment (`setup/cluster.md:418-518`):

```
Cloudflare DNS  →  AWS NLB (round-robin, TLS passthrough)  →  N × sandboxd+Caddy
```

The NLB has no knowledge of sandbox→owner mapping. It picks a backend
node at random per connection. Caddy on that backend node has routes
only for sandboxes it owns locally.

- **For SDK API** (`https://sandbox.example.com/v1/...`): every node
  serves it via `clusterForwardWrap`. Works.
- **For sandbox URLs**: works only when the NLB happens to pick the
  owner. At N=3, hit rate ~33%. At N=200, hit rate **~0.5%**.

The product brief says public sandbox URLs are not the dominant use
case — most traffic is SDK. But:

- "Most traffic is SDK" is a *bandwidth* statement, not a *value*
  statement. If 1% of requests are sandbox URLs and 99% of those 404,
  the product looks broken to anyone who clicks a sandbox link.
- Several user-visible features rely on sandbox URLs: previews,
  webhooks, OAuth callbacks, `iframe` embeds, shareable preview links.
  At ~0.5% reliability these features are unusable.

So: the cluster *must* solve the data plane to be a real product at
200×50, separate from the question of whether sandboxes are HA.

---

## 2. The four candidate shapes

The existing `plans/fucked-up-design-in-cluster.md` enumerates these
already; this page critiques each at the **200-node** target rather
than the 3-node target the original doc was sized against.

### Shape A: Status quo (DNS RR / L4 NLB)

What it is: today's design. NLB does TLS pass-through; Caddy
terminates on whichever backend the LB picks; if backend ≠ owner, 404.

| Property | 3 nodes | 200 nodes |
|---|---|---|
| API plane | ✓ | ✓ |
| Sandbox URL hit rate | 33% | **0.5%** |
| Failover behavior | ~30 s grace + recreate | same |
| Operator complexity | one LB | one LB |
| Code to write | none | none |

**Verdict at 200:** broken.

---

### Shape B: Per-sandbox DNS

Write a DNS record per sandbox: `<id>.sandbox.example.com →
<owner-ip>`. Update on placement change.

| Property | 3 nodes | 200 nodes |
|---|---|---|
| API plane | ✓ | ✓ |
| Sandbox URL hit rate | ~99% (after TTL) | ~99% (after TTL) |
| Failover behavior | + DNS TTL gap (30–60 s) | same |
| Per-create cost | 1 DNS API call | 1 DNS API call |
| Operator complexity | + DNS provider integration | + DNS provider integration |
| Provider rate limits | within free tier | **at risk** (Cloudflare ~1200 ops / 5 min) |
| Code to write | DNSProvider driver + placement hook | same |

At 200×50, the steady-state DNS write rate is ~3.4 ops/min from
churn. Within rate limits. But during a 50-sandbox failover, you do
50 DNS writes in <30 s. Three of those a day = 150 writes/5min — still
fine.

**Verdict at 200:** *works*, but you've outsourced your routing
correctness to your DNS provider's rate limits and TTL behaviour.
The "URL is stale during TTL gap" property is a real product wart.

---

### Shape C: Cross-node Caddy stub routes ("every node is a router")

Every node's Caddy has a route for every sandbox in the cluster —
local ones point to local containers, remote ones pass-through via
caddy-l4 (SNI) to the owner.

| Property | 3 nodes | 200 nodes |
|---|---|---|
| API plane | ✓ | ✓ |
| Sandbox URL hit rate | ✓ | ✓ |
| Caddy routes per node | T = ~150 | T = **10,000** |
| Caddy admin API calls per placement change | N-1 = 2 | N-1 = **199** |
| Hairpin hop cost | one extra LAN hop on 67% | one extra LAN hop on **99.5%** of traffic |
| Failover update fan-out | small | **massive** — 50 sandbox failover = 50 × 200 = 10K Caddy admin calls |
| Caddy config blob size per node | ~50 KB | ~5 MB |
| Code to write | route reconciler | same + much more error handling |

At 200, this shape **becomes the bottleneck.** Every placement change
ripples to every node's Caddy. Caddy's admin API is one-config-at-a-
time per node. A failover storm of 50 sandboxes triggers 10K admin
operations across the cluster, each one mutating a 5 MB config. The
cluster spends seconds-to-minutes reconciling Caddy.

**Verdict at 200:** designed for 3 nodes. Does not generalize. The
existing plan recommends this at the 3-node scale; at 200, it's
exactly the wrong shape.

---

### Shape D: Dedicated ingress tier (Envoy / HAProxy)

A small set of nodes (3–10) run an L7-aware ingress (Envoy with xDS,
or HAProxy with a config-rewriter). They hold the cluster-wide
SNI-to-owner map. They route to the owner by sandbox ID
(SNI-keyed). The 200 workers don't route for peers — their Caddy
only knows about local sandboxes.

```
              Cloudflare DNS (sandbox.example.com → ingress-tier)
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
        ingress-1  ingress-2  ingress-3        (Envoy / HAProxy, holds SNI→owner)
            │          │          │
            └──────────┼──────────┘
                       ▼
                 200 workers (Caddy serves local sandboxes only)
```

The ingress nodes:

- Watch the placement map from the control plane (same RPC the
  control-plane critique already proposes).
- For each sandbox, hold `(SNI hostname, owner IP)`.
- Use SNI routing for HTTP/TLS sandbox URLs; route to the right
  worker's `:443`.

The workers:

- Same Caddy as today, but only with local routes (no cross-node stub
  routes).
- Receive SNI-pass-through TCP from the ingress, terminate TLS
  locally.

| Property | 3 nodes | 200 nodes |
|---|---|---|
| API plane | ✓ | ✓ |
| Sandbox URL hit rate | ✓ | ✓ |
| Failover behavior | ingress watch picks up new owner in seconds | same |
| Hairpin hop cost | one extra LAN hop on 67% | one extra LAN hop on **99.5%** |
| Routing state size per ingress node | 10K SNI rules | 10K SNI rules |
| Operator complexity | + ingress tier deployment | + ingress tier deployment |
| Code to write | xDS feeder OR HAProxy config-writer | same |

The **hairpin hop is the same as Shape C** — every byte travels
ingress → worker. The difference is that the routing state lives in 3
ingress nodes, not 200 worker Caddys. That's a 200× reduction in
config update fan-out.

**Verdict at 200:** the right shape. Same hairpin cost as the cross-
node-Caddy approach, but with concentrated routing state and a real
LB tier in front. The operator cost of running Envoy is real but is
the same cost K8s operators already accept for ingress-controllers.

---

### Optional: Shape E — `<id>.<node>.sandbox.example.com`

The hybrid the existing plan landed on (Option 6 in
`fucked-up-design-in-cluster.md`). The URL itself encodes the owner
node. DNS wildcards per node (`*.node-c.sandbox.example.com →
node-C-IP`).

| Property | 3 nodes | 200 nodes |
|---|---|---|
| API plane | ✓ | ✓ |
| Sandbox URL hit rate | ✓ | ✓ |
| Failover URL stability | ✗ — URL changes | ✗ — URL changes |
| Per-node wildcard certs | 3 | **200** |
| Cert renewal load on Let's Encrypt | trivial | every node renews its own |
| Operator DNS records | N+1 | N+1 (one per node + the API record) |
| Code to write | URL composition + per-node cert | same |

**Verdict at 200:** technically works; URL-changes-on-failover is the
real trade. Lets-Encrypt-friendly because each node solves DNS-01 for
its own narrow wildcard rather than 200 nodes racing for the same one.

This is actually the cheapest first step. **Ship E first, ship D
later.** The URLs the SDK returns can be opaque enough that the
"failover changes the URL" property is invisible to most users who
fetch a fresh URL via the SDK rather than hardcoding it.

---

## 3. Recommendation

**Ship E first. Move to D when public-URL stability matters.**

The reasoning:

| Driver | Choice |
|---|---|
| Time to ship | E is days; D is weeks |
| Operator burden | E adds DNS records; D adds an Envoy tier |
| Failover URL stability | E breaks; D preserves |
| Self-hosted suitability | E is great; D requires more ops chops |
| Managed offering future | D's ingress tier is the path |

If the goal is "make the cluster genuinely work at 200×50 in self-host
mode in the next quarter", E is the answer.

If the product roadmap calls for stable public URLs (so you can put
them on stickers / docs / OAuth callbacks), D is the answer.

The two are *not exclusive*: E + a stable fallback `<id>.sandbox.
example.com` via Shape C reconciler on a small subset of ingress
nodes gets you both. But it's two pieces of code, so don't pretend
it's one.

---

## 4. What the LB tier actually needs to do

Drilling into Shape D since it's the durable answer.

### Inputs

1. **Placement map** (sandbox_id → owner_ip:port) — pulled from the
   control plane's `/v1/cluster/placements` (a new endpoint that
   exposes the FSM's id→owner mapping).
2. **Member health** — same gossip view the cluster has; or a separate
   health check from the ingress to each worker's :443. Probably
   both.
3. **SNI hostname → sandbox_id mapping** — derivable from sandbox_id
   (the hostname has the id in it).

### Routing rule

For each incoming TLS connection on `:443`:

```
extract SNI hostname
if hostname starts with "<id>." (or "<id>-<port>."):
    look up owner = placements[id]
    if owner alive: TCP-proxy to owner:443
    if owner dead/missing: 502 with "sandbox placement in flux"
else if hostname == api.sandbox.example.com:
    L7-balance round-robin to any healthy worker (or any server with
    API enabled)
else:
    drop
```

Envoy with xDS handles this cleanly. The xDS feeder is a small Go
service (or a goroutine in the control-plane server) that pushes
`Cluster` and `Endpoint` updates to Envoy whenever a placement
changes.

HAProxy with a config-rewriter is the lower-tech version: regenerate
`/etc/haproxy/haproxy.cfg` on placement change, `kill -HUP haproxyd`.
At ~100 placement changes/min, HAProxy reloads at ~1 Hz max — which is
fine for HAProxy.

### Sizing

- 3 ingress nodes is the minimum for HA.
- Bandwidth: every byte of sandbox-URL traffic flows through ingress.
  Size to peak bandwidth, not peak request rate.
- CPU: ~negligible for TCP-passthrough mode. ~modest for TLS
  termination mode if you choose to terminate at the ingress.
- Memory: ~10K SNI rules × ~200 B = ~2 MB. Trivial.
- 3 small nodes (4 vCPU, 8 GB) is enough until you're moving real
  bandwidth.

### Failure modes

- **Ingress node dies:** L4 LB in front (cloud NLB) sheds it. Sub-second.
- **All ingress nodes die:** sandbox URLs go dark; SDK API stays up if
  workers have direct DNS records too.
- **Stale routing table:** ingress watch is eventually consistent; the
  worst case is a few seconds of "route to dead owner" before the
  table updates. Workers return 502 on no-such-sandbox; ingress retries.
- **Misconfigured SNI in client:** falls through to the "drop" rule;
  client gets an unmatched-SNI error.

### Why not just use the worker-as-router approach for ingress?

You can! `sandboxd` running in "ingress only" mode is a viable
implementation of the ingress tier:

- Reuses Caddy + caddy-l4 SNI muxing.
- Reuses the control-plane RPC.
- Reuses the cert distribution story (DNS-01 wildcard).
- No new component to operate.

The catch: Caddy's admin API doesn't gracefully accept 10K SNI rules
in real time. You'd need a thin layer that batches admin reloads.
That's solvable. The result is "`sandboxd --mode ingress` runs
Caddy with the cluster-wide SNI map; doesn't run sandboxes."

This is the **lowest-effort path to D**: ship it as a third
`sandboxd` mode (alongside `server` and `worker`).

---

## 5. The TCP exposure plane

The TCP exposed-port plane (`<node-ip>:23xxx`) is a *direct-to-owner*
URL. The API hands the client the owner's public IP + a host port
from the owner's local pool.

This works today and is fine at 200×50. The catch is the same as the
existing doc notes:

- **On failover, the IP changes** (new owner) and the **host port
  changes** (new owner allocates from its own pool).
- The SDK has to re-fetch.

This is fine for the product semantics. No change needed.

If a future requirement is "TCP URLs should also be stable across
failover" — that's possible by adding TCP forwarding to the ingress
tier:

```
ingress-tier:23xxx  →  TCP forward to owner's :23xxx
```

But: TCP doesn't have SNI, so the ingress would need a per-port-range
mapping table. Doable, not free. **Defer until a user asks.**

---

## 6. Mental model summary

```
                            ┌────────────────────────┐
                            │  PUBLIC DNS            │
                            │  api.sandbox.ex.com  ──┼─►─┐
                            │  *.sandbox.ex.com    ──┼─►─┤
                            └────────────────────────┘   │
                                                         ▼
                                      ┌──────────────────────────────┐
                                      │ Cloud L4 LB (TCP-passthrough)│
                                      └──┬───────────┬───────────┬───┘
                                         ▼           ▼           ▼
                                     ingress-1   ingress-2   ingress-3
                                  (sandboxd --mode ingress,
                                   reads placements from control plane,
                                   SNI-routes to owner over LAN)
                                         │           │           │
                              ┌──────────┴───────────┴───────────┴──────────┐
                              │ Cluster LAN (VPC / WireGuard / etc.)        │
                              └────┬──────────┬──────────┬────────────┬─────┘
                                   ▼          ▼          ▼            ▼
                                worker-1  worker-2   ...        worker-200
                              (sandboxd --mode worker, 50 sandboxes each,
                               Caddy holds local routes only,
                               local SQLite, host port pool)

                              control plane (3–5 nodes) sits on the same LAN,
                              speaks raft to each other, internal RPC to workers,
                              optionally also hosts the ingress RPC for xDS feed.
```

That's the shape. The next page (`06`) walks through what breaks when
parts of this go wrong.
