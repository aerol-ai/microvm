# 04 - Data Plane Load Balancer

The first-stage plan correctly identifies that public sandbox URLs are broken
behind DNS round-robin or a dumb L4 NLB. Stage 2 raises the bar: cluster mode
should release with a real owner-aware network ingress, or it should not claim
to support cluster networking.

## Traffic planes

| Plane | Original PR status | Current branch status | Release-grade requirement |
|---|---|---|---|
| SDK/API calls to `/v1/...` | Conceptually owner-forwarded, but create has a blocker | Target-locked create forwarding is implemented. | Any node/API frontend can accept; zero wrong-owner writes. |
| Sandbox HTTP URL | Owner-local Caddy route only | Non-owners reconcile owner-aware routes. | Stable through owner-aware ingress with measured convergence. |
| Exposed HTTP port URL | Owner-local Caddy route only | Non-owners reconcile owner-aware routes. | Stable through owner-aware ingress with measured convergence. |
| Exposed TLS/SNI port URL | Owner-local caddy-l4 SNI route only | Non-owners pass SNI through to the owner mux. | Stable through owner-aware SNI ingress with measured convergence. |
| Raw TCP exposure | Direct owner `host:port` | TCP host port is replicated and bound/proxied on every node. | Stable via global ingress port map with conflict handling and SLOs. |
| UDP exposure | Not supported | Not supported. | Do not document until designed. |

## Required load-balancer shape

The durable design is a small ingress tier:

```text
public DNS
  -> cloud NLB / BGP VIP / MetalLB-assigned VIP
  -> 3+ ingress instances
  -> owner worker's local Caddy / host port
```

The ingress tier watches the placement/route map from the control plane and
routes by hostname/SNI for HTTP/TLS.

For a production line, workers should not all hold routes for every sandbox in
the cluster. They should hold local routes, and a small ingress tier should hold
the public route map. This prevents the "10K sandboxes x 200 workers" Caddy
config explosion.

This branch intentionally takes a smaller product step: every node runs an
ingress reconciler and can accept public traffic. That is acceptable for a
cluster beta and removes the 1/N correctness gap, but it must be load-tested
before it becomes the production topology.

## Envoy, HAProxy, or sandboxd-ingress

### Envoy with xDS

Best long-term managed-service answer.

Pros:

- dynamic config is a first-class Envoy feature;
- xDS is designed for route/endpoint updates;
- strong observability;
- can support TCP passthrough and TLS/SNI routing.

Cons:

- operators must run Envoy and an xDS management server;
- more moving parts for self-hosted users;
- xDS correctness becomes part of the product.

### HAProxy with generated maps/config

Good low-tech answer.

Pros:

- operationally familiar;
- can use map files for SNI/hostname routing;
- easier than xDS for a first release.

Cons:

- reload batching must be designed;
- high route churn needs careful testing;
- less elegant controller model than Envoy.

### `sandboxd --mode ingress`

Best self-hosted product answer if the team wants one binary.

Pros:

- reuses existing Caddy/caddy-l4 integration;
- reuses placement watch and cluster TLS;
- simpler install story than Envoy;
- can later be replaced by Envoy for managed deployments.

Cons:

- Caddy route scale and admin reload behavior must be load-tested;
- the team owns the route reconciler;
- must avoid the worker-as-router mesh problem by running only a small ingress
  tier, not every worker as ingress.

## MetalLB is not the routing solution

MetalLB is useful when AerolVM is deployed inside Kubernetes or on bare metal
and needs a `LoadBalancer`-style VIP. It allocates and announces IPs using
standard networking/routing protocols.

It does not know `sandbox_id -> owner`. It does not route SNI to the correct
worker by itself.

Use MetalLB like this:

```text
MetalLB/VIP
  -> Envoy or sandboxd-ingress Service
  -> owner worker
```

Do not describe MetalLB as a replacement for Envoy, HAProxy, or a route-aware
`sandboxd --mode ingress`.

## Raw TCP needs a separate decision

Raw TCP has no hostname and no SNI. If the product wants a stable cluster-wide
TCP endpoint, the control plane needs a global L4 model:

```text
ingress.example.com:31042 -> node-17:22491 -> sandbox container:5432
```

The branch now implements the core of this model:

- cluster-wide TCP host-port uniqueness is checked by the placement FSM;
- `ExposePort` records TCP `HostPort` in Raft;
- every node can bind the same `hostPort` and proxy to the owner;
- failover replay tries to preserve the same `hostPort`.

The production version still implies:

- a clearly defined cluster-wide ingress port pool;
- Raft/etcd-backed allocation with durable revisions;
- route map watched by ingress rather than only polled;
- health checks and retry/failover behavior;
- response schema that clearly returns the ingress endpoint;
- migration behavior when the owner dies and the preferred host port is not
  available on the new owner.

If the product ever backs away from this scope, say so explicitly:

> HTTP/TLS sandbox URLs are stable through cluster ingress. Raw TCP endpoints
> are direct-to-owner and must be re-fetched after failover.

That is an acceptable product line. What is not acceptable is implying raw TCP
is load-balanced when it is owner-local. This branch now chooses the stronger
cluster-stable TCP line, so the release gates need to prove it under churn.

## Per-node URLs are not enough

`<id>.<node>.sandbox.example.com` can be a cheap workaround. It makes DNS land
on the owner without writing one DNS record per sandbox.

But it is not the same as a load balancer:

- URLs change when ownership changes.
- Raw TCP is still owner-local.
- A node-specific URL leaks placement into the public API.
- It does not provide a stable shared ingress endpoint.

Per-node URLs can ship as an escape hatch. They should not be the main answer
for a "cluster mode comparable to Kubernetes robustness" release.

## Required release behavior

For HTTP/TLS:

- placement change to route update convergence under 2 seconds p95;
- zero 404s caused by wrong-owner ingress after convergence;
- ingress removes or marks dead-owner routes during failover;
- ingress serves a clear 502/409 during placement-in-flux, not a Caddy fallback;
- route table can hold 10K sandboxes with headroom;
- route update storms from 50-sandbox node failure are batched and bounded.

For TCP if supported through ingress:

- one global endpoint per exposure;
- no duplicate ingress port allocations;
- route update after failover is bounded;
- clients can distinguish "sandbox gone" from "route not converged."
- local host-port conflicts on failover are surfaced clearly and do not loop
  forever without operator visibility.

For UDP:

- explicitly unsupported until a design lands.
