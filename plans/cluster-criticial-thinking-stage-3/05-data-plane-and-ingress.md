# 05 - Data Plane And Ingress

## P0. Every Ingress Node Holds A Full Route Map

**Where:**

- `internal/service/service.go:2136-2295`
- `cmd/sandboxd/main.go:203-205`

Every node with the ingress role calls `ReconcileClusterIngress`, snapshots the
full placement map, hashes it, builds operations for remote placements, and
writes Caddy routes.

If operators leave the default `mixed` role, every worker is also ingress. In a
10,000-node cluster with 100,000 sandboxes, that can become:

```text
10,000 nodes x 100,000 routes = 1,000,000,000 route entries
```

That is not a scalable ingress architecture.

**Required redesign:**

- default cluster role should not be `mixed` for production;
- workers should not hold global public routes;
- a small ingress tier should watch route deltas;
- ingress should be horizontally scaled by route shard, tenant, or hostname
  partition if 100,000 routes is required;
- route data should be delivered incrementally, not full-map scanned.

## P0. Caddy Admin Writes Are One-Route-At-A-Time

**Where:**

- `internal/service/service.go:2183-2274`
- `pkg/caddy/client.go:343-377`
- `pkg/caddy/client.go:776-820`

The reconciler builds one closure per route, then `runIngressOps` executes
those closures with a concurrency cap of 8. Each closure generally does one
Caddy admin request.

New routes use `PUT /routes/0`, which inserts at the front of an array. Even
if the client-side code treats this as O(1), the server-side config mutation is
not proven O(1). Repeating this for tens or hundreds of thousands of routes is
not safe without real benchmarks.

**Required proof:**

- cold install 100,000 HTTP routes into Caddy;
- cold install 100,000 SNI routes into caddy-l4;
- update 1,000 random routes per minute for 60 minutes;
- delete 10,000 routes from a dead-owner event;
- measure Caddy admin p50/p95/p99, memory, config size, reload/apply latency,
  and route miss rate.

If Caddy cannot meet the SLOs, use Envoy xDS, HAProxy maps, or a custom
sandboxd-ingress route table instead.

## P0. Ingress Reconcile Is Full-Scan And Full-Sort

**Where:**

- `internal/service/service.go:2148-2157`
- `internal/service/ingress_metrics.go:200-260`

Each reconcile calls `c.Placements()`, which deep-copies the FSM map, then
`hashPlacementView` allocates a map and slice, sorts all sandbox IDs, and
hashes route fields.

At 100,000 sandboxes this may be acceptable once every few seconds on a small
ingress tier. It is not acceptable after every placement mutation on many
nodes. The push channel collapses signals, but it does not turn full-map work
into incremental work.

**Required redesign:**

- watch route deltas by revision;
- debounce bursts;
- apply batches;
- keep an ingress-local route cache keyed by sandbox ID;
- avoid sorting the full world on every mutation.

## P0. Ingress Metrics Can Report False Convergence

**Where:**

- `internal/service/ingress_metrics.go:163-178`
- `internal/service/service.go:2274-2294`

`recordIngressReconcile` advances `ingressPlacementVersionMax` even when the
reconcile outcome is `reconcileErrored`. This makes the installed version
metric and `/v1/cluster/placements/{id}.converged` unreliable.

Failure mode:

1. Caddy admin is down or rejects a route.
2. `runIngressOps` returns an error.
3. `recordIngressReconcile(reconcileErrored, ..., maxVersion)` still advances
   the installed-version gauge.
4. route lag can fall to zero.
5. the placement endpoint can say converged even though no route exists.

**Required fix:**

- only advance installed version after a successful reconcile;
- track attempted version separately from installed version;
- track per-route failures;
- make convergence read from reconciler state, not a process-global expvar;
- add a regression test where Caddy fails and `converged` remains false.

## P0. Raw TCP Has A Hard Port-Space Ceiling

**Where:**

- `internal/config/config.go` L4 port range defaults
- `pkg/caddy/client.go:612-681`

Raw TCP cluster-stable exposure consumes one host port per exposed port. The
default port pool is 22000-23000, roughly 1,001 ports. Even if operators expand
it, a single shared host-port namespace has a hard ceiling well below 100,000.

If every sandbox exposes one raw TCP port, 100,000 concurrent sandboxes cannot
fit behind this design.

**Required product decision:**

Pick and document one of these:

- raw TCP is limited by a configured cluster-wide port pool;
- raw TCP requires per-sandbox IPs or per-tenant load balancers;
- raw TCP endpoints are owner-local and must be re-fetched;
- raw TCP at 100,000 scale is not supported.

Do not imply raw TCP scales like HTTP hostnames.

## P1. Host-Port Reservation Is O(sandboxes x ports)

**Where:**

- `internal/cluster/fsm.go:476-490`

`validateHostPortAvailableLocked` scans all placements and all exposed port
routes to check whether a TCP host port is already reserved.

At 10,000 placements this may benchmark acceptably. At 100,000 placements,
with a nearly full port pool and many concurrent allocations, it becomes a
leader-side hot path. The linear fallback in `allocateHostPort` can repeat this
scan many times.

**Required fix:**

Maintain an FSM index:

```text
host_port -> sandbox_id:container_port
```

and update it inside `opAddExposedPort`, `opRemoveExposedPort`, `opDelete`, and
snapshot restore.

## P1. Caddy GC Scans Local Store And Global Routes

**Where:**

- `internal/service/service.go:1875-1940`
- `internal/service/service.go:2342-2350`

Zombie route GC builds keep sets from local sandboxes and cluster placements,
then compares against a Caddy snapshot. At 100,000 global routes this becomes
large memory and CPU work. It also runs from the same reconcile path that is
trying to catch up route mutations.

**Required redesign:**

- separate route GC from route apply;
- shard route ownership;
- keep route state in a reconciler cache;
- avoid taking full Caddy snapshots on every reconcile pass;
- expose GC duration and deleted counts.

## P1. DataPlaneAdvertiseHost Can Create Routing Loops

Remote ingress uses `OwnerDataPlaneHost` to proxy to the owner. If operators
misconfigure it to the same public load balancer or wildcard ingress host that
clients use, an ingress node can proxy back into the load balancer instead of
to the owner.

At small scale this is a confusing outage. At large scale it is a traffic
amplifier.

**Required fix:**

- validate that `SB_DATA_PLANE_ADVERTISE_HOST` is an owner-reachable private
  address, not the public ingress hostname;
- add startup warnings for loopback, wildcard, and known public ingress values;
- add a peer reachability check.

## P1. HTTP/TLS And Raw TCP Need Separate Capacity Models

HTTP/TLS route count, raw TCP bound sockets, Caddy admin latency, file
descriptors, conntrack entries, and per-upstream connection pools are separate
capacity dimensions. The scheduler does not know any of them.

At 100,000 sandboxes, "the node has CPU/memory" is not enough. An ingress node
can be saturated by route count or connections while a worker still has CPU.

**Required fix:**

- advertise ingress capacity separately from worker capacity;
- track route count, active connections, accepted connections, open FDs,
  Caddy admin p99, and route table memory;
- exclude degraded ingress nodes from public LB health;
- define route shard ownership.

