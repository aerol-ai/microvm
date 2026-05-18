# 01 - Scalability Verdict

## Bottom Line

PR #58 is not a 10,000-node or 100,000-sandbox design. It is a single-binary
cluster prototype with several useful correctness patches, but its core
architecture is still "replicate a full global map everywhere and scan it from
many hot paths."

That design can survive a small cluster. It does not survive the requested
scale without a more explicit control plane, worker protocol, ingress tier, and
data model.

## Scale Tier Verdict

| Scale | Current branch verdict | Why |
|---|---|---|
| 3 nodes, 100 sandboxes | Usable for v1 smoke testing, still risky. | Basic owner forwarding and placement can work, but Daytona/E2B/SSH are not cluster-aware and role gates are incomplete. |
| 10-50 nodes, 1,000-5,000 sandboxes | Beta only with strict docs. | Global FSM replication, Caddy route churn, cluster-wide list fanout, and local admission gaps start to matter. |
| 200 nodes, 10,000 sandboxes | Not release-grade without redesign. | Stage 2 fixes remove some functional blockers, but all workers still run Raft/non-voter state, ingress is full-map, list is all-peer fanout, and tests do not exercise real Caddy or real churn. |
| 1,000 nodes, 50,000 sandboxes | Architecturally unsafe. | Raft config, snapshots, gossip scans, route tables, and API fanout become dominant failure modes. |
| 10,000 nodes, 100,000 sandboxes | Not viable. | Membership, control-plane replication, route config, list, create bursts, and port-space limits all become hard bottlenecks. |

## The Most Important PR Reasoning Mistakes

### R1. "Workers do not vote" is not enough

The branch prevents worker/ingress roles from becoming Raft voters in
`internal/cluster/voter_autojoin.go:101-105`, but every cluster node still runs
`setupRaft` in `internal/cluster/client.go:131-138`, and the leader still adds
extra members as Raft non-voters in `internal/cluster/voter_autojoin.go:161-169`.

At 10,000 nodes, "10,000 Raft non-voters" is still a broken control plane:

- every non-voter needs log replication;
- every non-voter can receive snapshots;
- Raft configuration churn includes workers;
- every worker stores full placement state;
- dead-worker cleanup still mutates Raft membership.

The actual scalable split is: workers do not run Raft at all. They should
register via leases/heartbeats and watch only assignments relevant to them.

### R2. The FSM row-size assumption is wrong

`internal/cluster/fsm.go:84-87` says the map is small, "one row per sandbox;
row size ~150 bytes." That is not the current schema. `Placement` carries:

- sandbox ID and owner fields;
- placement version and timestamps;
- a full redacted `CreateSandboxRequest`;
- sealed secret blobs;
- exposed port maps;
- exposed route metadata;
- reservation state and expiry.

At 100,000 sandboxes, the difference between 150 bytes and even 2-10 KB per row
is the difference between "fine" and "large snapshots, large heap, long GC,
large Raft replication, and expensive deep-copy scans." If users put sizable
env maps, tags, mount specs, registry config, or credentials into create
requests, the upper bound is not controlled.

### R3. The placement algorithm is not O(1)

`internal/cluster/placement.go:46-51` describes power-of-two choices as O(1),
but `SelectPlacement` currently:

- reads every gossip member via `c.gossip.members()` at line 58;
- scans every pending reservation via `pendingReservationsByNode` at line 65;
- copies drained-node state at line 71;
- loops over every member at lines 73-89.

`pendingReservationsByNode` itself scans the whole placement map in
`internal/cluster/fsm.go:539-558`.

The random choice is O(1), but the implementation around it is O(nodes +
placements). Under a 100,000-create burst, this becomes a CPU and lock-contention
problem before Docker even starts.

### R4. "10K ingress scale tests" do not prove ingress scale

The branch has useful unit tests around hashing and synthetic operation pools,
but the real risk is Caddy config behavior:

- one route per sandbox or exposed port;
- per-route Caddy admin PATCH/PUT/DELETE calls;
- `PUT /routes/0` insertion that shifts an array in Caddy;
- Caddy config snapshot/gc cost;
- layer4 route table size;
- config reload/apply latency under churn.

The code in `internal/service/service.go:2183-2274` still builds one closure
per route and sends one Caddy admin write per route. The code in
`pkg/caddy/client.go:343-377` and `pkg/caddy/client.go:776-820` still inserts
new routes one at a time.

That is not proof for 100,000 routes, and definitely not for many ingress nodes
each holding the same 100,000-route table.

### R5. The convergence metric can lie

`recordIngressReconcile` updates `aerolvm_ingress_placement_version_max` when
`maxVersion` is higher, regardless of whether the reconcile applied or errored
(`internal/service/ingress_metrics.go:163-178`). `ReconcileClusterIngress`
calls it on the error path at `internal/service/service.go:2285-2287`.

Result: a failed Caddy reconcile can still advance the "installed version"
gauge. Then `/v1/cluster/placements/{id}` may report `converged=true`, and
`aerolvm_ingress_route_lag_versions` may go to zero, even though routes were
not actually installed.

This invalidates one of the PR's central observability claims.

### R6. The cluster layer only covers v1

The v1 routes use `clusterCreateWrap`, `clusterListWrap`, and
`clusterForwardWrap` in `pkg/api/v1/routes.go`.

Daytona and E2B do not. Daytona creates sandboxes by directly calling
`Service.CreateSandbox` at `pkg/api/daytona/handlers.go:61`; E2B does the same
at `pkg/api/e2b/handlers.go:103`. Their routes in
`pkg/api/daytona/routes.go:56-74` and `pkg/api/e2b/routes.go:24-32` are not
wrapped by owner forwarding.

That means a major part of the public product surface remains local-node only:

- create does not write a placement;
- get/delete/connect/start/stop can 404 on the wrong node;
- E2B idempotency is local SQLite, not cluster-wide;
- Daytona/E2B list is local, not cluster-wide;
- facade mutations do not replicate spec updates.

At scale, this breaks the "any node can accept any request" premise.

### R7. Roles are not enforced by scheduling or handlers

`Config` has `server`, `worker`, and `ingress` roles, but `SelectPlacement`
does not filter on worker role (`internal/cluster/placement.go:73-89`). The API
handlers also do not reject worker-only operations on pure server/ingress nodes.

`cmd/sandboxd/main.go:41-125` constructs the store, Docker client, Caddy client,
secret cipher, mount manager, and service before any role-specific gating.
Even pure server/ingress nodes still pay those dependencies and can still run
handlers that call into them.

This is not a real role split. It is partial background-loop gating.

### R8. "Sandbox recovery" is not actually enabled

`clusterRecreateOnFailoverEnabled` is false in
`internal/cluster/dead_owner.go:18-25`. Dead owners are orphaned, not
recreated. That product policy may be acceptable, but the PR reasoning should
not lean on spec replication as if failover recreate is a shipped behavior.

Worse, false-positive dead-owner orphaning can create a permanent control-plane
orphan while the original sandbox still exists locally. `AssertOwnership` does
not reclaim an existing orphaned placement, and `reconcileStaleOwnership`
intentionally ignores `ErrOrphaned`.

At large node counts, false-positive liveness events are not rare edge cases.

