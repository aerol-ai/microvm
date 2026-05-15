# 01 - Review Of The Stage-1 Plan

The first-stage plan is useful and mostly correct at the architecture level.
It should not be treated as release-ready. It is a pressure-test, not yet a
decision record.

## What the plan gets right

### 1. It names the real P0 architectural problems

The plan correctly identifies that auto-promoting every runner into a Raft
voter does not scale to 200 nodes. That is the right critique. A robust cluster
needs a small control plane and a larger worker fleet, not 200 consensus
participants.

It also correctly identifies the public sandbox URL gap. API traffic can be
forwarded by Go handlers because the handler can read the sandbox ID from the
path. Caddy data-plane traffic cannot do that unless there is an owner-aware
route table in front of it.

### 2. It respects the product's non-HA sandbox semantics

The plan does not over-design pod-style high availability. It accepts that
container filesystem state, exec sessions, port-forward streams, and local host
ports vanish when a runner dies.

That is the right product stance. The cluster should be robust. Individual
sandboxes are disposable unless users explicitly mount durable storage.

### 3. It is grounded in code

The first-stage plan reads `internal/cluster`, `pkg/api/v1`, `setup/cluster.md`,
and the failover code paths. That makes it much more valuable than a generic
"use Kubernetes" argument.

### 4. It points toward the right target shape

The proposed end state is directionally correct:

- 3 or 5 server/control-plane nodes;
- many worker nodes;
- workers heartbeat capacity and watch assigned placements;
- a dedicated ingress tier routes sandbox URL traffic by placement;
- drain, reservation, failover pacing, and health-aware scheduling.

That shape is close to the Kubernetes/K3s mental model without forcing this
product to become Kubernetes.

## Where the plan is too soft

### 1. It assumes the API create path is healthier than it is

The first-stage current-architecture doc says a create request forwarded to
target `T` "runs the same wrap, sees IsSelf=true, runs createSandbox locally."
That is not what the current code guarantees.

In `pkg/api/v1/cluster_handler.go`, `clusterCreateWrap` always calls
`SelectPlacement` again on the receiving node. `ForwardHTTP` sets
`X-Cluster-Forwarded: 1`, and `ForwardHTTP` returns 421 if a forwarded request
would be forwarded again. So the request path is:

1. node A picks node T;
2. A forwards `POST /v1/sandboxes` to T;
3. T re-runs placement instead of honoring "T is the target";
4. if T chooses any node other than T, the second forward fails as a loop.

At 200 nodes, T is unlikely to select itself on the second random placement.
This makes create unreliable before any Raft scaling issue appears.

This is the most important stage-2 correction: the API plane is not
"bulletproof" yet. Per-sandbox API calls after placement are conceptually fine;
create is not.

### 2. It makes ingress optional too late

The first-stage plan says "ship per-node URLs first, ship ingress later." That
is acceptable only if cluster mode is explicitly documented as SDK-only and not
a complete network product.

The stated target here is different: cluster mode should release with a real
load balancer for network traffic. Under that bar, owner-aware ingress is not
next-quarter hardening. It is a release blocker.

Per-node URLs can be a compatibility escape hatch, but they are not a load
balancer. They also do not solve stable raw TCP exposure through one public VIP.

Implementation note: this branch now adds an owner-aware ingress reconciler on
each node, plus replicated raw TCP host-port metadata. That removes the original
1/N public URL failure mode. The remaining criticism is that the route map is
poll-reconciled from the local FSM and lacks the production traits a dedicated
ingress control plane would need: watch revisions, batching, route-lag metrics,
health-driven backend removal, and load-tested Caddy admin behavior at 10K
routes.

### 3. It critiques Raft voter count but does not make a storage decision

The plan recommends a server/worker split but does not force a decision between:

- keeping the embedded HashiCorp Raft FSM and building watches, leases,
  compaction, backup/restore, and revision semantics ourselves;
- moving placement state to etcd and treating `sandboxd` control-plane logic as
  API/controllers on top of a proven store.

If the goal is "Kubernetes-grade robustness," this decision cannot be left as
implicit. Kubernetes uses etcd as the consistent store and builds controllers
around watch streams. A custom FSM can work, but then the plan must explicitly
own all the etcd-like features it needs.

### 4. It under-specifies the network planes

The first-stage data-plane doc is good for HTTP and TLS/SNI. It punts raw TCP as
"direct-to-owner is fine." That is not enough if the product promise includes
a load balancer for network traffic.

HTTP/TLS can route by hostname/SNI. Raw TCP cannot. UDP is not supported at all
today. A release-grade networking plan needs to say exactly which of these are
stable through the cluster ingress:

- sandbox public HTTP URL;
- exposed HTTP port URL;
- exposed TLS/SNI port URL;
- raw TCP host:port;
- future UDP.

If raw TCP stays direct-to-owner, the product documentation must say that. If it
must be load-balanced through one endpoint, the control plane needs a
cluster-wide L4 port allocator and an ingress `port -> owner:hostPort` map.

Implementation note: this branch chose the cluster-stable TCP path. The Raft
placement now records `HostPort` for TCP routes, the FSM rejects duplicate TCP
host-port reservations across placements, each node binds the same host port,
and non-owners proxy to the owner. That is the right product direction. It
still needs scale and failure testing around local port conflicts, route
convergence after ownership changes, and route garbage collection during churn.

### 5. It treats placement as mostly CPU/memory, but the API is richer

The current scheduler scores CPU and memory only. The plan mentions node labels
and taints but does not elevate several existing API fields to release blockers:

- `DiskGB` exists but disk capacity is not part of placement.
- `GPUs` exists but GPU availability is not part of placement.
- sandbox `Name` uniqueness is local SQLite state, not cluster-wide state.
- raw TCP port pool availability is local, not part of placement or ingress.

If the requirement is "sandbox placement should be completely proper," these
are not optional niceties. They are correctness holes.

### 6. It lacks release gates

The plan has priorities, but not pass/fail release criteria. A production-grade
cluster document should include measurable gates:

- create success rate under forwarded requests;
- Raft apply p50/p99 under burst;
- route table convergence after placement change;
- zero wrong-owner writes;
- bounded list latency;
- failover storm behavior;
- no route misses for public URLs after convergence;
- chaos tests for partitions and restarts;
- backup/restore and lost-quorum recovery drills.

Without these gates, "200 runners x 50 sandboxes" remains an aspiration.

## Stage-2 conclusion

Keep the first-stage plan as the architecture critique. Add this stage-2 folder
as the release critique.

The release bar should be:

- P0: keep the target-locked create fix and move toward reservation-before-create;
- P0: keep the voter cap and design a real server/worker role split;
- P0: harden the owner-aware ingress implementation with watch semantics,
  metrics, and scale tests;
- P0: define exactly which network protocols are cluster-stable;
- P0: make placement correct for the API fields already exposed;
- P0: add measurable scale and chaos gates.
