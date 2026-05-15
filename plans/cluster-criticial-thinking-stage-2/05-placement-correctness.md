# 05 - Placement Correctness

The first-stage plan says power-of-two choices is acceptable for steady-state
placement but needs reservations, batching, and rebalancing. That is true, but
the stricter release bar is "proper placement." Proper placement means the
scheduler accounts for the resource and identity constraints exposed by the API,
not just CPU and memory.

## Current placement model

`internal/cluster/placement.go` filters by:

- gossip member alive;
- API URL present;
- CPU budget;
- memory budget.

It then samples two candidates and chooses the one with better CPU/memory
headroom.

This is a good prototype scheduler. It is not a complete release scheduler.

## Missing resource dimensions

### Disk

`CreateSandboxRequest.DiskGB` exists and defaults to 10 GB, but placement does
not model disk capacity or disk pressure.

At 50 sandboxes per runner, the default request implies 500 GB of nominal disk
per runner. If the runtime does not enforce disk quotas, the field still creates
operator expectations. If the runtime does enforce disk later, placement must
already know the budget.

Required:

- node disk inventory;
- reserved disk accounting;
- disk pressure health signal;
- scheduler filter on `DiskGB`.

### GPU

`CreateSandboxRequest.GPUs` exists, but placement does not model GPU inventory.

Required:

- node labels/resources for GPU count/type;
- scheduler filter for GPU requests;
- runtime compatibility filter (`gvisor` cannot satisfy GPU requests);
- failover recreation must not move a GPU sandbox to a non-GPU node.

### Runtime support

Different nodes can have different runtimes or kernel features. Placement needs
a runtime capability signal:

- `docker`;
- `gvisor`;
- future `kata`;
- caddy-l4 support;
- mount driver support.

Without this, a request can be placed on a node that passes CPU/memory but fails
runtime admission.

### L4 port capacity

Raw TCP exposures allocate from a local host port pool. Placement currently
does not know whether the future owner has enough L4 capacity.

This matters if:

- create ever includes initial port exposure;
- a workload creates many TCP exposures after placement;
- stable ingress TCP is implemented with a global pool.

For HTTP/TLS, route table capacity also needs a signal. Caddy can handle many
routes, but admin API latency and config size must be observable.

## Missing identity constraints

### Cluster-wide sandbox names

Sandbox names are unique in local SQLite, not cluster-wide. Any facade that
uses name-based lookup can end up ambiguous if two owners create the same name
concurrently.

Required:

- `name -> sandbox_id` index in Raft/etcd;
- name reservation before local create;
- conflict responses from the control plane, not from a random owner.

### Idempotency keys

If create retry/idempotency keys exist in facades, they need cluster-wide
semantics. Local idempotency is not enough once clients can hit any node and
placement can choose any owner.

Required:

- idempotency key namespace in the control plane;
- compare-and-swap create reservation;
- retry returns the original sandbox ID and owner.

## Reservation-first placement

The current order is:

```text
pick target -> forward -> local create -> raft placement commit
```

The release-grade order should be:

```text
validate request
reserve name/idempotency/resources in control plane
pick target deterministically
record placement intent/reservation
target creates locally
target reports complete or failed
control plane finalizes or releases reservation
```

This costs more control-plane work before docker run. That is the right trade
for cluster correctness.

## Batch placement

A 1000-sandbox burst should not mean 1000 independent stale-gossip placement
decisions.

Required:

- batch create API or internal batch scheduler;
- one scheduler pass over N requests;
- in-batch reservation accounting;
- bounded per-worker fanout;
- per-result response.

This does not need to be in the public SDK v1 if the team is not ready, but the
internal scheduler should support grouped assignments for failover and future
bulk APIs.

## Rebalancing must be conservative

The first-stage plan proposes an hourly rebalancer that destroys and recreates
sandboxes because they are non-HA. Be careful: "non-HA" does not mean
"scheduler may kill user work casually."

Recommendation:

- P0: no automatic load rebalancing that kills running sandboxes.
- P1: operator-triggered drain and maintenance migration.
- P2: opt-in rebalancer only for explicitly disposable sandboxes or sandboxes
  with a lifecycle policy allowing recreation.

Kubernetes can evict pods because pods are declared desired state. AerolVM
sandboxes may be user sessions. Treat automatic kill-and-recreate as a product
policy decision, not just a scheduler tool.

## Placement release checklist

Cluster placement is not "proper" until these are true:

- create target is deterministic and does not reschedule on forwarded request;
- control plane reserves before side effects;
- CPU, memory, disk, runtime, GPU, and health are modeled;
- draining nodes receive no new placements;
- same-name creates cannot succeed on two owners;
- failover target selection excludes nodes that cannot satisfy the full spec;
- scheduler decisions are observable with reason codes;
- create failures release reservations reliably;
- tests cover concurrent create, duplicate name, GPU request, disk pressure,
  stale gossip, and failover recreation.

