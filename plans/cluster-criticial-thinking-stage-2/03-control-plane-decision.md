# 03 - Control Plane Decision

The first-stage plan says "use a small fixed control plane." That is correct,
but not specific enough. The real decision is whether AerolVM should keep the
current embedded HashiCorp Raft FSM or adopt an etcd-style control plane.

## What Kubernetes-grade robustness means here

Kubernetes robustness does not mean every sandbox is highly available. It means
the cluster control plane has these properties:

- small, stable consensus group;
- durable state with backup/restore;
- monotonic revisions and watch streams;
- idempotent desired-state writes;
- controllers that reconcile desired state into runtime state;
- explicit node health, drain, and scheduling constraints;
- bounded behavior during partitions and lost quorum;
- observable health and documented recovery.

Current PR #58 has some of this, but not enough to call it release-grade at
200 runners.

## Option A - Keep HashiCorp Raft and build the missing control-plane APIs

This is the shortest path from PR #58.

### What stays

- `internal/cluster/fsm.go` as placement state.
- `internal/cluster/raft.go` as the consensus layer.
- `internal/cluster/gossip.go` for membership and coarse liveness.
- `owner_watcher` and `dead_owner` as controllers.

### Required additions

- `server|worker|ingress|mixed` node roles.
- Workers do not run Raft.
- A revisioned placement watch:
  - `GET /v1/internal/placements?since=<revision>`;
  - monotonic durable revision based on Raft log index or persisted FSM version;
  - compacted revision error, so clients know to relist.
- Worker heartbeat:
  - capacity;
  - running sandbox IDs;
  - runtime health;
  - disk pressure;
  - GPU inventory;
  - image-cache hints;
  - route/port pool health.
- Explicit admin APIs:
  - promote/demote server;
  - drain/uncordon worker;
  - remove dead node;
  - list placements with revision;
  - force orphan/delete placement.
- Snapshot backup/restore runbook for the Raft data directory.

### Pros

- Smallest code delta.
- Keeps the "single binary" self-hosted story.
- Existing tests and FSM commands remain useful.
- Good fit if the initial release hard-caps production guidance to 3-5 servers
  plus workers.

### Cons

- AerolVM must implement etcd-like watch semantics itself.
- Backup/restore, compaction behavior, lease-like liveness, and revision
  handling are now product code.
- Operational tooling will be custom.
- A subtle FSM bug becomes a cluster outage risk because there is no mature
  storage layer below it.

## Option B - Move placement state to etcd

etcd is a distributed, consistent key-value store built around Raft. Kubernetes
uses it as the source of truth for cluster state. The official etcd FAQ also
calls out the leader-based nature of Raft: consensus writes go through the
leader.

### What changes

Raft FSM state becomes etcd keys:

```text
/aerolvm/placements/<sandbox_id>
/aerolvm/names/<name>
/aerolvm/nodes/<node_id>
/aerolvm/reservations/<sandbox_id>
/aerolvm/ingress/http/<hostname>
/aerolvm/ingress/tcp/<port>
```

Controllers watch key prefixes instead of local FSM snapshots:

- scheduler writes reservations and placements with compare-and-swap;
- workers watch placements assigned to them;
- ingress watches route maps;
- dead-owner reconciler watches node leases;
- list scans etcd state rather than fan-out to workers.

### Pros

- Mature watch API with revisions.
- Built-in compaction model.
- Clear backup/restore story.
- Familiar to Kubernetes operators.
- Easier to build controller-style reconciliation.
- Removes custom Raft membership code from `sandboxd`.

### Cons

- Operational dependency: users now run an etcd cluster or let AerolVM embed and
  supervise it.
- Bigger install/runbook surface.
- Significant rewrite of `internal/cluster`.
- Requires etcd TLS/auth lifecycle.
- If embedded poorly, it becomes "custom control plane plus hidden etcd," which
  is worse than the current honest one-binary model.

## Recommendation

For PR #58, do not switch to etcd unless the release can absorb a large delay.
Instead:

1. Keep HashiCorp Raft for the near-term.
2. Immediately split server and worker roles.
3. Build explicit revisioned watch APIs.
4. Add backup/restore and lost-quorum recovery docs.
5. Write an architecture decision record explaining why etcd is deferred.

Revisit etcd when one of these becomes true:

- multiple teams are adding controllers and watch consumers;
- ingress requires high-churn route watches;
- operators ask for Kubernetes-like backups and disaster recovery;
- Raft FSM/watch code becomes a source of correctness bugs;
- managed AerolVM becomes the primary deployment model.

## What the first-stage plan should change

The plan should not simply say "small fixed control plane." It should add a
decision section:

| Decision | Required before release? |
|---|---|
| Keep embedded Raft for v1 cluster mode | Yes |
| Define server/worker/ingress roles | Yes |
| Define durable watch revision semantics | Yes |
| Decide whether etcd is deferred or adopted | Yes |
| Add backup/restore and lost-quorum procedures | Yes |
| Add node leases or lease-like liveness | Yes |

Without this, the plan borrows Kubernetes's architecture shape but skips the
part that makes Kubernetes robust: a strongly consistent store with a controller
watch model.

