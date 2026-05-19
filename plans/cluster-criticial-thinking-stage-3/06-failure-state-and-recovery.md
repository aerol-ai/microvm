# 06 - Failure State And Recovery

## P0. False Dead-Owner Orphaning Can Be Permanent - Fixed

**Where:**

- `internal/cluster/cluster.go` defines explicit owner state and orphan
  metadata on `Placement`.
- `internal/cluster/fsm.go` implements `opOrphanOwner` and `opClaimOrphan`.
- `internal/cluster/client.go` and `internal/cluster/agent.go` reclaim only
  previous-owner or legacy orphans during `AssertOwnership`.
- `pkg/api/v1/cluster_handler.go` exposes orphan inspect/reclaim/delete
  operator paths.

Automatic failover recreate is disabled. The leader orphans placements when a
node is considered dead. If the liveness decision was a false positive, the
original owner can still have the local sandbox running.

This branch now has a bounded recovery path:

- orphaned placements carry `owner_state=orphaned`,
  `orphaned_owner_node_id`, and `orphaned_unix`;
- `AssertOwnership` can reclaim only when the previous owner is this node (or
  the row predates previous-owner metadata);
- `POST /v1/cluster/orphans/{id}/reclaim-local` requires a local sandbox row
  before claiming;
- `DELETE /v1/cluster/orphans/{id}` force-deletes an orphaned placement record;
- active foreign owners and other nodes' orphans are deliberately not
  claimable.

Clients still see 410 for unreclaimed orphans, which matches the current
product policy that running sandboxes are not automatically highly available.

Remaining product decision:

- whether to add opt-in recreate queues/backoff for sandboxes whose owner is
  truly gone.

## P0. Dead-Owner Handling Is One Raft Write Per Sandbox - Fixed

**Where:**

- `internal/cluster/dead_owner.go` sends one `opOrphanOwner` command in the
  no-recreate policy path.
- `internal/cluster/fsm.go` maintains `ownerIndex` and
  `pendingReservationIDsByOwner`, so the command does not scan the full
  placement map.
- `internal/cluster/scale_gates_test.go` includes a 100k-placement batch
  orphan gate.

`evictDeadOwner` no longer emits one Raft apply per sandbox when recreate is
disabled. It emits one batch orphan command by owner node ID, and the FSM:

- orphans every active placement for that owner;
- records the previous owner and orphan timestamp;
- removes the owner from the active-owner index;
- cancels that owner's pending reservations so failed creates do not hold
  capacity/name slots until TTL.

## P0. Recreate Code Exists But Product Policy Disables It

The branch replicates specs/secrets/ports as if failover recreation is central,
but `clusterRecreateOnFailoverEnabled` is false. The shipped product behavior
is "owner death -> 410 Gone".

That behavior is now explicit in the orphan flow: running sandboxes do not
recover automatically, but operators can inspect, reclaim a false-positive
local orphan, or force-delete the orphaned placement. Automatic recreate still
requires a separate product decision.

If automatic recreate becomes product scope, it needs a separate design:

- opt-in per sandbox;
- bounded recreate queues;
- image-pull backoff;
- mount credential validation;
- port replay policy;
- conflict parking;
- user-visible lifecycle state;
- no silent recreation of interactive sessions.

## P0 Fixed. Secret Material Is No Longer Replicated Through Raft

**Where:**

- `internal/cluster/cluster.go` `Placement.SecretRef`,
  `Placement.SecretVersion`, and legacy-only `Placement.SealedSecrets`;
- `internal/cluster/fsm.go` `applyCommandSecretUpdate`;
- `internal/service/cluster_secrets.go`
  `PutClusterSecretsForRecipient` / `OpenClusterSecretsForNode`;
- `internal/store/store.go` `cluster_secrets`.

New placement writes store only a secret ref + version in Raft. The encrypted
payload is stored behind the service secret-provider boundary, currently in
the local `cluster_secrets` table, with a recipient-bound envelope and a
per-secret data key wrapped by the service key. If a command accidentally
contains both `SecretRef` and `SealedSecrets`, the FSM keeps the ref and drops
the payload so Raft does not fan out secret material.

`Placement.SealedSecrets` remains as a rolling-upgrade fallback only: old
snapshots/log entries can still be opened, but create/reserve/promote/assert
paths no longer write it for new placements.

The external KMS integration point is now the provider boundary, not placement
state. A KMS-backed provider can replace the local table without rewriting the
Raft map; key rotation can rewrap provider records while placement refs remain
stable.

## P1. Reconcile And Lifecycle Are Full Local Scans

**Where:**

- `internal/service/service.go:1470-1540`
- `internal/service/service.go:1572-1680`
- `internal/service/netstats.go:191-210`

Many background loops scan the full local sandbox table:

- lifecycle sweep every minute;
- periodic reconcile;
- netstats target listing every poll interval;
- stale ownership check;
- zombie Caddy GC;
- mounts sweep.

This may be fine for 100 local sandboxes. It is not proven for thousands of
local sandboxes per node, especially with netstats polling every 10 seconds and
then doing PID lookups and `/proc` reads per running sandbox.

**Required redesign:**

- index and page local sweeps;
- make netstats event/incremental where possible;
- configure poll cadence by local sandbox count;
- avoid running expensive local loops on non-worker roles;
- expose per-loop duration and overrun counters.

## P1. Docker And Host Limits Are Not Modeled

100,000 concurrent sandboxes stress host limits outside the cluster FSM:

- Docker daemon API concurrency;
- container count per host;
- image layer storage;
- overlay filesystem inode count;
- network namespace count;
- veth count;
- IPAM subnet size;
- conntrack table;
- iptables/nftables rule count;
- file descriptors;
- pids;
- cgroup limits;
- logs and stdout/stderr backpressure.

The current scheduler does not know these constraints, and the release tests do
not prove them.

**Required fix:**

- define a per-node supported sandbox count;
- expose host pressure metrics for each dimension;
- feed pressure into placement;
- reject or drain nodes before hard host failures;
- run soak tests at the target local density.

## P1. Snapshots And Images Are Not Cluster-State-Aware Enough

Snapshot/image behavior is still largely local:

- built images can exist only on one node;
- snapshot rows are local SQLite;
- create-from-snapshot can place on a node that cannot pull or find the image;
- image GC is per-node and may remove images needed by future placement;
- Daytona snapshot flows are facade-local.

At large scale, image locality and registry availability dominate create
latency. A scheduler that ignores image cache will create avoidable pull storms.

**Required redesign:**

- make snapshots globally addressable;
- require images to live in a registry or distributed cache before cross-node
  placement;
- advertise image-cache hints;
- batch and dedupe pulls;
- make image GC cluster-aware or registry-backed.

## P1. Lost Quorum And Backup/Restore Are Undefined

At 100,000 sandboxes, the placement state is business-critical even if running
sandbox state is non-HA. The branch needs explicit answers for:

- Raft data backup;
- snapshot restore;
- replacing a failed server;
- lost quorum;
- split-brain prevention;
- rolling upgrade;
- downgrades;
- schema compatibility for gob snapshots and JSON commands;
- disaster recovery when some workers still have local sandboxes but placement
  state is lost.

Without this, operators cannot safely run the cluster as more than an
experiment.
