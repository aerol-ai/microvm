# 06 - Failure State And Recovery

## P0. False Dead-Owner Orphaning Can Be Permanent

**Where:**

- `internal/cluster/dead_owner.go:18-25`
- `internal/cluster/dead_owner.go:151-180`
- `internal/service/service.go:198-239`
- `internal/cluster/client.go:500-570`

Automatic failover recreate is disabled. The leader orphans placements when a
node is considered dead. If the liveness decision was a false positive, the
original owner can still have the local sandbox running.

The current branch does not have a clean automatic recovery path:

- `OwnerOf` returns `ErrOrphaned`;
- `reconcileStaleOwnership` ignores `ErrOrphaned` and leaves the local sandbox
  alone;
- `AssertOwnership` treats an existing placement with `OwnerNodeID == ""` as
  "not self" and does not reclaim it;
- clients see 410 even though the sandbox may still be running.

At 10,000 nodes, gossip false positives, partitions, pauses, and rolling
network events are not theoretical.

**Required fix:**

- represent owner liveness as durable lease state;
- require a recoverable transition from orphaned to reclaimed when the original
  owner proves it still has the sandbox;
- add an operator API to claim/delete/recover orphan placements;
- distinguish "owner dead and sandbox gone" from "owner unreachable" from
  "control plane orphaned but local row exists."

## P0. Dead-Owner Handling Is One Raft Write Per Sandbox

**Where:**

- `internal/cluster/dead_owner.go:151-180`

`evictDeadOwner` enumerates IDs owned by the dead node and applies one
`opReassign` per sandbox. A node owning 100 sandboxes is fine. A node owning
10,000 sandboxes or a rack event killing many nodes can generate a storm of
Raft writes and ingress route updates.

With recreate disabled, all those writes are just setting owner to empty.

**Required redesign:**

- add a batch orphan command by owner node ID;
- or store node liveness separately and make `OwnerOf` interpret dead owners
  without rewriting every placement immediately;
- pace route changes;
- expose orphan queue depth and age;
- define rack/zone failure behavior.

## P0. Recreate Code Exists But Product Policy Disables It

The PR replicates specs/secrets/ports as if failover recreation is central,
but `clusterRecreateOnFailoverEnabled` is false. The shipped product behavior
is "owner death -> 410 Gone".

That can be acceptable, but the architecture should then be simpler and more
honest:

- do not replicate large secret/spec payloads to every node for a disabled
  feature;
- document that running sandboxes do not recover;
- provide operator cleanup and recreate APIs;
- avoid implying that owner recovery has been solved.

If automatic recreate becomes product scope, it needs a separate design:

- opt-in per sandbox;
- bounded recreate queues;
- image-pull backoff;
- mount credential validation;
- port replay policy;
- conflict parking;
- user-visible lifecycle state;
- no silent recreation of interactive sessions.

## P0. Secrets Are Replicated To Every Raft Participant

**Where:**

- `internal/cluster/cluster.go` `Placement.SealedSecrets`
- `internal/service/cluster_secrets.go`
- `internal/config/config.go` shared credential key requirement

The branch seals credentials, but the sealed blobs are still replicated to
every Raft participant. Because every worker currently runs Raft, every worker
stores every sandbox's sealed secrets. Since the service process on each node
also has the shared credential encryption key, compromise of any node can
become compromise of the cluster's replicated credentials.

At 3 nodes this may be acceptable for an operator-owned cluster. At 10,000
nodes it is a major blast-radius problem.

**Required redesign:**

- do not replicate secret material to all workers;
- store secret refs in placement state;
- fetch/decrypt secrets only on the owner or approved recovery target;
- use KMS/envelope encryption with per-sandbox or per-tenant keys;
- rotate keys without rewriting the entire placement map;
- audit every secret access.

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

