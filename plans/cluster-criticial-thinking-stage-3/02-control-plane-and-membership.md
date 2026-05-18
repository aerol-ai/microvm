# 02 - Control Plane And Membership

## P0. All Nodes Still Run Raft

**Where:**

- `internal/cluster/client.go:131-138`
- `internal/cluster/voter_autojoin.go:101-105`
- `internal/cluster/voter_autojoin.go:161-169`

The PR reduces voter growth, but it does not remove workers from Raft. Every
cluster node still starts a Raft transport and local FSM. The leader then adds
worker/ingress nodes as non-voters.

That distinction matters:

- non-voters still receive the full log;
- non-voters still need snapshots when they fall behind;
- non-voters still appear in the Raft configuration;
- every worker stores all cluster placement/spec/secret state;
- every worker death can require Raft config mutation.

At 3 nodes this is fine. At 200 workers it is a concern. At 10,000 workers it
is a control-plane design failure.

**Required redesign:**

- only `server` nodes run Raft;
- workers do not have Raft data dirs or Raft transports;
- workers register capacity and health through a worker heartbeat/lease API;
- workers watch only assignments for their own node;
- ingress nodes watch only route-map deltas;
- Raft config contains 3 or 5 servers, not every data-plane node.

## P0. The FSM Is A Global Full-State Database

**Where:**

- `internal/cluster/fsm.go:84-112`
- `internal/cluster/fsm.go:561-621`
- `internal/cluster/fsm.go:687-693`

The FSM stores full placement records in memory and snapshots the entire map.
`snapshot()` deep-clones every placement, and `Snapshot()` then hands that full
map to gob encoding.

At 100,000 sandboxes this becomes expensive even if it still fits in memory:

- every snapshot copies every placement;
- every snapshot serializes every placement;
- every non-voter stores the same full snapshot;
- every follower recovery can transfer the full snapshot;
- every process GC sees a large object graph with maps, pointers, and slices.

The current comment claiming roughly 150 bytes per row is no longer credible.
A realistic placement row includes redacted spec, secret refs, tags, env, mount
metadata, lifecycle, GPU config, and exposed routes.

**Required redesign:**

- split placement ownership from sandbox spec;
- keep hot placement rows small;
- store large specs/secrets in a separate object keyed by sandbox ID and
  fetched only by the owner or recovery controller;
- use revisioned key-value prefixes or an explicit append-only event stream;
- shard by tenant, sandbox ID, or node group before 100,000 sandboxes;
- make snapshots incremental or bounded by shard.

## P0. Raft Writes Are Too Chatty

Current create and expose flows emit multiple Raft commands:

- cross-node create: `opReserve` before forward, then `opPlace` after local
  create;
- self create: local Docker create, then `opPlace`;
- TCP expose: candidate reservation through `opAddExposedPort`, local store
  reservation, Caddy upsert, another `opAddExposedPort`, and then the v1
  handler calls `replicateAddExposedPort` again;
- resize/lifecycle updates emit `opUpsertSpec`.

At 100,000 concurrent sandbox creates, the leader sees hundreds of thousands
of serial consensus writes before any exposed ports, lifecycle changes, starts,
stops, deletes, or route updates are included.

**Required redesign:**

- batch creates and placements;
- reserve resources in batches per target;
- collapse duplicate expose writes;
- move idempotent "same value" checks before Raft where possible;
- use compare-and-swap desired-state records rather than many single-field
  commands;
- apply backpressure before the leader queue grows.

## P0. No Strong Node Lease Model

**Where:**

- `internal/cluster/dead_owner.go:79-180`
- `internal/cluster/gossip.go`

Dead-owner handling is driven by memberlist liveness plus in-memory first-seen
timestamps. That is not enough at large scale.

Failure modes:

- a transient gossip false positive can orphan a live owner's placements;
- first-seen timestamps reset on leader restart or leadership change;
- the original owner returning after an orphan does not reclaim the placement;
- liveness is not tied to a durable lease revision;
- there is no heartbeat freshness SLO per node;
- there is no distinction between API-dead, Docker-dead, Caddy-dead,
  disk-pressure, or network-partitioned.

**Required redesign:**

- store node leases in the control plane with expiry revisions;
- make worker heartbeats include role, health, capacity, pressure, versions,
  and feature/capability flags;
- make dead-owner transitions explicit controller decisions over durable
  node state, not direct reactions to gossip;
- add "suspect", "unreachable", "draining", "dead", and "removed" states;
- require operator or policy thresholds before orphaning large owner sets.

## P1. Memberlist Metadata Is Fragile At Scale

**Where:**

- `internal/cluster/gossip.go:20-31`
- `internal/cluster/gossip.go:73-85`
- `internal/cluster/gossip.go:215-241`

`nodeMeta` is sent through memberlist's 512-byte metadata limit. If the JSON
blob gets too large, `NodeMeta` falls back to a minimal blob that omits capacity,
role, Raft address, and internal URL.

That creates dangerous downgrade behavior:

- placement may treat missing capacity as "unknown but allowed";
- worker role may disappear;
- internal mTLS URL may disappear, pushing owner forwarding to the public API
  fallback;
- raft address may disappear, preventing membership repair;
- future capability fields make the limit easier to hit.

**Required redesign:**

- put only stable node identity and a small status revision in gossip metadata;
- fetch detailed capacity/health via a versioned node-status API or control
  plane key;
- reject oversize metadata loudly instead of silently dropping load-bearing
  fields;
- add tests that force metadata over 512 bytes and verify safe behavior.

## P1. Hot Paths Scan All Members

**Where:**

- `internal/cluster/gossip.go:244-277`
- `internal/cluster/gossip.go:279-309`
- `internal/cluster/placement.go:57-89`
- `internal/cluster/voter_autojoin.go:253-261`

`gossip.members()` walks memberlist's full member slice and decodes metadata.
Several lookups then scan that slice again by node ID.

At 10,000 nodes, this is not catastrophic once per minute, but it is not
acceptable on request hot paths:

- placement scans all nodes per create;
- owner forwarding resolves URLs by scanning members;
- voter reconciliation scans all members every 5 seconds;
- route/list handlers use all-member snapshots.

**Required redesign:**

- maintain an indexed in-memory node cache keyed by node ID;
- separate scheduler candidate sets by role and health;
- maintain pre-filtered worker heaps or buckets for placement;
- expose O(1) owner endpoint lookup;
- avoid decoding JSON metadata on every API request.

## P1. Raft Snapshot Cadence Is Churn-Sensitive

**Where:**

- `internal/cluster/raft.go:57-61`

Snapshot threshold is 1024 log entries. With two Raft writes per create, expose
writes, delete writes, and ingress/port writes, a high-churn cluster can
snapshot constantly. Since snapshots encode the whole placement map, the cost
scales with total state, not just recent churn.

At 100,000 sandboxes, a snapshot every few seconds can become a self-inflicted
control-plane outage.

**Required redesign:**

- measure snapshot duration and size under 100,000 placements with realistic
  specs;
- tune snapshot threshold by bytes and time, not only log count;
- avoid storing large specs/secrets in the hot FSM;
- use external KV compaction semantics or explicit sharding.
