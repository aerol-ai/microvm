# 01 — Current Architecture (as actually built)

Before any critique, fact-finding. This page describes what the code on
`distributed-orchestrator` actually does today, with file:line references.
Every later document refers back here.

If a sentence here disagrees with the code, the code wins — flag it and
update.

---

## The pieces, one paragraph each

**`sandboxd`.** One process per host. Owns Docker, SQLite (`state.db`),
Caddy admin API, the SSH gateway, and — in cluster mode — both a raft
node and a gossip node. Single binary; no microservice split.

**Raft (HashiCorp).** `internal/cluster/raft.go`. Listens on `:7000` for
log replication, optionally wrapped in mTLS via a custom `StreamLayer`
(`internal/cluster/raft_tls.go`). BoltDB log + stable stores, file
snapshot store. Snapshot interval 30s / threshold 1024 entries
(`raft.go:62-63`).

**Gossip (HashiCorp memberlist).** `internal/cluster/gossip.go`. SWIM
protocol on `:7001` (TCP+UDP). Carries one piece of useful state — each
node's `nodeMeta` blob (NodeID, APIURL, RaftAddr, InternalURL,
`capacity.Snapshot`). Refresh loop re-publishes the blob every 5 s
(`gossip.go:188`). AES-encrypted with `SB_GOSSIP_SECRET_KEY`; refuses
plaintext if a key is configured.

**Internal RPC.** `:7002`. mTLS HTTPS endpoint that receives leader-
forwarded raft applies (`internal/cluster/internal_server.go`). Backstop
for any node that isn't the raft leader: it forwards the encoded `command`
to the leader's `:7002` and the leader runs `raft.Apply`.

**Placement FSM.** `internal/cluster/fsm.go`. An in-memory
`map[string]Placement` plus a version counter. Six op codes: `opPlace`,
`opDelete`, `opReassign`, `opUpsertSpec`, `opAddExposedPort`,
`opRemoveExposedPort` (`fsm.go:19-25`). One row per sandbox.

**Placement.** `internal/cluster/cluster.go:71-81`. The row carries:

- `SandboxID`, `OwnerNodeID`, `OwnerAPIURL`
- `Version`, `CreatedUnix`, `UpdatedUnix`
- `Spec` (the redacted `CreateSandboxRequest` — no plaintext secrets)
- `SealedSecrets` (encrypted bag — registry/mount creds)
- `ExposedPorts` (intent-only `map[port]protocol`)

The Spec + SealedSecrets are what makes failover-recreate work — they're
why a fresh node can re-materialize a sandbox the dead owner used to run.

**Capacity admitter.** `pkg/capacity/capacity.go`. Pure resource math:
CPU and memory reservation ratios (with overcommit factor) plus a live
`/proc/meminfo` `MemAvailable` floor. Tracked in-process; replayed at
boot from SQLite.

**Placement scheduler.** `internal/cluster/placement.go`. Power-of-two-
choices over `gossip.members()`. Filters dead nodes, nodes with no
advertised `APIURL`, nodes that don't fit `capacity.Request`
(`placement.go:64-79`). Picks two random survivors, takes the one with
more `headroomScore = (cpuHeadroom + memHeadroom) / 2`. Self always
loses ties.

**Forwarder.** `internal/cluster/forward.go`. Reverse-proxy with a
per-peer `*httputil.ReverseProxy` cache. Stamps `X-Cluster-Forwarded: 1`
on outbound; returns 421 if it sees that header on inbound *and* would
forward again. No retries, no backoff, no circuit breaker.

**API plane shim.** `pkg/api/v1/cluster_handler.go`.
`clusterForwardWrap` is the path-`{id}` middleware that calls `OwnerOf`
and either runs locally or `ForwardHTTP`s. `clusterCreateWrap` runs
placement before delegating to local create, then commits the placement
to raft after the local create succeeds. `clusterListWrap` fan-outs to
peers, dedupes by ID, swallows per-peer errors.

**Owner watcher.** `internal/cluster/owner_watcher.go`. Polls
`fsm.snapshot()` every 5 s. For every placement that points at self and
has a `Spec` but no corresponding local container, calls
`SandboxRecreator.RecreateSandbox`. Counts consecutive failures per
sandbox; after 5 the placement is reassigned to a peer
(`owner_watcher.go:26`, `tryReassignStuckPlacement`).

**Dead-owner reconciler.** `internal/cluster/dead_owner.go`. Leader-only
periodic loop, 5 s tick. Tracks "first observed dead at" per node
(`deadOwnerTracker`). After `SB_DEAD_OWNER_GRACE` (default 30 s) it
runs `evictDeadOwner`: reassigns every placement owned by the dead node
to a live peer chosen by `SelectPlacement`, then `RemoveServer`s the
dead node from raft config. Orphans (owner=`""`) when no spec is
available — failed reassign is a no-op the next tick will retry.

**Voter auto-join.** `internal/cluster/voter_autojoin.go`. The leader,
on every memberlist `NotifyJoin`, calls `AddVoter`. Plus a 5 s
reconcile loop that re-checks gossip and adds anyone it missed. *Every
node that joins becomes a voter.*

**Sealed secrets.** `internal/service/cluster_secrets.go`. The service
layer holds the `pkg/secrets` AES-GCM cipher. Before raft replication
the create handler calls `SealClusterSecrets` and `RedactClusterSecrets`
so the wire payload has no plaintext. Recreate calls `UnsealClusterSecrets`
to re-merge before docker-run.

---

## How a request flows today (cluster mode)

### Create

```
SDK ──► any node A
A: c.SelectPlacement(req) → power-of-two over gossip → target T
   if T == A: createSandbox locally; SealClusterSecrets; RecordPlacement → raft
   if T ≠ A:  ForwardHTTP(T.APIURL, w, r); T runs the same wrap, sees IsSelf=true,
              runs createSandbox locally, RecordPlacement → raft (via leader-forward)
A: respond 201 with sandbox handle
```

Two raft commits per create at most: `opPlace` plus zero or more
`opAddExposedPort` if the create body asks for any exposures (rare).

### Hot-path (exec / file / port-forward)

```
SDK ──► any node A
A: clusterForwardWrap reads {id} from path
A: c.OwnerOf(id) → in-memory FSM read → owner T
   if T == A: run locally
   if T ≠ A:  ForwardHTTP(T.APIURL, w, r); T runs locally
A: stream response back
```

Zero raft commits. Pure read-path on the FSM map plus one HTTP hop.

### List

```
SDK ──► any node A
A: clusterListWrap fans out GET /v1/sandboxes to every other alive peer,
   each carrying X-Cluster-Forwarded: 1 so no recursion.
   5 s per-peer timeout; failed peers logged + skipped.
A: merge local + per-peer results, dedupe by SandboxID.
```

At 200 nodes, every list call fans out 199 HTTP requests. Five-second
deadline; the slowest peer caps response time. No batching, no
pagination, no incremental list, no streaming.

### Failover-recreate

```
Node B dies (power loss / kernel panic).
Surviving nodes: gossip SWIM marks B suspect → dead.
Leader L: dead-owner reconciler tick (every 5 s).
  After SB_DEAD_OWNER_GRACE (default 30 s):
    For each placement owned by B:
      target = pickRecreationTarget(spec)   ← SelectPlacement
      raft.Apply(opReassign, sandbox-id, target)   ← single leader log entry per sandbox
    raft.RemoveServer(B)
Every node's FSM now points each formerly-B sandbox at target T_i.
Each T_i's owner watcher (5 s poll) sees FSM ≠ local, calls RecreateSandbox.
RecreateSandbox: UnsealClusterSecrets, docker pull, docker run, re-expose ports.
```

The reassign step writes `len(placements_owned_by_B)` raft entries in one
leader tick. If B owned 50 sandboxes, that's 50 sequential applies.

### Public sandbox URL

```
Browser opens https://<id>.sandbox.example.com
DNS: round-robin / NLB picks one of N nodes — call it A.
A's Caddy: looks up host = <id>.sandbox.example.com.
  If owner is A: route exists, proxy to local container ✓
  If owner is T ≠ A: NO ROUTE on A's Caddy → 404 / unmatched-SNI fallback.
```

The data plane has no cross-node routing. Documented at
`setup/cluster.md:431-477` and re-acknowledged in
`plans/fucked-up-design-in-cluster.md`.

---

## The pieces of cluster-wide state

| Thing | Where it lives | Replicated? | Size at 10K sandboxes |
|---|---|---|---|
| Placement map (id → owner) | Raft FSM, in-memory map | Yes (every voter) | ~150 B/row × 10K = ~1.5 MB before spec |
| Spec | Raft FSM, in Placement.Spec | Yes | ~1–4 KB/row × 10K = ~20 MB |
| SealedSecrets | Raft FSM, in Placement.SealedSecrets | Yes | ~1 KB/row when present × 10K = ~10 MB |
| ExposedPorts intent | Raft FSM, in Placement.ExposedPorts | Yes | ~50 B/exposure × 10K avg 2 = ~1 MB |
| Local sandbox runtime state (container, ports, sessions, mounts) | Local SQLite | No | Lives only on owner |
| Caddy routes for local sandboxes | Caddy in-process | No | Owner-local |
| Capacity advertisement | Gossip nodeMeta | Eventually consistent (5 s) | ~200 B/node × 200 = ~40 KB |
| Membership view | Gossip ml.Members() | Eventually consistent | ~200 entries |

Roughly **~30 MB of state replicated to every voter** at the 10K-sandbox
target. That's not the bottleneck — even at 200 voters that's 30 MB ×
200 = 6 GB of duplicated RAM, which is significant but not fatal. The
bottleneck is what happens to a raft *log* and *fan-out* under that
load. See [`03`](./03-scale-200x50.md).

---

## What the cluster does NOT do

These are the explicit gaps. They're not bugs; they're deliberate
non-goals or deferred work. Worth naming so the critique stays honest:

1. **No data-plane cross-node routing for sandbox URLs.** A public
   sandbox URL only resolves on the owner. Acknowledged in code
   comments and `setup/cluster.md`.

2. **No external load balancer.** The recommended topology is "your
   cloud's L4 NLB does TLS passthrough across all nodes" — which is
   round-robin, not SNI-aware.

3. **No leader-only writes from the SDK side.** Every node can take any
   request; mutating calls leader-forward via `:7002`. Reads are local
   FSM. This is good — but it means every node holds the full FSM in
   RAM. That includes pure workers, in a world where the design treats
   every node as a voter.

4. **No worker/server split.** Every node runs raft. Every node is a
   voter (auto-promoted). Every node holds the full placement map.

5. **No scheduler features beyond raw fit.** No taints/tolerations, no
   node selectors / labels, no anti-affinity, no preemption, no priority
   class, no quota, no batch placement, no rebalancing.

6. **No gang scheduling, no admission throttling.** A burst of 1000
   creates against any node will fan out 1000 raft commits in series
   through the leader. No queueing, no shedding.

7. **No image-pull coordination.** On mass failover of 100 sandboxes
   using the same base image to a new node, the new owner does 100
   `docker pull`s — the underlying Docker engine dedupes some of this,
   but the raft cost and the network cost are paid up front.

8. **No snapshot support in cluster mode.** Explicitly out of scope per
   the operator brief.

9. **No notion of "control plane" vs "data plane" nodes.** Everything
   is one role.

10. **No UDP.** `ValidExposedPortProtocol` only takes http/tcp/tls
    (`pkg/models/types.go:362`).

This is the surface we're going to push on for the next 6 documents.
