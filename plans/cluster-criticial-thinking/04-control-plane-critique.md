# 04 — Control-Plane Critique

The control plane is the part of the system that decides *where each
sandbox goes* and *who owns it*. Three components today:

- **Raft FSM** — the placement map (id → owner + spec + secrets + ports).
- **Gossip / SWIM** — membership, liveness, capacity heartbeats.
- **Power-of-two-choices scheduler** — picks a node when a create lands.

This page goes through each and asks: at 200×50, is this enough?

---

## 1. Raft, as currently configured: not enough

### What the code does

`internal/cluster/raft.go` brings up a HashiCorp raft node on every
`sandboxd` daemon in cluster mode. `voter_autojoin.go` promotes every
gossip-joining node to a *voter*. There is no "non-voter" steady-state
role; the file name is `voter_autojoin`, not `member_autojoin`.

Every node ends up a voter.

### Why this is wrong at scale

Raft is a leader-based consensus protocol designed to give you
*strongly consistent decisions* across a *small fixed-size* set of
servers. The canonical configs are 3, 5, or 7 voters. The reason
nobody runs raft with 200 voters is in the math:

- **Quorum = ⌈(N+1)/2⌉.** At N=200, quorum=101. Every commit needs 101
  acks. The 100th-percentile follower latency sets your commit latency.
- **N² configuration churn.** Every AddVoter / RemoveServer is itself a
  raft log entry that must be committed. A flapping 200-voter cluster
  spends a lot of leader work on configuration changes.
- **Snapshot transfer on join.** New voters replay the log; once they
  catch up, they become a quorum participant. While catching up they
  count as "configured" but can't ack — joining one node temporarily
  raises quorum without raising the ack-able count.
- **Leader election with 200 voters is brutal.** During a leadership
  flip, every voter votes. Election timeouts and the candidate's
  RequestVote fan-out scale with N. The cluster is read-only during
  election; longer election = longer outage.

This is a solved problem with a well-known shape: **separate
control-plane voters from data-plane workers.** etcd does it. K3s does
it. Nomad does it. Consul does it.

### The correct shape

```
┌──────────────────────────────────────────────────────────┐
│  CONTROL PLANE (3 or 5 nodes, raft voters)               │
│                                                          │
│  ┌───────┐   ┌───────┐   ┌───────┐                       │
│  │svr-a  │◄─►│svr-b  │◄─►│svr-c  │  full raft FSM         │
│  │leader │   │follow │   │follow │  placement decisions    │
│  └───┬───┘   └───┬───┘   └───┬───┘                       │
└──────┼───────────┼───────────┼───────────────────────────┘
       │           │           │
       │ internal RPC (mTLS), each worker pulls placements
       │ relevant to itself + pushes capacity heartbeats
       ▼           ▼           ▼
┌──────────────────────────────────────────────────────────┐
│  DATA PLANE (3–200+ nodes, workers — no raft)            │
│                                                          │
│  ┌───┐ ┌───┐ ┌───┐  ...  ┌───┐                           │
│  │w1 │ │w2 │ │w3 │       │w200│  containers, host ports,  │
│  └───┘ └───┘ └───┘       └────┘  local SQLite, Caddy      │
└──────────────────────────────────────────────────────────┘
```

What changes:

- **Servers** run raft. They hold the FSM. They make placement
  decisions. They handle the API plane (or proxy to it).
- **Workers** are the runners. They do `docker run`, hold the local
  store, terminate Caddy for their local sandboxes. They talk to the
  control plane via two RPCs:
  - **Heartbeat** (worker → server, every few seconds): "I'm node-X,
    here's my capacity snapshot, here's my list of running sandbox
    IDs, here are my recent events."
  - **Watch** (worker pulls from server, long-poll or
    streaming-watch): "Tell me about placements assigned to me; tell
    me when one is reassigned away."
- Servers can themselves *not* run sandboxes — keeps the control plane
  isolated. Or they can, in small deployments (`--mode mixed` for
  laptop / 3-node setups).
- The leader-forward path (`:7002`) survives essentially unchanged —
  workers just forward to a server instead of to "whichever peer might
  be leader."

### What survives from the existing code

Most of it. `internal/cluster/fsm.go` is unchanged. The wire commands
(`opPlace`, `opReassign`, etc.) are unchanged.
`internal/cluster/forward.go` is reused for the worker → server hop.

What's new:

- A worker mode for `sandboxd` (`SB_NODE_ROLE=worker` or similar).
- A heartbeat RPC + watch RPC on the server's `:7002`.
- A worker-local "placements assigned to me" cache, populated by the
  watch RPC.
- A bootstrap config for the small server set (3 or 5 fixed nodes).

This is one moderate-sized feature, not a rewrite.

### What you give up

- The "any node is identical" property dies. You now have two roles
  with two install scripts (or one install with a mode flag).
- Single-node still works (mode=server-and-worker), but the 3-node
  cluster is now "3 servers" not "3 hybrid voters."
- Operators have to size the control plane. The doc has to explain
  3-server vs 5-server, in-AZ vs cross-AZ, etc.

This is a *real* added operator burden. But it's the same burden K3s,
Nomad, Consul, and every other production-scale orchestrator hands the
operator, because there isn't a better shape.

---

## 2. Gossip / SWIM: keep, narrow

### What the code does

`internal/cluster/gossip.go`. Memberlist SWIM. Carries `nodeMeta`
(NodeID, APIURL, RaftAddr, InternalURL, capacity.Snapshot). 5 s
refresh tick.

### Verdict

**Keep.** Gossip is the right tool for membership and liveness at any
scale memberlist supports (up to ~1000 nodes per the maintainers'
sizing guidance). At 200 nodes the cluster-wide gossip bandwidth is
sub-MB/s and convergence is sub-10 s. No issue.

### Things gossip should NOT carry

The `nodeMeta` blob is 512-byte capped. Today it carries:
- IDs / URLs / raft addr / internal URL (~200 B)
- capacity.Snapshot (~200 B)

That leaves ~100 B for everything else. Anything richer (image cache
state, queue depth, runtime health) should go in a **pull-based RPC**:

```
GET /v1/internal/node-state
→ {
    "node_id": "...",
    "capacity": {...},
    "running_sandboxes": [...],
    "recent_events": [...],
    "runtime_health": {...},
    "image_cache_keys": [...]    // hashed image refs the node has cached
  }
```

The control plane pulls this from each worker on a slow tick (every
5–30 s) for non-urgent scheduler inputs. **Don't grow gossip; grow the
RPC.**

### One real gap: "node is degraded but alive"

`Member.Alive` from memberlist is binary. Real ops needs three states:
healthy / degraded / dead. Today, a node with a disk near full or a
container runtime in a bad state still scores well in placement
because its `capacity.Snapshot` looks fine.

Add a `node_health` field to the pull RPC (above) and a "degraded
nodes are deprioritized but not excluded" rule in the scheduler.

---

## 3. The scheduler: one-shot, no rebinning, no batching

### What the code does

`internal/cluster/placement.go:21-59`. Power-of-two-choices over alive
gossip members. Filters by fit. Picks the higher `headroomScore`. One
decision per create. After that, the placement is fixed until the
sandbox is destroyed.

### Why this is too naive for 200×50

Three classes of problem:

#### 3a. Stale signal under load

Capacity is gossip-refreshed every 5 s. Many concurrent creates score
against the same snapshot. The "least full" node from snapshot N gets
piled on until snapshot N+1 arrives showing it full — then everyone
piles on the next "least full" node.

**Fix:** *Reserve* on the chosen node when the scheduler commits the
decision. Today the placement is committed *after* the local create
succeeds (`clusterCreateWrap` order). Inverting that to *reserve →
forward → create → confirm* gives the cluster a real-time view of
in-flight placements that gossip can't.

Concretely: when the leader writes `opPlace`, the placement row is in
the FSM before the local create completes. Every other scheduler now
sees that placement against the target's `Reserved` count via the
*replicated FSM*, not via stale gossip. The accounting is
strongly-consistent because it's behind raft.

#### 3b. No rebinning

After 24 hours of churn at 1% per minute, the cluster's bin-packing
drifts. Some nodes hold a long tail of long-lived sandboxes; some
nodes are nearly empty. Power-of-two won't fix it because new
placements just go to "least loaded" which is the empty ones — but
the *full* nodes never shed.

The operator brief says sandboxes don't have to be HA. That means
**rebalancing is allowed**: destroy a long-lived sandbox on a full
node and recreate it on an empty one. The user's client retries the
SDK call and reconnects.

A **rebalancer** that runs hourly:

1. Looks at per-node load skew.
2. Finds the most-skewed node.
3. Picks the most-recently-active sandbox (or oldest, by policy).
4. Marks it for migration (raft op = `opReassign`, but the *current*
   owner first does a graceful destroy).
5. New owner recreates from spec.

This is not Kubernetes-grade pod migration. It's the simple version
the product semantics allow.

#### 3c. No batching for bursts

`POST /v1/sandboxes` is one-at-a-time. A client creating 1000
sandboxes makes 1000 HTTP calls, each going through:

- `SelectPlacement` (gossip read)
- `ForwardHTTP` to chosen node (HTTP hop)
- Local `CreateSandbox` (docker pull, container create)
- `RecordPlacement` (raft commit)

1000 × ~50 ms best case = 50 s, but the raft commits serialize through
the leader and the docker work serializes on each owner. Real wall
time is much worse.

**Fix:** a batch create endpoint:

```
POST /v1/sandboxes:batchCreate
[ {spec_1}, {spec_2}, ..., {spec_N} ]

→ scheduler scores all N at once with awareness of in-batch fan-out
→ leader writes one batched raft entry with N opPlace records
→ owners run their slices in parallel
→ response: per-spec result with sandbox id or error
```

This is a small API addition with large throughput wins for burst
workloads (CI matrix, AI agent fan-out, batch evals).

---

## 4. Missing scheduler features

Things K8s/Nomad operators expect that don't exist here. Not all of
them must be built — the question is which omissions become real
problems at 200×50.

| Feature | Built? | Needed at 200×50? | Notes |
|---|---|---|---|
| Node selectors (sandbox wants GPU / SSD / region) | No | **Yes** | Heterogeneous fleets are inevitable past ~10 nodes. |
| Affinity (place near another sandbox / on the same host) | No | Maybe | Useful for chatty multi-sandbox apps; deferrable. |
| Anti-affinity (spread replicas) | No | No | Sandboxes aren't HA; nothing to spread. |
| Taints/tolerations (drain mode, "do not place new work") | No | **Yes** | Required for planned maintenance. |
| Priority/preemption | No | No | Sandboxes aren't HA; the kill-and-recreate model already handles priority by destroying old work. |
| Resource quotas per tenant | No | Maybe | Depends on multi-tenant model. Out of scope today. |
| Gang scheduling (all or none) | No | No | Not the workload shape. |

The two real misses are **node selectors** (labels) and **taints**.
Both are small additions on top of the existing capacity.Snapshot.

**Node labels** = `map[string]string` in `nodeMeta`. Scheduler filter:
sandbox spec carries `placement: { node_selector: { "gpu": "h100" } }`,
scheduler drops nodes without matching labels.

**Taints** = `[]string` in `nodeMeta`. A drained node sets
`taints: ["drain"]`. Scheduler filter drops tainted nodes unless the
sandbox spec carries the matching toleration.

Both can be done without touching raft semantics. Both fit in the
existing 512 B nodeMeta budget (most fleets have <10 labels per
node).

---

## 5. The reservation pattern is missing

The current order on `CreateSandbox`:

```
1. Scheduler picks target T from gossip view.
2. ForwardHTTP to T (if T != self).
3. T runs local CreateSandbox (docker work, store insert).
4. T succeeds → RecordPlacement → raft commit.
5. Response to client.
```

Two concurrent schedulers can pick the *same* T against the *same*
gossip snapshot. T sequentially admits and only the latter fails
admission. The losers waste the round-trip.

The fix is the standard "two-phase placement":

```
Phase 1 (any scheduler):
  - Read replicated reservations from FSM
  - Pick target T with available_capacity = budget - reservations
  - Write opReservation(sandbox-id, T, expiry=10s) to raft
  - (now FSM-visible to every other scheduler)
Phase 2 (any scheduler):
  - ForwardHTTP to T
  - T runs CreateSandbox locally
  - On success: opPlace(sandbox-id, T) — converts reservation to placement
  - On failure: opReleaseReservation(sandbox-id)
  - On expiry: T's own reaper clears stale reservations
```

This trades one raft commit for *atomicity* of placement decisions
across concurrent schedulers. At low write rates this is fine. At
high burst rates, batch the reservations.

---

## 6. The "single-leader is the world's serialization point" problem

Every placement, reassign, port intent, spec patch — all funnel through
one leader. That leader is also handling its own SDK traffic, its own
worker responsibilities (if mixed-mode), and Caddy admin reloads.

With the worker/server split, **servers don't run sandboxes**. The
leader's only job is raft applies and the API plane. Leader CPU is
freed; commit latency drops.

Even so, all writes serialize through one leader. Hot keys (one
sandbox getting many `opAddExposedPort`) serialize as expected.

The product doesn't have hot-key workloads, so this is fine.

---

## 7. Summary

| Area | Today | Target shape |
|---|---|---|
| Raft voters | All N nodes | 3 or 5 fixed control-plane nodes |
| Workers | Same as voters | Heartbeat + watch the control plane |
| FSM RAM | All N copies | 3–5 copies on servers; workers cache only their assignments |
| Scheduler | Pow2c on gossip | Pow2c + reservations in FSM + hourly rebalance |
| Gossip carries | Capacity + IDs | Capacity + IDs + node labels + taints |
| Non-urgent signals | (nowhere) | Pull-based `/v1/internal/node-state` RPC |
| Batch create | No | Batched raft entries; scheduler scores N at once |
| Drain mode | No | Tainted node + proactive reassign |
| Health beyond binary | No | Degraded state in pull RPC |

Concrete proposals for each item live in
[`07`](./07-improvement-proposals.md).
