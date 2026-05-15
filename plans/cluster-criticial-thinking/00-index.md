# Cluster — Critical Thinking

A pressure-test of the `distributed-orchestrator` branch's cluster design,
written as if a tech lead with K8s/K3s/Nomad background were doing a design
review before this code touches anything close to production scale.

The target the rest of this folder is sized against:

> **200 runners × 50 sandboxes/node = ~10,000 concurrent sandboxes.**

Two ground rules from the operator (so you don't read these docs and think
they're missing the point):

1. **Sandboxes are NOT highly available.** If a sandbox dies, it's gone.
   Failover-recreate is a nice-to-have, not a hard requirement. The
   container's local state (filesystem, exec sessions, host ports) is
   allowed to vanish on owner death. What MUST survive is *the cluster*,
   not any one sandbox.
2. **Snapshot endpoints don't speak cluster yet.** Out of scope.

What's in scope:

- Is the **control plane** (raft + gossip + placement FSM) good enough to
  orchestrate 10K sandboxes across 200 nodes?
- Does the **"every worker is also a router for its peers"** design work,
  or does it fall over?
- What does a real **load balancer** look like for the data plane?

---

## Reading order

| # | File | What it covers |
|---|---|---|
| 01 | [`01-current-architecture.md`](./01-current-architecture.md) | Fact-finding: what is actually built today, grounded in code paths and file:line refs. The baseline every later critique is measured against. |
| 02 | [`02-assumptions-challenged.md`](./02-assumptions-challenged.md) | The unwritten assumptions embedded in the design, named explicitly and pressure-tested one at a time. |
| 03 | [`03-scale-200x50.md`](./03-scale-200x50.md) | The numbers. Raft fan-out, gossip bandwidth, FSM RAM footprint, host-port pool, Caddy config size, image-pull stampede on 100-sandbox failover. Where the wheels come off. |
| 04 | [`04-control-plane-critique.md`](./04-control-plane-critique.md) | Raft as 200-voter consensus, gossip-as-membership at 200 nodes, power-of-two-choices vs real bin-packing, missing scheduler features (affinity, taints, preemption, gang-scheduling). |
| 05 | [`05-data-plane-and-load-balancer.md`](./05-data-plane-and-load-balancer.md) | The worker-is-also-router model. Why it's a 1/N hit rate today, what a real LB tier looks like, the four viable shapes and the one I'd ship. |
| 06 | [`06-failure-modes.md`](./06-failure-modes.md) | What breaks on power loss, network partition, gossip flap, image-pull stampede, registry outage, raft leader churn, slow-disk degradation. Where the design is silent. |
| 07 | [`07-improvement-proposals.md`](./07-improvement-proposals.md) | The concrete fixes, sized and ordered. What ships in a week, what ships in a quarter, what gets deferred until the system actually demands it. |

---

## TL;DR for the impatient

The code in `internal/cluster/` is well-written and well-commented. It is
**not** sized for 200 nodes. The design has three loud cracks and a fourth
quiet one:

1. **Voter auto-promotion makes every node a raft voter.** At 200 voters,
   quorum is 101. Raft log fan-out is O(N) per commit. Every
   placement-create writes to 200 disks. This is the single biggest
   problem. The fix is the K3s pattern: a small fixed control-plane set
   (3–5 voters) and the rest of the fleet as workers that consume the
   placement map but don't vote. See [`04`](./04-control-plane-critique.md).

2. **The data plane is 1/N reliable.** Sandbox-URL traffic only succeeds
   when DNS happens to land the connection on the owner. There is no LB.
   The `setup/cluster.md` doc acknowledges this and calls it
   "Topology A — sandbox URL hit-rate is acceptable for SDK-only use." At
   200 nodes that's a 0.5% hit rate. There must be a real LB tier. See
   [`05`](./05-data-plane-and-load-balancer.md).

3. **The scheduler is one-shot, score-once, never-reschedule.** Power-of-
   two-choices is fine for placement, but: no rebinning when a node fills
   up, no preemption, no soft/hard affinity, no scheduler for the
   image-pull stampede on mass failover, no admission throttling. The
   first real production incident will look like "200 sandboxes try to
   pull the same image from Docker Hub at the same second."

4. **The placement FSM is the only "queue."** Every mutation, every port
   intent, every exposed-port add, every spec patch, every failover
   decision — single raft log, single leader. At 10K sandboxes with
   modest churn (1% destroy/create per minute = 100 raft commits/min just
   from create+destroy) the leader is a bottleneck only if you let the
   churn spike — and the design has no admission throttle in front of
   raft. See [`03`](./03-scale-200x50.md).

The system **can** do 3–10 nodes and ~500 sandboxes well. The leap to 200
nodes and 10K sandboxes is not a knob to turn — it's two missing components
(a real LB and a worker/server split) plus a handful of paper cuts.

---

## What this is not

- Not a refactor plan. The proposals in `07` are sequenced but each is
  itself a design doc, not a punch list.
- Not a critique of the code quality. The code in `internal/cluster/` is
  legible, commented, and tested. The critique is of the **shape** of the
  design at the target scale, not of the implementation.
- Not a "rewrite as K8s" pitch. K8s is the wrong answer here — this
  product's whole reason to exist is "self-hostable in one binary." The
  proposals stay inside that constraint.
