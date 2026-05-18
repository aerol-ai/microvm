# Cluster Critical Thinking - Stage 3

This stage reviews PR #58 against a much harsher scalability bar:

- node count from 3 to 10,000;
- concurrent sandbox count from 100 to 100,000;
- real user traffic through v1, Daytona, E2B, SSH, public HTTP/TLS, and raw TCP;
- failure, rollout, and operations behavior under high churn.

The conclusion is intentionally critical: the current branch is a useful
multi-node prototype, but it is not a scalable cluster architecture yet. Several
Stage 2 items marked as "resolved" are only resolved for small functional
correctness, not for large-scale bounded behavior.

Post-review implementation status is tracked in
[`08-iteration-status.md`](./08-iteration-status.md). That file separates the
capabilities fixed in this branch from the larger design work still required
for 10,000-node / 100,000-sandbox scale.

## Stage-3 Verdict

PR #58 should not be described as production-scalable for 10,000 nodes or
100,000 concurrent sandboxes.

It can plausibly be hardened into a small cluster beta if the product sharply
limits scope:

- 3 or 5 server nodes;
- tens to low hundreds of worker nodes;
- a small dedicated ingress tier;
- v1 API only, or all facades routed through the same cluster layer;
- no claim that raw TCP scales beyond the configured host-port pool;
- no automatic sandbox HA unless a separate desired-state policy lands.

The current design breaks down at larger targets because too many things are
global and unbounded:

- every cluster node starts Raft and can be added as a Raft non-voter;
- every server-role Raft participant stores the full placement map, full
  redacted create specs, secret refs, exposed port maps, and drained-node
  state;
- placement scans all gossip members and all pending reservations per create;
- cluster list fans out to every peer and returns every sandbox in one response;
- ingress nodes scan and sort the entire placement map and then issue one Caddy
  admin write per route;
- Daytona, E2B, SSH, snapshots, and several service-layer mutations do not share
  the v1 cluster routing/placement contract;
- local admission accounting still omits disk, GPU, and runtime reservations in
  the actual create/start/replay paths;
- the metrics that are supposed to prove ingress convergence can report
  convergence after a failed reconcile.

## Reading Order

| File | Purpose |
|---|---|
| [`01-scalability-verdict.md`](./01-scalability-verdict.md) | Hard verdict by scale tier and the most important PR reasoning errors. |
| [`02-control-plane-and-membership.md`](./02-control-plane-and-membership.md) | Raft, non-voters, FSM state size, snapshots, gossip, node liveness, and sharding concerns. |
| [`03-placement-admission-and-create.md`](./03-placement-admission-and-create.md) | Scheduler complexity, reservation TTL, resource accounting, create storms, and backpressure. |
| [`04-api-facades-and-idempotency.md`](./04-api-facades-and-idempotency.md) | v1 vs Daytona/E2B/SSH coverage, list fanout, idempotency, pagination, and mutation consistency. |
| [`05-data-plane-and-ingress.md`](./05-data-plane-and-ingress.md) | Caddy route scale, SNI/raw TCP limits, convergence metrics, route churn, and public LB assumptions. |
| [`06-failure-state-and-recovery.md`](./06-failure-state-and-recovery.md) | Node death, partitions, orphan semantics, stale ownership, local state cleanup, snapshots, and image/storage issues. |
| [`07-release-plan.md`](./07-release-plan.md) | Concrete blockers, required redesigns, scale gates, and a staged path from small beta to 100k scale. |
| [`08-iteration-status.md`](./08-iteration-status.md) | What this implementation pass fixed, what tests passed, and what capabilities remain pending. |

## Critical Distinction

The PR often proves that a behavior works at small N. That is not the same as
proving it scales.

For this review, a fix only counts as scalable when it is:

- bounded by a small control-plane size, not by all workers;
- incremental, not full-map scan/sort/copy on each hot-path operation;
- debounced or batched under churn;
- role-aware at the API and service layers, not only in docs;
- observable with metrics that cannot claim success on partial failure;
- validated with integration load, not just unit-level synthetic loops.
