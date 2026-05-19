# 07 - Release Plan

This is the minimum plan I would require before calling the PR scalable beyond
a small beta.

## P0 - Make The Role Split Real

Required changes:

- only server nodes start Raft;
- workers and ingress nodes do not have Raft transports or Raft data dirs;
- workers register through leases/heartbeats;
- workers watch assignments for self only;
- ingress watches route deltas only;
- scheduler excludes non-worker nodes;
- non-worker API handlers reject local sandbox operations or proxy to the right
  role;
- pure server/ingress nodes do not require Docker.

Release gate:

- start 5 servers, 1,000 workers, 10 ingress nodes;
- verify Raft config has 5 servers and zero worker/non-voter entries;
- verify worker restart does not trigger Raft membership changes.

## P0 - Move Cluster Create Below The Facades

Required changes:

- `Service.CreateSandbox` or a new orchestrator-level create API owns cluster
  placement;
- v1, Daytona, and E2B all call the same cluster create path;
- idempotency is control-plane scoped;
- follow-up facade calls are owner-forwarded;
- facade list/get/delete are cluster-aware;
- name lookup is cluster-wide.

Release gate:

- run v1, Daytona, and E2B SDK tests through a load balancer that randomly
  selects any node for every request;
- retries with the same E2B idempotency key must return the same sandbox from
  any node;
- facade-created sandboxes must appear in placement state immediately.

## P0 - Fix Admission Accounting

Required changes:

- all create/start/replay/event paths reserve CPU, memory, disk, GPU, vendor,
  and runtime;
- capacity snapshots prove those counters move after real local creates;
- placement and target admission use the same normalized resource request;
- resize updates full resource accounting correctly.

Release gate:

- disk-saturating workloads are rejected before Docker ENOSPC;
- GPU requests cannot overbook a single GPU;
- runtime-specific requests never land on unsupported nodes;
- resize cannot corrupt replicated spec defaults.

## P0 - Replace Full-Map Hot Paths

Required changes:

- scheduler cache indexed by node;
- pending reservations indexed by owner;
- host-port index in FSM;
- route watch deltas by revision;
- paginated list/index API;
- no full placement snapshot on every create/list/route update.

Release gate:

- 100,000 placements;
- 10,000 workers in membership cache;
- create placement p99 stays within SLO without scanning all placements;
- route update for one sandbox does not sort/hash 100,000 entries on every
  ingress node.

## P0 - Make Ingress A Bounded Tier

Required changes:

- production docs default to dedicated ingress nodes;
- workers do not install global routes;
- ingress applies route deltas in batches;
- Caddy route scale is proven or replaced;
- convergence metrics distinguish attempted, installed, and failed revisions;
- raw TCP scale limits are explicitly documented.

Release gate:

- 100,000 HTTP/TLS sandbox routes across the intended ingress tier;
- 1,000 route updates per minute for 60 minutes;
- dead owner with 1,000 routes does not stall ingress;
- route convergence p95/p99 measured from placement commit to successful public
  request;
- failed Caddy admin does not advance installed-version metrics.

## P0 - Define Orphan And Recovery Semantics - Fixed For No-Recreate Policy

Implemented:

- explicit owner states and orphan metadata on placement records;
- single-command batch orphan by owner node ID;
- previous-owner-only orphan reclaim command;
- operator APIs for orphan inspect, local reclaim, and force-delete;
- false-positive dead-owner recovery path;
- 100k-placement scale gate for batch orphan behavior.

Still product-gated:

- optional recreate policy with queues and backoff if product wants automatic
  HA recreation instead of the current 410 Gone policy.

Release gate:

- partition owner from servers, heal it, and verify previous-owner reclaim;
- false-positive orphan can be recovered without DB surgery through
  `/v1/cluster/orphans/{id}/reclaim-local`;
- dead owner with 1,000 sandboxes emits one orphan command instead of one Raft
  write per sandbox;
- clients receive stable 410 for unreclaimed orphans.

## P1 - Reduce Secret Blast Radius

Implemented:

- store only secret refs in placement;
- decrypt only on owner or authorized recovery target;
- per-sandbox or per-tenant envelope keys;
- no worker-wide access to every user's sealed credential blob.

Remaining release hardening:

- external KMS provider wiring beyond the local provider;
- key rotation runbook and provider-level rewrap tests;
- secret-access audit events on every provider read.

Release gate:

- compromised worker cannot decrypt unrelated sandbox credentials;
- rotating a key does not require rewriting all placement state at once.

## P1 - Add Real Scale Tests

The current unit tests are not enough. Add these integration tests:

| Test | Minimum pass condition |
|---|---|
| 5 servers + 1,000 workers | Workers do not join Raft; heartbeat cache stable. |
| 100,000 placement records | Snapshot size, heap, GC, and apply p99 within SLO. |
| 10,000-node membership churn | No goroutine storm; no Raft config storm. |
| 100,000 create burst simulation | Backpressure works; no unbounded reservations; no leader collapse. |
| 100,000 Caddy routes or replacement ingress | Public route p99 and admin p99 proven. |
| 10,000 concurrent list callers | Pagination/index prevents worker fanout meltdown. |
| E2B/Daytona through random LB | All calls route to owner or replay idempotently. |
| Node false-positive death | Recover/reclaim path works. |
| Registry/image pull storm | Pulls dedupe and queue; registry throttling does not wedge create. |
| Local-only snapshot/image placement | Router never reserves or forwards a local-only image to a different node; missing local image fails before registry pull storm. |
| Netstats at local max density | Poll duration stays below interval; no DB writer starvation. |

## P1 - Observability Required Before Scale

Implemented in-process expvar metrics for the scale gates:

- Raft apply latency, in-flight apply queue depth, leader-forward latency,
  snapshot duration, snapshot bytes, restore duration, and snapshot placement
  count.
- Worker lease/memberlist state: gossip members total/alive, worker-capable
  leases total/alive, lost lease count, max lease age, and last refresh time.
- Scheduler decisions by result and candidate rejection reason; placement cache
  refresh latency/errors, cache size, and shard-cache entry count.
- Create pressure: create queue depth, latency buckets, error causes,
  admission rejects, timeout causes, reservation state transitions, and expired
  reservation cancellations.
- Per-node host pressure: local sandbox count, reserved CPU/memory/disk/GPU,
  effective budgets, live free memory, can-admit gauge, and rejection reasons.
- Ingress convergence: desired/applied/failed revisions, protocol route counts,
  per-shard route counts, route lag, route misses by reason, Caddy operation
  pending/in-flight gauges, batch counts, and batch size.
- Caddy admin latency histogram in addition to call count, error count, and
  last-call latency.
- Owner forwarding: latency buckets, target-miss reasons, and stale-owner 421
  count.
- Facade idempotency: claim/acquire/replay/conflict/complete/delete counts.
- Netstats: poll duration buckets, targets, samples, total samples, and dropped
  samples by reason.
- Secret access: decrypt latency/counts, decrypt failure reasons, recipient
  denies, and key-version mismatches.

## P2 - Product Limits To Document Honestly

Before merging as anything beyond experimental, docs should state:

- recommended maximum server count;
- recommended maximum worker count for this release;
- recommended maximum sandboxes per worker;
- whether Daytona/E2B are cluster-supported;
- whether SSH is owner-aware or owner-local;
- snapshot/image support mode: `external_registry` and `aocr` can run on any
  worker that can pull them; `local_only` is pinned to the receiving worker and
  has no cross-node failover promise;
- raw TCP port-pool limits;
- UDP unsupported;
- failover means 410 by default, not running sandbox HA;
- recreate is disabled unless an explicit future policy enables it.

## Recommended Release Classification

For the current PR state:

```text
Experimental v1-only cluster prototype.
Not production scalable.
Not Daytona/E2B cluster-ready.
Not 10,000-node-ready.
Not 100,000-sandbox-ready.
```

After P0 role split, facade routing, admission, ingress metrics, and orphan
semantics are fixed and tested:

```text
Small cluster beta.
Target: 3-5 servers, <= 100 workers, <= 10,000 total sandboxes.
```

After sharded/incremental control plane, bounded ingress tier, real list/index
APIs, and 100,000-scale integration tests:

```text
Large cluster beta.
Target: 1,000+ workers and 100,000 total sandboxes.
```

10,000 nodes should be treated as a separate architecture milestone, not a
linear extension of this PR.
