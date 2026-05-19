# 06 - Release Gates

This is the pass/fail checklist that the first-stage plan is missing. If these
gates are not met, cluster mode can be marked experimental, but it should not be
marketed as robust or Kubernetes-comparable.

## Functional gates

### API routing

- `POST /v1/sandboxes` succeeds when the initial receiving node is not the
  owner.
- Forwarded creates do not reschedule randomly.
- File write, exec, sessions, lifecycle, resize, expose, unexpose, and destroy
  always hit the owner or return a clear owner-unavailable response.
- No request can mutate the wrong sandbox after a stale placement read.

### Data-plane routing

- HTTP sandbox URL reaches the owner through ingress after placement convergence.
- TLS/SNI exposure reaches the owner through ingress after placement convergence.
- Wrong-owner route misses are zero after convergence.
- During failover, ingress returns explicit "placement in flux" behavior rather
  than random 404/unmatched-SNI fallback.
- Raw TCP is stable through ingress with global L4 allocation metadata.
- Preferred host-port replay on failover either succeeds or enters an explicit,
  observable parked state.
- UDP is explicitly unsupported until implemented.

### Control-plane roles

- Production docs show 3 or 5 server nodes, not 200 voters.
- Workers do not vote.
- Server loss behavior is documented by quorum math.
- Worker loss does not affect control-plane quorum.
- Joining 50 workers does not trigger Raft snapshot transfer to every worker.

### Placement correctness

- CPU, memory, disk, runtime, GPU, and drain state are considered.
- Cluster-wide sandbox name uniqueness is enforced if names remain in the API.
- Create idempotency is cluster-wide.
- Placement and route watches have durable monotonic revisions.

## Scale gates

Run these before release:

| Test | Pass condition |
|---|---|
| 200 worker registration | all workers healthy; no Raft voter growth beyond configured servers. |
| 10K placement load | control-plane memory and snapshot size bounded; list latency stays within SLO. |
| 1000 create burst | bounded failures with retry-after; no orphan local sandboxes; no duplicate names. |
| 1% churn/min for 60 min | Raft/apply p99, ingress route lag, and Caddy/admin latency remain stable. |
| single worker death with 50 sandboxes | no control-plane outage; recreate/drain behavior follows documented semantics. |
| 3 worker death burst | failover work is paced; no leader stall beyond SLO. |
| ingress node death | L4 LB removes it; public URLs continue through remaining ingress nodes. |
| control-plane leader death | new leader elected; writes resume within SLO. |
| network partition | no split-brain placement commits; post-heal reconcile cleans orphan containers. |

## Suggested SLOs

These are starting points, not final product commitments:

- Raft/control-plane write p99 under steady churn: less than 100 ms.
- Raft/control-plane write p99 under burst with shedding: less than 500 ms for
  accepted writes.
- API owner-forward added latency p99: less than 50 ms inside one region.
- Placement-to-ingress convergence p95: less than 2 seconds.
- Cluster-wide list p95 at 10K sandboxes: less than 1 second.
- Worker heartbeat freshness p95: less than 10 seconds.
- Ingress wrong-owner route miss after convergence: zero.
- Recreate concurrency per worker: bounded and configurable.

## Observability gates

Add metrics before release:

- control-plane leader ID and leadership changes;
- Raft apply latency, backlog, log index, snapshot duration, snapshot size;
- server voter count and worker count;
- gossip/member heartbeat freshness;
- placement decisions by reason and selected node;
- reservation counts by node;
- create rollback failures;
- owner-forward latency and 421/502/503 counts;
- route watch revision lag per ingress;
- ingress route misses by reason;
- Caddy admin API latency and reload failures;
- recreate queue depth and recreate failures by image;
- image pull latency and cache hit/miss;
- disk/memory/CPU/GPU pressure by worker;
- TLS certificate expiry;
- credential-key mismatch/unseal failures.

## Runbook gates

Operators need documented procedures for:

- bootstrap 3-server + worker cluster;
- add worker;
- add/promote server;
- drain worker;
- remove dead worker;
- replace server;
- recover lost quorum;
- rotate cluster CA;
- rotate credential encryption key;
- recover failed ingress route convergence;
- inspect placement for one sandbox;
- force delete orphan placement;
- verify raw TCP exposure behavior.

## Documentation gates

Before release, remove contradictions:

- Create flow docs must match implementation.
- API owner-forwarding docs must state whether mTLS or public API URL is used.
- User-facing docs must say public sandbox URLs require owner-aware ingress.
- `DELETE /v1/cluster/members/<node-id>` must either exist or be removed.
- Snapshot endpoints must be marked unsupported in cluster mode.
- TCP and UDP behavior must be explicit.

## Release classification

Recommended labels:

- **Experimental cluster mode:** current PR after fixing create-forwarding and
  docs, before server/worker split and before data-plane hardening.
- **SDK-only cluster beta:** server/worker split done; API paths robust; data
  plane documented as not stable.
- **Network-capable cluster beta:** owner-aware HTTP/TLS ingress done; raw TCP
  globally routed; route convergence, metrics, and Caddy churn tests pass.
- **Production cluster:** release gates above pass at 200 x 50 with runbooks and
  metrics.
