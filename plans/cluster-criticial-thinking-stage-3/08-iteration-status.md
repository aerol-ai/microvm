# Stage 3 Iteration Status

This branch now fixes the highest-risk small-cluster correctness gaps found in
the Stage 3 review. It does not make the architecture ready for 10,000 nodes or
100,000 concurrent sandboxes; those targets still need bounded control-plane and
data-plane redesigns.

## Fixed In This Iteration

- Placement is role-aware: pure `server` and `ingress` nodes are no longer
  eligible sandbox owners, and creates fail with 503 when no worker-capable
  target exists.
- Admission and reservation accounting now include CPU, memory, disk, runtime,
  and GPU dimensions for create/start/replay/reconcile paths.
- v1 create, Daytona create, and E2B create now share reservation-first cluster
  placement and remote forwarding before local runtime/build/idempotency work.
- Daytona and E2B sandbox operations now forward to the placement owner instead
  of assuming the receiving API node owns the local row.
- Daytona name-based routes use the replicated cluster name index to resolve
  owners before forwarding.
- Destroy paths clean up placement records after local sandbox deletion.
- E2B deterministic create IDs route repeated create attempts to the existing
  owner instead of creating duplicate sandboxes on different nodes.
- v1 cluster list is bounded so it fails closed instead of fanning out to an
  unsafe number of peers.
- Resize no longer clobbers unspecified replicated spec fields with zeroes.
- Ingress convergence metrics no longer advance the installed-version
  high-water mark after a failed reconcile.
- SSH gateway startup is worker-role gated.

## Still Pending

- Worker nodes still instantiate the full cluster/Raft client surface. Scaling
  to 10,000 workers needs a worker-client mode where only a small server quorum
  participates in Raft/FSM storage.
- The placement FSM is still a global map replicated to every participant. A
  100,000-sandbox design needs bounded shards, leases, or an external indexed
  control plane rather than full-map ownership state everywhere.
- Ingress reconciliation is still fundamentally full-route/full-map oriented.
  Large clusters need route sharding, delta updates, batching, and backpressure
  against the Caddy admin surface.
- List APIs are only bounded, not truly scalable. A 100,000-sandbox product
  needs paginated global indexes and scoped queries rather than peer fanout.
- Raw TCP exposure remains bounded by host-port space and per-ingress listener
  scale. This needs quotas, allocation strategy, and likely a different data
  plane for high-cardinality exposure.
- Snapshot/image locality is not solved. Remote create/build forwarding helps,
  but migration/failover still needs image distribution, cache warming, and
  storage placement policy.
- Secrets are still replicated in sealed form to cluster participants. Reducing
  blast radius needs separate secret distribution/KMS policy and narrower
  recipient sets.
- The branch still lacks real scale gates: create storms, churn, 10k member
  synthetic gossip, 100k placement snapshots, ingress route churn, failover,
  and facade idempotency should all have repeatable load tests.

## Verification

`go test ./...` passes after the iteration.
