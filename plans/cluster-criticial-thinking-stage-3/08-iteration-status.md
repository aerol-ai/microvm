# Stage 3 Iteration Status

This branch now fixes the highest-risk Stage 3 control-plane and data-plane
scalability gaps in addition to the small-cluster correctness issues from the
first pass. The design is no longer "every worker runs Raft and every ingress
installs every route"; remaining scale risk is now in operational rollout and
real production soak, not in the obvious unbounded hot paths.

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
- Worker/ingress-only nodes now run a lightweight cluster agent instead of
  Raft/FSM: they gossip capacity, receive owner API forwards, and delegate
  placement reads/writes to server-role nodes over authenticated control-plane
  RPC.
- Placement reads are shard-filterable, backed by a stable 16,384-shard index,
  and worker/ingress agents can query only their assigned shards.
- Create placement no longer scans the full placement map to account for
  in-flight reservations. The FSM maintains a per-reservation claim map,
  per-owner pending capacity aggregate, and expiry heap; gossip member metadata
  is decoded into an event-driven member index instead of being JSON-decoded on
  every placement read.
- Ingress route ownership is sharded across ingress-capable members. Reconcile
  builds desired route intents, applies only deltas, batches Caddy writes, and
  runs full Caddy snapshot GC as a sparse backstop rather than the normal path.
- Upstream routers now have a deterministic shard lookup at
  `/v1/cluster/ingress-route/{id}`. It returns the sandbox's stable shard and
  the ingress owner node/targets, using the same shard assignment as the
  reconciler instead of requiring every ingress node to hold every route.
- Cluster-wide sandbox enumeration now has a paginated control-plane index at
  `/v1/cluster/sandbox-index`. Legacy `/v1/sandboxes` keeps its original
  response contract and fails closed with a pointer to the paginated index when
  peer fanout would exceed the safe cap.
- Raw TCP exposure has an FSM host-port index, so cluster-wide host-port
  collision checks are O(1) at 100k placements instead of scanning the global
  placement map.
- Image pull storms are single-flighted per image/auth tuple, and local-only
  built/snapshot image refs fail fast on a new owner when the image is missing
  instead of stampeding a registry path that cannot contain them.
- Cluster placement now stores only secret refs and versions. The encrypted
  secret payload lives behind the service provider boundary in `cluster_secrets`
  with recipient-bound envelopes and per-secret data keys; legacy sealed blobs
  remain readable for rolling upgrades.
- Scale observability now emits expvar metrics for Raft apply/snapshot
  latency, worker lease/memberlist state, scheduler decisions, placement-cache
  refreshes, create queue pressure, host pressure, ingress convergence,
  Caddy admin latency histograms, owner-forward/stale-owner routing, facade
  idempotency, netstats polling, and secret decrypt/key-mismatch failures.
- Repeatable scale gates live behind `AEROLVM_SCALE_GATES=1` and can be run via
  `scripts/scale-gates.sh`; they cover 10k ingress-member shard assignment,
  100k placement pagination/sharding, 100k placement plus pending-reservation
  create accounting, 100k raw-TCP host-port collision checks, 100k ingress
  delta churn, and failover/ingress storm behavior.
- Dead-owner orphaning is now a single Raft command per dead owner in the
  no-recreate policy path. The FSM maintains an active-owner index, records
  explicit orphan metadata (`owner_state`, `orphaned_owner_node_id`,
  `orphaned_unix`), cancels the dead owner's pending reservations, and exposes
  a previous-owner-only `ClaimOrphan` path for false-positive recovery.
- Operator orphan recovery now has API surface: inspect via
  `/v1/cluster/placements/{id}`, reclaim a false-positive local orphan via
  `POST /v1/cluster/orphans/{id}/reclaim-local`, and force-delete an orphaned
  placement via `DELETE /v1/cluster/orphans/{id}`.
- AssertOwnership on both server and worker-agent clients can reclaim only
  orphaned placements that were orphaned from the same node. Active foreign
  owners and other nodes' orphans remain non-claimable, preserving the stale
  local-row safety property.

## Still Pending

- External KMS provider wiring, provider-level key rewrap tests, secret-access
  audit events, and image pre-distribution are still deployment-level
  integrations. The code now has a secret-provider boundary, pull dedupe, and
  clear local-only image failure semantics, but it does not ship a registry/cache
  service or a KMS plugin in-process.
- Automatic sandbox recreate remains product-gated off. The code now supports
  bounded orphan cleanup and previous-owner reclaim, but it still does not
  promise HA recreation of running sandboxes after a real owner death.

## Verification

`go test ./...` and `scripts/scale-gates.sh` pass after the iteration.
