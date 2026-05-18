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
- Cluster secret blobs now use a v2 recipient envelope: the recipient set is
  authenticated as AES-GCM AAD, new create paths seal to the selected owner
  node, and legacy raw blobs remain readable for rolling upgrades.
- Repeatable scale gates live behind `AEROLVM_SCALE_GATES=1` and can be run via
  `scripts/scale-gates.sh`; they cover 10k ingress-member shard assignment,
  100k placement pagination/sharding, 100k raw-TCP host-port collision checks,
  100k ingress delta churn, and failover/ingress storm behavior.

## Still Pending

- External KMS rewrap and image pre-distribution are still deployment-level
  integrations. The code now has recipient envelopes, pull dedupe, and clear
  local-only image failure semantics, but it does not ship a registry/cache
  service or a KMS plugin in-process.

## Verification

`go test ./...` and `scripts/scale-gates.sh` pass after the iteration.
