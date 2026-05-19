# 03 - Limitations

This file enumerates where the PR falls short. Each item is tagged:

- **(SCOPE)** — out of scope per the Stage 4 product bar but worth flagging.
- **(BAR)** — within the Stage 4 bar but still limited; should be a follow-up.
- **(STRETCH)** — only matters for the harsher Stage 3 / 10k-node ambition.

## L1. No multi-process 500-node integration test (BAR)

The scale gates in `internal/cluster/scale_gates_test.go` and
`internal/service/scale_gates_test.go` exercise the **FSM** at 100k rows
and the **ingress reconciler** at 10k members, but they do so inside one Go
test process. They do not:

- launch 500 distinct `sandboxd` binaries on real (or even simulated)
  network namespaces;
- exercise memberlist gossip over a 500-node fanout;
- exercise the mTLS internal channel under load between agents and
  servers;
- exercise actual Caddy admin under 100k routes.

The release-blocker checklist in `plans/cluster-criticial-thinking-stage-3/
07-release-plan.md` calls for a "5 servers + 1,000 workers" integration
test as a hard gate; that test still does not exist.

**Impact.** This is the single biggest "we don't know" risk for the 500/100k
target. Single-process unit gates are necessary but not sufficient evidence.

## L2. Daytona / E2B mutating handlers do not write through to the FSM spec (BAR)

The v1 layer wires `replicateSpecPatch` for `ResizeSandbox`,
`UpdateLifecycle`, and exposed-port mutations
(`pkg/api/v1/handlers.go:138-198`). The Daytona and E2B handlers **do
not**:

- `pkg/api/daytona/handlers.go:481-509` — `resizeSandbox` calls
  `Service.ResizeSandbox` directly. No `UpsertSpec` follows.
- `pkg/api/daytona/handlers.go:601-646` — `updateIdleLifecycle` calls
  `Service.UpdateLifecycle` directly. No `UpsertSpec` follows.
- `pkg/api/daytona/handlers.go:572-599` — `setAutoArchiveInterval`
  only persists facade-local compat state.
- `pkg/api/e2b/handlers.go` — `updateTimeout`, `pauseSandbox` use
  `Service.UpdateLifecycle`. No `UpsertSpec` follows.

Note that `Service.ExposePort` does call `recordClusterExposedPort`
internally, so facade preview-URL paths *do* replicate exposed ports —
that part is fine. The gap is **spec mutations only**.

**Impact.** The cluster-replicated spec drifts after every Daytona/E2B
resize or lifecycle change. The drift is invisible until the owner dies
and `clusterRecreateOnFailoverEnabled` is flipped on — which is
intentionally never under current policy. So today this is a latent bug
guarded by the no-recreate policy. **The day the recreate gate flips,
sandboxes resurrected by Daytona/E2B will revert to their create-time
spec.**

## L3. No global create-burst backpressure (BAR)

The `clustercreate.Prepare` path commits one `opReserve` per create.
A 100k-concurrent burst on a 500-node fleet drives 100k Raft log entries
through the leader before any local create starts. There is no:

- per-leader admission queue with `Retry-After`;
- per-target create concurrency cap that returns 429 when full;
- registry-pull token bucket per node;
- image-pull dedupe across simultaneous creates of the same image (single-
  flight exists *within* a node — see `pkg/docker/client.go` — but not
  across the cluster).

`internal/scaleobs/metrics.go` emits create-queue-depth and reservation-
state-transition counters, so the *visibility* is there, but the
*enforcement* is not.

**Impact.** A pathological 100k-create burst can stall the Raft leader's
apply loop. Stage 3 P0 ("Create has no cluster backpressure") is
acknowledged but not fixed.

## L4. Raft snapshot still encodes the full FSM (STRETCH at 500, BAR at 5k)

`internal/cluster/fsm.go:1067-1117` — `snapshot()` deep-clones the entire
placement map and hands it to gob. `internal/cluster/raft.go:57-61` keeps
the 1024-log-entry snapshot threshold.

At 100k placements, each carrying a redacted spec, secret ref, exposed-
port map, etc., the snapshot is in the **tens of megabytes** range. The
PR ships:

- `pruneExpiredPendingReservationsLocked` on the leader so the snapshot
  doesn't carry dead reservations;
- a placement-page API so operators read incrementally;

but it does NOT ship:

- incremental snapshots;
- a separate "hot vs. cold" placement split (small core row + larger
  spec/secret refs stored elsewhere);
- snapshot-size or snapshot-duration metrics that gate a refusal to
  snapshot when too big.

**Impact.** At the Stage 4 ceiling (100k sandboxes), this is workable
but tight: a follower joining from a stale snapshot pays a multi-second
restore. At 1M sandboxes it would not work.

## L5. Gossip metadata still rides memberlist's 512-byte limit (BAR)

`internal/cluster/gossip.go:17-103` — `nodeMeta` is JSON-encoded into the
512-byte memberlist NodeMeta slot. The fallback path drops `Capacity`,
`Role`, `RaftAddr`, and `InternalURL`, leaving only `NodeID`/`APIURL`/
`DataPlaneHost`. This silently demotes a node to "no role, no capacity"
in the eyes of all peers when the JSON exceeds 512 bytes (e.g. many
supported runtimes, GPU vendor combinations, etc.).

There is no test that forces the metadata over 512 bytes and asserts safe
behavior, despite Stage 3 P1 calling for one.

**Impact.** At 500 nodes this rarely fires; at 10k it becomes a regular
event during rolling capacity-snapshot growth.

## L6. Reservation TTL is static (120s) (BAR)

`pkg/api/clustercreate/clustercreate.go:22` — `ReservationTTL = 120 *
time.Second`. The leader GC sweep at
`internal/cluster/dead_owner.go:285-313` cancels expired reservations on
a 5s tick.

A slow image pull on a cold GPU node (multi-gigabyte CUDA image, registry
throttling, mount adapter delays) can exceed 120s. The target's
`CreateSandboxWithID` still completes and `RecordPlacement` still
promotes the row (the FSM treats a re-place as a no-op even if the
reservation was cancelled), but the **capacity accounting** in the gap
counts that node as having free room when it doesn't.

Stage 3 P0 ("Reservation TTL can expire during a slow create") flagged
this. The PR mitigates it by carrying the redacted spec through the
reservation so a successful promote still has the right metadata, but it
does not extend the TTL during create.

## L7. SSH gateway is owner-local (BAR)

`cmd/sandboxd/main.go:234-249` gates the SSH gateway to `cfg.IsWorker()`.
`pkg/sshgateway/gateway.go` calls `Service.GetSandbox` against the local
store. There is no owner-forwarding path: if a TCP load balancer in front
of the SSH gateway sends a connection to a non-owner worker, auth fails.

The pattern that works for HTTP/TLS (clusterForwardWrap) does not apply
because SSH is not HTTP. The viable options remain:

1. operator routes SSH at the LB by sandbox-id-derived hostname;
2. ssh-gateway looks up the owner via `Cluster().OwnerOf(id)` and proxies
   the connection itself;
3. document SSH as a one-node-at-a-time feature.

None of those are implemented. Stage 3 P1 unfixed.

## L8. Caddy admin is still one PUT/PATCH per route (STRETCH)

`pkg/caddy/client.go:343-682` — every route mutation is a single admin
API call. The reconciler in `internal/service/service.go:2234-2237` runs
them through `runIngressOpsBatched` with `clusterIngressMaxConcurrentWrites
= 8` and `clusterIngressBatchSize` batched submission. There is no:

- bulk Caddy admin endpoint;
- xDS-style streaming config push;
- alternative ingress backend behind a feature flag.

At 100k routes, a full rebuild on a new ingress node taking over a shard
still walks every route in that shard. The fingerprint-diff path mitigates
steady-state churn but not initial sync.

**Impact.** Adding a new ingress node to handle a hot shard is a slow
operation (seconds-to-minutes range, depending on Caddy admin throughput).
For the Stage 4 bar (100k sandboxes, low churn) this is acceptable.

## L9. No backup/restore, no schema migration plan for the Raft FSM (BAR)

There is no documented or scripted way to:

- back up the Raft data dir;
- restore from a known-good snapshot when quorum is permanently lost;
- migrate FSM schema (the `command` struct changes the JSON wire format
  any time a field is added);
- replace a failed server while keeping quorum (manual `RemoveServer` +
  `AddVoter` works but is not in the runbook).

Stage 3 P1 ("Lost quorum and backup/restore are undefined") is unfixed.

## L10. Daytona / E2B list endpoints are not cluster-wide (BAR)

`pkg/api/daytona/handlers.go:305-326` and `pkg/api/e2b/handlers.go` —
`listSandboxes` calls `Service.ListSandboxes(ctx, nil)` which is local-only.
Only v1's `clusterListWrap` does the fan-out (and that one is bounded to
256 peers anyway).

A Daytona client calling `daytona.sandboxes.list()` on Node A sees only
Node A's local sandboxes, not the global view. The same is true for E2B.

**Impact.** Inconsistent product behavior. From a single user's
perspective, listing through Daytona vs. through v1 returns different sets
of sandboxes. Cluster-wide enumeration is only available via the new
`/v1/cluster/sandbox-index` paginated endpoint, which Daytona/E2B SDKs
don't call.

## L11. Image cache locality is not in the scheduler (STRETCH)

`internal/cluster/placement.go:59-127` — `SelectPlacement` scores on
CPU/Mem/Disk/GPU/runtime. It does not know which workers have an image
cached. The image-distribution metadata distinguishes
`local_only` (pinned), `aocr`, and `external_registry`, but the latter two
are placed identically regardless of cache state.

**Impact.** A 100k-create burst of the same image hammers the registry
once per cold-cache worker — `pkg/docker/client.go`'s in-process
single-flight prevents intra-node duplication, but not cross-node.

## L12. `SealedSecrets` legacy bag still rides Raft on rolling upgrade (BAR)

`internal/cluster/cluster.go:124-152` and
`internal/cluster/fsm.go:91-111` — new writes use `Ref`+`Version` only,
but a log entry written by an older binary that carries `SealedSecrets`
still gets replicated to every server-role node on Raft replay/restore.
The fallback is correct for compatibility but means the "secret material
is off Raft" invariant is **eventually true**, not **always true**, until
operators have rolled all servers past the old binary.

**Impact.** During a rolling upgrade window, the new-style placement rows
land on the new binaries with refs only, but the historical Raft log
still carries sealed bytes. A snapshot taken during the upgrade window
includes them.

## L13. Raw TCP high-cardinality is a product/data-plane ceiling, not a code limit (BAR)

**This is not an allocator bug.** The FSM `hostPortIndex`
(`internal/cluster/fsm.go`) gives O(1) cluster-wide collision
rejection at any sandbox count, proven by
`TestScaleGateHostPortIndexAt100K`. `internal/service/service.go`'s
`allocateHostPort` commits the cluster intent via `opAddExposedPort`
before any local side effect, and `pkg/caddy/client.go`
`UpsertTCPProxyRoute` lets every ingress node bind the same
`:hostPort` and forward to the owner. The cluster-stable raw-TCP
contract is correct.

What bounds raw-TCP exposure is the **data plane**, not the FSM:

- **Configured host-port pool.** `SB_L4_PORT_RANGE_START` /
  `SB_L4_PORT_RANGE_END` default to `22000` / `23000` —
  1,001 distinct ports. The cluster's raw-TCP ceiling is
  `(end - start)`, full stop.
- **Per-ingress L4 listener count.** Every exposed raw-TCP port
  becomes one `caddy-l4` server bound to `:hostPort` on **every**
  alive ingress node. With N exposed ports × M ingress nodes, each
  ingress process holds N listening sockets and N entries in the
  caddy-l4 server map. Caddy admin mutations walk that map.
- **Public IP/port arithmetic.** A single public IP physically caps
  at 65,535 ports, of which the operator can realistically dedicate
  some fraction to the raw-TCP pool.

**Operator strategy at scale:**

- enlarge `SB_L4_PORT_RANGE_*` (a 10K-port pool gives 10K
  simultaneous raw-TCP exposures);
- front the cluster with multiple public IPs, or partition tenants
  across ingress shards each with their own pool;
- for >~1,000 simultaneous TCP-shaped exposures, prefer
  **TLS-SNI passthrough** — `UpsertSNIPassthroughRoute` scales with
  hostnames, not ports, so it inherits the same near-unlimited
  cardinality HTTP has;
- raw TCP at 100K simultaneous exposures is **not in scope** and
  should be documented as such.

**Impact.** A user reading the docs cannot tell when raw TCP scaling
stops working. The constraint should be documented in
`docs/src/content/docs/tcp-ports.mdx` with the three knobs above and
an explicit "prefer TLS-SNI for high cardinality" recommendation.
Stage 3 P0 ("Raw TCP has a hard port-space ceiling") is the same
observation, properly scoped: it is a documentation gap, not a code
issue.

## L14. Single-tier ingress shard assignment, no replicas (BAR)

`internal/cluster/shards.go:107-148` — `IngressShardFilterForNode`
assigns each placement shard to one ingress-capable node (modulo). If
that node dies, the shard is unowned until gossip converges and the
reconciler reassigns.

There is no:

- `replicas: 2` mode where two ingress nodes own each shard for hot
  failover;
- ingress health weight that excludes a degraded node before a hard
  failure;
- intentional drift between expected and installed routes for canary
  rollout.

**Impact.** Ingress failover is gossip-bound (subsecond to a few seconds).
For the stated SLO that is acceptable; for a five-nines public ingress
SLO it is not.

## L15. Snapshot of running sandboxes (the AerolVM `snapshot` feature) is local-only and not cluster-aware (SCOPE)

Snapshot rows live in local SQLite; create-from-snapshot must run on the
node that holds the snapshot image (pinned by image-distribution
metadata). There is no plan in this PR for distributed snapshot storage —
which matches the explicit user constraint, but is called out here so
operators are not surprised.
