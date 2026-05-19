# 01 - Features Enhanced In This PR

This file enumerates what the PR materially adds or rewrites versus the
state Stage 3 reviewed. Each item points at the canonical file/line where the
behavior lives. The bar for "enhanced" is "shipped code path that did not
exist or was fundamentally different in the Stage 3 review."

## 1. Real role split (k3s-shaped server/agent decomposition)

- `internal/cluster/cluster.go:1-28` — package doc now explicitly states that
  worker/ingress-only nodes "do not store the FSM and do not join Raft as
  non-voters."
- `internal/cluster/client.go` — `Cluster` is the server-role implementation;
  starts Raft + FSM + gossip + mTLS internal listener.
- `internal/cluster/agent.go` — new `Agent` type for worker/ingress-only
  roles. **No Raft transport, no FSM, no non-voter membership.** Carries:
  - gossip-only membership (`RaftAddr: ""`);
  - control-plane RPC client (`doControlPlaneBytes`) that walks server-role
    peers on `ErrNotLeader`/503;
  - mTLS internal listener + reverse-proxy cache symmetric to `Cluster`.
- `cmd/sandboxd/main.go:130-169` — boot branches on `cfg.IsServer()`:
  - server roles call `cluster.New(...)`;
  - worker / ingress / `worker,ingress` call `cluster.NewAgent(...)`.
- `internal/cluster/voter_autojoin.go:108-148` — `peerForcedNonVoter` /
  `isForcedNonVoterRole`: a gossiped role of `worker`, `ingress`, or
  `worker,ingress` is *never* promoted to a Raft voter. The leader also
  short-circuits before any AddNonvoter when the peer has no `RaftAddr`,
  which is the only state an agent ever advertises.

This is the structural change Stage 3 P0 demanded: workers are off Raft.

## 2. Reservation-first create unified across v1, Daytona, and E2B

- `pkg/api/clustercreate/clustercreate.go` — new shared package:
  - `Prepare(...)` — parses `X-Cluster-Create-Target`/`X-Cluster-Create-ID`
    forwarded headers, runs `SelectPlacement`, writes `opReserve`, and
    forwards. Used by all three facades.
  - `CreateOnSelectedNode(...)` — runs `CreateSandboxWithID` against the
    reserved ID, seals secrets for the recipient, calls `RecordPlacement`,
    rolls back on every failure path.
  - `ReservationTTL = 120 * time.Second`, mirrored by
    `internal/cluster/dead_owner.go:268-313`'s 5-second leader GC tick.
- `pkg/api/v1/cluster_handler.go:117-247` — v1 `POST /v1/sandboxes` runs the
  same flow.
- `pkg/api/daytona/handlers.go:42-119` — Daytona `POST /daytona/sandbox`
  calls `clustercreate.Prepare` + `clustercreate.CreateOnSelectedNode`.
- `pkg/api/e2b/handlers.go:44-138` — E2B `POST /e2b/sandboxes` does the same,
  with E2B's deterministic fingerprint sandbox ID flowing through as
  `PreferredSandboxID`.

## 3. Per-facade owner forwarding for sandbox-scoped routes

- `pkg/api/v1/cluster_handler.go:50-99` — v1 `clusterForwardWrap`.
- `pkg/api/daytona/cluster_forward.go` — Daytona `clusterForwardWrap`,
  including `OwnerOfName` fallback for the SDK's name-or-ID addressing.
- `pkg/api/e2b/cluster_forward.go` — E2B `clusterForwardWrap`.
- `pkg/api/daytona/routes.go:56-77` and `pkg/api/e2b/routes.go:21-37` — every
  per-sandbox mutating route is now wrapped:
  - Daytona: get/destroy/start/stop/snapshot/resize/labels/autostop/
    autodelete/autoarchive/toolbox-proxy/preview-url;
  - E2B: get/delete/connect/pause/timeout/snapshots.

## 4. Cluster-wide name uniqueness

- `internal/cluster/fsm.go:266-275`, `682-700`, `1011-1022` — `nameIndex`
  built inside `Apply`, validated on every `opPlace`/`opReserve`/
  `opClaimOrphan`/`opUpsertSpec` and rebuilt on `Restore`. Returns
  `cluster.ErrNameConflict` so the facade can translate it to 409.

## 5. O(1) host-port collision check via FSM index

- `internal/cluster/fsm.go:138-172` — `hostPortIndex map[int]hostPortClaim`.
- `internal/cluster/fsm.go:803-847` — claim/release/validate locked helpers,
  populated lazily on first call so old snapshots still restore.
- `internal/cluster/scale_gates_test.go:59-84` — `TestScaleGateHostPortIndex
  At100K` proves the duplicate-host-port rejection works at 100k placements.

## 6. Pending reservation accounting in O(1)

- `internal/cluster/fsm.go:144-152`, `849-998` — `pendingReservationClaims` +
  `pendingReservationCapacity` (per-owner aggregate) +
  `pendingReservationIDsByOwner` + `pendingReservationExpiries` heap.
- `internal/cluster/placement.go:60-100` — `SelectPlacement` no longer scans
  the placement map; it reads `pendingReservationsByNode(now)` which prunes
  expired claims lazily from the heap.

## 7. Placement sharding (16,384 shards)

- `internal/cluster/shards.go:8-105` — `DefaultPlacementShardCount = 16384`,
  `PlacementShardForSandbox` (FNV-1a), `PlacementShardFilter`,
  `PlacementPageRequest/Response`.
- `internal/cluster/fsm.go:128-133`, `772-801`, `1077-1117`, `1119-1175` —
  FSM shard index + `placementsForShards` + `placementPage`.
- `pkg/api/v1/cluster_handler.go:536-595` — `/v1/cluster/sandbox-index`
  paginated index endpoint.
- `pkg/api/v1/cluster_handler.go:540-561` — `/v1/cluster/ingress-route/{id}`
  exposes the stable shard + owner set for an upstream router.

## 8. Ingress sharding + delta reconcile

- `internal/cluster/shards.go:107-148` — `IngressShardFilterForNode` carves
  the 16,384 shards across alive ingress-capable members.
- `internal/service/ingress_delta.go:42-181` — `buildClusterIngressIntents`
  produces per-route intents with fingerprints.
- `internal/service/ingress_delta.go:222-250` — `planClusterIngressDelta`
  diffs against `ingressRouteCache` and emits only changed apply/delete ops.
- `internal/service/service.go:2198-2269` — `ReconcileClusterIngress` only
  runs full Caddy snapshot GC sparsely (`clusterIngressFullGCInterval = 1m`);
  the hot path is delta-only.
- `internal/service/service.go:2164-2196` — `StartClusterIngressReconcile`
  wakes on `SubscribePlacement` instead of a 500ms poll.

## 9. In-flux placeholder routes during failover

- `internal/service/ingress_delta.go:183-220` — when a placement's owner is
  unknown or its data-plane host is empty, the ingress reconciler installs an
  in-flux Caddy route that returns a controlled 503/Retry-After instead of
  letting traffic drop to a connection reset.

## 10. Convergence metrics no longer report success on failure

- `internal/service/service.go:2256-2268` — `recordIngressReconcile` is
  called with `reconcileApplied` only on success and `reconcileErrored` on
  failure; `ingressLastHash` is reset to 0 on error so the next tick retries.
- This was the Stage 3 P0 "convergence metric can lie" claim.

## 11. Secret reference model (payloads off Raft)

- `internal/cluster/cluster.go:124-152` — `PlacementSecrets` carries
  `Ref`+`Version`; `LegacySealed` is rolling-upgrade fallback only.
- `internal/cluster/fsm.go:103-111` — `applyCommandSecretUpdate` keeps the
  ref, drops any accidental `SealedSecrets` blob.
- `internal/service/cluster_secrets.go:1-150` — `clusterSealedSecrets` schema
  (registry + per-mount creds only), AES-GCM with recipient-bound AAD,
  per-secret data key wrapped by the service cipher.
- `internal/store/store.go:110-124`, `200` — `cluster_secrets` table with
  recipients_json + sealed_payload + index on `sandbox_id`.

## 12. Image distribution metadata + single-flight pulls

- `internal/service/image_distribution.go` — `ImageDistributionProvider`
  contract with three modes: `external_registry`, `aocr`, `local_only`.
- `pkg/api/v1/cluster_handler.go:183-190` and
  `pkg/api/clustercreate/clustercreate.go:66-72` —
  `ImageRequiresLocalPlacement` pins `local_only` to the receiving worker
  before placement; a worker that does not have the image fails fast.
- `pkg/docker/client.go` — image-pull single-flight per `(image, auth)` tuple
  so a 100k-create burst on a node does not stampede the registry.

## 13. Full-spectrum admission (CPU + memory + disk + GPU + runtime)

- `internal/service/service.go:309-349` — `capacityRequestFromCreate`,
  `capacityRequestFromSandbox`, GPU/vendor helpers.
- `internal/cluster/placement.go:14-46` — `capacityRequestFromSpec` mirrors
  the same shape on the recreate / failover path.
- `internal/cluster/placement.go:134-176` — `nodeFits` now checks
  `CPUBudget`, `MemoryBudgetMB`, `DiskBudgetGB`, GPU count/vendor, and the
  member's `SupportedRuntimes` list.

## 14. Resize spec patch preserves unset fields

- `pkg/api/v1/cluster_handler.go:1070-1107`, `pkg/api/v1/handlers.go:138-142`
  — `replicateSpecPatch` reads the cluster-replicated spec, applies a
  caller-supplied patch, and writes back via `UpsertSpec` so an unspecified
  CPU/Disk is preserved instead of being clobbered with zero.

## 15. Batch orphan + reclaim-local for false-positive dead-owner events

- `internal/cluster/fsm.go:475-555` — `opOrphanOwner` walks the owner index
  and orphans every placement plus cancels pending reservations in **one**
  Raft command. `opClaimOrphan` reclaims only when the previous owner is
  this node.
- `internal/cluster/dead_owner.go:187-247` — `evictDeadOwner` in the
  no-recreate policy path issues exactly one `opOrphanOwner` instead of one
  Raft apply per sandbox.
- `pkg/api/v1/cluster_handler.go` — operator orphan APIs:
  - `GET /v1/cluster/placements/{id}` (orphan inspect);
  - `POST /v1/cluster/orphans/{id}/reclaim-local`;
  - `DELETE /v1/cluster/orphans/{id}`.

## 16. Bounded list fanout + paginated index alternative

- `pkg/api/v1/cluster_handler.go:36-38` — `clusterListMaxFanoutPeers = 256`,
  `clusterListMaxConcurrentPeerReads = 64`.
- `pkg/api/v1/cluster_handler.go:379-500` — `clusterListWrap` fails closed
  with a 503 pointing at `/v1/cluster/sandbox-index` if the peer count
  exceeds the cap.

## 17. mTLS internal control-plane channel

- `internal/cluster/tls.go`, `internal/cluster/raft_tls.go` — cluster CA +
  node keypair loaded from `SB_CLUSTER_TLS_DIR`.
- `internal/cluster/internal_server.go` — mTLS HTTPS listener on
  `SB_CLUSTER_INTERNAL_LISTEN_ADDR` accepts leader-forwarded raft applies
  and reverse-proxied owner-API forwards (via `AttachInternalHandler`).
- `internal/cluster/client.go:166-201` and `agent.go:124-147` — both server
  and agent use the same mTLS dial path with a separate proxy cache.

## 18. Observability surface (`internal/cluster/metrics.go`,
`internal/service/metrics.go`, `internal/scaleobs/metrics.go`, etc.)

- Raft apply / snapshot / restore latency + queue depth.
- Gossip member counts, worker lease counts, lease loss counters.
- Scheduler decisions split by `self/remote/no_target` + rejection reasons.
- Placement-cache refresh latency + shard-cache size (agent side).
- Create queue depth, latency buckets, reservation state transitions.
- Per-node host pressure (CPU/Mem/Disk/GPU reserved, can-admit gauge).
- Ingress route counts per protocol, lag, attempted vs. installed revision,
  Caddy admin latency histogram, route misses by reason.
- Owner forwarding latency + stale-owner 421 count.
- Facade idempotency claim/acquire/replay/conflict/complete counts.
- Netstats poll duration + dropped samples by reason.
- Secret decrypt latency + recipient-deny + key-version-mismatch counts.

## 19. Scale gates (single-process, 100k row scale)

- `internal/cluster/scale_gates_test.go` — gated behind
  `AEROLVM_SCALE_GATES=1`:
  - `TestScaleGatePlacementPageAndShardAt100K`;
  - `TestScaleGateHostPortIndexAt100K`;
  - `TestScaleGatePendingReservationIndexAt100KPlacements`;
  - `TestScaleGateBatchOrphanOwnerAt100KPlacements`.
- `internal/service/scale_gates_test.go`:
  - `TestScaleGateIngressShardAssignmentAt10KMembers`;
  - `TestScaleGateIngressDeltaAt100KPlacements`.
- `scripts/scale-gates.sh` — convenience wrapper running the gates plus the
  ingress storm / 10K hash regression tests.
- `scripts/load/ingress_churn.go` + `scripts/load/stats.go` — load
  generator + percentile stats.

## 20. Setup documentation for the new topology

- `setup/arch.md`, `setup/cluster.md`, `setup/single-node.md`,
  `setup/local.md` — operator-facing docs that describe the server/worker/
  ingress split, bootstrap peers, gossip key, TLS material, and the
  reservation-first create flow.
- `docs/src/content/docs/cluster-setup.md`,
  `docs/src/content/docs/cluster-setup-step-by-step.mdx`,
  `docs/src/content/docs/cluster-ingress.mdx`,
  `docs/src/content/docs/durability.mdx` — user-facing docs site updates.
