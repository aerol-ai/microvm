# 04 - Current Running Issues In This Branch

Concrete bugs, gaps, and footguns observable in `distributed-orchestrator-2`
today. Sorted roughly by severity. Each has a "where" pointer, a "what
goes wrong" sketch, and a proposed remediation shape.

This file is **distinct from `plans/limitations.md` / `03-limitations.md`**:
limitations are architectural ceilings the design knowingly accepts;
issues are things the design intends to do correctly that it currently does
not.

---

## I1. PR description is the unfilled template — every required section is blank

**Where.** `gh pr view 79 --json body` returns the verbatim
`.github/pull_request_template.md` with no sections filled in. The PR
touches:

- 170 files;
- 34,909 insertions, 409 deletions;
- `internal/service/service.go` (+857 / -75) — boot path;
- `pkg/api/v1/cluster_handler.go` (+1,180);
- `internal/cluster/` (10K+ new lines);
- `pkg/caddy/client.go` (+273);
- `internal/store/store.go` (+209);
- TCP host-port pool and L4 bootstrap.

`pr-review.md` calls out exactly these axes as "silence in the PR
description is **not** acceptable." None of:

- Summary,
- Sandbox boot impact,
- Idempotency,
- Failure-path consistency,
- L4 / host-port-pool changes,
- Test plan,

are filled in.

**Remediation.** Before this PR is mergeable under the existing
`pr-review.md` contract, every section must be filled. Specifically the
review must call out:

1. **Boot impact** of the `cluster.Cluster` / `cluster.Agent` construction
   path (`cmd/sandboxd/main.go:130-169`) and the `AssertOwnership` replay
   at `cmd/sandboxd/main.go:204-216`.
2. **Idempotency** of the reservation-first create flow under retry,
   leader change, and same-name racing creates.
3. **Failure-path rollback** for `clustercreate.CreateOnSelectedNode` —
   what happens when `RecordPlacement` succeeds but secret seal fails,
   when secret seal succeeds but Docker create fails, when Caddy upsert
   succeeds but `store.Create` fails, etc.
4. **L4 / host-port-pool** changes: the FSM `hostPortIndex`,
   `TryReserveHostPort` interaction with the new `allocateHostPort` call
   shape, and the cross-node `UpsertTCPProxyRoute` semantics.
5. **Regression test** pointers for `host_port` partial unique index +
   FSM index parity (`internal/store/store_test.go` already covers some
   of this).

---

## I2. Daytona and E2B mutating handlers do not write through to the FSM spec

**Where.**

- `pkg/api/daytona/handlers.go:481-509` (`resizeSandbox`),
  `601-646` (`updateIdleLifecycle`), `572-599` (`setAutoArchiveInterval`).
- `pkg/api/e2b/handlers.go` (`updateTimeout`, `pauseSandbox`).

All of these call into the service layer (`ResizeSandbox`,
`UpdateLifecycle`) without invoking `Cluster().UpsertSpec(...)`. Only the
v1 layer's `replicateSpecPatch` (`pkg/api/v1/cluster_handler.go:1088-1107`,
called from `pkg/api/v1/handlers.go:138-198`) keeps the cluster spec
fresh.

**What goes wrong.** After a Daytona resize:

- the local sandbox row has the new CPU/Memory/Disk;
- the cluster FSM still has the original CPU/Memory/Disk;
- `SpecOf` on any peer returns stale values;
- if `clusterRecreateOnFailoverEnabled` ever flips to true (or a future
  reclaim-orphan flow runs), the sandbox comes back at create-time size,
  not its current size.

Today this is masked by `clusterRecreateOnFailoverEnabled = false`.

**Remediation.** Either:

1. Move the write-through into `Service.ResizeSandbox` / `UpdateLifecycle`
   so every caller (v1, Daytona, E2B) benefits. This is cleaner — the
   cluster contract no longer depends on which HTTP wrapper the call
   went through. The `pr-review.md` § 5 invariant ("multi-step writes
   touching both caddy and the store must have a documented rollback
   rule") effectively requires this.
2. Or wire `replicateSpecPatch` equivalents into each facade. Adds
   duplication but minimally invasive.

Either way, write a regression test that issues a Daytona resize and asserts
`Cluster().SpecOf(id).CPU` changed.

---

## I3. Reservation TTL of 120s is shared with leader GC tick of 5s

**Where.** `pkg/api/clustercreate/clustercreate.go:22` —
`ReservationTTL = 120 * time.Second`;
`internal/cluster/dead_owner.go:268-313` — leader GC sweep every 5 seconds.

**What goes wrong.** Slow image pulls (especially GPU images,
multi-gigabyte) plus mount setup plus Caddy plus SQLite can exceed 120
seconds on a busy worker. The reservation is then cancelled mid-create.

The downstream effect is recoverable but ugly:

- the target's `RecordPlacement` (opPlace) succeeds because the FSM
  treats it as a fresh placement; the cluster ends up correct.
- but during the gap, `SelectPlacement` on the cancelled-reservation
  owner sees free capacity that's actually committed to an in-flight
  create.

**Remediation.** Either:

1. Make the target extend the reservation TTL during long-running create
   steps (e.g. heartbeat every 30s while pulling).
2. Set TTL by request shape — GPU images get a longer TTL, plain Alpine
   gets a short one.
3. Tie reservation expiry to a server-side heartbeat from the target
   instead of a flat wall-clock TTL.

The plan in `plans/reservation-first-create.md` already notes this; the
fix has not landed.

---

## I4. Gossip metadata fallback silently drops role + capacity

**Where.** `internal/cluster/gossip.go:90-103` — `NodeMeta(limit int)`
when `encoded > limit` falls back to a `nodeMeta{NodeID, APIURL,
DataPlaneHost}` blob — no `Role`, no `Capacity`, no `RaftAddr`, no
`InternalURL`.

**What goes wrong.**

- A degraded peer is treated as "no role advertised" by every other
  node, which `CanOwnSandboxRole("")` treats as **worker-capable** for
  rolling-upgrade compatibility. So a pure server can become an
  `opReserve` target if its gossip blob ever overflows.
- The leader's voter-auto-promotion code reads `Role` and would lose the
  "do not promote this worker" guard.
- Owner forwarding falls back to public APIURL + PAT because
  `InternalURL` is empty — non-fatal, but a quiet downgrade from mTLS.

This is the third time it has been raised (Stage 3 P1).

**Remediation.**

1. Split the gossip blob: only stable identity in NodeMeta; capacity and
   role fetched via a versioned status endpoint.
2. Add a test that forces the blob over 512 bytes and asserts that the
   leader still refuses to promote a worker (via a documented safe-mode
   fallback) and that placement still excludes degraded peers.
3. Bump the memberlist `Config.NodeMeta` limit from the default 512 if
   the configuration allows.

---

## I5. `OwnerOf` on a stale follower can forward to a former owner

**Where.** `internal/cluster/client.go:293-322` — `OwnerOf` reads the
local FSM. A follower that is behind by N raft entries will see the
pre-failover owner.

**What goes wrong.**

- A reassign command lands on the leader.
- A request to delete the sandbox arrives at follower A whose FSM has
  not applied the reassign yet.
- `clusterForwardWrap` forwards to the old owner over the mTLS channel.
- The old owner returns 421 / 410 / 5xx depending on its local state.
- The PR catches loops via `X-Cluster-Forwarded: 1` (see
  `pkg/api/daytona/cluster_forward.go:50-54`), but a single stale
  forward still wastes a round-trip.

**Remediation.**

1. Expose owner lookup with the FSM revision so callers can include a
   `If-Min-Revision` header.
2. For mutating operations, do a leader-read (round-trip to the leader)
   before forwarding.
3. Add the `stale_owner_forward_count` counter to a dashboard alert.

---

## I6. `clusterForwardWrap` and `clusterListWrap` carry different loop-detection conventions

**Where.**

- `pkg/api/daytona/cluster_forward.go:50-54` checks
  `X-Cluster-Forwarded: 1`.
- `pkg/api/v1/cluster_handler.go:380-386` (list path) and
  `internal/cluster/forward.go` (forward setter) use the same header.
- But `pkg/api/v1/cluster_handler.go:50-99` (the v1 `clusterForwardWrap`)
  trusts the next hop to set the header — if a misconfigured peer drops
  the header, the request can ping-pong.

**What goes wrong.** A request loop between two nodes with divergent
placement views consumes both nodes' goroutines for the request lifetime.

**Remediation.**

1. Make the forward setter increment a hop count header
   (`X-Cluster-Forward-Hops`) and the wrappers reject requests with
   `> max_hops` (e.g. 2).
2. Add a test that forces a placement-disagreement scenario and asserts
   the loop terminates with `MisdirectedRequest`.

---

## I7. `clusterListWrap` returns no partial-success metadata

**Where.** `pkg/api/v1/cluster_handler.go:379-500`.

**What goes wrong.** Per-peer errors are logged and skipped. The HTTP
response merges the local list with whichever peers responded in time.
There is no:

- `X-Partial-Results: true` header;
- failed-peer count in the response body;
- per-row "from which node" attribution.

Operator dashboards cannot distinguish a 200 with 10k rows from "all peers
healthy" vs. "half the peers timed out, this is half the cluster."

**Remediation.** Add a wrapping envelope (or response header) for
partial-result indication. The Daytona/E2B layers don't list cluster-wide
so this only affects v1, which makes the surface small.

---

## I8. `SubscribePlacement` channel cap=1 can drop wake signals during bursts

**Where.** `internal/cluster/cluster.go:476-490`,
`internal/cluster/fsm.go:222-228`.

**What goes wrong.** During an N-create burst, the FSM signals
subscribers N times. The cap=1 channel collapses them — the reconciler
wakes once, processes the latest view, and may miss intermediate
versions. This is documented as "tolerant of spurious wakes" but it's
also a "tolerant of missed wakes within a single tick."

Combined with the `ingressLastHash` idle-skip
(`internal/service/service.go:2218-2224`), if the burst is large enough
to advance the view hash but the reconciler is mid-pass with a stale
hash, the post-pass wake may collapse against the already-set "in
progress" state and the new placement waits for the slow timer.

**Remediation.** Either:

1. Bump the subscriber buffer to a small N (4-8) with a documented
   drop-with-counter on overflow.
2. Pass the latest applied raft index through the channel so the
   receiver can re-check against a stored "max processed" instead of
   relying on the hash diff alone.

This is subtle; under steady state it's fine. Under burst it can add
seconds to convergence.

---

## I9. `placementCanBeClaimedBy` in agent allows reclaim only on previous-owner — but agent has no FSM, so it relies on RPC

**Where.** `internal/cluster/agent.go:402-444` —
`AssertOwnership` path that uses `placementCanBeClaimedBy(existing.Placement, a.nodeID)`.

The agent reads the placement via `lookupPlacement` over the control-plane
RPC. If the server-role member it talks to is a stale follower, the
returned `OrphanedOwnerNodeID` may be empty or wrong, and the agent might
either:

- claim a placement it shouldn't (orphan claim conflict surfaces only at
  apply time), or
- decline to claim a placement it should (a legit reclaim retries on the
  next boot).

**What goes wrong.** The agent's `ClaimOrphan` then either succeeds (FSM
returns the orphan-claim-conflict error and the agent skips), or fails
with `ErrOrphanClaimConflict`. Net behavior is safe — the FSM is the
arbiter — but the agent logs noise during stale reads.

**Remediation.** Pass the placement version observed at lookup into
`ClaimOrphan` so the FSM can reject `If-Match` style. Cheap and removes a
race window.

---

## I10. Snapshot/built-image GC remains per-node, not cluster-aware

**Where.** `internal/service/service.go:2114-2138` —
`runBuiltImageGC` uses the local store's `HasActiveImageRef`. There is no
cluster-wide reference count.

**What goes wrong.** A sandbox placed on Node A using a registry-style
image built locally on Node B will keep Node B's `HasActiveImageRef`
returning false. Node B's GC then deletes the image while Node A still
references it — at recreate time (or owner reassignment, if that's ever
on) the new owner can't find the image.

For the current Stage 4 product policy (local-only images pinned, no
recreate), this is harmless. It becomes a bug if any of these change.

**Remediation.** Cluster-wide image refs (the FSM can already see every
sandbox's image string via the redacted spec). Or: a "do not GC" mark
operators can set on built images that are intentionally shared.

---

## I11. The reconcile / lifecycle / netstats sweeps still iterate the full local store

**Where.** `internal/service/service.go:1470-1540`, `1572-1680`,
`internal/service/netstats.go:191-210` (paraphrased — search for the
sweep loops).

**What goes wrong.** Per-node sweeps are O(local-sandbox-count). At
500 nodes × 200 sandboxes/node = 100k cluster sandboxes, that's 200/sweep
per node — fine. At 500 × 1k = 500k cluster sandboxes, the per-node
sweep is heavy.

This is **within the Stage 4 ceiling**, but the path to growing the
cluster further is bounded by these loops, not the cluster plane.

**Remediation.** Index the sweeps. Make netstats event-driven on Docker
`/events` for short-lived sandboxes.

---

## I12. The `internal/scaleobs` package adds metrics but no Prometheus / OTEL exporter wiring is visible in this PR

**Where.** `internal/scaleobs/metrics.go` (and the new metrics in
`internal/service/metrics.go`, `internal/cluster/metrics.go`,
`pkg/caddy/metrics.go`, `pkg/capacity/metrics.go`).

**What goes wrong.** Metrics are written via `expvar`. Operators using
Prometheus or OTEL need a scraper or translator. There's no
`/v1/metrics` endpoint surfaced by `pkg/api`.

**Remediation.** Wire `expvar` to a `/v1/metrics` Prometheus-compatible
endpoint, or document the scrape path (`/debug/vars`).

---

## I13. No documentation on `SB_NODE_ROLE` migration for existing single-node deployments

**Where.** `setup/cluster.md`, `setup/single-node.md`,
`setup/local.md`, `setup/arch.md` — new but they describe greenfield
clusters.

**What goes wrong.** An operator running a single-node `sandboxd`
upgrading to a multi-node cluster has to:

1. set `SB_NODE_ROLE=server,worker` (the "mixed" default already covers
   this);
2. set `SB_ENABLE_CLUSTER=true`;
3. set TLS dir, gossip key, bootstrap peers;
4. arrange that the existing sandboxes' placements are claimed via
   `AssertOwnership` at boot.

Step 4 is covered by `cmd/sandboxd/main.go:204-216` but operators have
no doc that says so. A naive upgrade to a multi-node cluster where the
second node tries to "rebalance" existing sandboxes will be confused by
410-Gone on the originals.

**Remediation.** Add a "migrating an existing single-node deployment to a
cluster" page to `docs/src/content/docs/`. The cluster-criticial-thinking-
stage-4 plan exists; the user-facing doc does not.

---

## I14. The `merge-base` workflow filter does not appear to run the cluster scale gates

**Where.** `.github/workflows/test.yml` is path-filtered for `docs/**`
short-circuit. The cluster scale gates require `AEROLVM_SCALE_GATES=1`
(`scripts/scale-gates.sh`) which is not invoked by CI.

**What goes wrong.** A regression that breaks the 100k-placement
host-port collision check is invisible until manual run.

**Remediation.** Add a slow-job in CI that runs `scripts/scale-gates.sh`
nightly or on `cluster-*` label.
