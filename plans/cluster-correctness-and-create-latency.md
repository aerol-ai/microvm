# Cluster correctness first, then create latency

Status: draft, 2026-11-07. Not reviewed. Next gate: `/plan-eng-review`.
Base: `main` at 58c9a0bd4ab4aa2fbd10910a00a66686b26f970c.

## 0. Why this plan exists

The owner asked two things together:

1. Make creates faster: the cold path, cluster create throughput, the owner
   lookup on routed requests, network setup.
2. Make sure the simple orchestration (Raft + gossip + per-node SQLite +
   reconcile, instead of Kubernetes) has not given up correctness.

A code audit of `main` (Section 2) found that it has, in specific places. Some
of the speed work in Section 4 changes exactly the synchronization these bugs
live in. So the order is:

1. Write down the invariants (Section 1).
2. Fix the verified violations, each with a test that fails first (Section 2).
3. Build the fault tests that keep them fixed (Section 3).
4. Then the speed work, measured before and after (Sections 4 and 5).

Rule for every PR here: one PR per item, a test that fails on `main` and
passes with the fix, numbers from something that was run. Items in
`internal/cluster` follow CLAUDE.md rule 6: a regression test next to the
changed file, a cluster-correctness call-out, and a no-op when
`EnableCluster` is false.

## 1. Invariants

| # | Invariant | Enforced on `main` |
|---|---|---|
| I1 | **One executor.** A node runs or serves sandbox X only while it may own X. | No. Ownership lives only in Raft; a cut-off old owner keeps running X. |
| I2 | **Ownership epoch.** Every owner change raises an epoch, and anything carrying an older epoch is refused. | No. The incarnation stays the same on reassign, and no request carries `Placement.Version`. |
| I3 | **No resurrection.** Once (X, incarnation) is deleted, it is never placed or run again. | Partly. Owner and incarnation checks exist on delete; broken by C2 and C3. |
| I4 | **Capacity.** A worker never runs more than its budget, and the leader never under-counts a worker's load. | First half yes (`Admitter.AdmitOwned`). Second half no (C7). |
| I5 | **Deterministic replication.** Applying a log entry depends only on the state and the entry. | No (C1). |
| I6 | **Convergence.** After failures stop and quorum is back, every sandbox has exactly one copy, on its owner, within a bounded time T. | Partly. T is the 5-minute reconcile interval; broken by C2 and C5. |
| I7 | **Routing safety.** Only the current owner serves X; any other node answers 421 or 503. | API path yes, except stale reads on a cut-off follower. Ingress data path no (C4). |
| I8 | **A failed create leaves nothing.** A create reported as failed leaves no sandbox and no placement once things converge. | No, when the rollback itself fails (C5). |

These go into `docs/src/content/docs/engineering-placement-failover.mdx` once the
fixes land, replacing the statements there that are not true today.

## 2. Verified violations, ranked

Each was traced through the code. C1, C2 and the 5-minute convergence time
were re-checked by hand; the rest come from the audit with file and function
names that exist on `main`.

### C1. The Raft state machine reads the wall clock (breaks I5) — high

- **Where:** `internal/cluster/fsm.go`, `placementFSM.apply` sets
  `now := time.Now().Unix()`. Reserve conflicts and expiry sweeps compare it
  with `ExpiresUnix` (`reservePlacementLocked`,
  `validateReservationBatchLocked`, the reserved and deleting sweeps).
- **Failure:** the leader rejects a re-reserve of the same id because the old
  reservation has not expired; a follower applying the entry a few seconds
  later, or any server replaying its log after a restart, sees it expired and
  overwrites it. Servers then disagree on the owner and the incarnation.
  Trigger: keyed creates (E2B, Runloop) re-reserving an id near the 120 s
  reservation expiry.
- **Fix:** use the leader's timestamp carried in the log entry
  (`raft.Log.AppendedAt`, hashicorp/raft v1.7.3) instead of `time.Now()`.
  Entries written before the upgrade have no timestamp; they keep today's
  behaviour, recorded as a known gap for logs older than the upgrade.
- **Test:** apply the same `opReserve` sequence to two FSMs whose clocks
  differ, and replay it after a simulated restart; the snapshots must be
  identical byte for byte. Fails on `main`.

### C2. A returning node brings a deleted sandbox back (breaks I3, I6) — high

- **Where:** `Cluster.AssertOwnership` (`internal/cluster`) calls
  `RecordPlacement` when no placement exists, and `opPlace` on a missing row
  does not check for a post-delete record. `Service.reconcileStaleOwnership`
  skips ids with no placement.
- **Failure:** W1 is cut off; X moves to W2 (or is orphaned); the user deletes
  X; W1 comes back, and its boot-time ownership replay re-creates X's
  placement on W1 with the old incarnation. X is routable again.
- **Fix:** `opPlace` on a missing row is refused when a post-delete record
  exists for (X, incarnation) (`retainAuditACLLocked` keeps one for
  `SB_AUDIT_DELETED_GRACE`, 1 h); the worker then destroys its local copy.
  Decide a rule for a node that returns after the record expired (quarantine:
  never re-place, ask the leader).
- **Test:** FSM: place, delete, place again with the same incarnation → error.
  Service: a local row whose placement was deleted is destroyed by the replay,
  not re-placed.

### C3. A delete during failover is lost (breaks I3) — medium-high

- **Where:** after `opReassign` to W2 and before W2 recreates X, a DELETE
  reaches W2, finds no local row (404), and the owner watcher recreates X a
  few seconds later. SDKs treat 404 on delete as done.
- **Fix:** when there is no local row but the authoritative placement belongs
  to this node, `DestroySandbox` commits the delete fence and the delete for
  the placement alone, under the create lease.
- **Test:** reassign, DELETE before the recreate, run the owner watcher; X
  must stay deleted.

### C4. A cut-off owner keeps running and serving (breaks I1, I2, I7) — high

- **Where:** `Cluster.evictDeadOwner` reassigns a dead node's
  `failover.policy=recreate` sandboxes after `SB_DEAD_OWNER_GRACE` (30 s);
  the old owner stops its copy only in `Service.reconcileStaleOwnership`,
  which needs a reachable leader. A follower on the cut-off side keeps
  answering placement reads from its own state; the ingress placement feed
  (`agent_placement_feed.go`) keeps its last rows with no age limit.
- **Failure:** during a partition the old and new owner both run X, both may
  mount the same volumes, and ingress on the cut-off side sends traffic to the
  old copy. The docs already admit "the dying owner might still write".
- **Fix, in this order:**
  1. **Worker ownership lease:** a worker that has not completed an
     authoritative read for longer than half the dead-owner grace pauses its
     recreate-policy sandboxes and refuses to serve them (`clusterroute.Wrap`
     answers 503).
  2. **No stale reads:** a follower answers internal placement reads with 503
     when `raft.LastContact()` is older than a bound.
  3. **Feed age limit:** after N seconds without a successful poll, the
     ingress feed marks every entry in-flux.
  4. **Ownership epoch (I2):** raise an epoch on every reassign and stamp it on
     forwarded requests (`StampForward`); the owner refuses a stale epoch.
- **Test:** offline, a fake clock and a failing control plane prove the lease
  pauses and refuses; live, a partition test (Section 3) asserts at most one
  running copy.

### C5. A failed rollback leaves a billed sandbox (breaks I8) — medium

- **Where:** `pkg/api/clustercreate/overlap.go` `retractFailedPromote`: when the
  promote fails during a leader election, the rollback also needs the leader,
  fails, keeps the local row, and nothing retries it. The ownership replay then
  promotes or re-places it.
- **Fix:** mark the local row rollback-pending; the replay skips it and
  reconcile retries the destroy.
- **Test:** leader unavailable during promote and rollback, then reconcile: no
  placement and no local row.

### C6. Dead-owner eviction has no owner fence (breaks I3) — medium-low

- **Where:** `evictDeadOwner` sends `opReassign` without
  `ExpectedOwnerNodeIDSet` and does not re-check each sandbox.
- **Fix:** set the expected owner per sandbox and re-check liveness.
- **Test:** a hook moves the placement between listing and applying; the
  reassign must be refused.

### C7. The leader under-counts load right after a promote (breaks I4) — low-medium

- **Where:** `opPlace` releases the reservation at once, so until the worker's
  next capacity snapshot that sandbox counts nowhere on the leader
  (`internal/cluster/placement.go`, `capacity_lease.go`). Mass failover
  reassigns a dead node's sandboxes against one snapshot. The worker's local
  admitter refuses the overflow, so no worker is oversubscribed; creates fail
  with 503 instead.
- **Fix:** keep promoted and reassigned load counted until a newer snapshot
  arrives.
- **Test:** fill a worker, promote, reserve again on the unchanged snapshot →
  `ErrCapacityExceeded`.

### C8. `opReserveBatch` is not all-or-nothing — low today, blocks E1

- **Where:** `validateReservationBatchLocked` skips the same-owner incarnation
  check that `reservePlacementLocked` makes (`ErrIncarnationConflict`), so
  earlier items are stored before a later one fails. No production caller uses
  the batch op yet.
- **Fix:** validate everything `reservePlacementLocked` checks before writing.
- **Test:** a batch with a same-owner incarnation mismatch leaves no partial
  writes.

## 3. Fault tests

Two layers. The offline layer runs in `go test` and gates every PR; the live
layer runs on AWS through `integration-tests/` and gates releases.

### 3.1 Offline (in-process, no AWS)

The in-process multi-node harness in `internal/cluster/cluster_test.go`
(`newTestCluster`, `waitForVoter`) runs real Raft between several `Cluster`
values. Add:

| Test | Guards |
|---|---|
| Two FSMs with different clocks, plus replay after restart, give identical snapshots | I5 (C1) |
| Place, delete, place again with the same incarnation is refused | I3 (C2) |
| Leader transfer during 64 concurrent reserves: granted ≤ capacity, no orphan reservations after TTL | I4, E2 |
| Promote and its rollback both fail during an election, then reconcile: nothing left | I8 (C5) |
| A worker whose control plane fails past the lease bound refuses to serve | I1 (C4) |
| A follower cut off from the leader answers placement reads with 503 | I7 (C4) |
| Property test: random interleavings of create, destroy, restart, reassign and leader change against a model; every invariant checked after each step | I1–I8 |

### 3.2 Live (AWS, operator-run)

New scenarios in `integration-tests/suite/`, next to
`z_disruptive_cluster_test.go`. Today the live failover tests only stop the
daemon (`systemctl stop sandboxd`), which leaves containers running and so
never checks that the old copy dies; the only live partition test
(`z_identity_chaos_test.go`) covers identity, not placement.

| Experiment | Expected |
|---|---|
| Kill the Raft leader during 1,000 concurrent creates | Committed placements survive; creates that did not get an answer converge to created or absent, never both |
| Partition an owner from the servers for 120 s, with an ingress on its side | At most one running copy at any time; traffic on the cut-off side gets 503, never the old copy |
| Kill a worker after the runtime started but before the store write | The restart finds and removes the orphan |
| Concurrent create, destroy and restart on the same ids | Only valid lifecycle transitions; nothing deleted comes back |
| 5% packet loss and 200 ms delay between nodes | No unsafe placement; failed creates are allowed |
| Restart every server one at a time | Committed state and placements preserved |
| 72-hour high-churn soak | No growth in leaked containers, orphans or placements |

### 3.3 Release gates

| Metric | Gate |
|---|---|
| Duplicate-ownership violations (two running copies) | 0 |
| Orphans left after the convergence deadline | 0 |
| Resurrections (deleted sandbox running or routable again) | 0 |
| Control-plane crash recovery | Within a stated RTO, measured |
| Resource leak over the soak | No sustained growth |

## 4. Create latency

### 4.1 Where a cold containerd create spends its time

From the live benchmark reports (3 × t3.medium, 2026-07-14; 3 × t3.large,
2026-07-19), default runc, containerd warm pool off:

| Stage | Server-Timing name | p50 |
|---|---|---|
| Raft reserve and forward | none (before `create;dur` starts) | ~10 ms (estimate) |
| Network namespace | `containerd_netns` | **recorded as a hard-coded 0** (`internal/runtime/containerd/lifecycle.go`) |
| Image resolve (cached) | `containerd_image` | 1 ms |
| Container and task create | `containerd_create` | 93–106 ms |
| Task start | `containerd_start` | 8–10 ms |
| Raft promote | `cluster_promote` | 10–12 ms |
| **Not covered by any stage** | — | **74–92 ms** |
| Total | `create` | 189–223 ms |

Facts behind this:

- The network namespace pool is off in code but every installer turns it on
  (`scripts/install.sh`, `Ansible/playbooks/configure-ops.yml`), so real
  installs already pre-make network namespaces. The published "Network setup
  0 ms" in `docs/src/content/docs/performance-benchmark.mdx` comes from the
  hard-coded zero, not a measurement.
- The containerd warm container pool is off everywhere. With it on, the same
  benchmark measured 223 ms → 25 ms for creates it could serve. Only creates
  with no env, mounts, command, registry, non-root user or GPU qualify
  (`internal/runtime/containerd/warm_adopt.go`).
- Suspected bug (traced, not run): on a single node, turning the containerd
  pool on does nothing, because the ready socket it needs is enabled only by
  cluster mode or the Docker pool (`Config.DockerReadySocketEffective`).

### 4.2 Work, in order

| # | Work | Expected | Notes |
|---|---|---|---|
| L1 | **Measure the gap.** Time `containerd_netns` for real (hit or miss); add stages before the driver, for spec and lease, `NewContainer` vs `NewTask`, and the IP read-back; time the reserve step | Turns 74–92 ms of unknown into named stages | Fix the docs table once measured |
| L2 | **Single-node containerd pool fix** in `DockerReadySocketEffective` | Makes the pool work outside cluster mode | Test first that it is really broken |
| L3 | **Wider warm-pool eligibility:** hand env (sealed) to the adopted container instead of requiring none (`plans/docker-warm-pool.md` §10) | ~200 ms for env-carrying creates | Needs its own design |
| L4 | **Warm pool in cluster deploys:** add the setting to `config/cluster.yml`, `Terraform/locals.tf` and Ansible; decide the default | ~200 ms per eligible create | Measure memory per waiting sandbox first |
| L5 | **Network namespace refill under bursts:** refill on claim, not only every 2 s; in-process netlink instead of two `ip` commands in `internal/network/netns/host.go` | 30–50 ms per create above ~2 creates/s per node | Fragile allocator: regression test |
| L6 | **Shrink `containerd_create`** (crun, shared shims) | 20–40 ms (estimate) | Measure with the containerd spike test first |

## 5. Cluster create throughput and routed requests

Design notes from the audit of `internal/cluster`:

- **E2. Do not hold the reservation lock during the Raft commit.**
  `Cluster.applyReservationEncodedLocal` holds `reservationAdmissionMu` for the
  whole commit, so reservations commit one at a time (estimated ~150 creates/s
  per cluster). Replace it with an in-memory ledger of in-flight holds, checked
  together with committed state under the same lock, released only after the
  commit's outcome is known, and reset on a new leader term together with an
  admission barrier on the new leader. Expected: ~1,000–3,000 reserves/s.
- **E1. Group commit comes mostly for free.** hashicorp/raft v1.7.3 already
  groups up to 64 concurrent `Apply` calls into one disk sync
  (`GROUP_COMMIT_LOOP` in its `leaderLoop`); creates never benefit only
  because of the lock above. A combined multi-reserve op is optional and needs
  C8 first.
- **E3a. Owner cache on worker and ingress nodes.** A routed request makes up
  to four control-plane lookups today (`PlacementOf` and `OwnerOf` in
  `pkg/api/clusterroute/forward.go`, on both hops). A bounded cache may choose
  where to forward but never produce a 404, a 410 or a local serve; the owner
  stays authoritative and answers "not here" (421 with a private header) so the
  edge drops the entry and retries once. Behind a flag.
- **E3b. Owner-side lease** to skip the owner's own lookup. Gated on C4.

Gates: E2 only after C1 (it changes how entries are admitted, and C1 makes
apply deterministic) and with the leader-change test of Section 3.1. E3b only
after C4.

Measure offline first: a benchmark over the in-process cluster with an
injected 6.5 ms log-store delay, at concurrency 1, 16 and 64, reporting
reserves per second and disk syncs per reserve; and a counter of control-plane
lookups per routed request.

## 6. PR order

| # | PR | Area |
|---|---|---|
| 1 | C1 deterministic FSM time | `internal/cluster` |
| 2 | C2 no resurrection | `internal/cluster`, `internal/service` |
| 3 | C8 batch validation | `internal/cluster` |
| 4 | L1 create-stage timing, plus the docs table | `internal/runtime/containerd`, `pkg/createtiming`, docs |
| 5 | L2 single-node containerd pool fix | `internal/config` |
| 6 | C3 lost delete during failover | `internal/service` |
| 7 | C5 rollback-pending | `pkg/api/clustercreate`, `internal/service` |
| 8 | C6 eviction owner fence | `internal/cluster` |
| 9 | Offline fault-test harness (Section 3.1) | `internal/cluster` |
| 10 | E2 admission ledger (+ benchmark) | `internal/cluster` |
| 11 | E3a owner cache | `internal/cluster`, `pkg/api/clusterroute` |
| 12 | C4 worker lease, stale-read refusal, feed age limit | `internal/cluster`, `internal/service`, ingress |
| 13 | C7 capacity lag | `internal/cluster` |
| 14+ | L3–L6, ownership epoch (C4 part 4), live fault scenarios | various |

The already-open PR #999 (store name index) is independent of all of these.

## 7. Live run plan (AWS)

**Order.** Offline first: every fix PR green on its own, then one local branch
that merges all of them (plus the chaos scenarios of PR #1008) passes the full
Go suite and the offline fault harness. The live runs then build from that one
branch (`run.sh` builds from the working tree), so every fix is tested
together. No fix PR merges until these runs pass.

**Wave 1** (in parallel, one VPC each):

| Run | Target | Machines | What it checks | Time (est.) | Cost (est.) |
|---|---|---|---|---|---|
| Chaos | `make integration-cluster-chaos` | 3 servers, 3 workers, 1 ingress; t3.medium on-demand | UC-470–479: partition, real kills, leader kill during creates, packet loss, rolling restart; C1–C7, I1–I8 | 1.5–2 h | $0.50–0.65 |
| Split roles | `make integration-cluster-hetero-lite` | same 7-node split, on-demand | Full suite with separate server, worker and ingress nodes: C4 lease, stale reads and feed age; C6; C2; routing | ~1.5 h | ~$0.45 |
| Mixed cluster | `make integration-cluster-mixed` | 3 × t3.medium spot | Full suite including UC-58b failover: C1, C3, C5 | ~1.5 h | ~$0.10 |

**Wave 2:**

| Run | Target | Machines | What it checks | Time (est.) | Cost (est.) |
|---|---|---|---|---|---|
| Create benchmark | `make integration-benchmark-containerd` | 3 × spot | L1: every create stage named; fills the 74–92 ms gap in 4.1 | ~1 h | ~$0.10 |
| Single-node pool | one hand-launched node: `install.sh` with no cluster, containerd, `SB_CONTAINERD_POOL_ENABLED=true`; a few creates | 1 × spot | L2: pool hits on a node that is not in cluster mode | ~20 min | ~$0.01 |
| Single node | `make integration-single` | 1 × spot | Nothing in the cluster fixes changes single-node mode | ~1 h | ~$0.03 |

Why L2 needs a hand-launched node: every Terraform-built node runs
`cluster-init`, even in the "single-node" scenarios, and cluster mode already
turns on the ready socket the pool needs. The bug only shows with cluster mode
off, so a harness scenario would pass on `main` too and prove nothing.

Total about $1.20–1.40 of EC2 (about $2 if spot is unavailable and everything
runs on-demand), plus small S3 and disk charges. Each rerun of a failed
scenario costs about the same as its first run.

**Rows of 3.2 not covered yet:**

- Kill a worker between runtime start and store write: needs a failpoint in
  the create path to hit that exact moment; not built.
- 1,000 concurrent creates during a leader kill: UC-473 uses 200, the most
  three t3.medium workers hold. 1,000 needs bigger workers.
- 72-hour churn soak: no long-running churn driver exists yet. On three spot
  t3.medium nodes it would cost about $3–4 of EC2 once built.

## 8. Open questions

1. After a returning node's post-delete record has expired (C2), what is the
   rule: quarantine the local row until the leader confirms, or destroy it?
2. Ownership lease length (C4) against `SB_DEAD_OWNER_GRACE`: half the grace
   is proposed; how short can the grace go before healthy nodes start losing
   sandboxes on a slow network?
3. Should the reconcile interval (5 minutes) shrink once the fences are in, so
   convergence time T is measured in seconds?
4. Warm containerd pool default: which images, how deep, and is the memory
   per waiting sandbox acceptable for the target density?
5. Comparison with Kubernetes: the same image, hardware, security settings and
   readiness definition on both, cold against cold and warm against warm.

## Sources

- Audit of `internal/cluster`, `internal/service`, `pkg/api` on `main`
  (2026-11-07), with C1 and C2 re-checked by hand.
- The Kubernetes v2 architecture plan in PR #522, Sections 9.3–9.4: limits
  L-a to L-i and fixes E1 to E8.
- `plans/warm-create-latency-tier1.md`: warm create 28 ms p50 shipped in v0.6.0.
- `plans/containerd-engine.md`, `plans/docker-warm-pool.md`,
  `setup/config-defaults.md`: warm pool decisions and gates.
