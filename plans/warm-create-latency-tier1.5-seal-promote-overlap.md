# Warm create latency Tier 1.5: seal overlap (revised — promote stays sequential)

Status: **implemented — revised 2026-07-11 after PR #306 review.** Successor
to `plans/warm-create-latency-tier1.md` §6. The original design overlapped
`PutClusterSecretsForRecipient` **and** `RecordPlacement` with the local
`CreateSandboxWithID`. Review found that promoting before the local create
finishes breaks three FSM couplings (§0); the shipped design overlaps **only
the seal** and promotes sequentially after both legs join. The ≤20ms
full-overlap acceptance target is **withdrawn**; the safe win is the seal
share (~2–3ms) on top of Tier 1's ≤30ms gate.

**Acceptance: warm p50 ≤ 30ms preserved (Tier 1 gate), `cluster_seal` no
longer serial on the wall clock; stretch ~27–28ms.** Single-node /
`EnableCluster=false` is a no-op (nil cluster falls back to plain
`CreateSandboxWithID`).

Owner rules that apply: boot-path call-out (`/touch-create-sandbox`,
pr-review §2); **failure-path consistency** (pr-review §4); **cluster
correctness** (pr-review §7 / CLAUDE §6) — owner-watcher + reconcile +
backpressure analysis mandatory in the PR description.

## 0. Why promote overlap was withdrawn (post-review, load-bearing)

`opPlace` is not just "record the owner" — it releases FSM accounting that
three mechanisms depend on while a local create is still running:

1. **Per-worker create backpressure.** `opPlace` calls
   `releasePendingReservationLocked` (fsm.go), and
   `admitReservationCommands` (placement.go) enforces
   `ClusterCreateMaxPendingPerWorker` against that pending count. Promoting
   at reserve+~5ms instead of create-done means a slow/cold create stops
   counting toward the cap almost immediately — under burst, the per-worker
   create-storm protection is bypassed.
2. **Placement double-booking guard.** `SelectPlacement` subtracts pending
   reservations from each peer's headroom precisely because the gossip
   capacity ledger lags ("two creates that arrive between gossip ticks both
   pick the same best node"). An early-promoted sandbox consumes *neither*
   pending nor heartbeat capacity until the create finishes and the next
   heartbeat fires — the double-booking window the reservation system exists
   to close reopens.
3. **Owner-watcher visibility.** Reserved rows are not in the FSM owner
   index; Placed rows are. The owner watcher (5s tick) recreates any
   owned, failover-enabled placement "not present locally" — an
   early-promoted row whose local create takes >5s (cold image pull) is
   exactly that, and the watcher would start a **concurrent duplicate
   create** of the same sandbox ID. Routing also observes Placed while the
   local store still 404s.

A durable `Creating` placement state (charged to pending until an explicit
confirm) would fix all three while keeping the overlap, but the confirm is a
second Raft commit that lands back on the critical path unless it is async —
which is Tier 3's semantics change, not this plan's. **Rule: the FSM row
stays Reserved until the local create has succeeded.**

## 1. Problem and the remaining safe win

Post–Tier 1 anatomy on a warm hit, reserved-path create on a worker:

| Component | Expected after Tier 1 | Notes |
|---|---|---|
| `docker_pool` (rename + netrules + readyproto) | ≤ 15ms | Tier 1 Phase 1 |
| Seal (`PutClusterSecretsForRecipient`) | ~2–3ms | SQLite AEAD write; no container needed — **overlappable** |
| Raft promote (`RecordPlacement`) | ~3–5ms all-WAL | **Must stay after create** (§0) |
| Service glue | ~2–3ms | |
| **Sequential total** | **~25–30ms** | Tier 1 acceptance |
| **Seal-overlapped total** | **~23–27ms** | This plan |

On the **reserved path** every seal input is known before create starts:
sandbox ID minted on the router before `opReserve` (`cluster_handler.go`
~260), redacted spec + `SelfNodeID()` likewise.

**Client-visible contract preserved:** join **both** legs, then promote,
then 201. On 201 the FSM knows the owner. On error the cluster view is
retracted before the error response.

## 2. Design: create ∥ seal → join → promote → 201

Shipped as `clustercreate.OverlapCreateAndPromote`, used by both
`pkg/api/v1/cluster_handler.go` and `clustercreate.CreateOnSelectedNode`
(Daytona/E2B facades) so the paths cannot drift.

```
createCh ← go CreateSandboxWithID(ctx, req, reservationID)      // leg 1
sealCh   ← go PutClusterSecretsForRecipient(commitCtx, ...)     // leg 2
cr := <-createCh ; sr := <-sealCh                               // join
if either failed → retractReservedCreate (§3) → error
RecordPlacement(commitCtx, reservationID, redacted?, sr.secrets) // sequential
if promote failed → retractFailedPromote (§3) → error
201
```

- **Scope gate:** only when `reservationID != ""`. Self-wins /
  `CreateSandbox` (no ID) stays sequential.
- Both legs run in bare goroutines → each carries a `recover()` that
  converts a panic into a leg failure (net/http's per-request recover does
  not extend to handler-spawned goroutines; an unrecovered panic is a daemon
  crash). Promote runs on the request goroutine and needs no extra recover.
- Server-Timing: `create_with_id`, `cluster_seal` (overlapped),
  `cluster_promote` (serial).

### 2.2 Ambiguous promote errors — the commit may have landed

Unchanged from the original plan and still load-bearing for the sequential
promote: a `RecordPlacement` error caused by timeout/cancel does not prove
the command did not commit. Treat every promote error as "possibly Placed":

- Retract with `DeletePlacement` (`opDelete` — effective on Placed **or**
  Reserved, releases the pending reservation, idempotent). Never
  `CancelReservation` alone: `opCancelReserve` is a documented no-op on
  Placed, and the ghost row would stick until reconcile (~5 min).
- **Never use cancellation of the promote as cleanup.** Always classify the
  error, then retract deterministically.

This also fixed the pre-existing latent bug in the sequential self-wins
handler (Destroy+Cancel only → ghost Placed) — see `TODOS.md`.

## 3. Failure paths (two retract shapes, both ordered destroy-first)

**Retract ordering is destroy-first on purpose:** `ReplayClusterOwnership`
(boot + periodic reconcile) re-asserts a placement for any live local
sandbox that has none. Deleting the placement/reservation while a failed
destroy leaves the local sandbox alive would let the reconciler resurrect a
create the client was told failed. Destroy first; if destroy fails, the
retract metric says so loudly.

**`retractReservedCreate`** — create- or seal-leg failure. Promote was never
attempted, the row is still Reserved, no ambiguity exists:

1. `DestroySandbox` best-effort (quiet not-found when the create leg already
   rolled itself back; loud `destroy_failed` when create succeeded).
2. `CancelReservation` — the correct, idempotent release for Reserved.
3. `DeleteClusterSecrets`.

**`retractFailedPromote`** — promote errored after create+seal OK
(possibly committed, §2.2):

1. `DestroySandbox` (loud on failure).
2. `DeletePlacement` — mandatory; covers Placed and still-Reserved, so no
   separate cancel.
3. `DeleteClusterSecrets`.

Both run on a fresh background context (30s) and record
`aerolvm_cluster_promote_retract_total{result}` where result reflects the
first failing step (`destroy_failed`, `cancel_failed`,
`delete_placement_failed`, `delete_secrets_failed`, else `ok`). The client
always gets the **original** leg error.

| Create | Seal | Promote | Action |
|---|---|---|---|
| OK | OK | OK | 201 |
| FAIL | OK/FAIL | not attempted | `retractReservedCreate`; surface create error (create precedence when both legs fail) |
| OK | FAIL | not attempted | `retractReservedCreate`; surface seal error (500, `cluster: store secret ref: …`) |
| OK | OK | FAIL | `retractFailedPromote`; surface promote error (409 on name conflict / 503) |

**Failure-path cost:** a failed create no longer pays a promote commit (the
original overlap did — promote fired regardless). Failed reserved creates
cost one `opCancelReserve`; failed promotes cost one `opDelete`. Cheaper
than both the original overlap design and equal to today's sequential code.

## 4. Owner-watcher, reconcile & backpressure analysis

| Mechanism | Interval | Interaction with this design |
|---|---|---|
| Pending-reservation accounting | per opReserve/opPlace | **Preserved exactly**: row is Reserved for the full local create; `ClusterCreateMaxPendingPerWorker` and `SelectPlacement` headroom subtraction see every in-flight create. |
| Owner watcher | 5s, failover-recreate specs only | Never sees the row mid-create (Reserved rows are not in the owner index). No duplicate-create race, regardless of create duration. |
| `reconcileMissingSelfOwnedPlacements` | ~5 min | Backstop only for a failed `retractFailedPromote` (stuck Placed). |
| `ReplayClusterOwnership` | boot + periodic | Retract destroys local state **first** so replay cannot re-assert a placement for a sandbox the client saw fail. Residual exposure: destroy itself fails (metric `destroy_failed`) — same exposure as the pre-Tier-1.5 sequential rollback. |
| Reservation TTL GC (`reconcileReservations`) | periodic | Reaps a Reserved row if the node dies mid-create or a cancel is lost — unchanged. |

**Node death mid-create:** the row is Reserved → TTL GC reaps it; the
sandbox does not fail over into existence. (Under the withdrawn early
promote, a failover-enabled sandbox whose owner died mid-create would have
been recreated elsewhere from a create the client never saw succeed.)

## 5. Idempotency

- Reservation IDs are server-minted per request (`GenerateSandboxID`,
  cluster_handler.go ~260) — a client retry is a new ID; concurrent retract
  races on the same ID cannot arise from client behavior.
- Client retries after retract: name freed (cancel/delete both release it);
  new reserve proceeds. Retry during a stuck retract sees
  `ErrNameConflict` — same as any lingering placement, not a new class.
- Concurrent duplicate creates: still gated by reservation-first + name
  claim at reserve; the overlap does not widen that race.

## 6. Tests (shipped)

`pkg/api/clustercreate/clustercreate_test.go`:

1. **[REGRESSION] `TestOverlapCreateAndPromote_PromoteWaitsForCreate`** —
   `RecordPlacement` must not fire until the create leg completed (hook
   asserts `createFinished`); guards the §0 backpressure invariant.
2. Create-FAIL → no promote call, `CancelReservation` (not DeletePlacement),
   store row gone.
3. Seal-FAIL (panic-injected via `SelfNodeID`) → seal phase surfaced, no
   promote, reserved retract.
4. Both legs fail → create-phase precedence.
5. Promote-FAIL after create-OK → `DeletePlacement` mandatory (errored-but-
   committed §2.2), no cancel, store row gone.
6. Retract error branches for both shapes (closed store + cluster errors);
   original error still surfaced.
7. Create-leg panic → leg failure + retract, not a daemon crash.
8. Guards: empty reservation ID, nil service, nil cluster sequential
   fallback.

`pkg/api/v1/cluster_create_coverage_test.go`: the same matrix through the
HTTP handler (status mapping 400/500/503/409) plus
`OverlapWallClockNearMax` (wall clock ≈ create, not create+seal).

## 7. Expected results — MEASURED 2026-07-11 (live 3× t3.medium, netlink, all-WAL)

| Configuration | warm p50 (cluster reserved) | Gate |
|---|---|---|
| Released baseline (v-latest) | 45ms burst (p90 362ms) | — |
| Branch: Tier 1 + 1.5 seal overlap | **40–44ms burst / 42ms sparse (p90 44ms)** | ≤30ms **NOT met** |
| Full overlap (withdrawn) | ~18–20ms | requires a durable Creating state — Tier 3 candidate |

Measured stages: `create_with_id` 17ms, `cluster_seal` **0ms (fully
overlapped — this plan's mechanism works)**, `cluster_promote` **23–25ms**.
The promote is NOT the ~3–5ms Raft commit this plan assumed: it is dominated
by the synchronous recovery-blob replication to every member inside
`applyCommand` (`recovery_replication.go`) — identical on BoltDB and
raft-wal. The ≤30ms gate is blocked on that, not on anything this plan
changed; see `TODOS.md` ("cluster_promote is recovery-replication-bound").
Sparse run also proved Phase 2: zero `docker_image` resolves across 8
samples at 15s gaps.

## NOT in scope

- **Full seal+promote overlap** — withdrawn (§0); revisit only with a
  durable `Creating` FSM state or Tier 3 async semantics.
- **Tier 3 async promote / async rename** — separate entry gate.
- **NVMe/io2** — `plans/nvme-datadir.md` / `TODOS.md`.
- **Moving reserve off the router**; **owner-watcher policy changes**.

## Implementation tasks

- [x] **T1** — Shared `OverlapCreateAndPromote` used by `cluster_handler`
  and `clustercreate` (seal-only overlap; sequential promote)
- [x] **T2** — Two-shape retract (`retractReservedCreate` /
  `retractFailedPromote`), destroy-first ordering, retract metric covers
  destroy/cancel failures
- [x] **T3** — Failure-matrix unit tests in both packages, incl. the
  promote-waits-for-create regression
- [x] **T4** — Sequential self-wins promote-fail rollback fixed to
  `DeletePlacement` (latent ghost-Placed bug)
- [x] **T5** — PR description call-outs: boot-path latency, failure-path
  consistency, cluster correctness (§0 analysis)
- [x] **T6** — Bench run 2026-07-11: `cluster_seal` confirmed off the wall
  clock (0ms); ≤ 30ms NOT held — blocked on promote recovery replication
  (§7, TODOS.md), not on this plan's mechanism

## Relation to Tier 1

| | Tier 1 | Tier 1.5 (revised) |
|---|---|---|
| Semantics of success | Unchanged | Unchanged (join + promote before 201) |
| FSM ordering | Reserved until create done | **Unchanged — deliberately** (§0) |
| Failure matrix | Unchanged | Two retract shapes; destroy-first |
| Latency win | Removable RTT / fsync / cache | Seal off the critical path (~2–3ms) |

(`plans/warm-create-latency-tier1.md` §6 points here.)
