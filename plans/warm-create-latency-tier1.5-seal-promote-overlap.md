# Warm create latency Tier 1.5: seal+promote overlap (~10ms → ~18–20ms warm p50)

Status: **implemented** (2026-07-11). Successor to
`plans/warm-create-latency-tier1.md` §6. Tier 1 removes removable round-trips
**without** changing create/promote ordering. This plan overlaps
`PutClusterSecretsForRecipient` + `RecordPlacement` with the local
`CreateSandboxWithID` so the response path becomes
`max(create, seal+promote)` ≈ the create alone — the remaining ~10ms Raft
promote share drops off the critical path **while still joining before the
HTTP 201**.

**Acceptance target: warm p50 ≤ 20ms on the standard bench topology
(t3.medium + gp3), cluster mode, reserved-path creates**, measured under
burst *and* sparse traffic with Tier 1 Phases 1–4 landed
(`SB_NETRULES_BACKEND=netlink`, all-WAL voters preferred). Single-node /
`EnableCluster=false` is a no-op (Noop cluster never promotes).

Owner rules that apply: boot-path call-out (`/touch-create-sandbox`,
pr-review §2); **failure-path consistency** (pr-review §4) — the new
promote-OK/create-FAIL retraction is the load-bearing design; **cluster
correctness** (pr-review §7 / CLAUDE §6) — owner-watcher + reconcile
analysis mandatory in the PR description.

## 1. Problem: sequential promote still owns ~10ms after Tier 1

Post–Tier 1 anatomy on a warm hit (image-cache warm, netlink, transport
pooled), reserved-path create on a follower worker:

| Component | Expected after Tier 1 | Notes |
|---|---|---|
| `docker_pool` (rename + netrules + readyproto) | ≤ 15ms | Phase 1 |
| Seal (`PutClusterSecretsForRecipient`) | ~2–3ms of residual glue | SQLite AEAD write; no container needed |
| Raft promote (`RecordPlacement`) | ~3–5ms all-WAL / ~10ms mid-rollout | Inside `create;dur` today |
| Service glue (admit already done at reserve) | ~2–3ms | |
| **Sequential total** | **~25–30ms** | Tier 1 acceptance |
| **Overlapped total** | **~max(create, seal+promote) ≈ 15–20ms** | This plan |

The response path in `createSandboxOnSelectedNode`
(`pkg/api/v1/cluster_handler.go` ~349–403) is strictly sequential:

```
CreateSandboxWithID  →  PutClusterSecretsForRecipient  →  RecordPlacement  →  201
```

On the **reserved path** every promote input is known **before** create
starts: sandbox ID was minted on the router before `opReserve`
(`cluster_handler.go` ~259), redacted spec + `SelfNodeID()` likewise. Seal
does not need a container (`cluster_secrets.go` — SQLite write only).

**Client-visible contract Tier 1.5 preserves (unlike Tier 3 async promote):**
join **both** legs before responding. On 201 the FSM already knows the
owner. On error the cluster view is retracted before the error response —
no “respond now, clean up later.”

## 2. Design: overlap + join + synchronous retract

### 2.1 Happy path (reserved path only)

```
createCtx, createTiming := docker.WithCreateTiming(r.Context())
commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
defer cancel()

createCh  := make(chan createResult, 1)
promoteCh := make(chan promoteResult, 1)

go func() {
  resp, err := Service.CreateSandboxWithID(createCtx, req, reservationID)
  createCh <- createResult{resp, err}
}()

go func() {
  secrets, err := Service.PutClusterSecretsForRecipient(
    commitCtx, reservationID, req, c.SelfNodeID())
  if err != nil { promoteCh <- promoteResult{err: err}; return }
  redacted := service.RedactClusterSecrets(req)
  err = c.RecordPlacement(commitCtx, reservationID, &redacted, secrets)
  promoteCh <- promoteResult{secrets: secrets, err: err}
}()

cr := <-createCh
pr := <-promoteCh
// join + apply failure matrix (§3) before WriteJSON / WriteError
setCreateServerTiming(...)  // wall clock now ≈ max(legs)
```

**Scope gate:** only when `reservationID != ""`. The self-wins /
`CreateSandbox` (no ID) path keeps today’s sequential order — rarer, and
the ID isn’t fixed before create on that branch the same way.

**Mirror:** `pkg/api/clustercreate/clustercreate.go` `CreateOnSelectedNode`
must get the same overlap + retract (Daytona/E2B facades). Prefer extracting
one shared helper so the two paths cannot drift.

### 2.2 Why CancelReservation is NOT the retract tool

| FSM op | Effective on | Role |
|---|---|---|
| `CancelReservation` (`opCancelReserve`) | **Reserved only** | Inverse of reserve; no-op on Placed (documented) |
| `DeletePlacement` (`opDelete`) | Placed **or** Reserved | Removes the row; frees name |

After a successful `RecordPlacement` the row is **Placed**. Calling
`CancelReservation` is a silent no-op — the ghost ownership would stick until
`reconcileMissingSelfOwnedPlacements` (~5 min default). Tier 1.5 retract
**must** use `DeletePlacement` (+ secret cleanup).

`clustercreate.rollbackCreate` already calls `DeletePlacementBestEffort`;
`cluster_handler.go`'s promote-fail rollback today does only Destroy+Cancel.
That is **not** merely a uniformity gap — see "ambiguous promote errors"
below: an errored promote may still have committed, so `DeletePlacement` is
**mandatory on every promote-fail path**, overlapped or not. Today's handler
carries this as a latent bug (ghost Placed row for a destroyed sandbox until
the ~5 min reconcile) — worth fixing independently of Tier 1.5; tracked in
`TODOS.md`.

**Ambiguous promote errors — the commit may have landed.** A
`RecordPlacement` error caused by context timeout/cancel does not prove the
command did not commit: a Raft apply can fail client-side and still be
applied by the FSM. Treat every promote error as "possibly Placed":

- Retract with `DeletePlacement` (idempotent; effective on Placed **or**
  Reserved), never `CancelReservation` alone.
- **Never use cancellation of the promote leg as cleanup.** Cancelling
  `commitCtx` after a create failure does not guarantee the placement
  didn't — or won't — commit. Always **join** the promote channel, then
  retract deterministically.

### 2.3 Server-Timing attribution

Add explicit stages so the overlap win is measurable:

- `cluster_seal;dur=` — seal leg
- `cluster_promote;dur=` — Raft place leg
- `create;dur=` — wall clock of the handler (already ≈ overlapped total)

Optional prerequisite slice (plan §6): attribute residual glue finer first
if seal alone is the interesting subset (Phase A below).

## 3. Failure matrix (the load-bearing design)

Join both channels, then classify. **Never return 201 unless both legs OK.**
**Never return an error until retract of any committed side effects has been
attempted** (best-effort with loud logs if retract itself fails).

**Classification happens only after BOTH channels are received** — there is
no "in flight" state at decision time. If create fails and the promote later
succeeds, that is the promote-OK row below, not a promote-pending one.
Early-exiting on create failure without joining the promote channel leaves
an unretracted commit racing the error response.

| Create | Seal | Promote | Action before error/201 |
|---|---|---|---|
| OK | OK | OK | **201** — today’s success |
| FAIL | OK | FAIL | `DeletePlacementBestEffort` (**the errored promote may have committed**, §2.2) + `CancelReservation` + `DeleteClusterSecrets`; if create partially persisted → `DestroySandbox` best-effort |
| FAIL | OK | OK (**Placed**) | **NEW:** `DeletePlacement` + `DeleteClusterSecrets` + `DestroySandbox` best-effort. **Do not** rely on `CancelReservation`. |
| OK | FAIL | — | Today’s seal-fail path: `DestroySandbox` + `CancelReservation` (+ `DeleteClusterSecrets` via Destroy or explicit) |
| OK | OK | FAIL | `DestroySandbox` + `DeletePlacement` (**mandatory**, not uniformity — the errored promote may have committed, §2.2) + `CancelReservation` (covers the still-Reserved case) |
| FAIL | FAIL | — | Cancel reservation + best-effort secret delete |

### Retraction rule (promote-OK / create-FAIL) — Option A, mandatory

On a fresh background context (request ctx may be cancelled), timeout 5–30s:

1. **`DeletePlacement(sandboxID)`** — retracts Placed; frees cluster-wide name.
   Idempotent if already gone.
2. **`DeleteClusterSecrets(sandboxID)`** — seal can succeed with no store row;
   Destroy alone may never run.
3. **`DestroySandbox(sandboxID)`** best-effort — covers partial create (container
   and/or SQLite row) if create failed mid-flight after some persistence.
4. Log at Error if any step fails after retries; surface the **original create
   error** to the client (retract failure is operational, not a different API
   shape). Metrics: `aerolvm_cluster_promote_retract_total{result=...}`.

**Rejected alternatives:**

- **Lean on reconcile** (up to ~5 min ghost Placed) — violates pr-review §4.
- **Async retract + 503** — client may retry into name conflict / forward-to-owner
  404 during the window; breaks the sync-owner-before-201 contract.
- **Seal-only overlap (Phase A)** — valid *first slice* if full retract isn’t
  ready; not the full Tier 1.5 win.

**Failure-path cost (accepted, previously unstated):** overlapping means a
reserved-path create that *fails* now pays the promote commit **plus** the
`DeletePlacement` retract — ~2 Raft commits that today's sequential order
avoids (it never promotes after a failed create). Bounded and
failure-path-only, but a failure storm (a hot retry loop on a broken image)
adds leader log write load. No mitigation needed at current scale; if it
shows up, gate the overlap off per-request after repeated failures. Called
out so §8's bench doesn't read failure-path Raft traffic as a regression.

## 4. Owner-watcher & reconcile analysis (cluster-correctness)

| Mechanism | Interval | Touches default warm Docker creates? | Tier 1.5 implication |
|---|---|---|---|
| Owner watcher | 5s | **Only** `failover.policy=recreate` | Default warm path **not** auto-recreated on Placed-missing. Ghost Placed does **not** trigger recreate storms for default sandboxes. |
| `reconcileMissingSelfOwnedPlacements` | `SB_RECONCILE_INTERVAL` default **5 min** | Yes — deletes self-owned Placed with no local row | Safety net only; **must not** be the primary retract. Sync Option A keeps the ghost window to the retract RTT (~10ms). |

**Transient window under Option A:** from promote commit → retract commit.
During it: FSM says owner=self, local GET/exec 404, name held. Duration ≈ one
Raft round-trip on the failure path only. Acceptable if retract is
synchronous before the error response.

**Failover-opt-in sandboxes:** if a create with `failover.policy=recreate`
hits promote-OK/create-FAIL and retract is slow/fails, the owner watcher
**may** attempt `RecreateSandbox` within ~5s. Retraction must still be sync;
add a test that retract completes before a watcher tick can observe the
ghost (or that recreate is harmless / idempotent against a racing retract).

**Leader change mid-retract:** `DeletePlacement` must remain safe under
retry (idempotent delete). Document in PR: split-brain risk is low because
we never return 201 for the failed create; the only risk is a stuck Placed
row if retract itself fails — loud metric + reconcile backstop.

## 5. Idempotency

- Client retries after promote-OK/create-FAIL + successful retract: name is
  free again; new reserve can proceed.
- Client retries while retract in flight / stuck Placed: reserve may see
  `ErrNameConflict` — same as any lingering placement; not a new class.
- `CreateSandboxWithID` remains idempotent if a local row already exists
  (partial create) — retract’s `DestroySandbox` clears that before the
  error returns when possible.
- Concurrent duplicate creates: still gated by reservation-first + name
  claim at reserve; overlap does not widen that race.

## 6. Phased delivery

| Phase | Scope | Risk | Expected win |
|---|---|---|---|
| **A — seal-only overlap** | `PutClusterSecretsForRecipient` ∥ create; promote stays after create | Low — failure matrix unchanged for Placed | ~2–3ms if seal is that share of glue |
| **B — full seal+promote overlap** | §2 + §3 Option A retract | Medium — new Placed-without-container class | ~8–10ms (Raft off critical path) |
| **C — unify handler + clustercreate** | Shared overlap/retract helper | Refactor | Drift prevention |

Recommended: land A with finer Server-Timing first (cheap proof of glue
attribution), then B with the full test matrix. A alone is optional if B is
ready in one PR.

## 7. Tests (mandatory, next to the handler)

All in `pkg/api/v1/cluster_create_coverage_test.go` and
`pkg/api/clustercreate/clustercreate_test.go` (or shared helper tests):

1. **[REGRESSION] promote-OK / create-FAIL → `DeletePlacement` called** (not
   merely `CancelReservation`); FSM row gone; secrets deleted.
2. promote-FAIL / create-OK → destroy + **`DeletePlacement` (mandatory,
   §2.2)** + cancel. Include the injected **errored-but-committed** case:
   the fake cluster returns an error from `RecordPlacement` yet applies the
   command anyway — assert the Placed row is removed before the error
   response.
3. seal-FAIL / create-OK → destroy + cancel + no Placed row.
4. both OK → 201; timing wall clock ≤ max(create, promote)+ε under a fake
   clock / injectable delays.
5. both FAIL → cancel + no leaked Placed / secrets.
6. retract `DeletePlacement` error → Error log + metric; client still gets
   create error (not 201).
7. Facade path (`clustercreate`) same promote-OK/create-FAIL matrix.
8. Single-node / Noop: overlap branch not taken or promote no-op — no panic.

Optional integration: reserved-path warm create under cluster-3-mixed-docker
with injected create failure after artificial promote delay — assert no
lingering placement via cluster members API.

## 8. Expected results

| Configuration | warm p50 (cluster reserved) | Gate |
|---|---|---|
| Tier 1 only (Phases 1–4) | ≤ 30ms | Tier 1 acceptance |
| Tier 1.5 Phase A (seal overlap) | ~27–28ms | optional |
| Tier 1.5 Phase B (full overlap) | **≤ 20ms** | **this plan’s acceptance** |
| Tier 1.5 + NVMe | ~15–18ms | not gated here |

Verification: `make integration-benchmark-docker-only` + sparse, with Tier 1
netlink default or explicit `SB_NETRULES_BACKEND=netlink`. Server-Timing:
`cluster_promote` duration may still be ~3–10ms but must **overlap**
`docker_pool` on the wall clock (`create;dur` ≈ docker_pool, not sum).

## 9. Open questions

1. Should Phase A ship as its own PR before B, or one PR with both behind a
   `SB_CLUSTER_CREATE_OVERLAP=seal|full|off` flag (default `off` until soak)?
2. Unify `cluster_handler` and `clustercreate` retract helpers in the same
   PR as B, or a pure refactor PR first?
3. Failover-opt-in sandboxes: assert retract-before-watcher, or temporarily
   skip overlap when `Failover.ShouldRecreate()`?

## NOT in scope

- **Tier 3 async promote / async rename** — stops waiting; changes recovery
  semantics. Separate entry gate.
- **NVMe/io2** — `plans/nvme-datadir.md` / `TODOS.md`.
- **Moving reserve off the router** — reservation-first stays; overlap is
  worker-local only.
- **Changing owner-watcher recreate policy** for default sandboxes.

## Failure modes (new/changed)

| Codepath | Prod failure | Test? | Handling | User sees? |
|---|---|---|---|---|
| Promote commits, create fails, retract OK | Transient Placed-missing for ~RTT | **[REGRESSION] yes** | Sync DeletePlacement + secrets + Destroy | Create error; no 201 |
| Promote commits, create fails, DeletePlacement fails | Ghost Placed until reconcile (~5 min) | yes (retract error case) | Error log + metric; reconcile backstop | Create error; name may conflict on retry |
| Promote **errors but command committed** (timeout/cancel) | Retract via `CancelReservation` alone no-ops on Placed → ghost row for a destroyed sandbox | yes (§7.2 errored-but-committed) | `DeletePlacement` mandatory on every promote-fail path | Create error; no ghost |
| Seal orphans secrets, create fails, no Destroy | Secret blob leak | yes | Explicit DeleteClusterSecrets | Create error |
| Overlap on Noop / no reservation | Panic / double-create | yes | Gate on reservationID + cluster enabled | n/a |
| Facade path drifts from handler | Facades leak Placed | yes (both packages) | Shared helper | Facade-only ghosts |

## Implementation tasks

- [x] **T1** — Document + agree Option A retract; decide Phase A vs B vs flag
  (shipped Phase B without flag — reserved path always overlaps)
- [x] **T2** — Extract shared `OverlapCreateAndPromote` + `retractAfterOverlap`
  used by `cluster_handler` and `clustercreate`
- [x] **T3 (optional Phase A)** — Skipped; Phase B landed in one change
- [x] **T4 (Phase B)** — Full overlap; join; Option A retract; Server-Timing
  `cluster_seal` / `cluster_promote`
- [x] **T5** — Failure-matrix unit tests (§7) in both packages
- [ ] **T6** — PR description: boot-path latency (overlap win + failure-path
  Raft), failure-path consistency (Option A), cluster-correctness
  (owner-watcher / reconcile / leader-change)
- [ ] **T7** — Bench gate ≤ 20ms warm p50 on standard topology

## Relation to Tier 1

| | Tier 1 | Tier 1.5 |
|---|---|---|
| Semantics of success | Unchanged | Unchanged (join before 201) |
| Failure matrix | Unchanged | **Widens** — needs retract |
| Latency win | Removable RTT / fsync / cache | Overlap promote with create |
| Config revert | Phases 1/2/4 yes; 3 no | Flag-gated recommended until soak |

(`plans/warm-create-latency-tier1.md` §6 points here.)
