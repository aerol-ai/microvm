# Firecracker snapshot-clone create latency: 3.45s → sub-700ms

Status: **In progress** (updated 2026-07-04). Phases 0 (code), 1, 2, 3a, 3b
and the 3c static cap are code-complete on
`feat/firecracker-create-latency-phase1`; the E1 experiment, the UC-98
integration scenarios, and every benchmark gate below are still open — no
latency number in this document has been re-measured yet.

Owner rules that apply: this plan changes `CreateSandbox` callees
(`/touch-create-sandbox`), the TAP allocator and warm-VMM pool (fragile areas —
regression tests mandatory next to the file), and needs boot-path latency
call-outs in every PR description per `pr-review.md` §2.

## Implementation status (2026-07-04)

| Phase | State | Notes |
|---|---|---|
| 0 — instrumentation | code done, **E1 + bench run open** | Recorder moved to `pkg/createtiming` (docker keeps aliases); `fc_*` stages recorded in `Driver.Create` (cold, snapshot-load, warm) and surfaced via `setCreateServerTiming`; harness parses all `<name>;dur=` pairs into `latency[].stages` (mean/p50). The warm-hit marker (`fc_warm;dur=…;desc=hit`) landed here too. E1 and the stage-sum exit criterion still need an operator bench run. See deviations below. |
| 1 — verify-once cache + async probe | done | `snapshot_verify_cache.go`, `toolbox_probe.go` + full test table incl. `TestVerifyCache_WarmSpawnShares`. |
| 2 — poll-cadence trims | done | `retry.go`; WaitSocket 2→20ms, vsock 5→50ms, backoff-sequence test. |
| 3a — TAP `Transfer` | done | Atomic single-`UPDATE` re-key in `store.go`; idempotent-retry + concurrent-duplicate regression tests in `tap/pool_test.go`. |
| 3b — warm pool v1.15 redesign | done | WarmSpawn owns TAP + `network_overrides` at load; Acquire transfers ownership, zero `PatchNetworkInterface`. Pool still **off by default** (ship-dark, per this plan). |
| 3c — sizing guards | partial | Boot-time depth cap `min(configured, tap_pool_size/8)` in `pkg/daemon`. The dynamic refill guard (refuse when free TAP slots < 2× pool size) is NOT implemented. |
| UC-98/98b/98c/98d | not started | Require Phase 0's warm-hit marker + a cluster-hetero run. |

**Deviation from the 3a design (call out in the PR):** rollback after a
failed warm acquire *releases* the transferred TAP row (via
`warmHandle.Shutdown`) instead of transferring it back to the slot id.
Simpler and leak-free — Destroy/rollback double-release is idempotent —
but a failed warm create burns the parked slot's TAP + VMM instead of
returning them to the pool; the refill loop replaces the slot on its
next tick. `TestTransfer_RollbackShape` is therefore superseded by
`TestCreate_WarmRollbackOnTapTransferFailure` +
`TestAcquire_ConcurrentDuplicateCreate`.

**Deviations from the Phase 0 design (call out in the PR):**

- `fc_tcp_probe` is **not** recorded: Phase 1 moved the TCP probe off the
  create path onto a detached goroutine, so there is no boot-path duration
  to attribute — the header would always report a meaningless ~0ms.
- Three stages were added beyond the planned list so the per-stage p50s can
  actually sum to the `create` total (the Phase 0 exit criterion):
  `fc_rootfs` (template stage / OCI build), `fc_tap_ensure` (host `ip`
  realization), and `fc_configure` (cold-boot REST config, the counterpart
  of the snapshot path's `fc_load`).
- The warm-hit marker (`fc_warm;dur=…;desc=hit`) shipped with Phase 0
  instead of waiting for UC-98; the warm path also records
  `fc_resume`/`fc_handshake`/`fc_post_resume` so warm hits are attributable
  without a separate stage set.
- `fc_driver` is recorded on failed creates too (the handler already sets
  Server-Timing on error responses), so slow failures are visible.

---

## Problem

The `cluster-hetero` benchmark (UC-94, run 2026-07-01, artifact
`integration-tests/reports/cluster-hetero-bench.json`) measured firecracker
snapshot-clone creates at:

| metric | docker | firecracker |
|---|---|---|
| api p50 (client round-trip) | 1047ms | 4224ms |
| server p50 (Server-Timing) | 291ms | **3452ms** |
| server p90 / p99 | 2450 / 2690ms | 3460 / **3467ms** |

Two things stand out:

1. **The firecracker distribution is flat** — 15ms of spread between p50 and
   p99 across 10 samples. That is the signature of fixed, deterministic
   pipeline work (hashing a fixed-size file, fixed-cadence polls), not
   contention, cold caches, or network variance.
2. **Docker's 291ms server p50 bounds the shared scaffolding.** Both runtimes
   pay the same service-layer work (admission, SQLite row, caddy route upsert,
   Raft placement + cross-node forward). Everything above ~300ms is
   firecracker-driver cost.

The reference number everyone carries in their head — "a snapshot resume is
~125ms" — describes only `spawn + LoadSnapshot + Resume`. The shipped path
pays, per create, on top of that:

| # | Stage | Where | Estimated cost | Why it exists |
|---|---|---|---|---|
| A | SHA256 re-verify of the full snapshot | `configureVMMForLoad` → `verifySnapshotChecksum` (`internal/runtime/firecracker/snapshot.go`) | **~1.2–1.8s** | `SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD` defaults `true`; re-hashes the 512MiB `snapshot.memory` + `snapshot.state` on *every* clone. c5.metal (Cascade Lake) has no SHA-NI; Go sha256 ≈ 300–500 MB/s single-threaded. |
| B | Cold VMM spawn | `Driver.Create` steps 2–7 | ~200–400ms | The warm-VMM pool (the designed fast path) is **disabled**: Firecracker v1.15 moved TAP rebinding to `LoadSnapshot.network_overrides`; the pool still PATCHes `host_dev_name` post-load, which v1.15 forbids (`warmspawn.go` header). Every create pays jailer spawn + `WaitSocket` (20ms poll) + LoadSnapshot + 2× PatchDrive + Resume. |
| C | Guest-readiness gating | `Driver.Create` steps 8–8b | ~400–800ms | Sequential: vsock handshake (50ms retry cadence) → `post_resume` op (guest RNG reseed + wallclock + eth0 reconfig; bounded 2s) → `probeToolboxTCP` (100ms cadence, 200ms dial timeouts, bounded 2s). The TCP probe is **log-only** — it never affects the create result — yet blocks the HTTP response. |
| D | Service + cluster scaffolding | `createFirecrackerSandbox` + forward | ~300ms | Bounded by docker's 291ms server p50 through the identical path. |
| — | Client ↔ AWS network | outside the server | ~600–800ms | api − server gap (4224 − 3452 = 772ms p50). Bench client ran from a residential connection. Not a server cost; fixed by benchmark methodology, not code. |

A + B + C + D ≈ the observed 3.45s. Stage costs are estimates attributed from
file sizes, hash throughput, and the docker baseline — **Phase 0 exists to
replace the estimates with measured numbers before we commit to Phase 1/3
targets.**

---

## Targets (grounded, per phase)

All server-side p50, measured by UC-94 on `cluster-hetero` (c5.metal FC
worker, 512MiB template memory, default image), benchmark client **inside the
VPC** (see Methodology below). "Committed" is the number the phase's PR must
demonstrate before merge; "stretch" is what the analysis says is likely.

| Milestone | Committed | Stretch | What changes |
|---|---|---|---|
| Baseline (measured 2026-07-01) | — | — | server p50 **3452ms** |
| Phase 0: instrumentation | no latency change | — | per-stage Server-Timing + bench artifact breakdown; validation experiment E1 |
| Phase 1: verify-once cache + async TCP probe | **≤ 2000ms** | ≤ 1600ms | removes A (after first load) and C's probe tail |
| Phase 2: poll-cadence trims | **≤ 1900ms** | ≤ 1500ms | first-retry backoff on WaitSocket + vsock dial |
| Phase 3: warm-VMM pool redesign (v1.15) | **≤ 700ms** | ≤ 450ms | removes B entirely on warm hit; driver stage (`fc_driver` timing) ≤ 250ms committed / ≤ 150ms stretch |

Why the Phase 3 floor is ~450–700ms and not 125ms: the driver's warm-hit work
(patch drives + Resume + handshake + post_resume) is the only part the 125ms
folklore describes. On this cluster every create also pays scaffolding +
Raft placement + one forward hop ≈ 300ms (docker's measured floor). Getting
end-to-end server p50 to ~125ms would require attacking D (caddy upsert off
the critical path, placement fast-path) — explicitly **out of scope** here;
if Phase 3 lands at target, a follow-up plan can own D.

Density/regression guard: docker and gvisor numbers in the same bench run must
not regress by more than 10% p50 in any phase (the phases must not perturb the
shared path).

---

## Phase 0 — Measure before promising (1 small PR)

The single biggest analysis risk is stage attribution being wrong (e.g.
LoadSnapshot secretly copying the memory file, or the TCP probe being cheap).
Phase 0 makes every later target falsifiable.

### Work

1. **Per-stage create timing for firecracker.** Reuse the existing
   `docker.CreateTiming` context-recorder pattern (`pkg/docker/create_timing.go`,
   surfaced via `setCreateServerTiming` in `pkg/api/v1/handlers.go`). Add
   firecracker stages, recorded inside `Driver.Create`:
   `fc_tap_alloc`, `fc_verify`, `fc_spawn` (spawn→socket), `fc_load`
   (stage+LoadSnapshot+patches), `fc_resume`, `fc_handshake`, `fc_post_resume`,
   `fc_tcp_probe`, and a `fc_driver` total. The recorder type should move to a
   neutral package (or a new `pkg/createtiming`) rather than deepening the
   `docker` import — mechanical refactor, keep the docker fields intact.
2. **Bench artifact breakdown.** UC-94 already parses Server-Timing
   (`harness.Client.LastServerCreateMS`); extend it to record all
   `<name>;dur=` pairs and emit a per-stage mean/p50 block into
   `cluster-hetero-bench.json` under `latency[].stages`.
3. **Validation experiment E1** (operator-run, no code): rerun UC-94 with
   `SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD=false` on the FC worker. Expected:
   server p50 drops to ~1.5–2.2s. Confirms stage A's magnitude before Phase 1
   is built. If E1 shows < 800ms of savings, STOP and re-attribute (the flat
   p99 says *something* deterministic is burning >1s; find it in the Phase 0
   stage data).

### Tests

- `pkg/api/v1/handlers_test.go` (or existing timing test file): Server-Timing
  header includes fc stages when the recorder carries them; absent stages are
  omitted; docker fields unchanged.
- `internal/runtime/firecracker/driver_test.go` (table-driven, existing fake
  seams): a successful snapshot-load Create populates every stage with a
  non-negative duration; a cold-boot (no template) Create leaves `fc_verify`
  and `fc_load` zero.
- Bench harness unit test: `LastServerCreateMS`-style parser returns the full
  stage map for a synthetic header.

### Exit criteria

A cluster-hetero bench run produces per-stage p50s that sum to within 15% of
the `create` total. Targets in this doc are then re-baselined against the
measured stage table (edit this file; keep the history).

---

## Phase 1 — Verify-once checksum cache + async TCP probe (1 PR)

### Design: checksum cache

Templates are immutable once `status=ready`; re-hashing the same bytes per
clone is pure waste. Add a per-driver verified-set consulted by both
`configureVMMForLoad` (`driver.go`) and `WarmSpawn` (`warmspawn.go`):

- **Key:** template's persisted checksum string + file identity of both
  artifacts (`dev`, `inode`, `size`, `mtime` from `os.Stat`) captured at
  verification time. Any stat drift → treat as unverified.
- **Concurrency:** the repo's canonical single-flight latch —
  `sync.Mutex` + map entry with done-channel/`atomic.Bool` — mirroring
  `Service.EnsureLayer4Ready` (`internal/service/service.go` →
  `layer4_bootstrap_test.go`), so N concurrent creates of one template hash
  once and the other N−1 wait for the result (a failed verify must NOT be
  cached as verified; waiters get the error and the next caller retries).
- **Invalidation:** (a) stat mismatch on lookup; (b) the corrupt-notification
  path — when `MarkSnapshotCorrupt` fires (or the driver's `notifyCorrupt`
  seam), drop the template's entry; (c) daemon restart (cache is in-memory
  only — deliberately, so a corrupted-on-disk artifact is re-checked at least
  once per boot).
- **Config:** `SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD=false` keeps its exact
  current meaning (skip entirely). New
  `SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE=always` opt-out of the cache for
  paranoid operators (default `once`). Document both in `internal/config`.

Integrity honesty (for the PR description): the threat this check actually
catches is torn writes / partial registry pulls at artifact-creation time —
still caught, on first load. Silent in-place bit-rot between creates within
one daemon boot is no longer caught; it was the only coverage lost, and
`LoadSnapshot`/Resume failing remains the backstop. This trade must be stated
in the PR, not silently made.

### Design: async TCP probe

`probeToolboxTCP` (`driver.go`) is observational — it logs reachability and
returns nothing. Move both call sites (`Create` step 8b, `tryAcquireWarm`) to
a goroutine with `context.Background()`-derived timeout (the request ctx dies
when the handler returns), keeping `PostResumeTimeout` as the bound and the
existing log fields. Add the probe's outcome to the RSS of the *next* create
only via logs — no behavior change for callers.

`post_resume` itself stays synchronous: it reconfigures the guest's eth0 to
the clone IP; returning earlier would hand users a sandbox whose network isn't
up yet (immediate `exec` would fail — regression against UC-44).

### Tests (package must stay ≥ ~85%; run `/maintain-coverage`)

New file `internal/runtime/firecracker/snapshot_verify_cache_test.go`
(table-driven, matching `layer4_bootstrap_test.go` style). Needs a countable
hash seam — inject the hash function (mirror the existing `spawn`/`newClient`
seam pattern) so tests count invocations instead of timing them:

| Test | Asserts |
|---|---|
| `TestVerifyCache_SecondLoadSkipsHash` | two sequential snapshot-load Creates of one template → hash seam called exactly once |
| `TestVerifyCache_SingleFlight` | N concurrent Creates → exactly one hash; all N succeed |
| `TestVerifyCache_FailureNotCached` | first verify fails (corrupt) → second Create re-hashes (failed result not latched) |
| `TestVerifyCache_InvalidatesOnFileChange` | rewrite `snapshot.memory` (new mtime/size) → re-hash on next Create |
| `TestVerifyCache_CorruptNotificationInvalidates` | `notifyCorrupt` / MarkSnapshotCorrupt path drops the entry |
| `TestVerifyCache_ModeAlways` | `VERIFY_MODE=always` → hash on every Create |
| `TestVerifyCache_DisabledSkipsEntirely` | `VERIFY_ON_LOAD=false` → zero hash calls, zero cache entries |
| `TestVerifyCache_WarmSpawnShares` | WarmSpawn then Create (or vice versa) → one hash total |

Async probe, in `driver_test.go` / `warmacquire_test.go`:

| Test | Asserts |
|---|---|
| `TestCreate_TCPProbeOffCriticalPath` | prober seam blocks forever → Create still returns within test deadline; probe goroutine observed started |
| `TestCreate_TCPProbeUsesDetachedContext` | cancel the request ctx immediately after Create returns → probe still completes its bounded run (no premature ctx-cancelled log) |
| `TestWarmAcquire_TCPProbeOffCriticalPath` | same for the warm path |

Config: `internal/config/config_test.go` — new env var default/parse rows in
the existing table.

### Validation benchmark

Rerun UC-94 (in-VPC client). **Merge gate: firecracker server p50 ≤ 2000ms**,
`fc_verify` stage p50 ≤ 5ms on samples 2–10 (first sample pays the one-time
hash), docker/gvisor p50 within 10% of baseline. Record the run's JSON next to
this plan's status table.

---

## Phase 2 — Poll-cadence trims (optional, 1 tiny PR)

Only worth doing while the files are already open; skip if Phase 3 starts
immediately.

- `WaitSocket` (`vmm.go`): first retry at 2ms, doubling to the existing 20ms
  cap. Socket appears in single-digit ms on a healthy host; today's fixed
  20ms cadence rounds that up.
- `vsockHandshake` (`driver.go`): same shape — first retry 5ms, doubling to
  the existing 50ms cap.

Tests: extend `vmm_test.go` / `driver_test.go` retry tests to assert the
backoff sequence (fake clock or attempt-counter seam), and that the existing
deadline behavior is unchanged. Expected win is ~50–150ms; measured via the
Phase 0 `fc_spawn` / `fc_handshake` stages, not eyeballed.

---

## Phase 3 — Warm-VMM pool redesign for Firecracker v1.15 (2–3 PRs)

The endgame. Everything in stage B disappears on a warm hit: the pool's
refill goroutine pays spawn + LoadSnapshot ahead of time; Create becomes
patch-drives + Resume + handshake + post_resume.

### Why it's currently impossible and what unblocks it

The parked snapshot's eth0 references the (torn-down) template-build TAP.
v1.15 only allows TAP rebinding **at load time** via
`LoadSnapshot.network_overrides` — the cold path already uses exactly this
(`configureVMMForLoad`), so the mechanics are proven in production. The warm
pool predates that contract and tries to `PatchNetworkInterface` after load
(`warmacquire.go`), which v1.15 rejects. Fix: the warm slot must **own a real
TAP slot before LoadSnapshot**.

### Design

PR 3a — TAP ownership transfer (fragile area: TAP allocator):

- New op on the TAP pool (`internal/network/tap/pool.go` + store):
  `Transfer(ctx, fromID, toID)` — re-keys an allocated slot atomically
  (single SQLite writer; one UPDATE guarded by the existing uniqueness
  constraints). No IP/CID/name change — only the owner column.
- `Driver.Create`'s warm-hit path stops allocating its own TAP slot and
  instead Transfers the slot the pool's WarmSpawn allocated (slot-ID →
  sandbox-ID). Cold fallback keeps today's allocate-first shape. On warm-hit
  rollback, Transfer back (sandbox-ID → slot-ID) before Release so the GC
  sweep still owns cleanup.

PR 3b — WarmSpawn owns network at load time (fragile area: warm pool):

- `WarmSpawnRequest` gains the TAP slot; the refill spawner allocates a TAP
  slot under the warm slot's ID, realizes the host TAP (`tapHost.Ensure`),
  and passes `network_overrides` in its LoadSnapshot. Failure paths tear the
  TAP down (LIFO, same flag-and-defer pattern the file already uses).
- `tryAcquireWarm` drops `PatchNetworkInterface` entirely; keeps rootfs +
  overlay PatchDrive, Resume, handshake (template CID), post_resume with the
  transferred slot's IP.
- Guest MAC: the snapshot froze the template MAC; the host neighbor entry
  must use `macFromCID(SnapshotVsockCID)` exactly as the cold path's
  `hostSlot.GuestMAC` override does today — carry that into WarmSpawn's
  `Ensure`.
- Pool enable: flip the default only after UC-98 passes on cluster-hetero;
  ship dark behind the existing pool-size=0-off config first.

PR 3c — capacity & sizing guards:

- Warm slots consume finite TAP slots (`SB_FIRECRACKER_TAP_POOL_SIZE`,
  default 256/host). Cap warm-pool size at `min(configured,
  tap_pool_size/8)` and refuse to refill when free TAP slots <
  2× warm-pool size, so parked VMMs can never starve real creates. Slots
  already count toward RSS pressure (Phase 5 sampler) — verify the admission
  interaction with a test, not a comment.

Cluster note (per CLAUDE.md hard rule 6): no `internal/cluster` code changes
are expected — placement/forwarding are agnostic to how the driver boots. The
PR call-out must still state this and confirm single-node no-op behavior
(`cfg.EnableCluster=false` untouched).

### Tests

Fragile-area regression tests, next to the files they change:

`internal/network/tap/pool_test.go` (+ store tests if the column moves):

| Test | Asserts |
|---|---|
| `TestTransfer_RekeysOwner` | slot survives with same TAP/IP/CID under new ID; old ID no longer resolves |
| `TestTransfer_TargetAlreadyHasSlot` | conflict → error, no partial state |
| `TestTransfer_SourceMissing` | clean error |
| `TestTransfer_ConcurrentDuplicate` | two concurrent Transfers of one slot → exactly one wins (idempotency rule #1) |
| `TestTransfer_RollbackShape` | transfer → transfer-back round-trip restores the original row |

`internal/runtime/firecracker/warmspawn_test.go`:

| Test | Asserts |
|---|---|
| `TestWarmSpawn_LoadSnapshotCarriesNetworkOverrides` | fake client records `network_overrides` = slot TAP |
| `TestWarmSpawn_TapEnsuredBeforeLoad` | seam-call ordering |
| `TestWarmSpawn_FailureTearsDownTap` | error after Ensure → `tapHost.Remove` called (LIFO, after process shutdown) |
| `TestWarmSpawn_UsesTemplateMAC` | Ensure receives `macFromCID(SnapshotVsockCID)` |

`internal/runtime/firecracker/warmacquire_test.go`:

| Test | Asserts |
|---|---|
| `TestAcquire_NoNetworkPatch` | fake client sees zero `PatchNetworkInterface` calls |
| `TestAcquire_TransfersSlot` | TAP Transfer(slotID→sandboxID) before Resume |
| `TestAcquire_RollbackTransfersBack` | post-Transfer failure → Transfer back + Release + Shutdown, no TAP leak |
| `TestAcquire_PoolMissFallsBackCold` | `ErrNoLoadedSlot` → cold path result identical to pool-nil driver |
| `TestAcquire_ConcurrentDuplicateCreate` | same sandbox ID raced → one slot claimed, no double-Resume |

`internal/pool/vmm/refill_test.go`: refill respects the TAP-budget guard;
`pool_test.go`: GC of an aged warm slot releases its TAP slot.

Integration (new UCs, `integration-tests/suite/`; UC-97 is soft-reserved by
the docker-readiness plan):

| UC | Title | Gate |
|---|---|---|
| UC-98 | Warm-pool hit: firecracker clone create p50 ≤ 700ms server-side | `CapCluster, CapFirecracker, CapBenchmark`; asserts `fc_driver` stage ≤ 250ms and a warm-hit marker (new `fc_warm;desc=hit` Server-Timing entry) |
| UC-98b | Pool exhaustion falls back to cold create (correctness, not speed) | drain the pool with N parallel creates > pool size; all succeed |
| UC-98c | Warm slot ages out → TAP slot returns to the free pool | create after GC TTL still finds capacity; `/v1/capacity` TAP count restored |
| UC-98d | Daemon restart with parked warm slots → orphan sweep reclaims TAPs and firecracker processes | no leaked `fctap*` devices (reuse the existing orphan-reclaim harness shape from UC-60) |

### Validation benchmark

UC-94 with the pool enabled on the FC worker. **Merge gate for flipping the
default: server p50 ≤ 700ms, `fc_driver` p50 ≤ 250ms, zero failures across
≥ 20 samples (raise from 10 — the warm/cold hit mix needs the larger n), pool
refill keeps up at the bench's sequential rate (no cold fallbacks after
sample 3), docker/gvisor within 10% of baseline.**

---

## Benchmark methodology (applies to every phase gate)

1. **Client in-VPC.** The 2026-07-01 run's api−server gap (772ms p50) is the
   operator's home connection. Run the suite from a runner in the cluster VPC
   (or accept server-side numbers as the only gate — they already exclude
   client RTT). Phase gates above are all server-side for this reason.
2. **Same scenario, same instance types** (`cluster-hetero.tfvars`, c5.metal
   FC worker), same template shape (default image, 512MiB memory), n ≥ 10
   (n ≥ 20 for Phase 3), sequential creates (today's UC-94 shape).
3. **Warm the page cache first** — the existing warmup create already does
   this; keep it, otherwise sample 1 measures EBS.
4. **Record artifacts**: commit the bench JSON for each phase gate under
   `integration-tests/reports/` and update the status table in this file with
   measured (not estimated) stage numbers.
5. **Regression floor**: no phase may regress docker/gvisor server p50 by
   >10% or reduce UC pass count on the cluster-hetero matrix.

## Risks

| Risk | Mitigation |
|---|---|
| Stage attribution wrong (hash isn't the dominant term) | Phase 0 E1 experiment gates Phase 1; STOP rule if savings < 800ms |
| Cached-verify misses in-place corruption within a daemon boot | stated trade in PR; `VERIFY_MODE=always` escape hatch; LoadSnapshot failure backstop; per-boot re-verify |
| Warm slots starve TAP pool / host memory | PR 3c budget guard + RSS sampler already counts parked slots; UC-98c |
| Transfer op corrupts TAP bookkeeping under concurrent duplicate creates | single SQLite writer + `TestTransfer_ConcurrentDuplicate`; idempotency is pr-review rule #1 |
| v1.15 `network_overrides` behaves differently on warm (paused-long) VMMs than on cold loads | UC-98 runs on real hardware before the pool default flips; pool ships dark first |
| Bench flakiness blocks merges | gates are p50 (not p99) with fixed n; UC-98 lives behind `CapBenchmark` so ordinary runs don't hard-fail on latency |

## Out of scope (deliberately)

- Attacking stage D (caddy upsert / placement / forward ≈ 300ms floor) — its
  own plan if Phase 3 lands at target.
- Faster hash algorithms (BLAKE3 etc.) — the cache makes hash speed
  irrelevant after first load; changing the persisted checksum format is not
  worth the migration.
- UFFD-based memory loading — File-backend mmap is already lazy; no evidence
  yet that LoadSnapshot itself is a material cost (Phase 0 will confirm).
- Client-RTT reduction (regional endpoints, connection reuse in SDKs).
