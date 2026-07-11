# Warm create latency Tier 1: 43ms → ≤30ms acceptance (semantics-preserving)

Status: **planned (not started)** (written 2026-07-11; revised after eng review
2026-07-11; post-review addenda 2026-07-11: Phase 2 flush-race fence + §6
Tier-1.5 overlap record). Successor to `plans/docker-warm-pool.md` §12, which shipped the
warm-adopt fast path at **server p50 43ms** (v0.5.33). This plan removes the
removable engine/consensus round-trips **without changing any idempotency or
failover semantics**. The semantics-changing follow-ups (async rename, async
promote) stay deferred in §6, alongside a recorded Tier-1.5 candidate
(seal+promote overlap, ~18–20ms path) that awaits its own failure-matrix
design.

**Acceptance target: warm p50 ≤ 30ms on the standard bench topology
(t3.medium + gp3), measured under BOTH burst and sparse traffic.** The ≤25ms
stretch depends on NVMe/io2 infra with weaker durability assumptions — that
work is **split out to `plans/nvme-datadir.md`** (tracked in `TODOS.md`) and is
NOT gated here. The old "→ ~25ms" headline conflated the code win with the
infra win; this plan owns the code win only.

Owner rules that apply: every phase changes `CreateSandbox` callees
(`/touch-create-sandbox`, boot-path call-outs per `pr-review.md` §2). Phase 3
touches `internal/cluster/` (fragile — regression tests next to the file +
cluster-correctness PR call-out mandatory). Phase 1 touches the netrules path
that broke warm adopts once already on iptables-nft hosts; its regression suite
is the floor, not the ceiling.

## 1. Problem: measured anatomy of the 43ms warm hit

Live probes against the kept `cluster-3-mixed-docker` cluster
(2026-07-11, v0.5.33, t3.medium + gp3, follower worker). A pure warm hit
(`docker_pool;desc=hit`, **image cache hit**) measured 44.6ms end-to-end
server-side, fully attributed:

| Component | Measured | Evidence |
|---|---|---|
| `docker rename` (park name → sandbox ID) | ~11ms | 5 reps via engine API on-host: 11.0–11.6ms |
| iptables `ClearBlockAllEgress` | ~8ms | 2 execs minimum (delete + "no such rule" loop terminator, `netrules/manager.go`), ~4–5ms per exec on-host |
| readyproto adopt handshake | ~2ms | remainder of `docker_pool` stage |
| **= `docker_pool` stage** | **21.9ms** | Server-Timing |
| Raft placement promote (`RecordPlacement`) | ~10ms | `aerolvm_raft_leader_forward_latency`: p50 ≈ 10ms, p90 ≈ 20ms (124 samples). Runs inside `create;dur` (`cluster_handler.go`, response path) |
| Secrets ref + service glue (validate, keygen, admit) | ~5–6ms | residual |
| `svc_persist` (SQLite insert + Get) | 1.3ms | Server-Timing |
| **Total** | **≈ 44.6ms** | ✔ sums |

The Raft promote splits further (leader vs follower expvar histograms):

- **~6–7ms: the commit itself** — leader-local `aerolvm_raft_apply_latency`
  p50 ≈ 6–7ms, p90 ≈ 15ms (393 samples). raft-boltdb pays two fsyncs per
  transaction on gp3 EBS (~1ms/fsync), **in parallel with replication to one
  follower (RTT + its fsync)**. Note (eng review): the log-store swap only
  removes the boltdb share of this; follower replication + follower fsync
  remain, so the p50 win is bounded and only fully lands once all voters
  migrate — see Phase 3 tempered math.
- **~3ms: the follower→leader HTTP hop** (pooled mTLS). The p90 ≈ 20ms tail
  is consistent with connection churn: the internal transport has
  `MaxIdleConns: 4` total and the Go default 2 idle conns per host, so
  concurrent creates re-handshake mTLS. This limit exists in **both**
  `internal/cluster/client.go:189` **and** `internal/cluster/agent.go:135`
  (the follower/worker path via `NewAgent`).

Placement/slot-pop itself is microseconds. The 43ms is three round-trips:
dockerd rename (11ms), iptables execs (8ms), Raft commit (10ms).

**Critical second-order effect — the image resolve (now Phase 2).**
`docker_image;desc=resolve` (~45ms engine inspect) re-runs once per 10s cache
TTL **per node**. The 44.6ms anatomy above is an **image-cache-HIT** sample;
on a cache MISS add ~45ms → ~90ms. The probe observed a miss on **3 of 4**
sparse creates: each node's 10s cache goes cold between creates and placement
spreads consecutive creates across nodes, so on realistic sparse multi-node
traffic the resolve dominates every other line item. This is why cache warming
is a **first-class phase** (Phase 2), not a rider.

## 2. Phase 1 — netrules off the exec path (~8ms → sub-ms target)

`pkg/docker/netrules/manager.go` drives `go-iptables`, which shells out to the
`iptables` binary per call (~4–5ms each on t3.medium). The adopt path pays ≥2
execs (`ClearBlockAllEgress` delete-until-missing loop); requests with egress
policies pay 1–2 more per rule. Cold creates pay the same on `docker_netrules`.

**Target design: a netlink-native `RuleBackend` (`google/nftables`).** The seam
already exists (`RuleBackend` interface + `NewWithBackend`, `manager.go:40-77`),
but it is **iptables-shaped**: `Exists/Insert/Delete` take iptables argv
(`"-s", ip, "-j", "DROP"`; `"-m", "comment", "--comment", ...` for policies).
So the netlink backend is **not a 3-method swap** — it is a translator. Phase 1
therefore explicitly includes:

1. **An iptables-argv → nftables-expression translator** for the exact rule
   shapes the Manager emits: `-s`/`-d` source/dest match, `-j DROP`/`-j ACCEPT`
   verdict, and the `-m comment --comment sbx-egress` tag that keeps selective
   egress disjoint from the blanket block (`egressPolicyComment`,
   `manager.go:187`).
2. **Rule-equality semantics** so `Exists` matches a rule the translator (or
   dockerd/iptables tooling) previously wrote — the `DOCKER-USER` chain on
   Ubuntu 22.04+/Docker 28 is an **iptables-nft compat** chain; rules written
   via raw netlink must emit compat expressions that `iptables -L DOCKER-USER`
   still lists and matches.
3. **The compat proof is the PRIMARY feasibility gate, not a test detail.**
   Well-trodden (firewalld, kube-router) but must be proven e2e: a rule inserted
   via the new backend is visible to `iptables -L DOCKER-USER` **and actually
   drops traffic**, across the iptables flavors in the matrix (see §7 Q1).

**Reworked clear loop (semantics-preserving, backend-agnostic).**
`ClearBlockAllEgress` (`manager.go:121`), `ClearBlockAllIngress` (`:169`), and
`deletePolicyRule` (`:275`) currently loop `Delete` until `ruleNotExist(err)`
terminates. `ruleNotExist` (`manager.go:22`) classifies **iptables** errors
(typed `*iptables.Error` or 3 substrings). A netlink backend returns netlink
errors (e.g. `ENOENT` "no such file or directory") that match none of those →
"rule gone" reads as **fatal** → the adopt path breaks — the **exact bug**
`manager.go:13-21` memorializes. Fix (one shared helper, applied to all three
loops):

```
for {
  err := Delete(...)
  if err == nil { continue }              // swept one, retry (dup-sweep intact)
  if ruleNotExist(err) { return nil }     // exec path: recognized, 2 execs, UNCHANGED
  if ex, e := Exists(...); e == nil && !ex { return nil } // netlink: confirm gone
  return err
}
```

This keeps the **exec backend at its current 2-exec cost** (the `Exists`
fallback never fires when `ruleNotExist` already recognizes the error), so it
does **not** regress the §8-gated cold-path `docker_netrules`; and it makes the
netlink path safe **without** teaching `ruleNotExist` netlink error strings.

**Fallback if the translator/compat proof stalls: Option B — batch via
`iptables-restore --noflush`** (one exec per adopt instead of 2+N, ~halves the
cost to ~4–5ms, zero compat risk). Kept as the documented off-ramp; if Option A
soaks poorly, Option B still gets Phase 1 most of the way.

Config: `SB_NETRULES_BACKEND=exec|netlink`, default `exec` until Option A soaks
in an integration run; flip the default in a follow-up release. **Consequence
to bench honestly (eng review):** while the default is `exec`, the standard
benchmark does NOT exercise the netlink path — the sparse/burst gates in §8
must be run with `SB_NETRULES_BACKEND=netlink` to validate the Phase 1 win, and
the default-flip is what carries it to production.

Regression floor (all mandatory, next to `manager_test.go`):
- **[REGRESSION]** netlink `Delete` on an absent rule → clear loop terminates
  cleanly (unrecognized error + `Exists`=false path). Protects the
  `manager.go:13` bug on the new backend.
- exec no-regression: a call-counting backend asserts the common single-rule
  clear issues **2 `Delete` calls and 0 `Exists` calls** (recognized not-exist
  short-circuits the fallback).
- translator round-trip: each Manager rule shape → nft expression → visible to
  `iptables -L` (unit where possible; the drop-traffic proof is the e2e below).
- **[→E2E, tag-gated]** iptables-nft `DOCKER-USER` visibility + actual drop,
  across the §7-Q1 flavor matrix. This is the exact spot the invisible
  adopt-breakage bug lived (`ruleNotExist` comment).

Exit gates: adopt-path netrules cost sub-ms p50 (Option A) or ≤5ms (Option B),
`docker_netrules` cold-path stage drops equivalently and the **exec backend
does not regress**, zero `docker_pool;desc=adopt_failed` samples in a full
bench run.

## 3. Phase 2 — image-ID cache warming (first-class; ~45ms sparse resolve → ~0)

Promoted from a rider at eng review: on realistic sparse multi-node traffic the
~45ms `docker_image;desc=resolve` (§1) is the single biggest per-create cost,
larger than iptables + Raft savings + forward-tail combined. The
park/refill path already inspects each parked image (`docker_pool.go:312`
stores `imageInspect.ID` on the slot), and the adopt path consults the TTL cache
at `docker_pool.go:117` (`resolveImageIDCached`).

**Why the naïve "free-ride on Park" rider does NOT work (eng review):**
`refillTick` (`refill.go:56`) only calls `spawner.Park` when
`SpawnBudget(ks) > 0` — i.e. only *after* consumption. When the pool sits full,
no Park runs, so there is no fresh resolution to `Put`. And `Put` stamps a 10s
TTL (`image_cache.go:72`); the sparse condition is "one create per 15s+", so
even a post-consumption `Put` **expires before the next sparse create arrives
(15s > 10s)** → cold resolve again. Free-riding on Park keeps the cache warm
only when consumption outpaces the TTL — the opposite of the sparse traffic it
targets.

**Design: unconditional per-tick re-resolve, Client-owned.**

```
warmTick (every RefillInterval, e.g. 5s):
  for key in pool.ListTargets():         // pool-eligible images only
     id := <timing-free engine inspect>(key.image)   // OFF the boot path
     imageIDs.Put(key.image, id)                       // refresh -> now + TTL
```

- **Keeps the cache warm:** `RefillInterval` (5s) < `imageIDCacheTTL` (10s), so
  a pool-eligible image is re-`Put` before its entry can expire → sparse
  creates always hit. **Invariant, asserted at wiring:
  `RefillInterval < imageIDCacheTTL`** (fail-fast/log if violated; a misconfig
  silently reverts to cold sparse creates).
- **Tightens staleness:** because each tick *re-resolves* (fresh engine
  inspect), an out-of-band re-tag is picked up within one tick (≤5s) instead of
  the 10s TTL. In-band mutations (pull, build tag, GC delete) still `Flush`
  immediately — kept true under the warm loop by the fence below.
- **Flush/Put race — generation fence (post-review 2026-07-11):** a warm
  tick's inspect can begin *before* an in-band mutation lands, and its `Put`
  can arrive *after* the mutation's `Flush` — re-installing the stale ID and
  silently weakening `image_cache.go`'s documented "in-band mutations never
  wait on the TTL" to "within one tick". Fix: a **per-ref generation
  counter**, bumped by `Flush`; the warm loop snapshots the generation before
  its inspect and its `Put` is dropped when the generation has moved (the
  next tick re-resolves fresh). Boot-path `Put`s are untouched — their
  narrower pre-existing race window is not in scope.
- **Zero boot-path cost:** the inspect runs in the background warm loop, never
  on `CreateSandbox`. Cost is one background inspect per pool-eligible key per
  tick — negligible for the small pool-eligible set (see §7 Q2 for the
  many-images caveat).

**Wiring boundary (eng review):** `resolveImageIDCached` is a `*docker.Client`
method (`docker_pool.go:338`) that **records a `docker_image` timing stage** via
`CreateTimingFrom(ctx).RecordStageDesc`. The refill loop lives in
`internal/pool/dockerpool` and only sees the `Spawner` interface — it cannot
reach `c.imageIDs`. So warming is a **Client-side responsibility** (a
Client-owned ticker over `pool.ListTargets()`), and it MUST use a **timing-free
resolve variant**, not `resolveImageIDCached` — calling the timing path with a
background ctx risks a nil/mis-recorded `RecordStageDesc`.

Tests (fake clock, `image_cache.go`'s `now` seam already exists):
- warm-across-sparse-gap: tick warmer, advance clock past TTL **and** past the
  15s inter-create gap, assert `Get` still hits (proves "permanently warm").
- re-tag freshness: change the resolved ID between ticks, assert `Get` returns
  the new ID within one interval (proves "tightens staleness").
- invariant: wiring rejects/warns when `RefillInterval >= imageIDCacheTTL`.
- flush-race fence: `Flush` fired between the warm loop's generation snapshot
  and its `Put` → the stale `Put` is dropped; the next tick installs the
  fresh ID.
- background-only: warming issues no `docker_image` boot-path timing stage.

Exit gate: `docker_image;desc=resolve` appears on ~zero warm hits for
pool-eligible images in the **sparse** bench (§8), with warm p50 holding.

## 4. Phase 3 — raft-wal log store (commit ~6–7ms → ~3–4ms on gp3)

Swap the Raft **log store** from `raft-boltdb/v2` to `hashicorp/raft-wal`
(`internal/cluster/raft.go` `setupRaft`). raft-wal exists precisely because
BoltDB's two-fsync B+tree commit is the known hot-path cost (Consul and Vault
both migrated); it also fixes BoltDB freelist growth, which degrades append
latency as the log churns. The **stable store stays Bolt** (tiny, rare writes).

**Tempered perf expectation (eng review):** the log-store swap removes only the
boltdb share of the ~6–7ms commit. Follower replication RTT + follower fsync
remain, and the win only fully lands once **all voters** run WAL — a
mixed-format cluster mid-rollout may not move p50 much. Expected p50 ≤ 4ms on
gp3 is the **all-WAL** steady state, not the mid-rollout state.

Scope and blast radius:

- `raft-log.bolt` / `raft-stable.bolt` filenames appear only in `raft.go`;
  scripts/Ansible operate on the DataDir and never name the files.
- **Type blast radius is wider than "recovery params" (eng review).**
  `raftNode.logStore` is concrete `*raftboltdb.BoltStore` (`raft.go:21`) and
  `raftNode.Close` calls `logStore.Close()` (`raft.go:166`) — but
  `raft.LogStore` does **not** include `Close`. So the co-change needs a small
  **custom closable interface** (`raft.LogStore` + `io.Closer`), used by both
  the struct field and `raft_recovery.go`'s `maybeRecoverRaftClusterFromPeersFile`
  (`raft_recovery.go:26-34`, currently concrete `*raftboltdb.BoltStore`).
- **Migration = per-node format detection, not conversion.** On startup:
  `if boltdb-log-file present → open Bolt; else → open WAL`. Detection runs
  **before** recovery and hands `RecoverCluster` the **same store** it picked
  (detect → recover ordering is load-bearing). Name the raft-wal on-disk
  artifact explicitly so detection keys off "boltdb file present", not a fuzzy
  "non-empty" (a boltdb file is never byte-empty). No offline converter.

**Mixed-format safety (mandatory cluster-correctness call-out).** During a
rolling migration some nodes run Bolt and some run WAL. This **is safe**: the
log store is **node-local**, raft replicates log **entries** over the transport
(not store files), and the FSM sits **above** the store, so replay safety is
unchanged. Leader-change behavior is unchanged. Rollout is one node at a time
via the standard Ansible **drain → remove-member → rejoin** cycle, **never
dropping below quorum**.

**Revertability is NOT in-place (eng review — corrects the old §9 claim).**
Once a node writes WAL state, boltdb-only code **cannot read it**. Reverting a
node is therefore **drain → rejoin with the bolt build + a fresh DataDir**, not
a config flip. Phases 1, 2, and 4 stay config-gated/revertable in place; Phase 3
is a one-way door per node and the rollout doc must say so.

Regression tests next to `raft.go` (mandatory): WAL setup; restart + recovery
round-trip on a WAL node; **[REGRESSION]** mixed-format node → recovery uses the
matching store type; detection unit test (bolt-present→bolt, absent→WAL);
single-node no-op when `EnableCluster=false`.

Exit gate: `aerolvm_raft_apply_latency` p50 ≤ 4ms on gp3 (≤ 2ms on NVMe),
all-WAL steady state; lost-quorum recovery runbook re-verified on a WAL node.

## 5. Phase 4 — forward transport pooling (tail fix, trivial)

Raise the internal mTLS transport idle-conn limits so followers stop
re-handshaking mTLS under concurrent creates. **Two call sites (eng review):**

- `internal/cluster/client.go:189`
- `internal/cluster/agent.go:135` (the `NewAgent` follower/worker path — the
  nodes that actually forward to the leader, i.e. the path the p90 tail comes
  from). Fixing only `client.go` leaves the tail on the forwarding nodes.

Set both to `MaxIdleConns: 64`, `MaxIdleConnsPerHost: 16`, `IdleConnTimeout:
90s`. (Note: the proxy caches just below each — `client.go:206`, `agent.go:147`
— are `100/10/90s`; "match the neighbour" was imprecise, these are deliberately
16-per-host for the forward fan-in.) Expected: `leader_forward` p90 20ms →
≤ 12ms; p50 mostly unchanged. Test: one connection-reuse test against a counting
test server, covering both transports.

## 6. Deferred: Tier 1.5 overlap + Tier 3 async — entry-gated

Not in scope. On record so the trade-offs are documented.

**Tier 1.5 (recorded post-review 2026-07-11): overlap seal + promote with the
local create — ~10ms, the path to ~18–20ms warm p50 without NVMe.** The
response path is strictly sequential today (`cluster_handler.go:349-403`):
`CreateSandboxWithID` (docker_pool, ~13–14ms post-Phase-1) →
`PutClusterSecretsForRecipient` (seal) → `RecordPlacement` (Raft, ~10ms). But
on the reserved path every seal/promote input is known **before** the create
starts — the sandbox ID is minted on the router before `opReserve`
(`cluster_handler.go:167`), and the redacted spec + self node ID likewise. Run
seal+promote concurrently with the local create and **join both before
responding**: the response path becomes max(create, seal+promote) ≈ the create
alone, and the client-visible guarantee holds (the FSM knows the owner before
the client can act — unlike Tier-3 async promote below, which stops waiting).
Why it is NOT in this plan: the failure matrix widens. Today rollback only
handles promote-failed-**after**-create-succeeded
(`cluster_handler.go:405-424`); the overlap adds
promote-succeeded-but-create-**failed** — a `Placed` FSM entry with no
container for the failure window. That needs a documented retraction rule
(pr-review §4), an owner-watcher analysis of the transient Placed-but-missing
state, and the full cluster-correctness call-out (pr-review §6). A small
design doc, not a config flip. **Entry: Phases 1–4 landed + a want for
sub-20ms server-side warm p50 without the NVMe topology.** Prerequisite first
slice either way: attribute the ~5–6ms residual glue with finer Server-Timing
stages (validate / keygen / admit / seal); if the seal is 2–3ms of it,
overlapping the seal alone is a low-risk subset.

Tier 3 (semantics-changing), on record:

- **Async rename**: the 11ms is dockerd's own container lock + state write; we
  can only move it off the response path. The warm-path duplicate guard is
  already the in-process slot pop + the cluster reservation, so the rename is
  belt-and-suspenders there — but the `name=sandboxID` convention is
  **load-bearing for `ErrSandboxContainerExists` idempotency on the cold path**,
  and a window where the container is still named `park-<hex>` changes what
  reconcile and duplicate-create see. Needs its own design.
- **Async promote**: `RecordPlacement` is a synchronous response-path Raft
  commit **by design** — the FSM must know the owner before the client can act.
  Could become TTL-fenced async, but that changes the recovery/replay story
  (what does the owner watcher do with a Reserved-but-running sandbox whose
  owner died?) — split-brain + leader-change analysis required.

Entry criterion: a product requirement for sub-20ms server-side warm creates in
cluster mode. Below ~20ms the WAN dominates everything a remote client observes
(bench api p50 is ~800ms of network on 43ms of server).

Also on record: **p99 is hit-rate work, not hit-path work.** At 9/10 hits, p99
is by definition a cold miss (~250–300ms floor). The fix is pool sizing ≥ worst
burst + single-flight refill (docker-warm-pool §10 follow-ups). No phase here
moves p99 materially. Concurrency ceiling: the `netrules` `Manager.mu`
serializes Block/Clear/Apply across creates (`manager.go:46`) — out of scope
here (p50 single-create never contends it), tracked in `TODOS.md`.

## 7. Open questions

1. Option A compat proof: which iptables flavors must the e2e matrix cover?
   (iptables-legacy hosts still exist in self-hosted deployments; the matrix
   also fixes how much translator/rule-equality surface Phase 1 must carry.)
2. Non-pooled images still pay the once-per-TTL resolve — Phase 2 only warms
   pool-eligible images (the ones `ListTargets` knows). Acceptable, since
   non-pooled images miss the pool and go cold anyway. Also bounds the warm
   loop's background inspect volume to the pool-eligible set; revisit (cap /
   stagger) only if that set grows large or a facade workload shows otherwise.

## 8. Expected results

| Configuration | warm-burst p50 | warm-sparse p50 | warm p90 | Gate |
|---|---|---|---|---|
| Today (v0.5.33, t3.medium + gp3) | 43ms | ~88ms (cache miss) | 78ms | — baseline |
| Phases 1–4, standard topology | **≤ 30ms** | **≤ 30ms** | ≤ 45ms | **acceptance** |
| NVMe topology (`plans/nvme-datadir.md`) | ≤ 25ms | ≤ 25ms | ≤ 35ms | not gated here |
| (Tier 1.5 seal+promote overlap, §6) | ~18–20ms | ~18–20ms | — | not gated here |
| (deferred Tier 3, for scale) | ~8–12ms | — | ~15–20ms | not gated here |

Verification — **both** benches, run with `SB_NETRULES_BACKEND=netlink`:
- `make integration-benchmark-docker-only` (existing burst) — image cache warm.
- **`make integration-benchmark-docker-sparse` (NEW)** — one create per 15s+,
  placement-spread across nodes. Gate: `docker_image;desc=resolve` on ~zero warm
  hits AND warm p50 ≤ 30ms. This is the only gate that exercises Phase 2.

Per-stage attribution via Server-Timing must show `docker_pool` ≤ 15ms and the
promote share of the residual ≤ 5ms (`aerolvm_raft_apply_latency` /
`leader_forward` histograms). Cold-path `docker_netrules` and `docker_create`
must not regress (guards the Phase 1 exec-backend rework).

## 9. Phase ordering & release shape

Each phase is independently shippable. Phases 1, 2, 4 are config-gated and
**revertable in place**. **Phase 3 is NOT revertable in place** — a WAL node
reverts only via drain → rejoin with the bolt build + fresh DataDir (see §4).

Suggested order: Phase 4 (trivial, both transports) → Phase 2 (biggest sparse
win, code-only) → Phase 1 (biggest burst win, riskiest — the nft translator) →
Phase 3 (needs the Ansible rejoin cycle to roll out, one-way per node).

---

## NOT in scope

- **NVMe/io2 data-dir infra** — split to `plans/nvme-datadir.md` (`TODOS.md`).
  Different review surface (AWS infra), operator opt-in, no code dep, and NOT
  semantics-preserving (instance-store loss = Raft log + SQLite state). Only
  moves the ≤25ms stretch, never the acceptance gate.
- **Async rename / async promote** (Tier 3, §6) — semantics-changing, entry-gated
  on a sub-20ms product requirement.
- **Seal+promote overlap with the local create** (Tier 1.5, §6) — awaits both
  before responding so client semantics hold, but the
  promote-succeeded/create-failed retraction needs its own design doc +
  cluster-correctness call-out. Recorded in §6 with entry criteria; not scoped
  here.
- **`netrules` `Manager.mu` sharding** (`TODOS.md`) — concurrency ceiling; §6
  scopes p99/concurrency out; p50 never contends it.
- **p99 / pool-sizing + single-flight refill** — hit-rate work, not hit-path;
  docker-warm-pool §10 follow-up.
- **Non-pooled image resolve** (§7 Q2) — out of the warm loop's knowledge.

## What already exists (reused, not rebuilt)

| Sub-problem | Existing code | Plan action |
|---|---|---|
| netrules backend seam | `RuleBackend` iface + `NewWithBackend` (`manager.go:40-77`) | Reuse the seam; add nft backend + argv→nft translator (the seam is iptables-shaped, so translation is new work) |
| not-exist classification | `ruleNotExist` (`manager.go:22`) | Keep for exec; add `Exists`-fallback for netlink (no new error strings) |
| image-ID TTL cache | `imageIDCache` Get/Put/Flush (`image_cache.go`), wired at `docker_pool.go:117` | Reuse; add a Client-owned per-tick re-resolve/`Put` loop + per-ref generation fence on `Flush` |
| warm refill loop | budget-gated `refillTick` (`refill.go`), the "self-warming refill" from `b8cd956` | Left as-is; warming is a **separate** Client ticker (refill can't reach the cache) |
| raft log store | `setupRaft` boltdb (`raft.go:65`), `maybeRecoverRaftClusterFromPeersFile` (`raft_recovery.go`) | Swap log store to raft-wal behind a closable interface + format detection |
| mTLS transport | `client.go:189`, `agent.go:135` | Raise idle-conn limits on both |

## Failure modes (per new/changed codepath)

| Codepath | Realistic prod failure | Test? | Error handling? | User sees? |
|---|---|---|---|---|
| netlink `Delete` on absent rule | netlink `ENOENT` unrecognized → clear loop returns fatal → **adopt breaks** | **[REGRESSION] yes** (Exists-fallback test) | Exists-fallback confirms gone → clean | Silent today → would be `adopt_failed` fallback to cold path |
| nft rule not iptables-nft-compat | rule invisible to `iptables -L` / doesn't drop → egress leak or adopt mismatch | **[→E2E] yes** (visibility + drop, primary gate) | compat proof gates the default-flip | Silent (security-relevant) if unproven — hence e2e is the gate |
| warm loop misconfig `RefillInterval ≥ TTL` | cache goes cold between ticks → sparse creates pay ~45ms again | yes (invariant test) | fail-fast/log at wiring | Slow creates, no error |
| warm loop timing on background ctx | `RecordStageDesc` nil/mis-record | yes (background-only test) | use timing-free resolve variant | n/a (would be a panic if wired wrong) |
| warm-loop `Put` racing an in-band `Flush` | stale ID re-installed after pull/re-tag → adopt validates against the previous image for ≤1 tick | yes (flush-race fence test) | per-ref generation fence drops the stale `Put` | Nothing — staleness prevented (silent if unfenced, hence the test) |
| raft-wal mixed-format recovery | recovery opens wrong store type → node fails to rejoin | **[REGRESSION] yes** (mixed-format test) | detect → recover ordering | Operator sees rejoin failure (loud) |
| WAL node reverted to bolt build | bolt can't read WAL → node won't start | rollout doc (not in-place revertable) | drain → rejoin fresh DataDir | Operator sees start failure (loud) — documented |
| transport pool exhaustion (agent.go missed) | followers keep re-handshaking mTLS → p90 tail persists | yes (reuse test, both transports) | both call sites raised | Slow tail, no error |

No failure mode is left with **no test AND no error handling AND silent** — the
two silent ones (netlink not-exist, nft compat) both get the mandatory
regression/e2e tests above.

## Worktree parallelization strategy

| Step | Modules touched | Depends on |
|------|----------------|------------|
| Phase 1 netrules | `pkg/docker/netrules/`, `pkg/docker/` (adopt) | — |
| Phase 2 image warming | `pkg/docker/` (Client), `internal/pool/dockerpool/` (ListTargets read) | — |
| Phase 3 raft-wal | `internal/cluster/` (raft.go, raft_recovery.go), `go.mod` | — |
| Phase 4 transport | `internal/cluster/` (client.go, agent.go) | — |

- **Lane A:** Phase 3 → Phase 4 (sequential — both touch `internal/cluster/`,
  merge conflict risk otherwise).
- **Lane B:** Phase 1 → Phase 2 (sequential — both touch `pkg/docker/`; Phase 1's
  clear-loop rework and Phase 2's Client ticker are near each other).

Execution: **launch Lane A and Lane B in parallel worktrees**, merge each lane
internally, then merge the two lanes. **Conflict flag:** Phases 3 and 4 both
touch `internal/cluster/` — keep them in the same lane (sequential), do not
parallelize within Lane A.

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship.

- [ ] **T1 (P1, human: ~3-4 days / CC: ~3h)** — netrules — Build the netlink `RuleBackend` incl. the iptables-argv→nft-expression translator + rule-equality
  - Surfaced by: Architecture / Outside voice — "RuleBackend is iptables-shaped; nftables is a translator, not a 3-method swap"
  - Files: `pkg/docker/netrules/` (new backend + translator), `pkg/docker/netrules/manager_test.go`
  - Verify: unit round-trip (Manager rule → nft expr → visible to `iptables -L`); tag-gated e2e drop proof
- [ ] **T2 (P1, human: ~half day / CC: ~30min)** — netrules — Rework the three clear loops to delete-first + `Exists` fallback
  - Surfaced by: Code Quality — "netlink ENOENT unrecognized by `ruleNotExist` → clear loop fatal → adopt breaks (`manager.go:13` bug)"
  - Files: `pkg/docker/netrules/manager.go` (shared helper for `ClearBlockAllEgress:121`, `ClearBlockAllIngress:169`, `deletePolicyRule:275`)
  - Verify: **[REGRESSION]** netlink absent-rule clear terminates; exec no-regression (2 Delete, 0 Exists)
- [ ] **T3 (P1, human: ~1 day / CC: ~1h)** — image-cache — Client-owned per-tick re-resolve warming loop + `RefillInterval < TTL` invariant + `Flush` generation fence
  - Surfaced by: Architecture — "free-ride on Park fails the 15s sparse gate (10s TTL); needs unconditional per-tick re-resolve"; post-review — "warm `Put` can race an in-band `Flush` and re-install a stale ID"
  - Files: `pkg/docker/` (Client ticker + timing-free resolve), `pkg/docker/image_cache.go` (per-ref generation), reads `internal/pool/dockerpool` `ListTargets` (exists, `pool.go:372`)
  - Verify: warm-across-sparse-gap (fake clock), re-tag freshness, invariant, background-only (no boot-path timing stage), flush-race fence (stale `Put` dropped)
- [ ] **T4 (P1, human: ~1 day / CC: ~40min)** — cluster — raft-wal log store + closable interface + format detection + mixed-format safety
  - Surfaced by: Architecture / Outside voice — "`raft.LogStore` lacks `Close`; detect→recover ordering; mixed-format & revert unstated"
  - Files: `internal/cluster/raft.go`, `internal/cluster/raft_recovery.go`, `go.mod`
  - Verify: WAL setup, restart round-trip, **[REGRESSION]** mixed-format recovery, detection unit, single-node no-op
- [ ] **T5 (P2, human: ~20min / CC: ~5min)** — cluster — Raise idle-conn limits on BOTH `client.go:189` and `agent.go:135`
  - Surfaced by: Outside voice — "Phase 4 missed `agent.go`; followers do the forwarding"
  - Files: `internal/cluster/client.go`, `internal/cluster/agent.go`
  - Verify: connection-reuse test against counting test server, both transports
- [ ] **T6 (P1, human: ~1 day / CC: ~45min)** — integration-tests — Add `make integration-benchmark-docker-sparse` gate
  - Surfaced by: Performance — "burst bench keeps cache warm; Phase 2's win invisible and its regression untested"
  - Files: `integration-tests/suite/`, `Makefile`
  - Verify: gate — `docker_image;desc=resolve` on ~0 warm hits AND warm p50 ≤ 30ms under sparse load
- [ ] **T7 (P3, human: ~15min / CC: ~3min)** — docs/rollout — Document Phase 3 as NOT in-place revertable (drain→rejoin, fresh DataDir)
  - Surfaced by: Outside voice — "raft-wal not revertable; §9 claim was false"
  - Files: this plan §4/§9 (done), Ansible recovery runbook note
  - Verify: rollout doc names the one-way door + quorum-preserving order

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | not run |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | not run |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR (PLAN) | 5 issues, 0 critical gaps, all folded |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | n/a (server/infra) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | not run |

- **CODEX (outside voice, `codex-plan-review`):** ran read-only/high-effort; verified the code paths and confirmed the review's findings independently. New items it surfaced were all folded: Phase 4 missed `agent.go:135`; raft-wal is not in-place revertable (§9 corrected); the netlink backend is an iptables-argv→nft translator, not a 3-method swap (Phase 1 rewritten); plus fold-in constraints (timing-free warm resolve, `LogStore.Close` interface, `Manager.mu` HOL → TODO).
- **CROSS-MODEL:** no contradictions — Codex and the Eng review agreed on every finding; Codex extended (agent.go, revertability, translator depth) rather than disputing. Cross-model consensus on the image-cache budget-gate and the headline mislabel.
- **VERDICT:** ENG CLEARED — ready to implement. Scope reduced (Phase 4 NVMe split to `plans/nvme-datadir.md`; image-resolve promoted to first-class Phase 2). 7 implementation tasks (T1–T7) recorded.

NO UNRESOLVED DECISIONS
