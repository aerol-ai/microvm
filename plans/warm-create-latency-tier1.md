# Warm create latency Tier 1: 43ms → ~25ms (semantics-preserving)

Status: **planned (not started)** (written 2026-07-11). Successor to
`plans/docker-warm-pool.md` §12, which shipped the warm-adopt fast path at
**server p50 43ms** (v0.5.33). This plan removes the remaining
engine/consensus round-trips that are removable **without changing any
idempotency or failover semantics**. The semantics-changing follow-ups
(async rename, async promote) are documented in §6 as explicitly deferred.

Owner rules that apply: every phase here changes `CreateSandbox` callees
(`/touch-create-sandbox`, boot-path call-outs per `pr-review.md` §2). Phase 2
touches `internal/cluster/` (fragile area — regression tests next to the file
+ cluster-correctness PR call-out mandatory). Phase 1 touches the netrules
path that broke warm adopts once already on iptables-nft hosts; its
regression suite is the floor, not the ceiling.

## 1. Problem: measured anatomy of the 43ms warm hit

Live probes against the kept `cluster-3-mixed-docker` cluster
(2026-07-11, v0.5.33, t3.medium + gp3, follower worker). A pure warm hit
(`docker_pool;desc=hit`, image cache hit) measured 44.6ms end-to-end
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
  transaction on gp3 EBS (~1ms/fsync), in parallel with replication to one
  follower (RTT + its fsync).
- **~3ms: the follower→leader HTTP hop** (pooled mTLS). The p90 ≈ 20ms tail
  is consistent with connection churn: the internal transport has
  `MaxIdleConns: 4` total and the Go default 2 idle conns per host, so
  concurrent creates re-handshake mTLS.

Placement/slot-pop itself is microseconds. The 43ms is three round-trips:
dockerd rename (11ms), iptables execs (8ms), Raft commit (10ms).

Second-order p50 effect: `docker_image;desc=resolve` (~45ms engine inspect)
re-runs once per 10s cache TTL **per node**. Bursts on one node amortize it;
sparse traffic spread by placement pays it on most creates (observed: 3 of 4
probes). See §7 open questions.

## 2. Phase 1 — netrules off the exec path (~8ms → ≤1ms)

`pkg/docker/netrules/manager.go` drives `go-iptables`, which shells out to
the `iptables` binary per call (~4–5ms each on t3.medium). The adopt path
pays ≥2 execs (`ClearBlockAllEgress` delete-until-missing loop); requests
with egress policies pay 1–2 more per rule. Cold creates pay the same on
`docker_netrules`.

**Target design:** a netlink-native `RuleBackend` implementation. The seam
already exists (`RuleBackend` interface + `NewWithBackend`), so this is a new
backend, not a Manager rewrite.

- **Option A (target): `google/nftables`** — native netlink, sub-ms per op,
  no exec. Risk: `DOCKER-USER` on Ubuntu 22.04+/Docker 28 is an iptables-nft
  *compat* chain; rules written via raw netlink must emit the compat
  expressions that `iptables`/dockerd tooling still lists and matches. This
  is well-trodden (firewalld, kube-router do it) but must be proven with an
  e2e check: rule inserted via the new backend is visible to `iptables -L
  DOCKER-USER` and actually drops traffic.
- **Option B (fallback): batch via `iptables-restore --noflush`** — one exec
  per adopt instead of 2+N. Halves the cost (~4ms) rather than eliminating
  it; zero compat risk.

Config: `SB_NETRULES_BACKEND=exec|netlink`, default `exec` until Option A
soaks in an integration run; flip the default in a follow-up release.

Regression floor: the existing manager tests run against both backends via
the seam; add the iptables-nft visibility e2e to the tag-gated suite (this
is the exact spot where the invisible adopt-breakage bug lived — see the
`ruleNotExist` comment).

Exit gate: adopt-path netrules cost ≤1ms p50 (Option A) or ≤5ms (Option B),
`docker_netrules` cold-path stage drops equivalently, zero
`docker_pool;desc=adopt_failed` samples in a full bench run.

## 3. Phase 2 — raft-wal log store (commit ~6–7ms → ~3–4ms on gp3)

Swap the Raft **log store** from `raft-boltdb/v2` to `hashicorp/raft-wal`
(`internal/cluster/raft.go` `setupRaft`). raft-wal exists precisely because
BoltDB's two-fsync B+tree commit is the known hot-path cost (Consul and
Vault both migrated); it also fixes BoltDB freelist growth, which degrades
append latency as the log churns — a latent problem for us independent of
this plan, given create/destroy churn. The **stable store stays Bolt**
(tiny, rare writes).

Scope and blast radius:

- `raft-log.bolt` / `raft-stable.bolt` filenames appear only in
  `internal/cluster/raft.go`; scripts/Ansible operate on the DataDir and
  never name the files.
- `internal/cluster/raft_recovery.go` takes `*raftboltdb.BoltStore` params —
  co-change to accept the store interfaces so lost-quorum recovery works on
  either format.
- **Migration = per-node format detection, not conversion.** On startup: if
  `raft-log.bolt` exists and is non-empty, keep Bolt for that node;
  otherwise create raft-wal. Existing clusters move via the standard Ansible
  drain → remove-member → rejoin cycle (fresh DataDir ⇒ WAL); integration
  clusters are re-provisioned anyway. No offline converter.

This is the fragile cluster area: regression tests next to `raft.go`
(setup with WAL store, restart/recovery round-trip, single-node no-op when
`EnableCluster=false`) plus a cluster-correctness call-out in the PR
(replay safety unchanged — the log store is below the FSM; leader-change
behavior unchanged; the risk is on-disk-format lifecycle, covered by the
detection rule).

Exit gate: `aerolvm_raft_apply_latency` p50 ≤ 4ms on gp3 (≤ 2ms on NVMe),
lost-quorum recovery runbook re-verified on a WAL node.

## 4. Phase 3 — forward transport pooling (tail fix, trivial)

`internal/cluster/client.go` (~L189): raise the internal mTLS transport to
`MaxIdleConns: 64`, `MaxIdleConnsPerHost: 16`, `IdleConnTimeout: 90s`
(matching the proxy cache right below it). Removes mTLS re-handshakes under
concurrent creates. Expected: `leader_forward` p90 20ms → ≤ 12ms; p50
mostly unchanged. One connection-reuse test against a counting test server.

## 5. Phase 4 — fsync floor: NVMe / io2 data-dir option (Terraform)

gp3 fsync (~1ms) is the floor under every remaining fsync: both Raft
stores, and the single-writer SQLite WAL behind `svc_persist` and the
secrets ref. Options, operator-choice via Terraform variables:

- **Instance-store NVMe** (c5d/m5d/m6id): fsync ~0.1ms → Raft commit
  ~1–2ms, `svc_persist` sub-ms. Caveat: instance store evaporates on stop.
  Raft log + SQLite are per-node state; a single node loss recovers via
  rejoin, but a **full-cluster stop loses everything** → gate this topology
  on the lost-quorum recovery runbook and say so in `Terraform/` docs.
- **io2** — safer middle, smaller win (~0.5ms fsync).

Scope: instance-type + volume variables in `Terraform/nodes.tf`, bootstrap
template mounts the instance store at the sandboxd data dir when present.
The standard integration bench topology **stays t3.medium+gp3** (cost);
add one optional NVMe scenario for the stretch gate.

## 6. Deferred (Tier 3): async rename + async promote — entry-gated

Not in scope. Documented so the trade-off is on record:

- **Async rename**: the 11ms is dockerd's own container lock + state write;
  we can only move it off the response path. The warm-path duplicate guard
  is already the in-process slot pop + the cluster reservation, so the
  rename is belt-and-suspenders there — but the name=sandboxID convention
  is **load-bearing for `ErrSandboxContainerExists` idempotency on the cold
  path**, and a window where the container is still named `park-<hex>`
  changes what reconcile and duplicate-create see. Needs its own design.
- **Async promote**: `RecordPlacement` is a synchronous response-path Raft
  commit **by design** — the FSM must know the owner before the client can
  act. The reservation already carries spec + target, so promote could
  become TTL-fenced async, but that changes the recovery/replay story
  (what does the owner watcher do with a Reserved-but-running sandbox whose
  owner died?) — split-brain and leader-change analysis required.

Entry criterion: a product requirement for sub-20ms server-side warm
creates in cluster mode. Below ~20ms the WAN dominates everything a remote
client observes (bench api p50 is ~800ms of network on 43ms of server).

Also on record: **p99 is hit-rate work, not hit-path work.** At 9/10 hits,
p99 is by definition a cold miss (~250–300ms floor). The fix is pool
sizing ≥ worst burst + single-flight refill (see docker-warm-pool §10
follow-ups), which collapses p99 to ~3× p50. No phase in this plan moves
p99 materially.

## 7. Open questions

1. Image-ID cache TTL (10s) vs placement spread: sparse traffic pays the
   ~45ms resolve on most creates because each node's cache is cold. Options:
   raise TTL (staleness window for out-of-band re-tags grows — see the
   rationale on `imageIDCacheTTL`), or warm the cache from the park refill
   loop, which already knows the image ID it parked. The refill-loop warm
   costs nothing on the boot path and keeps the 10s out-of-band guarantee —
   likely a Phase 1 rider.
2. Option A compat proof: which iptables flavors must the e2e matrix cover?
   (iptables-legacy hosts still exist in self-hosted deployments.)

## 8. Expected results

| Configuration | warm p50 | warm p90 | Gate |
|---|---|---|---|
| Today (v0.5.33, t3.medium + gp3) | 43ms | 78ms | — baseline |
| Phases 1–3 on standard bench topology | **≤ 30ms** | ≤ 45ms | **acceptance** |
| + Phase 4 NVMe topology | ≤ 25ms | ≤ 35ms | stretch |
| (deferred Tier 3, for scale) | ~8–12ms | ~15–20ms | not gated here |

Verification: `make integration-benchmark-docker-only` on the standard
topology; per-stage attribution via Server-Timing must show `docker_pool`
≤ 15ms and the promote share of the residual ≤ 5ms
(`aerolvm_raft_apply_latency` / `leader_forward` histograms).
Cold-path `docker_netrules` and `docker_create` must not regress.

## 9. Phase ordering & release shape

Each phase is independently shippable and independently revertable
(config-gated where behavior could differ: netrules backend, log-store
format detection). Suggested order: Phase 3 (trivial) → Phase 1 (biggest
per-create win) → Phase 2 (needs the Ansible rejoin cycle to roll out) →
Phase 4 (operator opt-in, no code dependency on the others).
