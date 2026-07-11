# TODOS

Deferred work items with enough context to pick up cold. Each entry says
what, why, the caveat that motivated capturing it, and where to start.

## NVMe/io2 data-dir option (infra) — `plans/nvme-datadir.md`

- **What:** Terraform instance-type + volume variables (`Terraform/nodes.tf`)
  plus a bootstrap template that mounts an instance-store NVMe (c5d/m5d/m6id)
  or io2 volume at the sandboxd data dir when present.
- **Why:** gp3 fsync (~1ms) is the floor under every remaining fsync on the
  warm-create path: both Raft stores AND the single-writer SQLite WAL behind
  `svc_persist` and the secrets ref. NVMe drops fsync to ~0.1ms (Raft commit
  ~1–2ms, `svc_persist` sub-ms); io2 is the safer middle (~0.5ms).
- **Caveat (the reason this is its own plan, not a phase):** it is **not
  semantics-preserving.** Instance-store evaporates on stop, and the data dir
  holds the local SQLite sandbox store too (`internal/service/service.go`
  `s.store.Create`), not just Raft logs. A single-node loss recovers via
  rejoin, but a **full-cluster stop loses everything.** Gate the topology on
  the lost-quorum recovery runbook and document the durability trade in
  `Terraform/` docs.
- **Depends on / blocked by:** nothing (operator opt-in, no code dependency on
  the latency phases). Split out of `plans/warm-create-latency-tier1.md` at
  eng review 2026-07-11.
- **Start:** `Terraform/nodes.tf` + the node bootstrap template; add one
  optional NVMe bench scenario for the stretch gate (≤25ms).

## netrules Manager mutex head-of-line blocking — DONE (PR #306)

Shipped as per-IP refcounted locks in `pkg/docker/netrules/manager.go`
(`lockIP`). Same-IP Exists+Insert mutual exclusion preserved; different IPs
no longer serialize. See `ip_lock_test.go`.

## cluster_promote is recovery-replication-bound, not fsync-bound (latency)

- **What:** live bench 2026-07-11 (3× t3.medium, branch build, netlink):
  `cluster_promote` p50 = 23ms on BoltDB and 25ms on raft-wal — the Phase 3
  log-store swap moved nothing. `applyCommand` runs
  `externalizeCommandRecovery` before every apply, which synchronously PUTs
  the recovery blob to **every other member** (wall clock = slowest peer) —
  the code comment in `recovery_replication.go` says it runs "twice per
  create (opReserve and opPlace)". That, not the raft fsync, owns promote.
- **Why it matters:** warm create;dur = create leg (~17ms, Tier 1 working) +
  promote (~23ms) — the ≤30ms Tier 1 gate fails at 40-44ms until promote
  sheds the sync replication. The api-side cost is bigger still: opReserve
  pays the same replication before the create even starts.
- **Plan:** `plans/warm-create-latency-tier2-recovery-replication.md` —
  inline small secret-free payloads in the Raft command (the original wire
  shape, so mixed-version-safe both directions); blob mesh remains only for
  legacy sealed bytes / oversized specs. Raft-quorum durability is strictly
  stronger than today's best-effort mesh for failover recreate.
- **Status:** IMPLEMENTED 2026-07-11 (PR #307, stacked on PR #306):
  `inlineRecoveryEligible` gate in `recovery_replication.go`, externalize-mode
  metric, determinism-parity + replay + threshold-crossing regression tests.
  **Remaining:** operator bench re-run (plan T4) to confirm `create;dur`
  p50 ≤ 30ms / `cluster_promote` ≤ 8ms, then close this entry.
- **Start (for the bench re-run):** `make integration-benchmark-docker-only`
  + `-sparse` with `SB_NETRULES_BACKEND=netlink`, all-WAL raft; prior
  artifacts `integration-tests/reports/cluster-3-mixed-docker-bench-{baseline,netlink,netlink-wal}.json`.

## netrules backend switch on iptables-legacy hosts — DONE

Counter parity (`translator_linux.go`) makes exec↔netlink cleanup
interoperate on iptables-nft hosts. For iptables-legacy hosts: sandboxd now
logs a boot warning when `SB_NETRULES_BACKEND=netlink` meets a legacy
iptables (`netrules.WarnIfLegacyIptables`, wired in `pkg/daemon`), and the
drain-before-switch procedure is documented in `setup/single-node.md` +
`packaging/.env.template`.

## netlink live enforcement probe + bench backend gate — CODE DONE, live run pending

Closed the two open PR #306 review findings 2026-07-11:
- **UC-98** (`integration-tests/suite/netrules_test.go`): egress deny rule
  must DROP real traffic from inside the sandbox (control sandbox proves the
  target reachable; denied sandbox must time out; unrelated egress must flow).
- **Bench backend gate**: `aerolvm_netrules_backend` expvar (exec | netlink |
  disabled, recorded in `netrules.NewWithOptions`) + benches fail when
  `AEROL_BENCH_EXPECT_NETRULES` doesn't match `/v1/metrics`.

**Remaining:** both only prove things on a live cluster — fold into the next
operator integration run (the Tier 2 T4 bench re-run is the natural slot:
set `AEROL_BENCH_EXPECT_NETRULES=netlink`, UC-98 runs in the same suite pass).

## Promote-fail rollback can leave a ghost Placed row (latent, cluster)

- **Status:** fixed in Tier 1.5 (`OverlapCreateAndPromote` / self-wins
  promote-fail now always `DeletePlacement`). See
  `plans/warm-create-latency-tier1.5-seal-promote-overlap.md`.
- **What was wrong:** promote-fail rollback in `cluster_handler.go` used
  Destroy+CancelReservation only; `CancelReservation` is a no-op on Placed,
  so an errored-but-committed Raft place left a ghost row until reconcile
  (~5 min).
- **Fix:** every promote-fail path (overlapped reserved + sequential
  self-wins) calls `DeletePlacement`; reserved-path create-FAIL after
  promote-OK retracts the same way.
## netrules Manager mutex head-of-line blocking

- **What:** shard `Manager.mu` per-container-IP (or move to lock-free netlink
  ops) so concurrent creates don't serialize their Block/Clear/Apply calls.
- **Why:** `pkg/docker/netrules/manager.go` guards every Block/Clear/Apply with
  a single `Manager.mu` (`manager.go:46`). Under concurrent creates every
  sandbox's netrules op queues behind one lock.
- **Caveat / when it matters:** `plans/warm-create-latency-tier1.md` §6 scopes
  p99 / concurrency OUT — the plan's targets are p50 (single create), which
  never contends the mutex. Once the netlink backend lands, each op is sub-ms
  so the critical section shrinks. This only becomes the next bottleneck if
  concurrent-create p90/p99 throughput becomes a stated goal.
- **Note on correctness:** the mutex is load-bearing — it serializes the
  non-atomic `Exists`+`Insert` pair (`manager.go:51`). Sharding must preserve
  per-IP mutual exclusion, not remove it.
- **Depends on / blocked by:** Phase 1 netlink backend landing first (sub-ms
  ops are what make the mutex the next-visible cost).
- **Start:** `pkg/docker/netrules/manager.go`.

## Remove the legacy recovery-blob emit path (inline-only recovery) — PLANNED, do not start yet

- **What:** delete the blob fallback Tier 2 kept: the `inlineRecoveryEligible`
  gate, blob emit + member PUT fan-out, `command.SealedSecrets`,
  `PlacementSecrets.LegacySealed`, and the dual-contract tests; oversized
  specs (>4KiB) become a create-time validation error instead of a slow path.
  Fetch-on-miss + the local recovery store STAY (snapshot-joined voters need
  them even in a 100%-inline world).
- **Why:** with zero deployments there are no legacy sealed-secret sandboxes,
  no old logs, no mixed-version clusters — the compat machinery guards
  nothing and costs dual-path reasoning on every future recovery change.
  ~400–700 lines removed; makes "no secrets in the Raft log" structural
  (the field stops existing).
- **Caveat (why not yet):** it is a wire-compat break, valid only while the
  zero-deployments premise holds — re-verify before starting. Blocked on
  PR #306 + #307 merging and the Tier 2 T4 bench gate passing, so the
  latency stack is proven before its code is reshaped.
- **Start:** `plans/remove-legacy-recovery-blob-path.md` (tasks T1–T7;
  T5's snapshot-join fetch-on-miss regression test comes FIRST).
