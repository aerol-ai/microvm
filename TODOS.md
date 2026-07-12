# TODOS

Deferred work items with enough context to pick up cold. Each entry says
what, why, the caveat that motivated capturing it, and where to start.

## Audit Firecracker outbound NAT path (networking)

- **What:** Trace an FC sandbox's outbound connectivity on a live host
  (`iptables -t nat -L`, `sysctl net.ipv4.ip_forward`) and either document
  where NAT/forwarding comes from or file the gap as a bug.
- **Why:** The containerd-engine plan review (2026-07-12) grepped the whole
  tree for masquerade/ip_forward/br_netfilter handling and found **none** —
  for Docker sandboxes, dockerd provides NAT invisibly; for FC VMs on /30
  TAP slots (`internal/network/tap/host.go` does link/addr only), nothing
  in the repo answers "how does traffic leave the box." Either it lives in
  host bootstrap outside the repo (document it) or FC sandboxes have no
  outbound internet (fix it).
- **Caveat (why it's a TODO, not a bug yet):** may be a non-issue —
  Terraform user-data / manual host provisioning may already set it up;
  30 minutes on any FC bench host settles it.
- **Depends on / blocked by:** access to a live FC host (bench topology
  has them). Nothing else.
- **Start:** any FC node: `iptables -t nat -L POSTROUTING -n`,
  `sysctl net.ipv4.ip_forward`, then `Terraform/` node bootstrap templates
  if rules exist but aren't in-repo.

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
- **T4 bench re-run DONE 2026-07-12** (v0.6.0 release build, fresh 3×
  t3.medium, all-WAL, netlink, `AEROL_BENCH_EXPECT_NETRULES=netlink`):
  `cluster_promote` p50 **23–25ms → 10–11ms**; warm `create;dur` p50
  **40–44ms → 28ms sparse (gate ≤30ms PASS) / 32ms burst (2ms over)**.
  Externalize metric across all 3 nodes: inline=1043, blob=0 — 100% of
  cluster creates rode the Raft log; the blob mesh never fired. Artifacts:
  `integration-tests/reports/cluster-3-mixed-docker-bench.json` (idle burst),
  `-sparse-bench.json`, `-bench-suiteload.json` (under full-suite load).
- **Remaining 10–11ms promote is the raft round itself, not replication:**
  probe creates entered at the leader still measure 9.6–12.9ms with zero
  variance spikes — leader WAL fsync + follower ack + owner→leader forward
  on t3.medium/gp3. Closing this entry; shaving promote below ~8ms is a
  Tier 3 shape (e.g. the withdrawn promote-overlap with a durable Creating
  FSM state) and only matters if the burst 2ms overshoot matters.

## netrules backend switch on iptables-legacy hosts — DONE

Counter parity (`translator_linux.go`) makes exec↔netlink cleanup
interoperate on iptables-nft hosts. For iptables-legacy hosts: sandboxd now
logs a boot warning when `SB_NETRULES_BACKEND=netlink` meets a legacy
iptables (`netrules.WarnIfLegacyIptables`, wired in `pkg/daemon`), and the
drain-before-switch procedure is documented in `setup/single-node.md` +
`packaging/.env.template`.

## netlink live enforcement probe + bench backend gate — DONE (live-verified 2026-07-12)

Closed the two open PR #306 review findings 2026-07-11; both live-verified on
the T4 bench cluster (v0.6.0, netlink on all 3 nodes) 2026-07-12:
- **UC-98** (`integration-tests/suite/netrules_test.go`): egress deny rule
  must DROP real traffic from inside the sandbox — **PASS** on the netlink
  backend (control sandbox reached the target; denied sandbox timed out;
  unrelated egress flowed).
- **Bench backend gate**: `aerolvm_netrules_backend` expvar + benches fail
  when `AEROL_BENCH_EXPECT_NETRULES` doesn't match `/v1/metrics` — gate
  confirmed netlink on the burst, sparse, and suite-load runs.

With UC-98 + a full live soak now on record, flipping the server default
`SB_NETRULES_BACKEND` exec→netlink is unblocked (separate decision/PR).

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

## Remove the legacy recovery-blob emit path (inline-only recovery) — DONE 2026-07-12

Executed after all three gates cleared (#306/#307 merged in v0.6.0, T4 bench
passed, zero-deployments premise re-verified in-tree). Branch
`refactor/inline-only-recovery`. What shipped:

- Deleted: `inlineRecoveryEligible` gate (inline is now the only path), blob
  emit + member PUT fan-out (`storeAndReplicateRecoveryBlob`,
  `replicateBlobToMembers`, both `putRecoveryBlobToMember`s, the PUT half of
  `PublicInternalRecoveryPath`), `command.SealedSecrets` +
  `command.Name`/`RecoveryRef`, `PlacementSecrets.LegacySealed`,
  `Placement.SealedSecrets`, `SealedSecretsOf` (no callers), command-level
  `hydrateCommandRecovery`, the `openPlacementSecrets` legacy branch, the
  externalize metric, and the dual-contract tests. Net ~1,650 lines removed,
  ~290 added.
- Kept (per plan §2): blob GET half + `fetchRecoveryBlob` +
  `resolveRecoveryRef` fetch-on-miss and the local recovery store — pinned
  FIRST by `TestFSMSnapshotJoinFetchOnMiss` (snapshot-joined voters get rows
  with refs but no local files).
- New product rule (§3): specs whose recovery record encodes >4KiB are
  rejected at create with a clean 400 (`cluster.ErrRecoveryPayloadTooLarge`,
  boundary-tested at exactly 4096); cluster mode only — single-node keeps no
  cap. Defensive re-check at command encode + on the leader-forward path.
- "No secrets in the Raft log" is now structural: no field exists to carry
  sealed bytes anywhere in cluster state.
