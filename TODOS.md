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
- **Start:** `internal/cluster/recovery_replication.go`
  (`storeAndReplicateRecoveryBlob`), `recovery_store.go` fetch path; bench
  artifacts `integration-tests/reports/cluster-3-mixed-docker-bench-{baseline,netlink,netlink-wal}.json`.

## netrules backend switch on iptables-legacy hosts — DONE

Counter parity (`translator_linux.go`) makes exec↔netlink cleanup
interoperate on iptables-nft hosts. For iptables-legacy hosts: sandboxd now
logs a boot warning when `SB_NETRULES_BACKEND=netlink` meets a legacy
iptables (`netrules.WarnIfLegacyIptables`, wired in `pkg/daemon`), and the
drain-before-switch procedure is documented in `setup/single-node.md` +
`packaging/.env.template`.

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
