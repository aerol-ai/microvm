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
