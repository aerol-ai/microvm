# Warm create latency Tier 2: inline recovery payloads (40ms → ≤30ms gate unlock)

Status: **DONE — shipped in v0.6.0 (PR #307); T4 live bench run 2026-07-12.**
T4 results (fresh 3× t3.medium, all-WAL raft, netlink verified by
`AEROL_BENCH_EXPECT_NETRULES`, release build): `cluster_promote` p50
**23–25ms → 10–11ms**; warm `create;dur` p50 **40–44ms → 28ms sparse
(≤30ms gate PASS, p90 30ms, 8/8 warm hits, zero image resolves) / 32ms
burst (2ms over, 2/10 warm-pool misses in-burst)**; externalize metric
across all 3 nodes inline=1043 / blob=0 — the blob mesh never fired.
Residual 10–11ms promote is the raft round itself (probe creates entering
at the leader measure 9.6–12.9ms), not replication — shaving it further is
Tier 3 territory. Follow-up to
`plans/warm-create-latency-tier1.md` (gates run 2026-07-11) and the TODOS
entry "cluster_promote is recovery-replication-bound". Tier 1 + 1.5 got the
create leg to 17ms and the seal to 0ms, but the ≤30ms warm-p50 gate failed
at 40–44ms because `cluster_promote` measures **23–25ms — identical on
BoltDB and raft-wal**. The cost is not the Raft fsync: `applyCommand`
synchronously stores and replicates a recovery blob to **every** alive
control-plane member before the Raft apply, and it does this **twice per
create** (opReserve on the router, opPlace on the owner). This plan takes
that replication off the critical path for the common case by carrying
small, secret-free payloads **inline in the Raft command** — the wire shape
the FSM already supports — and leaving the blob machinery to the cases that
actually need it.

**Acceptance target: warm p50 ≤ 30ms burst AND sparse on the standard bench
topology (3× t3.medium + gp3, netlink, all-WAL), i.e. `cluster_promote`
p50 ≤ 8ms.** Semantics-preserving: no change to what survives owner death,
no change to FSM state for a given create, no new failure windows for
failover recreate (inline payloads ride the Raft log, which is *stronger*
durability than today's blob mesh). Single-node / `EnableCluster=false`
untouched.

Owner rules that apply: boot-path call-out (`/touch-create-sandbox`,
pr-review §2); **cluster correctness** (pr-review §6 / CLAUDE §6) — this
touches `applyCommand`, the FSM apply path, and recovery replication, all
high-risk; regression tests next to every file changed; mixed-version
rollout analysis mandatory in the PR description.

## 1. Measured problem (live bench 2026-07-11)

| Stage | p50 | Note |
|---|---|---|
| `create_with_id` (docker_pool + netrules + readyproto) | 17ms | Tier 1 working |
| `cluster_seal` | 0ms | Tier 1.5 overlap working |
| `cluster_promote` | **23–25ms** | identical BoltDB vs raft-wal |
| `create;dur` total | 40–44ms | gate ≤30ms FAILED |

`RecordPlacement` → `applyCommand` → `externalizeCommandRecovery`:

1. `newRecoveryBlob` — JSON-encode {sandboxID, redacted spec, secret
   ref+version, legacy sealed bytes}, ref = sha256 (content-addressed).
2. `storeAndReplicateRecoveryBlob` — local file write **+ fsync + rename**
   (`recovery_store.go`), then concurrent HTTP PUT to every alive
   control-plane member; wall clock = slowest peer; **first error fails the
   create**.
3. Only then the Raft apply (leader-forward + commit, the part Tier 1
   Phase 3 optimized — a minority of the 23–25ms).

The router's `ReserveOnTarget` pays the same externalize+replicate again
before the create even starts (visible in the api−server gap, not in
`create;dur`).

## 2. Why the blob mesh exists (what must be preserved)

| Property | Mechanism today | Constraint on any fix |
|---|---|---|
| Voter FSM applies need the payload (spec feeds the name index, owner watcher, failover recreate) | Blob pre-replicated to all members; `hydrateCommandRecovery` resolves locally, `recoveryResolver` network-fetch as fallback | Every voter must still materialize identical FSM state at apply time — deterministically |
| Failover: new owner needs spec + secret handle **after the old owner is dead** | Blob exists on every surviving member | Payload must survive owner death with at least Raft-quorum durability |
| Raft log / snapshot size stays small | Log carries Name + RecoveryRef only; snapshot retains refs, `RetainSnapshotRefs` GCs files | Inline payloads must be size-bounded |
| Legacy sealed secret bytes stay OUT of the immutable Raft log (deletable on destroy) | Sealed bytes live only in 0600 blob files, deleted by `deletePlacementRecoveryLocked` | **Never** inline `SealedSecrets` — the log and snapshots are not erasable per-sandbox |

The load-bearing observation: for the **modern create path**, the payload is
a redacted spec (no credential material — `RedactClusterSecrets` strips it)
plus `SecretRef`/`SecretVersion`, which is a provider *handle*, not secret
material. That payload is typically well under 2KiB. Carrying it in the
Raft command replicates it to every voter **through Raft itself** — the
exact durability the blob mesh approximates, minus two HTTP fan-outs and a
per-peer fsync, and *stronger* on failover (quorum-committed vs
best-effort-mesh).

## 3. Design: inline small secret-free payloads; blob path only for the rest

`externalizeCommandRecovery` gains a size/content gate:

```
inline-eligible iff:
  len(cmd.SealedSecrets) == 0            // never put sealed bytes in the log
  AND encoded payload ≤ inlineRecoveryMaxBytes (4096)
```

- **Inline-eligible (the warm-path case):** skip `newRecoveryBlob`, skip
  store+replicate entirely. The Raft command keeps `Spec`, `SecretRef`,
  `SecretVersion` inline — the ORIGINAL wire shape. FSM apply:
  `hydrateCommandRecovery` is already a no-op when `RecoveryRef == ""`;
  `opPlace`/`opReserve` handling is unchanged. **Verified at implementation
  time:** `storePlacementLocked` splits an inline payload into each voter's
  *local* recovery store at apply time under the same content-addressed ref
  the blob path would compute — so a blob file still lands on every voter
  (written locally, not pushed over HTTP pre-apply), destroy-time deletion
  and snapshot GC behave identically, and the stored FSM row is
  byte-identical between the two wire shapes (pinned by the determinism
  parity test).
- **Not eligible (legacy sealed bytes, or oversized spec):** today's path,
  byte-for-byte — externalize, store locally, sync-replicate to all
  members, apply with `RecoveryRef`.

`opReserveBatch` applies the gate per reservation (mixed batches are fine —
each reservation already externalizes independently).

**Threshold rationale:** 4KiB × hashicorp/raft's apply batching stays orders
of magnitude under suggested entry limits; a 10k-placement FSM snapshot
grows by ≤40MiB worst-case if every spec is at the cap (typical specs are
~0.5–1KiB → ~5–10MiB), against blob files of the same total size today.
`inlineRecoveryMaxBytes` is a const with a rationale comment, not config —
an env knob would create per-node divergence in what the leader emits
(harmless, but pointless surface).

### What this deliberately does NOT change

- The blob store, replication, fetch-on-miss resolver, snapshot
  `RetainSnapshotRefs` GC, and `/internal/recovery/` endpoints all stay —
  they serve the residual path and every pre-existing ref-carrying row.
- `hydrateCommandRecovery` / `resolveRecoveryRef` lazy point-reads stay —
  historical placements still carry refs.
- Admission (`applyReservationEncodedLocal`) sees the original command
  either way — unchanged.

### Expected numbers

| Stage | Today | After |
|---|---|---|
| `cluster_promote` p50 | 23–25ms | ~4–8ms (leader forward + WAL commit only) |
| `create;dur` p50 | 40–44ms | **~22–27ms → gate ≤30ms PASS** |
| Router reserve (api-side, per create) | same replication again | same win again (~15–20ms off api−server gap) |

## 4. Mixed-version rollout (cluster-correctness call-out)

Inline is the original command shape, so compatibility is symmetric:

| Emitter | Applier | Result |
|---|---|---|
| New node emits inline | Old voter applies | Old FSM applies inline natively (`RecoveryRef==""` → hydrate no-op) — the pre-recovery-store code path, still tested |
| New node emits inline, forwards to OLD leader | Old `ApplyEncoded` | Hydrate no-op → old leader **re-externalizes** (its own behavior) → cluster behaves as today until the leader upgrades |
| Old node emits ref | New voter applies | Unchanged ref path: local blob or fetch |
| Replay/restore of mixed log | Any | Deterministic: inline entries self-contained; ref entries resolve via retained blobs / fetch — exactly today's replay contract |

No ordering requirement on the rollout; the latency win lands when the
leader (for reserve) and the owner+leader (for promote) run the new build.
Rollback-safe: old builds apply inline commands correctly.

**FSM determinism:** for the same create, an inline command and a
pre-hydrated ref command must produce identical placement rows (same Name,
Spec, SecretRef/Version, ports/hostname preservation). This is the core
regression test (§6.2).

## 5. Failure modes (new/changed)

| Codepath | Prod failure | Handling | vs today |
|---|---|---|---|
| Inline create, owner dies after commit | Spec+handle in Raft log/FSM on quorum | Failover recreate reads FSM spec directly | **Strictly better** — today a blob PUT that raced the death can be missing on some members (fetch may 404 if survivors lack it) |
| Inline create, voter restarts and replays | Log entry self-contained | Applies deterministically | Better — no blob-file dependency for replay |
| Oversized/legacy create | Unchanged blob mesh (~20ms, rare) | Unchanged | Same |
| Threshold edge (spec crosses 4KiB between reserve and place) | Reserve inline, place blob (or vice versa) | Both shapes valid per-command; FSM state converges (spec preservation rules already handle partial payloads) | New but benign — add explicit test |
| Raft log growth | Bounded by threshold × create rate | Log truncation after snapshot, as today | Snapshot grows by inline spec bytes (≤4KiB/row); measured call-out in PR |

Secret-material rule is preserved by construction: `SealedSecrets` never
inlines, and the modern path's `SecretRef` is a handle. Anyone adding a new
payload field to `command` must extend the eligibility gate — enforced by a
test that fails if `commandCarriesRecoveryPayload` and the inline gate
drift.

## 6. Tests (mandatory, next to the files they cover)

1. `recovery_replication_test.go` — eligibility gate: small secret-free →
   inline (no store call, no replication calls — assert via injected `put`
   counter); legacy sealed → blob; > threshold → blob; batch with mixed
   eligibility.
2. `fsm_*_test.go` — **determinism parity**: inline command vs equivalent
   ref command (blob pre-seeded) apply to identical placement rows,
   including Name index, ports/hostnames preservation on re-place, and
   opReserve name-uniqueness enforcement from an inline spec.
3. Replay: restart FSM, replay a log with interleaved inline + ref entries;
   assert final state matches; assert refless rows create no GC work.
4. Reserve/place threshold-crossing pair (§5) converges.
5. Promote-path integration (bench, operator-run): burst + sparse re-run;
   gate `create;dur` p50 ≤ 30ms and `cluster_promote` p50 ≤ 8ms; assert
   `aerolvm_cluster_recovery_externalize_total{mode="inline"}` covers the
   bench creates (new metric, one counter, two label values).

## 7. Rollout & verification

1. Land behind no flag — inline eligibility is deterministic and
   backward-compatible both directions (§4). (If review disagrees, the
   cheap flag is `SB_CLUSTER_INLINE_RECOVERY=false` → force-blob; default
   true.)
2. Re-run `make integration-benchmark-docker-only` +
   `integration-benchmark-docker-sparse` (netlink, all-WAL): expect
   ~22–27ms p50; the sparse suite's hardened ≤30ms assertion becomes the
   regression gate.
3. Watch `aerolvm_cluster_promote_retract_total` (unchanged paths) and the
   new externalize-mode counter for an unexpected blob-path share.

## 8. Open questions (for eng review)

1. Threshold value: 4KiB proposed; is there a real workload with >4KiB
   redacted specs (huge env maps / many mounts) that deserves measurement
   first?
2. Should the residual blob path ALSO drop from sync-to-all to
   sync-to-one + async-mesh (fetch-on-miss covers stragglers)? Deferred
   here — it only pays off for legacy/oversized creates; the failover
   window analysis (owner + chosen peer dual failure) is its own §5.
3. Snapshot size guard: emit a metric for FSM snapshot bytes so growth is
   observable before it matters?

## NOT in scope

- Async promote / async retract (Tier 3 — semantics-changing).
- Durable `Creating` FSM state to re-enable promote overlap (Tier 3
  candidate recorded in the Tier 1.5 plan).
- Removing the recovery blob store or its endpoints (needed for residual
  path + historical rows).
- NVMe/io2 (`plans/nvme-datadir.md`).

## Implementation tasks

- [x] **T1** — Eligibility gate in `externalizeCommandRecovery` (+ const,
  rationale comment, externalize-mode metric
  `aerolvm_cluster_recovery_externalize_total{inline,blob}`)
- [x] **T2** — Regression tests §6.1–6.4 (`recovery_inline_test.go` for the
  gate + batch mixing; `fsm_recovery_inline_test.go` for determinism parity,
  mixed-log replay, name-index-from-inline-spec, threshold crossing)
- [x] **T3** — PR call-outs: boot-path (§2 pr-review), cluster-correctness
  (§4 rollout matrix, §5 failure modes), coverage at ~85% — branch
  `perf/warm-create-latency-tier2-inline-recovery`, stacked on PR #306
- [ ] **T4** — Bench gate re-run (burst + sparse, netlink, all-WAL) —
  ≤30ms p50 with `cluster_promote` ≤8ms; update Tier 1/1.5 plan status
  lines to "gate MET" with the artifact paths
- [ ] **T5** — Close the TODOS entry ("cluster_promote is
  recovery-replication-bound") pointing here (after T4 confirms the gate)
