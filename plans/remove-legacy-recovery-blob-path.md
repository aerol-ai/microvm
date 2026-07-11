# Remove the legacy recovery-blob emit path (inline-only recovery)

Status: **DONE — implemented 2026-07-12** (branch
`refactor/inline-only-recovery`), after all three pickup gates cleared:
#306/#307 shipped in v0.6.0, the T4 bench passed (sparse 28ms ≤ 30ms gate,
promote 10–11ms, inline=1043/blob=0), and the zero-producer premise was
re-verified in-tree (T1). T5's snapshot-join fetch-on-miss regression test
was written and committed FIRST, before any deletion. Net ~1,650 lines
removed / ~290 added; full offline suite green. Follow-up simplification
to `plans/warm-create-latency-tier2-recovery-replication.md`: Tier 2 made the
blob path a residual fallback; this plan deleted the fallback so **inline is
the only way a recovery payload travels**, and the dual-path reasoning burden
disappears.

## 0. Premise — what makes this deletable at all

This plan is a **wire-compat break** and is only valid pre-deployment:

- **Zero production deployments / users.** No existing Raft logs to replay,
  no mixed-version clusters to roll through, no sandboxes whose recovery
  records carry legacy sealed secret bytes.
- **Verified in-tree 2026-07-12:** nothing in the current build *produces*
  `PlacementSecrets.LegacySealed` on the create path (no producers outside
  tests). The only non-test uses are compat *readers*:
  `internal/service/cluster_secrets.go:218` (legacy branch of
  `openPlacementSecrets`) and the pass-through clones in
  `internal/cluster/client.go` / `agent.go`. The modern path seals via
  `PutClusterSecretsForRecipient` and ships only `SecretRef`/`SecretVersion`
  (a provider handle — log-safe).
- **If a real deployment exists when you pick this up, STOP.** Mixed-version
  symmetry and old-log replay compatibility come back as requirements and
  this plan is void — the Tier 2 dual-path design is the correct end state
  in that world.

## 1. Why

Tier 2 (PR #307) kept the blob path for two cases: legacy sealed bytes
(must never enter the immutable Raft log) and encoded records > 4KiB. With
zero deployments, case one has **zero instances** and can be removed at the
source (delete the legacy sealed-secrets carrier entirely), and case two is
better handled as a **validation cap** than as a second delivery mechanism.
What the deletion buys:

- One emit path. `inlineRecoveryEligible` and every "which path is this
  create on?" branch disappears.
- The synchronous member-to-member blob **PUT replication** machinery goes
  away (client fan-out + server endpoint half).
- `SealedSecrets` stops existing on the wire (`command`), in recovery
  records, and in `PlacementSecrets` — the "no secrets in the log" rule
  becomes structural: there is no field to put them in.
- The dual-contract regression tests (mixed-version parity, threshold
  crossing, blob-forced re-points) are deleted rather than maintained.
- Net estimate: **~400–700 lines removed** across code + tests.

## 2. What goes vs. what stays

| Component | Fate | Why |
|---|---|---|
| `inlineRecoveryEligible` + externalize gate (`recovery_replication.go`) | **DELETE** | Inline becomes unconditional; oversized is rejected upstream (§3), with a defensive error (never a blob fallback) at externalize. |
| `newRecoveryBlob` emit side + `storeAndReplicateRecoveryBlob` (pre-apply fsync + PUT fan-out) | **DELETE** | The entire reason Tier 2 existed. Nothing emits blobs anymore. |
| Blob **PUT** half of the internal HTTP surface (`PublicInternalRecoveryPath` handler write side + client push in `recovery_replication.go`) | **DELETE** | Only the pre-apply push used it. |
| Blob **GET** half + `fetchRecoveryBlob` + `fsm.recoveryResolver` / `resolveRecoveryRef` fetch-on-miss (`client.go:182`, `fsm.go:1607`) | **KEEP** | Hidden dependency: a voter joining from a **snapshot** receives FSM rows with `RecoveryRef`s but no local files, and must pull them from a peer once. Needed even in a 100%-inline world. |
| Local recovery store (`recovery_store.go`): content-addressed Put/Get/Delete, destroy-time erasure, `RetainSnapshotRefs` GC | **KEEP** | Shared machinery: `storePlacementLocked` splits inline payloads into it at apply; failover recovery reads from it. Not "the old path". |
| `command.SealedSecrets` wire field + `cloneBytes` plumbing (`fsm.go`, `client.go:376/396/418/599/628`, `agent.go:261/276`) | **DELETE** | No producers. Removing the field makes the secrets-in-log mistake unrepresentable. |
| `PlacementSecrets.LegacySealed` (`cluster.go:183`) + `hasUpdate` term | **DELETE** | Modern path is `Ref`+`Version` only. |
| Legacy branch of `openPlacementSecrets` (`cluster_secrets.go:218`) | **DELETE** | Reader for records that can no longer exist. Keep `UnsealClusterSecretsForNode` only if the snapshot-restore path (`cluster_secrets.go:216`, `SealedPayload`) still needs it — verify in T1; that caller is the *modern* sealed-recipient record, not the legacy blob field. |
| Command-level ref hydration (`hydrateCommandRecovery` ref branch, `fsm.go:1593`) + `commandName` ref/inline duality | **DELETE / SIMPLIFY** | Only blob-emitted commands carried `RecoveryRef`; with no emitters and no old logs, the branch is dead. Row-level `resolveRecoveryRef` (fsm.go:1558) stays — that serves snapshot-joined voters (see GET row above). |
| `aerolvm_cluster_recovery_externalize_total{inline,blob}` metric | **DELETE** | Meaningless with one path. (`aerolvm_netrules_backend` is unrelated — stays.) |
| Dual-contract tests: `recovery_inline_test.go` blob/threshold cases, `fsm_recovery_inline_test.go` ref-parity + mixed-replay, blob-forced re-points in `recovery_replication_additional_test.go` / `coverage_final_test.go` / `agent_wrapper_additional_test.go` | **DELETE / RE-POINT** | Their purpose was protecting the two-path world. Keep the single-path versions: inline apply determinism, name uniqueness from inline specs. |

## 3. The one product decision: 4KiB becomes a validation cap

Without a blob fallback, an encoded recovery record (redacted spec + secret
handle) larger than `inlineRecoveryMaxBytes` (4096) must be **rejected at
create** with a clean 400 (`apihttp.WriteStoreAwareError` shape), not silently
routed to a slower path.

- Enforce in `normalizeCreateRequest`/validation (service layer, before
  admission — zero boot-path cost for valid requests: the encode already
  happens at externalize; do it once and reuse, or bound by a cheap
  field-length proxy and keep the exact check at externalize).
- Keep a **defensive error** at externalize (never fall back): if a record
  crosses the cap after service-side mutation, fail the create loudly —
  that's a bug, not a routing decision.
- Typical records measure ~0.5–1KiB; 4KiB is ~4–8× headroom. The cap is
  relaxable later (bump the const) without wire changes, since Raft entry
  size is the only pressure.
- Document the limit wherever create-request limits are documented (five-tab
  SDK docs page for limits, if/when one exists — follow the docs hard rules).

## 4. Tasks

- [ ] **T1 — Re-verify the premise.** Re-run the producer grep
  (`LegacySealed`, `SealedSecrets` writers outside tests); confirm no
  deployment exists; check whether `cluster_secrets.go:216`'s
  `SealedPayload` (modern recipient-sealed record) keeps
  `UnsealClusterSecretsForNode` alive — if yes, only the `:218` legacy branch
  dies, not the function.
- [ ] **T2 — Validation cap** (§3) + regression test (oversized create →
  400; boundary at exactly 4096 accepted).
- [ ] **T3 — Delete the emit path**: gate, blob emit, PUT fan-out + PUT
  endpoint half, `command.SealedSecrets`, Name/RecoveryRef strip-and-restore
  logic, externalize metric. Externalize reduces to "encode, defensive size
  check, return cmd unchanged".
- [ ] **T4 — Delete the legacy secrets carrier**: `PlacementSecrets.
  LegacySealed`, clone sites in client.go/agent.go, `openPlacementSecrets`
  legacy branch. Cluster-secrets modern flow (`Ref`/`Version`, seal/open/
  delete) untouched.
- [ ] **T5 — Simplify FSM**: remove command-level hydrate ref branch +
  `commandName` duality; **keep and regression-test** row-level fetch-on-miss
  (snapshot-join scenario: restore FSM from snapshot with refs, empty local
  store, resolver serves — if no such test exists, ADD it before deleting
  anything).
- [ ] **T6 — Tests**: delete/re-point per §2 table; package stays ≥85%
  (`/maintain-coverage` before the PR).
- [ ] **T7 — PR call-outs** (pr-review §7 is mandatory): state the
  single-version premise explicitly — new builds cannot join or replay
  clusters/logs created by pre-removal builds; fresh clusters only; both
  rollout directions are breaks. Release-note it. This is the inverse of
  Tier 2's "symmetric mixed-version" section — silence is not acceptable.

## 5. Verification

- Full offline suite green; `internal/cluster` ≥85%.
- New/kept regression tests: snapshot-join fetch-on-miss (T5), oversized
  reject (T2), inline apply determinism + name uniqueness (kept from Tier 2).
- One live smoke on a fresh 3-node cluster (can ride any scheduled
  integration run): create/destroy/failover-recreate + `create;dur` p50
  unchanged vs the T4 numbers (this plan must be latency-neutral — it
  deletes idle code).

## 6. Risks

- **Snapshot-join blindspot** is the one real way to break failover with
  this deletion — hence T5's test-first requirement.
- **A deployment appearing mid-plan** voids §0; check before starting, not
  after.
- Oversized-spec rejection is user-visible; without the §3 error being clear
  (which field, what limit), it becomes a support trap.

## 7. Out of scope

- Changing the snapshot format (rows keep carrying `RecoveryRef`s; embedding
  payloads in snapshots trades this plan's simplicity for snapshot bloat).
- The modern cluster-secrets flow (`PutClusterSecretsForRecipient` /
  `OpenClusterSecretsForNode`) — untouched.
- Flipping `SB_NETRULES_BACKEND` default to netlink (separate decision,
  gated on T4 + UC-98 evidence).
