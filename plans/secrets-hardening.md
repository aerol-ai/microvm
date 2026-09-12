# Secrets hardening: cross-node failover, audit trail, env sealing, and the provider seam

Status: **IMPLEMENTED 2026-08-08** (T1–T13 + E1a/E1b/E2a/E2b/E3a/E4) — ENG-REVIEWED 2026-08-06
decisions below remain the build contract. E2b's repository mechanism is closed;
the external witness/export receivers and their retention policy remain deployment
requirements. Remaining gated/out-of-scope: E3b (own justification), E3c
(deferred), E5 (out of scope).
Supersedes the 2026-08-02 draft, whose Phase 0 premise is now proven and whose
provider-seam and env-storage designs were both wrong (see §Corrections).

Covers GitHub issues #80, #81, #82, plus two defects and one API change that
had no issue when this plan was written.

---

## 0. What was proven, not assumed

A throwaway two-node probe was run against `internal/service` during review and
then deleted. Both nodes shared **one** `*secrets.Cipher`, so nothing below is
a key-distribution problem:

```
STEP 0  redacted spec → raft ............. env=map[OPENAI_API_KEY:REDACTED_EXAMPLE]
        STEP 1  node-a (owner) open .............. OK, password recovered
        STEP 2  node-b, payload NOT replicated ... cluster secret ref "..." not found
        STEP 3  node-b, payload REPLICATED ....... recipient "node-b" is not allowed to open
        STEP 4  node-b, legacy empty-nodeID ...... recipient "" is not allowed to open
```

Two independent walls block cross-node failover, not one:

```
        create on node-a                     failover to node-b
        ────────────────                     ──────────────────
  req ──┬─ RedactClusterSecrets ─► raft ──►  redacted spec  ─┐
        │    (Env NOT stripped ✗)                            │
        └─ seal(recipient=node-a) ─► node-a SQLite           │
                                     └── never replicated ───┼─► WALL 1
                                                             │   ref not found
                    even if you copy the row over ───────────┴─► WALL 2
                                                                 recipient denied
```

**WALL 1** — the sealed payload lives only in `cluster_secrets` on the sealing
node (`store.go:144` calls it "the local secret-reference backend"). The only
production writer is `cluster_secrets.go:180`; all four callers pass
`c.SelfNodeID()` (`cluster_ownership.go:149`, `cluster_handler.go:377`,
`clustercreate.go:254`, `overlap.go:139`). Nothing replicates the row.

**WALL 2** — the envelope is recipient-bound. Even with the bytes in hand, a
different node is refused.

The 2026-08-02 draft only addressed WALL 1, so as written it would have shipped
a fix that still fails.

**Blast radius:** bounded. Only `failover.policy=recreate` sandboxes reach the
recreate path (`service.go:929`: *"default sandboxes remain non-HA and are
orphaned on owner death"*). The failure is loud (sandbox is not recreated), not
silent corruption.

Also proven: `Env` survives `RedactClusterSecrets` (`:265` deep-copies but
never clears) and rides into the Raft log in plaintext. At rest, `env_json` is
plain JSON (`store.go:3642`) protected only by `chmod 0600` (`store.go:766`).

### The constraint that shapes every fix

`plans/remove-legacy-recovery-blob-path.md` (DONE 2026-07-12) deleted
`command.SealedSecrets`, `PlacementSecrets.LegacySealed`, and
`Placement.SealedSecrets` so that **"no secrets in the Raft log" is structural —
no field exists to carry sealed bytes.** Putting ciphertext back in the log is
off the table. (The 2026-08-02 draft listed it as an option; deleted.)

---

## 1. Decisions (eng review 2026-08-06)

| # | Decision |
|---|---|
| D2 | One plan, all phases. Not split. |
| D3 | Seal to a recipient **set** (owner + N failover candidates) and push the sealed row to those peers. Preserves recipient binding; keeps bytes out of Raft. |
| D4 | **Bounded first-backup ACK, then asynchronous remainder** (see §3e), **only** for `failover.policy=recreate`. Every cluster mode fails and retracts a zero-ACK HA create. Default non-HA creates remain unchanged. **Plus** a KMS provider as a configurable alternative backend — both ship, operator picks. |
| D5 | Recipient drift is repaired by an owner/leader-coordinated, generation-fenced reseal. The new sealed row and retired-recipient cleanup journal commit atomically before the Raft CAS; cleanup is released only after the promoted generation is visible. |
| D6 | One fail-closed seal+fanout helper. Ownership replay must never publish an unredacted spec when sealing fails. |
| D7 | One shared contract suite runs against **both** providers (offline fake for KMS); live KMS behind the `integration` tag. |
| D8 | Sealed env lives in its **own row, read on demand**, mirroring `sealMounts`/`loadMounts`/`GetMounts`. The hot row scanner never carries env. |
| D9 | `Get`/`List` **omit env by default**; an explicit opt-in returns it, and that read is audited. |
| D10 | The `Provider` interface owns **ref → plaintext**, not crypto. `Put(secret) → ref`, `Open(sandboxID, ref, nodeID) → plaintext` (signature settled in 3d-4). |

### Corrections to the 2026-08-02 draft

1. Phase 0 was "verify the claim" — now proven, so it is mandatory work, not a gate.
2. "Replicate ciphertext through the recovery payload" — **deleted**, violates the structural rule.
3. "#80 is demand-gated, do not start without a customer" — **reversed by D4**. KMS ships.
4. The `Seal(plaintext, recipient string)` sketch was single-recipient — **wrong**, bakes in the bug (D3 needs sets).
5. The crypto-only provider seam was **wrong** — a KMS provider under it would still need local bytes and would not fix failover (D10).
6. "Keep the package at ~85%" undersells these packages. Measured 2026-08-06:
   `internal/service` 95.1%, `internal/store` 95.1%, `internal/cluster` 95.9%,
   `pkg/secrets` 96.5%. CLAUDE.md's floor remains ~85%; for this program hold
   these packages at their measured baseline (~95%), not the floor.
7. Env-at-rest proposed mutating `env_json` in place — **wrong**, that column is projected by the shared row scanner on six read paths (D8).

---

## 2. The provider seam (D10) — build this first

Everything else depends on it. Pure refactor first, no behavior change, own PR.

```go
// pkg/secrets — the thing that varies between backends is HOW A NODE REACHES
// PLAINTEXT, not which cipher runs. That is what this abstracts.
type Provider interface {
    // Put seals secrets for a set of recipients and makes them retrievable
    // by every recipient. Returns a log-safe handle.
    Put(ctx context.Context, sandboxID string, s Secrets, recipients []string) (Handle, error)
    // Open resolves a handle to plaintext for nodeID, by whatever means the
    // backend allows — local row, peer fetch, or a KMS call. sandboxID is
    // explicit (3d-4): the audit event needs it, and a not-found cannot
    // recover it from a handle that resolved to nothing.
    Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error)
    Delete(ctx context.Context, sandboxID string) error
}
```

**CORRECTED 2026-08-07.** An earlier version of this table said the `kms`
provider needs no local storage and any authorized node can therefore open any
secret. **That is wrong and it was the most consequential error in this plan.**
KMS wraps *keys*; it does not store your ciphertext. `PutClusterSecret` writes
`SealedPayload` (`cluster_secrets.go:180`) and something must keep doing so.
KMS removes WALL 2 (recipient binding). It does nothing about WALL 1.

| | `local` | `kms` |
|---|---|---|
| Key custody | node-local AES key file | KMS wraps the data key into the v4 envelope's `WrappedKey` field |
| Ciphertext storage | `cluster_secrets` row | `cluster_secrets` row — **same**, KMS stores nothing |
| Distribution | bounded first-backup ACK, then async remainder (§3e) | the same bounded/async fan-out — shared machinery |
| Who can take over | only pre-sealed recipients | any node with IAM access **that received the bytes** |
| Boot cost (HA creates only) | **bounded sync min-ACK** (`SB_SECRET_FANOUT_MIN_ACK_WAIT`, default 2s) then async remainder; local seal always | KMS wrap rides fan-out; first peer ACK may add ≤2s on HA create |
| Membership drift | owner/leader reseals to live replacements; requires one current holder | same distribution repair; KMS removes recipient-bound decrypt restrictions but still needs the bytes |
| Offline `make test` | native | fake; live behind `integration` tag |

The fan-out is therefore **shared across both providers**, not a local-provider
workaround. Providers differ in key custody and who may decrypt, not in whether
distribution is needed.

### KMS is optional. `local` is the default.

**`SB_SECRET_PROVIDER` defaults to `local`.** A deployment that never sets it
never contacts AWS, Vault, or any external service. This is stated explicitly
because "default-off" is ambiguous for a multi-valued flag — the values are
`local` | `awskms` | `vault`, and the off-state is `local`, not "no provider".

Concretely, without KMS:

- **The confirmed failover defect is still fixed.** T1-T4 — recipient-set
  sealing, sync peer fan-out, the seal/fanout helper — is entirely
  local-provider work. Slice 1 has no external dependency of any kind.
- **`make test` is unaffected.** Local is native; the KMS path is exercised by
  an offline fake, with live KMS only behind the `integration` tag per
  CLAUDE.md's offline-test rule.
- **Nothing else in slices 1-3 touches a provider boundary** beyond the seam
  itself.

What you give up without it is centralized key custody and the ability for any
IAM-authorized node that holds the ciphertext to decrypt it. The local provider
now repairs recipient drift by resealing from a live holder, so KMS is not a
substitute for distribution or cleanup. `failover_ready` remains false until a
replacement holder ACKs the current generation.

The only item that genuinely requires an external KMS or Vault by nature is
**E5** (brokering short-lived credentials from the customer's vault), which is
gated on its own eng review and excluded from the totals.

When T10 lands, add the `SB_SECRET_PROVIDER` row to `setup/config-defaults.md`
with this rationale. Do not add it before the flag exists in `config.go` — that
file is an operator reference for shipped flags, not a spec.

`internal/service/cluster_secrets.go` stops touching `s.cipher` directly.

**Resolved (Codex #11):** the router selects the recipient set once at reserve
time and records it in the Raft reservation; the target obeys that recorded
set. Section 3d-1 defines the source membership view and serialization rule.

---

## 3. Fix cross-node failover (D3, D4, D5, D6)

### 3a. Recipient-set sealing + fan-out

- `sealClusterSecrets` already takes `recipients []string`; the canonical,
  identity-bound v4 envelope carries the authenticated recipient set and seal
  generation.
- Compute the set **only** when `failover.policy=recreate`. Otherwise seal to
  self exactly as today and skip the fan-out entirely.
- For an HA create, wait a configured bounded interval for the first backup
  acknowledgement before success, then fan out to the remaining recipients
  asynchronously. A zero-ACK create is retracted and fails; `failover_ready`
  reflects authoritative possession of the promoted generation.
- New peer-receive endpoint in `internal/cluster/`: idempotent on retry,
  rejects **unauthenticated** pushes (node-ID-bound cluster mTLS plus PAT and
  `d.Auth`), no-op under `Noop`.

### 3b. One fail-closed helper (D6)

Seal failure currently has three undocumented policies across four sites:

| Call site | Today | After |
|---|---|---|
| `cluster_ownership.go:150` | warn + continue (silently drops the ref) | **fail closed**: skip only the unsafe row, report the error, and continue safe rows |
| `cluster_handler.go:378` | error + rollback | **fail closed** |
| `clustercreate.go:255` | rollback + return | **fail closed** |
| `overlap.go:139` | error into channel | **fail closed** |

**Current scope after §3e:** strict HA create requires the local sealed row plus
one authenticated backup acknowledgement within the bounded wait. It does not
wait for every recipient. The actual holder count is recorded and
`failover_ready` reports authoritative possession; delete-fanout cleanup is
generation-fenced as specified in **3d-3**.

### 3c. Membership repair and no-vacuum retirement (D5)

Recipient sets are generation-bound, not permanently frozen. When any intended
recipient dies, the owner (or leader for ownerless records) opens the current
generation, seals to live replacements, and requires a replacement ACK before
the Raft CAS. The sealed row and an `awaiting_promotion` retired-recipient
journal are one SQLite transaction. Peer deletion starts only after Raft shows
the new generation, so a crash cannot create either a recovery vacuum or a
forgotten ciphertext copy. Removed/decommissioned node IDs remain pending in
the delete outbox until their authenticated generation-scoped DELETE ACKs;
membership disappearance is never treated as cleanup success.

### 3d. Corrections that ride along

- `service.go:920` comment is wrong: *"eventually move the placement to a node
  whose key matches"* — it is not a key problem, and reassign will fail on
  every node. Rewrite.
- `config.go:2047` tells operators creds *"will not survive failover without a
  shared key"*, implying they survive with one. They do not. Rewrite.
- Delete `SealClusterSecrets` (`:84`) — seals to wildcard `"*"`, zero
  production callers, a footgun sitting next to recipient-set code.

---

## 4. Audit trail (#82)

The hook exists: `beginClusterSecretOpen()` (`metrics.go:153`), called at
`cluster_secrets.go:199` with `defer done(err)` covering every return. It only
bumps expvar counters today.

**Blocker: there are no typed errors to classify.** Every error is an inline
`errors.New` (`:115, :174, :177, :202, :353, :379`). Sentinels come first, then
the audit `Reason` switches on them. Reason is a class
(`not_found`, `recipient_denied`, `version_mismatch`, `decrypt_failed`), never
the wrapped error string, which can carry caller input.

Event payload: timestamp, actor (node ID), ref, sandbox ID, result, reason.
Never plaintext, never PII.

**Implementation hardening verified 2026-09-05.** Cluster capabilities bind to
the Raft placement incarnation. Standalone WASM capabilities bind to a stable
digest of the per-create toolbox token, which rotates when a deterministic
sandbox ID is reused. The existing compound `sandbox_audit_acl` row stores that
incarnation, while the live sandbox row keeps the exact current-lifecycle
pointer. A monotonic establishment sequence selects post-delete history without
trusting node clocks. Create rollback removes only the aborted incarnation,
while normal delete retains evidence until the audit-retention prune. There is
no legacy any-incarnation authorization fallback and no second lifecycle/GC
table.

All lifecycle-wide destroy paths first commit an exact owner/incarnation
`deleting` fence in Raft. The FSM rejects reassignment, failover recreation,
spec/route/volume mutation, and secret reseal while fenced; reserved rollback
uses the same state. Runtime, exact-incarnation secret/outbox, and external
artifact finalizers complete before the final placement delete. A failed step
retains retry anchors, and leader cleanup expires abandoned fences only when the
owner is unavailable. Peer secret scans are page-bounded and retire replicas
whose exact authoritative lifecycle has disappeared.

Worker delivery remains asynchronous, but an available loopback ingest socket
does not disable the spill path. Every worker carries both destinations so a
temporary IPC failure produces a durable spill record instead of an invisible
gap.

Also cover the two non-cluster decrypt sites currently outside the seam:
`service.go:1883` (`UnsealRegistry`) and `service.go:1941` (`loadMounts`).

**Resolved (Codex #12):** the audit path uses a durable spill-aware JSONL sink,
correlation IDs, explicit gap records and metrics, retention checkpoints,
strict hash-chain verification, off-node witnessing, and an enterprise-required
authenticated exporter. WORM retention remains an operator-owned external
control and is not claimed by this repository.

**Resolved (Codex #9):** every explicit env materialization is audited. Env is
opt-in on read, while ordinary `List` remains quiet and omits it.

---

## 5. Env sealing (D8, D9)

### 5a. Own row, read on demand

Mirror mounts exactly: `sealEnv`/`loadEnv` + a dedicated `GetEnv(sandboxID)`.
The shared row scanner (`store.go:3642`) stops carrying env entirely.

Why not in place: that column is projected by the scanner used by `Get`,
`List`, `ListByOwner`, `ListByRuntime` and two more paths, and
`netstats.go:219` calls `store.List(ctx)` **every poll tick** (open issue #70).
Sealing in place adds an AES-GCM open per sandbox per tick, forever.

There is no plaintext migration path. The schema has no `env_json` column;
writes require the cipher and reads accept only the sealed `sandbox_env` row.

### 5b. API contract change (D9)

`Get`/`List` omit env by default; an explicit opt-in returns it and audits the
read. This is a **breaking change** for callers reading `sandbox.Env` today —
needs SDK work across all five languages and a docs page per CLAUDE.md
(five-tab `syncKey="lang"`, no curl).

### 5c. Redact `Env` from the replicated spec

- Add `Env` to `clusterSealedSecrets` (`:60`); clear it in
  `RedactClusterSecrets` (`:265`); re-merge on open.
- **Unclaimed benefit:** `Env` currently counts against the 4KiB
  `ErrRecoveryPayloadTooLarge` cap. Moving it out *shrinks* recovery records.

`PlacementSecrets.Version` and the envelope version are separate invariants.
This implementation has no mixed-version writer gate: only the current
placement-ref version and identity-bound envelope v4 are accepted.

---

## 6. Test plan

Baselines measured 2026-08-06 — hold these packages at their measured ~95%
baseline (CLAUDE.md floor remains ~85%).

**CRITICAL / mandatory regression test:** cross-node failover open. A node in
the recipient set opens a sandbox sealed by a different node. This is the test
that would have caught the confirmed defect; the probe in §0 stood in for it.

Shared contract suite (D7) runs every case below against **both** providers:

| Area | Cases |
|---|---|
| Recipient set | policy unset → no set/no fanout; `=recreate` → owner+N; cluster < N; single-node Noop |
| Fan-out | all peers ok; peer down → rollback when no backup ACKs; partial 2/3; ownership-replay seal failure → no Raft write; 4xx vs timeout distinct |
| Open | owner opens; **new owner in set opens (CRITICAL)**; not in set → distinct legible error; wrong recipient denied; version mismatch |
| Audit | success → exactly one event; each failure class → one event + reason; no plaintext in payload; nil logger/sink no panic |
| Peer endpoint | idempotent on retry; rejects foreign push; Noop no-op |
| Env at rest | sealed round-trip; schema has no plaintext env column; upsert preserves sealed env |
| Env in spec | absent from redacted spec; re-merged on open; missing or mismatched sealed state rejects loudly |
| API | `Get`/`List` omit env by default; opt-in returns it; opt-in read is audited |
| Boot path | **default create latency unchanged** (benchmark assertion) |

Integration-tagged (`integration`): kill owner → recreate with creds, on each
provider; add/drain nodes after create → reseal, replacement ACK, promoted
generation, and old-recipient cleanup; live KMS.

Per CLAUDE.md: `internal/cluster`, `internal/store`, and the boot path each
need a regression test next to the file they change plus a PR call-out.

---

## 7. Performance

### Create-path cost, item by item (authoritative — updated 2026-08-07)

| Item | Create-path cost | Note |
|---|---|---|
| T1-T4 | **~0** | Fan-out is async (§3e). Recipient set reuses the list `SelectPlacement` already builds. `opReserve` is written either way. |
| T5 | 0 | Pure refactor. |
| T6 audit | **0 *if* async** | Hot sites are `UnsealRegistry` (`service.go:1903`) and `loadMounts` (`service.go:2038`, via `StartSandbox`). Requirement, not a guarantee — see below. |
| **T7 env row** | **+1 INSERT + AES-GCM seal, on nearly every create** | **The one real cost.** Calibrated: `PutMounts` (`store.go:4053`) is the identical shape and already runs on the create path at `service.go:1585` and `wasm.go:228`. |
| T8 | 0 | Read path. Actually *removes* work from `List`. |
| T9 | ~0 | Map copy plus a version check. |
| T10 KMS | 0 | The wrap rides the async fan-out. No cache means no warm-up either. |
| T11-T13 | 0 | Messages, a deletion, docs. |
| E1a | 0 create; **List: 1 store read per page** | Computed on read from the live memberlist, never persisted, never in the row scanner. Per-page, not per-row: one membership snapshot, one `PlacementsByIDs`, one batched `cluster_secrets` summary read for the page's recreate-policy rows (the first cut ran one SQLite query and one O(members) alive-set rebuild per row — the same shape as #70, relocated; closed in a stacked PR after #403). |
| E1b | 0 | New read endpoint. |
| E2a / E2b | **0 *if* async** | Chain append is serialized, but off the request path behind the bounded channel. |
| E3a | **0 *if* async** | Event emission must not be synchronous on create. |
| **E3b** | **+1 rule per sandbox** | **Added 2026-08-07 — this table previously omitted it.** NFLOG/conntrack rule installation lands where per-sandbox netrules already run during sandbox setup (`pkg/docker/client.go:213-282`, `BlockAllEgress`/`ClearBlockAllEgress` keyed by container IP). Measure it. |
| E4 | 0 on create | Daemon boot only; first-call KMS round-trip is off the create path. |

### The actual risk is discipline, not design

**Four items are "must be async" requirements rather than guarantees** — T6,
E2a, E2b, E3a. Nothing in the code will stop an implementer writing a
synchronous audit append into `StartSandbox`; only review will. If create
latency regresses during this program, that is overwhelmingly the likely cause.

What catches it: CLAUDE.md non-negotiable #2 makes the boot-latency call-out
mandatory on every PR touching this path; `overlap.go:141` already records a
`cluster_seal` stage to carry the measurement; slice 1's exit criterion is
literally *"default create latency unmoved"*; and the HA-create benchmark case
gives the regression signal.

### Other performance notes

- **Env reads.** D8 keeps them off the shared row scanner. D9 keeps them off
  `List`.
- **Facade list hydration.** Ingress selects at most one placement page and
  sends that exact sandbox-ID set to each owner. Daytona and E2B peers apply the
  set before loading/serializing facade metadata, so a 100-row page cannot turn
  into an unbounded owner inventory response at the 100,000-sandbox target.
- **KMS call volume.** Decided: no cache. Unwraps happen only on failover
  recreate, ~20 req/s worst case — about 0.1% of quota. See the KMS cache
  section.
- **CI.** `internal/cluster` runs ~4.5 min; D7 roughly doubles the credential
  suite. Acceptable, but watch it.

---

## 8. NOT in scope

| Deferred | Why |
|---|---|
| Placement filter for stale recipient sets | **Closed:** placement uses the promoted recipient set and drift triggers reseal |
| Resealing protocol on membership change | **Closed:** live-holder reseal with generation CAS, staged retirement, and replacement ACK |
| `toolbox_token` at rest | **Closed as enterprise follow-up** — encrypted in the existing sandbox row; see §8a |
| Fixing issue #70 (full-table scan) | D8 avoids making it worse; fixing it is its own work |
| `internal/cluster` test flake | Captured in TODOS.md instead |
| Credential brokering into sandboxes | **Out of scope 2026-08-07** — customer secrets arrive at create time; revisit only on an explicit customer ask |

### 8a. `toolbox_token` — enterprise follow-up closed

The token remains a platform-minted, sandbox-scoped control-plane credential
and remains `json:"-"`, so it cannot enter the Raft-replicated spec. Writes
always encrypt it with the existing secret cipher and sandbox-bound AAD into
`toolbox_token_sealed`; there is no plaintext token column. Reads authenticate
and decrypt it through the shared sandbox scanner.

This deliberately reuses the sandbox row and lifecycle rather than adding a
second token table, reconciliation loop, or garbage collector.

## 9. What already exists — reuse, do not rebuild

- `beginClusterSecretOpen()` — the audit hook, already wrapping both paths.
- `sealMounts`/`loadMounts`/`GetMounts` — the exact shape D8 copies.
- The v4 envelope's explicit named recipient set and sandbox/ref binding.
- `opts.Timing.RecordStage("cluster_seal", …)` — boot-path measurement, free.
- Recovery store + blob GET fetch-on-miss — kept deliberately for
  snapshot-joined voters. **Read before designing the fan-out**; note it pulls
  from a *live* peer, which is exactly what failover does not have.

## 10. Failure modes

| Failure | Test? | Handled? | User sees |
|---|---|---|---|
| **GAP-1: owner dies inside the async fan-out window** | yes (UC-58c + unit) | **closed for all cluster modes** — bounded sync min-ACK wait (`SB_SECRET_FANOUT_MIN_ACK_WAIT`, default 2s), and zero ACKs retract/fail the create | create either has a backup ACK or fails |
| Failover node not in recipient set | yes (D5 case) | must be distinct error | clear error — **required**, not a decrypt failure |
| Partial fan-out | yes | 3d-2 holder-count rule | create succeeds at owner + ≥1; holder count surfaced |
| Peer unreachable during fan-out | yes | durable put-outbox + reconciler retry + metric (not silent in-memory drop) | nothing at create; `failover_ready` stays false |
| Ownership replay seal failure | yes | fail closed for that row; redact unconditionally; continue reconciling safe rows | reconciliation error; no credential enters Raft |
| Missing sealed env during recreate | yes | strict canonical ref and required sealed row | **fails loudly**, never boots with silently empty env |
| KMS unreachable during fan-out | yes (fake) | durable put-outbox + reconciler retry | nothing at create; `failover_ready` stays false |
| **Holder count lost on restart** | yes (ReFanout unit) | **fixed** — boot `ReFanoutClusterSecrets` rebuilds holders from local rows + async re-push | brief `failover_ready=false` until peers ACK again |

### GAP-1 — minimum HA contract CLOSED; configured redundancy converges asynchronously

**A successful HA create never returns with fewer than two holders.** It has the
owner plus at least one peer ACK for the current lifecycle and seal generation.
The asynchronous window only concerns additional configured recipients; losing
more holders than the minimum one-node-failure contract before convergence can
still exhaust redundancy.

Distribution cannot be fully asynchronous because that leaves an unbounded
owner-loss race. The contract is a **bounded sync
min-ACK wait** (`SB_SECRET_FANOUT_MIN_ACK_WAIT`, default 2s): create waits for
≥1 peer ACK (or the timeout), then continues any remaining peer pushes async.

What bounds the remaining window:

- Default create waits up to ~2s for the first backup ACK — typically closes
  the race for healthy clusters before `201` returns.
- If 0 peers ACK in the window, the sealed row is retracted, peer deletes are
  durably enqueued, and create fails.
- `failover_ready` reads **false** until all configured recipients are verified
  at the current generation (E1a); this reports convergence beyond the minimum
  successful-create contract.
- Fan-out retries with bounded backoff; failures emit
  `aerolvm_secret_fanout_failures_total` and feed the operator alert.
- Live chaos: integration `UC-58c` (kill-owner-mid-fan-out, `integration` +
  disruptive gate).

Who is affected: only `failover.policy=recreate` sandboxes. Non-HA sandboxes
are explicitly orphaned on owner death regardless.

There is no zero-ACK success mode. `failover_ready=false` after a successful
create only means the remaining configured replicas are still converging, not
that the create returned with only the owner holding ciphertext.

### The other critical gap

A sandbox created with a silently empty environment. It boots, looks healthy,
and misbehaves. The canonical ref, strict envelope binding, and required sealed
row make this a hard failure instead.

## 11. Parallelization

| Lane | Work | Depends on |
|---|---|---|
| A | Provider seam refactor (§2) | — |
| B | Sentinels + audit events (§4) | — |
| C | Cross-node failover (§3) | A |
| D | Env sealing + API (§5) | A |

Lanes A and B start in parallel. C and D both wait on A, then run in parallel —
but C touches `internal/cluster` + `pkg/api/clustercreate` while D touches
`internal/store` + SDKs, so they do not collide.

## Implementation Tasks

- [x] **T1 (P1, human: ~1d / CC: ~2h)** — pkg/secrets — Extract the `Provider` interface (ref → plaintext, D10)
  - Surfaced by: Codex #5 — crypto-only seam preserves the cross-node failure
  - Files: `pkg/secrets/`, `internal/service/cluster_secrets.go`
  - Verify: `go test ./pkg/secrets/... ./internal/service/...`, no behavior change
- [x] **T2 (P1, human: ~4h / CC: ~45m)** — internal/service — Answer recipient-set selection before coding §3
  - Surfaced by: Codex #11 — reserve writes spec before sealing on target
  - Files: `pkg/api/clustercreate/clustercreate.go:136`, `overlap.go:139`
  - Verify: written decision in this plan + a determinism test
- [x] **T3 (P1, human: ~1w / CC: ~1-2d)** — internal/service+cluster — Recipient-set sealing + async peer fan-out
  - Surfaced by: §0 WALL 1 + WALL 2, both proven
  - Files: `cluster_secrets.go`, `internal/cluster/`, 4 seal call sites
  - Verify: CRITICAL cross-node failover regression test
- [x] **T4 (P1, human: ~2d / CC: ~3h)** — internal/service — One fail-closed seal+fanout helper (D6)
  - Surfaced by: Code quality — 3 undocumented failure policies across 4 sites
  - Files: `cluster_ownership.go:149`, `cluster_handler.go:377`, `clustercreate.go:254`, `overlap.go:139`
  - Verify: failure/partial cases and ownership replay never sends plaintext to Raft
- [x] **T5 (P2, human: ~3h / CC: ~30m)** — internal/service — Typed sentinel errors
  - Surfaced by: Audit `Reason` has nothing to switch on
  - Files: `cluster_secrets.go:115,174,177,202,353,379`
  - Verify: each class asserted
- [x] **T6 (P2, human: ~1d / CC: ~2h)** — internal/service — Audit events on every provider read (#82)
  - Surfaced by: #82 partial — metrics exist, per-event records do not
  - Files: `metrics.go:153`, `cluster_secrets.go:199`, `service.go:1883`, `service.go:1941`
  - Verify: one event per path, no plaintext
- [x] **T7 (P2, human: ~2d / CC: ~4h)** — internal/store — Env to its own sealed row (D8)
  - Surfaced by: Performance — scanner + `netstats.go:219` per-tick decrypt
  - Files: `store.go`, `internal/service/service.go`
  - Verify: sealed round-trip, no plaintext schema column
- [x] **T8 (P2, human: ~3d / CC: ~5h)** — pkg/api+sdk — Env opt-in on `Get`/`List` (D9)
  - Surfaced by: Codex #8 — breaking API contract decision
  - Files: `pkg/api/v1/`, all five SDKs, docs `.mdx`
  - Verify: default omits, opt-in returns + audits
- [x] **T9 (P2, human: ~2d / CC: ~4h)** — internal/service — Redact env from spec + strict sealed-row restore (§5c)
  - Surfaced by: Codex #10 — placement vs envelope version conflated
  - Files: `cluster_secrets.go:60,211,265`
  - Verify: missing or mismatched sealed state fails loudly, never silent empty env
- [x] **T10 (P2, human: ~3d / CC: ~5h)** — pkg/secrets — KMS provider + offline fake + shared contract suite (D7)
  - Surfaced by: D4 — both backends ship
  - Files: `pkg/secrets/`, `internal/config/config.go`, `integration-tests/`
  - Verify: both providers pass one suite; live KMS behind `integration`
- [x] **T11 (P3, human: ~1h / CC: ~10m)** — docs+config — Fix the two wrong operator messages
  - Surfaced by: Architecture A3/A4
  - Files: `service.go:920`, `config.go:2047`
  - Verify: review
- [x] **T12 (P3, human: ~30m / CC: ~5m)** — internal/service — Delete legacy wildcard `SealClusterSecrets`
  - Surfaced by: Code quality — zero production callers, seals to `"*"`
  - Files: `cluster_secrets.go:84`
  - Verify: `make test`
- [x] **T13 (P3, human: ~1d / CC: ~2h)** — docs — Operator docs: provider choice + D5 recipient repair
  - Surfaced by: D5 — repair and its live-holder boundary must be operator-visible
  - Files: `docs/src/content/docs/`, `docs/src/content.config.ts`
  - Verify: `make docs-build`

## Slice-0 decisions — DECIDED 2026-08-07

The four gates that blocked slice 1, plus one supersession. All four are now
decided; slice 1 may start.

### 3d-1. Who computes the recipient set — the router, at reserve time

**The router picks. The target obeys. Nobody recomputes.**

`SelectPlacement` (`internal/cluster/placement.go:85-140`) already builds a
filtered `candidates` slice — excluding dead nodes, ineligible roles, members
with no advertised API URL, stale capacity heartbeats, and drained nodes — and
then discards everything except the one node `pickTwo` returns. That discarded
list is exactly the recipient set, already filtered for exactly the properties a
recipient needs.

```
ROUTER node                                    TARGET node
───────────                                    ───────────
SelectPlacement() ─► candidates[] (filtered)
                     pickTwo → target
                     recipients = target + N from candidates
ReserveOnTarget(..., Recipients) ── opReserve through raft ──┐
                                                             │
                                     forwarded create ───────┤
                                                             ▼
                                        seal to the RECORDED recipient set
                                        RecordPlacement(...) ── opPlace
```

Why this seam:

- The candidate list already exists and is already correctly filtered.
- `opReserve` goes through Raft, so it is **serialized on the leader**. Two
  racing creates cannot produce disagreeing sets — that is the race the gate
  existed for, closed by construction rather than by convention.
- `reservationCommand` (`internal/cluster/fsm.go`) carries the canonical,
  sorted `Recipients []string` set that every node must understand.

**N defaults to owner + 2 backups**, configurable. A cluster smaller than that
uses every eligible candidate. Boot replay (`cluster_ownership.go:149`) has no
reservation, so it seals for self and widens on the next mutation — it is a
backfill path, not a create.

### 3d-2. Partial fan-out — holder count, not a boolean

Neither "fail the create" nor "accept silent half-HA." **Success requires the
owner plus at least one backup to hold the secret; the actual holder count is
recorded and surfaced.**

Strict-all lets one flaky peer fail creates that would have been perfectly
recoverable. Silent partial is worse: the sandbox reports success and looks
highly available, but whether it survives depends on which specific node dies —
unpredictable and untestable.

Owner + ≥1 gives real redundancy and fails loudly when it cannot. E1a's
`failover_ready` reports the **actual holder count** rather than a boolean, so
"HA with 2 of 3 holders" becomes a true statement monitoring can act on.

### 3d-3. Failed-create leftovers — delete-fanout, not attempt-unique refs

**Delete-fanout on rollback and on destroy. Refs stay deterministic.**

Two reasons. Delete-fanout is required regardless: outside-voice #4 established
that peer rows are never cleaned up on sandbox *destroy* either, since
`DeleteClusterSecretsForSandbox` is local-only. And the collision risk is
smaller than it first appeared — `PutClusterSecret` is an upsert
(`store.go:4004`, `sealed_payload = excluded.sealed_payload`), so a retry that
reaches a peer **overwrites** the stale row rather than reading it. The real
leak is only peers a retry does not reach, which delete-fanout fixes and
attempt-unique refs would merely orphan under a new name.

Keeping refs derivable from `(sandboxID, incarnationID, version)` is worth
preserving. The incarnation component is mandatory: deterministic sandbox IDs
may be reused, but an old worker, delayed delete, or stale peer row must never
address the new lifecycle.

### 3d-4. `Provider.Open` takes the sandbox ID explicitly

```go
Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error)
```

Requiring handles to encode the sandbox ID would dictate opaque-token structure
to AWS KMS and Vault, which we neither control nor should constrain. The caller
always has the sandbox ID — it is how the handle was obtained. And the case that
decides it is the one that cannot work otherwise: a **not-found** audit event,
where the handle resolved to nothing and there is no payload to decode.

Explicit over clever.

### 3e. SUPERSEDES D4 — the fan-out is ASYNCHRONOUS

The caller waits only for the bounded first-backup ACK window; remaining
distribution runs asynchronously with bounded backoff. Every cluster mode
treats zero ACKs as a create failure.

This reverses D4's synchronous choice, which was made before E1a existed.
**E1a is what makes async defensible now**, and the pairing is load-bearing:

- `failover_ready` starts **false** and flips true only when the owner plus at
  least one backup actually hold the secret (3d-2).
- The system therefore never claims a guarantee it does not yet have. The window
  between `201 Created` and fan-out completion is *visible*, not silent.
- Because nobody is waiting, retries are cheap — use bounded backoff rather than
  a single attempt.
- Fan-out failure emits `aerolvm_secret_fanout_failures_total` plus a log line
  carrying sandbox ID, target peer, and error class, and feeds the operator
  alert from the §8 decision.

**The cost, stated plainly:** a successful create is protected against one
holder loss, but may not yet have reached every configured recipient. Losing
multiple holders before the remainder converges can exhaust redundancy.
`failover_ready` reports false until the full configured holder set is verified,
so the reduced-redundancy interval is visible. **E1a therefore moves from slice
3 into slice 1**, alongside the fan-out it guards.

Boot-path consequence: HA creates perform one bounded first-backup ACK wait.
Only the remaining recipients are fully asynchronous; default/non-HA creates
still make no peer call.

## E1b cluster-read model — DECIDED 2026-08-07

**Local log is the operational copy. Bounded owner-history fan-out serves OSS
reads. The off-node exporter is mandatory in enterprise mode.**

Four parts, all of them load-bearing:

1. **Always** write audit events to the local node's append-only log. That log
   is the source of truth on every build.
2. Serve `/v1/sandboxes/{id}/audit` by live fan-out to the bounded Raft-retained
   owner-node history, merged by timestamp, with an **explicit coverage block**.
   **Revised 2026-08-13 for the 2,000-node target:** missing or truncated index
   state fails explicitly (`503`) instead of launching an all-worker scan. The
   off-node exporter is mandatory in enterprise mode, so completeness does not
   depend on an unbounded discovery query. **Rate-limited** (see below).
3. Authenticated HTTPS batch export, or a programmatically wired
   `controlplane.AuditExporter`, advances a daemon-owned durable watermark;
   receiver-controlled cursors cannot skip local records.
4. Open-source mode may omit the exporter and use bounded owner-history reads.
   `SB_ENTERPRISE_MODE=true` fails boot unless either an authenticated HTTPS
   exporter (with a strong bearer credential) or a non-noop programmatic
   `controlplane.AuditExporter` is configured. Enterprise mode separately
   requires a non-noop external `controlplane.Witness`.

### The claim is gated on the sink, and this is not optional wording

**Do not claim dead-disk durability unless a real sink is wired.** On the
open-source build a node's disk loss is permanent record loss, and the docs must
say so plainly rather than implying the fan-out protects against it. Fan-out is
a *discovery* mechanism, not a durability one — it finds records whose location
nothing tracks; it cannot find records that no longer exist.

This is the same honesty rule as GAP-1 and the D14 gap marker: state the
boundary rather than let a reader infer a stronger guarantee than exists.

### Why fan-out, and why owner-forwarding was eliminated

The FSM now retains a bounded `AuditNodeIDs` owner history on the live placement
and copies it into the post-delete `AuditACL`. Normal reads are therefore
O(owner changes), not O(cluster workers). A sticky `AuditNodesTruncated` bit
makes the discovery API return `503`; the enterprise exporter is the complete
off-node record and avoids a fleet-wide amplification fallback.

### Rate-limit dimension — DECIDED 2026-08-07: per-identity **plus** a per-node ceiling

**Two limits, not one.**

1. **Per-identity bucket**, keyed to the resolved `Access`: the operator PAT gets
   its own, and in managed builds each `Identity.OwnerRef` gets its own.
   **Keyed to `OwnerRef`, not to the token** — a tenant must not be able to
   multiply its budget by minting more tokens.
2. **Global per-node ceiling** on total audit fan-out, independent of who is
   asking.

**Why both.** `requireAuth` (`pkg/api/middleware.go:67`) has exactly two
outcomes: a PAT authenticates as operator with unscoped fleet-wide access, and
any other bearer token goes to the `controlplane.Validator`. Under
`controlplane.Noop()` — **the open-source default** — the validator rejects
every non-PAT token, so **the OSS build has exactly one caller identity.** A
per-identity limit therefore does nothing there; the ceiling is the only part
that protects an open-source cluster. Conversely, per-identity is what stops one
tenant starving the rest in a managed build, which a ceiling alone cannot do.

**The two eliminated candidates, and why:**

- **Per-token** — meaningless in OSS (one token exists) and wrong in managed,
  because tokens are mintable and `OwnerRef` is the stable identity.
- **Per-sandbox** — wrong threat model. It bounds queries about a single
  sandbox while a caller sweeping a thousand different sandbox IDs gets a
  thousand times the fan-out unimpeded. The thing being protected is the
  cluster, not the sandbox.

**Design notes for build time:**

- The **operator bucket must be generous.** Operators run incident response, and
  a limiter that throttles someone diagnosing an outage has made things worse.
  Bound it, but do not tune it like a tenant.
- **On rejection: `429` with `Retry-After`.** Never a silent truncation.
- **Throttled internal fan-out composes with the coverage block.** A peer whose
  internal request was shed simply did not answer, so it appears as missing
  coverage — the existing E1b mechanism already reports it, and no separate
  signal is needed. Say this explicitly so nobody adds one.
- The ceiling is a **security parameter** (it bounds amplification), not a
  throughput tuning knob. Document it as such in `setup/config-defaults.md`
  when it ships.

### Rate-limiting is NEW machinery — scope it, do not assume it

Verified 2026-08-07: **there is no rate-limiting anywhere in `pkg/api` or
`internal/service`, and `golang.org/x/time/rate` is not in `go.mod`.** This is
not "add a limiter to the audit route." It is introducing rate-limiting to a
codebase that has none, which means:

- A new dependency. `golang.org/x/time/rate` is the boring, standard choice
  (**[Layer 1]** — do not hand-roll a token bucket).
- A new middleware sitting alongside `d.Auth` in the `pkg/api/v1` chain.
- A decision on the limit dimension — per-token, per-caller, or per-sandbox —
  which is **not yet made** and should be settled when E1b is built.
- Scope discipline: this decision rate-limits **the audit endpoint only.**
  Introducing the machinery will invite applying it elsewhere; that is separate
  work with its own review.

The rationale is not politeness, it is amplification. One audit request becomes
N internal requests across the cluster, so an unthrottled endpoint is a
cluster-wide amplification vector reachable by any authorized caller. That makes
the limiter a **security control**, not a nicety — and it is why it ships with
E1b rather than after it.

## KMS wrapping-material cache — DECIDED 2026-08-07: no cache

**Every open calls KMS. No unwrapped DEK is ever cached, in memory or on disk.**

### The volume does not justify a cache

Verified against the call sites:

- **KMS unwraps happen only on failover recreate.** `Provider.Open` is reached
  from `RecreateSandboxReport` (`service.go:948`, `:986`), driven by the owner
  watcher. The *frequent* decrypt path — `StartSandbox` → `loadMounts`
  (`service.go:2038`, `:2070`) and `UnsealRegistry` (`:1903`) — reads
  locally-sealed blobs through `s.cipher`, not cluster secrets, and D10 routes
  only cluster secrets through `Provider`. **KMS is never on the hot path.**
- **The burst is small.** `ownerWatcherInterval = 5s` and
  `maxRecreateFailuresBeforeReassign = 5` (`owner_watcher.go:16,25`). A node
  dying with 100 HA sandboxes is ~100 Decrypt calls on the happy path; the
  pathological case where every recreate fails is 100 × 5 = 500 calls over ~25
  seconds, about **20 req/s**. AWS KMS Decrypt quotas run to tens of thousands
  per second — roughly **0.1% of quota**.
- **§3e already removed the latency argument.** The async fan-out took the KMS
  wrap off the create path, which was the original reason to consider caching.

### The cost is the two properties KMS was adopted for

A cached plaintext DEK is key material KMS can no longer revoke. Disable the key
or pull the IAM grant, and any node with a warm cache keeps decrypting for the
cache lifetime. That defeats centralized revocation.

It also makes **CloudTrail incomplete**. KMS's own access log is part of the
evidence story this plan is built around, and a cache means it records a fraction
of actual reads.

That is the same failure mode as silent audit drops (D14) and silent partial
history (E1b), both rejected earlier today. The through-line of this plan is that
**a record must not imply completeness it does not have.** Caching DEKs would
violate it on the one log we do not control and cannot annotate.

### Escape hatch, gated on evidence

If a real deployment ever hits KMS throttling, add a short in-process TTL **then,
with measurements in hand** — not speculatively. Record the observed call rate
and the quota it approached in this section before adding it. A cache introduced
without that evidence is trading a proven security property for an unproven
performance one.

## E5 credential brokering — OUT OF SCOPE (2026-08-07)

**Reverses the acceptance made during the CEO review.** Do not build credential
brokering, Vault-backed customer secret storage, or transparent interception.

- Customer application secrets are provided **at create time**, from the
  customer's own systems. AerolVM may seal them at rest so they survive failover
  (slices 1-3). It must **not** require storing customer application secrets in
  an AerolVM-operated Vault or KMS as a product feature.
- **Platform KMS/Vault is only for AerolVM's own wrapping keys** — the DEK that
  protects cluster secrets. It is not a customer secret store. This narrows and
  clarifies T10's purpose rather than changing its design.
- **The "every use attributed" and "guest never holds the secret" claims are
  withdrawn** from this plan and from anything derived from it.
- Revisit only on an explicit customer ask.

### What this changes elsewhere

1. **The audit claim narrows, and the docs must say so.** T6 records what the
   *daemon* did: which credentials it opened, when, on which node. It cannot
   record what an agent does with a secret once that secret is inside the
   sandbox — that is invisible **by construction**, not by omission.
   Outside-voice #4 flagged the overclaim risk; it is now simply the truth.
2. **One breaking change, not two.** The T8/E5 overlap the CEO review accepted
   as a cost no longer exists. T8's own rationale is untouched: env still
   carries customer credentials, so keeping it out of `Get`/`List` responses is
   still correct.
3. **Slice 6 is removed**, not deferred. Totals are unaffected — E5 was already
   excluded pending its own estimate.
4. **AerolVM stays on the category norm.** Every competitor injects secrets as
   env vars visible inside the sandbox; E5 would have departed from that. The
   differentiation argument for departing is withdrawn with it.

## E2b tamper-evidence — DECIDED 2026-08-07: external witness, Reporter-first

**The product goal stays "tamper-evident." It is not downgraded.** What is
scoped is the witness channel: start with an off-node witness over the
control-plane seam, and add stronger stores later.

### v1 — witness over the control-plane seam

- Ship hash-chain **heads** (and optionally signed audit batches) off-node when
  a real control-plane sink is configured.
- **Verification** recomputes the local chain head and compares it to the last
  witnessed head. A mismatch means the local log was altered after that head
  was witnessed.
- **Open-source build (no-op sink):** local append-only plus integrity
  checksums still work for operations, but **do not claim tamper-evidence**
  until a real sink is wired. Managed and customer builds that configure a sink
  get the claim.

This mirrors the E1b rule exactly: the mechanism is additive, the *claim* is
gated on a real sink existing.

### Mechanical finding — `Reporter` cannot carry a head as it stands

`controlplane.Sample` is a **usage-metering** record: `Value float64`,
`Unit string`, `WindowStart/End time.Time`, with a doc comment stating it
"carries units, never money." A chain head is a hex digest. There is no field it
fits without abusing documented semantics, and `Report(ctx, batch []Sample)
error` returns only an error — no receipt, no witness-side timestamp.

**Recorded shape:** a sibling `Witness` interface in `pkg/controlplane`,
alongside `Reporter`, using the same no-op-by-default pattern the package
already establishes:

```go
// Witness records audit-chain heads off-node so retroactive tampering with a
// node's local log is detectable. No-op in the open-source build.
type Witness interface {
    WitnessHeads(ctx context.Context, heads []AuditHead) (WitnessReceipt, error)
}
```

The receipt matters: a witness that cannot tell you *when it recorded* a head
lets an attacker who later compromises the host backdate a forged chain.
Confirm this shape at build time — it is an implementation of the decision
above, not a change to it.

### The precise security property, stated so nobody overstates it

Reporter-first witnessing detects **retroactive** tampering: an attacker who
compromises the host *after* a head was witnessed cannot rewrite history covered
by that head without producing a mismatch.

It does **not** defend against a daemon that was already compromised when it
wrote. Such a daemon controls both the local chain and what it ships, so it can
emit a self-consistent forgery from the start. That is exactly the bar the
follow-ups raise.

**Detection granularity equals ship cadence.** Records written since the last
witnessed head can be rewritten undetected. The witness interval is therefore a
security parameter, not a performance tuning knob, and must be documented as
such.

### Follow-ups — stronger stores, same goal

- **WORM-backed head store**, so heads cannot be deleted or rewritten even by
  someone holding the sink credential.
- **Signatures from a key the daemon cannot read** — HSM or a separate signer
  process — so a compromised reporter credential is not sufficient to forge.

Either follow-up may land in this plan or the next. Neither is required for the
v1 claim, and neither changes the goal.

## Re-review decisions (eng review #2, 2026-08-07)

Delta-focused re-review after the CEO scope expansion. Two reversals, two
corrections, all verified against source.

| # | Finding | Decision |
|---|---|---|
| **REVERSAL** | **Peer-push auth: use PAT + `d.Auth`, not gossip-secret signing.** Every node-to-node HTTP call in this repo already authenticates with `Bearer <pat>` — `capacity_lease.go:242`, `agent.go:900`, `client.go:775/1116`, `recovery_replication.go:162`, `jsbundle_replication.go:75`, `wasm_migrate.go:65`. The closest analogue is the *same operation*: `recovery_replication.go:162` fetches a recovery payload from a peer with `Bearer <pat>`, received via `d.Auth(...)` at `routes.go:178`. Gossip-secret signing would be a second auth model on the same wire. | Reverses the earlier gossip-secret decision. Register the endpoint as `PublicInternalSecretPath` alongside the other six `/v1/cluster/internal/...` routes. |
| **SUPERSEDED** | Rollout flags were proposed for mixed-version deployment. | Recipient fan-out, env sealing, toolbox-token sealing, and canonical envelope/ref validation are now mandatory. Only provider selection remains configurable. |
| **CORRECTION** | **Boot-path table omits D13.** Under the `kms` provider an HA create costs fan-out **+ one KMS wrap** — a network round-trip on the boot path. | Add the row; measure and report it like every other boot-path change. |
| **CORRECTION** | **D13 was over-estimated.** The envelope carries `WrappedKey []byte`, so a KMS-wrapped DEK uses the same canonical v4 format. | 4 eng-days → **~2**. |

### Outside voice (codex, re-review pass) — 9 findings

| # | Finding | Resolution |
|---|---|---|
| 1 | **The §2 provider table still said KMS needs no local storage** — corrected in the CEO plan but not here, and this is the doc implementers read. | **Fixed above.** |
| 2 | **Env redaction contradicts "default creates unchanged."** `cluster_secrets.go:111-113` returns nil with no registry/mount secret, so most creates seal nothing today. Adding env would give nearly every create a ref and a fan-out. | **Decided:** redact env from every replicated spec and seal it locally (T7); **fan out only for `failover.policy=recreate`.** Non-HA specs are never used to recreate, so stripping env costs them nothing. |
| 3 | **Env side-row write needs atomicity.** Insert row → write sealed env as two steps means a crash yields the "healthy sandbox with empty env" failure this plan calls critical. | **Required:** single transaction, plus an explicit crash-between-writes rollback test. Gates T7. |
| 4 | **Peer secret deletes are unplanned.** Fan-out creates rows on peers; `DeleteClusterSecretsForSandbox` is local-only (`store.go:4040`) and `cluster_secrets` has no FK by design. | **Required:** delete fan-out on destroy, create rollback, partial fan-out, and promote failure. Tests for each. Gates T3. |
| 5 | **Stale peer rows can collide.** Refs are deterministic (`cluster-secret://sandbox/<id>/v1`), so a failed create with partial fan-out leaves remote rows a later retry may reuse. | **Required:** either delete-fan-out on rollback (see #4) or attempt-unique refs. Pick one before coding T3. |
| 6 | **"Rejects foreign pushes" is not achievable with PAT + `d.Auth` alone** — that is caller authorization, not peer identity. | **Closed:** secret PUT/DELETE + internal audit require **operator** (`Access.Operator` / fleet PAT) after `d.Auth`; receiver validates ref↔sandbox/version, live placement recipients, and self∈envelope recipients. Every cluster mode requires cluster-CA mTLS on the internal listener, rejects these routes on the public listener, does not downgrade after TLS failure, and binds every leaf to `node:<SB_NODE_ID>`. Generic SPIFFE identities are unnecessary for this contract. |
| 7 | **D5 causes reassign churn.** `owner_watcher.go:109` reassigns after 5 failures to another arbitrary candidate excluding only the current node; a recipient-denied error therefore walks the fleet. | **Required:** a recipient-aware stop rule so a recipient-denied open halts reassignment instead of cycling. Gates T3; needs a regression test next to `owner_watcher.go`. |
| 8 | **`Provider.Open(ctx, handle, nodeID)` carries no sandbox ID**, but the audit event needs one and a not-found event cannot recover it from an opaque handle. | **Required:** add `sandboxID` to the `Open` signature, or require handles to encode it. Decide at T1 — it is the interface definition. |
| 9 | **The API change is under-scoped.** `GetSandbox`/`ListSandboxes` are thin wrappers (`service.go:1987`) and internal workflows call `store.Get/List` directly. | **Required:** separate internal "with env" reads from public response omission. A default change in the store would break internal callers. Gates T8. |

Confirmed unchanged: D8/D15's flag conventions match the house pattern
(`getEnvBool("SB_X_ENABLED", false)`, rationale in `setup/config-defaults.md`,
which already has a "rule for flipping a default on" section). `config.go:562`
shows `SB_WASM_RESIDENT_HOST_ENABLED` was flipped default-on in v0.7.12 with a
documented escape hatch — precedent for D15's defect-fixes-default-on posture.

## Follow-up — audit read index (2026-09-11)

Review of PR #374 found the audit read path O(retained fleet events) per
page (full scan + full chain re-hash per request, 8 slots queueing to 504
under the 50 req/s limiter, unmetered peer fan-out). Closed in a stacked PR:
per-sandbox posting-list index over `secrets.jsonl` (`secret_audit_index`,
O(page) reads, re-based on retention, rebuilt from the file on any
disagreement), per-record verification on read with whole-chain verification
at boot / retention / `POST /v1/audit/verify`, fail-fast `429` on read-slot
saturation, and a separate per-node rate bucket on the peer fan-out
endpoint. Design and scale table: `plans/audit-read-index.md`.

The same review found the WASM worker's egress-audit spill re-implementing
the daemon's writer with a flock + fsync per event on the pool goroutines
(and, before the connectors PR, on the dial path itself). Closed in a
second stacked PR: one shared writer (`pkg/auditlog/spill.go`,
`auditlog.SpillFile`) used by the daemon's sink and every worker; workers
spill through a single goroutine in batches (one lock, one fsync per
batch) with backoff on disk failure and a coalesced gap marker for every
drop, so audit backpressure can never stall a tenant's egress.

Third stacked PR: `List` paid one SQLite query (`ClusterSecretSealGeneration`,
plus a sealed-row read for recipients when placement lacked them) and one
O(members) alive-set rebuild per row for `failover_ready` — 100 serialized
round trips on the single connection and ~200k map inserts per page at
2,000 nodes. Now one membership snapshot, one placement batch, and one
batched summary read (`ClusterSecretSealSummaries`, ≤500 refs per `IN`
list) per page; the per-row step is in-memory only. A failed batch read
reports not-ready for the page (the per-row reader used to report *ready*
on a store error, because "no recipients" read as single-node).

Fourth stacked PR: boot read the whole log up to three times (sink open;
`recomputeChain` for the witness with an all-hashes slice; a separate pass
for the retention checkpoint's `WitnessedThrough`). Now one pass, O(1)
memory: the scan probes for the hashes it is asked about and carries the
checkpoint's `WitnessedThrough`; boot-time witness validation reuses the
open pass. `SB_SECRET_AUDIT_BOOT_VERIFY=checkpoint` (opt-in) makes boot
O(bytes since the last sync) via `secrets.verified` and proves the prefix in
the background, withholding reads on failure instead of refusing to start.

Fifth stacked PR (review finding #7, js-bundle replication removal): the
node-bound `module_ref` was the right scale call, but `GET /v1/js-bundles`
became local-only (empty from ingress) and a bundle became single-copy with a
generic 503 on node loss. Closed by making the list the shared per-worker
catalogue shape (leader-coalesced, cached, bounded fan-out to isolate
workers only, digest-deduped, partial coverage in headers — one generic
implementation now serves templates and bundles), and by a machine-readable
`503` + `code: artifact_node_unavailable` (no `Retry-After`) from the create,
get and delete paths so SDKs re-upload. Placement's no-target error is now
classified: a request pinned to an artifact's node fails as
`cluster.ErrArtifactNodeUnavailable` (still `errors.Is` `ErrNoPlacementTarget`)
when that node is not a live capacity-reporting member. Registry-backed
durable bundles are recorded in `plans/isolate-runtime.md` as the Phase 5
prerequisite.

The same PR replaces the enterprise isolate gate. The old text ("experimental
fleet-wide bundle replication") named machinery that no longer existed; the
real reason isolate could not run in enterprise mode was that its jail was a
uid drop with an unpopulated chroot, and every live run disabled it. The jail
is now realized end to end (`pkg/isolate`: boot-time chroot base, per-group
hard-linked roots, cgroup v2 caps, a re-exec shim that chroots, drops
privileges, sets `no_new_privs` and installs a classic-BPF seccomp allowlist
before `execve`), and enterprise mode requires it with an enforcing filter
rather than forbidding the runtime. Real-host proof is a new scenario
(`make integration-single-isolate-jail`, UC-109) that has not yet been run.

Sixth stacked PR (review finding #10, cluster→single-node downgrade): the
secret-lifecycle reconciler was wired only inside the cluster branch, and both
per-row reconcilers returned untouched when there was no peer transport, so a
node that left the cluster kept its `cluster_secrets` / tombstone / put-outbox
/ delete-outbox rows forever. The same loop now runs standalone; without peers
it retires obligations it can never send after `SB_SECRET_OUTBOX_STANDALONE_GRACE`
(default 1h, so a brief cluster-off restart keeps them), tombs sealed rows
whose `(sandbox, incarnation)` has no live local sandbox (the local table is
the standalone authority, through the same retirement transaction the cluster
scan uses), and lets tombstone retention finish the job. Cluster mode with the
transport not yet attached still keeps every row. Counted and logged with the
peers named; documented in the runbook ("Leaving a cluster").

Seventh stacked PR (review finding #11, prefix-only retention): `pruneLocked`
stopped dropping at the first record inside the window and never resumed, so an
expired record that the spill drain or worker ingest had landed behind a newer
one stayed for as long as that record lived — over-retention with no bound the
retention claim could state. Retention is now by record time anywhere in the
file: the expired prefix is dropped as before, and an expired record behind a
fresh one is reduced in place to a `retention_redacted` stub (`time`,
`event_id`, `prev_hash`, `event_hash`, nothing else) so the immutable chain
still verifies through it; the verifier links a stub by its stored hashes and
rejects one that carries payload, and a later prune reclaims stubs with the
prefix. The leading checkpoint is re-minted by every rewrite (carrying its
ancestor and `WitnessedThrough` forward, which a second prune used to drop)
but never causes one. A redacting prune rebuilds the read index once; a pure
prefix drop still shifts it. `POST /v1/audit/verify` reports `redacted`;
`aerolvm_audit_retention_{dropped,redacted}_total` count both.

Eighth stacked PR (review finding #12, `Sync()` can block `Emit`): confirmed
real. `Sync`, `EmitDurable` and `Prune` did a blocking channel send while
holding the sink's `sendMu` exclusively, and `Emit` took the same mutex before
its non-blocking send. With the writer parked in a long retention rewrite (or
an fsync stall) the buffer fills; the next witness ship (`Sync`), worker
ingest (`EmitDurable`) or retention tick then waited for a slot under the
mutex and every `Emit` — `loadEnv` / `loadMounts` on StartSandbox, egress
audit — queued behind it for the rest of the outage, undoing "audit I/O stays
off the request path" exactly when the writer was slowest. Reproduced by a test
that parks the writer behind the audit flock. Fix: `sendMu` is an RWMutex held
on the read side by every sender (senders never exclude one another; a waiting
`Sync` cannot stall `Emit`, which takes the overflow path as designed) and on
the write side by `Close`, which flips `closed` first so request-path Emits
never queue behind a shutdown either.

Ninth stacked PR (review finding #13, two minor security notes): both
validated. (a) The audit-ingest loopback check skipped itself when the peer
address did not parse; the listener is TCP loopback so it was unreachable, but
the logic was inverted — it now fails closed. (b) `RedactClusterSecrets` keeps
mount `Options` (and `Source`) in the replicated spec. One correction to the
note's premise: the S3 adapter drives `mount-s3`, which takes credentials only
through the AWS chain (fed from the sealed `Credentials` profile), so no
`extra_args` flag carries a secret today; the live exposure was the rclone
adapter's `source`, whose connection-string syntax (`:s3,secret_access_key=…:b`)
needs no rclone.conf. Scrubbing the replicated copy alone was rejected: a value
removed from the spec but absent from the sealed bag silently breaks the
failover recreate it exists for. Instead `models.MountSpec.ValidateSecretsPlacement` refuses
credential-shaped names (secret / password / token / access_key / …) in
`options` keys, `extra_args` flags, NFS `opts` entries and rclone
connection-string parameters, pointing at `credentials` — on new requests
only; a stored spec replayed for a failover recreate (already replicated) logs
a warning and proceeds, since refusing it would lose the sandbox. Docs, the review
rulebook (§5) and the cluster-secrets checklist now state that `source` and
`options` are replicated in the clear and only `credentials` is sealed.

Tenth stacked PR (review finding #8, the 100-ingress target's opt-in):
investigated and judged worth fixing, not as a code defect — the gate is right
and loud (enterprise boot refuses with the fix in the message; open-source logs,
skips ingress reconcile, reports `degraded`) — but as an operability gap with a
specific hazard: every place an operator designs a large ingress tier (the
cluster-ingress docs page, `setup/cluster.md`, the Terraform module, and the
plans that set the 100-ingress scale bar) recommended plain load balancers and
never named the 10-node cap, so the first sign is a refused boot at scale-out
time, and the tempting wrong fix — flipping `SB_CLUSTER_SHARD_AWARE_INGRESS`
to silence it while keeping the plain LB — black-holes most public traffic with
nothing daemon-side able to notice. Fixed by stating the prerequisite where the
target is set and where LBs are recommended (this plan, the export plan, the
LB plan's failure table corrected: the ingress-count rule never refuses
creates), a runbook, a Terraform `shard_aware_ingress` variable that threads
the env flag and a plan-time precondition refusing more than 10 ingress-capable
nodes without it (mirrored in `Terraform/validate`), and a gauge
`aerolvm_cluster_topology_ok` with a critical alert so the open-source
not-ready state is visible in monitoring, not only in logs and `/health`.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAR | 5 proposals, 5 accepted, 0 deferred; 8 section findings; 2 critical gaps |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 2 | CLEAR | 18 issues + 4 delta findings, 2 reversals |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |
| Outside Voice | `/plan-eng-review` ×2 + `/plan-ceo-review` | Cross-model challenge | 3 | issues_found | 12 + 14 + 9 findings (codex) |

**CEO plan:** `~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-08-06-secrets-hardening.md`
— SCOPE EXPANSION mode. All 5 expansions accepted (E1-E5), 8 section-review
findings decided, 3 outside-voice corrections applied. Scope grew from 13 tasks
to ~16 engineer-weeks across 6 slices. **Read it before starting any slice.**

- **CODEX:** 12 findings. 5 were plan-staleness against decisions taken during
  this review (folded). 4 were real gaps the review missed and are now explicit
  open items: KMS wrapping-material caching changes the threat model (#6); audit
  scope once env is a secret read (#9); `PlacementSecrets.Version` vs envelope
  version are not the same gate (#10); recipient-set selection is unspecified
  across the reserve/promote race (#11). 2 drove user decisions: the `Get`/`List`
  env contract break (#8 → D9) and the provider seam abstracting crypto instead
  of the backend (#5 → D10).
- **CROSS-MODEL:** Both reviewers independently flagged that sealing `env_json`
  in place would land in the hot row scanner. Codex additionally caught that a
  crypto-only provider seam would leave the KMS backend with the same cross-node
  defect it was chosen to fix — the review had accepted that sketch. User took
  Codex's side on both (D9, D10).
- **CROSS-MODEL:** Codex ran twice. Round 1 (eng) caught that a crypto-only
  provider seam would leave the KMS backend with the same cross-node defect.
  Round 2 (CEO) caught that **KMS stores keys, not ciphertext** — so KMS never
  removed the payload-distribution problem at all, an error that survived the eng
  review, the CEO review, and three adversarial spec rounds. Both were verified
  against source and both changed the design. Two Claude spec-review rounds
  separately caught that the attribution premise was factually wrong in
  *opposite* directions across drafts.
- **VERDICT:** ENG (×2) + CEO CLEARED — ready to implement. Start with slice 0,
  which is now larger: the four original decisions **plus** codex #5 (delete-fanout
  vs attempt-unique refs) and #8 (does `Provider.Open` take a sandbox ID). Both are
  interface-shape calls that get expensive to change after T1.

**Re-review verdict (eng #2):** peer-push auth moved to the existing PAT +
`d.Auth` pattern rather than a second gossip-secret scheme. The later strict
contract removed the proposed rollout flags. Nine further codex findings
folded, four of them (#3 atomicity, #4 peer deletes, #5 ref collisions, #7
reassign churn) are **required work that gates T3 or T7** and had no coverage in
any prior pass.

**RESOLVED 2026-08-07** — the four slice-1 gates are closed (§3d): recipient-set
selection (router picks at reserve time, recorded in `opReserve`); partial
fan-out (owner + ≥1 backup, holder count surfaced); failed-create leftovers
(delete-fanout, deterministic refs); `Provider.Open` takes `sandboxID`
explicitly. Plus §3e supersedes D4: HA fan-out uses a **bounded first-backup
ACK followed by an asynchronous remainder**; every cluster mode retracts/fails
a zero-ACK create, while E1a `failover_ready` exposes completion. **Slice 1 is
unblocked.**
Also resolved: the E1b cluster-read model — local hash-chained operational log,
bounded owner-history reads with explicit coverage and rate limiting, and a
mandatory authenticated exporter in enterprise mode. Dead-disk durability is
**not claimed** on the open-source build without that exporter.
And the KMS wrapping-material cache: **no cache**, every open calls KMS, so
revocation stays instant and CloudTrail stays complete. **E5 credential
brokering is out of scope** — customer secrets arrive at create time, platform
KMS covers only AerolVM's own wrapping keys, and the "every use attributed"
claim is withdrawn. New accepted gap
recorded: **GAP-1** (closed for every cluster create via min-ACK wait,
retraction, and failure when peers are unreachable — §10).

**UNRESOLVED BUSINESS / OPERATIONAL REQUIREMENTS:**
- SOC 2 observation window and auditor engagement status; the repository
  mechanism does not itself constitute certification
- Owners, dates, and per-slice rollback plans
- Full off-node WORM/SIEM event store (Witness + HTTP export seam ship; reconstructable history still requires configuring export)
- Automated certificate issuance/renewal and revocation distribution for the
  existing node-ID-bound cluster certificates remains an operational follow-up.
  Atomically replaced leaf pairs hot-reload on the next handshake and expiry
  metrics/alerts are shipped; CA rotation remains a coordinated operation.
- Live 2,000-process / 100-ingress soak remains operator-run (`plans/data-plane-load-balancer.md`).
  **Prerequisite for any ingress tier above 10 nodes:** a shard-aware router
  that resolves owners through `GET /v1/cluster/ingress-route/{id}`, and
  `SB_CLUSTER_SHARD_AWARE_INGRESS=true` on every node once it does. Above
  `cluster.MaxReplicatedIngressRouteNodes` (10) each ingress node holds only its
  rendezvous-hashed share of the route table, so a plain LB is not an option;
  without the flag enterprise boots refuse and open-source never marks ingress
  ready (`aerolvm_cluster_topology_ok = 0`). Nothing in this plan removes that
  requirement; the 100-ingress figure assumes it is met.
