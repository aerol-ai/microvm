# Secrets hardening: cross-node failover, audit trail, env sealing, and the provider seam

Status: **ENG-REVIEWED 2026-08-06** — decisions below are the build contract.
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
STEP 0  redacted spec → raft ............. env=map[OPENAI_API_KEY:sk-live-...]
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
| D4 | ~~Sync~~ **ASYNC** fan-out (superseded 2026-08-07 — see §3e), **only** for `failover.policy=recreate`. Default creates byte-for-byte unchanged. **Plus** a KMS provider as a configurable alternative backend — both ship, operator picks. |
| D5 | Stale recipient sets after membership change = **documented known limitation**, point operators at KMS. No placement filter. |
| D6 | One seal+fanout helper with an explicit strict / best-effort policy argument. |
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
6. "Keep the package at ~85%" was **wrong**. Measured 2026-08-06: `internal/service` 95.1%, `internal/store` 95.1%, `internal/cluster` 95.9%, `pkg/secrets` 96.5%. The real bar is ~95%.
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
| Key custody | node-local AES key file | KMS wraps the data key into the existing `WrappedKey` field (envelope v3, `cluster_secrets.go:65-70` — **no format change**) |
| Ciphertext storage | `cluster_secrets` row | `cluster_secrets` row — **same**, KMS stores nothing |
| Distribution | **async** peer fan-out after create (§3e) | **async peer fan-out after create** — shared machinery |
| Who can take over | only pre-sealed recipients | any node with IAM access **that received the bytes** |
| Boot cost (HA creates only) | **none — fan-out is async (§3e)**; local seal only | **none on the caller**; the KMS wrap rides the async fan-out, not the create |
| Membership drift | **degrades — see D5** | immune to recipient staleness; still needs the bytes |
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

What you give up without it: **D5's escape hatch.** Stale recipient sets after
cluster membership change stay a documented limitation with no alternative
remedy — E1a's `failover_ready` makes the degradation visible but does not
repair it. Note this is a smaller loss than the earlier framing implied: KMS
removes recipient binding but the ciphertext still travels by the same fan-out,
so the recipient list matters either way.

The only item that genuinely requires an external KMS or Vault by nature is
**E5** (brokering short-lived credentials from the customer's vault), which is
gated on its own eng review and excluded from the totals.

When T10 lands, add the `SB_SECRET_PROVIDER` row to `setup/config-defaults.md`
with this rationale. Do not add it before the flag exists in `config.go` — that
file is an operator reference for shipped flags, not a spec.

`internal/service/cluster_secrets.go` stops touching `s.cipher` directly.

**Open item (Codex #11): recipient-set selection is unspecified.** Reserve
writes the redacted spec (`clustercreate.go:136`) *before* sealing happens on
the target (`overlap.go:139`). Who picks the N candidates, from which
membership view, and how does the choice survive reserve/promote races? Must be
answered before coding — a non-deterministic set is a correctness bug, not a
detail.

---

## 3. Fix cross-node failover (D3, D4, D5, D6)

### 3a. Recipient-set sealing + fan-out

- `sealClusterSecrets` already takes `recipients []string` and the envelope is
  already v3 with a `Recipients` field — no format invention needed.
- Compute the set **only** when `failover.policy=recreate`. Otherwise seal to
  self exactly as today and skip the fan-out entirely.
- Fan out synchronously before create returns, so a 201 means the HA guarantee
  is already true.
- New peer-receive endpoint in `internal/cluster/`: idempotent on retry,
  rejects unauthenticated/foreign pushes, no-op under `Noop`.

### 3b. One helper, explicit policy (D6)

Seal failure currently has three undocumented policies across four sites:

| Call site | Today | After |
|---|---|---|
| `cluster_ownership.go:150` | warn + continue (silently drops the ref) | **best-effort**: metric + mark sandbox not-HA |
| `cluster_handler.go:378` | error + rollback | **strict** |
| `clustercreate.go:255` | rollback + return | **strict** |
| `overlap.go:139` | error into channel | **strict** |

**Scope note after §3e:** the policy argument governs the **local seal only**,
which is still synchronous. The fan-out is asynchronous and never fails a
create, so "strict" now means *the local sealed row and its ref must exist
before the create succeeds* — not *every peer must have acknowledged*.

Partial fan-out is therefore no longer a create-time rollback question. Its rule
is **3d-2**: owner + at least one backup constitutes success, the actual holder
count is recorded, and `failover_ready` reports it. CLAUDE.md non-negotiable #4
is satisfied by that rule plus the delete-fanout cleanup in **3d-3**.

### 3c. Known limitation (D5)

Recipient sets are frozen at create. Add a node, drain the sealed ones, and
failover can pick a node that provably cannot decrypt. **Documented, not
fixed** — operators who need HA that survives membership change use the KMS
provider. This goes in operator docs, not just a code comment.

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

Also cover the two non-cluster decrypt sites currently outside the seam:
`service.go:1883` (`UnsealRegistry`) and `service.go:1941` (`loadMounts`).

**Open item (Codex #12):** structured logs are best-effort observability, not
an audit trail. If #82's claim is compliance-grade, the plan needs retention,
correlation IDs, and stated tamper/loss expectations. Decide the strength of
the claim before building the sink.

**Open item (Codex #9):** once env is a secret read, does every env
materialization emit an event? D9 makes this tractable — env is opt-in, so the
explicit read is the auditable event and `List` stays quiet.

---

## 5. Env sealing (D8, D9)

### 5a. Own row, read on demand

Mirror mounts exactly: `sealEnv`/`loadEnv` + a dedicated `GetEnv(sandboxID)`.
The shared row scanner (`store.go:3642`) stops carrying env entirely.

Why not in place: that column is projected by the scanner used by `Get`,
`List`, `ListByOwner`, `ListByRuntime` and two more paths, and
`netstats.go:219` calls `store.List(ctx)` **every poll tick** (open issue #70).
Sealing in place adds an AES-GCM open per sandbox per tick, forever.

Migration: lazy. Read tries the sealed row, falls back to plaintext `env_json`,
reseals on next write. Emit a fallback-read metric so we know when the backfill
is effectively done and the plaintext path can be dropped. Do not drop it on a
guess.

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

**Rollout — Codex #10, and the draft got this wrong.** `PlacementSecrets.Version`
(compared at `:211`) and `clusterSealedSecretsEnvelope.Version` (inside the
ciphertext, `:65`) are different things. Bumping the envelope to v4 does **not**
gate placement compatibility. This needs an explicit **writer capability gate**:
N ships the reader, N+1 turns on the writer, and a node that cannot re-merge env
must fail loudly rather than create a sandbox with a silently empty environment.

---

## 6. Test plan

Baselines measured 2026-08-06 — new code holds ~95%, not 85%.

**CRITICAL / mandatory regression test:** cross-node failover open. A node in
the recipient set opens a sandbox sealed by a different node. This is the test
that would have caught the confirmed defect; the probe in §0 stood in for it.

Shared contract suite (D7) runs every case below against **both** providers:

| Area | Cases |
|---|---|
| Recipient set | policy unset → no set/no fanout; `=recreate` → owner+N; cluster < N; single-node Noop |
| Fan-out | all peers ok; peer down (strict → rollback); partial 2/3; best-effort → metric + not-HA; 4xx vs timeout distinct |
| Open | owner opens; **new owner in set opens (CRITICAL)**; not in set → distinct legible error; wrong recipient denied; version mismatch |
| Audit | success → exactly one event; each failure class → one event + reason; no plaintext in payload; nil logger/sink no panic |
| Peer endpoint | idempotent on retry; rejects foreign push; Noop no-op |
| Env at rest | round-trip; legacy plaintext row fallback; fallback metric; upsert preserves sealed env |
| Env in spec | absent from redacted spec; re-merged on open; **old writer/reader → loud reject, never silent env loss** |
| API | `Get`/`List` omit env by default; opt-in returns it; opt-in read is audited |
| Boot path | **default create latency unchanged** (benchmark assertion) |

Integration-tagged (`integration`): kill owner → recreate with creds, on each
provider; add node after create → non-recipient failover (proves D5's
limitation is real and legible); live KMS.

Per CLAUDE.md: `internal/cluster`, `internal/store`, and the boot path each
need a regression test next to the file they change plus a PR call-out.

---

## 7. Performance

- **Boot path.** Default creates: unchanged, and the PR must say so with
  numbers. HA creates: +1 sync fan-out. `overlap.go:141` already records a
  `cluster_seal` stage — extend it to cover the fan-out so the cost is
  measurable for free.
- **KMS on create (Codex #6).** Envelope encryption still calls
  `GenerateDataKey`/`Encrypt` per new secret unless wrapping material is cached
  locally. Caching changes the threat model — decide the TTL and state the
  tradeoff explicitly rather than hand-waving "don't round-trip."
- **Env reads.** D8 keeps them off the scanner. D9 keeps them off `List`.
- **CI.** `internal/cluster` runs ~4.5 min; D7 roughly doubles the credential
  suite. Acceptable, but watch it.

---

## 8. NOT in scope

| Deferred | Why |
|---|---|
| Placement filter for stale recipient sets | D5 chose documentation + KMS instead |
| Resealing protocol on membership change | Needs a live decryptor; the dead owner is the one that had it |
| `toolbox_token` at rest | Same plaintext class as `env_json` (`store.go:766`), but a separate change |
| Fixing issue #70 (full-table scan) | D8 avoids making it worse; fixing it is its own work |
| `internal/cluster` test flake | Captured in TODOS.md instead |
| Credential brokering into sandboxes | The real enterprise product. Own plan, own eng review. |

## 9. What already exists — reuse, do not rebuild

- `beginClusterSecretOpen()` — the audit hook, already wrapping both paths.
- `sealMounts`/`loadMounts`/`GetMounts` — the exact shape D8 copies.
- `clusterSealedSecretsEnvelope.Recipients []string` at v3 — the format already
  anticipated recipient sets.
- `opts.Timing.RecordStage("cluster_seal", …)` — boot-path measurement, free.
- Recovery store + blob GET fetch-on-miss — kept deliberately for
  snapshot-joined voters. **Read before designing the fan-out**; note it pulls
  from a *live* peer, which is exactly what failover does not have.

## 10. Failure modes

| Failure | Test? | Handled? | User sees |
|---|---|---|---|
| **GAP-1: owner dies inside the async fan-out window** | yes (chaos case) | **accepted, not fixed** — bounded by `failover_ready=false` | sandbox is unrecoverable; `failover_ready` was false throughout |
| Failover node not in recipient set | yes (D5 case) | must be distinct error | clear error — **required**, not a decrypt failure |
| Partial fan-out | yes | 3d-2 holder-count rule | create succeeds at owner + ≥1; holder count surfaced |
| Peer unreachable during fan-out | yes | async retry + backoff + metric | nothing at create; `failover_ready` stays false |
| Ownership replay seal failure | yes | best-effort + metric | sandbox marked not-HA |
| **Old node re-merges env it cannot read** | yes | writer capability gate | **must fail loudly** — silent empty env is the critical gap |
| KMS unreachable during fan-out | yes (fake) | async retry + backoff | nothing at create; `failover_ready` stays false |
| Legacy plaintext env row | yes | lazy fallback | transparent |

### GAP-1 — the async fan-out window (ACCEPTED, not fixed)

**There is a window between `201 Created` and fan-out completion during which
the sandbox is running but no backup node holds its credentials. If the owner
dies in that window, failover fails and the sandbox cannot be recreated
anywhere.**

This is a direct and accepted consequence of the §3e decision to make key
distribution asynchronous so callers never block on it. It is a real gap, not a
theoretical one, and it is recorded here rather than in a design section so it
cannot be missed.

What bounds it:

- `failover_ready` reads **false** for the entire window (E1a, moved into slice
  1 specifically for this). The system never claims a guarantee it does not
  have, so no operator or automation is misled into believing the sandbox is
  recoverable.
- Fan-out retries with bounded backoff, so transient peer failures close the
  window on their own rather than leaving it open indefinitely.
- Failures emit `aerolvm_secret_fanout_failures_total` and feed the operator
  alert, so a window that is *not* closing becomes visible.

What does **not** bound it: window length. There is no upper bound on how long
a fan-out can take when peers are unreachable, and no create-time guarantee of
any kind. A sandbox can be live and permanently not-failover-ready.

Who is affected: only `failover.policy=recreate` sandboxes, since no other
sandbox fans out at all. Non-HA sandboxes are explicitly orphaned on owner death
regardless (`service.go:929`), so nothing changes for them.

**If `failover_ready` does not ship in slice 1, this gap becomes silent and §3e
is not safe.** That coupling is the reason E1a moved out of slice 3.

Accepted trade: callers never wait on peer I/O during create.

### The other critical gap

A sandbox created with a silently empty environment. It boots, looks healthy,
and misbehaves. §5c's writer capability gate is what prevents it.

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

- [ ] **T1 (P1, human: ~1d / CC: ~2h)** — pkg/secrets — Extract the `Provider` interface (ref → plaintext, D10)
  - Surfaced by: Codex #5 — crypto-only seam preserves the cross-node failure
  - Files: `pkg/secrets/`, `internal/service/cluster_secrets.go`
  - Verify: `go test ./pkg/secrets/... ./internal/service/...`, no behavior change
- [ ] **T2 (P1, human: ~4h / CC: ~45m)** — internal/service — Answer recipient-set selection before coding §3
  - Surfaced by: Codex #11 — reserve writes spec before sealing on target
  - Files: `pkg/api/clustercreate/clustercreate.go:136`, `overlap.go:139`
  - Verify: written decision in this plan + a determinism test
- [ ] **T3 (P1, human: ~1w / CC: ~1-2d)** — internal/service+cluster — Recipient-set sealing + sync peer fan-out
  - Surfaced by: §0 WALL 1 + WALL 2, both proven
  - Files: `cluster_secrets.go`, `internal/cluster/`, 4 seal call sites
  - Verify: CRITICAL cross-node failover regression test
- [ ] **T4 (P1, human: ~2d / CC: ~3h)** — internal/service — One seal+fanout helper with policy arg (D6)
  - Surfaced by: Code quality — 3 undocumented failure policies across 4 sites
  - Files: `cluster_ownership.go:149`, `cluster_handler.go:377`, `clustercreate.go:254`, `overlap.go:139`
  - Verify: strict/best-effort/partial cases
- [ ] **T5 (P2, human: ~3h / CC: ~30m)** — internal/service — Typed sentinel errors
  - Surfaced by: Audit `Reason` has nothing to switch on
  - Files: `cluster_secrets.go:115,174,177,202,353,379`
  - Verify: each class asserted
- [ ] **T6 (P2, human: ~1d / CC: ~2h)** — internal/service — Audit events on every provider read (#82)
  - Surfaced by: #82 partial — metrics exist, per-event records do not
  - Files: `metrics.go:153`, `cluster_secrets.go:199`, `service.go:1883`, `service.go:1941`
  - Verify: one event per path, no plaintext
- [ ] **T7 (P2, human: ~2d / CC: ~4h)** — internal/store — Env to its own sealed row + lazy migration (D8)
  - Surfaced by: Performance — scanner + `netstats.go:219` per-tick decrypt
  - Files: `store.go`, `internal/service/service.go`
  - Verify: round-trip, plaintext fallback, fallback metric
- [ ] **T8 (P2, human: ~3d / CC: ~5h)** — pkg/api+sdk — Env opt-in on `Get`/`List` (D9)
  - Surfaced by: Codex #8 — breaking API contract decision
  - Files: `pkg/api/v1/`, all five SDKs, docs `.mdx`
  - Verify: default omits, opt-in returns + audits
- [ ] **T9 (P2, human: ~2d / CC: ~4h)** — internal/service — Redact env from spec + writer capability gate (§5c)
  - Surfaced by: Codex #10 — placement vs envelope version conflated
  - Files: `cluster_secrets.go:60,211,265`
  - Verify: old reader fails loudly, never silent empty env
- [ ] **T10 (P2, human: ~3d / CC: ~5h)** — pkg/secrets — KMS provider + offline fake + shared contract suite (D7)
  - Surfaced by: D4 — both backends ship
  - Files: `pkg/secrets/`, `internal/config/config.go`, `integration-tests/`
  - Verify: both providers pass one suite; live KMS behind `integration`
- [ ] **T11 (P3, human: ~1h / CC: ~10m)** — docs+config — Fix the two wrong operator messages
  - Surfaced by: Architecture A3/A4
  - Files: `service.go:920`, `config.go:2047`
  - Verify: review
- [ ] **T12 (P3, human: ~30m / CC: ~5m)** — internal/service — Delete legacy wildcard `SealClusterSecrets`
  - Surfaced by: Code quality — zero production callers, seals to `"*"`
  - Files: `cluster_secrets.go:84`
  - Verify: `make test`
- [ ] **T13 (P3, human: ~1d / CC: ~2h)** — docs — Operator docs: provider choice + D5 limitation
  - Surfaced by: D5 — limitation must be operator-visible
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
- `reservationCommand` (`internal/cluster/fsm.go`) is a JSON struct of
  `omitempty` fields, so `Recipients []string` is **additive and
  wire-compatible** — the same shape as `ReassignCause`, which was added
  additively with an explicit mixed-version-safety comment.

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

Keeping refs derivable from `(sandboxID, version)` is worth preserving.

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

**The caller does not wait for key distribution.** Create returns as soon as the
sandbox is up. The fan-out runs in the background, retries with bounded backoff,
and logs plus increments a metric on failure. Nobody blocks on it.

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

**The cost, stated plainly:** a sandbox that dies inside the fan-out window loses
its credentials and cannot be recreated elsewhere. The mitigation is not that the
window is small — it is that `failover_ready` reports false for its duration, so
nothing and nobody is misled. If that field is not shipped, this decision is not
safe. **E1a therefore moves from slice 3 into slice 1**, alongside the fan-out it
now guards.

Boot-path consequence, and it is a good one: HA creates are now **also**
unchanged. No sync peer calls on any create path.

## E1b cluster-read model — DECIDED 2026-08-07

**Local log is authoritative. Fan-out serves reads. The off-node sink is
additive, never required.**

Four parts, all of them load-bearing:

1. **Always** write audit events to the local node's append-only log. That log
   is the source of truth on every build.
2. **Always** serve `/v1/sandboxes/{id}/audit` by live fan-out to reachable
   members, merged by timestamp, with an **explicit coverage block** naming
   which nodes answered and which did not. **Rate-limited** (see below).
3. **Additionally**, best-effort `Report(...)` audit events through
   `controlplane.Reporter` when a real reporter is configured — the managed or
   customer sink path.
4. If the Reporter is no-op or unset (**the open-source default**), skip the
   off-node ship entirely. Reads stay fan-out plus local.

### The claim is gated on the sink, and this is not optional wording

**Do not claim dead-disk durability unless a real sink is wired.** On the
open-source build a node's disk loss is permanent record loss, and the docs must
say so plainly rather than implying the fan-out protects against it. Fan-out is
a *discovery* mechanism, not a durability one — it finds records whose location
nothing tracks; it cannot find records that no longer exist.

This is the same honesty rule as GAP-1 and the D14 gap marker: state the
boundary rather than let a reader infer a stronger guarantee than exists.

### Why fan-out, and why owner-forwarding was eliminated

The FSM stores a single `OwnerNodeID` and `opPlace` overwrites it
(`internal/cluster/fsm.go:427`). **No owner history is retained anywhere.** After
a failover, nothing in the system knows which node held the sandbox last week, so
forwarding to the current owner returns only that node's slice and silently drops
everything before it. Fan-out to `c.gossip.members()` is both the established
pattern (eight-plus call sites — `dead_owner.go:119`, `capacity_lease.go:128`,
`client.go:737`, `agent.go:767`) and the only topology that can find records whose
location is unrecorded.

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

## Re-review decisions (eng review #2, 2026-08-07)

Delta-focused re-review after the CEO scope expansion. Two reversals, two
corrections, all verified against source.

| # | Finding | Decision |
|---|---|---|
| **REVERSAL** | **Peer-push auth: use PAT + `d.Auth`, not gossip-secret signing.** Every node-to-node HTTP call in this repo already authenticates with `Bearer <pat>` — `capacity_lease.go:242`, `agent.go:900`, `client.go:775/1116`, `recovery_replication.go:162`, `jsbundle_replication.go:75`, `wasm_migrate.go:65`. The closest analogue is the *same operation*: `recovery_replication.go:162` fetches a recovery payload from a peer with `Bearer <pat>`, received via `d.Auth(...)` at `routes.go:178`. Gossip-secret signing would be a second auth model on the same wire. | Reverses the earlier gossip-secret decision. Register the endpoint as `PublicInternalSecretPath` alongside the other six `/v1/cluster/internal/...` routes. |
| **REVISED** | **Flag granularity: ~3 flags grouped by default posture, not 5+.** A single umbrella cannot express mixed defaults, and one-per-change is more surface than the split needs. | One flag for the default-ON defect fixes (recipient-set sealing + fan-out), one for env-row storage, one for provider selection. Each gets a `setup/config-defaults.md` row and a removal criterion in the same commit. |
| **CORRECTION** | **Boot-path table omits D13.** Under the `kms` provider an HA create costs fan-out **+ one KMS wrap** — a network round-trip on the boot path. | Add the row; measure and report it like every other boot-path change. |
| **CORRECTION** | **D13 was over-estimated.** `clusterSealedSecretsEnvelope` already carries `WrappedKey []byte` at envelope v3 (`cluster_secrets.go:65-70`), so a KMS-wrapped DEK needs no format change. | 4 eng-days → **~2**. |

### Outside voice (codex, re-review pass) — 9 findings

| # | Finding | Resolution |
|---|---|---|
| 1 | **The §2 provider table still said KMS needs no local storage** — corrected in the CEO plan but not here, and this is the doc implementers read. | **Fixed above.** |
| 2 | **Env redaction contradicts "default creates unchanged."** `cluster_secrets.go:111-113` returns nil with no registry/mount secret, so most creates seal nothing today. Adding env would give nearly every create a ref and a fan-out. | **Decided:** redact env from every replicated spec and seal it locally (T7); **fan out only for `failover.policy=recreate`.** Non-HA specs are never used to recreate, so stripping env costs them nothing. |
| 3 | **Env side-row write needs atomicity.** Insert row → write sealed env as two steps means a crash yields the "healthy sandbox with empty env" failure this plan calls critical. | **Required:** single transaction, plus an explicit crash-between-writes rollback test. Gates T7. |
| 4 | **Peer secret deletes are unplanned.** Fan-out creates rows on peers; `DeleteClusterSecretsForSandbox` is local-only (`store.go:4040`) and `cluster_secrets` has no FK by design. | **Required:** delete fan-out on destroy, create rollback, partial fan-out, and promote failure. Tests for each. Gates T3. |
| 5 | **Stale peer rows can collide.** Refs are deterministic (`cluster-secret://sandbox/<id>/v1`), so a failed create with partial fan-out leaves remote rows a later retry may reuse. | **Required:** either delete-fan-out on rollback (see #4) or attempt-unique refs. Pick one before coding T3. |
| 6 | **"Rejects foreign pushes" is not achievable with PAT + `d.Auth`** — that is caller authorization, not peer identity. | **Claim downgraded:** the test asserts *unauthenticated* pushes are rejected, not foreign-node ones. Per-peer identity across all seven `/v1/cluster/internal/...` endpoints is separate work — TODO, not this plan. |
| 7 | **D5 causes reassign churn.** `owner_watcher.go:109` reassigns after 5 failures to another arbitrary candidate excluding only the current node; a recipient-denied error therefore walks the fleet. | **Required:** a recipient-aware stop rule so a recipient-denied open halts reassignment instead of cycling. Gates T3; needs a regression test next to `owner_watcher.go`. |
| 8 | **`Provider.Open(ctx, handle, nodeID)` carries no sandbox ID**, but the audit event needs one and a not-found event cannot recover it from an opaque handle. | **Required:** add `sandboxID` to the `Open` signature, or require handles to encode it. Decide at T1 — it is the interface definition. |
| 9 | **The API change is under-scoped.** `GetSandbox`/`ListSandboxes` are thin wrappers (`service.go:1987`) and internal workflows call `store.Get/List` directly. | **Required:** separate internal "with env" reads from public response omission. A default change in the store would break internal callers. Gates T8. |

Confirmed unchanged: D8/D15's flag conventions match the house pattern
(`getEnvBool("SB_X_ENABLED", false)`, rationale in `setup/config-defaults.md`,
which already has a "rule for flipping a default on" section). `config.go:562`
shows `SB_WASM_RESIDENT_HOST_ENABLED` was flipped default-on in v0.7.12 with a
documented escape hatch — precedent for D15's defect-fixes-default-on posture.

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

**Re-review verdict (eng #2):** two reversals — peer-push auth moves to the
existing PAT + `d.Auth` pattern rather than a second gossip-secret scheme, and
flags group into ~3 by default posture rather than 5+. Nine further codex findings
folded, four of them (#3 atomicity, #4 peer deletes, #5 ref collisions, #7
reassign churn) are **required work that gates T3 or T7** and had no coverage in
any prior pass.

**RESOLVED 2026-08-07** — the four slice-1 gates are closed (§3d): recipient-set
selection (router picks at reserve time, recorded in `opReserve`); partial
fan-out (owner + ≥1 backup, holder count surfaced); failed-create leftovers
(delete-fanout, deterministic refs); `Provider.Open` takes `sandboxID`
explicitly. Plus §3e supersedes D4: the fan-out is **asynchronous** and E1a
`failover_ready` moves into slice 1 to guard it. **Slice 1 is unblocked.**
Also resolved: the E1b cluster-read model — local log authoritative, fan-out with
an explicit coverage block, rate-limited, `controlplane.Reporter` additive and
never required, dead-disk durability **not claimed** on the open-source build.
And the KMS wrapping-material cache: **no cache**, every open calls KMS, so
revocation stays instant and CloudTrail stays complete. **E5 credential
brokering is out of scope** — customer secrets arrive at create time, platform
KMS covers only AerolVM's own wrapping keys, and the "every use attributed"
claim is withdrawn. New accepted gap
recorded: **GAP-1**, the async fan-out window (§10).

**UNRESOLVED DECISIONS:**
- Rate-limit dimension for E1b — per-token, per-caller, or per-sandbox — settle when E1b is built (the machinery itself is decided; only the dimension is open)
- SOC 2 observation window and auditor engagement status — E2a has no business date without it; E2b gated on an auditor ask
- E2b trust boundary / external witness — or downgrade the tamper-evidence claim
- `toolbox_token` plaintext at rest: write the deferral rationale or pull it into scope
- Owners, dates, and per-slice rollback plans
- Per-peer identity across all seven `/v1/cluster/internal/...` endpoints — separate work, not this plan
