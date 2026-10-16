# Open audit witness: enterprise mode in the open-source build

Status: founder decisions made 2026-10-11 (F1–F5, under "Decisions"); engineering review done 2026-10-11, and its decisions (D1–D18, in the review below) are folded into the sections below. A follow-up review on 2026-10-16 (D19–D24, in "Follow-up review" at the end of this file) corrected five of those decisions against the code and AWS behavior; its changes are folded in too. Founder decision: make enterprise mode usable in the free download.

## In one paragraph

Enterprise mode needs a **witness**: a store outside the server that keeps the fingerprints (hash-chain heads) of the server's audit log. The open-source build ships only a placeholder witness, so `SB_ENTERPRISE_MODE=true` always refuses to start. This plan adds a real witness to the open-source build that writes each fingerprint to an S3 bucket with **Object Lock** turned on. Object Lock means a written object cannot be changed or deleted until its retention period ends, not even by the server that wrote it. With it, anyone can turn on enterprise mode with only the free download and an S3 bucket.

## Why enterprise mode is closed today

Three facts in the code, each checked on 2026-10-11:

1. Enterprise mode forces the witness on, even when the operator sets it off (`internal/config/config.go:2491-2496`).
2. Boot refuses a placeholder witness (`pkg/daemon/daemon.go:294-296`).
3. The open-source entrypoint passes no provider, so the daemon uses `controlplane.Noop()` and its placeholder witness (`cmd/sandboxd/main.go`, the comment on `main`).

The integration harness gets around this with a build tag (`cmd/sandboxd/provider_itest.go`, `-tags itestwitness`) that plugs in an HTTP witness. Release builds never set that tag.

The witness is the **only** missing piece. Every other enterprise-mode requirement already works in the open-source build:

- off-node audit export (`webhook`, `s3`), from `pkg/auditexport`;
- AWS KMS with strict boot;
- the 32-byte token minimums;
- the cluster checks (mTLS, gossip key, two backups, no CA key on the node);
- the isolate jail checks.

The original witness design already listed this as the next step: "WORM-backed head store, so heads cannot be deleted or rewritten even by someone holding the sink credential" (`plans/secrets-hardening.md`, "Follow-ups"). WORM means write once, read many.

## Goals

- `SB_ENTERPRISE_MODE=true` boots on the **released** `sandboxd` binary, given an Object Lock bucket.
- The witness is real: the node that writes a head cannot later change or remove it.
- Zero change when it is not configured. No S3 calls, and the placeholder witness stays the default, as `CLAUDE.md` requires for `pkg/controlplane`.
- Works on a single server and in a cluster.

## Non-goals

- No change to how the daemon checks the chain. `internal/service/secret_audit_witness.go` stays as it is; this plan only supplies a `controlplane.Witness`.
- No signing key the daemon cannot read, such as an HSM. That is the other follow-up in `plans/secrets-hardening.md`, and it stays separate.
- No other storage backends in v1, such as GCS or Azure. The backend registry leaves room for them.
- No change to the managed build. A provider that supplies its own witness still wins.

## What the witness proves, and what it does not

This repeats the property from `plans/secrets-hardening.md` so the docs never overstate it.

**It proves:** an attacker who takes over a server **after** a head was witnessed cannot rewrite or delete the history that head covers without being caught. The node refuses to boot, and the verifier fails.

**It does not prove:**

- **Records written since the last ship.** Heads ship every 30 seconds (`SB_SECRET_AUDIT_WITNESS_INTERVAL`), so the newest 30 seconds can be rewritten. The interval is a security setting.
- **A server that was already compromised when it wrote.** It can write a forged chain and witness it from the start.
- **That a newer forged head is false.** A compromised node can still write a new head that matches a rewritten chain. The daemon's boot check looks only at the **latest** head, so it passes. The **offline verifier** (Phase 5) catches this, because it checks every head witnessed inside the time window the auditor names, and those cannot be removed. It proves each witnessed head links to the next with records from the local log **and the off-node export**, because retention prunes the local log and leaves a checkpoint the node writes about itself (D5). The window comes from the auditor, never from the evidence, so an attacker who deletes the oldest records cannot shrink what gets checked (D22). The verifier is what makes this claim complete, so it is part of v1.

## Design

### Where it plugs in

Resolve the witness the way the daemon already resolves the audit exporter (`pkg/daemon/daemon.go:315-320`): **a provider-supplied witness wins; otherwise `SB_AUDIT_WITNESS_BACKEND` selects one.**

```
cp := provider (Noop in the open-source build)
if !cp.HasExternalWitness() && cfg.AuditWitnessBackend != "" {
    w, err := auditwitness.Open(ctx, cfg.AuditWitnessConfig())   // fails boot on bad config; 30 s deadline (D9)
    cp.Witness = w
}
// existing gate: SB_SECRET_AUDIT_EXTERNAL_WITNESS requires cp.HasExternalWitness()
```

This must run before the gate at `daemon.go:294`. Putting it in `pkg/daemon`, not in `cmd/sandboxd`, means every entrypoint gets it, and the managed build's own witness still takes priority.

### Settings

These mirror the audit export S3 settings (`SB_AUDIT_EXPORT_S3_*`, `internal/config/config.go:1865-1869`):

| Setting | Meaning | Default |
|---|---|---|
| `SB_AUDIT_WITNESS_BACKEND` | `s3`, or empty for none | empty |
| `SB_AUDIT_WITNESS_S3_BUCKET` | The Object Lock bucket | required with `s3` |
| `SB_AUDIT_WITNESS_S3_PREFIX` | Key prefix | `witness/` |
| `SB_AUDIT_WITNESS_S3_REGION` | AWS region | from the AWS config |
| `SB_AUDIT_WITNESS_S3_ENDPOINT` | For S3-compatible stores | empty |
| `SB_AUDIT_WITNESS_S3_PATH_STYLE` | Path-style addressing | `false` |

Credentials come from the standard AWS chain (instance role, environment or profile), the same as the S3 exporter (`pkg/auditexport/s3.go`, `newS3Client`). Rename it to an exported `auditexport.NewS3Client` with a neutral error prefix and call it. There is no new shared package and no backend registry: `Open` switches on the backend name and rejects an unknown one (D1).

With a backend set, `SB_NODE_ID` is required and must not be `standalone`. The witness key is per node id, and a single server without `SB_NODE_ID` defaults to `standalone`, so two servers sharing a bucket would write the same keys (D3). Uniqueness across servers stays the operator's job and is documented.

### Storage layout

**One key per node per UTC day, with bucket versioning (D2):** `path.Join(prefix, "node="+id, "day="+yyyy-mm-dd, "head.json")`. `path.Join` also handles a prefix set without a trailing slash.

- Object Lock requires versioning, so every write adds a **new version**. Older versions stay, locked.
- A key holds at most one day of ships: 2,880 versions at the 30 s default. AWS recommends fewer than 100,000 versions per object, and a single key per node would pass that after about 34 days of locked history.
- "The latest head" is a `GetObject` of today's key. When today's key has no current version, one `ListObjectVersions` with `Delimiter` under `node=<id>/` finds the newest day, then a `GetObject` of that day's key. It must be `ListObjectVersions`, not `ListObjectsV2`: `ListObjectsV2` hides a key whose current version is a delete marker, and the fallback would then validate against the previous day's head (C2). The fallback depends on S3 answering 404 `NoSuchKey` for today's missing key, and S3 does that only when the caller holds `s3:ListBucket`; without it, S3 answers 403 `AccessDenied` (D19).
- **An idle node still writes once a day (D20).** The ship loop writes only when the head changes. Without help, an idle node would have no key for today after UTC midnight, and every tick would pay a GET that misses, a LIST and a second GET. So the service re-ships an unchanged head on its first tick of each UTC day. Today's key then exists on every running node, the LIST runs only on a boot after downtime across midnight, and a node whose newest version is more than a day old has really stopped shipping.
- Ordering within a day comes from S3. The day comes from the node's clock, so a clock jump across midnight can make boot read the wrong day; that fails closed, never silently.
- The full history is `ListObjectVersions` under `node=<id>/`, which the verifier uses. Within a key, the order is S3's own version order; across keys it is `LastModified`, with ties broken by the day key. `LastModified` alone is not enough, because list results carry it only to the second (D22).

The object body is a small JSON document, about 300 bytes, and never holds audit payloads:

```json
{"node_id":"…","head_hex":"…","event_id":"…","observed":"2026-10-11T12:00:00Z","sandboxd_version":"0.6.x"}
```

*Rejected:* one key per node. It passes S3's per-object version guidance within weeks at any retention above about 34 days, and S3 then throttles the whole bucket. *Rejected:* one key per head, sorted by an inverted timestamp. It costs a LIST for every read and depends on the node's clock for ordering.

### Mapping to `controlplane.Witness`

| Interface call | S3 calls | Notes |
|---|---|---|
| `WitnessHeads(heads)` | `PutObject` on today's key with `ChecksumAlgorithm: SHA256` | Exactly one head per call; any other count is an error (D11). **Gotcha:** S3 rejects any upload to a bucket with default Object Lock retention unless it carries `Content-MD5` or an SDK checksum. The shared client uses `RequestChecksumCalculationWhenRequired`, so set the algorithm explicitly. The receipt is `ReceiptID = VersionId`; `RecordedAt` stays zero, so the service stores `ShippedAt`. The witness-side time the original design requires (so an attacker cannot backdate a forged chain) is the version's `LastModified` in the bucket, which the node cannot change and the verifier reads. No `HeadObject` (D10). |
| `LastWitnessedHead(node)`, found | `GetObject` on today's key, else on the newest day's key | Returns `head_hex`, `ok=true` |
| `LastWitnessedHead(node)`, no current version | `ListObjectVersions` with `Delimiter` under `node=<id>/`, then on the newest day's key | No versions anywhere means "never recorded": `ok=false`, no error. If the newest day's latest entry is a **delete marker**, return an **error**. The daemon never deletes, so a delete marker means someone tried to hide the head. The daemon then fails closed through the existing path. |
| `LastWitnessedHead("standalone")` | none | `ok=false` without a request. D3 means no S3 head can exist under that id, and the service's legacy-id fallback would otherwise read a key any node's role can write (D24). |

`heads` holds one entry today (`shipSecretAuditHeadNow`), and the backend rejects any other count (D11).

### Boot checks: refuse a bucket that is not really WORM

`auditwitness.Open` checks the bucket before it returns. Any failure stops boot with a message that names the fix. All checks run under a 30 s deadline; on expiry the error names the check that timed out and the bucket (D9).

1. `GetBucketVersioning` returns `Enabled`.
2. `GetObjectLockConfiguration` shows Object Lock enabled, with a **default retention rule**.
3. Default retention is at least `SB_SECRET_AUDIT_RETENTION_DAYS`. A head must outlive the local records it vouches for.
4. **Missing-key probe (D19):** `GetObject` on a random key under `<prefix>probe/` must answer `NoSuchKey`. `AccessDenied` means the role lacks `s3:ListBucket`, so every missing key would later look like an error, and the first boot after an idle midnight would fail. Refuse to start and name the permission. The key is random so that no writer can make it exist. This costs one call per boot.
5. **Canary** (recommended; see Decisions, F4): put `<prefix>canary/node=<id>`, then `DeleteObject` with that `VersionId` **and `BypassGovernanceRetention=true`**, the way an attacker would. Expect `AccessDenied`. If the delete succeeds, the lock is not protecting this node's writes, so refuse to start; on a governance bucket the message names `s3:BypassGovernanceRetention`. Any other error also refuses to start, because an unknown result is not proof of safety. Without the header, a governance lock refuses even a role that holds bypass, so the check would pass a role an attacker can use (D7). Then a plain `DeleteObject` with no version id, which on a versioned bucket would hide the key behind a delete marker: Object Lock does not stop that, only IAM does, so a success refuses boot naming `s3:DeleteObject` (added in Phase 1; it makes "the node role cannot hide a head" a boot check rather than a one-off integration step). This costs one small locked object per boot.

Without these checks, a witness on an ordinary bucket would look healthy while providing nothing, which is the one outcome the existing code comments forbid ("a witness that silently 'succeeded' would let a scenario claim tamper-evidence it never had", `provider_itest.go`).

### IAM for the node role

| Allow | Deny explicitly |
|---|---|
| `s3:PutObject` and `s3:GetObject` on `<prefix>*` | `s3:DeleteObject` (blocks delete markers) and `s3:DeleteObjectVersion` |
| `s3:GetObjectVersion` and `s3:ListBucketVersions` | `s3:PutObjectRetention`, `s3:PutObjectLegalHold` and `s3:BypassGovernanceRetention` |
| `s3:GetBucketVersioning` and `s3:GetBucketObjectLockConfiguration` | `s3:PutBucketObjectLockConfiguration`, `s3:PutBucketVersioning`, `s3:PutLifecycleConfiguration` and `s3:PutBucketPolicy` |
| `s3:ListBucket` on the bucket, with no `s3:prefix` condition (D19) | |

The canary's `DeleteObject` call expects this denial. Denied by IAM or by the lock, both mean the evidence is safe.

Object actions take the object ARN (`arn:aws:s3:::<bucket>/<prefix>*`). `s3:ListBucket`, `s3:ListBucketVersions` and the two bucket reads take the bucket ARN. `s3:ListBucket` is not optional: without it, S3 answers a GET for a missing key with 403 instead of 404, so a first boot on an empty bucket fails, and so does any boot after an idle midnight (D19). Leave it unconditioned: a GET carries no `s3:prefix` key, so a grant limited by an `s3:prefix` condition would not count, and S3 would still answer 403. Give the witness its own bucket instead.

The auditor who runs `aerolvm audit verify` needs read access only: `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObject` and `s3:GetObjectVersion` on the witness bucket, plus list and read on the export bucket. Phase 3's Terraform outputs this as an optional read-only policy (D22).

### Retention mode

| Mode | Who can delete before expiry | Use |
|---|---|---|
| **Compliance** | No one, not even the AWS account root | Production. The strongest claim. |
| **Governance** | Only principals with `s3:BypassGovernanceRetention` | Trials. The node role never has it. |

Cost control: add a lifecycle rule that expires **noncurrent** versions after the retention period. Never expire the current version.

### Cluster

- Each node writes only under its own prefix (`node=<SB_NODE_ID>/day=…`). That matches `witnessNodeID()` and the legacy-id fallback in `witnessNodeIDCandidates()`.
- **Known limit:** the Terraform node role is shared, so node A can write a version to node B's key. It cannot erase B's history, because the lock prevents that. It can make B refuse to boot, because B's latest head no longer matches. That is a denial of service, not silent tampering. Limiting each node to its own path with IAM needs a key that embeds the writer's AWS identity (`${aws:userid}`, as the cluster-join rendezvous uses), because IAM cannot express `SB_NODE_ID`. That is a v2 layout change, tracked in `TODOS.md` ("Per-node witness write scoping"). Until then, a cross-node write shows as a verifier FAIL on the victim and a foreign-head alert on the victim's next tick (D23). It makes the victim's restart fail only if the foreign head is still the newest when the victim restarts, because the victim's own next ship puts its head back on top. The runbook says to turn on CloudTrail S3 data events on the witness bucket to attribute it (D8).
- No change to Raft, gossip or placement. Witness traffic is node to S3 only.

### Failure behavior

| Situation | Result |
|---|---|
| S3 unreachable at boot, enterprise mode | Boot fails within the 30 s deadline, naming the check and bucket (D9), through the existing `ValidateSecretAuditWitness` error path. Strict on purpose; see Decisions, F3. A witness configured without enterprise mode is validated at boot the same way. |
| S3 unreachable at run time | The ship fails, `aerolvm_secret_audit_witness_healthy` drops to 0 and the failures counter rises. Records keep being written locally, and the next ship catches up. |
| Bucket without lock or versioning | Boot fails with the fix in the message |
| Node role without `s3:ListBucket` | Boot fails at the missing-key probe and names the permission (D19) |
| `SB_AUDIT_WITNESS_BACKEND` set without `SB_NODE_ID`, or with `standalone` | Config load fails and names `SB_NODE_ID` (D3) |
| Local log edited or deleted | Boot fails (`secret audit witness mismatch`). This behavior already exists. |
| Disk lost or node rebuilt under the same `SB_NODE_ID` | Boot fails under the existing erasure rule. Object Lock forbids clearing the old head, so the message says to rebuild under a new `SB_NODE_ID`; the old id's locked history stays as the record of the loss. The runbook covers single servers and cluster remove-and-rejoin (D4). |
| A delete marker on the newest day's head key | `LastWitnessedHead` returns an error, so boot fails |
| Another node writes into this node's key (shared role), or two servers share an `SB_NODE_ID` by mistake | The victim reads the witness before every ship, so on its next tick, busy or idle, it counts the foreign head in `aerolvm_secret_audit_witness_foreign_head_total`, logs a warning naming both heads, and an alert fires; the loop then ships as today (D18, D23). A foreign write that lands between the victim's read and its write is buried under the victim's version, and only the verifier sees it. A restart fails only if the foreign head is still the newest. The verifier always reports FAIL; attribute the write with CloudTrail S3 data events (D8). |
| Node idle across UTC midnight | Its first tick of the day re-ships the unchanged head to today's key. That is not counted as foreign (D20). |

### Cost (AWS list prices, us-east-1, per node)

- Reads: one GET of today's key every 30 seconds, busy or idle, because the loop reads before it writes (D23). That is 2,880 a day, or about $0.001 a day.
- Writes: at most one PUT every 30 seconds when the head changes (D10), plus one a day for an idle node (D20). That is under $0.015 a day.
- Storage: about 300 bytes per version, up to about 1 million versions a year spread over one key per day (at most 2,880 per key), which is about 300 MB, or under $0.01 a month.
- Boot: about seven calls (versioning, lock configuration, missing-key probe, canary PUT and two DELETEs, latest head), plus one LIST and one GET for a node that was down across midnight.

## Code changes

| Area | Change |
|---|---|
| `pkg/auditwitness/` (new) | `Open` (switches on the backend name, 30 s deadline), the `s3` backend with day-partitioned keys, boot checks with the missing-key probe and the bypass-header canary, a local `ok=false` for the `standalone` id, and unit tests on an `httptest` S3 fake through the real client; the fake answers 403 for a missing key when its role lacks `s3:ListBucket` (D1, D2, D7, D9, D12, D19, D24) |
| `pkg/auditexport/s3.go` | Rename `newS3Client` to an exported `NewS3Client` with a neutral error prefix (D1) |
| `internal/config/config.go` | The `SB_AUDIT_WITNESS_*` settings, validation (including the `SB_NODE_ID` rule, D3), and `AuditWitnessConfig()` |
| `pkg/daemon/daemon.go` | Resolve the witness before the gate at line 294 |
| `pkg/controlplane/controlplane.go` | Update the `Witness` comment: "No-op unless a provider or `SB_AUDIT_WITNESS_BACKEND` supplies one" |
| `internal/service/secret_audit_witness.go` | The erasure boot error names the rebuild-under-a-new-`SB_NODE_ID` recovery, and the comment at `:364-367` is updated (D4). The ship loop reads the witness before every ship, not only when the head is unchanged (`:203`), counts a head this node did not ship, or a missing head, in `aerolvm_secret_audit_witness_foreign_head_total` and logs a warning before shipping; a read error is not counted (D18, D23). It re-ships an unchanged head on its first tick of each UTC day, keyed on the receipt's `ShippedAt` date (D20) |
| `setup/prometheus/` | An alert rule on any increase of `aerolvm_secret_audit_witness_foreign_head_total` (D18) |
| `internal/service/secret_audit.go` → `pkg/auditlog` | Move `secretAuditChainVerifier` and `recomputeChain`'s scan rules into `pkg/auditlog`, shared by the daemon and the verifier; existing tests move with them (D6) |
| `cmd/aerolvm/` | `aerolvm audit verify`, the offline verifier (Phase 5; D5, D6, D15, D21, D22): `--since` (required), `--export s3://…` or `--export-dir`, `--local`, `--max-lag`; exit 0 PASS, 1 FAIL, 3 INCOMPLETE (2 stays the CLI's usage error); export batches walked by chain linkage per UTC day |
| `Terraform/` | An optional witness bucket: Object Lock, versioning, default retention, a noncurrent-version lifecycle rule, the IAM statements above (including an unconditioned `s3:ListBucket`, D19), an optional auditor read-only policy (D22), and variables `witness_lock_mode` (default `COMPLIANCE`) and `witness_lock_days` (default 30, ≥ `SB_SECRET_AUDIT_RETENTION_DAYS`) (D13) |
| `integration-tests/` | A new single-node enterprise scenario plus all six existing enterprise scenarios on governance 1-day buckets; teardown empties the bucket with the bypass flag; then delete `cmd/sandboxd/provider_itest.go` and the `sandboxd-witness` build (D13, D17) |
| `Ansible/`, `install.sh` | Pass the settings through, including `SB_NODE_ID`. The installer only documents them and never creates buckets. |
| `setup/config-defaults.md`, `setup/runbooks/secrets-and-audit.md` | New settings, the bucket recipe, what to do on a witness mismatch, the rebuild-under-a-new-`SB_NODE_ID` procedure (D4), cross-node write attribution with CloudTrail (D8), and what a foreign-head alert does and does not prove (D23) |

## Tests

The full requirement list, with a value card per case, is [`plans/open-audit-witness-test-plan.md`](./open-audit-witness-test-plan.md).

- **Unit (`pkg/auditwitness`, ≥85% coverage, table-driven), all through the real client against an `httptest` S3 fake that speaks S3 XML and error codes (D12):**
  - put, then get the latest head from today's key;
  - today's key missing: the newest day is found with `ListObjectVersions` (D2);
  - no versions anywhere returns `ok=false`;
  - a delete marker on today's key, or on the newest day's key of an idle node, returns an error and never falls back to the previous day (C2);
  - every boot-check failure: versioning off, lock off, no default rule, retention too short (including a rule given in Years), a canary delete that succeeds with the bypass header (D7), a canary delete that fails with a non-AccessDenied error, and an endpoint that never answers (30 s deadline, D9);
  - a PUT without `x-amz-sdk-checksum-algorithm` and `x-amz-checksum-sha256` is rejected 400 by the fake, exactly as S3 rejects it, and the real client's PUT succeeds;
  - one request per changed-head ship; the receipt is `ReceiptID = VersionId` with zero `RecordedAt` (D10);
  - `len(heads) != 1` is an error (D11);
  - a missing key answers 403 when the fake's role lacks `s3:ListBucket`, and `Open` refuses boot naming the permission; with the permission it answers 404 and the fallback runs (D19);
  - `LastWitnessedHead("standalone")` returns `ok=false` and the fake sees no request (D24).
- **Config:** unknown backend, `s3` without a bucket, and backend set with `SB_NODE_ID` empty or `standalone` each fail with a message naming the setting (D3); a prefix without a trailing slash still yields `<prefix>/node=…`.
- **Service:** the erasure boot error names the new-`SB_NODE_ID` recovery (D4); the ship loop counts and logs a foreign head and a missing head on an idle tick and on a busy tick (head changed since the last ship), and leaves the counter alone for a matching head and for a read error (D18, D23); the first tick of a new UTC day re-ships an unchanged head, and a later tick that day does not (D20); every existing `internal/service/secret_audit*_test.go` passes after the D6 move with unchanged assertions.
- **Daemon (regression contract, D14):**
  - S3 witness settings present but the backend unset: the fake sees 0 requests, and `SB_SECRET_AUDIT_EXTERNAL_WITNESS=true` still fails closed with the existing message (`pkg/daemon/misc_coverage_test.go:10` stays green unchanged);
  - a provider witness plus `SB_AUDIT_WITNESS_BACKEND=s3`: the fake sees 0 requests and the provider witness is installed;
  - the setting fills a placeholder witness, and enterprise mode boots against the fake.
- **Verifier (`pkg/auditlog`, `cmd/aerolvm`):**
  - PASS across a retention prune when the link exists only in the export; FAIL on a forged newer head, a rollback to an older head, a forged retention checkpoint and a missing link (D5);
  - export batches are walked by chain linkage, one UTC day at a time, never by key order. An honest history passes across a prune in the middle of a day (the new generation's offsets restart), a batch re-sent after midnight, a re-export after a cursor reset, and node ids containing `_` (D21);
  - a head newer than `--since` that the evidence never reaches is FAIL, including when the oldest export batches inside the window were removed; a head older than `--since` is listed and not checked (D22);
  - without `--local`, a head newer than the end of the evidence is pending, and one pending longer than `--max-lag` makes the result INCOMPLETE (exit 3), never PASS (D22);
  - two versions in the same second on one key keep S3's version order (D22);
  - a node idle for days is not listed as silent; one with no version for more than a day plus N intervals is (D5, D20);
  - allocations stay bounded by the witness version list plus one day's batch index on a large synthetic history (D15, D21);
  - `TestDependencyGuard` stays green with the AWS SDK added (D6).
- **Integration (real AWS, `integration-tests/`):**
  - a new single-node enterprise scenario, plus all six existing enterprise scenarios (`cluster-3-mixed-secrets-enterprise` and the five `cluster-hetero-*`), on governance buckets with a 1-day lock and `SB_SECRET_AUDIT_RETENTION_DAYS=1` (D13, D17);
  - a first boot against an empty witness bucket with the Terraform node role (D19);
  - tamper cases: edit the local JSONL (boot fails), delete it (boot fails), try a delete marker with the node role (denied);
  - teardown empties each bucket with the bypass flag before `terraform destroy`; the first run must show a clean `--destroy-only` (D13);
  - each scenario keeps `itestwitness` until it passes on S3; once all of them do, delete `cmd/sandboxd/provider_itest.go` and the `sandboxd-witness` build (D17);
  - **release smoke (T24):** after the release of Phases 1–5 is published, the new single-node enterprise scenario runs once on the published artifact (`integration-tests/run.sh <scenario> --version <tag>`). Phase 4 tests working-tree builds, and the docs promise the released binary.
- `make test` stays offline. AWS calls live only in `integration-tests/`.

## Phases

Ship as stacked PRs, one per phase, and merge nothing until the whole stack is green. Then merge Phases 1–5 and cut a release from them. Phases 6 and 7 (docs and the blog post) merge only after that release is published and the release smoke (T24) passes on it. The docs site publishes from `main`, and both phases tell readers to turn enterprise mode on with the free download, so merging them earlier would describe a release that does not exist yet.

The Tasks column maps each task in "Implementation Tasks" to the PR that carries it. A task split across two phases names its part.

| # | Phase | Tasks | Done when | Size (human / CC) |
|---|---|---|---|---|
| 0 | Decisions below | | Done 2026-10-11; follow-up 2026-10-16 | |
| 1 | `pkg/auditwitness` S3 backend, boot checks and the `httptest` S3 fake | T1, T7, T8, T13, T14, T15, T16, T18 (code and fake), T23 | Unit tests green, ≥85% coverage | ~5 days / ~3 h |
| 2 | Settings (including the `SB_NODE_ID` rule), daemon wiring and the service changes | T2, T3, T6, T9, T19, T22 | Enterprise mode boots on the release build against the fake. With no setting the fake sees zero requests. The foreign-head, read-error and daily re-ship rows pass. | ~2.5 days / ~2 h |
| 3 | Terraform bucket (lock mode and days variables), IAM (including `s3:ListBucket`), the auditor read-only policy, Ansible, runbook (rebuild, attribution) and config defaults | T10 (Terraform), T12 (runbook), T18 (IAM), T21 (auditor policy) | `terraform plan` is clean with and without the witness | ~2 days / ~2 h |
| 4 | Integration on real Object Lock buckets: a new single-node scenario plus all six enterprise scenarios; then delete the itest witness | T10 (teardown), T11 | All runs green, a first boot on an empty bucket succeeds, tamper cases fail closed, `--destroy-only` leaves no bucket, `provider_itest.go` and the `sandboxd-witness` build deleted | ~4 days plus metal AWS time / ~4 h plus AWS time |
| 5 | Chain verifier moved to `pkg/auditlog`; `aerolvm audit verify` | T4, T5, T20, T21 (verifier) | Catches a forged newer head, a rollback, a forged checkpoint, a missing link and removed early exports; passes an honest history across a prune, including one in the middle of a day; reports INCOMPLETE for a stalled export; memory stays bounded | ~6 days / ~5.5 h |
| — | Release smoke | T24 | The new single-node enterprise scenario passes on the published release artifact | ~0.5 day / ~15 min plus AWS time |
| 6 | Docs and positioning | T12 (docs) | The pages below are updated, the docs checks pass, and the PR merges after the release smoke passes | ~1 day / ~1 h |
| 7 | Blog post | T17 | The post below merges after the release smoke passes and is live, linked from the Blogs index and the security overview, and every number in it is traced to the shipped code or a Phase 4 run | ~1 day / ~1 h |

### Phase 6 docs

These pages merge only after the release of Phases 1–5 is published (see Phases).

- **Enterprise Overview (`enterprise/index.mdx`):** add a row "Off-server audit witness (S3 Object Lock)", marked *You turn it on*. Enterprise mode is no longer managed-build only.
- **Security controls, Audit (`enterprise/security-controls.mdx`):** add a "Tamper evidence off the server" row.
- **Hardening (`enterprise/hardening.mdx`):** add enterprise mode back as a server setting, now open to everyone, with its requirements listed.
- **Audit and compliance (`enterprise/audit-evidence.mdx`):** add the witness to "Evidence you can collect", strengthen the AU-9 row, and add a step to "Prepare for an audit" that runs `aerolvm audit verify` with a `--since` that matches the retention period. Say that exports must be kept at least as long as that window. The integration suite's export bucket (`Terraform/audit_export.tf`) expires objects after 3 days, which suits tests and is too short for an audit.
- **CLI (`cli.mdx`):** document `aerolvm audit verify` and its flags in the Reference section, in that page's own format.
- **Secrets providers:** the checklist step "Set `SB_ENTERPRISE_MODE=true`" becomes correct. Add "configure the witness" next to it.
- **New Docs page, "Enterprise mode" (`enterprise/enterprise-mode.mdx`):** what it turns on, the witness bucket recipe (including the required `SB_NODE_ID` and `s3:ListBucket`), how to rebuild a node under a new id, how to run `aerolvm audit verify` (the `--since` window, and what PASS, FAIL and INCOMPLETE mean), what a foreign-head alert does and does not prove (D23), and the five-language `sandbox.audit()` example. Register it in the Enterprise tab (the `ent` group in `content.config.ts`).
- **Ideas Discussions:** post this as proposal 7, or as an announcement if it ships first.

### Phase 7 blog post

A post in the docs site's Blogs section that tells the story behind the feature. The Phase 6 pages say how to turn it on; the post says why it exists and why each check is there. It is its own PR on top of the stack, and like Phase 6 it merges only after the release of Phases 1–5 is published.

- **File and links:** `docs/src/content/docs/engineering-audit-witness.mdx`, title "Catching a rewritten audit log". Add it to the "How AerolVM Is Built" group in `getBlogSidebarConfig` (`docs/src/content.config.ts`) as `link('/engineering-audit-witness', '- Catching a rewritten audit log')`, and add a row to the "How AerolVM is built" table in `docs/src/content/docs/blog.mdx`.
- **Shape:** the same as the other `engineering-*.mdx` posts: the maintainer byline, an "In short" list, a mermaid diagram, plain language at a 10th-grade reading level, and a "Next steps" list.
- **Outline:**
  1. **The problem.** A hash chain catches an edited record but not a whole chain rebuilt by someone who controls the server. This picks up where "The logbook: audit" in `engineering-security-overview.mdx` stops.
  2. **The witness.** What it stores (fingerprints, not records), why the free build had only a placeholder, and what Object Lock adds. Diagram: `sandboxd` writes a fingerprint to the locked bucket every 30 seconds; an auditor's laptop runs `aerolvm audit verify` against the bucket, the export and the local log.
  3. **Making sure the bucket is really locked.** The boot checks, and why the test delete is sent with the bypass header, the way an attacker would send it (D7).
  4. **One key per day.** The AWS guidance of fewer than 100,000 versions per object, and why finding the newest day needs `ListObjectVersions`: `ListObjectsV2` hides a key whose newest version is a delete marker (D2, C2).
  5. **The attack the boot check misses.** A hacked server writes a new fake fingerprint that matches a rewritten chain. The verifier catches it by linking every fingerprint to the next one through the local log and the off-node export, over a time window the auditor sets, so deleting old records cannot shrink the check (D5, D21, D22).
  6. **What it does not protect.** The three limits in "What the witness proves, and what it does not" above, plus the cross-node write limit (D8), a foreign write that slips between a node's read and its write, which only the verifier catches (D23), restarts blocked during an S3 outage (founder F3), and a rebuilt node needing a new `SB_NODE_ID` (D4).
  7. **What it costs.** S3 requests and storage per node.
  8. **Try it.** A link to the new "Enterprise mode" page for the settings, and the five-language `sandbox.audit()` example.
- **Code rules:** the only code is the `sandbox.audit()` example in five `<Tabs syncKey="lang">` tabs (TypeScript, Python, Go, Rust, Java), checked against `sdk/*`. Settings and `aerolvm` commands stay on the "Enterprise mode" page, so the post has no shell or HTTP examples.
- **Numbers:** every number comes from the shipped code (the boot calls, the 30-second interval, the 30-second boot deadline) or from a Phase 4 run (request counts, boot time, cost). The plan's estimates are not quoted.
- **Links into the post:** in `engineering-security-overview.mdx`, the line "An outside witness for the free version is planned." becomes a link to the post. The Ideas Discussions announcement from Phase 6 links to the post too.

## PR call-outs (`pr-review.md`)

- **Boot-path latency (`CreateSandbox`):** none. The witness runs on daemon boot and on a background loop.
- **Daemon boot:** adds about seven S3 calls (versioning, lock configuration, missing-key probe, canary put and two deletes, latest head) when configured, plus one LIST and one GET for a node that was down across midnight, all under a 30 s deadline; none otherwise.
- **Witness ship loop (every backend):** reads the witness before every ship, not only when the head is unchanged (D23), and re-ships an unchanged head once per UTC day (D20). For the S3 backend that adds no request; for a provider witness it adds one read per changed-head ship and one write a day.
- **Cluster:** no FSM, placement or gossip change. With cluster mode off, the behavior is the same.
- **Idempotency:** re-shipping the same head adds a version. That is harmless, and the daemon already skips unchanged heads after a successful read-back, except for the one daily re-ship (D20).
- **Failure paths:** no multi-step write across S3 and the store. The local receipt is written after the S3 acknowledgment, as today.

## Decisions (founder, 2026-10-11: "go with your suggestions")

Founder decisions are numbered F1–F5 so they don't collide with the engineering review's D1–D24.

| # | Question | Decision |
|---|---|---|
| F1 | Which retention mode do the docs recommend? | **Compliance for production, governance for trials.** |
| F2 | AWS only in v1, or S3-compatible stores too? | **Support the endpoint setting, but test and document only AWS in v1.** The boot checks still protect any store, because one without Object Lock fails them. |
| F3 | Should an S3 outage block node restarts in enterprise mode? | **Yes, for now.** Same as today with any witness. Revisit if users hit it. |
| F4 | Keep the boot canary? | **Yes.** |
| F5 | Keep the name "enterprise mode"? | **Keep it.** The docs say anyone can use it. |

## Acceptance

- The released `sandboxd`, with `SB_ENTERPRISE_MODE=true` and a witness bucket, boots on one server and on a 3-node cluster. The release smoke (T24) checks the published artifact before the docs merge.
- A first boot against an empty witness bucket succeeds with the Terraform node role, and a role without `s3:ListBucket` is refused at boot by name (D19).
- The same setup with an ordinary bucket refuses to start and names the fix.
- Editing or deleting the local audit log makes the node refuse to boot.
- The node role cannot delete or hide a witnessed head.
- The offline verifier catches a rewritten history that the boot check passes.
- The verifier passes an honest history across a retention prune, including one in the middle of a day, by reading the export (D21), and fails a rollback, a forged checkpoint, a missing link and a window whose oldest export batches were removed (D22).
- The verifier reports INCOMPLETE, never PASS, when the export has stalled and no local log was given (D22).
- An idle node writes today's key once per UTC day, and the verifier does not list it as silent (D20).
- A foreign write into a busy node's key raises the foreign-head alert on that node's next tick (D23).
- Two single servers sharing a bucket without `SB_NODE_ID` refuse to start, naming the setting.
- A rebuilt node's boot error names the new-`SB_NODE_ID` recovery.
- All six existing enterprise scenarios run on the S3 witness, and the `itestwitness` build is gone.
- With no witness setting, behavior is identical to today, and the test fake records zero S3 calls.
- The Phase 6 docs pages and the blog post go live only after the release of Phases 1–5 is published and the release smoke passes.
- The blog post "Catching a rewritten audit log" is live, linked from the Blogs index and the security overview, and its numbers match the shipped code and the Phase 4 runs.

---

# Engineering review (/plan-eng-review, 2026-10-11)

Target: `plans/open-audit-witness.md` (fixed for this review). Reviewer: Claude, primary. Code evidence was checked against `origin/main` at `ec4c1c16`; the checkout's only extra commit touches docs.

## Scope record

feature answers: no cuts proposed; structure: A, Smaller arrangement (D1, user answer 2026-10-11); accepted scope: the plan's features and phases unchanged, arranged as `pkg/auditwitness` without a backend registry (`Open` switches on `SB_AUDIT_WITNESS_BACKEND`, and an unknown name is a config error), with the S3 client from `auditexport.newS3Client` renamed to an exported `NewS3Client` with a neutral error prefix, and no new shared package; pending remedies: every Section 1–4 finding.

Scope Challenge result: scope accepted as-is. The smaller arrangement keeps the same features.

Scope Challenge findings: no issues found beyond the structure answer. Every code citation in the plan matched `origin/main`.

## Decision ledger

### R1: Witness key layout vs. S3's per-object version limit
Finding: A1, P1, confidence 9/10, plan lines 89-93 and 163 ("up to about 1 million versions a year"), `internal/config/config.go:1840` (`SB_SECRET_AUDIT_RETENTION_DAYS` default 30), reviewer Claude.
Plan baseline: original proposal, not approved: one key per node, `<prefix>node=<node-id>/head.json`, and every ship adds a locked version.
Runtime evidence: proposed code; nothing runs today. AWS guidance: keep each object under 100,000 versions; millions of versions on one object cause bucket-wide 503 Slow Down on PUT and DELETE (AWS "Troubleshooting versioning"). Arithmetic: 2,880 ships a day at the 30 s default, and a locked version cannot expire before its lock does, so the floor is 2,880 × retention days: 86,400 at 30 days, 259,200 at 90 days.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1 key layout | one key per node (proposal, pending) | one key per node per UTC day, built with `path.Join` | one key per node | one key per node |
| R1 version guard | none | not needed: at most 86400 / interval versions per key | `Open` refuses retention_days × 86400 / interval > 100,000 | none; the limit is documented |
| R1 latest-head read | 1 GET | 1 GET; when today's key is missing, 1 LIST + 1 GET | 1 GET | 1 GET |
| R2–R13 (later findings) | pending | pending | pending | pending |

Question D2:
D2 — Witness key layout: one key per node passes S3's per-object version limit
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: Every 30 seconds a busy node writes its fingerprint as a new version of the same S3 object, and Object Lock stops old versions from being deleted until their lock ends. AWS says to keep any one object under 100,000 versions; past that, S3 throttles writes to the whole bucket. At the default 30-day lock a busy node holds about 86,000 versions on its one key, and a 90-day lock reaches about 260,000. Once the witness is throttled, ships fail, and in enterprise mode node restarts fail too.
Stakes if we pick wrong: about a month after launch, a customer with longer retention sees witness ships fail and nodes refuse to restart, and the key layout can't change without a data migration.
Recommendation: A because it keeps the plan's one-GET read in the common case and caps each key at one day of versions (2,880 at 30 s) whatever the retention.
Completeness: A=9/10, B=6/10, C=3/10
Pros / cons:
A) Day-partitioned keys (recommended)
  ✅ Each key holds at most one day of ships (2,880 at 30 s, 8,640 at 10 s), far below 100,000 for any retention
  ✅ The common read is still one GET of today's key; only an idle node's boot pays one extra LIST and GET
  ❌ The day comes from the node's clock, so a clock jump across midnight can make boot read the wrong day and fail closed (loud, not silent)
B) One key plus a guard
  ✅ Keeps the plan's simplest layout and read path exactly as written
  ✅ The boot check makes the limit explicit, so nobody reaches throttling by surprise
  ❌ At the 30 s default, retention is capped at 34 days, so customers who need 90 days can't use the witness
C) Keep one key
  ✅ No change to the plan or the code it describes
  ✅ Works for any deployment that keeps retention at or below about 34 days
  ❌ Longer retention hits bucket-wide throttling weeks after launch, and the fix then needs a layout migration
Net: one extra LIST on idle-node boots buys a layout that never reaches S3's version limit.
Header: Key layout
Options:
A) Day-partitioned keys
Key = path.Join(prefix, "node="+id, "day="+UTC yyyy-mm-dd, "head.json"), which also fixes a prefix set without a trailing slash. Write: PUT today's key. Latest: GET today's key; on NoSuchKey, one ListObjectsV2 with Delimiter under node=<id>/ finds the newest day, then GET it, with the planned delete-marker check on that key. The verifier orders versions across all day keys by S3 LastModified. Effort: human ~0.5 day / CC ~20 min. Risk: low; clock jumps fail closed. Maintenance: one extra read branch with tests.
B) One key plus a guard
Keep <prefix>node=<id>/head.json. auditwitness.Open refuses to start when retention_days × 86400 / SB_SECRET_AUDIT_WITNESS_INTERVAL exceeds 100,000, naming both settings. Effort: human ~1 h / CC ~5 min. Risk: caps retention at 34 days at the 30 s default. Maintenance: one boot check.
C) Keep one key
Plan unchanged; docs state the per-object version limit and the retention at which it is reached. Effort: none. Risk: bucket-wide throttling and failed restarts for retention above about 34 days. Maintenance: a layout migration later if anyone hits it.

State: approved
Actual answer: A) Day-partitioned keys (D2, user answer 2026-10-11)
Accepted scope: key = `path.Join(prefix, "node="+id, "day="+UTC yyyy-mm-dd, "head.json")`; a write PUTs today's key; the latest head is a GET of today's key and, on NoSuchKey, one `ListObjectVersions` with Delimiter under `node=<id>/` to find the newest day (so a day whose current version is a delete marker still counts as newest), then a GET of it with the planned delete-marker check; the verifier orders versions across day keys by S3 LastModified; unit tests cover the fallback branch, including a delete marker on the newest day's key of an idle node (must be an error, never a fall-back to the previous day). The plan's Storage layout, Mapping and Cost text is updated at the end of this review.
History: 2026-10-11, Section 2 correction (no new answer needed; necessary implementation of the delete-marker check approved in D2). Earlier accepted-scope wording used "one ListObjectsV2 with Delimiter" to find the newest day. ListObjectsV2 omits keys whose current version is a delete marker, so a delete marker on the newest day's key made the fallback silently validate against the previous day's head, bypassing plan line 109's rule. Finding C2, P2, confidence 8/10, reviewer Claude. 2026-10-16, follow-up review: D19 adds `s3:ListBucket`, which the fallback's 404 needs, and D20 adds a daily re-ship so the fallback leaves the steady-state path.

### R2: Single servers default to the same witness id
Finding: A2, P1, confidence 9/10, `internal/service/secret_audit_witness.go:509-520` (`witnessNodeID` falls back to the cluster handle) and `:527-528` ("on a single-node box that is the Noop's \"standalone\", forever"); `install.sh` sets no `SB_NODE_ID`; plan lines 34 and 145. Reviewer Claude.
Plan baseline: original proposal: key `node=<SB_NODE_ID>` (line 145) with no `SB_NODE_ID` requirement; layout approved in R1 (D2) as `node=<id>/day=<UTC date>/head.json`.
Runtime evidence: `witnessNodeID` returns `cfg.NodeID`, else `Cluster().SelfNodeID()`, which is `"standalone"` on a single node. `grep SB_NODE_ID install.sh` finds nothing. So a default single-node install witnesses under `node=standalone`, and two such servers sharing a bucket and prefix write the same keys. Each ship loop then sees a foreign head, re-ships every interval, any restart fails with `secret audit witness mismatch`, and the verifier sees two interleaved chains.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R2 witness id when `SB_NODE_ID` is unset | falls back to `"standalone"` (existing code) | config error at load | falls back to `"standalone"` |
| R2 docs | none | installer, Ansible and runbook set `SB_NODE_ID`; uniqueness is the operator's job | docs say one bucket or prefix per single server |
| R1 key layout | approved: day-partitioned (D2) | unchanged | unchanged |
| R3–R13 (later findings) | pending | pending | pending |

Question D3:
D3 — Single servers all default to the same witness id ("standalone")
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: The witness files each node's fingerprints under its node id. A single server with no SB_NODE_ID uses the id "standalone", and the installer never sets one. So two single servers pointed at the same company bucket write to the same place. Each overwrites the other's latest fingerprint, both keep "repairing" it every 30 seconds, and whichever restarts next refuses to boot with a witness mismatch.
Stakes if we pick wrong: the first customer with two single-server installs and one bucket gets nodes that won't restart and a verifier that reports tampering that never happened.
Recommendation: A because a one-line config check turns a silent collision into a clear boot error with the fix in the message.
Completeness: A=9/10, B=5/10
Pros / cons:
A) Require SB_NODE_ID (recommended)
  ✅ config.Load refuses a witness with an empty or "standalone" node id, so the default install can't collide
  ✅ No storage or protocol change; only the installer, Ansible, docs and runbook set SB_NODE_ID
  ❌ Two servers given the same SB_NODE_ID by hand still collide; uniqueness stays the operator's job
B) Document it only
  ✅ No code change; the docs say to use one bucket or prefix per single server
  ✅ Existing single-node setups need no new setting to turn the witness on
  ❌ The default install still collides silently, and the first symptom is a node that won't restart
Net: one config check versus a silent default that breaks the first multi-server customer.
Header: Node id
Options:
A) Require SB_NODE_ID
internal/config/config.go: when SB_AUDIT_WITNESS_BACKEND is set, SB_NODE_ID must be non-empty and not "standalone"; the error names SB_NODE_ID and says it must be unique per server sharing the bucket. install.sh, Ansible and the runbook pass it. Plus a config test row. Effort: human ~2 h / CC ~10 min. Risk: low. Maintenance: one validation rule.
B) Document it only
No code change. Docs and runbook say each single server needs its own bucket or prefix, or a unique SB_NODE_ID. Effort: human ~30 min / CC ~5 min. Risk: the default install collides silently. Maintenance: none.

State: approved
Actual answer: A) Require SB_NODE_ID (D3, user answer 2026-10-11)
Accepted scope: `internal/config/config.go` rejects `SB_AUDIT_WITNESS_BACKEND` set with `SB_NODE_ID` empty or `"standalone"`; the error names `SB_NODE_ID` and says it must be unique per server sharing the bucket. `install.sh`, Ansible and the runbook pass it. A config test row covers the rule. Duplicate ids set by hand remain the operator's responsibility and are documented as such.
History: none

### R3: A rebuilt node cannot boot for the whole lock period
Finding: A3, P1, confidence 9/10, `internal/service/secret_audit_witness.go:364-381` (`emptyLocalChainIsErasure`; the comment at `:364-367` says an operator rebuilding a node "has to clear the node's witnessed head (and the stale local receipt) deliberately"); plan line 109 (a delete marker is an error); founder decision F1 (compliance mode in production); boot check 3 (lock ≥ `SB_SECRET_AUDIT_RETENTION_DAYS`, default 30). Reviewer Claude.
Plan baseline: original proposal: no rebuild or disk-loss recovery path; a delete marker fails boot; compliance mode for production (founder F1, approved). R1 (D2) and R2 (D3) approved.
Runtime evidence: existing code fails boot when the local chain is empty and the witness still holds a head for this node id. Under compliance Object Lock nobody can delete those versions until the lock ends, and the plan treats a delete marker as tampering. So a node rebuilt or restored from an empty disk under the same `SB_NODE_ID` cannot boot for at least 30 days, and the documented recovery is impossible.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R3 rebuild under the same node id | blocked for the lock period; recovery undocumented | still blocked; the boot error and runbook direct the operator to a new `SB_NODE_ID` | allowed once an operator writes a reset record newer than the latest head | blocked; undocumented |
| R3 erasure rule | empty chain + remembered head = fail | unchanged | unchanged, except a newer reset record satisfies it | unchanged |
| R3 new trust surface | none | none | operator-only `reset/` prefix that the node role is denied | none |
| R1 key layout | approved: day-partitioned (D2) | unchanged | unchanged; `reset/` is a sibling prefix | unchanged |
| R2 `SB_NODE_ID` required | approved (D3) | unchanged | unchanged | unchanged |
| R4–R13 (later findings) | pending | pending | pending | pending |

Question D4:
D4 — A rebuilt node can't boot for the whole lock period
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: If a node's disk is lost or rebuilt, its local audit log is empty, but the witness still remembers its last fingerprint. Today's code calls that "someone deleted the log" and refuses to boot, and its comment says the operator must clear the remembered fingerprint to recover. Object Lock in compliance mode makes clearing it impossible for at least 30 days, and the plan treats a delete marker as tampering. So a routine disk replacement keeps that node down for a month unless there's another way back.
Stakes if we pick wrong: the first enterprise customer who replaces a disk has a node that refuses to start for 30+ days, with an error that points at a recovery step the storage forbids.
Recommendation: A because a new node id is an explicit, logged operator act with no new trust surface, and the old id's history stays in the bucket as the record of the loss.
Completeness: A=8/10, B=9/10, C=2/10
Pros / cons:
A) Rebuild with a new SB_NODE_ID (recommended)
  ✅ No new code path or credential: the erasure rule stays exactly as strict as today
  ✅ The old node id's locked history remains, so an auditor can see when and where evidence was lost
  ❌ The rebuilt server gets a new identity, so cluster mode needs a remove-member and join rather than a plain restart
B) Operator reset record
  ✅ The node keeps its id: an operator writes a reset record and the node boots
  ✅ The reset record is itself locked evidence of who accepted the loss and when
  ❌ A new trust surface: anyone holding the operator credential can launder an erasure, and it needs IAM, code and tests (~2 days human)
C) Leave as planned
  ✅ No work now
  ✅ The erasure rule stays strict
  ❌ The documented recovery is impossible, and a disk replacement means 30+ days of downtime for that node
Net: a new node id costs an identity change on rebuild; a reset record keeps the id but adds a credential that can excuse evidence loss.
Header: Rebuild path
Options:
A) Rebuild with a new SB_NODE_ID
The erasure boot error names the recovery: rebuild under a new SB_NODE_ID. Runbook: a single server picks a new id; a cluster node is removed (scripts/sandboxd-node-lifecycle.sh) and rejoins under a new id (scripts/cluster-join.sh NODE_ID). Update the comment at secret_audit_witness.go:364-367 and add a test asserting the message. Effort: human ~0.5 day / CC ~15 min. Risk: low. Maintenance: runbook text.
B) Operator reset record
Add a reset/node=<id>/ prefix that only an operator principal can write (node role explicitly denied). Boot accepts an empty chain when a reset record newer (by S3 LastModified) than the latest head exists; the verifier reports resets. Effort: human ~2 days / CC ~1.5 h. Risk: a new credential that can excuse evidence loss. Maintenance: IAM, code and tests for a second trust path.
C) Leave as planned
No rebuild path; the existing comment keeps describing a recovery that compliance mode forbids. Effort: none. Risk: 30+ days of downtime for a rebuilt node. Maintenance: support tickets.

State: approved
Actual answer: A) Rebuild with a new SB_NODE_ID (D4, user answer 2026-10-11)
Accepted scope: the erasure boot error names the recovery (rebuild under a new `SB_NODE_ID`). Runbook: a single server picks a new id; a cluster node is removed with `scripts/sandboxd-node-lifecycle.sh` and rejoins under a new id with `scripts/cluster-join.sh NODE_ID`. The comment at `internal/service/secret_audit_witness.go:364-367` is updated to match, and a test asserts the message. The erasure rule itself is unchanged.
History: none

### R4: The offline verifier's inputs and algorithm are unspecified
Finding: A4, P1, confidence 8/10, plan line 53 ("checks every head ever written and those cannot be removed") and Phase 5 (line 211); `internal/service/secret_audit.go:1391-1403` (retention checkpoint: `PrevHash` = last dropped hash plus `WitnessedThrough`; "the leading checkpoint is re-minted by every rewrite"); `pkg/daemon/daemon.go:321-327` (enterprise requires an off-node exporter); `pkg/auditexport/s3.go:22-24` (a re-send overwrites the same object). Reviewer Claude.
Plan baseline: original proposal: the verifier "checks every head ever written"; inputs, algorithm and output are unspecified; acceptance line 247. Approved so far: R1 day keys (D2), R2 (D3), R3 rebuild under a new `SB_NODE_ID` (D4).
Runtime evidence: retention prune drops the chain's expired prefix and writes a checkpoint whose `PrevHash` and `WitnessedThrough` the node asserts itself. After a prune, the local JSONL cannot prove that an older witnessed head links to the current chain, and a forged checkpoint followed by a rewritten tail verifies locally. Enterprise mode already requires an off-node exporter, which holds the dropped records. Because R3 makes a new `SB_NODE_ID` the rebuild path, an attacker with root can also switch ids to dodge the boot erasure check, and only an off-node check sees the old id go silent.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R4 verifier inputs | unspecified | witness versions + local JSONL + exported batches | witness versions + local JSONL | unspecified until Phase 5 |
| R4 a witnessed pair with no linking records | unspecified | FAIL, never a pass | heads before the last prune are reported unverifiable | unspecified |
| R4 coverage report | none | covered window, bounded by the export's retention | window = local retention | unspecified |
| R4 node ids that went silent | not checked | listed as a warning for the auditor to reconcile | not checked | unspecified |
| R4 acceptance (line 247) | as written | kept | narrowed to the local window | as written |
| R1–R3 | approved (D2, D3, D4) | unchanged | unchanged | unchanged |
| R5–R13 (later findings) | pending | pending | pending | pending |

Question D5:
D5 — Specify what the offline verifier reads and when it fails
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: The plan relies on an offline verifier to catch the one attack the boot check misses: a node that rewrites its history and then witnesses a new fingerprint. To catch it, the verifier must prove each old fingerprint leads to the next, which needs the actual log records in between. But retention deletes old local records and leaves a summary line the node writes about itself, so a forger can write that line too. The only honest copy of old records is the off-node export that enterprise mode already requires. Today the plan doesn't say what the verifier reads, so it could be built to trust the node's own summary.
Stakes if we pick wrong: the verifier ships, passes a forged history after the first retention prune, and the docs claim tamper evidence it doesn't deliver.
Recommendation: A because only the export can vouch for pruned history, and treating "can't prove the link" as FAIL is what stops deleted evidence from passing as clean.
Completeness: A=9/10, B=5/10, C=3/10
Pros / cons:
A) Specify the full verifier (recommended)
  ✅ Checks every pair of witnessed fingerprints against records from the local log and the off-node export, so pruned history stays verifiable
  ✅ Missing links fail loudly, and node ids that stopped shipping are listed, which also covers the new-node-id dodge from D4
  ❌ About one extra CC hour in Phase 5, and the verifier needs read access to the export store
B) Local-only verifier
  ✅ Simpler: reads only the witness bucket and the node's own log
  ✅ No access to the export store needed
  ❌ Anything older than the last prune is unverifiable, a forged checkpoint passes, and the acceptance claim must shrink to about 30 days
C) Leave it to the Phase 5 PR
  ✅ No plan change now
  ✅ The implementer can choose with code in hand
  ❌ The hard part (pruned history) gets designed under PR pressure, with no agreed failure rule to review against
Net: reading the export costs one more input; skipping it shrinks the security claim to the local retention window.
Header: Verifier spec
Options:
A) Specify the full verifier
Inputs: every witness version per node id (ordered by S3 LastModified), the local JSONL, and exported batches. Rules: each consecutive pair of witnessed heads must be linked by a recomputed hash-chain segment from those inputs; a pair with no linking segment is FAIL; the report names the covered window (bounded by export retention); node ids whose newest head is older than N witness intervals are listed as silent. Overwriting exports can remove links but cannot forge one. Effort: human ~3 days / CC ~3 h (plan said 2 days / 2 h). Risk: low. Maintenance: one verifier with table tests.
B) Local-only verifier
Inputs: witness versions plus the local JSONL and its latest checkpoint. Heads older than the last prune are reported unverifiable; acceptance line 247 is narrowed to the local retention window; no silent-node check. Effort: human ~2 days / CC ~2 h. Risk: a forged checkpoint passes. Maintenance: low.
C) Leave it to the Phase 5 PR
Plan text unchanged; the Phase 5 author decides inputs and failure rules. Effort: none now. Risk: the security claim's hardest part is designed late with no agreed rule. Maintenance: unknown.

State: approved
Actual answer: A) Specify the full verifier (D5, user answer 2026-10-11)
Accepted scope: verifier inputs are every witness version per node id (ordered by S3 LastModified), the local JSONL, and exported batches. Each consecutive pair of witnessed heads must be linked by a recomputed hash-chain segment from those inputs; a pair with no linking segment is FAIL; the report names the covered window, bounded by export retention; node ids whose newest head is older than N witness intervals are listed as silent for the auditor to reconcile. Acceptance line 247 is kept. Phase 5 is re-sized to human ~3 days / CC ~3 h. Table tests cover each rule.
History: 2026-10-16, amended by D22: the window comes from the auditor's `--since`, not from the evidence; a head newer than the evidence is pending, and a stale pending head makes the result INCOMPLETE. D20 redefines "silent" as no version for more than a day plus N intervals.

### R5: Where the offline verifier lives
Finding: A5, P2, confidence 8/10, plan line 174 ("`cmd/aerolvm/` or a `sandboxd` subcommand"); `integration-tests/lib/build.sh:288` (`sandboxd` is a CGO=1 Linux build); `cmd/aerolvm/deps_test.go:10-25` (forbids `internal/service`, requires a CGO-free build); `internal/service/secret_audit.go:1813-1884` (the chain verifier and `recomputeChain` live in `internal/service`); `internal/service/secret_audit.go:122` (`type SecretAuditEvent = auditlog.Event`, so the event type is already in `pkg/auditlog`). Reviewer Claude.
Plan baseline: original proposal: location undecided. Approved: R4 full verifier (D5), which must run away from the node it audits.
Runtime evidence: `go list -deps ./cmd/aerolvm` shows no AWS SDK packages; `go list -deps ./pkg/auditexport` pulls 97. The verifier must judge chains exactly as the daemon writes them (checkpoints, redacted stubs, gap markers), so a second implementation would drift.
Shared-code rubric (for A and C): callers are `recomputeChain` (`secret_audit.go:1884`) and `newSecretAuditChainVerifier` (`:1813`) in the daemon (existing) plus the verifier (proposed). About 250 lines move to `pkg/auditlog` rather than being copied; net implementation saved ≈ 250 lines; tests move with them. Blast radius: one bug affects boot validation and the verifier alike, which is the point: they must agree.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R5 verifier command | undecided | `aerolvm audit verify` | `sandboxd verify-audit` | a new `aerolvm-audit` binary |
| R5 chain-verification code | `internal/service` only | moved to `pkg/auditlog`, shared | stays in `internal/service` | moved to `pkg/auditlog`, shared |
| R5 runs on an auditor's Mac or Windows laptop | n/a | yes | no (Linux CGO build) | yes |
| R5 release cost | n/a | `aerolvm` grows by the AWS SDK (~97 packages) | none | one more binary in release.yml and install channels |
| R1–R4 | approved (D2–D5) | unchanged | unchanged | unchanged |
| R6–R13 (later findings) | pending | pending | pending | pending |

Question D6:
D6 — Where the offline verifier lives
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: The verifier exists to catch a node that lied, so it must run somewhere other than that node. sandboxd only builds for Linux with C bindings, so an auditor on a laptop can't run it, and the obvious Linux box to run it on is a node. The aerolvm CLI runs anywhere, but it's banned from importing the daemon's internals, and that's where the chain-checking code lives today. Moving that code into the shared pkg/auditlog package lets the daemon and the verifier use one implementation.
Stakes if we pick wrong: either auditors run the tamper check on the machine they're auditing, or two copies of the chain rules drift and the verifier passes chains the daemon would reject (or the reverse).
Recommendation: A because it runs on any auditor's machine, keeps one copy of the chain rules, and adds no new release artifact; the cost is a larger CLI binary.
Completeness: A=9/10, B=6/10, C=9/10
Pros / cons:
A) aerolvm audit verify (recommended)
  ✅ Runs on Mac, Windows and Linux from the CLI auditors already install, so the check happens off the audited node
  ✅ The chain rules move once into pkg/auditlog and both the daemon and the verifier call them
  ❌ aerolvm gains the AWS SDK (~97 packages), so the CLI binary grows by several MB
B) sandboxd subcommand
  ✅ No code move and no new CLI dependencies
  ✅ Ships in the binary operators already deploy, with no release changes
  ❌ Linux-only CGO build, so the natural place to run it is a node, the machine under suspicion
C) New aerolvm-audit binary
  ✅ Same off-node reach and single copy of the chain rules as A
  ✅ Keeps aerolvm lean for people who never verify audits
  ❌ One more artifact in release.yml and every install channel, to build, sign and document
Net: a bigger CLI binary buys an off-node check with one copy of the rules and nothing new to release.
Header: Verifier home
Options:
A) aerolvm audit verify
Add `aerolvm audit verify`. Move secretAuditChainVerifier and recomputeChain's scan rules from internal/service/secret_audit.go into pkg/auditlog; internal/service calls the moved code, and existing tests move with it. aerolvm gains the AWS SDK; the dependency guard stays green because pkg/auditlog is not forbidden. Effort: human ~1 extra day / CC ~30 min. Risk: low (move, not rewrite). Maintenance: one shared implementation.
B) sandboxd subcommand
Add `sandboxd verify-audit` beside the existing re-exec flags in cmd/sandboxd/main.go; no code move. Linux-only. Effort: human ~0.5 day / CC ~15 min. Risk: auditors run it on a node. Maintenance: low.
C) New aerolvm-audit binary
Add cmd/aerolvm-audit with the same pkg/auditlog move as A, plus release.yml, checksums and install-channel entries. Effort: human ~1.5 days / CC ~45 min. Risk: low. Maintenance: one more release artifact.

State: approved
Actual answer: A) aerolvm audit verify (D6, user answer 2026-10-11)
Accepted scope: add `aerolvm audit verify`. Move `secretAuditChainVerifier` and `recomputeChain`'s scan rules from `internal/service/secret_audit.go` into `pkg/auditlog`; `internal/service` calls the moved code and its existing tests move with it. `aerolvm` gains the AWS SDK; `cmd/aerolvm/deps_test.go` stays green because `pkg/auditlog` is not forbidden. Plan line 174 is updated.
History: none

### R6: The boot canary can't see a role that holds governance bypass
Finding: A6, P2, confidence 8/10, plan line 120 ("then `DeleteObject` with that `VersionId`. Expect `AccessDenied`") and line 132 ("Denied by IAM or by the lock, both mean the evidence is safe"); founder F1 (governance mode for trials) and F4 (keep the canary). Reviewer Claude.
Plan baseline: original proposal: the canary deletes its own version without the governance-bypass header. Founder F4 (keep the canary) approved. R1–R5 approved.
Runtime evidence: per AWS, a principal holding `s3:BypassGovernanceRetention` can delete a governance-locked version, but only when the request carries `x-amz-bypass-governance-retention: true`. Without the header, the lock refuses the delete even for that principal. So a node role mistakenly granted bypass passes the planned canary, while an attacker on that node, who would send the header, can delete every governance-locked head. Compliance mode is unaffected, and boot checks 1 and 2 already refuse a bucket without Object Lock before the canary runs.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R6 canary delete request | version-ID delete, no bypass header | version-ID delete with `BypassGovernanceRetention=true` | as planned |
| R6 governance bucket, role holds bypass | canary passes (missed) | boot refused; the message names `s3:BypassGovernanceRetention` | canary passes (missed) |
| R6 compliance bucket | delete refused by the lock | unchanged | unchanged |
| R1–R5 | approved (D2–D6) | unchanged | unchanged |
| R7–R13 (later findings) | pending | pending | pending |

Question D7:
D7 — Make the boot canary delete the way an attacker would
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: At boot the node writes a test object and tries to delete it, expecting a refusal; if the delete works, the bucket isn't protecting anything. In governance mode (F1's trial setting), a delete only skips the lock when the request carries a special "bypass" header and the caller holds bypass permission. The planned canary never sends the header, so it's refused even when the node role wrongly holds bypass. An attacker would send the header and succeed.
Stakes if we pick wrong: a trial customer's misconfigured role passes every boot check while any compromised node can delete all of its own witnessed heads.
Recommendation: A because one extra request field makes the canary test the actual attack, at no cost in compliance mode.
Completeness: A=9/10, B=6/10
Pros / cons:
A) Send the bypass header (recommended)
  ✅ Catches the one governance-mode misconfiguration that makes witnessed heads deletable, before the node serves anything
  ✅ One request field and one fake-S3 test row; compliance mode behaves exactly as before
  ❌ A trial bucket set up with a bypass-holding node role now fails boot until the role is fixed
B) Keep the canary as planned
  ✅ No change to the plan or the boot sequence
  ✅ Still catches buckets where the lock isn't applied to new objects at all
  ❌ A node role holding governance bypass passes, so trial buckets can look protected while they aren't
Net: one header turns the canary from "the lock exists" into "this node can't get around it".
Header: Canary
Options:
A) Send the bypass header
The canary DeleteObject (with VersionId) sets BypassGovernanceRetention=true and still expects AccessDenied; a successful delete refuses boot with a message naming s3:BypassGovernanceRetention. Fake-S3 test row: governance bucket + bypass-holding role → boot refused. Effort: human ~1 h / CC ~5 min. Risk: low. Maintenance: none.
B) Keep the canary as planned
The canary deletes without the bypass header, as written at plan line 120. Effort: none. Risk: governance trials with a bypass-holding role look safe. Maintenance: none.

State: approved
Actual answer: A) Send the bypass header (D7, user answer 2026-10-11)
Accepted scope: the canary `DeleteObject` (with `VersionId`) sets `BypassGovernanceRetention=true` and still expects `AccessDenied`; a successful delete refuses boot with a message naming `s3:BypassGovernanceRetention`. A fake-S3 test row covers a governance bucket with a bypass-holding role. Plan line 120 is updated.
History: none

### R7: Per-node write scoping needs a layout decision now, not in Phase 3
Finding: A7, P2, confidence 7/10, plan line 146 ("Phase 3 can limit each node to its own prefix with an IAM condition on the caller's identity, the same idea as the S3 rendezvous the cluster join already uses"); `Terraform/iam.tf:97-112` (`csr/$${aws:userid}/*`); `Terraform/nodes.tf:465-472`; `internal/service/secret_audit_witness.go:522-536` (`witnessNodeIDCandidates` exists because an id change broke existing history). Reviewer Claude.
Plan baseline: original proposal: shared node role, cross-node writes accepted as a DoS, scoping deferred to Phase 3. Approved: R1 layout `node=<id>/day=<date>/head.json` (D2), R2 (D3), R3 rebuild under a new `SB_NODE_ID` (D4), R4–R6 (D5–D7).
Runtime evidence: the cluster-join rendezvous confines writes with `${aws:userid}`, which for an EC2 instance role is `ROLEID:instance-id`, assigned by AWS. It cannot express `SB_NODE_ID`, so IAM can only confine a node to a key that contains its userid. Under the R1 layout, the Phase 3 sentence is not implementable without a layout change, and changing the layout after data exists is the upgrade trap `witnessNodeIDCandidates` was written for. S3 also records no writer on a version, so without CloudTrail data events the verifier cannot tell whether a foreign head on B's key came from B or from another node.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R7 key layout | approved (D2): `node=<id>/day=<date>/head.json` | unchanged | `node=<id>/writer=<aws:userid>/day=<date>/head.json` |
| R7 cross-node write | possible with the shared role | still possible; documented; shows as a verifier FAIL and a boot refusal on the victim's next restart | denied by IAM |
| R7 plan line 146 | "Phase 3 can limit…" | corrected: scoping needs a writer-identity layout, a v2 change | implemented now (IAM in Phase 3, layout in Phase 1) |
| R7 boot calls | about 5 S3 calls | unchanged | plus 1 `sts:GetCallerIdentity` |
| R7 attribution of a foreign head | none | runbook recommends CloudTrail S3 data events on the witness bucket | structural: the writer path |
| R3 rebuild under a new `SB_NODE_ID` | approved (D4) | unchanged | unchanged; a data volume reattached to a new instance also fails closed |
| R1, R2, R4–R6 | approved | unchanged | unchanged |
| R8–R13 (later findings) | pending | pending | pending |

Question D8:
D8 — Cross-node writes: document the limit, or scope writes per node now?
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: All cluster nodes share one AWS role, so a hacked node A can write a fake fingerprint into node B's folder. It can't erase B's history (the lock stops that), but B refuses its next restart, and the verifier blames B. The plan says Phase 3 can fix this with an IAM rule tied to the caller's identity. The only identity IAM gives us is AWS's own instance id, not our node id, so that rule only works if the folder name contains the AWS identity. That's a layout decision, and it has to be made before any data is written.
Stakes if we pick wrong: either the plan promises a Phase 3 fix that can't be built on the chosen layout, or Phase 1 takes on an extra identity lookup and new edge cases for a DoS that needs an already-hacked node.
Recommendation: A because the attack needs an already-compromised cluster node, it's loud rather than silent, and B adds new fail-closed edges (a reattached disk on a new instance) for limited gain.
Completeness: A=6/10, B=8/10
Pros / cons:
A) Document the limit (recommended)
  ✅ Layout and boot path stay as approved; the plan stops promising a Phase 3 fix it can't build
  ✅ The runbook explains the symptom (verifier FAIL plus a refused restart) and how to attribute it with CloudTrail
  ❌ A compromised node can still knock other nodes over on their next restart, and attribution needs CloudTrail turned on
B) Scope writes per node now
  ✅ IAM denies cross-node writes outright, and the writer path tells the verifier who wrote each head
  ✅ Built in from day one, so no later migration of witness data
  ❌ One extra boot call, writer=static on non-AWS stores, and a data volume moved to a new instance fails closed
Net: honest documentation now versus a structural fix that adds an identity dependency and new boot failure cases.
Header: Cross-node
Options:
A) Document the limit
Keep the approved layout. Rewrite plan line 146: per-node scoping needs a key that embeds the writer's AWS identity, a v2 layout change. Runbook: a cross-node write shows as a verifier FAIL on the victim and a boot refusal on its next restart; turn on CloudTrail S3 data events on the witness bucket to attribute it. Effort: human ~1 h / CC ~5 min. Risk: the DoS remains. Maintenance: docs.
B) Scope writes per node now
Key = node=<id>/writer=<aws:userid>/day=<date>/head.json. Open calls sts:GetCallerIdentity; Terraform grants PutObject only on <prefix>node=*/writer=${aws:userid}/*; reads use the node's own writer path; the verifier lists writers per node id and flags more than one. Non-AWS endpoints use writer=static. Effort: human ~1.5 days / CC ~1 h. Risk: new fail-closed cases. Maintenance: identity-dependent layout.

State: approved
Actual answer: A) Document the limit (D8, user answer 2026-10-11)
Accepted scope: keep the approved layout. Rewrite plan line 146: per-node scoping needs a key that embeds the writer's AWS identity, a v2 layout change. The runbook explains that a cross-node write shows as a verifier FAIL on the victim and a boot refusal on its next restart, and recommends CloudTrail S3 data events on the witness bucket for attribution. Accepted shortcut (completeness 6/10), logged with `gstack-decision-log`; revisit when a customer needs attribution without CloudTrail or a per-node identity layout lands.
History: 2026-10-16, D23 corrected the symptom text: the alert fires on the victim's next tick, and a restart fails only if the foreign head is still the newest.

### R8: `auditwitness.Open` has no time limit at boot
Finding: A8, P3, confidence 7/10, plan lines 115-120 (boot checks and canary run inside `Open` during daemon boot) with no deadline; runtime witness calls are bounded by `secretAuditWitnessShipTimeout = 10 * time.Second` (`internal/service/secret_audit_witness.go:21`). Reviewer Claude.
Plan baseline: original proposal: `Open` "fails boot on bad config" with no stated deadline. Approved: R1–R7 (D2–D8).
Runtime evidence: proposed code. The AWS SDK's default HTTP client has dial and TLS timeouts and retries but no overall request deadline (SDK defaults, not measured here). Against an unreachable endpoint, such as a missing VPC endpoint, boot stalls for the dial timeout times the retry count before the first check fails, and the error names a dial failure rather than the witness check.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R8 `Open` deadline | none (SDK defaults) | 30 s context around all boot checks | none (SDK defaults) |
| R8 error on timeout | SDK dial error | names the witness check that timed out and the bucket | SDK dial error |
| R1–R7 | approved (D2–D8) | unchanged | unchanged |
| R9–R13 (later findings) | pending | pending | pending |

Question D9:
D9 — Put a deadline on the witness boot checks
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: When the daemon starts with the witness turned on, it makes about five S3 calls to check the bucket. If S3 can't be reached (say, the network route is missing), the AWS library waits out its own connection timeouts and retries before giving up, so boot hangs and then prints a low-level network error. The daemon's other witness calls already give up after 10 seconds.
Stakes if we pick wrong: an operator watches a node hang at boot and then sees "dial tcp ... i/o timeout" with no hint that the witness bucket is the problem.
Recommendation: A because a single deadline and a clear message cost minutes and turn a confusing hang into a one-line diagnosis.
Completeness: A=9/10, B=6/10
Pros / cons:
A) 30-second deadline (recommended)
  ✅ Boot fails within 30 seconds when S3 is unreachable, with a message naming the witness check and bucket
  ✅ Matches the existing habit of bounding witness calls (the 10-second ship timeout)
  ❌ A very slow but working S3-compatible store could hit 30 seconds; the value may need a setting later
B) Keep SDK defaults
  ✅ No extra code or test
  ✅ Never cuts off a slow but working store
  ❌ An unreachable bucket hangs boot and ends with a generic network error that hides the cause
Net: one context and one message versus a slow, confusing boot failure.
Header: Open deadline
Options:
A) 30-second deadline
pkg/auditwitness.Open runs its boot checks under a 30 s context; on expiry the error names the check (versioning, lock configuration, canary or latest head) and the bucket. Unit test with a fake endpoint that never answers. Effort: human ~1 h / CC ~5 min. Risk: low. Maintenance: one constant.
B) Keep SDK defaults
No deadline; SDK dial and retry timeouts decide how long boot waits. Effort: none. Risk: slow, unclear boot failures. Maintenance: none.

State: approved
Actual answer: A) 30-second deadline (D9, user answer 2026-10-11)
Accepted scope: `pkg/auditwitness.Open` runs its boot checks under a 30 s context; on expiry the error names the check (versioning, lock configuration, canary or latest head) and the bucket. A unit test uses a fake endpoint that never answers.
History: none

### R9: A `HeadObject` on every ship fills a receipt field nothing reads
Finding: A9, P3, confidence 8/10, plan line 107 (`PutObject` … "then `HeadObject(VersionId)`", "`RecordedAt = LastModified`"); `internal/service/secret_audit_witness.go:241-251` (`RecordedAt` only goes into the local receipt, and falls back to `ShippedAt` when zero); `plans/secrets-hardening.md:988-990` (the witness must record when it saw a head). Reviewer Claude.
Plan baseline: original proposal: `PutObject` then `HeadObject` on every ship, `ReceiptID = VersionId`, `RecordedAt = LastModified`. Approved: R1–R8 (D2–D9).
Runtime evidence: a repo-wide search finds `RecordedAt` written into `witness_receipts.jsonl` and `witness_tip.json` and never read for any decision. The witness-side time the original design asks for is the version's `LastModified` in the bucket, which the verifier reads with `ListObjectVersions` (R4) and which the node cannot change. The extra call adds a request per ship and a failure mode: if `PutObject` succeeds and `HeadObject` fails, the ship reports failure and the next tick writes a duplicate version.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R9 calls per changed-head ship | `PutObject` + `HeadObject` | `PutObject` only | `PutObject` + `HeadObject` |
| R9 local receipt `RecordedAt` | S3 `LastModified` | zero, so the service stores `ShippedAt` (existing fallback) | S3 `LastModified` |
| R9 authoritative witness time | version `LastModified` in the bucket | unchanged | unchanged |
| R1–R8 | approved (D2–D9) | unchanged | unchanged |
| R10–R13 (later findings) | pending | pending | pending |

Question D10:
D10 — Drop the extra S3 read after every witness write
Project/branch/task: reviewing plans/open-audit-witness.md; Section 1 (architecture).
ELI10: After each fingerprint upload, the plan makes a second request just to learn S3's timestamp for it, and stores that timestamp in a local file. Nothing in the daemon ever reads that field. The timestamp that actually matters is already stored on the object in S3, where the node can't change it and where the verifier reads it. The extra request also adds a way to fail: the upload works, the follow-up read fails, and the node uploads the same fingerprint again.
Stakes if we pick wrong: keeping it costs a request every 30 seconds per node plus a duplicate-write failure path; dropping it means the local receipt shows the node's clock, which never mattered.
Recommendation: A because the authoritative time already lives in S3, so the second request buys nothing.
Completeness: A=9/10, B=7/10
Pros / cons:
A) Drop HeadObject (recommended)
  ✅ One request per ship instead of two, and no "upload worked, read failed" retry that writes a duplicate version
  ✅ The witness time stays where the node can't touch it: the version's LastModified, which the verifier reads
  ❌ The local receipt's recorded_at shows the node's ship time rather than S3's, so it can't be quoted as S3's clock
B) Keep HeadObject
  ✅ The local receipt carries S3's own timestamp, matching the plan's wording
  ✅ No change to the plan text
  ❌ An extra request per ship and a failure path that writes duplicate versions, for a field nothing reads
Net: the second request copies a timestamp that S3 already keeps safely.
Header: HeadObject
Options:
A) Drop HeadObject
WitnessHeads does PutObject only (with ChecksumAlgorithm SHA256); ReceiptID = the response VersionId; RecordedAt stays zero, so the service's existing fallback stores ShippedAt. Plan line 107 is rewritten to say the witness time is the version's LastModified, read by the verifier. Effort: human ~30 min / CC ~5 min. Risk: low. Maintenance: one fewer call.
B) Keep HeadObject
PutObject then HeadObject(VersionId); RecordedAt = LastModified, as written at plan line 107. Effort: as planned. Risk: duplicate versions when the read fails. Maintenance: one more call to fake and test.

State: approved
Actual answer: A) Drop HeadObject (D10, user answer 2026-10-11)
Accepted scope: `WitnessHeads` does `PutObject` only, with `ChecksumAlgorithm: SHA256`; `ReceiptID` = the response `VersionId`; `RecordedAt` stays zero, so the service's existing fallback stores `ShippedAt`. Plan line 107 is rewritten: the witness time is the version's `LastModified`, read by the verifier.
History: none

Section 1 dispositions: A1 accepted (D2); A2 accepted (D3); A3 accepted (D4); A4 accepted (D5); A5 accepted (D6); A6 accepted (D7); A7 accepted as a documented limit (D8, shortcut logged); A8 accepted (D9); A9 accepted (D10).

### R10: `WitnessHeads` loops over a list that always holds one head
Finding: C1, P3, confidence 8/10, plan line 111 ("If more arrive, write one version per entry, in order."); `internal/service/secret_audit_witness.go:227-232` (the only caller ships exactly one head); `pkg/controlplane/controlplane.go:150` (one receipt per call). Reviewer Claude.
Plan baseline: original proposal: one version per entry, in order. Approved: R1–R9 (D2–D10).
Runtime evidence: one caller, always one head. A loop that returns one receipt leaves partial failure undefined: head 1 is written and locked, head 2 fails, and the caller gets an error with no receipt for the version that does exist.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R10 `len(heads) != 1` | loop, partial failure undefined | error naming the one-head contract | loop, one version per entry |
| R10 test | none | one table row | rows for ordering and partial failure |
| R1–R9 | approved (D2–D10) | unchanged | unchanged |
| R11–R13 (later findings) | pending | pending | pending |

Question D11:
D11 — Accept exactly one head per witness call
Project/branch/task: reviewing plans/open-audit-witness.md; Section 2 (code quality).
ELI10: The witness interface takes a list of fingerprints, but the daemon only ever sends one. The plan adds a loop for a future with several, which returns a single receipt. If the second write in a loop fails after the first succeeded, the first is permanently locked in S3 and the caller is told the whole call failed. Rejecting anything but one fingerprint keeps the behavior exact until a real second caller exists.
Stakes if we pick wrong: a loop nobody calls ships with undefined partial-failure behavior; or, if a multi-head caller ever appears, it has to add the loop deliberately.
Recommendation: A because it matches the only real caller and removes an undefined failure case.
Completeness: A=9/10, B=7/10
Pros / cons:
A) Exactly one head (recommended)
  ✅ The behavior is fully defined: one PUT, one receipt, one error
  ✅ One table-test row, no partial-failure semantics to design
  ❌ A future caller that batches heads must extend the backend first
B) Loop as planned
  ✅ Ready for a batching caller without another change
  ✅ Matches the plan text as written
  ❌ Partial failure leaves a locked version the caller was told failed, and needs its own rules and tests
Net: one guard clause versus a loop with undefined failure behavior and no caller.
Header: Head count
Options:
A) Exactly one head
WitnessHeads returns an error naming the contract when len(heads) != 1. Plan line 111 is rewritten to match. One table-test row. Effort: human ~15 min / CC ~2 min. Risk: none. Maintenance: none.
B) Loop as planned
Write one version per entry in order; define partial failure (stop at the first error, report it); tests for ordering and partial failure. Effort: human ~1 h / CC ~10 min. Risk: semantics nobody exercises. Maintenance: extra tests.

State: approved
Actual answer: A) Exactly one head (D11, user answer 2026-10-11)
Accepted scope: `WitnessHeads` returns an error naming the contract when `len(heads) != 1`. Plan line 111 is rewritten to match. One table-test row.
History: none

Section 2 dispositions: C1 accepted (D11); C2 accepted as necessary implementation under D2 (recorded in R1's History).

### R11: The checksum gotcha can't be caught by an interface-level fake
Finding: T1, P2, confidence 9/10, plan line 107 (S3 "rejects any upload to a bucket with default Object Lock retention unless it carries `Content-MD5` or an SDK checksum"; the shared client uses `RequestChecksumCalculationWhenRequired`) and test line 186 ("an upload missing the checksum header is refused by the fake, exactly as S3 refuses it"); `pkg/auditexport/s3.go:16-20` (`s3PutObjectAPI` fakes take `*s3.PutObjectInput`, not HTTP); `pkg/auditexport/auditexport_test.go:553-603` (`TestS3BackendRealClientAgainstCompatibleEndpoint`, a real-SDK-against-`httptest` pattern already in the repo). Reviewer Claude.
Plan baseline: original proposal: unit tests "with a fake S3 API (the `s3PutObjectAPI` pattern)". Approved: R1–R10 (D2–D11).
Runtime evidence: an interface fake receives the SDK input struct, so it can see that `ChecksumAlgorithm` was set but not that the SDK actually sent `x-amz-sdk-checksum-algorithm` and `x-amz-checksum-sha256` on the wire under `RequestChecksumCalculationWhenRequired`. That wire behavior is the gotcha. The other paths (NoSuchKey, AccessDenied, delete markers in `ListObjectVersions`) are typed SDK results that an interface fake can return faithfully.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R11 checksum proof | interface fake checks the input field | interface fakes for the suite + one real-SDK `httptest` test that rejects a PUT without the checksum headers | the whole suite on an `httptest` S3 fake | interface fake only |
| R11 other unit paths | interface fake | interface fake | `httptest` S3 fake (XML responses) | interface fake |
| R11 production test hooks | none | none | none | none |
| R1–R10 | approved (D2–D11) | unchanged | unchanged | unchanged |
| R12–R13 (later findings) | pending | pending | pending | pending |

Question D12:
D12 — Prove the checksum headers reach the wire
Project/branch/task: reviewing plans/open-audit-witness.md; Section 3 (tests).
ELI10: S3 refuses uploads to a locked bucket unless a checksum header is on the request. The plan's tests use a fake that receives the upload as a Go struct, so it can only check that our code asked for a checksum, not that the AWS library actually sent the header. The shared client is configured to send checksums only when required, which is exactly the setting that could drop it. The repo already has a test that points the real AWS client at a local fake server, and that's the only way to see the headers.
Stakes if we pick wrong: every unit test passes, and the first real Object Lock bucket rejects every upload, so every enterprise boot fails in Phase 4 or, worse, at a customer.
Recommendation: A because one real-client test covers the wire behavior, and interface fakes stay cheap for the typed paths where they're faithful.
Completeness: A=9/10, B=10/10, C=6/10
Pros / cons:
A) Interface fakes + one wire test (recommended)
  ✅ Catches the real failure: a PUT that reaches S3 without x-amz-sdk-checksum-algorithm and x-amz-checksum-sha256 is rejected by the test server
  ✅ Copies an existing repo pattern (TestS3BackendRealClientAgainstCompatibleEndpoint), so it's quick to write
  ❌ XML parsing of ListObjectVersions and lock-configuration responses is only exercised live, in Phase 4
B) Whole suite on an httptest S3 fake
  ✅ Every call goes through the real SDK, including XML parsing and error codes
  ✅ Closest to S3 without AWS
  ❌ Writing a faithful S3 XML server for five APIs is real work, and its own bugs can mask SDK ones
C) Interface fake only
  ✅ Cheapest, and matches the plan as written
  ✅ Fast, simple table tests
  ❌ Can't see headers, so the named gotcha passes unit tests and fails in production
Net: one real-client test closes the one gap an interface fake structurally can't see.
Header: Wire test
Options:
A) Interface fakes + one wire test
pkg/auditwitness unit tests use interface fakes for typed paths, plus one test that builds the real client via auditexport.NewS3Client against an httptest server returning 400 unless both checksum headers are present, then asserts WitnessHeads and the canary PUT succeed. Value: protects=checksum headers on locked-bucket PUTs; fails_when=checksum config or ChecksumAlgorithm is dropped; why_new=interface fakes can't see headers; seam=none. Effort: human ~2 h / CC ~10 min. Risk: low. Maintenance: one test.
B) Whole suite on an httptest S3 fake
An httptest server implementing PutObject, GetObject, ListObjectVersions, GetBucketVersioning, GetObjectLockConfiguration and DeleteObject with S3 XML and error codes; every unit test runs through the real client. Effort: human ~2 days / CC ~1 h. Risk: fake-server bugs. Maintenance: a mini S3 to keep honest.
C) Interface fake only
Plan as written: an s3PutObjectAPI-style fake that refuses inputs without ChecksumAlgorithm. Effort: none extra. Risk: the header gotcha is invisible to tests. Maintenance: none.

State: approved
Actual answer: B) Whole suite on an httptest S3 fake (D12, user answer 2026-10-11)
Accepted scope: an `httptest` S3 fake in `pkg/auditwitness` tests implementing PutObject, GetObject, ListObjectVersions, GetBucketVersioning, GetObjectLockConfiguration and DeleteObject with S3 XML bodies and error codes. It rejects a PUT without `x-amz-sdk-checksum-algorithm` and `x-amz-checksum-sha256` with 400, honours `x-amz-bypass-governance-retention`, and models delete markers and per-version Object Lock modes. Every `pkg/auditwitness` unit test runs through the real client built by `auditexport.NewS3Client` (Endpoint + path-style), with no production test hooks. Effort human ~2 days / CC ~1 h; the plan's test list (line 181) is updated.
History: none

### R12: Phase 4's live Object Lock buckets have no teardown plan
Finding: T2, P2, confidence 8/10, plan lines 193-197 (move the enterprise scenarios to a real Object Lock bucket on `single-node` and `cluster-3-mixed`); founder F1 (compliance in production); boot check 3 (lock ≥ `SB_SECRET_AUDIT_RETENTION_DAYS`, default 30, `internal/config/config.go:1840`); enterprise refuses zero retention (`internal/config/config.go:2515-2516`); `Terraform/audit_export.tf:16-24` (itest buckets rely on `force_destroy` so teardown is never blocked). Reviewer Claude.
Plan baseline: original proposal: Phase 4 runs on real Object Lock buckets; mode, lock length and teardown unspecified. Approved: R1–R11 (D2–D12).
Runtime evidence: a compliance-mode version cannot be deleted by anyone until its lock ends, so a per-run compliance bucket can't be destroyed for at least 30 days at the default, and never in less than one day because enterprise refuses zero retention. Governance-mode versions can be deleted by a principal holding `s3:BypassGovernanceRetention` that sends the bypass header. Whether the Terraform AWS provider's `force_destroy` sends that header is unverified (the web search was inconclusive).
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R12 itest lock mode | unspecified (production default is compliance) | GOVERNANCE, via a Terraform variable | GOVERNANCE, on one shared bucket | unspecified |
| R12 itest lock length | unspecified (≥ 30 days) | 1 day, with `SB_SECRET_AUDIT_RETENTION_DAYS=1` | 1 day | unspecified |
| R12 bucket lifetime | per run (implied) | per run | one long-lived bucket, a prefix per run | per run |
| R12 teardown | `terraform destroy`, which fails on locked objects | bucket emptied with the bypass flag before destroy; proven on the first Phase 4 run | nothing per run | fails; each run leaks a bucket for 30+ days |
| R12 compliance-mode coverage | none | boot-check unit tests on the D12 fake | boot-check unit tests on the D12 fake | none |
| R12 production defaults | unspecified | `witness_lock_mode = COMPLIANCE`, `witness_lock_days = 30` | unspecified | unspecified |
| R1–R11 | approved (D2–D12) | unchanged | unchanged | unchanged |
| R13 (later finding) | pending | pending | pending | pending |

Question D13:
D13 — How Phase 4's live Object Lock buckets get torn down
Project/branch/task: reviewing plans/open-audit-witness.md; Section 3 (tests).
ELI10: Phase 4 runs the enterprise scenarios against real locked buckets. In compliance mode nobody, not even the AWS root account, can delete a locked object until its lock ends, so the bucket can't be deleted either. With the default 30-day lock, every integration run would leave an undeletable bucket behind for a month. Governance mode can be cleaned up by a principal with bypass permission, and enterprise allows a lock as short as one day.
Stakes if we pick wrong: the first Phase 4 run leaves a bucket nobody can delete for 30 days, the harness teardown fails, and every rerun adds another.
Recommendation: A because per-run buckets keep runs isolated like the rest of the harness, and governance with a 1-day lock is deletable while still exercising the real lock path.
Completeness: A=9/10, B=7/10, C=3/10
Pros / cons:
A) Governance, 1 day, emptied with bypass (recommended)
  ✅ Each run gets its own bucket and destroys it, matching how the harness isolates everything else
  ✅ Production Terraform defaults stay compliance and 30 days; compliance boot checks are covered by unit tests
  ❌ Whether force_destroy sends the bypass header is unproven, so the first Phase 4 run must prove teardown (run.sh empties the bucket itself if not)
B) One shared long-lived bucket
  ✅ No per-run teardown problem at all; runs just use their own prefix
  ✅ Simple to provision once
  ❌ Manual one-time setup outside Terraform, state that outlives every run, and runs that can see each other's prefixes
C) Leave unspecified
  ✅ No plan change now
  ✅ Phase 4 can decide with AWS in hand
  ❌ The default compliance bucket leaks undeletably for 30+ days on every run
Net: a governance, 1-day, per-run bucket keeps the harness clean; compliance is proven offline.
Header: Itest bucket
Options:
A) Governance, 1 day, emptied with bypass
Terraform variables witness_lock_mode (default COMPLIANCE) and witness_lock_days (default 30, must be ≥ SB_SECRET_AUDIT_RETENTION_DAYS). Enterprise itest scenarios set GOVERNANCE, 1 day and SB_SECRET_AUDIT_RETENTION_DAYS=1. Before terraform destroy, teardown empties the bucket with the bypass flag (aws s3api delete-objects --bypass-governance-retention, or force_destroy if the first run proves it sends the header). The first Phase 4 run must show a clean --destroy-only. Effort: human ~0.5 day / CC ~30 min. Risk: low. Maintenance: one teardown step.
B) One shared long-lived bucket
Create one governance, 1-day witness bucket once, outside per-run Terraform; each run uses witness/<run-id>/ as its prefix. Effort: human ~2 h one-time / CC ~15 min. Risk: shared state across runs. Maintenance: a hand-made resource.
C) Leave unspecified
Plan as written; Phase 4 picks mode and teardown. Effort: none now. Risk: undeletable buckets on every run. Maintenance: manual cleanup after 30 days.

State: approved
Actual answer: A) Governance, 1 day, emptied with bypass (D13, user answer 2026-10-11)
Accepted scope: Terraform variables `witness_lock_mode` (default `COMPLIANCE`) and `witness_lock_days` (default 30, must be ≥ `SB_SECRET_AUDIT_RETENTION_DAYS`). Enterprise itest scenarios set `GOVERNANCE`, 1 day and `SB_SECRET_AUDIT_RETENTION_DAYS=1`. Before `terraform destroy`, teardown empties the bucket with the bypass flag (`aws s3api delete-objects --bypass-governance-retention`, or `force_destroy` if the first run proves it sends the header). The first Phase 4 run must show a clean `--destroy-only`. Compliance-mode boot checks are proven by unit tests on the D12 fake.
History: none

### R13: Regression contract for existing behavior (mandatory)
Finding: T3, P1 (regression rule), confidence 9/10, plan lines 188-197 (daemon and integration tests) and line 33 ("Zero change when it is not configured"); existing tests `pkg/daemon/misc_coverage_test.go:10` (`TestCoverage95LiftExternalWitnessRequired`), `pkg/daemon/daemon_coverage_test.go:796` (`TestCoverage95LiftEnterpriseWitnessMismatch`), `internal/service/secret_audit_witness_boot_gate_test.go`, `secret_audit_witness_nodeid_test.go`, `secret_audit_erasure_test.go`, `cmd/aerolvm/deps_test.go:29` (`TestDependencyGuard`), and the six `itestwitness` enterprise scenarios (`integration-tests/scenarios/*.caps.yml`). Reviewer Claude.
Plan baseline: original proposal: "with no setting, nothing changes and the fake records zero calls"; "the provider witness wins over the setting"; keep `itestwitness` until the S3 scenarios pass. Not separately approved. Approved: R1–R12 (D2–D13), including D6 (chain-verifier move) and D12 (`httptest` S3 fake).
Runtime evidence: behavior at risk: the daemon boot order around `pkg/daemon/daemon.go:294-331`; the open-source default (noop witness, external-witness gate fails closed); provider precedence; the service witness rules, whose verifier code moves under D6; the `aerolvm` dependency guard, which gains the AWS SDK under D6; the live enterprise scenarios, which switch witness under Phase 4.
Contract (behavior to preserve): (1) with no `SB_AUDIT_WITNESS_BACKEND`, the placeholder witness stays, zero S3 requests are made, and `SB_SECRET_AUDIT_EXTERNAL_WITNESS=true` or enterprise mode still fail closed with the existing message; (2) a provider-supplied witness wins over `SB_AUDIT_WITNESS_BACKEND`; (3) every existing `internal/service/secret_audit*_test.go` passes after the D6 move with unchanged assertions; (4) the six `itestwitness` scenarios keep passing until the S3 scenarios pass on `single-node` and `cluster-3-mixed`; (5) `TestDependencyGuard` stays green. Intentional changes: the D4 erasure message text and the `aerolvm` binary size.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R13 contract items (1)–(5) | plan baseline, not approved | adopted | adopted |
| R13 zero-request proof | "the fake records zero calls"; mechanism unspecified | the D12 `httptest` fake counts requests: S3 settings present but backend unset → 0; provider witness + backend `s3` → 0 | a package variable `openAuditWitness` in `pkg/daemon` that tests replace with a counting stub |
| R13 production test hooks | none | none | one package variable used only by tests |
| R13 acceptance | unspecified | the existing tests above pass unchanged (except the D4 message); two new daemon tests | same, with the stub-based tests |
| R1–R12 | approved (D2–D13) | unchanged | unchanged |

Question D14:
D14 — Lock in what must not change, and how to prove it
Project/branch/task: reviewing plans/open-audit-witness.md; Section 3 (tests).
ELI10: This change edits the daemon's boot order, moves the chain-checking code into a shared package, adds the AWS SDK to the CLI, and swaps the witness in six live test scenarios. Each of those can quietly break something that works today: the free build making S3 calls, the managed build losing its own witness, or the chain rules changing during the move. This contract lists five behaviors that must stay exactly as they are. The only open question is how to prove "zero S3 calls": count requests on the fake S3 server we're already building, or add a test-only hook in the daemon.
Stakes if we pick wrong: a release where the open-source daemon starts calling S3, or the managed build's witness is silently replaced, and no test notices.
Recommendation: A because the D12 fake server can count requests at the real network boundary, so no test-only hook goes into production code.
Completeness: A=9/10, B=8/10
Pros / cons:
A) Count requests on the fake S3 (recommended)
  ✅ Proves zero calls at the real boundary: configure the endpoint, leave the backend unset, and assert the server saw nothing
  ✅ No production code exists only for tests; reuses the D12 fake
  ❌ Only catches calls to the configured endpoint, not a stray call to default AWS (the existing tests disable instance metadata, which narrows this)
B) Test-only hook in the daemon
  ✅ Counts every attempt to open a witness, whatever endpoint it would hit
  ✅ Simple stub, no server needed
  ❌ Adds a package variable to pkg/daemon that only tests use, the kind of hook the test bar says to avoid
Net: both prove the contract; A does it at the network boundary without touching production code.
Header: Regression
Options:
A) Count requests on the fake S3
Adopt contract items (1)–(5). Existing tests named above pass unchanged except the D4 message. Two new daemon tests boot Run() with the D12 httptest fake as SB_AUDIT_WITNESS_S3_ENDPOINT: S3 settings present but backend unset → fake sees 0 requests; provider witness + SB_AUDIT_WITNESS_BACKEND=s3 → 0 requests and the provider witness is installed. Effort: human ~2 h / CC ~15 min. Risk: low. Maintenance: two tests.
B) Test-only hook in the daemon
Adopt contract items (1)–(5). Add var openAuditWitness = auditwitness.Open in pkg/daemon; tests swap in a counting stub and assert 0 opens for the two cases. Effort: human ~1 h / CC ~10 min. Risk: low. Maintenance: a test-only production variable.

State: approved
Actual answer: A) Count requests on the fake S3 (D14, user answer 2026-10-11)
Accepted scope: contract items (1)–(5) above are adopted. The existing tests named in the finding pass unchanged, except the D4 erasure message. Two new daemon tests boot `Run()` with the D12 `httptest` fake as `SB_AUDIT_WITNESS_S3_ENDPOINT`: S3 settings present but backend unset → the fake sees 0 requests; provider witness + `SB_AUDIT_WITNESS_BACKEND=s3` → 0 requests and the provider witness is installed. No production test hooks. Item (4) as revised by D17: each of the six `itestwitness` scenarios keeps passing until it is moved to the S3 witness in Phase 4, and `provider_itest.go` plus the `sandboxd-witness` build are deleted only after all six pass on S3.
History: 2026-10-11, item (4) revised by D17 (R16). The earlier value kept `itestwitness` on the five `cluster-hetero-*` scenarios indefinitely.

Section 3 dispositions: T1 accepted, full `httptest` S3 fake (D12); T2 accepted (D13); T3 regression contract accepted (D14). The required proofs for D2–D11 are carried into the test plan without new questions. Tests made obsolete by this plan: "the receipt uses S3's `LastModified`" (plan line 187), replaced by D10; the `itestwitness` HTTP witness in all six enterprise scenarios, plus `cmd/sandboxd/provider_itest.go` and the `sandboxd-witness` build, once every scenario passes on the S3 witness (contract item 4 as revised by D17).

Test plan artifact: [`plans/open-audit-witness-test-plan.md`](./open-audit-witness-test-plan.md). It was written to a local gstack directory and copied into the repo on 2026-10-16, with the follow-up review's rows added.

Section 4 notes: steady state at 2,000 nodes is about 67 GET/s and at most 67 PUT/s per bucket, spread across `node=<id>/` prefixes, far below S3's per-prefix limits (3,500 PUT/s, 5,500 GET/s). D10 halves the per-ship requests and D2 removed the per-object version limit. Boot adds about 5 S3 calls, plus one LIST and one GET for an idle node.

### R14: The verifier's memory has no bound, and export keys don't sort in chain order
Finding: P1, P2, confidence 7/10, approved verifier spec D5 (reads every witness version plus the local JSONL and exported batches); `internal/service/secret_audit_witness.go:279-281` ("One pass, O(1) memory … instead of materializing every hash in the file", added by commit 4fb6c844 because the daemon's own scan didn't scale); `internal/service/secret_audit_export.go:65-74` (batch id = `node:offset:digest` with a decimal offset) and `pkg/auditexport/s3.go:83-87` (`:` becomes `_` in the key), so `node_10_…` sorts before `node_9_…`; `SB_AUDIT_EXPORT_BATCH_MAX` default 4096 (`internal/config/config.go:1853`). Reviewer Claude.
Plan baseline: D5 (approved) defines inputs and failure rules but no memory bound or input order. D6 (approved) moves the daemon's streaming chain verifier into `pkg/auditlog`.
Runtime evidence: the daemon's boot verification had to be rewritten as one O(1)-memory pass, so real chains are large enough for O(records) memory to matter. The verifier runs on an auditor's laptop over the same chain plus overlapping exports, per node. A pairwise check that loads every record's hash into a map grows with record count. A key-order listing of export batches is not chain order.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R14 verifier memory | unspecified | bounded by the node's witness version list plus one export batch (≤ 4,096 events) | grows with record count (an in-memory hash index, about 150 B per record) | unspecified |
| R14 export input order | unspecified | day key, then the numeric offset parsed from the batch key; the local JSONL tail last; duplicates dropped by event hash | any order (the index makes order irrelevant) | unspecified |
| R14 test | none | large synthetic chain with offsets 9, 10, 100 across a day boundary; asserts order and bounded allocations | correctness rows only | none |
| R1–R13 | approved (D2–D14) | unchanged | unchanged | unchanged |

Question D15:
D15 — Keep the verifier's memory bounded on large chains
Project/branch/task: reviewing plans/open-audit-witness.md; Section 4 (performance).
ELI10: The verifier walks a node's entire audit chain, from the export store and the local log, on an auditor's laptop. The daemon's own check had to be rewritten to read the chain in one pass with flat memory, because loading every record didn't scale. The easy way to write the verifier (load every record into a lookup table) brings that problem back. Reading in one pass needs the export files in chain order, and their names don't sort that way: batch 10 sorts before batch 9.
Stakes if we pick wrong: the verifier works in tests and runs out of memory on the first real customer's month of audit history, right when an auditor needs it.
Recommendation: A because it reuses the streaming verifier D6 already moves into pkg/auditlog and fixes the ordering trap up front.
Completeness: A=9/10, B=6/10, C=4/10
Pros / cons:
A) Stream in chain order (recommended)
  ✅ Memory stays flat no matter how big the chain gets: the witness list plus one export batch at a time
  ✅ Reuses the one-pass checker the daemon already trusts, moved under D6
  ❌ The verifier must sort export batches by the numeric offset in their names, and a test must pin that order
B) In-memory index
  ✅ Simplest to write: load hashes into a map, then walk each pair of fingerprints
  ✅ Input order doesn't matter at all
  ❌ Memory grows with the record count, about 150 bytes per record, which fails on large histories
C) Leave it unspecified
  ✅ No plan change now
  ✅ Phase 5 can measure first
  ❌ The ordering trap and the memory bound are left for someone to discover on real data
Net: one sort rule and one allocation test keep the verifier usable on real histories.
Header: Verifier mem
Options:
A) Stream in chain order
One ordered pass per node: export batches by day key, then numeric offset parsed from the batch key; then the local JSONL tail; duplicates dropped by event hash at the overlap; each witnessed head checked as the pass reaches it. Memory is bounded by the node's witness version list plus one batch. Test: a large synthetic chain with offsets 9, 10 and 100 across a day boundary, asserting order and bounded allocations. Effort: human ~0.5 day / CC ~20 min on top of Phase 5. Risk: low. Maintenance: one ordering rule.
B) In-memory index
Load every record's hash and prev hash from all inputs into a map, then walk each consecutive pair of witnessed heads. Effort: none extra. Risk: memory grows with history. Maintenance: low.
C) Leave it unspecified
Phase 5 chooses. Effort: none now. Risk: out-of-memory on large histories and a mis-ordered export walk. Maintenance: unknown.

State: approved
Actual answer: A) Stream in chain order (D15, user answer 2026-10-11)
Accepted scope: one ordered pass per node: export batches by day key, then the numeric offset parsed from the batch key; then the local JSONL tail; duplicates dropped by event hash at the overlap; each witnessed head checked as the pass reaches it. Memory is bounded by the node's witness version list plus one batch. A test uses a large synthetic chain with offsets 9, 10 and 100 across a day boundary and asserts order and bounded allocations. Phase 5 grows by about human 0.5 day / CC 20 min.
History: 2026-10-16, order rule superseded by D21. The offset in a batch key is a byte position in the current file generation and restarts after every prune, so batches are walked by chain linkage per UTC day. The memory goal stands.

Section 4 dispositions: P1 accepted (D15). Version-count scaling was resolved by D2.

Outside voice: unavailable. The Codex preflight reported `model_unusable` after `Module not found "/../scripts/resolve-codex-generation-model.ts"` (a stale gstack install; fix with `/gstack-upgrade` or `GSTACK_CODEX_MODEL`). The native fallback needs `TaskOutput`, which this session does not have, so no reviewer ran. Logged as `codex-plan-review` `unavailable`.

### R15: TODO: per-node witness write scoping (v2 layout)
Finding: TODO proposal from D8 (R7), reviewer Claude.
Plan baseline: D8 approved documenting the cross-node write limit; no TODO recorded.
Runtime evidence: `Terraform/iam.tf:97-112` shows the `${aws:userid}` scoping pattern; `internal/service/secret_audit_witness.go:522-549` (`witnessNodeIDCandidates`) is the precedent for reading an old and a new id during a migration.
TODO text: **What:** let IAM confine each node's witness writes to its own path by putting the writer's AWS identity (`${aws:userid}`) in the key. **Why:** D8 left the shared node role able to write into another node's witness history: node A can make B refuse its next restart and make the verifier blame B, and attribution needs CloudTrail. **Pros:** closes the cross-node DoS structurally and gives attribution without CloudTrail. **Cons:** a v2 key layout with a dual-read migration, one more boot call (`sts:GetCallerIdentity`), a data volume moved to a new instance fails closed, and non-AWS stores need a static writer. **Context:** `plans/open-audit-witness.md` R7/D8; start from the Terraform rendezvous policy and the `witnessNodeIDCandidates` dual-read. **Depends on:** open audit witness v1 (Phases 1–5) shipped. Effort M, priority P3.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R15 disposition | not recorded | added to TODOS.md (P3) | skipped | built in this plan |
| R8 (D8) cross-node limit | approved: documented | unchanged | unchanged | reopened: the plan's layout and IAM change now |
| Other approved choices | approved (D1–D15) | unchanged | unchanged | unchanged |
| R16 (later TODO) | pending | pending | pending | pending |

Question D16:
D16 — TODO: scope each node's witness writes to its own path later?
Project/branch/task: reviewing plans/open-audit-witness.md; final planning decisions (TODOS).
ELI10: In D8 you chose to document, not fix, the fact that one hacked cluster node can write fake fingerprints into another node's witness folder. The structural fix puts each node's AWS identity in its folder name so AWS itself blocks cross-node writes. It's a storage-layout change, so it needs a careful migration. This asks whether to record it as a follow-up.
Stakes if we pick wrong: skip it and the reasoning behind D8 is lost by the time a customer asks for attribution; build it now and v1 takes on a layout migration you already chose to defer.
Recommendation: A because D8 deliberately deferred this, and a TODO keeps the reasoning and the starting points findable.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ Keeps the D8 trade-off, the IAM pattern to copy, and the migration precedent in one findable entry
  ✅ No change to the v1 scope you approved
  ❌ One more open entry in an already long TODOS.md
B) Skip
  ✅ TODOS.md stays shorter
  ✅ The decision log already records D8's ceiling and upgrade trigger
  ❌ Whoever picks this up later must rediscover the aws:userid pattern and the migration trap
C) Build it now in this plan
  ✅ Cross-node writes are blocked from day one, with no later migration
  ✅ Attribution without CloudTrail
  ❌ Reverses D8: Phase 1 gains an identity lookup, a writer-path layout and new fail-closed cases
Net: record the deferred fix, or reopen D8.
Header: TODO scoping
Options:
A) Add to TODOS.md
Add a "Per-node witness write scoping (v2 layout)" entry to TODOS.md with the What/Why/Pros/Cons/Context/Depends-on text above, P3, effort M. Effort: human ~10 min / CC ~2 min. Risk: none. Maintenance: one entry.
B) Skip
No TODO; the decision log entry for D8 is the only record. Effort: none. Risk: lost context. Maintenance: none.
C) Build it now in this plan
Reopen D8: writer=<aws:userid> path segment, sts:GetCallerIdentity at Open, Terraform IAM scoping, verifier writer listing. Effort: human ~1.5 days / CC ~1 h. Risk: new fail-closed cases. Maintenance: identity-dependent layout.

State: approved
Actual answer: A) Add to TODOS.md (D16, user answer 2026-10-11)
Accepted scope: add a "Per-node witness write scoping (v2 layout)" entry to `TODOS.md` with the TODO text above, P3, effort M.
History: none

### R16: TODO: move the five `cluster-hetero-*` enterprise scenarios to the S3 witness
Finding: TODO proposal from D14 (R13, contract item 4), reviewer Claude.
Plan baseline: D14 keeps `itestwitness` on the five hetero enterprise scenarios; the plan only moves `single-node` and `cluster-3-mixed` (line 196).
Runtime evidence: six scenarios advertise the witness capability today (`integration-tests/scenarios/*.caps.yml`); `integration-tests/lib/build.sh:288-291` builds a second `sandboxd-witness` artifact with `-tags itestwitness`; `integration-tests/run.sh:700-709` picks it per scenario.
TODO text: **What:** switch `cluster-hetero-lite-routing`, `cluster-hetero-secrets-kms`, `cluster-hetero-lite-kms`, `cluster-hetero-secrets` and `cluster-hetero-lite-secrets` from the `itestwitness` HTTP witness to a governance Object Lock bucket, then delete `cmd/sandboxd/provider_itest.go` and the `sandboxd-witness` build if nothing uses them. **Why:** until then the hetero enterprise runs (metal, Firecracker, ingress) test a witness no customer runs, and the harness keeps a second daemon artifact. **Pros:** one daemon artifact for every scenario, and the customer-facing witness gets hetero coverage. **Cons:** hetero runs are the expensive metal runs, and each needs the D13 teardown. **Context:** `plans/open-audit-witness.md` R13/D14 and R12/D13; start at `run.sh:700` and the five `.caps.yml` files. **Depends on:** Phase 4 green on `single-node` and `cluster-3-mixed`. Effort M (mostly AWS time), priority P2.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R16 disposition | not recorded | added to TODOS.md (P2) | skipped | built in this plan's Phase 4 |
| R13 (D14) contract item 4 | approved: hetero scenarios keep `itestwitness` | unchanged | unchanged | changed: Phase 4 moves all six scenarios |
| Other approved choices | approved (D1–D16) | unchanged | unchanged | unchanged |

Question D17:
D17 — TODO: move the hetero enterprise scenarios off the test-only witness later?
Project/branch/task: reviewing plans/open-audit-witness.md; final planning decisions (TODOS).
ELI10: Six live test scenarios run enterprise mode today using a special test-only build of the daemon with a fake HTTP witness. The plan moves two of them (single server and 3-node) to the real S3 witness. The other five run on expensive metal clusters and would keep the test-only build. This asks whether to record moving them as a follow-up, so the test-only build can eventually be deleted.
Stakes if we pick wrong: skip it and the harness keeps a second daemon build forever, with hetero enterprise runs never touching the witness customers use; build it now and Phase 4's AWS bill grows by five metal runs.
Recommendation: A because it keeps Phase 4 cheap and leaves a clear path to deleting the test-only build.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ Records exactly which five scenarios remain and the files to change, so nobody forgets the second build exists
  ✅ Phase 4 stays at two scenarios and its current AWS cost
  ❌ The hetero enterprise runs keep testing the test-only witness until someone picks this up
B) Skip
  ✅ TODOS.md stays shorter
  ✅ Contract item 4 in this plan already names the five scenarios
  ❌ The test-only build likely outlives its purpose, because nothing tracks its removal
C) Build it now in Phase 4
  ✅ One daemon build for every scenario, and the test-only file goes away in this plan
  ✅ Hetero enterprise runs exercise the real witness immediately
  ❌ Adds five expensive metal runs, plus their teardowns, to Phase 4
Net: record the follow-up, or pay for five more metal runs now.
Header: TODO hetero
Options:
A) Add to TODOS.md
Add a "Move the cluster-hetero enterprise scenarios to the S3 witness" entry to TODOS.md with the text above, P2, effort M. Effort: human ~10 min / CC ~2 min. Risk: none. Maintenance: one entry.
B) Skip
No TODO; contract item 4 in this plan is the only record. Effort: none. Risk: the second daemon build lingers. Maintenance: none.
C) Build it now in Phase 4
Phase 4 moves all six enterprise scenarios, then deletes provider_itest.go and the sandboxd-witness build. Effort: human ~2 days plus metal AWS time / CC ~1 h plus AWS time. Risk: Phase 4 cost and duration grow. Maintenance: less (one artifact).

State: approved
Actual answer: C) Build it now in Phase 4 (D17, user answer 2026-10-11)
Accepted scope: Phase 4 moves all six enterprise scenarios (`cluster-3-mixed-secrets-enterprise` plus the five `cluster-hetero-*` ones) and a new single-node enterprise scenario to governance Object Lock buckets with the D13 teardown. Once all of them pass on S3, Phase 4 deletes `cmd/sandboxd/provider_itest.go`, the `sandboxd-witness` build in `integration-tests/lib/build.sh` and its selection in `integration-tests/run.sh`. Regression contract item (4) in R13 is revised to match. Phase 4 is re-sized to human ~4 days plus metal AWS time / CC ~4 h plus AWS time. No TODO entry.
History: none

TODO dispositions: R15 added to TODOS.md (D16); R16 built in Phase 4 instead (D17).

### R17: The ship loop silently overwrites a foreign head (late finding from the failure-mode pass)
Finding: F1, P2, confidence 8/10, `internal/service/secret_audit_witness.go:206-221` (when the local receipt equals the current head and the witness reports a different or missing head, the loop re-submits: "re-submit the same idempotent head instead of suppressing witness repair forever") and `:257` (the gauge returns to 1 after the re-ship). Reviewer Claude.
Plan baseline: D8 documents cross-node writes as "a verifier FAIL plus a refused restart"; D3 leaves duplicate ids set by hand to the operator. Neither has a runtime signal.
Runtime evidence: under Object Lock nothing can delete a witnessed version, and S3 reads after writes are strongly consistent. So a witness that holds a head other than the one this node last shipped, or holds nothing after a successful ship, cannot happen by accident. It means a foreign write (D8's shared role, or a hand-set duplicate `SB_NODE_ID`) or tampering. Today the loop re-ships every interval, `aerolvm_secret_audit_witness_healthy` stays 1, and the failures counter does not move, so the first symptom is a refused restart or a verifier FAIL. Failure-mode rule: no test, no error handling, silent, so this is a critical gap unless addressed.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R17 foreign or missing head at run time | re-shipped silently; healthy stays 1 | counted in `aerolvm_secret_audit_witness_foreign_head_total`, logged as a warning naming both heads, then re-shipped as today | re-shipped silently |
| R17 alerting | none | a rule in `setup/prometheus/` fires on any increase | none |
| R17 tests | none | table rows: foreign head, missing head, matching head | none |
| R17 critical-gap count | 1 | 0 | 1 |
| R1–R16 | approved (D1–D17) | unchanged | unchanged |

Question D18:
D18 — Make a foreign witness head visible at run time
Project/branch/task: reviewing plans/open-audit-witness.md; failure modes (late finding).
ELI10: Every 30 seconds each node checks that the witness still holds the fingerprint it last sent. If the witness holds something else, today's code quietly sends its own fingerprint again and reports "healthy". With S3 Object Lock nothing can delete a fingerprint and reads are always current, so "something else is there" only happens when another node wrote into this node's folder or someone tampered. Right now nobody finds out until the node restarts and refuses to boot.
Stakes if we pick wrong: a compromised cluster node, or two servers given the same node id, overwrite each other's evidence for weeks while every dashboard says healthy.
Recommendation: A because a counter, a log line and an alert rule turn a weeks-long silent fight into a page within one interval, without changing what the loop does.
Completeness: A=9/10, B=5/10
Pros / cons:
A) Count, log and alert (recommended)
  ✅ The first foreign write raises a metric and a warning naming both fingerprints, within one 30-second interval
  ✅ Behavior is otherwise unchanged: the loop still re-ships, so no new failure path
  ❌ The test-only HTTP witness can lose state on a receiver restart and trip the counter in integration runs
B) Leave it silent
  ✅ No change to existing service code
  ✅ The verifier and the boot check still catch it eventually
  ❌ A foreign write or duplicate node id stays invisible for as long as nodes don't restart
Net: one metric turns a silent evidence fight into an alert; the loop itself doesn't change.
Header: Foreign head
Options:
A) Count, log and alert
In shipSecretAuditHeadNow's repair branch (secret_audit_witness.go:206-221), when the witness head differs from this node's last shipped head or is missing after a successful ship, increment aerolvm_secret_audit_witness_foreign_head_total and log a warning naming both heads, then re-ship as today. Add an alert rule in setup/prometheus/ and table-test rows for foreign, missing and matching heads. Applies to every witness backend. Effort: human ~2 h / CC ~15 min. Risk: low. Maintenance: one metric and one rule.
B) Leave it silent
No change; the first signal stays a refused restart or a verifier FAIL. Effort: none. Risk: silent evidence fights. Maintenance: none.

State: approved
Actual answer: A) Count, log and alert (D18, user answer 2026-10-11)
Accepted scope: in `shipSecretAuditHeadNow`'s repair branch (`internal/service/secret_audit_witness.go:206-221`), when the witness head differs from this node's last shipped head or is missing after a successful ship, increment `aerolvm_secret_audit_witness_foreign_head_total` and log a warning naming both heads, then re-ship as today. Add an alert rule in `setup/prometheus/` and table-test rows for foreign, missing and matching heads. Applies to every witness backend. The plan's Failure behavior, Code changes and Tests sections are updated.
History: 2026-10-16, amended by D23: the repair branch runs only when the head is unchanged, so a busy node never read the witness. The loop now reads before every ship, and read errors are not counted.

Approval readiness: PASS. Checked D1 (scope record), R1/D2 (with the C2 correction as necessary implementation of D2), R2/D3, R3/D4, R4/D5, R5/D6, R6/D7, R7/D8, R8/D9, R9/D10, R10/D11, R11/D12, R12/D13, R13/D14 (item 4 revised by D17), R14/D15, R15/D16, R16/D17, R17/D18. Every accepted remedy cites its own user answer of 2026-10-11.

Note on line numbers: "plan line N" in the ledger refers to the plan as reviewed (git `25d76cc0`). The plan body above has since been edited to fold in these decisions.

## NOT in scope

- **Testing and documenting S3-compatible stores (MinIO and others).** Founder F2: the endpoint setting is supported, but v1 tests and documents AWS only.
- **Per-node IAM write scoping.** Needs a v2 key layout with the writer's AWS identity; deferred by D8 and tracked in `TODOS.md` (D16).
- **A signing key the daemon cannot read (HSM).** A plan non-goal; a separate follow-up in `plans/secrets-hardening.md`.
- **GCS and Azure backends.** A plan non-goal; with no registry (D1), a second backend adds a switch case.
- **An operator reset record so a rebuilt node keeps its id.** Rejected in D4 in favour of a new `SB_NODE_ID`, which adds no trust surface.
- **Live compliance-mode integration runs.** Compliance buckets cannot be torn down; compliance boot checks are proven offline on the D12 fake (D13).
- **UC-145b retention-prune live coverage.** Unchanged by this plan: enterprise still refuses zero retention (`TODOS.md`, "UC-145b").
- **S3 conditional writes (`If-Match`) to close the gap between a node's read and its write.** No AWS documentation we found says they work on Object Lock buckets; the verifier covers that gap (D23).

## What already exists

- **Witness ship loop, boot validation, empty-witness bootstrap, erasure rule, node-id candidates and receipts:** `internal/service/secret_audit_witness.go`. Reused unchanged except the D4 message and the D18 counter.
- **`controlplane.Witness`, the noop witness and `HasExternalWitness`:** `pkg/controlplane/controlplane.go:147-283`. Reused; the S3 witness passes the non-noop check.
- **The "provider wins, otherwise a setting selects a backend" precedent:** `pkg/daemon/daemon.go:316-320` (audit exporter). Copied for the witness.
- **The S3 client builder:** `pkg/auditexport/s3.go:48-67`. Reused by exporting it (D1); `pkg/auditexport` depends only on the standard library and the AWS SDK.
- **A real-SDK-against-`httptest` test:** `pkg/auditexport/auditexport_test.go:553-603`. Grown into the full S3 fake (D12).
- **The streaming, O(1)-memory chain verifier:** `internal/service/secret_audit.go:1813-1884`. Moved into `pkg/auditlog` and shared by the daemon and `aerolvm audit verify` (D6). Shared-code rubric evidence is in R5: two callers, about 250 lines moved instead of copied, and a blast radius that is the point (both must agree).
- **`${aws:userid}` write scoping:** `Terraform/iam.tf:97-112`. Referenced by the v2 TODO.
- **Daemon boot test harness (`setBaseRunEnv`, `runWithAutoCancel`):** `pkg/daemon/*_test.go`. Reused for the D14 zero-request tests.

## Diagrams

Daemon boot with the witness (`pkg/daemon.Run`):

```
cp := provider (Noop in the open-source build)
 |
 +-- cp.HasExternalWitness()? --yes--> keep the provider witness (0 S3 requests)          [D14 test]
 |        no
 +-- SB_AUDIT_WITNESS_BACKEND == ""? --yes--> noop witness stays (0 S3 requests)          [D14 test]
 |        no  (config already required SB_NODE_ID != "" and != "standalone")             [D3]
 v
auditwitness.Open  (30 s deadline; on expiry: names the check and the bucket)             [D9]
 +-- GetBucketVersioning == Enabled ..................................... else refuse
 +-- GetObjectLockConfiguration: enabled, default rule >= retention days ... else refuse
 +-- GET <prefix>probe/<random> == NoSuchKey ............ else refuse (names s3:ListBucket)  [D19]
 +-- PUT canary (SHA256 checksum headers)                                                  [D12]
 +-- DELETE canary VersionId + BypassGovernanceRetention=true                              [D7]
 +-- DELETE canary key, no version (a delete marker): AccessDenied -> ok | else refuse (names s3:DeleteObject)
 |      AccessDenied -> ok | success -> refuse (names the permission) | other error -> refuse
 v
cp.Witness = s3 witness
 v
gate: SB_SECRET_AUDIT_EXTERNAL_WITNESS => HasExternalWitness   (daemon.go:294, unchanged)
 v
svc.SetWitness -> ValidateSecretAuditWitness (existing) -> ship loop every interval: read, then write if needed
                                                         +-> head this node did not ship (idle or busy tick): count + warn + alert, then ship [D18, D23]
                                                         +-> read error: not counted; ship if the head changed                               [D23]
                                                         \-> unchanged head, first tick of a new UTC day: re-ship to today's key            [D20]
```

Latest-head read (`LastWitnessedHead`, D2 + C2):

```
id == "standalone" --> ok=false, no request                                                [D24]
GET node=<id>/day=<today>/head.json
 +-- 200 --> parse; node_id mismatch or malformed --> error
 +-- 403 AccessDenied --> error (Open's probe already refused a role without s3:ListBucket)  [D19]
 +-- NoSuchKey (404, which needs s3:ListBucket; rare after D20: only on a boot after downtime across midnight)
       v
     ListObjectVersions(prefix node=<id>/, Delimiter "/")   <- sees delete-marked days
       +-- no day prefixes --> ok=false ("never recorded")
       +-- newest day D
             v
           GET node=<id>/day=D/head.json
             +-- 200 --> head, ok=true
             +-- NoSuchKey --> ListObjectVersions(key)
                                +-- latest entry is a delete marker --> ERROR (hiding attempt)
                                +-- no versions --> ok=false
```

Offline verifier (`aerolvm audit verify`, D5 + D6 + D15, as amended by D20–D22):

```
aerolvm audit verify --since T (required) --export s3://bucket/prefix | --export-dir D  [--local F] [--max-lag 15m]
for each node id under <prefix>:
  heads := ListObjectVersions(node=<id>/): S3 version order within a key,
           LastModified across keys, ties by day key                                    (H1 .. Hn)   [D22]
  for each UTC day of the export layout, oldest first:                                               [D21]
    index the day's batches: first record's prev_hash -> batch, last record's event_hash
    walk the links from the tip carried over from the previous day; where batches overlap,
      continue from the batch that holds the tip; count batches the walk never reaches
    pkg/auditlog recomputes the chain in one pass; mark Hi when its hash is reached
  then the --local tail, if given
  Hi newer than T, never reached, older than the end of the evidence --> FAIL "evidence missing"   [D22]
  consecutive reached pair (Hi, Hi+1) not linked -------------------> FAIL (names the pair)        [D5]
  Hi older than T --------------------------------------------------> listed, not checked
  Hi newer than the end of the evidence, no --local ----------------> pending; pending > --max-lag --> INCOMPLETE
  report: the window T..now, unreached batches; "silent" if no version for > 1 day + N intervals    [D20]
memory: the witness version list + one day's batch index (~150 B a batch) + one batch
exit: 0 PASS, 1 FAIL, 3 INCOMPLETE, 2 usage
```

## Failure modes

| New path | Realistic production failure | Test | Handling | What the user sees |
|---|---|---|---|---|
| `Open` boot checks | Witness S3 unreachable (missing VPC endpoint) | D9 never-answers row | 30 s deadline | Boot error naming the check and bucket |
| `Open` canary | Node role holds governance bypass | D7 row | Refuse boot | Boot error naming `s3:BypassGovernanceRetention` |
| `WitnessHeads` | SDK drops checksum headers | D12 wire test | Prevented | Nothing (caught in CI) |
| `WitnessHeads` | S3 throttles or 503s | Fake error row | Ship fails, retried next tick | `healthy=0`, failures counter rises |
| `LastWitnessedHead` | Delete marker on the newest day's key | C2 row | Error, boot fails | Boot error |
| `LastWitnessedHead` | Node clock jumps across midnight | None | Existing mismatch check | Loud boot refusal (not silent) |
| Ship loop | Foreign head or duplicate `SB_NODE_ID` | D18, D23 rows (idle and busy ticks) | Read before every ship; counter, warning, alert, then ship | Alert on the next tick, idle or busy |
| Ship loop | Foreign write between the victim's read and its write | Verifier rows | Buried under the victim's version | Verifier FAIL only |
| Ship loop | Node idle across UTC midnight | D20 rows | Daily re-ship to today's key | Nothing; one PUT a day |
| `Open` probe | Node role lacks `s3:ListBucket` | D19 403 row | Refuse boot | Boot error naming `s3:ListBucket` |
| Config | `SB_NODE_ID` missing with a witness | D3 row | Config error | Clear error |
| Rebuild | Empty disk under the same node id | D4 message test | Boot refusal | Error naming the new-id recovery |
| Verifier | Export batch overwritten or missing | D5 rows | FAIL | FAIL naming the unlinked pair |
| Verifier | Very large history | D15 allocation test | Streaming pass | Bounded memory |
| Verifier | Retention prune in the middle of a day (offsets restart) | D21 row | Chain-linkage walk per day | PASS |
| Verifier | The node removes the oldest export batches inside the window | D22 row | Window comes from `--since` | FAIL naming the unreached head |
| Verifier | Export stalled and no local log given | D22 row | Pending past `--max-lag` | INCOMPLETE, never PASS |
| Itest teardown | Locked objects block `terraform destroy` | First Phase 4 run | Empty with the bypass flag first | Harness error if it fails |

Critical gaps: 0. One was found (F1, a silent foreign-head overwrite) and resolved by D18; the follow-up review found that D18 missed busy nodes and fixed that with D23. The clock-jump case has no test but fails loudly, so it is not critical. The read-to-write race in D23 is caught only by the verifier, and the docs say so.

## Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| S3 client export, `pkg/auditwitness`, `httptest` S3 fake | `pkg/auditexport`, `pkg/auditwitness` | — |
| Settings and daemon wiring | `internal/config`, `pkg/daemon` | S3 backend step |
| Service changes (D4 message, D18/D23 counter and read before every ship, D20 daily re-ship) | `internal/service` | — |
| Chain verifier move | `internal/service`, `pkg/auditlog` | Service changes (same package) |
| `aerolvm audit verify` | `cmd/aerolvm`, `pkg/auditlog` | Verifier move; S3 client export |
| Terraform, Ansible, installer, runbooks, alert rule | `Terraform/`, `Ansible/`, `setup/`, `install.sh` | — |
| Integration scenarios and itest-witness removal | `integration-tests/`, `cmd/sandboxd` | Daemon wiring; Terraform step |
| Docs | `docs/` | Daemon wiring; verifier; merges after the release |
| Blog post | `docs/` | Docs; Phase 4 numbers; merges after the release |

Parallel lanes: Lane A: S3 backend → daemon wiring. Lane B: service changes → verifier move → `aerolvm audit verify` (shared `internal/service`, so sequential). Lane C: Terraform, Ansible and runbooks (independent).
Execution order: launch A, B and C together; B's last step waits for A's client export. Then integration (needs A and C), then docs. Conflict flags: Lane B and Lane A's daemon wiring both touch witness call sites only through `pkg/controlplane` types, which nobody changes; `pkg/auditlog` is touched only by Lane B. Per the stacked-PR rule, each phase is its own PR, and nothing merges until the whole stack is green. Phases 1–5 merge first and are released; the docs and blog PRs merge after the release.

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific finding above. Run with Claude Code or Codex; checkbox as you ship. Effort assumes the default human ÷ CC ratios (features ~30x, tests ~50x, architecture ~5x).

- [ ] **T1 (P1, human: ~1 day / CC: ~30 min)** — pkg/auditwitness — Day-partitioned keys with a `ListObjectVersions` fallback that errors on a delete marker
  - Surfaced by: Architecture A1 (D2) and Code Quality C2
  - Files: `pkg/auditwitness/s3.go`, `pkg/auditwitness/s3_test.go`
  - Verify: `go test ./pkg/auditwitness/...` (fallback and delete-marker rows)
- [ ] **T2 (P1, human: ~2 h / CC: ~10 min)** — internal/config — Require `SB_NODE_ID` (not `standalone`) when a witness backend is set
  - Surfaced by: Architecture A2 (D3)
  - Files: `internal/config/config.go`, its test file, `install.sh`, `Ansible/`
  - Verify: `go test ./internal/config/...`
- [ ] **T3 (P1, human: ~0.5 day / CC: ~15 min)** — internal/service + runbook — Erasure error names the rebuild-under-a-new-`SB_NODE_ID` recovery
  - Surfaced by: Architecture A3 (D4)
  - Files: `internal/service/secret_audit_witness.go`, `setup/runbooks/secrets-and-audit.md`
  - Verify: `go test -run Erasure ./internal/service/...`
- [ ] **T4 (P1, human: ~1 day / CC: ~30 min)** — pkg/auditlog — Move the streaming chain verifier out of `internal/service`
  - Surfaced by: Architecture A5 (D6)
  - Files: `internal/service/secret_audit.go`, `pkg/auditlog/`
  - Verify: `go test ./internal/service/... ./pkg/auditlog/...` with unchanged assertions
- [ ] **T5 (P1, human: ~3.5 days / CC: ~3.5 h)** — cmd/aerolvm — `aerolvm audit verify`: pairwise linkage over local and export, FAIL on a missing link, coverage window, silent ids, bounded-memory streaming (export order superseded by T20, window rules by T21)
  - Surfaced by: Architecture A4 (D5) and Performance P1 (D15)
  - Files: `cmd/aerolvm/audit.go` (new), `pkg/auditlog/`
  - Verify: `go test ./cmd/aerolvm/... ./pkg/auditlog/...` (forged head, rollback, forged checkpoint, missing link, allocation rows); `TestDependencyGuard`
- [ ] **T6 (P1, human: ~2 h / CC: ~15 min)** — pkg/daemon — Regression contract: zero-request tests and provider precedence
  - Surfaced by: Test review T3 (D14)
  - Files: `pkg/daemon/daemon.go`, a new `pkg/daemon/*_test.go`
  - Verify: `go test ./pkg/daemon/...`; `misc_coverage_test.go:10` unchanged and green
- [ ] **T7 (P2, human: ~2 days / CC: ~1 h)** — pkg/auditwitness — `httptest` S3 fake with S3 XML, checksum enforcement, bypass header and delete markers
  - Surfaced by: Test review T1 (D12)
  - Files: `pkg/auditwitness/s3fake_test.go` (new)
  - Verify: every `pkg/auditwitness` test runs through the real client; coverage ≥ 85%
- [ ] **T8 (P2, human: ~1 h / CC: ~5 min)** — pkg/auditwitness — Canary deletes with `BypassGovernanceRetention=true`; any non-AccessDenied result refuses boot
  - Surfaced by: Architecture A6 (D7)
  - Files: `pkg/auditwitness/checks.go`
  - Verify: fake row for a bypass-holding role on a governance bucket
- [ ] **T9 (P2, human: ~2 h / CC: ~15 min)** — internal/service + setup — Foreign-head counter, warning and alert rule
  - Surfaced by: Failure modes F1 (D18)
  - Files: `internal/service/secret_audit_witness.go`, `setup/prometheus/`
  - Verify: table rows for foreign, missing and matching heads
- [ ] **T10 (P2, human: ~0.5 day / CC: ~30 min)** — Terraform + harness — Lock mode and days variables; governance 1-day itest buckets emptied with the bypass flag
  - Surfaced by: Test review T2 (D13)
  - Files: `Terraform/` (new witness file, `variables.tf`, `iam.tf`), `integration-tests/run.sh`
  - Verify: `terraform plan` with and without the witness; the first Phase 4 run shows a clean `--destroy-only`
- [ ] **T11 (P2, human: ~4 days + metal AWS time / CC: ~4 h + AWS time)** — integration-tests — New single-node enterprise scenario plus all six enterprise scenarios on S3, then delete the itest witness build
  - Surfaced by: TODO review R16 (D17) and regression contract item 4
  - Files: `integration-tests/scenarios/`, `integration-tests/lib/build.sh`, `integration-tests/run.sh`, `cmd/sandboxd/provider_itest.go`
  - Verify: `make integration-*` runs green with tamper cases failing closed; `provider_itest.go` removed
- [ ] **T12 (P2, human: ~1 h / CC: ~5 min)** — plan + runbook — Document the cross-node write limit and CloudTrail attribution
  - Surfaced by: Architecture A7 (D8)
  - Files: `setup/runbooks/secrets-and-audit.md`, `docs/`
  - Verify: docs checks pass; the `docs/` part ships in the Phase 6 PR, so it waits for the release too
- [ ] **T13 (P2, human: ~30 min / CC: ~5 min)** — pkg/auditexport + pkg/auditwitness — Export `NewS3Client`; `Open` switches on the backend name, no registry
  - Surfaced by: Scope Challenge structure (D1)
  - Files: `pkg/auditexport/s3.go`, `pkg/auditwitness/open.go`
  - Verify: `go test ./pkg/auditexport/...`
- [ ] **T14 (P3, human: ~1 h / CC: ~5 min)** — pkg/auditwitness — 30 s deadline on `Open`
  - Surfaced by: Architecture A8 (D9)
  - Files: `pkg/auditwitness/open.go`
  - Verify: never-answers fake row
- [ ] **T15 (P3, human: ~30 min / CC: ~5 min)** — pkg/auditwitness — `PutObject` only; `ReceiptID = VersionId`, zero `RecordedAt`
  - Surfaced by: Architecture A9 (D10)
  - Files: `pkg/auditwitness/s3.go`
  - Verify: one-request-per-ship row
- [ ] **T16 (P3, human: ~15 min / CC: ~2 min)** — pkg/auditwitness — Reject `len(heads) != 1`
  - Surfaced by: Code Quality C1 (D11)
  - Files: `pkg/auditwitness/s3.go`
  - Verify: table row
- [ ] **T17 (P3, human: ~1 day / CC: ~1 h)** — docs — Blog post "Catching a rewritten audit log" (Phase 7)
  - Surfaced by: user request after the review (2026-10-12)
  - Files: `docs/src/content/docs/engineering-audit-witness.mdx` (new), `docs/src/content.config.ts`, `docs/src/content/docs/blog.mdx`, `docs/src/content/docs/engineering-security-overview.mdx`
  - Verify: `make docs-build`; the `sandbox.audit()` tabs match `sdk/*`; every number traced to the code or a Phase 4 report; merged only after the release

Added by the follow-up review (2026-10-16). The Phases table names the phase for every task.

- [ ] **T18 (P1, human: ~2 h / CC: ~15 min)** — pkg/auditwitness + Terraform — `s3:ListBucket` for the node role; `Open` probes a random missing key; the fake answers 403 without the permission
  - Surfaced by: follow-up R18 (D19)
  - Files: `pkg/auditwitness/checks.go`, `pkg/auditwitness/s3fake_test.go`, the Terraform witness file
  - Verify: 403 and 404 fake rows; the Phase 4 first boot on an empty bucket
- [ ] **T19 (P1, human: ~2 h / CC: ~15 min)** — internal/service — Re-ship an unchanged head on the first tick of each UTC day
  - Surfaced by: follow-up R19 (D20)
  - Files: `internal/service/secret_audit_witness.go` and its test
  - Verify: day-rollover rows (first tick re-ships, later ticks don't, not counted as foreign)
- [ ] **T20 (P1, human: ~1 day / CC: ~1 h)** — pkg/auditlog + cmd/aerolvm — Walk export batches by chain linkage, one UTC day at a time
  - Surfaced by: follow-up R20 (D21)
  - Files: `pkg/auditlog/`, `cmd/aerolvm/audit.go`
  - Verify: mid-day prune, re-send across midnight, overlapping re-export, `_` in node ids, and allocation rows
- [ ] **T21 (P1, human: ~0.5 day / CC: ~30 min)** — cmd/aerolvm + Terraform — `--since`, pending and INCOMPLETE, `--export` / `--export-dir` / `--local` / `--max-lag`, witness version order, auditor read-only policy
  - Surfaced by: follow-up R21 (D22)
  - Files: `cmd/aerolvm/audit.go`, `pkg/auditlog/`, the Terraform witness file
  - Verify: removed-early-exports FAIL row, stalled-export INCOMPLETE row, same-second version row; `terraform plan` with the policy
- [ ] **T22 (P2, human: ~2 h / CC: ~15 min)** — internal/service — Read the witness before every ship; count a foreign head on busy ticks; don't count read errors
  - Surfaced by: follow-up R22 (D23); ships with T9
  - Files: `internal/service/secret_audit_witness.go` and its test
  - Verify: busy-tick foreign row, read-error row, matching-head row
- [ ] **T23 (P3, human: ~30 min / CC: ~5 min)** — pkg/auditwitness — Answer the `standalone` id locally
  - Surfaced by: follow-up R23 (D24)
  - Files: `pkg/auditwitness/s3.go`
  - Verify: zero-request row
- [ ] **T24 (P2, human: ~0.5 day / CC: ~15 min + AWS time)** — integration-tests — Release smoke on the published artifact
  - Surfaced by: follow-up review (acceptance item 1 was untested)
  - Files: none beyond the Phase 4 scenario
  - Verify: `integration-tests/run.sh <single-node enterprise scenario> --version <tag>` green; gates the Phase 6 and 7 merges

## Unresolved decisions

None. Every choice raised in this review (D1–D18) has an answer.

## Completion summary

- Step 0: Scope Challenge — scope accepted as-is (smaller arrangement, D1)
- Architecture Review: 9 issues found (A1–A9), all resolved (D2–D10)
- Code Quality Review: 2 issues found (C1 via D11; C2 as necessary implementation under D2)
- Test Review: diagram produced, 38 path gaps mapped, 3 test-design findings (T1–T3, D12–D14)
- Performance Review: 1 issue found (P1, D15)
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 2 items proposed to user (1 added, D16; 1 built in Phase 4 instead, D17)
- Failure modes: 0 critical gaps flagged (1 found and resolved, F1/D18)
- Unresolved decisions: 0 in this review
- Outside voice: codex, unavailable (`model_unusable` after a missing gstack script; native fallback impossible without `TaskOutput`)
- Parallelization: 3 lanes, 2 parallel (A, C) / 1 sequential (B), then integration and docs
- Lake Score: 1/15 answers picked a 10/10 option (most options topped out at 9/10); the highest-completeness option was chosen in 13 of 15 scored answers (exceptions: D4, D8)

## Suppressed findings (appendix)

- `[P3] (confidence: 4/10) internal/service/secret_audit_witness.go:553-570` — `lastWitnessedHeadAny` drops one candidate's error when another candidate returns a head, so a delete-marker error on the canonical key could be masked by a head under the legacy id. Suppressed: the S3 backend never writes legacy keys, and anyone able to write one can already write a forged canonical version. (Since the follow-up review's D24, the S3 backend no longer reads the legacy `standalone` id at all.)
- `[P3] (confidence: 4/10) pkg/auditexport/s3.go:79-87` — node ids are not sanitized in keys, so an id containing `/` produces nested keys. Suppressed: ids are operator-chosen and the effect is cosmetic. (Moot: `internal/config/config.go:2048` already rejects `/` in `SB_NODE_ID` through `models.ValidClusterNodeID`.)

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Outside Review | codex (`codex-plan-review`, from this eng review) | Independent 2nd opinion | 1 | unavailable | 0 (no reviewer ran) |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | ISSUES OPEN (this run; review log written right after this save) | 15 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex, plan-review phase, unavailable (`model_unusable`: `Module not found "/../scripts/resolve-codex-generation-model.ts"`); native fallback not possible without `TaskOutput`; no outside findings. Missing coverage, not a clean result.
- **VERDICT:** no review is CLEAR. Eng Review found 15 issues and mapped every one to an approved plan change (18 decisions, 0 unresolved, 0 critical gaps). Ready to implement against the updated plan; eng review required to reach CLEAR.

NO UNRESOLVED DECISIONS

---

# Follow-up review (2026-10-16)

The plan was checked again against `origin/main` at `2598aa44`; line numbers in this section refer to that commit. The engineering review's code citations still hold. Only `internal/config/config.go` and `pkg/daemon/daemon.go` changed, and the external-witness gate moved one line, to `pkg/daemon/daemon.go:293`.

Five approved decisions did not survive a closer read of the code and of AWS behavior. D19–D23 correct them, and D24 is a small hardening. The user approved all six on 2026-10-16 ("fix the plan"). Their changes are folded into the plan body, the diagrams, the failure-mode table and the task list above.

### R18 / D19: The node role needs `s3:ListBucket`
Finding: P1, confidence 9/10. The IAM table allowed `s3:GetObject`, `s3:GetObjectVersion` and `s3:ListBucketVersions`, but not `s3:ListBucket`. AWS documents that a GetObject on a missing key returns 403 AccessDenied, not 404 NoSuchKey, when the caller lacks `s3:ListBucket` (GetObject API reference, "Permissions"). The latest-head read falls back to `ListObjectVersions` only on NoSuchKey. So a first boot on an empty bucket would fail, and so would any boot after an idle midnight. The `httptest` fake always answered NoSuchKey, so no unit test would have seen it; only a Phase 4 run would.
Decision: grant `s3:ListBucket` on the bucket ARN, with no `s3:prefix` condition (amended in Phase 3: a GetObject request carries no `s3:prefix` key, so a conditioned grant would not count when S3 picks 404 or 403; the bucket holds only witness objects). `Open` probes a random missing key under `<prefix>probe/` and refuses boot, naming the permission, on AccessDenied. The fake answers 403 for a missing key when its role lacks the permission. Boot grows by one call. Task T18.

### R19 / D20: Idle nodes never write today's key
Finding: P1, confidence 9/10. `shipSecretAuditHeadNow` writes only when the head changes, and reads only when it doesn't (`internal/service/secret_audit_witness.go:203-218`). Under the day layout (D2), an idle node has no key for today after UTC midnight. Every tick then paid a missed GET, a LIST (billed at the PUT rate) and a second GET, so the cost section's "one GET" was wrong. The D5 "silent node" rule (newest head older than N intervals) would also flag every healthy idle node.
Decision: the service re-ships an unchanged head on its first tick of each UTC day, keyed on the receipt's `ShippedAt` date, for every backend. It is not counted as foreign. The LIST fallback then runs only on a boot after downtime across midnight. A node is silent when it has no version for more than a day plus N intervals. Task T19.

### R20 / D21: Export batch keys do not sort in chain order
Finding: P1, confidence 9/10. D15 ordered export batches by day, then by the offset parsed from the batch key. That offset is a byte position in the current audit-file generation, and a retention prune starts a new generation and re-pins the cursor (`internal/service/secret_audit_export.go:203-219`). The generation is not in the batch id (`auditExportBatchID`, `:65-74`), and it is a hash, not a counter (`auditGenerationOfLine`, `:391-396`). On a prune day, the new generation's small offsets sort ahead of the old generation's large ones, so the one-pass walk sees a broken chain and fails an honest history. Node ids may also contain `_` (`models.ValidClusterNodeID`), and the key turns `:` into `_` (`pkg/auditexport/s3.go:82`), so the offset cannot be split out from the left. Events carry no sequence number (`pkg/auditlog/event.go`), so nothing else in a record gives the order.
Decision: walk export batches by chain linkage, one UTC day of the export layout at a time. Index the day's batches by their first record's `prev_hash` and last record's `event_hash` (about 150 bytes a batch; at most 86,400 batches a day at the 1 s `SB_AUDIT_EXPORT_FLUSH_INTERVAL` default, so about 13 MB). Walk from the tip carried over from the previous day; where batches overlap (a re-send across midnight, a re-export after a cursor reset), continue from the batch that holds the tip. Count batches the walk never reaches in the report, and carry the tip into the next day. Key names and offsets are never used for order, which also lets `--export-dir` take batches in any file layout. Memory: the witness version list, plus one day's batch index, plus one batch. This supersedes D15's order rule; D15's memory goal stands. Task T20.

### R21 / D22: The verifier's window must come from the auditor
Finding: P1, confidence 8/10. D5 made an unlinked pair a FAIL and said the report names a window "bounded by export retention". It never said what happens to heads older than the earliest record the verifier can read, and both readings fail. Failing those heads fails every honest cluster whose history outlives its records. Skipping them lets an attacker who controls a node rewrite the local log and overwrite the oldest export batches (the node role holds `s3:PutObject` on the export bucket, `Terraform/audit_export.tf:71`). That moves the walk's starting point past the last honest head, and the forged tail passes. D5 also left two inputs open: heads newer than the last exported record when no local log is given, and `webhook` or `bus` exports (`pkg/daemon/daemon.go:325`), which the verifier cannot read back.
Decision: `aerolvm audit verify --since <time>` is required, because the right window depends on retention that the verifier cannot learn from the node. The report prints the window.
- Every witnessed head newer than `--since` must be reached, or the result is FAIL ("evidence missing"). Older heads are listed, not checked.
- Inputs: `--export s3://bucket/prefix`, or `--export-dir <path>` (NDJSON batches saved from a webhook or bus receiver), and an optional `--local <jsonl>` per node.
- Without `--local`, a head newer than the end of the evidence is pending. A head pending longer than `--max-lag` (default 15 minutes; the export flushes every second) makes the result INCOMPLETE. Exit codes: 0 PASS, 1 FAIL (or could not verify), 3 INCOMPLETE; 2 stays the CLI's usage error, which every other verb uses.
- Witness versions are ordered by S3's version order within a key, and by `LastModified` across keys with ties broken by the day key, because list results carry `LastModified` only to the second.
- Terraform outputs an optional auditor read-only policy. The docs tell operators to keep exports at least as long as the window they verify.

This amends D5. Task T21.

### R22 / D23: A busy node never sees a foreign head
Finding: P2, confidence 9/10. D18 counts a foreign head in the ship loop's repair branch, which runs only when the local head is unchanged (`if lastLocal == head`, `internal/service/secret_audit_witness.go:203`). A node whose head changes every interval ships without reading, so it never counts a foreign write. Its next ship then puts its own head back on top, so its next restart boots too. The failure table, D8 and D18 promised an alert within one interval and a refused restart for every node; for a busy victim, only the verifier saw the write.
Decision: the loop reads `LastWitnessedHead` before every ship, idle or busy. A head that is neither this node's current head nor its last shipped head is counted and logged before the ship, and so is a missing head after a successful ship. A read error is not counted, so an S3 blip doesn't page anyone. For the S3 backend this adds no request, since the cost section already assumed a read every tick; for a provider witness it adds one read per changed-head ship. A foreign write that lands between the read and the write is still buried, and only the verifier sees it; the docs say so. A restart fails only if the foreign head is still the newest. S3 conditional writes (`If-Match`) could close that gap, but no AWS documentation we found says they work on Object Lock buckets, so they are not used. This amends D18 and corrects D8's symptom text. Task T22.

### R23 / D24: The S3 backend ignores the legacy `standalone` id
Finding: P3, confidence 8/10. `witnessNodeIDCandidates` (`internal/service/secret_audit_witness.go:536-549`) adds the cluster handle's id as a legacy fallback, and on a single server that is the Noop's `standalone`. With `SB_NODE_ID` now required (D3), a first boot also reads `node=standalone/`. That costs two wasted calls, against a key that D3 guarantees holds no real head but that any node's role can write. A head written there would fail a fresh server's boot.
Decision: the S3 backend answers `LastWitnessedHead("standalone")` with `ok=false` and no request, and rejects a `standalone` write. The service code is unchanged. Task T23.

### Editorial fixes (no decision needed)
- The founder decisions are renamed F1–F5. They shared numbers with the review's D1–D5, and the body used both.
- The test plan moved into the repo as [`plans/open-audit-witness-test-plan.md`](./open-audit-witness-test-plan.md). It had lived only in a local gstack directory that PR reviewers can't open.
- The Phases table now maps every task to a phase. T3, T9 and the new service tasks had none, so Phase 2 now carries the service changes.
- Phase 6 adds `enterprise/audit-evidence.mdx` and `cli.mdx`, and puts the new Enterprise mode page in the Enterprise tab.
- A release smoke (T24) runs the single-node enterprise scenario on the published artifact before Phases 6 and 7 merge. Phase 4 tests working-tree builds, and acceptance item 1 and the docs promise the released binary.
- The suppressed node-id finding is moot: config already rejects `/` in `SB_NODE_ID` (`internal/config/config.go:2048`).

Unresolved decisions: none.
