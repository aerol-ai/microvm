# Open audit witness: enterprise mode in the open-source build

Status: decisions made 2026-10-11; engineering review next. Founder decision: make enterprise mode usable in the free download.

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
- **That a newer forged head is false.** A compromised node can still write a new head that matches a rewritten chain. The daemon's boot check looks only at the **latest** head, so it passes. The **offline verifier** (Phase 5) catches this, because it checks every head ever written and those cannot be removed. The verifier is what makes this claim complete, so it is part of v1.

## Design

### Where it plugs in

Resolve the witness the way the daemon already resolves the audit exporter (`pkg/daemon/daemon.go:315-320`): **a provider-supplied witness wins; otherwise `SB_AUDIT_WITNESS_BACKEND` selects one.**

```
cp := provider (Noop in the open-source build)
if !cp.HasExternalWitness() && cfg.AuditWitnessBackend != "" {
    w, err := auditwitness.Open(ctx, cfg.AuditWitnessConfig())   // fails boot on bad config
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

Credentials come from the standard AWS chain (instance role, environment or profile), the same as the S3 exporter (`pkg/auditexport/s3.go`, `newS3Client`). Share that client builder; do not copy it.

### Storage layout

**One key per node, with bucket versioning:** `<prefix>node=<node-id>/head.json`.

- Object Lock requires versioning, so every write adds a **new version**. Older versions stay, locked.
- "The latest head" is a plain `GetObject`: one request, no listing. Ordering comes from S3, not from the node's clock.
- The full history is `ListObjectVersions` on that key, which the verifier uses.

The object body is a small JSON document, about 300 bytes, and never holds audit payloads:

```json
{"node_id":"…","head_hex":"…","event_id":"…","observed":"2026-10-11T12:00:00Z","sandboxd_version":"0.6.x"}
```

*Rejected:* one key per head, sorted by an inverted timestamp. It costs a LIST for every read and depends on the node's clock for ordering.

### Mapping to `controlplane.Witness`

| Interface call | S3 calls | Notes |
|---|---|---|
| `WitnessHeads(heads)` | `PutObject` with `ChecksumAlgorithm: SHA256`, then `HeadObject(VersionId)` | **Gotcha:** S3 rejects any upload to a bucket with default Object Lock retention unless it carries `Content-MD5` or an SDK checksum. The shared client uses `RequestChecksumCalculationWhenRequired`, so set the algorithm explicitly. The receipt is `ReceiptID = VersionId` and `RecordedAt = LastModified`, which is S3's own clock. The original design requires a witness-side time, so an attacker cannot backdate a forged chain. |
| `LastWitnessedHead(node)`, found | `GetObject` | Returns `head_hex`, `ok=true` |
| `LastWitnessedHead(node)`, `NoSuchKey` | `ListObjectVersions(key, max 2)` | No versions means "never recorded": `ok=false`, no error. If the latest entry is a **delete marker**, return an **error**. The daemon never deletes, so a delete marker means someone tried to hide the head. The daemon then fails closed through the existing path. |

`heads` holds one entry today (`shipSecretAuditHeadNow`). If more arrive, write one version per entry, in order.

### Boot checks: refuse a bucket that is not really WORM

`auditwitness.Open` checks the bucket before it returns. Any failure stops boot with a message that names the fix.

1. `GetBucketVersioning` returns `Enabled`.
2. `GetObjectLockConfiguration` shows Object Lock enabled, with a **default retention rule**.
3. Default retention is at least `SB_SECRET_AUDIT_RETENTION_DAYS`. A head must outlive the local records it vouches for.
4. **Canary** (recommended; see Decisions): put `<prefix>canary/node=<id>`, then `DeleteObject` with that `VersionId`. Expect `AccessDenied`. If the delete succeeds, the lock is not protecting this node's writes, so refuse to start. This costs two small objects per boot.

Without these checks, a witness on an ordinary bucket would look healthy while providing nothing, which is the one outcome the existing code comments forbid ("a witness that silently 'succeeded' would let a scenario claim tamper-evidence it never had", `provider_itest.go`).

### IAM for the node role

| Allow | Deny explicitly |
|---|---|
| `s3:PutObject` and `s3:GetObject` on `<prefix>*` | `s3:DeleteObject` (blocks delete markers) and `s3:DeleteObjectVersion` |
| `s3:GetObjectVersion` and `s3:ListBucketVersions` | `s3:PutObjectRetention`, `s3:PutObjectLegalHold` and `s3:BypassGovernanceRetention` |
| `s3:GetBucketVersioning` and `s3:GetBucketObjectLockConfiguration` | `s3:PutBucketObjectLockConfiguration`, `s3:PutBucketVersioning`, `s3:PutLifecycleConfiguration` and `s3:PutBucketPolicy` |

The canary's `DeleteObject` call expects this denial. Denied by IAM or by the lock, both mean the evidence is safe.

### Retention mode

| Mode | Who can delete before expiry | Use |
|---|---|---|
| **Compliance** | No one, not even the AWS account root | Production. The strongest claim. |
| **Governance** | Only principals with `s3:BypassGovernanceRetention` | Trials. The node role never has it. |

Cost control: add a lifecycle rule that expires **noncurrent** versions after the retention period. Never expire the current version.

### Cluster

- Each node writes only its own key (`node=<SB_NODE_ID>`). That matches `witnessNodeID()` and the legacy-id fallback in `witnessNodeIDCandidates()`.
- **Known limit:** the Terraform node role is shared, so node A can write a version to node B's key. It cannot erase B's history, because the lock prevents that. It can make B refuse to boot, because B's latest head no longer matches. That is a denial of service, not silent tampering. Phase 3 can limit each node to its own prefix with an IAM condition on the caller's identity, the same idea as the S3 rendezvous the cluster join already uses.
- No change to Raft, gossip or placement. Witness traffic is node to S3 only.

### Failure behavior

| Situation | Result |
|---|---|
| S3 unreachable at boot, enterprise mode | Boot fails, through the existing `ValidateSecretAuditWitness` error path. Strict on purpose; see Decisions. |
| S3 unreachable at run time | The ship fails, `aerolvm_secret_audit_witness_healthy` drops to 0 and the failures counter rises. Records keep being written locally, and the next ship catches up. |
| Bucket without lock or versioning | Boot fails with the fix in the message |
| Local log edited or deleted | Boot fails (`secret audit witness mismatch`). This behavior already exists. |
| A delete marker on a node's head key | `LastWitnessedHead` returns an error, so boot fails |

### Cost (AWS list prices, us-east-1, per node)

- Reads: one GET every 30 seconds while the head is unchanged, which is 2,880 a day, or about $0.001 a day.
- Writes: at most one PUT plus one HEAD every 30 seconds when the head changes. That is under $0.02 a day.
- Storage: about 300 bytes per version, up to about 1 million versions a year, which is about 300 MB, or under $0.01 a month.

## Code changes

| Area | Change |
|---|---|
| `pkg/auditwitness/` (new) | `Open`, an `s3` backend, boot checks, a small backend registry like `pkg/auditexport`'s, and tests with a fake S3 API (the `s3PutObjectAPI` pattern) |
| `pkg/auditexport/s3.go` | Export the client builder, or move it to a small shared package, so the witness reuses it |
| `internal/config/config.go` | The `SB_AUDIT_WITNESS_*` settings, validation, and `AuditWitnessConfig()` |
| `pkg/daemon/daemon.go` | Resolve the witness before the gate at line 294 |
| `pkg/controlplane/controlplane.go` | Update the `Witness` comment: "No-op unless a provider or `SB_AUDIT_WITNESS_BACKEND` supplies one" |
| `cmd/aerolvm/` or a `sandboxd` subcommand | The offline verifier (Phase 5) |
| `Terraform/` | An optional witness bucket: Object Lock, versioning, default retention, a noncurrent-version lifecycle rule, and the IAM statements above |
| `Ansible/`, `install.sh` | Pass the settings through. The installer only documents them and never creates buckets. |
| `setup/config-defaults.md`, `setup/runbooks/secrets-and-audit.md` | New settings, the bucket recipe, and what to do on a witness mismatch |

## Tests

- **Unit (`pkg/auditwitness`, ≥85% coverage, table-driven):**
  - put, then get the latest head;
  - `NoSuchKey` with no versions returns `ok=false`;
  - `NoSuchKey` behind a delete marker returns an error;
  - every boot-check failure: versioning off, lock off, no default rule, retention too short, and a canary delete that succeeds;
  - an upload missing the checksum header is refused by the fake, exactly as S3 refuses it;
  - the receipt uses S3's `LastModified`.
- **Daemon:**
  - the provider witness wins over the setting;
  - the setting fills a placeholder witness;
  - enterprise mode with a fake S3 witness boots;
  - with no setting, nothing changes and the fake records zero calls.
- **Integration (real AWS, `integration-tests/`):**
  - move the enterprise scenarios from the `itestwitness` HTTP witness to a real Object Lock bucket;
  - add tamper cases: edit the local JSONL (boot fails), delete it (boot fails), try a delete marker with the node role (denied);
  - run on `single-node` and `cluster-3-mixed`.
  - Keep `itestwitness` until both pass, then retire it from those scenarios.
- `make test` stays offline. AWS calls live only in `integration-tests/`.

## Phases

Ship as stacked PRs, one per phase, and merge nothing until the whole stack is green.

| # | Phase | Done when | Size (human / CC) |
|---|---|---|---|
| 0 | Decisions below | Done 2026-10-11 | |
| 1 | `pkg/auditwitness` S3 backend and boot checks | Unit tests green, ≥85% coverage | ~3 days / ~2 h |
| 2 | Settings and daemon wiring | Enterprise mode boots on the release build against the fake. With no setting there are zero calls. | ~1 day / ~1 h |
| 3 | Terraform bucket, IAM, Ansible, runbook and config defaults | `terraform plan` is clean with and without the witness | ~2 days / ~2 h |
| 4 | Integration scenarios on real Object Lock buckets | Single-node and 3-node enterprise runs green, tamper cases fail closed | ~2 days plus AWS time / ~3 h plus AWS time |
| 5 | Offline verifier | Catches a rewritten history that the boot check passes (a forged newer head) | ~2 days / ~2 h |
| 6 | Docs and positioning | The pages below are updated and the docs checks pass | ~1 day / ~1 h |

### Phase 6 docs

- **Enterprise Overview:** add a row "Off-server audit witness (S3 Object Lock)", marked *You turn it on*. Enterprise mode is no longer managed-build only.
- **Security controls, Audit:** add a "Tamper evidence off the server" row.
- **Hardening:** add enterprise mode back as a server setting, now open to everyone, with its requirements listed.
- **Secrets providers:** the checklist step "Set `SB_ENTERPRISE_MODE=true`" becomes correct. Add "configure the witness" next to it.
- **New Docs page, "Enterprise mode":** what it turns on, the witness bucket recipe, and the five-language `sandbox.audit()` example. Register it in `content.config.ts`.
- **Ideas Discussions:** post this as proposal 7, or as an announcement if it ships first.

## PR call-outs (`pr-review.md`)

- **Boot-path latency (`CreateSandbox`):** none. The witness runs on daemon boot and on a background loop.
- **Daemon boot:** adds about five S3 calls (versioning, lock configuration, canary put and delete, latest head) when configured, and none otherwise.
- **Cluster:** no FSM, placement or gossip change. With cluster mode off, the behavior is the same.
- **Idempotency:** re-shipping the same head adds a version. That is harmless, and the daemon already skips unchanged heads after a successful read-back.
- **Failure paths:** no multi-step write across S3 and the store. The local receipt is written after the S3 acknowledgment, as today.

## Decisions (founder, 2026-10-11: "go with your suggestions")

| # | Question | Decision |
|---|---|---|
| D1 | Which retention mode do the docs recommend? | **Compliance for production, governance for trials.** |
| D2 | AWS only in v1, or S3-compatible stores too? | **Support the endpoint setting, but test and document only AWS in v1.** The boot checks still protect any store, because one without Object Lock fails them. |
| D3 | Should an S3 outage block node restarts in enterprise mode? | **Yes, for now.** Same as today with any witness. Revisit if users hit it. |
| D4 | Keep the boot canary? | **Yes.** |
| D5 | Keep the name "enterprise mode"? | **Keep it.** The docs say anyone can use it. |

## Acceptance

- The released `sandboxd`, with `SB_ENTERPRISE_MODE=true` and a witness bucket, boots on one server and on a 3-node cluster.
- The same setup with an ordinary bucket refuses to start and names the fix.
- Editing or deleting the local audit log makes the node refuse to boot.
- The node role cannot delete or hide a witnessed head.
- The offline verifier catches a rewritten history that the boot check passes.
- With no witness setting, behavior is identical to today, and the test fake records zero S3 calls.
