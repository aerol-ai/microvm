# Runbook: Secrets and Audit

Use this when secret-audit or secret-fan-out alerts fire, or when investigating
credential open failures and `failover_ready` staying false.

## Honesty boundary (read first)

On the open-source build:

- The local JSONL audit log (`{Dir(DBPath)}/audit/secrets.jsonl`) is
  authoritative per node.
- **There is no dead-disk durability claim.** Losing a node's disk loses that
  node's audit history permanently. The local writer fsyncs at least once per
  second and again at shutdown, bounding ordinary host-crash loss without
  pretending that a local disk is an external evidence store.
- Cluster fan-out on `GET /v1/sandboxes/{id}/audit` is a **discovery**
  mechanism. It targets the Raft-retained owner history. If that bounded index
  is missing or truncated, the API returns `503` instead of amplifying one
  request into an all-worker fleet scan. It is **not** a durability mechanism
  and cannot recover records that no longer exist.
- Coverage in the API response names which members answered; `partial: true`
  means the page is incomplete — never treat a partial page as full history.

### Enterprise durability (Witness + export)

- **Witness heads ≠ event reconstruction.** An off-node witness
  (`pkg/controlplane.Witness`, wired via `SB_SECRET_AUDIT_EXTERNAL_WITNESS`)
  records chain heads / receipts so retroactive local-file tampering is
  detectable. It does **not** store full audit batches today and cannot rebuild
  the JSONL after disk loss. The open-source build gets a real witness from
  `SB_AUDIT_WITNESS_BACKEND=s3`, an S3 bucket with Object Lock; see
  [S3 audit witness](#s3-audit-witness).
- **Batch export.** Set `SB_AUDIT_EXPORT_BACKEND=webhook` with an `https://`
  `SB_SECRET_AUDIT_EXPORT_URL` and `SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN` (or
  HMAC / mTLS), or `s3` / `bus`, to enable authenticated periodic export
  of new JSONL segments (`Content-Type: application/x-ndjson`). A custom
  `controlplane.AuditExporter` is also supported. In enterprise mode the bearer
  token must contain at least 32 bytes. A configured
  `SB_AUDIT_INGEST_TOKEN` has the same minimum; leave it empty to mint a random
  per-boot 256-bit signing key.
  Receivers must honor `Idempotency-Key`; it includes the node, byte offset,
  and a payload digest so retries deduplicate without colliding after retention
  rewrites reset the local byte offset.
- Enterprise deployments **must** configure an off-node event exporter.
  Witness is an additional tamper-evidence control, not a substitute for the
  reconstructable event stream. This is enforced at boot: with
  `SB_ENTERPRISE_MODE=true` the daemon refuses to start unless the backend is
  `webhook`, `s3` or `bus`, or a programmatic `controlplane.AuditExporter` is
  wired. `noop`, `stdout` and `file` all keep the evidence on the node that
  produced it, so disk loss takes the history with it — "an exporter is
  configured" is not the bar, "the evidence leaves the node" is.
- See `controlplane.Witness` / `AuditExporter` / `HasExternalWitness` and the
  enterprise boot checks around `SB_SECRET_AUDIT_EXTERNAL_WITNESS` and
  `SB_SECRET_AUDIT_EXPORT_URL`.

If no export URL is configured, **disk loss loses events** that lived only on
that node's JSONL (already the open-source honesty boundary).

See also recipient-set repair and cluster identity requirements in
[`docs/.../cluster-secrets.mdx`](../../docs/src/content/docs/cluster-secrets.mdx).

**Peer auth honesty:** cluster mode requires `SB_CLUSTER_TLS_DIR`. Internal
secret, audit, recovery, and Raft-forward traffic uses the dedicated mTLS
listener; the server requires a certificate signed by the cluster CA and there
is no retry downgrade after a TLS failure. Every node certificate must carry a
`node:<SB_NODE_ID>` SAN; common-name/shared-SAN compatibility is not accepted.
Atomically replacing `node.crt` and `node.key` hot-reloads the pair on the next
TLS handshake, while existing connections drain naturally. The fleet PAT
remains a second operator credential, so protect and rotate it as well.
Enterprise cluster startup also refuses `ca.key` in `SB_CLUSTER_TLS_DIR`.
Keep the CA signing key with an offline signer or HSM; the daemon runtime needs
only `ca.crt`, `node.crt`, and `node.key`.

## Alerts

| Alert | Meaning | First action |
|---|---|---|
| `SandboxdSecretAuditSinkUnavailable` | The local audit writer cannot persist evidence | Restore directory/disk access; strict-boot nodes will remain down until healthy |
| `SandboxdAuditEventsDropped` | Audit buffer overflowed; gap markers were written | Check disk / audit I/O latency; inspect JSONL for `result=gap` |
| `SandboxdSecretFanoutFailures` | Async sealed-blob peer push/delete failed | Check peer health, PAT, and `failover_ready` on recent HA creates |
| `SandboxdSecretDeleteOutboxStalled` | A delete job is still unacknowledged after 15 minutes | Check recipient membership, internal API auth, and network reachability |
| `SandboxdSecretDeleteOutboxBacklogHigh` | More than 10,000 durable deletes are queued | Restore recipients and verify the bounded reconciler is draining |
| `SandboxdSecretPutOutboxBacklogHigh` | Durable create-path peer PUTs are queued (`aerolvm_secret_put_outbox_pending`) | Check peer health/mTLS; put-outbox uses the same bounded worker pool as delete reconcile |
| `SandboxdSecretPutOutboxFailures` | Put-outbox persist/reconcile failed (`aerolvm_secret_put_outbox_failures_total`) | Inspect disk/SQLite and peer reachability; creates retract when the initial journal fails |
| `SandboxdSecretAuditExportFailing` | Off-node event batches are not being accepted | Restore receiver connectivity/auth before local disk loss exceeds the recovery objective |
| `SandboxdAuditWitnessShipFailing` | Heads have not reached the witness for 15 minutes (`aerolvm_secret_audit_witness_healthy` is 0 and failures keep rising) | Fix the path to S3, the node role's witness grants or the bucket policy (the log names the error). Do not restart the node until the witness answers: boot validation needs it |
| `SandboxdAuditWitnessForeignHead` | This node's witness key holds a head this node did not ship (`aerolvm_secret_audit_witness_foreign_head_total` rose) | Check for a duplicate `SB_NODE_ID`, then treat it as a security incident: [foreign head](#foreign-head-sandboxdauditwitnessforeignhead) |
| `SandboxdClusterCertExpiring` | Node (<14 days) or CA (<30 days) certificate approaches expiry | Sign a fresh node pair and atomically replace `node.crt`/`node.key`; prefer ≤90-day leaf certs |
| `SandboxdSecretProviderCanaryFailing` | Provider boot/runtime canary is down | For `awskms`, check IAM/KMS; consider `SB_SECRET_PROVIDER_STRICT_BOOT` |

## Audit export connectors

`SB_AUDIT_EXPORT_BACKEND` selects `noop` | `stdout` | `file` | `webhook` | `s3`
| `bus` (design: `plans/audit-export-connectors.md`; defaults:
`setup/config-defaults.md`). The first three are on-node only and are rejected
under `SB_ENTERPRISE_MODE=true`. The split copies kube-apiserver: Raft holds only
live placement and a short-grace deleted-sandbox routing stub; the local JSONL
is the buffer; the backend carries history. Nothing here runs on a sandbox
request path.

What to expect and check:

1. **At-least-once.** A crash between the receiver's ack and the local cursor
   write re-sends a batch with the **same** `Idempotency-Key` /
   `X-Aerol-Audit-Batch-ID`; the S3 key is that id. Receivers dedupe on it or
   on `event_id`. Duplicates are normal after a restart, never a corruption sign.
2. **Lag, never loss.** A failing backend makes
   `aerolvm_audit_export_lag_bytes` grow and `aerolvm_audit_export_backend_healthy`
   read 0 (alerts `SandboxdAuditExportLagging` / `SandboxdAuditExportFailures`).
   Retention refuses to rotate unexported bytes, so disk grows until the
   receiver recovers. Fix the receiver; do not shrink retention to "free" disk —
   that discards evidence the backend never got.
3. **Backoff.** After a failure the tailer waits (exponential, jittered, capped
   by `SB_AUDIT_EXPORT_MAX_BACKOFF`) before retrying; the log line says
   `retry_in`. This is expected during a receiver outage.
4. **Every record carries `owner_ref` and `incarnation_id`**, so a downstream
   store can authorize and partition without asking the cluster.
5. **Post-delete reads.** For `SB_AUDIT_DELETED_GRACE` after a delete, any
   ingress can still route `GET /v1/sandboxes/{id}/audit` to the evidence
   nodes. After that (or when the stub index hit `SB_AUDIT_DELETED_INDEX_MAX`),
   the cluster answers 404/503 and the export backend is the source of record.
   The evidence node itself keeps serving from its own `sandbox_audit_acl`
   row for `SB_SECRET_AUDIT_RETENTION_DAYS`.

## Boot verification and `secrets.verified`

Every boot verifies the local chain before the writer opens. With
`SB_SECRET_AUDIT_BOOT_VERIFY=full` (default) that is one pass over the whole
file — O(retained volume) in time, O(1) in memory; the boot-time witness
check reuses that pass (it probes for the locally recorded witness tip), so a
node with an external witness does not read the file a second time.

With `checkpoint`, the writer keeps `secrets.verified` next to the log: the
offset, record, and head of the last fsync. Boot re-reads only that record
and what follows it, opens the writer, and then runs the same full pass an
operator can request with `POST /v1/audit/verify` in the background:

- `secret audit chain verified from checkpoint; full verification continues in
  background` at boot, then `secret audit chain fully verified after checkpoint
  boot` — normal.
- `secret audit chain failed full verification after checkpoint boot` (alert
  `SandboxdAuditChainBroken`, critical): the prefix boot trusted does not
  verify. Local audit reads answer `503`, the read index is off, appends
  continue (they link from the checkpoint). Capture the file; the log line
  and `POST /v1/audit/verify` name the offset.
- A stale sidecar (retention rewrote the file, the record is gone, or it
  points past EOF) is ignored: boot reads everything, then re-pins it.
  `aerolvm_secret_audit_boot_witness_provisional_total` counts boots that
  accepted a witnessed head on the local receipt because it lay in the
  trusted prefix; the background pass proves it.

Do not delete `secrets.verified` to "force" a full check — set the mode to
`full` for one boot, or call `POST /v1/audit/verify`.

An **empty** local chain is a failure, not a clean bill of health, whenever
something still remembers a chain: the external witness holds a head for this
node, or `witness_receipts.jsonl` records a head this node shipped. Deleting
the log is the cheapest tamper there is, and it used to short-circuit
verification before the witness was ever consulted. A node genuinely rebuilt
from scratch under the same node id therefore fails witness verification —
evidence loss is an event someone signs off on, not something the daemon
papers over. With an Object Lock witness the old head can never be cleared,
so the recovery is to bring the node back under a new id:
[Rebuild a node under a new SB_NODE_ID](#rebuild-a-node-under-a-new-sb_node_id).

## S3 audit witness

The witness keeps each node's audit fingerprint (the hash-chain head) off the
node, in an S3 bucket with **Object Lock**. Object Lock means nobody can change
or delete a stored version until its lock ends, not even the node that wrote
it. Design: `plans/open-audit-witness.md`. Settings and their defaults:
`setup/config-defaults.md`, "Audit witness".

**What it proves.** Someone who takes over a node *after* a head was stored
cannot rewrite or delete the history that head covers without being caught.
The node refuses to boot, and `aerolvm audit verify` reports FAIL.

**What it does not prove.**

- Records written since the last ship. Heads ship every
  `SB_SECRET_AUDIT_WITNESS_INTERVAL` (30 s), so the newest 30 seconds can be
  rewritten.
- A node that was already compromised when it wrote. It can witness a forged
  chain from the start.
- That a newer head is honest. A compromised node can store a new head that
  matches a rewritten chain, and the boot check reads only the latest head.
  The offline verifier catches this, because it checks every head ever stored.
- Who wrote a head. See [foreign head](#foreign-head-sandboxdauditwitnessforeignhead).

The witness stores fingerprints, not records. It cannot rebuild a lost log.
Pair it with an off-node export (`SB_AUDIT_EXPORT_BACKEND=s3`, `webhook` or
`bus`). Enterprise mode requires both.

### Bucket recipe

Terraform builds all of this with `audit_witness_enabled = true`
(`Terraform/audit_witness.tf`; lock mode `witness_lock_mode`, lock length
`witness_lock_days`). The installer never creates a bucket. By hand:

1. **Create the bucket with Object Lock on.** Turning on Object Lock at
   creation also turns on versioning, which it needs. Use the bucket for the
   witness alone: its default lock applies to every object in it.
2. **Add a default retention rule.**
   - **Compliance mode for production.** No one can delete a version before
     its lock ends, not even the AWS account root.
   - **Governance mode for trials.** A principal with
     `s3:BypassGovernanceRetention` can delete versions early, which is what
     lets you remove a trial bucket. The node role must never hold it.
   - **Days: at least `SB_SECRET_AUDIT_RETENTION_DAYS`** (default 30). A head
     must outlive the local records it vouches for. The lock length also
     limits how far back the verifier can see heads.
3. **Add a lifecycle rule that expires noncurrent versions** after the lock
   period. Every ship adds a version, so without it the bucket grows forever.
   Never expire current versions; the newest head of each day must stay. S3
   never expires a version that is still locked.
4. **Block public access and turn on default encryption.**
5. **Give the node role exactly this.** `<prefix>` is
   `SB_AUDIT_WITNESS_S3_PREFIX` (default `witness/`).

   | Effect | Actions | Resource |
   |---|---|---|
   | Allow | `s3:PutObject`, `s3:GetObject`, `s3:GetObjectVersion` | `arn:aws:s3:::<bucket>/<prefix>*` |
   | Allow | `s3:ListBucketVersions`, `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration` | `arn:aws:s3:::<bucket>` |
   | Allow | `s3:ListBucket`, with no `s3:prefix` condition | `arn:aws:s3:::<bucket>` |
   | Deny | `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold`, `s3:BypassGovernanceRetention` | `arn:aws:s3:::<bucket>/*` |
   | Deny | `s3:PutBucketObjectLockConfiguration`, `s3:PutBucketVersioning`, `s3:PutLifecycleConfiguration`, `s3:PutBucketPolicy` | `arn:aws:s3:::<bucket>` |

   `s3:ListBucket` is not optional. Without it, S3 answers a read of a missing
   key with 403 instead of 404. A first boot on an empty bucket then fails,
   and so does any boot after the node was down across UTC midnight. Do not
   limit it with an `s3:prefix` condition: a read carries no prefix, so S3
   would not count the grant and would still answer 403. Use a bucket that
   holds only the witness.
6. **Turn on CloudTrail S3 data events** (write events) for the bucket. An S3
   version does not record who wrote it. CloudTrail does, and it is the only
   way to attribute a foreign head.
7. **Set the settings on every node**, with an `SB_NODE_ID` that is unique
   among nodes sharing the bucket. Installer: commented out in
   `/etc/sandboxd/sandboxd.env`. Ansible: `sandboxd_audit_witness_*` and
   `sandboxd_node_id`. Terraform: automatic (the node id is
   `<cluster_name>-<node>`).

Turning the witness on for a node that never shipped to a witness is safe: the
first boot finds the bucket empty for that node and stores its current head.
Moving a node from another witness to S3 is not: its local receipts name heads
the new bucket never saw, and that is treated as lost evidence. Bring such a
node over under a new id ([rebuild](#rebuild-a-node-under-a-new-sb_node_id)).

The node role is shared by every node in a Terraform cluster, so one node can
write a version into another node's key. It cannot erase the other node's
history; the lock stops that. Limiting each node to its own key needs the
writer's AWS identity in the key, which is a future layout change
(`TODOS.md`, "Per-node witness write scoping"). Until then, CloudTrail is how
you find the writer.

### Boot refusals

sandboxd checks the bucket at every boot, within 30 seconds. If a check fails,
it refuses to start, and the error names the fix.

| The error names | What it means | Fix |
|---|---|---|
| Versioning not enabled | The bucket was not made for Object Lock | Create a new bucket with Object Lock on (simplest), or enable versioning and then Object Lock on this one |
| Object Lock not enabled | Nothing stops a delete or an overwrite | Same as above |
| No default retention rule | Heads are stored unlocked | Add a default retention rule with a mode and days |
| Retention shorter than `SB_SECRET_AUDIT_RETENTION_DAYS` | A head could expire before the records it vouches for | Raise the bucket's default days (it applies to new versions), or lower `SB_SECRET_AUDIT_RETENTION_DAYS` |
| `s3:ListBucket`, at the missing-key probe | S3 answered 403 for a key that does not exist | Grant `s3:ListBucket` on the bucket, without an `s3:prefix` condition |
| `s3:BypassGovernanceRetention`, after the canary delete | sandboxd stored a test version and deleted it, the way an attacker would. The delete worked, so the lock does not protect this node | Remove bypass from the node role and add the Deny statements. Check that no other policy grants it |
| `s3:DeleteObject`, after the canary delete marker | sandboxd then deleted the test key without a version id and got a delete marker. Object Lock does not block that, so this node could hide its newest head | Deny `s3:DeleteObject` on the node role (the Deny statements above do) |
| The canary delete failed with something other than AccessDenied | sandboxd cannot prove deletes are blocked | Fix the cause in the message (region, network, endpoint). An unknown answer is never treated as safe |
| A check and the bucket, after 30 seconds | S3 did not answer in time | Fix the path to S3 (VPC endpoint or NAT), the region or the endpoint |
| `SB_NODE_ID`, at config load | The witness is set, but the id is empty or `standalone` | Set a unique `SB_NODE_ID` |
| An empty local log while the witness holds a head | The log is gone, but the witness remembers a chain | [Rebuild a node under a new SB_NODE_ID](#rebuild-a-node-under-a-new-sb_node_id) |
| `secret audit witness mismatch: local_head=… witnessed_head=…` | The newest stored head is not in the local chain | [Witness mismatch](#witness-mismatch) |
| A delete marker on the newest head | Someone tried to hide the head. The node role cannot do this | [Witness mismatch](#witness-mismatch), step 4 |

An S3 outage blocks restarts whenever a witness is configured. That is on
purpose: a node that cannot reach its witness cannot prove its log is intact. A node that is
already running keeps working through an outage. Its ships fail,
`aerolvm_secret_audit_witness_healthy` drops to 0 and
`aerolvm_secret_audit_witness_failures_total` rises. Records keep landing in
the local log, and the next ship catches up.

Each boot stores one canary version under `<prefix>canary/`. It stays locked
for the lock period, then the lifecycle rule removes it.

### Witness mismatch

`secret audit witness mismatch` means the newest stored head is not in this
node's local chain. Either the local log changed (edited, rolled back, or
restored from an old backup), or someone else stored a newer head in this
node's key.

1. **Do not edit, delete or "repair" anything.** Copy the audit directory
   somewhere safe: `secrets.jsonl`, `witness_receipts.jsonl`,
   `witness_tip.json` and `secrets.verified`, next to the log
   (`/var/lib/sandboxd/audit/` by default).
2. **List the node's stored heads** (`witness/` is the default prefix):

   ```bash
   aws s3api list-object-versions --bucket <bucket> \
     --prefix "witness/node=<SB_NODE_ID>/"
   ```

   There is one key per UTC day, and the newest day sorts last. Within a key,
   the version marked `IsLatest` is the newest. Each version's body names its
   `node_id` and `head_hex`; read one with `aws s3api get-object --version-id`.
3. **Compare the newest `head_hex` with `witness_receipts.jsonl`.**
   - It is one this node shipped: the local log changed. That is tampering, or
     a restore from an old backup. Run the [verifier](#offline-verification-aerolvm-audit-verify)
     over a window that covers the change, and keep the node down until you
     know which.
   - It is not one this node shipped: someone else wrote it. Go to
     [foreign head](#foreign-head-sandboxdauditwitnessforeignhead).
4. **A delete marker** on the newest day's key also stops boot. The node role
   cannot create one, so someone with wider rights did. Find them in
   CloudTrail. The locked versions under the marker are intact. After the
   investigation, an administrator (never the node role) can delete the
   delete marker itself, which makes the head current again.

To bring the node back:

- **The newest head is foreign, and the local log is intact** (the verifier
  agrees): an administrator can restore the node's own head as the newest
  version. Fetch the body of the node's last own version, then store it as a
  new version of today's key
  (`witness/node=<SB_NODE_ID>/day=<UTC yyyy-mm-dd>/head.json`) with
  `aws s3api put-object --checksum-algorithm SHA256 --body <file>`. A bucket
  with a default lock refuses an upload without a checksum.
- **Anything else:** [rebuild under a new SB_NODE_ID](#rebuild-a-node-under-a-new-sb_node_id).

Either way, the foreign or stale version stays locked as evidence, and the
verifier keeps reporting FAIL for any window that contains it. Record the
incident.

### Foreign head (`SandboxdAuditWitnessForeignHead`)

Before every ship, idle or busy, a node reads its own key. If the newest head
there is neither its current head nor the last head it shipped, it counts that
in `aerolvm_secret_audit_witness_foreign_head_total`, logs a warning naming both
heads, and then ships as usual. A missing head after a successful ship counts
the same way. `SandboxdAuditWitnessForeignHead` fires on any increase.

What it means:

- Someone wrote into this node's key. That is another node using the shared
  role, a second server configured with the same `SB_NODE_ID`, or anyone
  holding the node role's credentials.
- It fires on the victim's next tick, whether the victim is idle or busy.
- A read error is not counted. An S3 blip shows in the failures counter and
  the healthy gauge instead, and pages nobody here.
- The first ship of each UTC day re-ships an unchanged head on purpose. That is
  not counted.

What it does not prove:

- **Who wrote it.** S3 versions carry no writer. Use CloudTrail S3 data events
  on the witness bucket: the caller is the node role's session, and an EC2
  instance-role session is named after the instance id. Terraform's `nodes`
  output maps instance ids to node names.
- **That every foreign write was seen.** A write that lands between the
  victim's read and its own write is buried under the victim's version. No
  alert fires. Only the verifier sees it, as a FAIL.
- **That the node will refuse to restart.** After the alert, the node's next
  ship puts its own head back on top, so it boots normally. A restart is
  refused only if the foreign head is still the newest, for example when the
  node was down as it landed.

What to do:

1. **Check for a duplicate `SB_NODE_ID`** among the servers that share the
   bucket. That is the common honest cause. Rebuild one of them under a new id.
2. **Otherwise, treat it as a security incident.** Find the writer in
   CloudTrail and isolate it. Its own node is suspect too.
3. **Run the verifier** over a window that covers the alert. Expect FAIL naming
   the foreign head, and keep the report with the incident.

### Rebuild a node under a new SB_NODE_ID

Use this when a node's disk was lost or replaced, or its audit log is gone,
and boot refuses because the witness still holds a head for its id. Object
Lock forbids clearing that head, by design. So the node comes back under a new
id, and the old id's locked history stays in the bucket as the record of the
loss. Write down the old id, the new id, the time and the reason.

**Single server:**

1. Stop sandboxd. If the disk survived, move the old local receipts aside and
   keep them: `witness_receipts.jsonl` and `witness_tip.json` in the audit
   directory. They name heads stored under the old id, and boot treats them as
   proof that a chain existed.
2. Pick a new id that is unique among servers sharing the bucket, for example
   `web-1-r2`.
3. Set `SB_NODE_ID=<new id>` in `/etc/sandboxd/sandboxd.env` by hand. Ansible's
   `sandboxd_node_id` refuses to change an existing id on purpose; it can set
   the id on a freshly installed server that has none yet.
4. Start sandboxd. The witness holds nothing for the new id, so the first boot
   stores the current head.

**Cluster node:** the node id is also its Raft member id and the `node:<id>`
name in its certificate, so the node leaves the cluster and joins again.

1. On a surviving node, remove the old member:

   ```bash
   sudo /usr/local/sbin/sandboxd-node-lifecycle.sh remove-member <old-id>
   ```

   (`scripts/sandboxd-node-lifecycle.sh` in the repo; Ansible's
   `configure-ops.yml` installs it there.) It refuses a member that is still
   gossiped alive; add `--force` only when you are sure the old node is down.
   Sandboxes the old node owned are gone, as with any removed member.
2. On the rebuilt host, stop sandboxd and move the old receipts aside, as in
   step 1 above. If an old Raft data directory is still there, rejoin with
   `--force`, which discards it.
3. Join under the new id, with the same flags the node first joined with:

   ```bash
   sudo ./cluster-join.sh --node-id <new-id> \
     --gossip-key '<key>' --peers <seed>:7001 \
     --tls-bundle <path> --cred-bundle <path>
   ```

   It writes a CSR for `node:<new-id>` and stops. Sign it on the seed with
   `cluster-sign-node.sh --csr <csr> --node-id <new-id> --out <crt>`, then run
   the same `cluster-join.sh` command again with `--signed-cert <crt>`.
4. On a Terraform cluster the id is `<cluster_name>-<name>`. Add the
   replacement under a new name in `nodes` and remove the old entry, instead
   of reusing the name.

### Offline verification (`aerolvm audit verify`)

The boot check reads only the newest head. The verifier checks every stored
head inside a time window against the evidence: the export and, if you give
it, each node's local log. Run it from a machine outside the cluster, with
read-only access. Terraform can create that policy
(`audit_witness_auditor_policy_enabled = true`, output
`audit_witness_auditor_policy_arn`).

```bash
aerolvm audit verify \
  --witness s3://<witness-bucket>/witness/ \
  --since 720h \
  --export s3://<export-bucket>/<SB_AUDIT_EXPORT_S3_PREFIX>
```

- **`--since` is required.** It takes an RFC 3339 time or a duration such as
  `720h`. Every head newer than it must be reached by the evidence, or the
  result is FAIL. Older heads are listed, not checked. The window comes from
  you, not the node, because a node that controls its own export could delete
  the oldest batches to shrink the check.
- **Keep exports at least as long as the window you verify.** If the oldest
  batches inside the window are gone, the result is FAIL. Keep the window no
  longer than the witness lock too: older noncurrent heads have expired. The
  integration suite's export bucket expires objects after 3 days, which suits
  tests and is too short for an audit.
- **Evidence.** `--export s3://…` reads an S3 export. For a `webhook` or `bus`
  export, save the NDJSON batches your receiver got and pass `--export-dir
  <dir>`. Add `--local <node-id>=<path to secrets.jsonl>` (repeatable) to
  include a node's local log; it covers records the export has not shipped
  yet.
- **Other flags.** `--node <id>` (repeatable) limits the check to some nodes.
  `--max-lag` (default `15m`) sets how long a head may wait for the export.
  `--region`, `--endpoint` and `--path-style` configure the S3 client.
  `--json` prints a machine-readable report.

Results:

| Result | Exit code | Meaning | Next step |
|---|---|---|---|
| PASS | 0 | Every head in the window links to the evidence | Keep the report |
| FAIL | 1 | A head is not reached: a rewritten history, a rollback, a foreign head, or missing evidence. Also used when the verifier cannot verify at all | Read the report; it names the head and node. Start at [witness mismatch](#witness-mismatch) |
| INCOMPLETE | 3 | A head is newer than the end of the evidence and has waited longer than `--max-lag` | The export is stalled or behind. Fix it and rerun, or pass `--local` for that node. Never read INCOMPLETE as PASS |

Exit code 2 means the command line was wrong.

An idle node still stores one head a day, so a node with no stored version for
more than a day has stopped shipping. Find out why.

### Retire a witness bucket

A compliance bucket cannot be emptied until every version's lock ends, and
`terraform destroy` fails on it until then. That is the point: the evidence
outlives the cluster. Either wait for the locks to end, or take the bucket out
of Terraform's state (`terraform state rm`) and delete it by hand once they
have.

A governance bucket can be emptied early by a principal that holds
`s3:BypassGovernanceRetention` and sends the bypass header, for example
`aws s3api delete-objects --bypass-governance-retention` over every version
and delete marker. Then `terraform destroy` succeeds. That is why integration
scenarios use governance buckets with a 1-day lock and
`SB_SECRET_AUDIT_RETENTION_DAYS=1` (Terraform: `witness_lock_mode =
"GOVERNANCE"`, `witness_lock_days = 1`).

## Audit read index and on-demand verification

`GET /v1/sandboxes/{id}/audit` is served from a per-sandbox index over the
local `secrets.jsonl` (`secret_audit_index` in the store; design:
`plans/audit-read-index.md`). A page costs O(page): the index names the
records, only those are read, and each is checked against its own hash. The
index is derived data — the JSONL and its chain stay the evidence — so any
disagreement between the two throws the index away and rebuilds it from the
file in the background while pages are served by a scan of the file.

What to expect and check:

1. **`aerolvm_audit_index_ready` = 0** (alert `SandboxdAuditIndexNotReady`)
   means pages are being served by the scan. Normal for the minutes after a
   first boot on an existing log, after retention rewrote lines it could not
   re-base, or after a read proved an index entry wrong; the log line
   `building secret audit index from the local log` says why and
   `aerolvm_audit_index_rebuilds_total` counts it. Persistently 0 with
   `aerolvm_audit_index_write_failures_total` rising means the store is
   refusing the index's transactions (disk full, locked DB) — fix that, the
   maintainer retries with backoff.
2. **`aerolvm_audit_index_lag_bytes`** is how much of the file the index does
   not yet cover; pages scan that tail themselves, so lag never hides an
   event, it only costs time. It is normally 0 or one batch.
3. **`aerolvm_audit_index_chain_breaks_total` > 0** (alert
   `SandboxdAuditChainBroken`, critical): while indexing, a record did not link
   to its predecessor. That is corruption or tampering, not a crash — a torn
   tail is cut at boot and never reaches the indexer. The node withholds all
   local audit reads (`503`) and the index stays off until restart, which
   re-verifies the whole file and refuses to boot on it under strict mode.
   Capture the JSONL for evidence before touching it; `POST /v1/audit/verify`
   names the offset.
4. **`POST /v1/audit/verify`** (operator PAT) re-verifies every record against
   the chain on demand: `{"ok":true,"head":…,"records":N,"writer_tip_matches":true}`.
   It is O(file) and runs one at a time per node (`429` while one is in
   flight). `aerolvm_audit_chain_verify_ok` / `_verified_unix` record the last
   result (alert `SandboxdAuditChainVerifyFailed`). Boot and every retention
   sweep also verify the whole chain; page reads do not.
5. **`aerolvm_audit_query_busy_total` rising** with `429 Retry-After: 1` on
   audit reads: the node's 8 read slots stayed busy for 50 ms. With the index
   ready a slot is held for milliseconds, so this means the node is genuinely
   saturated (or the index is off and pages are scanning). Peer fan-out reads
   have their own per-node rate bucket, so a fleet-wide storm cannot starve
   public reads here.
6. **`SB_AUDIT_INDEX_ENABLED=false`** returns to scanning every retained record
   per page. Use only to isolate a suspected index fault; nothing else depends
   on the index.

## Audit drops / gap markers

1. Confirm the counter:

   ```bash
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/metrics | grep aerolvm_audit_events_dropped
   ```

2. Inspect the local log for gap markers (`"result":"gap"`,
   `"reason":"overflow"`). A gap means events were dropped under backpressure —
   the stream remains honest about incompleteness.

3. Check `aerolvm_secret_audit_sink_healthy` (1 = writable, 0 = unavailable).
   The default `SB_SECRET_AUDIT_STRICT_BOOT=true` refuses daemon startup when
   the writer cannot be opened. Setting it false is an emergency recovery mode;
   attempted events remain counted as dropped and the critical alert remains.

4. Mitigate: free disk, reduce decrypt storms, restart only after capturing the
   current JSONL for evidence.

5. WASM worker subprocesses never write `secrets.jsonl`. When the loopback
   ingest is down they append to the same `secrets.spill.jsonl` under the same
   lock, through the same writer the daemon uses (`auditlog.SpillFile`): one
   goroutine per worker, one flock and one fsync per batch, and the daemon's
   drain folds the file into the chain. A sandbox's dial only ever does a
   non-blocking queue send; a full queue costs two atomics and is reported by
   one coalesced `reason=overflow` marker. If the spill disk fails the worker
   backs off (1s doubling to 30s, one log line per backoff) and keeps the loss
   owed until the next marker lands. Counters (worker expvar):
   `aerolvm_wasm_egress_audit_ipc_fail_total`,
   `aerolvm_wasm_egress_audit_spill_batches_total`,
   `aerolvm_wasm_egress_audit_spill_fail_total`,
   `aerolvm_wasm_egress_audit_gap_markers_total`.

### Torn tail at boot (`"reason":"torn_tail"`)

Appends are one write per batch and fsynced at least once per second, so an
unclean shutdown (OOM kill, power loss, `kill -9`, spot reclaim) can leave a
partial final record on disk. At the next open the sink cuts that
unterminated, unparseable tail back to the last verified record, chains a gap
marker (`"result":"gap","reason":"torn_tail"`), logs
`secret audit torn tail repaired at boot`, and increments
`aerolvm_audit_torn_tail_repairs_total` / `aerolvm_audit_torn_tail_bytes_total`
(alert `SandboxdAuditTornTailRepaired`). The node boots normally under strict
mode; no operator action is needed for the audit sink itself.

What this does and does not mean:

- Every record before the marker still verifies; nothing was rewritten.
- `dropped` on the marker is a floor. Exactly one partial record was visible on
  disk; events still in the page cache at the crash left no trace at all.
- Only an *unterminated* tail that is not valid JSON is treated as a tear. A
  fully written malformed line, or a parseable record whose hash does not link,
  still refuses to open — that is corruption or tampering, not a crash, and the
  `SandboxdSecretAuditSinkUnavailable` path applies.
- `secrets.torn` in the audit directory means a repair was recorded but its
  marker has not been chained yet (the daemon went down again in between). The
  next open writes it. Do not delete the file.

Repeated firing means the node itself is crashing. Find that cause first.

Retention: `SB_SECRET_AUDIT_RETENTION_DAYS` (default 30) removes records older
than the window daily, by record time, wherever they sit in the file:

- The expired head of the file is dropped and replaced by one immutable
  `retention_checkpoint` whose `prev_hash` is the last dropped `event_hash`
  (kept event bytes / `event_hash` are never rewritten). Witness verification
  uses `checkpoint.WitnessedThrough` (when that head was actually shipped) plus
  the remaining chain; the value is carried from prune to prune while the
  witness stays parked on it.
- An expired record that sits *behind* a newer one (the spill drain and worker
  ingest land older events after newer ones) cannot be cut out of the chain,
  so it is reduced in place to a `retention_redacted` stub: `time`,
  `event_id`, `prev_hash`, `event_hash`, and nothing else. The chain verifies
  through the stub (its `event_hash` is what the next record's `prev_hash`
  names), and a later prune reclaims the stub with the prefix once the record
  in front of it expires. A downstream verifier must treat
  `kind=retention_redacted` as a link-only record: accept it when its
  `prev_hash` is the chain so far, continue from its `event_hash`, and reject
  one that carries any other field. The node never writes a stub inside the
  retention window, so `redacted` in the `POST /v1/audit/verify` report counts
  what retention did; a stub younger than the window means a hand-edited file.
- `aerolvm_audit_retention_dropped_total` and
  `aerolvm_audit_retention_redacted_total` count both outcomes. A prune that
  redacted anything rebuilds the read index once (offsets after a stub move
  unevenly); a pure prefix drop shifts it in place.

## Per-sandbox egress evidence budget

Egress attribution writes one record per outbound connection. Without a
budget, one busy or compromised sandbox can grow the node-global
`secrets.jsonl` without bound, fill the bounded writer queue so other tenants'
secret-open records take the overflow path, and slow every O(file) pass
(boot verification, retention, index rebuild) for everyone on the node.

Each sandbox therefore has a token bucket of egress records
(`SB_AUDIT_EGRESS_SANDBOX_RATE` per second, burst
`SB_AUDIT_EGRESS_SANDBOX_BURST`; defaults 25 / 250). It is applied on the audit
writer itself, at the one funnel every record passes through, so the worker
ingest endpoint, the worker spill file, and the in-process mediators are all
covered and none can route around it. Secret-open records and gap markers are
never budgeted.

What you see when a sandbox is over budget:

- Its refused records are not written. They are counted and, within about five
  seconds (immediately at shutdown), written as **one** `egress` record for
  that sandbox with `reason: rate_limited` and `dropped: n` — indexed under the
  sandbox, so `GET /v1/sandboxes/{id}/audit` shows the loss to whoever reads
  that sandbox's history and to nobody else. The chain stays valid.
- `aerolvm_audit_egress_rate_limited_total` counts refused records;
  `aerolvm_audit_egress_rate_limit_markers_total` counts the coalesced
  records; `aerolvm_audit_ingest_throttled_total` counts worker posts answered
  `429`. Alert `SandboxdAuditEgressBudgetExceeded` fires while refusals
  continue.
- Workers treat `429` as final (`aerolvm_wasm_egress_audit_throttled_total`)
  and do not spill the record; the spill file is a path into the log, not
  around the budget.

If a legitimate workload needs more per-connection evidence, raise the rate and
burst — the cost is file growth on that node and export volume. Do not set the
rate to `0` on a shared node: that is the unbounded state the budget replaces,
and enterprise mode refuses it.

## Fan-out failures / `failover_ready` false

Peer obligations (the put and delete outboxes) retry on a schedule, not every
tick: attempt *n* is due `min(30s × 2^(n−1), 15m)` after the last attempt, a
never-attempted row is due at once, and a member rejoining gives every
obligation one immediate try regardless of its backoff. Rows whose placement
could not be read, or whose staged reseal is not yet promoted, are moved to
the back of the fair queue without counting an attempt, so they stay on the
30-second cadence. A permanently unreachable recipient therefore costs one
delivery attempt per 15 minutes per row, and the obligation stays until the
peer ACKs or retirement removes it; `aerolvm_secret_delete_outbox_pending`
and the stalled-outbox alert still show it.

1. Check `aerolvm_secret_fanout_failures_total` and recent create logs for
   `secret fanout` warnings.
2. Confirm recipients are alive (`GET /v1/cluster/members`) and share the
   credential encryption key / KMS access.
3. HA create success guarantees at least one backup ACK. Treat
   `failover_ready=false` as "the configured replica set is not complete yet";
   the remaining recipients continue asynchronously.
4. Recipient sets are recorded at seal/reserve time. When any intended backup
   target is dead, the holder-refresh path selects live worker/mixed
   replacements and **reseals** (recipients are in envelope AAD — old
   ciphertext cannot be pushed to new nodes). It atomically stages the sealed
   generation and retired-recipient journal, obtains a replacement ACK, then
   Raft-CASes `SecretRecipients` and releases cleanup. Until that completes,
   `failover_ready` may stay false.
5. Decommissioned recipient IDs remain in the delete outbox until they return
   an authenticated generation-scoped DELETE ACK. Permanently destroyed nodes
   therefore leave a visible cleanup obligation; membership disappearance is
   never accepted as evidence that their disks no longer contain ciphertext.

The reconciler exposes `aerolvm_secret_delete_outbox_pending`,
`aerolvm_secret_delete_outbox_oldest_age_seconds`,
`aerolvm_secret_put_outbox_pending`, `aerolvm_secret_put_outbox_failures_total`,
and `aerolvm_secret_tombstones`. Tombstones are pruned in bounded batches after
`SB_SECRET_TOMB_RETENTION_DAYS` (default 30), but never while a live sandbox,
sealed row, or pending delete outbox still references the sandbox ID.
After an eligible tomb is pruned, peer PUT still requires a matching live Raft
placement and exact recorded recipient set; deleted IDs cannot be resurrected
through the retention boundary.

### Leaving a cluster (cluster→single-node downgrade)

A node that ran in cluster mode keeps four lifecycle tables that only cluster
traffic could ever settle: sealed rows it holds as a backup for other owners'
sandboxes, tombstones, and the two peer outboxes (PUTs it still owed, DELETEs
it still owed). With `SB_ENABLE_CLUSTER=false` the same maintenance loop runs
and, having no peers, retires what cannot be finished:

1. **Peer obligations** older than `SB_SECRET_OUTBOX_STANDALONE_GRACE`
   (default 1h since their last attempt) are dropped, counted in
   `aerolvm_secret_delete_outbox_retired_standalone_total` /
   `aerolvm_secret_put_outbox_retired_standalone_total`, and logged once per
   sweep with a sample of the peers involved (`standalone: retired peer secret
   obligations ...`). Those peers may still hold ciphertext for the named
   lifecycles until their own retirement scan sees the placement is gone.
2. **Orphaned ciphertext** — a sealed row whose `(sandbox, incarnation)` has no
   live local sandbox row — is tombed after the same grace
   (`aerolvm_secret_ciphertext_retired_total`), exactly as the cluster
   retirement scan does when a placement disappears. Rows for sandboxes that
   still run here are never touched.
3. **Tombstones** are then pruned on `SB_SECRET_TOMB_RETENTION_DAYS` as usual,
   because nothing pins them any more.

Expect `SandboxdSecretDeleteOutboxStalled` to fire for up to the grace after
the downgrade (the obligations are visibly stranded, which is the point); it
clears when they are retired. If the node is going back into the cluster,
restart it in cluster mode within the grace and it still owes and retries them.
A node that was a cluster **server or ingress** never held secrets and has
nothing to retire.

## Provider canary failure

1. Read `aerolvm_secret_provider_canary_ok` (1 = ok, 0 = failing).
2. For `SB_SECRET_PROVIDER=awskms`: verify `SB_SECRET_AWS_KMS_KEY_ID`, IAM
   `Encrypt`/`Decrypt`, and network path to KMS.
3. Default boot is fail-open unless `SB_SECRET_PROVIDER_STRICT_BOOT=true`.
   Fail-open keeps the daemon up but new wraps/opens may fail — page on-call.

## Query audit history

Server-only (no SDK). Auth with PAT (operator) or a tenant token (own
sandboxes only — others 404).

```bash
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  'http://127.0.0.1:21212/v1/sandboxes/<id>/audit?limit=100' | jq .
```

Example response shape:

```json
{
  "events": [
    {
      "time": "2026-08-08T08:00:00.123456789Z",
      "actor": "node-a",
      "sandbox_id": "sb-1",
      "ref": "env:sb-1",
      "result": "success",
      "reason": "ok",
      "correlation_id": "1723104000123456789-deadbeef",
      "node_id": "node-a"
    }
  ],
  "coverage": {
    "answered": ["node-a", "node-b"],
    "missing": ["node-c"],
    "partial": true
  },
  "next_cursor": "2026-08-08T08:00:00.123456789Z"
}
```

Notes:

- Do **not** expect owner-forward to gather history; hit a node that has the
  sandbox row (typically the owner). That node fans out to peers.
- Rate limits apply (identity + node ceiling). `429` includes `Retry-After`.
- Internal peer path (mTLS + PAT in every cluster mode):
  `GET /v1/cluster/internal/sandboxes/{id}/audit`
  returns the local slice only.
- Host-mediated runtimes (wasm, isolate) also append `kind=egress` events with
  `destination` (host or host:port). Filter with `?kind=egress`. This is
  daemon-side destination attribution only — not guest secret-use proof.
  Byte totals remain on the netstats / controlplane path; per-destination
  bytes are not claimed. Disable with `SB_EGRESS_ATTRIBUTION_ENABLED=false`.

## Drill template

- Date:
- Cluster:
- Alert / scenario:
- Commander:
- Evidence captured (`/v1/metrics`, members, sample audit page):
- Mitigation:
- Follow-ups:
