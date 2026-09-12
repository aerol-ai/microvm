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
  the JSONL after disk loss.
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
  reconstructable event stream.
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
| `SandboxdClusterCertExpiring` | Node (<14 days) or CA (<30 days) certificate approaches expiry | Sign a fresh node pair and atomically replace `node.crt`/`node.key`; prefer ≤90-day leaf certs |
| `SandboxdSecretProviderCanaryFailing` | Provider boot/runtime canary is down | For `awskms`, check IAM/KMS; consider `SB_SECRET_PROVIDER_STRICT_BOOT` |

## Audit export connectors

`SB_AUDIT_EXPORT_BACKEND` selects `noop` | `stdout` | `file` | `webhook` | `s3`
| `bus` (design: `plans/audit-export-connectors.md`; defaults:
`setup/config-defaults.md`). The split copies kube-apiserver: Raft holds only
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

Retention: `SB_SECRET_AUDIT_RETENTION_DAYS` (default 30) prunes old lines daily.
Prune drops a prefix and inserts an immutable `retention_checkpoint` (kept
event bytes / EventHash are unchanged). Witness verification uses
`checkpoint.WitnessedThrough` (when that head was actually shipped) plus the
remaining chain.

## Fan-out failures / `failover_ready` false

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
