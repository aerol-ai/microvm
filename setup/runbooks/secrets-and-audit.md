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
- **Batch export.** Set an `https://` `SB_SECRET_AUDIT_EXPORT_URL` and
  `SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN` to enable authenticated periodic POST
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

See also the D5 frozen-recipient limitation and cluster identity requirements in
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
4. Recipient sets are recorded at seal/reserve time. When a majority of frozen
   backup targets are dead, the holder-refresh path selects live
   worker/mixed replacements, Raft-updates `SecretRecipients`, and **reseals**
   (recipients are in envelope AAD — old ciphertext cannot be pushed to new
   nodes). Until that completes, `failover_ready` may stay false.

The reconciler exposes `aerolvm_secret_delete_outbox_pending`,
`aerolvm_secret_delete_outbox_oldest_age_seconds`,
`aerolvm_secret_put_outbox_pending`, `aerolvm_secret_put_outbox_failures_total`,
and `aerolvm_secret_tombstones`. Tombstones are pruned in bounded batches after
`SB_SECRET_TOMB_RETENTION_DAYS` (default 30), but never while a live sandbox,
sealed row, or pending delete outbox still references the sandbox ID.
After an eligible tomb is pruned, peer PUT still requires a matching live Raft
placement and exact recorded recipient set; deleted IDs cannot be resurrected
through the retention boundary.

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
