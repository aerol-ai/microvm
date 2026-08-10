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
  mechanism. It targets the Raft-retained owner history and falls back to all
  workers if that bounded history is missing or truncated. It is **not** a
  durability mechanism and cannot recover records that no longer exist.
- Coverage in the API response names which members answered; `partial: true`
  means the page is incomplete — never treat a partial page as full history.

See also the D5 frozen-recipient limitation and cluster identity requirements in
[`docs/.../cluster-secrets.mdx`](../../docs/src/content/docs/cluster-secrets.mdx).

**Peer auth honesty:** with `SB_CLUSTER_TLS_DIR` configured, internal secret,
audit, recovery, and Raft-forward traffic prefers the dedicated mTLS listener;
the server requires a certificate signed by the cluster CA and there is no
retry downgrade after a TLS failure. `SB_ENTERPRISE_MODE=true` requires this
configuration, rejects internal routes on the public listener, and rejects
insecure gossip/credential modes. Non-enterprise
clusters may still use the legacy public API + fleet PAT path when no cluster
TLS directory is configured. The PAT remains an operator credential, so protect
and rotate it even when mTLS is enabled.

## Alerts

| Alert | Meaning | First action |
|---|---|---|
| `SandboxdSecretAuditSinkUnavailable` | The local audit writer cannot persist evidence | Restore directory/disk access; strict-boot nodes will remain down until healthy |
| `SandboxdAuditEventsDropped` | Audit buffer overflowed; gap markers were written | Check disk / audit I/O latency; inspect JSONL for `result=gap` |
| `SandboxdSecretFanoutFailures` | Async sealed-blob peer push/delete failed | Check peer health, PAT, and `failover_ready` on recent HA creates |
| `SandboxdSecretDeleteOutboxStalled` | A delete job is still unacknowledged after 15 minutes | Check recipient membership, internal API auth, and network reachability |
| `SandboxdSecretDeleteOutboxBacklogHigh` | More than 10,000 durable deletes are queued | Restore recipients and verify the bounded reconciler is draining |
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

## Fan-out failures / `failover_ready` false

1. Check `aerolvm_secret_fanout_failures_total` and recent create logs for
   `secret fanout` warnings.
2. Confirm recipients are alive (`GET /v1/cluster/members`) and share the
   credential encryption key / KMS access.
3. In enterprise mode, HA create success guarantees at least one backup ACK.
   Outside enterprise mode, treat `failover_ready=false` as "HA recreate is not
   safe yet" — wait or re-seal.
4. Remember D5: recipient sets are frozen at seal time; membership changes
   after create do not enlarge the set (see cluster-secrets docs).

The reconciler exposes `aerolvm_secret_delete_outbox_pending`,
`aerolvm_secret_delete_outbox_oldest_age_seconds`, and
`aerolvm_secret_tombstones`. Tombstones are pruned in bounded batches after
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
- Internal peer path (mTLS + PAT in enterprise mode):
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
