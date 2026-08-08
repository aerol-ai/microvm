# Runbook: Secrets and Audit

Use this when secret-audit or secret-fan-out alerts fire, or when investigating
credential open failures and `failover_ready` staying false.

## Honesty boundary (read first)

On the open-source build:

- The local JSONL audit log (`{Dir(DBPath)}/audit/secrets.jsonl`) is
  authoritative per node.
- **There is no dead-disk durability claim.** Losing a node's disk loses that
  node's audit history permanently.
- Cluster fan-out on `GET /v1/sandboxes/{id}/audit` is a **discovery**
  mechanism (find records whose location is untracked). It is **not** a
  durability mechanism and cannot recover records that no longer exist.
- Coverage in the API response names which members answered; `partial: true`
  means the page is incomplete — never treat a partial page as full history.

See also the D5 frozen-recipient limitation in
[`docs/.../cluster-secrets.mdx`](../../docs/src/content/docs/cluster-secrets.mdx).

## Alerts

| Alert | Meaning | First action |
|---|---|---|
| `SandboxdAuditEventsDropped` | Audit buffer overflowed; gap markers were written | Check disk / audit I/O latency; inspect JSONL for `result=gap` |
| `SandboxdSecretFanoutFailures` | Async sealed-blob peer push/delete failed | Check peer health, PAT, and `failover_ready` on recent HA creates |
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

3. Mitigate: free disk, reduce decrypt storms, restart only after capturing the
   current JSONL for evidence.

Retention: `SB_SECRET_AUDIT_RETENTION_DAYS` (default 30) prunes old lines daily.

## Fan-out failures / `failover_ready` false

1. Check `aerolvm_secret_fanout_failures_total` and recent create logs for
   `secret fanout` warnings.
2. Confirm recipients are alive (`GET /v1/cluster/members`) and share the
   credential encryption key / KMS access.
3. Treat `failover_ready=false` as "HA recreate is not safe yet" — wait or
   re-seal; do not assume create success implies peer copies exist.
4. Remember D5: recipient sets are frozen at seal time; membership changes
   after create do not enlarge the set (see cluster-secrets docs).

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
- Internal peer path (PAT): `GET /v1/cluster/internal/sandboxes/{id}/audit`
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
