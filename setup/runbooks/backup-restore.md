# Runbook: Backup and Restore

Use this when you need to prove backups are usable, restore a failed node, or
recover from accidental local state loss. This runbook covers the local
sandboxd backup archive produced by `sandboxd-backup.sh`.

## Severity

| Severity | Criteria |
|---|---|
| SEV-1 | Multiple worker/server nodes lost data, or restore is required to regain quorum. |
| SEV-2 | One production node lost local state but quorum and ingress still work. |
| SEV-3 | Scheduled restore drill or non-production restore. |

## Safety Rules

- Do not restore over a running `sandboxd`.
- Do not restore a backup from a different cluster unless you intentionally
  want that cluster identity, PAT, TLS, Raft state, and credential key.
- Do not reuse a Raft data directory with a different `SB_NODE_ID`.
- Keep the original failed disk attached or snapshotted until verification is
  complete.

## What the Backup Contains

The helper includes:

- `/var/lib/sandboxd/state.db`
- `/var/lib/sandboxd/raft/`
- `/etc/sandboxd/`
- a manifest with host, source path, and creation time

The archive does **not** contain Docker image layers, running containers, or
external mounted storage. Recovered sandboxes must still be recreated from
pullable images and valid credentials.

## Pre-Restore Checklist

1. Confirm the target cluster and node identity.
2. Find the newest backup archive for the node.
3. Confirm the archive is readable:

   ```bash
   tar -tzf /secure/backups/sandboxd-node-a-YYYY-MM-DD.tar.gz | head
   tar -xOzf /secure/backups/sandboxd-node-a-YYYY-MM-DD.tar.gz ./MANIFEST.txt
   ```

4. Confirm the replacement node is not running sandboxd:

   ```bash
   sudo systemctl is-active sandboxd || true
   sudo systemctl stop sandboxd
   ```

5. Snapshot or copy any existing data on the replacement node:

   ```bash
   sudo tar -C / -czf /root/pre-restore-sandboxd-$(date +%F-%H%M%S).tar.gz \
     etc/sandboxd var/lib/sandboxd || true
   ```

## Restore Procedure

1. Copy the backup archive to the replacement node.

2. Stop sandboxd:

   ```bash
   sudo systemctl stop sandboxd
   ```

3. Restore the archive:

   ```bash
   sudo /usr/local/sbin/sandboxd-restore.sh \
     --input /secure/backups/sandboxd-node-a-YYYY-MM-DD.tar.gz \
     --target-root / \
     --force
   ```

4. Verify expected files:

   ```bash
   sudo test -f /etc/sandboxd/sandboxd.env
   sudo test -f /var/lib/sandboxd/state.db
   sudo test -d /var/lib/sandboxd/raft
   sudo grep -E 'SB_NODE_ID|SB_NODE_ROLE|SB_ENABLE_CLUSTER' /etc/sandboxd/cluster.env
   ```

5. Start sandboxd:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start sandboxd
   ```

## Verification

Run from the restored node:

```bash
export SB_PAT_TOKEN=<redacted>
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/health | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/members | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_raft|aerolvm_worker|aerolvm_create' | head
```

Expected:

- `/health` is 200.
- A leader exists unless this was a lost-quorum restore.
- The restored node appears with the expected `node_id` and role.
- `aerolvm_secret_decrypt_errors_total` is not increasing.
- `aerolvm_worker_lease_max_age_nanos` returns to a fresh value on workers.

## If This Restore Is Also a Lost-Quorum Recovery

Do not start every survivor. Follow
[lost-quorum-recovery.md](lost-quorum-recovery.md) after restoring the chosen
survivor or replacement node.

## Rollback

If verification fails:

1. Stop sandboxd.
2. Preserve logs and current restored data:

   ```bash
   sudo journalctl -u sandboxd --since "1 hour ago" --no-pager > /root/sandboxd-restore-failed.log
   sudo tar -C / -czf /root/failed-restore-state-$(date +%F-%H%M%S).tar.gz \
     etc/sandboxd var/lib/sandboxd || true
   ```

3. Restore the pre-restore archive made in the checklist.
4. Escalate before attempting a different backup.

## Restore Drill

Use a staging node or disposable replacement instance.

| Field | Value |
|---|---|
| Date | |
| Operator | |
| Source backup | |
| Target node | |
| Restore start/end | |
| Health passed | yes/no |
| Leader visible | yes/no |
| Members correct | yes/no |
| Secret decrypt errors stable | yes/no |
| Follow-up fixes | |
