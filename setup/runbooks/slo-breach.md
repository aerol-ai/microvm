# Runbook: SLO Breach

Use this for any sandboxd SLO alert that does not have a more specific active
incident runbook. Start here, then branch to backup/restore, lost quorum, or
image-pull storm if the signals point there.

## SLO Surfaces

| Area | Primary signals |
|---|---|
| Control plane | Raft apply errors, in-flight applies, leader visibility |
| Scheduler | worker lease age/loss, no-admit workers, capacity pressure |
| Create path | queue depth, create errors, create latency buckets |
| Ingress | route lag, reconcile errors, Caddy admin errors |
| Data plane | owner-forward errors, route misses |
| Image pulls | queued pulls, pull errors, backoff rejects |
| Secrets | decrypt errors, key version mismatches |

## First Five Minutes

1. Freeze deploys and topology changes.
2. Identify alert group and affected cluster.
3. Open Grafana dashboard `sandboxd SLOs`.
4. Capture evidence:

   ```bash
   export SB_PAT_TOKEN=<redacted>
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/cluster/leader | jq .
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/cluster/members | jq .
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/metrics > /tmp/sandboxd.metrics
   ```

5. Decide the branch:
   - no leader: [lost-quorum-recovery.md](lost-quorum-recovery.md)
   - image pull metrics high: [image-pull-storm.md](image-pull-storm.md)
   - restore needed: [backup-restore.md](backup-restore.md)
   - otherwise continue below.

## Triage Matrix

| Alert | First action | Escalate when |
|---|---|---|
| `SandboxdRaftApplyErrors` | Inspect leader logs and recent deploys. | any create/expose writes fail. |
| `SandboxdRaftApplyStuck` | Stop new deploys; inspect leader CPU/disk/network. | in-flight apply remains > 5 minutes. |
| `SandboxdWorkerLeaseStale` | Check worker health and mTLS/gossip connectivity. | stale age keeps rising or all workers stale. |
| `SandboxdNoAdmitWorkers` | Check capacity, disk, and drains. | all creates fail or no workers can uncordon. |
| `SandboxdCreateQueueBacklog` | Determine if backlog is image, capacity, or Raft bound. | queue grows for > 10 minutes. |
| `SandboxdIngressRouteLag` | Check Caddy admin errors and ingress CPU. | route lag increases while creates continue. |
| `SandboxdCaddyAdminErrors` | Check Caddy service and admin endpoint. | public URLs fail or route lag grows. |
| `SandboxdOwnerForwardErrors` | Check owner node health and advertise URLs. | many sandboxes fail cross-node operations. |
| `SandboxdSecretDecryptErrors` | Check credential encryption key consistency. | failover/recreate workloads cannot start. |

## Control Plane Checks

```bash
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_raft_apply|aerolvm_raft_snapshot|aerolvm_gossip'
sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
  | grep -iE 'raft|leader|apply|snapshot|election|error'
```

Mitigation:

- If leader exists and apply errors correlate with one bad request type, stop
  that caller.
- If no leader exists, move to lost-quorum recovery.
- If snapshot errors correlate with disk full, free disk or move the node out
  of service.

## Scheduler and Capacity Checks

```bash
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/members | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_worker_lease|aerolvm_host_pressure|aerolvm_scheduler'
```

Mitigation:

- Uncordon accidentally drained workers.
- Add workers if capacity pressure is real and sustained.
- Drain workers with stale leases only if they are flapping and causing
  placement retries.
- Do not manually create sandboxes on server/ingress-only nodes.

## Create Path Checks

```bash
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_create_|aerolvm_image_pull_|aerolvm_host_pressure'
```

Mitigation:

- If image-pull signals are high, use image-pull storm runbook.
- If capacity reject reasons dominate, scale workers or reduce requested
  resources.
- If reservation conflicts dominate, check for duplicate idempotency keys or
  client retry behavior.

## Ingress and Data Plane Checks

```bash
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_ingress|aerolvm_caddy|aerolvm_owner_forward'
sudo systemctl status caddy --no-pager || true
sudo journalctl -u caddy --since "30 minutes ago" --no-pager || true
```

Mitigation:

- Restart Caddy only if admin calls fail and the route table is not actively
  converging.
- Reduce create/expose churn if route lag grows faster than it drains.
- Check `SB_DATA_PLANE_ADVERTISE_HOST` and `SB_CLUSTER_INTERNAL_ADVERTISE`
  when owner-forward errors or route misses appear after topology changes.

## Secret Failure Checks

```bash
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_secret_decrypt|aerolvm_secret_key_version'
sudo sha256sum /var/lib/sandboxd/credential_encryption.key
```

Mitigation:

- If key hashes differ across nodes, stop failover/recreate work and restore
  the intended cluster-wide key.
- Re-run `configure-ops.yml` only after key consistency is fixed; it does not
  rotate credential keys.

## Recovery Criteria

Declare the SLO breach recovered only after all relevant conditions are true:

- all critical alerts resolved for 15 minutes
- create queue depth back to normal
- worker lease age fresh
- route lag drains to normal
- no new Raft apply errors
- one known-good create/expose/delete smoke test succeeds

Smoke test:

```bash
# Replace with your normal SDK or API smoke create.
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/health | jq .
```

## Post-Incident

Within 24 hours:

1. Attach `/tmp/sandboxd.metrics` samples and relevant journal excerpts.
2. Record the first alert, first user impact, mitigation time, and recovery
   time.
3. Tune alert thresholds if they were noisy or late.
4. Add a staging drill if the response required improvisation.

## SLO Drill

| Field | Value |
|---|---|
| Date | |
| Alert tested | |
| Trigger method | |
| Alert fired within expected time | yes/no |
| Dashboard showed signal | yes/no |
| Runbook branch was clear | yes/no |
| Smoke test passed after mitigation | yes/no |
| Alert resolved automatically | yes/no |
| Follow-up fixes | |
