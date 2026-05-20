# Runbook: Image-Pull Storm

Use this when image pulls are queued, failing, rate-limited, or repeatedly
suppressed by the per-image failure backoff.

## Alerts

- `SandboxdImagePullQueueBacklog`
- `SandboxdImagePullBackoffRejects`
- `SandboxdImagePullErrors`
- create queue alerts that coincide with image-pull metrics

## Severity

| Severity | Criteria |
|---|---|
| SEV-1 | Most creates fail or the registry is unavailable for production workloads. |
| SEV-2 | A subset of images or tenants is failing, but other creates succeed. |
| SEV-3 | Backoff is working and impact is limited to a test or bad image tag. |

## First Checks

Run on affected workers:

```bash
export SB_PAT_TOKEN=<redacted>
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_image_pull|aerolvm_create_queue|aerolvm_create_errors'
sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
  | grep -iE 'pull image|images/create|manifest|unauthorized|too many requests|rate'
```

Classify the failure:

| Signal | Likely cause |
|---|---|
| `aerolvm_image_pull_queued > 0` | many distinct cold images or slow registry |
| backoff rejects increasing | same image/auth key keeps failing |
| error reason `not_found` | bad tag, deleted image, local-only image on wrong node |
| error reason `auth` | registry credentials invalid or secret decrypt failure |
| error reason `rate_limited` | registry throttling |
| create queue rising too | user-visible create latency/failure |

## Containment

Pick the smallest action that stops amplification:

1. Pause or rate-limit the caller issuing bad creates.
2. If a tag is bad, reject that request path in the caller or control plane.
3. If registry rate-limited, reduce create fan-in and pre-pull hot images.
4. If credentials are failing, stop private-image creates until the credential
   key or registry secret is fixed.
5. If only one worker is overloaded, drain it from new placement:

   ```bash
   curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/cluster/nodes/<node-id>/drain
   ```

Do not raise `SB_IMAGE_PULL_MAX_CONCURRENT` during registry rate limiting.
That increases pressure. Raise it only when the registry is healthy and the
worker has idle network/disk capacity.

## Mitigation by Cause

### Bad or Missing Image Tag

1. Confirm the image reference from logs.
2. Ask the caller to fix the tag or roll back the release.
3. Wait for `SB_IMAGE_PULL_FAILURE_BACKOFF` to expire or restart sandboxd only
   if the incident commander accepts the retry surge risk.

### Registry Authentication Failure

1. Check secret decrypt metrics:

   ```bash
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/metrics \
     | grep -E 'aerolvm_secret_decrypt_errors_total|aerolvm_secret_key_version_mismatches_total'
   ```

2. Verify `/var/lib/sandboxd/credential_encryption.key` matches across nodes.
3. Rotate or re-store registry credentials.
4. Retry one sandbox create before unpausing the caller.

### Registry Rate Limit or Outage

1. Reduce create concurrency at the caller.
2. Pre-pull the affected image on workers if registry policy permits:

   ```bash
   sudo docker pull <image>
   ```

3. Consider temporarily lowering:

   ```bash
   SB_IMAGE_PULL_MAX_CONCURRENT=1
   SB_IMAGE_PULL_FAILURE_BACKOFF=2m
   ```

   Apply through Ansible:

   ```bash
   ansible-playbook Ansible/playbooks/configure-ops.yml \
     -e sandboxd_image_pull_max_concurrent=1 \
     -e sandboxd_image_pull_failure_backoff=2m
   ```

4. Restore defaults after error rate is stable for 30 minutes.

### Worker Disk or Network Saturation

1. Check host pressure and Docker disk:

   ```bash
   df -h
   sudo docker system df
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/metrics \
     | grep -E 'aerolvm_host_pressure|aerolvm_image_pull'
   ```

2. Drain the worker if it cannot recover quickly.
3. Run image GC only if the incident commander accepts cache misses after GC.

## Recovery Verification

The incident is mitigated when all are true for at least 15 minutes:

- `sum(aerolvm_image_pull_queued) == 0`
- `rate(aerolvm_image_pull_errors_total[5m])` is near zero
- `rate(aerolvm_image_pull_backoff_rejects_total[5m])` is zero
- create queue depth returns to normal
- a known-good create succeeds

## Rollback

If you changed pull knobs through Ansible, restore defaults:

```bash
ansible-playbook Ansible/playbooks/configure-ops.yml \
  -e sandboxd_image_pull_max_concurrent=4 \
  -e sandboxd_image_pull_failure_backoff=30s
```

If you drained workers, uncordon one at a time:

```bash
curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/nodes/<node-id>/uncordon
```

## Image-Pull Storm Drill

Use a staging cluster.

| Field | Value |
|---|---|
| Date | |
| Operator | |
| Test image | |
| Expected failure reason | |
| Alert fired | yes/no |
| Backoff observed | yes/no |
| Queue returned to zero | yes/no |
| Create path recovered | yes/no |
| Follow-up fixes | |
