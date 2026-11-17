# Runbook: Image-Pull Storm

Use this when image pulls are queued, failing, rate-limited, or repeatedly
suppressed by the per-image failure backoff.

## Alerts

- `SandboxdImagePullQueueBacklog`
- `SandboxdImagePullBackoffRejects`
- `SandboxdImagePullErrors`
- create queue alerts that coincide with image-pull metrics

On Kubernetes the chart's `monitoring.prometheusRule` does not ship these
alerts (it ships the `AerolVM*` set in `charts/aerolvm/monitoring/rules.yaml`).
Load `setup/prometheus/sandboxd-alerts.yml` as a PrometheusRule of your own,
labelled for your Prometheus (the issue #1343 drill did; see
`integration-tests/k8s/drills-local.sh`, step `setup`).

The image-pull metrics count both engines' pulls. Before the fix for issue
#1343, the containerd engine (every Kubernetes worker, and the default on
VMs) reported none of them, so these three alerts could not fire there.

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
  | grep -iE 'pull image|image pull|images/create|resolve reference|manifest|backing off|awaiting response headers|unauthorized|too many requests|rate'
```

On Kubernetes, read the same numbers per worker pod in Prometheus, and the
log of the worker's `agent` container:

```text
sum by (pod) (aerolvm_image_pull_queued)
sum by (pod) (aerolvm_image_pull_inflight)
sum by (pod, key) (rate(aerolvm_image_pull_errors_total[5m]))
sum by (pod) (rate(aerolvm_image_pull_backoff_rejects_total[5m]))
sum by (pod) (aerolvm_create_queue_depth)
```

```bash
kubectl -n aerolvm-workers logs <worker-pod> -c agent --since=30m \
  | grep -iE 'image pull|resolve reference|backing off|awaiting response headers|unauthorized|too many requests'
```

The containerd engine words its failures differently from dockerd:
`failed to resolve reference ...: 429 Too Many Requests` and `... timeout
awaiting response headers`. On both engines each create the backoff
refuses logs `image pull for "<image>" backing off after recent failure:
<cause>`.

Classify the failure:

| Signal | Likely cause |
|---|---|
| `aerolvm_image_pull_queued > 0` | more distinct cold images on one worker than `SB_IMAGE_PULL_MAX_CONCURRENT` (4), each pulling slowly. Creates of one image never queue: a worker pulls it once and the others wait on that pull (`aerolvm_image_pull_dedup_waiters_total` rises) |
| backoff rejects increasing | same image/auth key keeps failing |
| error reason `timeout` | the registry sent no response headers within 30 s (containerd gives up then), or a pull outlasted the create (`SB_CREATE_TIMEOUT_SEC`, 600 s) |
| creates of a failing image take minutes to fail | its pull waits for a slot behind other images' slow pulls: the cap is per worker, shared by every image. In the issue #1343 drill a rate-limited image's creates waited about 260 s for a slot, then all failed on the one 429 |
| error reason `not_found` | bad tag, deleted image, local-only image on wrong node |
| error reason `auth` | registry credentials invalid or secret decrypt failure |
| error reason `rate_limited` | registry throttling |
| error reason `unavailable` | the registry answered 5xx, or refused or reset the connection |
| create queue rising too | user-visible create latency/failure |

What callers see: a create whose pull was rate-limited, timed out, met a
registry error, or was refused by the backoff after one of those answers
`503` with the code `image_pull_unavailable`; the SDKs retry it.
`Retry-After` is the worker's backoff (`SB_IMAGE_PULL_FAILURE_BACKOFF`,
30 s by default), or for a backoff refusal what is left of it. A missing
image, refused credentials or another failure that will not pass by itself
(no manifest for the worker's platform) answer `400`, and so does every
create the backoff refuses after one. (Before the issue #1343 fixes every
one of these was a `400`, which SDKs do not retry.)

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

   On Kubernetes, use `aerolvm cordon <node>` (the worker's AerolNode name).
   It sets the same drain mark: no new sandboxes land on the worker, and
   the ones it runs keep running. Run `aerolvm uncordon <node>` once the
   storm is over. Do not `kubectl cordon` its machine: that starts a full
   decommission, which moves every sandbox and adds pulls on the other
   workers in the middle of the storm. Do not delete the worker pod.

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

   That is for the dockerd engine only. With containerd, and on Kubernetes,
   there is no node-side pull: once the registry answers again, the first
   create of the image on a worker pulls it for every later create there,
   and creates that arrive meanwhile wait on that one pull. Resume the
   callers slowly rather than pre-pulling.

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

   On Kubernetes they are worker settings in the chart's `worker.extraEnv`
   (`helm upgrade --reuse-values --set-string
   worker.extraEnv.SB_IMAGE_PULL_FAILURE_BACKOFF=2m`), and a worker pod
   takes them only when it is made. In cluster mode the operator reads the
   pod template only when it makes a pod, and an upgrade swaps only the
   agent's image, so running workers keep the old values; only new worker
   pods get the new ones, and a new worker starts with no image cached,
   which adds pulls in a storm. In single mode the pod changes only when
   it is deleted, which ends every sandbox. So in a storm, change them only
   if new workers are coming anyway. The issue #1343 drill did not need to
   change them.

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

A create of the image that was failing succeeds as soon as the registry
answers and that worker's backoff (`SB_IMAGE_PULL_FAILURE_BACKOFF`, 30 s)
has run out; the error and backoff rates take their 5-minute window to
reach zero, and the alerts resolve then.

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
