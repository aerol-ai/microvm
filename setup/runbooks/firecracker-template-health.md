# Runbook: Firecracker Template Health

Use this when Firecracker template push, pull, or rebuild metrics fire. The
template pipeline has three stages and they fail in distinct ways:

1. **Build** — `ImportTemplate` produces `rootfs.ext4`, boots a one-shot VMM,
   and snapshots memory + device state. Failures here flip the row to
   `failed` (terminal) or `ready_no_snapshot` (rootfs ok, snapshot didn't).
2. **Push** — `TemplateArtifactPusher` ships the artifact bundle to AOCR for
   peer nodes to fetch. Failures move `push_state` from `pending` → `error`.
3. **Pull** — peer nodes call `EnsureTemplateLocal` on first create against
   a template they don't have on disk; the puller fetches and extracts.

Snapshot corruption observed on the boot path flips the row to `unhealthy`
and the rebuild path (`RebuildTemplateSnapshot`) re-runs stage 1's snapshot
substep in the background.

## Alerts

- `SandboxdFirecrackerTemplateUnhealthy`
- `SandboxdFirecrackerTemplateRebuildErrors`
- `SandboxdFirecrackerTemplatePushStalled`
- `SandboxdFirecrackerTemplatePushErrored`
- `SandboxdFirecrackerTemplatePullErrors`

## Severity

| Severity | Criteria |
|---|---|
| SEV-1 | Most Firecracker creates fail because templates are unhealthy or pull is broken. |
| SEV-2 | A subset of templates is stuck; healthy templates still serve creates. |
| SEV-3 | Push lag or a single rebuild failure; no create-path impact yet. |

## First Checks

Run on one worker:

```bash
export SB_PAT_TOKEN=<redacted>
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics \
  | grep -E 'aerolvm_template_'
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/templates | jq '.templates[] | {id,status,push_state,registry_ref}'
sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
  | grep -iE 'template|rebuild|snapshot|firecracker'
```

Classify by which metric is moving:

| Signal | Stage | Likely cause |
|---|---|---|
| `aerolvm_template_unhealthy > 0` and not draining | rebuild | VMM boot fails, CID exhausted, kernel mismatch |
| `rate(aerolvm_template_rebuild_failed_total[10m]) > 0` | rebuild | snapshotter error, disk full, broken rootfs |
| `aerolvm_template_push_pending > 0` for 30m | push | reconciler wedged or AOCR unreachable |
| `aerolvm_template_push_error > 0` | push | structural failure (auth, network, oversize artifact) |
| `rate(aerolvm_template_pull_failed_total[5m]) > 0` | pull | peer fetch failing on consumer worker; sandbox creates blocking |

## Containment

Pick the smallest action that stops amplification:

1. If a single bad template is fanning out failures, pause creates that
   reference it in the caller / control plane.
2. If pull is broken on one worker only, drain that worker from new
   placement so the template-aware gate stops sending Firecracker creates
   there:

   ```bash
   curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/cluster/nodes/<node-id>/drain
   ```

3. If push is the only failing stage, do not touch creates — push only
   affects new nodes joining or recovering. Buy time, then mitigate.

## Mitigation by Cause

### Unhealthy Templates Not Draining

The startup scanner re-kicks rebuilds for every `unhealthy` row on daemon
start, and `MarkSnapshotCorrupt` kicks an in-process rebuild on first
observer. If the count is stuck:

1. Find which template is stuck:

   ```bash
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/templates \
     | jq '.templates[] | select(.status=="unhealthy") | {id,image,last_rebuild_error}'
   ```

2. Force a rebuild from the operator surface (idempotent, CAS-gated):

   ```bash
   curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/templates/<id>/rebuild
   ```

   A `412 Precondition Failed` means the row is in a state that's not
   safely rebuildable (`pending`, `building_rootfs`, `snapshotting`,
   `ready_no_snapshot`, or `failed`). For `ready_no_snapshot` and `failed`
   the only path forward today is to delete the template and re-register.

3. If the rebuild keeps failing, check VMM logs and CID allocator:

   ```bash
   sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
     | grep -iE 'firecracker|cid|snapshot.*fail'
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/metrics \
     | grep -E 'aerolvm_vmm_|aerolvm_cid_'
   ```

### Push Stalled (pending climbing, error flat)

1. Confirm the reconciler is ticking:

   ```bash
   sudo journalctl -u sandboxd --since "15 minutes ago" --no-pager \
     | grep -iE 'template_push|TemplateArtifactPusher'
   ```

2. If silent, check AOCR reachability from this worker (registry credential
   check uses the same path as the image-pull side; see
   [image-pull-storm.md](image-pull-storm.md)).

3. If reachable but slow, lower fan-out before raising it. Raising fan-out
   during a stall amplifies the problem.

### Push Errored (rows in push_state=error)

1. Identify the failing rows:

   ```bash
   curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
     http://127.0.0.1:21212/v1/templates \
     | jq '.templates[] | select(.push_state=="error") | {id,push_error}'
   ```

2. Classify by `push_error` text:
   - `unauthorized` / `denied` → registry credentials; rotate and retry.
   - `payload too large` / artifact size → snapshot is oversized; expected
     after a memory bump, not after a code change.
   - network / timeout → transient; reconciler retries on its own.

3. Rows in `push_state=error` are picked up by the next reconciler tick — no
   manual kick needed unless the underlying cause is fixed and you want
   immediate retry.

### Pull Errors (peer-side fetch failing)

This is the only stage that blocks the boot path. A Firecracker create on a
worker without local artifacts calls `EnsureTemplateLocal` and waits.

1. Identify failing pulls:

   ```bash
   sudo journalctl -u sandboxd --since "15 minutes ago" --no-pager \
     | grep -iE 'template_pull|EnsureTemplateLocal'
   ```

2. Classify:
   - registry auth / network → same as push-side; fix the credential or
     network and the next first-create retries.
   - schema-version refused → the producer is on a newer template format;
     upgrade this worker.
   - checksum mismatch → bit-rot in AOCR or in transit; rebuild the
     template on the producer side.
   - extraction failed mid-way → the puller cleans up the `.partial`
     directory and the next call retries cleanly; disk pressure usually.

3. If a single template is broken cluster-wide, pause creates that
   reference it.

## Recovery Verification

The incident is mitigated when all are true for at least 15 minutes:

- `sum(aerolvm_template_unhealthy) == 0`
- `rate(aerolvm_template_rebuild_failed_total[10m])` is near zero
- `sum(aerolvm_template_push_pending)` returns to its baseline (usually 0)
- `sum(aerolvm_template_push_error) == 0`
- `rate(aerolvm_template_pull_failed_total[5m])` is zero
- a known-good Firecracker create succeeds end-to-end

## Rollback

These changes are usually mitigations, not configuration. If you drained
workers, uncordon them one at a time once pull errors stop:

```bash
curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/nodes/<node-id>/uncordon
```

If you disabled the rotation reconciler during mitigation, restore it
through Ansible once the cluster is stable:

```bash
ansible-playbook Ansible/playbooks/configure-ops.yml \
  -e sandboxd_firecracker_template_rotation_interval=24h \
  -e sandboxd_firecracker_template_max_age=720h
```

## Template Health Drill

Use a staging cluster.

| Field | Value |
|---|---|
| Date | |
| Operator | |
| Test template | |
| Failure injected (snapshot corruption / push break / pull break) | |
| Alert fired | yes/no |
| Operator rebuild succeeded | yes/no |
| Unhealthy gauge returned to zero | yes/no |
| Create path recovered | yes/no |
| Follow-up fixes | |
