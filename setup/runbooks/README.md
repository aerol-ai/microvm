# sandboxd Operational Runbooks

These runbooks are the operator procedures for production clusters. They are
intended to be copied into the same place as the Grafana dashboard and
Prometheus alert rules by `Ansible/playbooks/configure-ops.yml`.

Use them during incidents and during scheduled drills:

| Runbook | Use when |
|---|---|
| [backup-restore.md](backup-restore.md) | You need to restore a node or prove backups are usable. |
| [lost-quorum-recovery.md](lost-quorum-recovery.md) | Raft has no leader because too many voter nodes are gone. |
| [image-pull-storm.md](image-pull-storm.md) | Image pulls are queued, failing, rate-limited, or suppressed by backoff. |
| [firecracker-template-health.md](firecracker-template-health.md) | Firecracker template push, pull, or rebuild metrics fire. |
| [slo-breach.md](slo-breach.md) | Any sandboxd SLO alert fires and the first response is not obvious. |

## Incident Roles

- **Incident commander:** owns decisions, declares severity, and timestamps
  actions.
- **Operator:** runs commands and changes cluster state.
- **Comms:** updates users and stakeholders.
- **Observer:** records metrics before, during, and after mitigation.

For small teams, one person may hold multiple roles, but the incident log still
needs a single commander and one timestamped command trail.

## Standard First Five Minutes

1. Identify the firing alert and affected cluster.
2. Open the Grafana dashboard and the current Prometheus alert page.
3. Capture `GET /v1/cluster/leader`, `GET /v1/cluster/members`, and
   `GET /v1/metrics` from one server, one worker, and one ingress node.
4. Stop deploys and topology changes until the incident commander clears them.
5. Pick the narrow runbook below and follow its verification steps before
   changing state.

## Standard Evidence Commands

```bash
export SB_PAT_TOKEN=<redacted>
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/members | jq .
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/metrics | tee /tmp/sandboxd.metrics
sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
  | grep -iE 'error|warn|raft|leader|capacity|image|pull|caddy|reconcile'
```

## Drill Cadence

Run these drills on a staging cluster at least monthly:

- Backup restore drill: restore the latest archive into a replacement node.
- Lost quorum tabletop: walk the decision tree without creating `peers.json`.
- Image pull storm drill: point one test workload at a deliberately missing
  image tag and verify backoff alerts.
- Firecracker template health drill: mark a test template `unhealthy` via the
  rebuild endpoint and confirm the rebuild path closes the gauge.
- SLO breach drill: force a create backlog with a bounded load test and verify
  alert, dashboard, and mitigation steps.

Record the result in the drill template included in each runbook.
