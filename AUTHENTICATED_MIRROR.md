# Authenticated Mirror & Auto-Import

This document is the operator reference for the AerolVM-side knobs that
route sandbox image pulls through the AOCR authenticated mirror and
optionally auto-import private upstream images into the cluster namespace
after first pull.

> Companion reading: `aocr.sh/MIRROR.md` (mirror server architecture),
> `aocr.sh/plans/cluster-mirror-and-snapshot-distribution.md` (full spec,
> phases F17-F21), and `pkg/docker/pull_mirror.go` (rewrite implementation).

## What this gives you

When `SB_MIRROR_HOST` is configured, sandboxd rewrites every public-registry
pull (`ghcr.io`, `gcr.io`, `quay.io`, `registry.k8s.io` by default) onto the
AOCR mirror vhost. Two things follow:

1. **Bytes are cached cluster-side.** Repeated pulls of the same image
   across the cluster hit the mirror's S3 backend, not the upstream — no
   rate limiting, no upstream outage exposure.
2. **Per-pull credentials never leave the node.** With `SB_UPSTREAM_WRAP_KEY_PATH`
   configured, sandboxd wraps the upstream PAT/password into an opaque
   `identitytoken` that only AOCR's mirror auth can unwrap. Docker daemons
   see the wrapped form on the wire; the mirror unwraps it server-side and
   uses the underlying credential to authenticate to the upstream.

When `SB_AUTO_IMPORT_ENABLED=true` is added on top, sandboxd asks AOCR to
re-mount the just-cached bytes under the cluster's own namespace
(`cluster/<id>/_imported/<host>/<repo>`) after each successful private
pull. Subsequent failovers pull from the cluster namespace with a cluster
PAT — fully decoupled from the original upstream credential, surviving
upstream password rotations that would otherwise break F17 wrap-creds.

Docker Hub (`docker.io`) is intentionally **not** rewritten — operators
should configure that on the daemon's `registry-mirrors` setting instead.

## Required vs optional

| Goal                                        | Required env vars                                                                                                  |
|---------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Mirror-cached public pulls                  | `SB_MIRROR_HOST`                                                                                                   |
| Mirror-cached **private** pulls (no leak)   | `SB_MIRROR_HOST` + `SB_UPSTREAM_WRAP_KEY_PATH`                                                                     |
| + Post-pull auto-import into cluster ns     | All of the above + `SB_AUTO_IMPORT_ENABLED=true` + `SB_AUTO_IMPORT_HOOKS_URL` + `SB_AUTO_IMPORT_CLUSTER_ID` + `SB_AUTO_IMPORT_CLUSTER_PAT_PATH` |

`SB_MIRROR_HOST` is the only piece that has to be in place for any of this
to function — everything else is additive.

## Environment variables

### Mirror rewrite

| Variable                     | Default                                                            | Purpose                                                                                                                                                |
|------------------------------|--------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SB_MIRROR_HOST`             | *(empty — disables rewrite)*                                       | Mirror vhost for cached pulls, e.g. `mirror.aocr.aerol.ai`. When empty, all upstream refs are passed through unchanged.                               |
| `SB_MIRROR_PUSH_HOST`        | *(empty)*                                                          | Push vhost for the same AOCR cluster (e.g. `aocr.aerol.ai`). Refs already pointing here are left alone so they are not double-rewritten.              |
| `SB_MIRROR_UPSTREAMS`        | `ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s`         | Comma-separated `host=shortname` map controlling which upstreams get rewritten and the short name used in the rewritten ref (`<mirrorHost>/aocr/<short>/...`). |
| `SB_UPSTREAM_WRAP_KEY_PATH`  | *(empty — soft-fail to raw creds)*                                 | Path to the base64-encoded 32-byte upstream wrap key. When unset, pulls are still rewritten but creds go to the mirror unwrapped (public images only). |

`SB_UPSTREAM_WRAP_KEY_PATH` is intentionally **soft-fail**: a missing key
logs a warning and rewriting continues. Anonymous pulls (public images)
still work; private upstreams will 401 at the mirror. This matches the
production rollout where the wrap key is templated in by Kubernetes after
the first deploy.

### Auto-import (F21)

| Variable                              | Default        | Purpose                                                                                                                                          |
|---------------------------------------|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `SB_AUTO_IMPORT_ENABLED`              | `false`        | Master switch. When false, the post-pull hook never fires and the reconciler never starts.                                                       |
| `SB_AUTO_IMPORT_HOOKS_URL`            | *(required)*   | AOCR hooks service root, no trailing slash, e.g. `https://aocr.aerol.ai`. The importer appends `/v1/internal/imports`.                          |
| `SB_AUTO_IMPORT_CLUSTER_ID`           | *(required)*   | Identifies this sandboxd cluster on the AOCR side. Goes into the import payload and scopes the cluster PAT.                                      |
| `SB_AUTO_IMPORT_CLUSTER_PAT_PATH`     | *(required)*   | Path to a file containing the cluster PAT bearer token. Sourced from file (not env) so it can be a Kubernetes Secret without escaping the value. |
| `SB_AUTO_IMPORT_RETENTION_SUFFIX`     | `--idle-90d`   | Suffix appended to the imported tag in the cluster namespace. Must start with `--`. Drives the reaper's idle-eviction window (see `RETENTION.md`). |
| `SB_AUTO_IMPORT_REQUEST_TIMEOUT`      | `15s`          | Per-call timeout for the ImportAPI POST. The mount-from-repo flow is normally sub-second; the timeout guards against an upstream layer-list hang.|
| `SB_AUTO_IMPORT_RECONCILE_INTERVAL`   | `5m`           | Ticker period for the local `auto_import_pending` reconciler. Must be > 0. Lower values increase Docker daemon load on recovery.                 |
| `SB_AUTO_IMPORT_MAX_IN_FLIGHT`        | `4`            | Bounded fan-out cap for one sweep. Keeps a recovery storm from saturating the local Docker daemon or AOCR.                                       |

If `SB_AUTO_IMPORT_ENABLED=true` is set without one of the three
required pieces (`HOOKS_URL`, `CLUSTER_ID`, `CLUSTER_PAT_PATH`),
sandboxd refuses to start with a config-validation error rather than
silently degrading.

## Operational notes

- **PAT file format.** `SB_AUTO_IMPORT_CLUSTER_PAT_PATH` is read once at
  startup. A trailing newline is tolerated (common when generating with
  `echo ... > pat`). Rotate by replacing the file and restarting sandboxd.
- **Wrap key format.** `SB_UPSTREAM_WRAP_KEY_PATH` must contain a
  base64-encoded 32-byte key. Rotate by deploying the new key alongside
  the old in the key ring (see `pkg/secrets/upstream_wrap.go`); sandboxd
  reads on startup so a rolling restart picks up new keys.
- **Reconciler is per-node, no leader election.** Each worker runs its
  own ticker against its local `auto_import_pending` rows. The reconciler
  is idempotent: a second successful import for an already-imported tag
  is a no-op (`AlreadyPresent=true`).
- **Spec write-back is best-effort.** A successful import flips the
  replicated `CreateSandboxRequest.ImageDistributionMode` to
  `aocr_imported` and rewrites `ImageRegistryRef` to point at the
  cluster-side ref. The write goes through the Raft leader; non-leader
  forwarding failures are logged and absorbed because the imported
  bytes are already in AOCR and future pulls of the original ref still
  resolve cleanly through the mirror.
- **Standalone (single-node) mode.** With no cluster, `cluster.Client.SpecOf`
  returns nil. The reconciler treats that as "drop the flag, nothing to
  retry" — recreate is already impossible without a replicated spec.

## Kubernetes example

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: sandboxd-mirror }
data:
  SB_MIRROR_HOST: "mirror.aocr.aerol.ai"
  SB_MIRROR_PUSH_HOST: "aocr.aerol.ai"
  SB_AUTO_IMPORT_ENABLED: "true"
  SB_AUTO_IMPORT_HOOKS_URL: "https://aocr.aerol.ai"
  SB_AUTO_IMPORT_CLUSTER_ID: "prod-us-east-1"
  SB_AUTO_IMPORT_CLUSTER_PAT_PATH: "/etc/aocr/cluster-pat"
  SB_UPSTREAM_WRAP_KEY_PATH: "/etc/aocr/upstream-wrap-key"
---
apiVersion: v1
kind: Secret
metadata: { name: sandboxd-aocr-secrets }
stringData:
  cluster-pat: "aocr_cluster_xxxxxxxxxxxxxxxxxxxxxxxx"
  upstream-wrap-key: "base64-32-bytes-here=="
```

Mount both files into the sandboxd Pod at the paths above and reference
the ConfigMap with `envFrom`. The Secret is the authoritative storage for
both tokens; the env vars are just file paths so rotation does not
restart-thrash the ConfigMap.

## Troubleshooting

| Symptom                                                      | Likely cause                                                                                                                     |
|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| All pulls work, mirror cache stays empty.                    | `SB_MIRROR_HOST` empty, or upstream not in `SB_MIRROR_UPSTREAMS`. Check sandboxd logs for `mirror not configured`.              |
| Private upstream pulls 401 at the mirror.                    | `SB_UPSTREAM_WRAP_KEY_PATH` missing or wrong format. Sandboxd logs a warning at startup; mirror logs the unwrap failure.        |
| `auto-import reconcile sweep failed: ...`                    | `auto_import_pending` rows piling up. Check `SB_AUTO_IMPORT_HOOKS_URL` reachability + cluster PAT validity at AOCR `/v1/internal/imports`. |
| Reconciler logs `drop pending flag: no spec`.                | The sandbox row was flagged but no replicated spec exists (standalone mode, or pre-cluster sandbox). Expected; not an error.    |
| Spec still shows `external_registry` after import succeeded. | Spec write-back hit a non-leader/Raft error. Bytes are imported and pullable; the spec refreshes on the next mutation.          |
