# AOCR Integration: Snapshot Push + Cross-Node Image Pull

> Supersedes the earlier draft of this file, which assumed AOCR had a
> pull-through cache feature. After reading
> `/Users/sumansaurabh/Documents/startup-3/aocr.sh/` (README, understanding.md,
> RETENTION.md, registry/config.yml), the correct picture is:
>
> - AOCR is **Docker Distribution v2** + Postgres metadata + Node.js hooks +
>   token auth (no proxy mode is configured today).
> - Storage backend is **S3-compatible** (MinIO in dev).
> - Retention is encoded **in the tag name** as `--ttl-7d`, `--idle-30d`, etc.
>   Plain tags are kept-latest-only.
> - Namespace shape is `<host>/<org>/<image>:<tag>` (e.g. `aocr.aerol.ai/aocr/my-image:main`).
> - Auth is token-based via the auth service's `/v2/token` realm; the Docker
>   login uses a PAT-style token as password.
>
> This plan integrates that AOCR into AerolVM. DockerHub pull-through caching
> is intentionally **out of scope** here — Distribution proxy mode is push-
> incompatible (a registry in proxy mode is read-only), so the two features
> can't live in one AOCR instance. That work, if pursued, is a separate plan
> involving either a second proxy-mode Distribution instance or an AOCR
> feature addition.

## Context

Today in AerolVM:

- `Service.CreateSnapshotWithOwnership` (`internal/service/service.go:969`)
  calls `docker.CreateSnapshot` which does `POST /commit` → produces a local
  image tag.
- The snapshot row is forced to `ImageDistributionLocalOnly` via
  `normalizeSnapshotImageDistribution(ctx, snapshot, true)`
  (`service.go:1004`).
- `ImageRequiresLocalPlacement` (`image_distribution.go:140`) then pins any
  sandbox using that snapshot to the originating node.
- `failover.policy="recreate"` is rejected for local-only images
  (`service.go:2510`).
- The cluster placement path (`cluster/owner_watcher.go:153`,
  `cluster/dead_owner.go:284`) short-circuits cross-node recreation when the
  image is local-only.

Concretely: a snapshot taken on node-1 is invisible to node-2. The whole
cluster's snapshot mobility story is currently "you can't."

The fix is to push the snapshot to AOCR on commit, rewrite the stored image
reference to the AOCR-qualified form, flip distribution mode from
`local_only` to `aocr`, and let every other node pull it via the same
`RegistryAuth`-bearing `pullImage` path that already exists.

## Goal

After this change, when a user does:

```ts
await client.createSnapshot(sandboxId, { name: 'redis-with-data' });
// ... later, possibly on a different node ...
await client.create({ image: 'redis-with-data', ... });
```

The sequence is:

1. **First call** (on node-1):
   - `docker commit` produces a local image (existing behavior).
   - sandboxd tags it as `<aocr_host>/<cluster_org>/redis-with-data:<rev>--idle-30d`
     and `docker push`es it to AOCR using cluster-wide AOCR credentials.
   - Snapshot row stores `Image = <aocr_host>/<cluster_org>/redis-with-data:<rev>--idle-30d`
     and `ImageDistributionMode = "aocr"`.
2. **Second call** (placement lands on node-2):
   - `NormalizeCreateImageDistribution` already resolves snapshot-name aliases
     to the stored image ref (`image_distribution.go:65`). It now resolves
     to the AOCR-qualified ref.
   - `pullImage` on node-2 hits the AOCR endpoint with the cluster's
     AOCR credentials → image streams from AOCR's S3 backend → sandbox starts.
3. **Failover unlocked**: `failover.policy="recreate"` now works for
   snapshots because `ImageRequiresLocalPlacement` returns false.
4. **AOCR's reaper handles cleanup**: the `--idle-30d` suffix means snapshots
   not pulled in 30 days are evicted automatically. No new sandboxd-side GC.

## Non-goals (this plan)

- **DockerHub / public-registry pull-through caching.** That problem is
  real but architecturally separate. AOCR's Distribution backend cannot
  simultaneously accept pushes and proxy upstreams. If we want it, options
  are: (a) stand up a second Distribution instance in `proxy:` mode behind
  `aocr-mirror.aerol.ai`, (b) put Spegel on each node, (c) extend AOCR with
  a custom proxy handler. All belong in a follow-up plan.
- **Per-tenant AOCR credentials.** v1 uses one cluster-wide AOCR identity
  for snapshot push/pull. Per-user push-as-the-user is a real multi-tenant
  story (matches the hosted aocr.aerol.ai model) but expands scope
  significantly — defer.
- **Snapshot-name → tag uniqueness across clusters.** Each cluster gets its
  own AOCR namespace prefix (`<cluster_org>`) so two clusters can both have
  a snapshot called `redis-with-data` without colliding.

## Architecture

```
   ┌─────────────────────────────────────┐
   │            AOCR (Distribution v2)   │
   │   ┌──────────────────────────────┐  │
   │   │  /v2/<org>/<image>/manifests │  │
   │   │  /v2/<org>/<image>/blobs     │──┼──> S3 / MinIO
   │   └──────────────────────────────┘  │
   │   ┌──────────────────────────────┐  │
   │   │ Postgres: users/repos/tags   │  │   (cluster identity = one
   │   │ + retention metadata         │  │    AOCR user/PAT, scoped to
   │   └──────────────────────────────┘  │    org=<cluster_org>)
   │   ┌──────────────────────────────┐  │
   │   │ Reaper                       │  │
   │   │  - keep-latest plain tags    │  │
   │   │  - --ttl-* age TTL           │  │
   │   │  - --idle-* idle TTL  ◄──────┼──┼── snapshots use --idle-30d
   │   └──────────────────────────────┘  │
   └──────────────────┬──────────────────┘
                      │ HTTPS push/pull
                      │ X-Registry-Auth: <cluster PAT>
                      │
      ┌───────────────┼───────────────┐
      ▼               ▼               ▼
   ┌──────┐       ┌──────┐         ┌──────┐
   │node-1│       │node-2│   ...   │node-N│
   │      │       │      │         │      │
   │CreateSnap   │ pull snap        │
   │ → push to AOCR  │  on demand   │
   └──────┘       └──────┘         └──────┘
```

## Tag scheme

AOCR's namespace is `<host>/<org>/<image>:<tag>`. The proposed mapping:

- **host**: configurable via `SB_IMAGE_DISTRIBUTION_AOCR_HOST`
  (already exists, default `aocr.aerol.ai`).
- **org**: configurable via new `SB_AOCR_ORG`. Defaults to the cluster name
  if `SB_CLUSTER_NAME` is set, else `default`. Lets multiple clusters share
  one AOCR without colliding.
- **image**: the snapshot name, lowercased + slugified per Docker tag rules.
- **tag**: `<short-snapshot-id>--idle-30d` for sandbox-committed snapshots,
  or `<short-snapshot-id>--ttl-30d` (configurable) for paths that prefer
  age-TTL over idle-TTL.

Concrete: snapshot named `redis-with-data` taken in cluster `prod-us-east`
becomes:

```
aocr.aerol.ai/prod-us-east/redis-with-data:abc12345--idle-30d
```

The short-id-in-tag makes pushes content-addressable per snapshot — two
snapshots called `redis-with-data` get different tags and AOCR's
keep-latest cleanup doesn't accidentally evict one because of the other.
The `--idle-30d` suffix tells AOCR's reaper to evict if 30 days pass
without a pull.

**Why `--idle-30d` over `--ttl-30d`** for sandbox snapshots: sandboxes
created from a snapshot pull it, which bumps `last_pulled_at` in AOCR's
Postgres. Active snapshots stay forever; truly dormant ones expire. This
matches user intent ("keep snapshots I'm using").

## Configuration changes

**File:** `internal/config/config.go` (additions near `ImageDistributionAOCRHost`)

```go
// AOCROrg is the AOCR org/namespace prefix this cluster pushes to.
// Required when SB_ENABLE_AOCR_SNAPSHOT_PUSH=true. Falls back to
// SB_CLUSTER_NAME, then "default".
AOCROrg string

// AOCRUsername is the login name presented during docker login to AOCR.
// Matches the auth service's user `id`, `username`, or `email` per
// aocr.sh/README.md.
AOCRUsername string

// AOCRTokenPath is a filesystem path to the AOCR PAT token (read at
// startup; not held in env to keep it out of logs/proc). The path is
// templated into the sealed-creds discovery, same pattern as
// CredentialEncryptionKeyPath.
AOCRTokenPath string

// EnableAOCRSnapshotPush gates the push-on-commit behavior. When false
// (default), snapshots remain local_only as today. Set true once AOCR
// is reachable and the cluster identity is provisioned.
EnableAOCRSnapshotPush bool

// AOCRSnapshotRetentionSuffix is the tag suffix appended to snapshot
// pushes. Default "--idle-30d". Validated against AOCR's supported
// suffix list (see aocr.sh/RETENTION.md).
AOCRSnapshotRetentionSuffix string
```

Env mapping:

```
SB_AOCR_ORG=prod-us-east
SB_AOCR_USERNAME=cluster-prod-us-east
SB_AOCR_TOKEN_PATH=/etc/sandboxd/aocr.token
SB_ENABLE_AOCR_SNAPSHOT_PUSH=true
SB_AOCR_SNAPSHOT_RETENTION_SUFFIX=--idle-30d
```

Startup validation:
- If `EnableAOCRSnapshotPush=true` and any of (AOCROrg, AOCRUsername,
  AOCRTokenPath) is missing → fail-fast.
- If `AOCRSnapshotRetentionSuffix` doesn't match the allowlist
  (`--idle-7d|30d|90d|180d` or `--ttl-1h|6h|24h|7d|30d|90d|180d|365d`) →
  fail-fast.
- Token file must be readable at startup; otherwise warn and disable
  the feature (do **not** fail the daemon — operator may be mid-rollout).

## Code changes

### C1. Add `PushImage` to `pkg/docker/client.go`

Mirrors `pullImage` (`client.go:619`): builds `X-Registry-Auth`, streams
the NDJSON response, surfaces stream errors.

```go
func (c *Client) PushImage(ctx context.Context, imageRef string, auth *models.RegistryAuth) error {
    // POST /images/<name>/push?tag=<tag>
    // X-Registry-Auth: base64(json{username,password,serveraddress})
    // Streamed NDJSON, errors land in body with HTTP 200, scan for errorDetail.
}
```

Reuse the existing pull-slot semaphore? **No** — pulls and pushes have
different bandwidth/CPU profiles and the pull cap exists to protect the
local daemon during boot storms. A separate `pushSlots` (smaller, e.g. 2)
prevents a snapshot-push burst from saturating sandboxd's connection to
AOCR. New config knob: `SB_IMAGE_PUSH_MAX_CONCURRENT` (default 2).

### C2. Add `TagImage` to `pkg/docker/client.go`

`POST /images/<source>/tag?repo=<repo>&tag=<tag>` — needed to give the
locally-committed image its AOCR-qualified second tag before push without
having to re-commit.

### C3. Snapshot push integration in `internal/service/service.go`

In `CreateSnapshotWithOwnership` (`service.go:969`), after the existing
`s.docker.CreateSnapshot(...)` returns `imageID`:

```go
imageID, err := s.docker.CreateSnapshot(ctx, sandboxContainerRef(sandbox), name)
if err != nil {
    return nil, false, err
}

aocrRef := ""
if s.cfg.EnableAOCRSnapshotPush {
    aocrRef = s.buildAOCRSnapshotRef(name, shortID(imageID))
    if err := s.docker.TagImage(ctx, name, aocrRef); err != nil {
        // Don't fail the snapshot — fall back to local_only with a warning.
        s.logger.Warn("aocr tag failed, falling back to local-only snapshot",
            "snapshot", name, "error", err)
    } else if err := s.docker.PushImage(ctx, aocrRef, s.aocrAuth()); err != nil {
        s.logger.Warn("aocr push failed, falling back to local-only snapshot",
            "snapshot", name, "ref", aocrRef, "error", err)
        aocrRef = ""
    }
}

snapshot := &models.SandboxSnapshot{
    Name:            name,
    Image:           firstNonEmpty(aocrRef, name), // <-- key change
    ImageID:         imageID,
    SourceSandboxID: sandboxID,
    CreatedAt:       time.Now().UTC(),
}
forceLocal := aocrRef == ""
if err := s.normalizeSnapshotImageDistribution(ctx, snapshot, forceLocal); err != nil {
    return nil, false, err
}
```

**Failure-path consistency** (CLAUDE.md hard rule #4): the snapshot row
should always be created successfully even if AOCR is unreachable. If push
fails, we degrade to `local_only` with a warning — the same behavior as
today. The snapshot is still usable on the originating node; it just can't
move. The PR description must call this out.

### C4. `buildAOCRSnapshotRef` helper

In `internal/service/image_distribution.go`:

```go
func (s *Service) buildAOCRSnapshotRef(snapshotName, shortImageID string) string {
    host := s.cfg.ImageDistributionAOCRHost
    org := s.cfg.AOCROrg
    suffix := s.cfg.AOCRSnapshotRetentionSuffix
    repo := slugifyForDockerTag(snapshotName) // [a-z0-9_-]+ enforced
    tag := shortImageID + suffix
    return fmt.Sprintf("%s/%s/%s:%s", host, org, repo, tag)
}
```

`slugifyForDockerTag` is needed because AOCR snapshot names accept things
Docker's tag/repo grammar doesn't (uppercase, colons, etc.). Validate the
output is a legal OCI ref or error out.

### C5. AOCR credentials helper

```go
func (s *Service) aocrAuth() *models.RegistryAuth {
    return &models.RegistryAuth{
        Username: s.cfg.AOCRUsername,
        Password: s.aocrToken, // loaded once at startup from AOCRTokenPath
        Server:   s.cfg.ImageDistributionAOCRHost,
    }
}
```

Token rotation: re-read the file on SIGHUP or every N minutes
(`SB_AOCR_TOKEN_REFRESH_INTERVAL`, default 5m). Memoized, atomic swap, no
restart needed.

### C6. Pull path on other nodes — wire AOCR auth into `Service.CreateSandbox`

Today `pkg/docker/client.go:pullImage` accepts a `*models.RegistryAuth`
already pulled from `CreateSandboxRequest.Registry` (the per-sandbox creds
path). When the image ref points at the cluster's AOCR host, we need to
inject the cluster's AOCR auth automatically rather than require the SDK
to pass it.

In `pkg/docker/client.go`, `pullImage` is the canonical entry point. Add
auth resolution upstream of it: at the service layer, before calling pull,
check if the image host matches `cfg.ImageDistributionAOCRHost` and the
caller didn't supply explicit creds — if so, inject the cluster AOCR auth.

```go
// In Service, around the CreateSandbox path that calls into docker.PullImage:
func (s *Service) resolvePullAuth(image string, supplied *models.RegistryAuth) *models.RegistryAuth {
    if supplied != nil && supplied.Username != "" {
        return supplied  // explicit creds win
    }
    if imageRegistryHost(image) == s.cfg.ImageDistributionAOCRHost && s.aocrToken != "" {
        return s.aocrAuth()
    }
    return nil
}
```

`imageRegistryHost` already exists in `image_distribution.go:144`.

### C7. Distribution mode classifier respects the new ref shape

`defaultImageDistributionProvider.ClassifyImage` already returns
`ImageDistributionAOCR` when the host matches (`image_distribution.go:42`).
No code change there — it just starts seeing more AOCR-qualified refs as
inputs.

### C8. Snapshot delete should also delete the AOCR tag (best-effort)

In `Service.DeleteSnapshot` (find call site via `s.docker.RemoveImage` or
similar):

```go
if snapshot.ImageDistributionMode == models.ImageDistributionAOCR && snapshot.Image != "" {
    // Distribution v2 supports DELETE /v2/<name>/manifests/<reference>.
    // AOCR's reaper will eventually GC unreferenced blobs.
    // Best-effort — log on failure but don't fail the snapshot delete.
    _ = s.docker.DeleteRemoteImage(ctx, snapshot.Image, s.aocrAuth())
}
```

`DeleteRemoteImage` is new — uses the OCI Distribution `DELETE /v2/.../manifests/`
endpoint directly via the registry HTTP API (not Docker daemon, which
doesn't expose this). If AOCR's auth requires write scope for delete, the
cluster PAT needs `delete` permission. Verify with AOCR maintainer.

If delete is operationally fraught, an alternative is to do nothing here
and rely entirely on AOCR's `--idle-30d` reaper. Simpler, slightly more
S3 cost, but failure-safe. **Default to relying on the reaper**; add the
explicit delete only if storage cost becomes measurable.

### C9. Image-locality placement affinity (optional, deferred)

Even with AOCR, a node that already has the image cached locally avoids
the pull entirely. Implementation sketch:

- Each node gossips its top-K cached images (LRU, K=64) on the existing
  capacity heartbeat.
- `headroomScore` in `internal/cluster/placement.go:195` gets a small
  additive bonus (~+0.15) for a candidate that has the image.
- Power-of-two-choices then tiebreaks toward cached nodes without giving
  up load balance.

**Defer** to a follow-up. Ship the AOCR push path first, measure pull
volume to AOCR, only add affinity if AOCR pull pressure justifies it.

## Failure modes & invariants

| Failure | Behavior | Why |
|---|---|---|
| AOCR push fails on snapshot commit | Snapshot still created locally as `local_only`; warning logged. Sandbox using this snapshot pins to origin node. | Failure-path consistency rule. Don't lose user data because of an infra hiccup. |
| AOCR pull fails on a recreate-failover | Recreate retries on next live target per existing failover logic. If AOCR is truly down, the sandbox stays orphaned (same as today's local-only behavior). | Don't pretend the cluster is healthy when it isn't. |
| AOCR token rotation | Read from file every 5m; atomic swap. Active pulls/pushes use the auth they captured at request start. | Avoid race between rotation and in-flight HTTP. |
| Snapshot name collision across clusters | Solved by the `<org>` prefix in the AOCR ref. Two clusters pushing `redis-with-data` go to different orgs. | Multi-tenant safety. |
| Reaper evicts an active snapshot | Should never happen with `--idle-30d` if it's been pulled in last 30 days. If it does (e.g. operator pushed `--ttl-1h` by mistake), pull fails → sandbox create fails with a clear AOCR 404. | Surface as `models.ErrSnapshotImageGone`, distinct from `ErrSnapshotNotFound`. |
| AOCR reachable from leader but not from a follower | The follower's `Service.CreateSandbox` pull fails. Existing pull-failure handling applies (admission error, sandbox stays in `error` state). | No new behavior; existing semantics. |

## Tests

### Server-side unit (`internal/service/`)

- `snapshot_push_test.go` (new): given `EnableAOCRSnapshotPush=true` and a
  fake docker client that records calls, assert:
  - `CreateSnapshot` → `TagImage` is called with the expected AOCR ref.
  - `PushImage` is called with the cluster AOCR auth.
  - On `PushImage` failure, snapshot row's `Image` field falls back to
    the local tag and `ImageDistributionMode == local_only`.
  - On both success → snapshot row has AOCR-qualified `Image` and
    `ImageDistributionMode == aocr`.
- Extend `image_distribution_test.go`: cover `buildAOCRSnapshotRef`'s
  slugification and the suffix-validation allowlist.

### Cluster integration

- Extend `internal/cluster/dead_owner_test.go` and
  `owner_watcher_test.go`: a snapshot with `ImageDistributionMode=aocr`
  is eligible for cross-node recreation; a `local_only` one is not.
  (Regression-guard the existing branch as-is, add the new case.)

### End-to-end (manual; documented in PR description)

1. Bring up a 2-node cluster + a self-hosted AOCR (docker-compose from
   aocr.sh).
2. Create sandbox on node-1, run a workload, `createSnapshot`.
3. Verify AOCR push by `curl https://aocr/v2/<org>/<repo>/tags/list` (or
   `docker pull` from a third machine).
4. Create a new sandbox from that snapshot; verify placement allows
   node-2; verify node-2 pulls from AOCR (check `docker images` on node-2
   shows the AOCR-qualified ref, AOCR's metrics show the pull).
5. Set `failover.policy=recreate`, kill node-1, verify recreation on
   node-2.

### CLAUDE.md compliance checks

- This change touches `internal/service/service.go` (CreateSnapshot path,
  CLAUDE.md skill `/touch-create-sandbox` doesn't directly apply but the
  same rigor does) — boot-path latency is **not** affected (push happens
  on snapshot commit, not sandbox boot), but call this out in PR.
- No change to the TCP host-port pool or L4 bootstrap → no regression
  test there.
- Cluster placement code unchanged in v1 (affinity deferred) → no
  cluster-correctness call-out needed beyond noting that `aocr` mode now
  appears legitimately in the placement-eligible branch.
- SDK surface unchanged → no per-language SDK work.
- Docs: add `docs/src/content/docs/operations/snapshot-distribution.mdx`
  (new page) covering the operator setup. Register in
  `docs/src/content.config.ts`. Five-tab examples for the SDK-visible
  bits (essentially `createSnapshot` + create-from-snapshot showing
  failover policy now works).

## Rollout

1. Land the code changes with `EnableAOCRSnapshotPush=false` default
   (no behavior change).
2. Deploy AOCR (Helm or compose) in a dev cluster.
3. Provision an AOCR user/PAT for the cluster identity; install
   `/etc/sandboxd/aocr.token` via Ansible.
4. Flip `SB_ENABLE_AOCR_SNAPSHOT_PUSH=true` on one node in dev; create
   a snapshot, verify AOCR push, then enable on the rest.
5. Production rollout: same staged flip, behind a feature flag in the
   Ansible inventory.

## Open questions

1. **Cluster identity provisioning.** Today AOCR users come from the
   `app.aerol.ai` upstream validation service. Self-hosted deployments
   point at their own validator. Need a story for "this cluster is a
   first-class AOCR push identity" — probably a special account class on
   the auth service that has push rights to one specific org, no expiry.
   This is an AOCR-side decision; document the contract here, implement
   over there.

2. **Snapshot tag immutability.** Distribution v2 allows tag overwrites
   by default. AOCR's keep-latest policy assumes pushes are immutable
   within their tag (it's the *plain tag* that gets reaped to one).
   By embedding `shortImageID` in the tag, we make our tags effectively
   immutable. Validate that AOCR's reaper handles many `--idle-30d`
   tags per repository (it should — Postgres index on `last_pulled_at`).

3. **Cluster-name vs explicit org.** Defaulting `AOCROrg` to
   `SB_CLUSTER_NAME` is convenient but ties two unrelated concerns. Maybe
   require explicit `SB_AOCR_ORG` to force operator intent. Lean toward
   explicit-required when `EnableAOCRSnapshotPush=true`.

4. **Public vs private AOCR.** The hosted `aocr.aerol.ai` is multi-tenant
   with each user pushing to their own org. A self-hosted single-tenant
   AOCR is the obvious model for production AerolVM clusters. v1 assumes
   self-hosted; the public path requires per-user auth which is the
   "per-tenant credentials" non-goal.

5. **Pull-through cache for DockerHub.** Punted to a follow-up plan. The
   most plausible implementation is a separate Distribution instance in
   `proxy:` mode at `aocr-mirror.aerol.ai`, with daemons configured via
   `--registry-mirror`. AOCR-the-product stays focused on push.

## Estimated scope

- `internal/config/config.go`: ~60 LOC (config fields, env loading, validation).
- `pkg/docker/client.go`: ~150 LOC (`PushImage`, `TagImage`, optional
  `DeleteRemoteImage`).
- `internal/service/service.go`: ~80 LOC (push-on-commit integration in
  `CreateSnapshotWithOwnership`, pull-auth resolution).
- `internal/service/image_distribution.go`: ~50 LOC (`buildAOCRSnapshotRef`,
  slugification, suffix validation).
- Tests: ~300 LOC.
- Docs: one new `.mdx` page + sidebar entry.
- Ansible: token file deployment task.

Total: ~600 LOC of production code + tests + docs. Single PR, behind a
feature flag that defaults off.

## What this plan does NOT close

- DockerHub / external-registry pull amplification (separate plan).
- Per-tenant snapshot push (single cluster-wide identity in v1).
- Image-locality placement affinity (deferred to follow-up).
- AOCR HA topology (single AOCR instance assumed for v1; ops concern).
