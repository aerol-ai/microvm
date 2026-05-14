---
name: add-mount-adapter
description: Add an external-storage mount adapter (S3, NFS, SSHFS, rclone, etc.) under pkg/mounts/adapters/. Enforces the host-side input threat model and the per-sandbox cleanup contract. Use when the user asks to "add a mount type", "support mounting X", "add a storage adapter", or wants AerolVM sandboxes to consume a new backing storage. Proactively suggest when a feature request implies a new mount backend.
---

# Add an external-storage mount adapter

## Threat-model warning (read first)

Mount inputs run on the host, **outside** the microVM isolation boundary, as the daemon user:

- `source` is passed to mount-tool commands
- `options.opts` (NFS) is passed verbatim
- `options.extra_args` (S3) is passed verbatim
- mount-tool flags generally

**The current assumption is "PAT holder == host operator".** PAT holders are trusted as if they had shell on the host. Their mount input is already-trusted by the threat model.

**If this PR widens what a PAT holder can pass into a host-side mount command, you must explicitly re-justify safety under that assumption** in the PR template's mount section. If anyone is considering moving to multi-tenant PATs (sub-accounts, hosted offering, external CI) — these fields become a host attack surface and must be allowlisted / isolated. See `pr-review.md` §5.

## File layout

```
pkg/mounts/
  manager.go            Top-level Manager + adapter dispatch.
  types.go              Mount type interface; Mount, MountSpec, etc.
  sweep.go              Background unmount sweep for orphaned sandboxes.
  adapters/             ← new adapter goes here
    <yourthing>.go
  manager_test.go
  recovery_test.go
```

## Steps

1. **New adapter file** under `pkg/mounts/adapters/`. Implement the adapter interface (look at the existing adapters for the exact shape — it's small and stable). The adapter must support:
   - `Mount(ctx, sandboxID, spec)` — installs the mount, returns the host path for the docker bind.
   - `Unmount(sandboxID)` — must be idempotent; called from `mounts.UnmountAll` on cleanup *and* by the sweep.
   - Validation hooks for the adapter-specific options.
2. **Register** in the manager's adapter table in `pkg/mounts/manager.go`. Look for the existing dispatch — add a case for your mount kind.
3. **Validate inputs at the adapter boundary.** Schemes, control characters in `source`, and any flags you copy through. Even though the threat model trusts PATs today, garbage-in errors should be 4xx-shaped at the API, not opaque mount-tool stderr.
4. **Credentials.** If your adapter needs secrets, seal them via `pkg/secrets.Cipher` so they're encrypted at rest in the DB. The `MountsCredentialsRuntimeDir` is wiped + recreated on daemon start.
5. **Idempotency.** Re-mounting the same `(sandboxID, mountPath)` must be a no-op, not a "already mounted" error.
6. **Tests.** Add to `pkg/mounts/manager_test.go` (happy path + validation) and `recovery_test.go` (sweep / orphan cleanup).
7. **Docs.** Add to `docs/src/content/docs/external-storage.mdx` with all five SDK languages and `syncKey="lang"`. No curl.

## Limits

`models.MaxMountsPerSandbox` caps per-sandbox mount count. Don't bypass it for your adapter.

## What you must call out in the PR

- Anything you add to the `CreateSandbox` boot path via `mounts.MountAll` (most adapters fire here on every sandbox create). State the per-mount latency expectation.
- Any new field on `models.Mount` (ripples to facades + SDK Go transport).
- Any new place that runs a host command — re-check the threat-model paragraph above.
