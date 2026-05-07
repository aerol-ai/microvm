# External Storage (Bring Your Own Bucket)

This sandbox platform deliberately does **not** expose host disk to user containers. Sandboxes are ephemeral; if you need durable workspace state, you mount your own cloud or network storage.

The daemon does the mounting on the host and bind-mounts the result into your container. **Your image needs no mount tooling** — a vanilla `python:3.12` is enough — and **credentials never enter the container**.

## How it works

1. You declare mounts in the create request. The daemon validates the spec and encrypts your credentials at rest.
2. Sandboxd spawns the appropriate mount tool (`mountpoint-s3`, `sshfs`, `mount.nfs`, `rclone mount`) on the host inside `/var/lib/sandboxd/mounts/<sandbox-id>/<index>/` (mode 0700, owned by the sandboxd user).
3. The Docker container is created with that path bind-mounted at the target you chose. Inside the container `/workspace` (or whatever target) is just a directory.
4. If the FUSE process crashes, sandboxd restarts it. Two crashes within 30 s and the mount is disabled — the kernel returns I/O errors at the mount point until you recreate the sandbox.
5. On `Stop` the host mount is torn down. On `Start` it's re-established. After a host or sandboxd reboot the reconciler re-mounts every running sandbox automatically.

Cross-tenant isolation is enforced by the kernel's mount namespace: container A cannot see container B's bind source. The host parent directory is mode 0700 so even other host users can't traverse it.

## Threat model

- **Credentials never enter the container.** They live encrypted in sandboxd's database and are materialized briefly as a tmpfs file (`/run/sandboxd/<id>-<i>.cred`, mode 0600) for the FUSE process to read at startup. For S3 / rclone the file is unlinked once the mount is ready; sshfs keeps its key file because the SSH session may reconnect.
- **Encryption at rest.** AES-256-GCM with a host-resident key. Set `SB_CREDENTIAL_ENCRYPTION_KEY` (base64, 32 bytes) to bring your own; otherwise sandboxd auto-generates one at `SB_CREDENTIAL_ENCRYPTION_KEY_PATH` (default `/var/lib/sandboxd/credential_encryption.key`, mode 0600). Back this file up alongside `state.db` — without it, stored credentials are unrecoverable.
- **What sandboxd never does.** Make a network call to your storage on its own; log credentials; return them via any read API. The list-mounts endpoint shows `has_credentials: true` and never the values.

## Supported mount types

| Type     | Source format                      | Host binary used  | Credentials field                                  |
| -------- | ---------------------------------- | ----------------- | -------------------------------------------------- |
| `s3`     | `s3://bucket[/prefix]` or `bucket` | `mount-s3`        | `access_key_id`, `secret_access_key`, `session_token` (optional) |
| `nfs`    | `host:/exports/path`               | `mount.nfs`       | none (kernel mount, options via `options.opts`)    |
| `sshfs`  | `user@host:/path`                  | `sshfs`           | `private_key_pem`                                  |
| `rclone` | `remote:path`                      | `rclone mount`    | `rclone_conf` (the full text of an `rclone.conf`)  |

Up to 8 mounts per sandbox. Up to 32 credential keys, 4 KiB total payload.

## Validation rules

The daemon rejects (with HTTP 400) mounts whose:

- `type` isn't one of the four supported types
- `target` is empty, relative, contains `..`, or matches one of: `/`, `/proc`, `/sys`, `/dev`, `/etc`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/boot`, `/var/run`, `/run`, the toolbox mount path
- `source` doesn't match the type-specific format (e.g. an `s3` source must not be a filesystem path; `nfs` must contain `:/`; `sshfs` must contain `@` and `:`)
- `credentials` map has more than 32 keys or more than 4 KiB total payload, or contains null bytes / newlines

These rules are enforced at the API boundary; nothing is created if any mount is invalid.

## Examples

### S3 / S3-compatible (Cloudflare R2, AWS S3, MinIO, B2, Wasabi)

```go
sb, _, err := client.Create(ctx, microvm.CreateSandboxOptions{
    Image: "python:3.12",
    Mounts: []types.MountSpec{{
        Type:   types.MountTypeS3,
        Source: "s3://my-workspace",
        Target: "/workspace",
        Options: map[string]string{
            "region":   "us-east-1",
            // For non-AWS S3-compatible:
            // "endpoint": "https://<account>.r2.cloudflarestorage.com",
        },
        Credentials: map[string]string{
            "access_key_id":     os.Getenv("MY_S3_KEY_ID"),
            "secret_access_key": os.Getenv("MY_S3_SECRET"),
        },
    }},
})
```

Inside the container, `/workspace` is the bucket. No `mount-s3` install, no entrypoint script, no env vars.

### NFS

```go
Mounts: []types.MountSpec{{
    Type:   types.MountTypeNFS,
    Source: "nfs.internal:/exports/team",
    Target: "/mnt/team",
    Options: map[string]string{"opts": "ro,vers=4"},
}}
```

Sandboxd issues `mount.nfs` on the host. NFS is a kernel mount, so there's no FUSE process to supervise; if the server goes away the kernel returns errors at the mount point.

### SSHFS

```go
Mounts: []types.MountSpec{{
    Type:   types.MountTypeSSHFS,
    Source: "ubuntu@build.internal:/home/ubuntu/code",
    Target: "/workspace",
    Credentials: map[string]string{
        "private_key_pem": string(privateKeyPEM),
    },
}}
```

The key is written to a host-only tmpfs file; sshfs reads it and keeps reading it on reconnect (the option `reconnect` is set, along with `accept-new` host keys and 15 s/3-strike server-alive). The key file is mode 0600 and lives in `/run/sandboxd/`.

### Rclone (any provider rclone supports)

```go
Mounts: []types.MountSpec{{
    Type:   types.MountTypeRclone,
    Source: "myremote:bucket/prefix",
    Target: "/workspace",
    Options: map[string]string{
        "vfs_cache_mode": "writes", // default; override if needed
    },
    Credentials: map[string]string{
        "rclone_conf": string(rcloneConf), // full rclone.conf content
    },
}}
```

The config file is unlinked once `rclone mount` is ready (rclone holds it in memory).

## Reading back mount config

```go
mounts, err := client.Mounts(ctx, sb.ID)
// mounts[i].HasCredentials reports whether credentials were supplied at create time;
// the actual values are never returned.
```

The HTTP shape:

```
GET /v1/sandboxes/{id}/mounts
→ 200 {"mounts":[{"type":"s3","target":"/workspace","source":"s3://my-bucket","options":{...},"read_only":false,"has_credentials":true}]}
```

## Operational notes

- **Lifecycle.** Mounts are established at `Create`, torn down at `Stop` or `Destroy`, and re-established at `Start`. After a sandboxd or host restart the reconciler re-mounts every running sandbox the next time it ticks (or at startup).
- **Crash supervision.** A FUSE process that exits is restarted once. Two crashes within 30 s disable the mount; sandboxd logs the event with `sandbox_id`, `index`, and the exit error.
- **Host requirements.** Install `fuse3`, `sshfs`, `nfs-common`, `rclone`, and AWS's `mountpoint-s3` (`.deb` from AWS) on the host. The install script does this for you.
- **Egress.** Network egress is enforced inside the container, not for the host's mount tools. If you enable per-sandbox egress blocking (`network_block_all`), the container loses internet access but the host's FUSE process keeps talking to your storage. This is the desired behavior for most "lock down the workload, keep storage" cases.
- **Configuration.** `SB_MOUNTS_ROOT` (default `/var/lib/sandboxd/mounts`), `SB_MOUNTS_CRED_DIR` (default `/run/sandboxd`), `SB_MOUNT_WAIT_TIMEOUT` (default `30s`).

## What's intentionally out of scope

- Adding or removing a mount on a running sandbox. Mounts are set at create time.
- Per-mount metering, quotas, or resize.
- Multi-host volumes / CSI. Single-host only.
