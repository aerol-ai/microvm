---
title: External Storage
description: Mount S3, NFS, SSHFS, and rclone-backed storage on the host and bind it into containers.
---

# External Storage (Bring Your Own Bucket)

This sandbox platform deliberately does **not** expose host disk to user containers. Sandboxes are ephemeral; if you need durable workspace state, you mount your own cloud or network storage.

The daemon does the mounting on the host and bind-mounts the result into your container. Your image needs no mount tooling, and credentials never enter the container.

## How it works

1. You declare mounts in the create request. The daemon validates the spec and encrypts your credentials at rest.
2. `sandboxd` spawns the appropriate mount tool on the host inside `/var/lib/sandboxd/mounts/<sandbox-id>/<index>/`.
3. The Docker container is created with that path bind-mounted at the target you chose.
4. If the FUSE process crashes, `sandboxd` restarts it. Repeated crashes disable the mount.
5. On `Stop` the host mount is torn down. On `Start` it is re-established. Reconcile restores mounts after reboot.

## Supported mount types

| Type | Source format | Host binary used | Credentials field |
| --- | --- | --- | --- |
| `s3` | `s3://bucket[/prefix]` or `bucket` | `mount-s3` | `access_key_id`, `secret_access_key`, `session_token` |
| `nfs` | `host:/exports/path` | `mount.nfs` | none |
| `sshfs` | `user@host:/path` | `sshfs` | `private_key_pem` |
| `rclone` | `remote:path` | `rclone mount` | `rclone_conf` |

Up to 8 mounts per sandbox are supported, with up to 32 credential keys and 4 KiB total payload.

## Security Model

- Credentials never enter the container.
- Credentials are encrypted at rest with AES-256-GCM.
- Read APIs return `has_credentials: true` but never the actual values.

## Operational Notes

- Mounts are established at `Create` and re-established at `Start`.
- A FUSE process that exits is restarted once before the mount is disabled.
- Host requirements include `fuse3`, `sshfs`, `nfs-common`, `rclone`, and AWS `mountpoint-s3`.
- Egress blocking applies inside the container, not to the host mount helpers.