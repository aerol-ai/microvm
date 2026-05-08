title: External Storage

# External Storage (Bring Your Own Bucket)

Sandboxes are ephemeral by design. If you need durable workspace state across sandbox lifecycles, mount your own cloud or network storage into the sandbox.

The platform handles mounting on the host and bind-mounts the result into your sandbox. Your image needs no special mount tooling, and credentials never enter the sandbox.

## How it works

1. Declare mounts in the create request. The platform validates the spec and stores credentials encrypted at rest.
2. At sandbox start, the platform establishes the mount on the host and makes it available inside the sandbox at the path you specified.
3. On `Stop`, the mount is torn down. On `Start`, it is re-established. After a host reboot, mounts are restored automatically on the next sandbox start.

## Supported mount types

| Type | Source format | Host binary used | Credentials field |
| --- | --- | --- | --- |
| `s3` | `s3://bucket[/prefix]` or `bucket` | `mount-s3` | `access_key_id`, `secret_access_key`, `session_token` |
| `nfs` | `host:/exports/path` | `mount.nfs` | none |
| `sshfs` | `user@host:/path` | `sshfs` | `private_key_pem` |
| `rclone` | `remote:path` | `rclone mount` | `rclone_conf` |

Up to 8 mounts per sandbox are supported, with up to 32 credential keys and 4 KiB total payload.

## Security Model

- Credentials never enter the sandbox.
- Credentials are encrypted at rest with AES-256-GCM.
- Read APIs return `has_credentials: true` but never the actual values.

## Operational Notes

- Mounts are established at `Create` and re-established at `Start`.
- A failed mount is retried once before being disabled.
- Host requirements include `fuse3`, `sshfs`, `nfs-common`, `rclone`, and AWS `mountpoint-s3`.
- Network egress blocking applies inside the sandbox, not to the host mount process.
