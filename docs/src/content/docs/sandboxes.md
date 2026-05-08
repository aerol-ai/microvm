---
title: Sandboxes
description: What a sandbox is, its lifecycle states, and the core create/start/stop/destroy operations.
---

A sandbox is a Docker container managed by `sandboxd`. Each sandbox has:

- An isolated filesystem from a base OCI image.
- Dedicated process, network, and mount namespaces.
- A `toolboxd` binary injected at startup for command execution and file transfer.
- Optional public HTTPS routes managed through Caddy.
- Optional external storage mounts and network egress blocking.

## Lifecycle States

```
created ──► running ──► stopped ──► running
                │
                ▼
           destroyed
```

| State | Description |
|---|---|
| `running` | Container is up, `toolboxd` is accepting requests. |
| `stopped` | Container is paused, state is persisted in SQLite. |
| `destroyed` | Container and metadata are permanently removed. |

## Create

```http
POST /v1/sandboxes
Authorization: Bearer <token>
Content-Type: application/json

{
  "image": "ubuntu:22.04",
  "env": { "MY_VAR": "value" },
  "cpu_milli": 2000,
  "memory_mb": 512,
  "disk_gb": 5
}
```

The response includes the sandbox `id`, its `public_url`, and an `ssh_private_key` for SSH access (only returned on creation).

## Start and Stop

```http
POST /v1/sandboxes/{id}/start
POST /v1/sandboxes/{id}/stop
```

Stopping persists all container-level state via Docker. Starting resumes the same filesystem and running processes were not retained — a start is a fresh container launch from the persisted image layer.

## Destroy

```http
DELETE /v1/sandboxes/{id}
```

Permanently removes the container, all its data, and the SQLite record. External storage mounts are unmounted before removal.

## Resize

Change CPU or memory allocation on a running sandbox:

```http
POST /v1/sandboxes/{id}/resize
Content-Type: application/json

{
  "cpu_milli": 4000,
  "memory_mb": 1024
}
```

Resize updates Docker's cgroup constraints without restarting the container.

## Idle Lifecycle

Sandboxes can be configured to stop or destroy themselves when idle:

```json
{
  "lifecycle": {
    "stop_if_idle_for_ns": 3600000000000,
    "destroy_at_age_ns": 86400000000000
  }
}
```

`stop_if_idle_for_ns` and `destroy_at_age_ns` are nanosecond durations. The daemon tracks the last time `toolboxd` received a request and shuts down idle sandboxes automatically.

## Environment

See [Environment](/environment) for image selection, environment variables, and resource defaults.
