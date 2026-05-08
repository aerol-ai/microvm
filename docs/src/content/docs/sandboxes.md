title: Sandboxes

A sandbox is an isolated compute environment. Each sandbox has:

- An isolated filesystem from a base OCI image.
- Dedicated process, network, and mount namespaces.
- Configurable vCPU, memory, and disk quotas.
- Optional public HTTPS routes.
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
| `running` | Sandbox is up and accepting requests. |
| `stopped` | Sandbox is paused; state is persisted. |
| `destroyed` | Sandbox and all its data are permanently removed. |

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

Stopping persists all container-level state via Docker. Starting resumes from the persisted image layer - running processes are not retained across a stop/start cycle.

## Destroy

```http
DELETE /v1/sandboxes/{id}
```

Permanently removes the sandbox, all its data, and its metadata record. External storage mounts are unmounted before removal.

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

Resize updates resource constraints without restarting the sandbox.

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

`stop_if_idle_for_ns` and `destroy_at_age_ns` are nanosecond durations. The platform tracks inactivity and shuts down idle sandboxes automatically.

## Environment

See [Environment](/environment) for image selection, environment variables, and resource defaults.
