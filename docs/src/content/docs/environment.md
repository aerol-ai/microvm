title: Environment

The sandbox environment is fully specified at creation time through the create request body.

## Image

Any OCI-compatible image reachable by the Docker daemon on the host:

```json
{
  "image": "ubuntu:22.04"
}
```

Public images are pulled automatically. Private registries require the host Docker daemon to be authenticated (`docker login` or equivalent credentials in `/root/.docker/config.json`).

## Environment Variables

Pass key-value pairs into the container at creation:

```json
{
  "image": "ubuntu:22.04",
  "env": {
    "DATABASE_URL": "postgres://...",
    "APP_ENV": "sandbox"
  }
}
```

Variables are set in the container's process environment. They are stored encrypted at rest and are not exposed through the list or get endpoints.

## Resource Limits

| Field | Unit | Default | Description |
|---|---|---|---|
| `cpu_milli` | millicores | 1000 | CPU quota (1000 = 1 vCPU) |
| `memory_mb` | megabytes | 512 | Memory limit |
| `disk_gb` | gigabytes | 10 | Writable layer size (overlay quota) |

Example:

```json
{
  "image": "ubuntu:22.04",
  "cpu_milli": 2000,
  "memory_mb": 1024,
  "disk_gb": 20
}
```

Resources can be changed on a live sandbox without a restart using the [resize](/sandboxes#resize) endpoint.

## Idle Lifecycle

Sandboxes can self-terminate based on age or inactivity:

```json
{
  "lifecycle": {
    "stop_if_idle_for_ns": 3600000000000,
    "destroy_at_age_ns": 86400000000000
  }
}
```

| Field | Behavior |
|---|---|
| `stop_if_idle_for_ns` | Stop the sandbox after this many nanoseconds of inactivity. |
| `destroy_at_age_ns` | Destroy the sandbox once it is older than this duration (wall clock from creation). |

Either field can be set independently. Lifecycle parameters can be updated on a running sandbox:

```http
PUT /v1/sandboxes/{id}/lifecycle
Content-Type: application/json

{
  "stop_if_idle_for_ns": 7200000000000,
  "destroy_at_age_ns": 172800000000000
}
```

## Entrypoint

The sandbox image's default entrypoint and `CMD` are not used. Your workload runs via the exec or session APIs instead.
