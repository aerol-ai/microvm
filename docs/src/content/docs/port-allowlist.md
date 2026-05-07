---
title: Port Allowlist
description: Require explicit exposure before public traffic can reach a sandbox port.
---

# Port allowlist

Sandboxes default to **closed** for public proxy access. A port inside a container is only reachable from the public internet if the caller has explicitly exposed it via the SDK's `exposePort(port)`.

This closes the unauthenticated path from a sandbox URL to arbitrary internal services such as databases, debug ports, or accidental listeners.

## How it works

`exposed_ports` in the SQLite store is the source of truth. `toolboxd` keeps an in-memory copy, and `sandboxd` pushes updates every time the allowlist changes.

### When the list is pushed to toolboxd

| Trigger | Why |
| --- | --- |
| `ExposePort` | new port added |
| `UnexposePort` | port removed |
| `StartSandbox` | container restart clears toolbox state |
| `Reconcile` | recover from missed pushes after daemon restart |

The push endpoint requires the per-sandbox toolbox token:

```text
POST /admin/allowed-ports
Authorization: Bearer <toolbox-token>
Content-Type: application/json

{"ports": [8080, 3000]}
```

## SDK behavior

There is no new SDK surface. Existing `exposePort` and `unexposePort` calls now also gate `/proxy/<port>/...`.

```ts
const sandbox = await client.create({ image: 'ubuntu:22.04' })

await fetch(`${sandbox.publicURL}/proxy/8080/`) // 403

const portURL = await sandbox.exposePort(8080)
await fetch(`${sandbox.publicURL}/proxy/8080/`) // 200
await fetch(`${portURL}/`) // 200

await sandbox.unexposePort(8080)
await fetch(`${sandbox.publicURL}/proxy/8080/`) // 403
```

## Diagnosing 403 responses

1. Confirm the port is exposed in `GET /v1/sandboxes/<id>`.
2. Check the container logs for `allowed ports updated` entries.
3. If needed, restart `sandboxd` to force reconcile and re-push the allowlist.

## File map

| File | Role |
| --- | --- |
| `cmd/toolboxd/main.go` | Allowlist state and proxy enforcement |
| `pkg/docker/client.go` | `PushAllowedPorts` request to `toolboxd` |
| `internal/service/service.go` | Sync helper called from lifecycle operations |
| `internal/store/store.go` | `exposed_ports` table |