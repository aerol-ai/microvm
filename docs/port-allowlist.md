# Port allowlist

Sandboxes default to **closed** for public proxy access. A port inside a
container is only reachable from the public internet if the caller has
explicitly exposed it via the SDK's `exposePort(port)`. Unexposed ports -
including everything bound to `localhost` inside the container - are not
publicly reachable.

This document describes the allowlist mechanism that enforces this default.

## Why it exists

Each sandbox has a public URL (e.g. `https://<sandbox-id>.<domain>/`) that
Caddy reverse-proxies into the in-container `toolboxd`. `toolboxd` exposes a
`/proxy/<port>/...` endpoint that forwards requests to `localhost:<port>`
inside the container.

Before the allowlist existed, that endpoint was unauthenticated and accepted
any port. A container running an unintended internal service (Postgres,
Redis, debug HTTP, etc.) was implicitly exposed to the internet via:

```
https://<sandbox-id>.<domain>/proxy/5432/   # any listener, any caller
```

The allowlist closes that path. `/proxy/<port>/...` now returns
`403 Forbidden - port not exposed` unless `<port>` has been explicitly
exposed via the SDK.

## How it works

```
┌──────────────────────────────────────────────────────────────────┐
│ sandboxd (host)                                                  │
│                                                                  │
│   sandbox.exposePort(8080)                                       │
│        │                                                         │
│        ├──> store.UpsertPort  (persists in exposed_ports table)  │
│        ├──> caddy.UpsertPortRoute  (creates 8080-<id>.<domain>)  │
│        └──> docker.PushAllowedPorts ─────────┐                   │
│                                              │                   │
└──────────────────────────────────────────────┼───────────────────┘
                                               │  POST /admin/allowed-ports
                                               │  Authorization: Bearer <token>
                                               │  {"ports":[8080]}
                                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ toolboxd (PID 1 inside the container)                            │
│                                                                  │
│   allowedPorts: {8080}                                           │
│                                                                  │
│   GET /proxy/8080/api  ──> 200 (proxied to localhost:8080)       │
│   GET /proxy/5432/     ──> 403 (not in allowlist)                │
└──────────────────────────────────────────────────────────────────┘
```

`exposed_ports` (in the SQLite store) is the source of truth for the
allowlist. `toolboxd` keeps a copy in memory; `sandboxd` pushes the current
list every time it can change.

### When the list is pushed to toolboxd

| Trigger | Why |
| --- | --- |
| `ExposePort` | new port added |
| `UnexposePort` | port removed |
| `StartSandbox` | container restart - toolboxd restarted with empty allowlist |
| `Reconcile` (boot + every `SB_RECONCILE_INTERVAL`) | recover from missed pushes (e.g. sandboxd restart) |

Pushes are best-effort: a failure is logged but does not fail the API call.
The next reconcile will catch up. If `toolboxd` is unreachable during a
push, `/proxy/<port>/` will continue to deny that port until the next
successful push.

### Authentication

The push endpoint requires the per-sandbox toolbox token:

```
POST /admin/allowed-ports
Authorization: Bearer <SB_TOOLBOX_TOKEN value for this sandbox>
Content-Type: application/json

{"ports": [8080, 3000]}
```

The token is generated when the sandbox is created and stored in the
sandboxes table. Only `sandboxd` knows it; the SDK never sees it.

## SDK usage

There is no new SDK surface. The existing `exposePort` / `unexposePort`
calls now also gate `/proxy/<port>/...`:

```ts
const sandbox = await client.create({ image: "ubuntu:22.04" });

// Initially, /proxy/<port>/ on the sandbox URL refuses every port.
await fetch(`${sandbox.publicURL}/proxy/8080/`);     // 403

// After exposePort, port 8080 becomes reachable two ways:
const portURL = await sandbox.exposePort(8080);
await fetch(`${sandbox.publicURL}/proxy/8080/`);     // 200
await fetch(`${portURL}/`);                          // 200 - clean per-port URL

// Removing the exposure closes both paths.
await sandbox.unexposePort(8080);
await fetch(`${sandbox.publicURL}/proxy/8080/`);     // 403
```

The two public paths to your app:

1. **Per-port URL** - `https://<port>-<sandbox-id>.<domain>/`. Caddy
   reverse-proxies straight to the container; toolbox is not involved.
   Ideal for serving an app to end users.
2. **Proxy path** - `https://<sandbox-id>.<domain>/proxy/<port>/`.
   Goes through `toolboxd`, which checks the allowlist. Useful when you
   want all of a sandbox's traffic under one hostname.

Both require `exposePort`. Neither works for a port that has not been
exposed.

## Operational notes

### Migration for existing sandboxes

Sandboxes created before this change will have an empty allowlist on their
running `toolboxd` until one of:

- The sandbox is restarted (`StartSandbox` pushes the current allowlist).
- The periodic reconcile fires (`SB_RECONCILE_INTERVAL`, default `5m`).

Until then, `/proxy/<port>/` will return `403` even for ports that were
previously exposed. The per-port URLs (`<port>-<id>.<domain>`) keep working
throughout - they go through Caddy directly, not through toolbox.

To force an immediate sync, restart `sandboxd`; its boot reconcile pushes
to every running sandbox.

### Diagnosing 403 from `/proxy/<port>/`

1. Confirm the port is exposed:
   ```
   GET /v1/sandboxes/<id>
   ```
   `exposed_ports` should include the port.

2. Confirm toolboxd received the push. From the host running sandboxd:
   ```
   sudo docker logs <container-id> | grep "allowed ports"
   ```
   You should see one or more `allowed ports updated` lines reflecting the
   current set.

3. If the store has the port but the log doesn't, force a reconcile:
   ```
   sudo systemctl restart sandboxd
   ```

### What is NOT gated

- The auth-protected toolbox endpoints (`/process/execute`, `/files/upload`,
  `/files/download`, `/admin/allowed-ports`) are unaffected. They require
  the toolbox token, which only `sandboxd` knows.
- `/health`, `/version`, `/` on the toolbox remain unauthenticated and
  publicly reachable. They reveal the sandbox ID and toolboxd version.
- The per-port public URL (`<port>-<id>.<domain>`) is gated by Caddy: it
  exists only after `exposePort`. It does not consult toolboxd's allowlist.
  Removing the Caddy route is sufficient to close that path.

## File map

| File | Role |
| --- | --- |
| `cmd/toolboxd/main.go` | `allowedPorts` map, `setAllowedPorts`/`portAllowed`, `handleSetAllowedPorts`, allowlist check in `handleProxy` |
| `pkg/docker/client.go` | `PushAllowedPorts` HTTP call to toolboxd's admin endpoint |
| `internal/service/service.go` | `syncAllowedPorts` helper; called from `ExposePort`, `UnexposePort`, `StartSandbox`, `Reconcile` |
| `internal/store/store.go` | `exposed_ports` table is the source of truth |
