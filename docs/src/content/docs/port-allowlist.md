title: Port Allowlist

Sandboxes default to **closed** for public proxy access. A port inside a sandbox is only reachable from the public internet if it has been explicitly exposed via the SDK's `exposePort(port)`.

This prevents unauthenticated access to internal services such as databases, debug ports, or accidental listeners.

## How it works

The allowlist is maintained by the platform. Every `exposePort` and `unexposePort` call updates the allowlist and creates or removes the corresponding public route. When a sandbox restarts, the allowlist is restored automatically.

## SDK behavior

There is no new SDK surface. Existing `exposePort` and `unexposePort` calls gate `/proxy/<port>/...`.

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

1. Confirm the port is listed in `GET /v1/sandboxes/<id>` under `exposed_ports`.
2. Check that `exposePort` completed without error.
3. Verify the sandbox is in `running` state.
