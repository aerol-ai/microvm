---
title: Preview
description: Expose container ports publicly over HTTPS through Caddy subdomain or path routes.
---

Every sandbox gets a public `sandboxd`-managed URL that routes through Caddy to the `toolboxd` process inside the container. You can also expose additional ports on separate public URLs so browsers and external tools can reach services running inside the sandbox.

## Sandbox URL

When `SB_DOMAIN` is configured, sandboxes are reachable at:

```
https://<sandbox-id>.<domain>
```

Without `SB_DOMAIN`, the daemon falls back to a path-based URL:

```
http://<SB_PUBLIC_HOST>/<sandbox-id>/
```

The sandbox URL is returned as `public_url` in the create and get responses.

## Expose a Port

Services running inside the sandbox are not reachable publicly by default. Call `exposePort` to add a port to the allowlist and create a Caddy route for it:

```http
POST /v1/sandboxes/{id}/ports/{port}
Authorization: Bearer <token>
```

The response includes the public URL for that port:

```json
{
  "url": "https://<sandbox-id>-<port>.<domain>"
}
```

### SDK Usage

```ts
// TypeScript
const { url } = await sandbox.exposePort(3000)
console.log(url) // https://sandbox_abc123-3000.sandbox.example.com
```

```python
# Python
result = sandbox.expose_port(3000)
print(result['url'])
```

```go
// Go
result, err := sandbox.ExposePort(ctx, 3000)
fmt.Println(result.URL)
```

```java
// Java
var result = sandbox.exposePort(3000);
System.out.println(result.url);
```

## Unexpose a Port

Remove the public route and the port from the allowlist:

```http
DELETE /v1/sandboxes/{id}/ports/{port}
Authorization: Bearer <token>
```

```ts
await sandbox.unexposePort(3000)
```

## Port Allowlist

`toolboxd` maintains an in-memory allowlist of exposed ports. The `/proxy/` path on `toolboxd` forwards traffic to container-local ports — but only if the target port is in the allowlist. This prevents unauthenticated access to accidental listeners such as databases or debug servers.

See [Port Allowlist](/port-allowlist) for full details.

## TLS

Caddy issues TLS certificates automatically:

- **Domain mode** (`SB_DOMAIN` set): Caddy issues per-sandbox wildcard certificates via DNS-01 (Cloudflare recommended) or per-port certificates via HTTP-01. See [Getting Started](/getting-started) for the rate-limit implications of HTTP-01 at scale.
- **IP mode** (no `SB_DOMAIN`): Routes are HTTP-only, no TLS.

For production use with many sandboxes, configure DNS-01 wildcard TLS to avoid Let's Encrypt rate limits.
