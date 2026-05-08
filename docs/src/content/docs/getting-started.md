---
title: Server Setup
---

AerolVM runs on a single Linux host. The one-line installer configures the server, sets up Caddy for TLS, and registers a systemd service with automatic restarts and a health-check timer.

## Install

**Trial / single-user** (HTTP-01 on-demand TLS):

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --domain sandbox.example.com \
    --pat-token your-secret-pat
```

**Production** (DNS-01 wildcard TLS via Cloudflare - required for real workloads):

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --domain sandbox.example.com \
    --pat-token your-secret-pat \
    --dns-provider cloudflare \
    --dns-api-token your-cloudflare-api-token
```

> **Pick the right TLS mode up-front.** In HTTP-01 mode Caddy issues one Let's Encrypt certificate per sandbox subdomain on first access. Let's Encrypt caps **certificate issuance** at 50 new certs per registered domain per week — this is a TLS limit, not a sandbox capacity limit. Sandbox capacity is determined entirely by the host's CPU and memory. DNS-01 issues exactly **two** certs total (`<domain>` + `*.<domain>`) regardless of how many sandboxes exist, so it scales indefinitely and is required for any real workload.

If you omit `--pat-token`, the installer generates a token and prints it once at the end.

## Domain and DNS

Set `--domain` to the base hostname for your installation. Sandbox public URLs are formed as:

```
https://<sandbox-id>.<domain>
```

Exposed ports get separate URLs:

```
https://<sandbox-id>-<port>.<domain>
```

Required DNS records (both are needed):

```
A     sandbox.example.com   →  <server-ip>
A     *.sandbox.example.com →  <server-ip>
```

When domain mode is active, the control-plane API is also served at `https://<domain>/v1/...`.

## Firewall / Security Groups

Open the following inbound TCP ports on your host (EC2 security group, bare-metal firewall, etc.) before running the installer:

| Port | Protocol | Required for | Notes |
|---|---|---|---|
| `80` | TCP | HTTP-01 ACME challenges + HTTPS redirect | Not needed if using DNS-01 wildcard TLS only. |
| `443` | TCP | HTTPS - REST API and sandbox preview URLs | Primary public-facing port in production. |
| `2220` | TCP | SSH gateway - SSH access into sandboxes | Configurable via `SB_SSH_LISTEN_ADDR`. |

Port `8080` is the internal API port (default `SB_API_PORT`). In production Caddy proxies it - you do **not** need to expose `8080` publicly. In local dev mode (no Caddy) you reach the API directly on `8080`.

Port `2019` (Caddy Admin API) is bound to `127.0.0.1` only and must never be publicly exposed.

## Wildcard TLS via DNS-01 (Cloudflare)

Pass `--dns-provider cloudflare --dns-api-token <token>` to the installer. Caddy issues exactly two certificates and renews them on a schedule regardless of how many sandboxes exist.

Cloudflare token permissions required:
- Zone → Zone → Read
- Zone → DNS → Edit

Create a scoped token (not the legacy Global API Key) restricted to the target zone.

## Container Runtimes

| Runtime | Installer flag | Notes |
|---|---|---|
| Docker (default) | - | Lowest overhead. Suitable for trusted workloads. |
| gVisor | `--with-gvisor` | User-space kernel between the workload and the host. Recommended for untrusted code (LLM-generated, third-party submissions). |
| Kata Containers | - | Planned. Create requests return `runtime not yet implemented`. |

Install with gVisor support:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --domain sandbox.example.com \
    --pat-token your-secret-pat \
    --with-gvisor
```

Select the runtime per sandbox at create time:

```bash
curl -X POST $SB_API_URL/v1/sandboxes \
  -H "Authorization: Bearer $SB_PAT_TOKEN" \
  -d '{"image":"alpine","runtime":"gvisor"}'
```

Or set a host-level default:

```bash
export SB_CONTAINER_RUNTIME=gvisor
```

**gVisor limitations:**
- Incompatible with `--privileged` containers.
- `disk_gb` quota is silently ignored (CPU and memory caps still apply).
- Requires cgroupv2 + systemd on the host.

## Local Development

To run the server locally without the installer:

```bash
make build

export SB_PAT_TOKEN=dev-token
export SB_DB_PATH=$PWD/sandbox.db
export SB_PUBLIC_HOST=127.0.0.1

./bin/aerolvm
```

Required services: Docker daemon and Caddy with the Admin API enabled at `http://localhost:2019`.

## Next Steps

- [SDK Setup](/sdk-setup) - connect an SDK to the running server
- [Sandboxes](/sandboxes) - create and manage sandboxes
