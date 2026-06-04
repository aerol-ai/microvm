# AerolVM

[![Tests](https://github.com/aerol-ai/microvm/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/aerol-ai/microvm/actions/workflows/test.yml)
[![Coverage](https://codecov.io/gh/aerol-ai/microvm/branch/main/graph/badge.svg)](https://codecov.io/gh/aerol-ai/microvm)
[![Release](https://github.com/aerol-ai/microvm/actions/workflows/release.yml/badge.svg?event=release)](https://github.com/aerol-ai/microvm/actions/workflows/release.yml)
[![Publish SDKs](https://github.com/aerol-ai/microvm/actions/workflows/publish-sdks.yml/badge.svg)](https://github.com/aerol-ai/microvm/actions/workflows/publish-sdks.yml)

AerolVM is a self-hosted platform for creating isolated Docker-backed sandboxes on a single Linux host. This repository contains the server, installer, SDKs, and documentation you use to provision a host, create containers, expose preview URLs, and manage sandboxes over an API.

## Start Here

| Guide | Description |
|---|---|
| [Quick Start](docs/src/content/docs/quick-start.md) | Spin up a sandbox and run a command in under five minutes. |
| [Server Setup](docs/src/content/docs/getting-started.md) | Install and configure AerolVM on a Linux host. |
| [SDK Setup](docs/src/content/docs/sdk-setup.md) | Connect an SDK to your AerolVM server. |

## Install a Server

**Local Setup** :

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --local \
    --pat-token your-secret-pat
```

**Production** (DNS-01 wildcard TLS via Cloudflare):

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --domain sandbox.example.com \
    --pat-token your-secret-pat \
    --dns-provider cloudflare \
    --dns-api-token your-cloudflare-api-token
```

> **`--domain` requires `--dns-provider`.** The installer hard-fails otherwise. Caddy issues exactly two certificates — `<domain>` and `*.<domain>` — once at startup via DNS-01, then renews them on a schedule. Use `--local` for the only no-DNS path (binds to `127.0.0.1`, no TLS).

> **Running 10+ ingress nodes?** Opt into S3-backed shared Caddy cert storage so one node issues the wildcard and the rest read it from S3 — see [`setup/multi-node-cert-sharing.md`](./setup/multi-node-cert-sharing.md). Off by default.

If you omit `--pat-token`, the installer generates a token and prints it once at the end.

## What AerolVM Does

- Creates isolated sandboxes backed by Docker on your own infrastructure.
- Exposes sandbox URLs as `https://<sandbox-id>.<domain>` and port URLs as `https://<sandbox-id>-<port>.<domain>`.
- Provides a PAT-authenticated REST API and SDKs for TypeScript, Python, Go, Java, and Rust.
- Supports Docker by default and gVisor as an opt-in runtime for untrusted code.
- Uses Caddy for TLS termination and public routing on a single Linux host.

## SDK Example

```ts
import { MicroVM } from '@aerol-ai/aerolvm-sdk'

const client = new MicroVM({
  apiUrl: process.env.SB_API_URL,
  patToken: process.env.SB_PAT_TOKEN,
})

const sandbox = await client.create({ image: 'ubuntu:22.04' })
console.log(sandbox.publicUrl)
await sandbox.destroy()
```

## Runtime Options

| Runtime | Status | Notes |
|---|---|---|
| Docker | Available | Default runtime with the lowest overhead. |
| gVisor | Available | Install with `--with-gvisor` for stronger isolation. |
| Kata Containers | Planned | Create requests return `runtime not yet implemented`. |
| Firecracker | Available | MicroVM runtime for fast, secure isolation. |

Install with gVisor support:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --domain sandbox.example.com \
    --pat-token your-secret-pat \
    --with-gvisor
```

## Develop and Test

```bash
make install-git-hooks
make build
make test
make docs-install
make docs-dev
```

Run `make install-git-hooks` once per clone to enable the repo-managed pre-commit hook. It formats staged Go files with `gofmt` and re-stages them before the commit completes.

## License

[MIT](LICENSE)
