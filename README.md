# sandbox-library

`sandbox-library` turns a single Linux host into a sandbox runner with a small control-plane API, Docker-backed container lifecycle management, and dynamic Caddy routes for public access.

This repository ships two binaries:

- `sandboxd`: host daemon that manages Docker, persisted state, public routing, and the REST API.
- `toolboxd`: a lightweight in-container process mounted into each sandbox to provide health, command execution, file transfer, and local port proxying.

## Current scope

The implementation in this repository covers the core single-node workflow:

- create, list, inspect, start, stop, destroy, and resize sandboxes
- expose extra HTTP ports publicly through Caddy
- proxy toolbox requests through the host API
- persist sandbox state in SQLite and reconcile it on restart
- optional idle auto-stop and basic egress blocking
- Go SDK for the common control-plane operations

The original plan referenced embedding Daytona's toolbox daemon. This implementation keeps the same runner-style host/container split but uses a local `toolboxd` binary that is built from this repo and mounted into containers. That makes the repo self-contained and avoids depending on missing prebuilt Daytona assets.

## Build

```bash
make build
```

## Docs Site

The root [docs](/Users/sumansaurabh/Documents/startup-3/sandbox-library/docs) folder now contains a standalone Astro + Starlight docs app themed after the Daytona docs framework, but populated with this repository's content.

Install and run it with:

```bash
make docs-install
make docs-dev
```

Create a production build with:

```bash
make docs-build
```

Artifacts:

- `bin/sandboxd`
- `bin/toolboxd`

## Releases

Publishing a GitHub Release, or pushing a tag that starts with `v`, triggers the GitHub Actions release workflow in `.github/workflows/release.yml`.

The workflow publishes these release assets:

- `sandboxd_linux_amd64`
- `toolboxd_linux_amd64`
- `sandboxd_linux_arm64`
- `toolboxd_linux_arm64`
- `install.sh`
- `checksums.txt`

The assets are downloadable directly from the latest published release:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- --domain sandbox.example.com --pat-token your-secret-pat
```

Examples:

```text
https://github.com/aerol-ai/microvm/releases/latest/download/install.sh
https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64
https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_arm64
https://github.com/aerol-ai/microvm/releases/latest/download/toolboxd_linux_amd64
https://github.com/aerol-ai/microvm/releases/latest/download/toolboxd_linux_arm64
https://github.com/aerol-ai/microvm/releases/latest/download/checksums.txt
```

Only Linux amd64 and arm64 binaries are published today, because the host installer and runtime are Linux-only.

The installer defaults to downloading the latest GitHub release from `aerol-ai/microvm`. You can pin a specific release with `--version vX.Y.Z` or override the repository with `--github-repo owner/repo`.

The installer accepts `--pat-token <token>` and stores it in `/etc/sandboxd/sandboxd.env` as `SB_PAT_TOKEN` with `0600` permissions. If you omit `--pat-token`, the installer generates one automatically and prints it once at the end.

The installer writes `sandboxd.service` with `Restart=always` and enables `sandboxd-healthcheck.timer`, which probes the local `/health` endpoint every 30 seconds and restarts `sandboxd` if the process is up but no longer responding.

## Domain and DNS

If you install with `--domain <domain>`, the value is used literally as the sandbox host suffix. That means all of these are valid:

- `sandbox.aerol.ai`
- `aerol.ai`
- `sandbox.example.com`

For newly created sandboxes, the public hostname is:

- `https://<docker-short-id>.<domain>`

For exposed application ports, the public hostname is:

- `https://<docker-short-id>-<port>.<domain>`

Examples:

- If `--domain sandbox.aerol.ai`, sandbox URLs look like `https://7f3c2a1b9d4e.sandbox.aerol.ai`
- If `--domain aerol.ai`, sandbox URLs look like `https://7f3c2a1b9d4e.aerol.ai`

Both `sandbox.aerol.ai` and `aerol.ai` work with the current codebase. No code change is required for either shape.

When domain mode is enabled, the root domain also serves the control-plane API:

- `https://<domain>/health`
- `https://<domain>/v1/...`

That means an install with `--domain sandbox.aerol.ai` creates sandboxes through `https://sandbox.aerol.ai/v1/sandboxes`, and each created sandbox receives its own public URL like `https://<docker-short-id>.sandbox.aerol.ai`.

Required DNS records:

- `A sandbox.aerol.ai -> <server-ip>`
- `A *.sandbox.aerol.ai -> <server-ip>`

Or, for IPv6:

- `AAAA sandbox.aerol.ai -> <server-ipv6>`
- `AAAA *.sandbox.aerol.ai -> <server-ipv6>`

If you use `aerol.ai` instead, the equivalent records are:

- `A aerol.ai -> <server-ip>`
- `A *.aerol.ai -> <server-ip>`

Why both records are needed:

- `<domain>` itself is included in the generated Caddy site block
- `*.<domain>` is needed so per-sandbox and per-port hostnames resolve to the server

Operational notes:

- Use DNS-only records for initial setup if your DNS provider offers HTTP proxying, because Caddy is handling ACME and TLS issuance directly.
- The wildcard DNS record is for hostname resolution. By default the installer configures Caddy on-demand TLS, which issues one Let's Encrypt cert per concrete hostname on first hit. That works for trial-scale deployments only — Let's Encrypt caps you at 50 certs/week per registered domain.

### Wildcard TLS via DNS-01 (recommended for production)

For any deployment that creates more than a handful of sandboxes, pass `--dns-provider cloudflare --dns-api-token <token>` to `install.sh`. The installer then replaces the apt-installed Caddy binary with a custom build that includes the `caddy-dns/cloudflare` plugin and writes a Caddyfile that solves ACME via DNS-01. Caddy issues exactly two certs (`<domain>` and `*.<domain>`) and renews them on a schedule, regardless of how many sandboxes are created.

Cloudflare API token scope: create a scoped token (not the legacy Global API Key) with permissions:

- Zone → Zone → Read on the target zone
- Zone → DNS → Edit on the target zone

The token is written to `/etc/default/caddy` (mode 0600) and read by Caddy via `{env.SB_DNS_API_TOKEN}` substitution.

Other DNS providers (Route53, DigitalOcean, etc.) can be added by extending the `case "$DNS_PROVIDER"` switch in `scripts/install.sh` — Caddy's build server (`caddyserver.com/api/download`) supports any [`caddy-dns/*`](https://github.com/caddy-dns) plugin.

## Run locally

Required services:

- Docker daemon
- Caddy with Admin API enabled on `http://localhost:2019`

Minimal environment:

```bash
export SB_PAT_TOKEN=dev-token
export SB_DB_PATH=$PWD/sandbox.db
export SB_PUBLIC_HOST=127.0.0.1
export SB_TOOLBOX_BINARY_PATH=$PWD/bin/toolboxd

./bin/sandboxd
```

If `SB_DOMAIN` is set, sandbox routes are created as subdomains like `https://<sandbox-id>.<domain>`. If `SB_DOMAIN` is empty, the daemon falls back to path-based URLs like `http://<public-host>/<sandbox-id>/`. For newly created sandboxes, `<sandbox-id>` is the Docker short ID: the first 12 characters of the full container ID.

## API summary

- `GET /health`
- `POST /v1/sandboxes`
- `GET /v1/sandboxes`
- `GET /v1/sandboxes/{id}`
- `POST /v1/sandboxes/{id}/start`
- `POST /v1/sandboxes/{id}/stop`
- `DELETE /v1/sandboxes/{id}`
- `POST /v1/sandboxes/{id}/resize`
- `POST /v1/sandboxes/{id}/ports/{port}`
- `DELETE /v1/sandboxes/{id}/ports/{port}`
- `ANY /v1/sandboxes/{id}/toolbox/{path...}`
- `GET /v1/tls-check?domain=<host>`

All `/v1` endpoints except `/v1/tls-check` require `Authorization: Bearer <SB_PAT_TOKEN>`.

## SDK auth

Both SDKs send the PAT as `Authorization: Bearer <token>`.

Go:

```go
import (
	"os"

	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	"github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

client, err := microvm.NewClientWithConfig(&types.MicroVMConfig{
	PATToken: os.Getenv("SB_PAT_TOKEN"),
	APIUrl:   "https://sandbox-api.example.com",
})
```

TypeScript:

```ts
import { MicroVM } from "@aerol-ai/microvm-sdk";

const client = new MicroVM({
	apiUrl: "https://sandbox.example.com",
	patToken: process.env.SB_PAT_TOKEN,
});
```

Python:

```py
from microvm import MicroVM

client = MicroVM(api_url="https://sandbox.example.com", pat_token="${SB_PAT_TOKEN}")
```

Rust:

```rust
use microvm_sdk::Client;

let client = Client::new(Some("https://sandbox.example.com"), Some("your_token"))?;
```
