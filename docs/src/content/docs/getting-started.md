title: Getting Started

## Build

```bash
make build
```

This produces the server binary in `bin/`.

## Required Services

- Docker daemon
- Caddy with the Admin API enabled on `http://localhost:2019`

## Minimal Environment

```bash
export SB_PAT_TOKEN=dev-token
export SB_DB_PATH=$PWD/sandbox.db
export SB_PUBLIC_HOST=127.0.0.1

./bin/aerolvm
```

If `SB_DOMAIN` is set, sandbox routes are created as subdomains like `https://<sandbox-id>.<domain>`. If `SB_DOMAIN` is empty, the server falls back to path-based URLs like `http://<public-host>/<sandbox-id>/`.

## API Surface

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

## Local Workflow

1. Build the server.
2. Start Caddy with the admin API exposed locally.
3. Export the required environment variables.
4. Launch the server binary.
5. Use one of the SDKs to create and control sandboxes.
