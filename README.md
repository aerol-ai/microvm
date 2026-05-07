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

Artifacts:

- `bin/sandboxd`
- `bin/toolboxd`

## Run locally

Required services:

- Docker daemon
- Caddy with Admin API enabled on `http://localhost:2019`

Minimal environment:

```bash
export SB_API_TOKEN=dev-token
export SB_DB_PATH=$PWD/sandbox.db
export SB_PUBLIC_HOST=127.0.0.1
export SB_TOOLBOX_BINARY_PATH=$PWD/bin/toolboxd

./bin/sandboxd
```

If `SB_DOMAIN` is set, sandbox routes are created as subdomains like `https://<sandbox-id>.<domain>`. If `SB_DOMAIN` is empty, the daemon falls back to path-based URLs like `http://<public-host>/<sandbox-id>/`.

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

All `/v1` endpoints except `/v1/tls-check` require `Authorization: Bearer <SB_API_TOKEN>`.