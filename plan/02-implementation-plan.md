# Implementation Plan: sandbox-library

## Overview

`sandbox-library` is a standalone Go monorepo that ships as a single binary (`sandboxd`) plus a Go SDK package. It reuses Daytona runner's Docker management code and integrates Caddy's Admin API for dynamic HTTPS routing. No Daytona cloud API is required.

---

## Repository Layout

```
sandbox-library/
├── cmd/
│   └── sandboxd/
│       └── main.go                  # Entry point: wires all services, handles signals
│
├── internal/
│   ├── config/
│   │   └── config.go                # Config struct: env vars + CLI flags (envconfig)
│   ├── store/
│   │   ├── store.go                 # SQLite-backed state store (sandbox metadata)
│   │   └── migrations/
│   │       └── 001_init.sql         # Initial schema
│   └── version/
│       └── version.go               # Build-time version injection
│
├── pkg/
│   ├── docker/
│   │   ├── client.go                # DockerClient wrapper (init, ping, network setup)
│   │   ├── create.go                # CreateSandbox: pull image, create container, start
│   │   ├── start.go                 # StartSandbox: start stopped container, wait for daemon
│   │   ├── stop.go                  # StopSandbox: graceful stop with retry
│   │   ├── destroy.go               # DestroySandbox: remove container + cleanup
│   │   ├── resize.go                # ResizeSandbox: update cgroup limits
│   │   ├── state.go                 # GetSandboxState: inspect container, map to enum
│   │   ├── ports.go                 # Port allocation helpers
│   │   ├── monitor.go               # DockerMonitor: listen for Docker events
│   │   ├── image_pull.go            # PullImage: with registry auth support
│   │   └── netrules/
│   │       └── manager.go           # iptables rule manager (NetworkBlockAll, AllowList)
│   │
│   ├── caddy/
│   │   ├── client.go                # Caddy Admin API client (localhost:2019)
│   │   ├── routes.go                # AddRoute / RemoveRoute / ListRoutes
│   │   └── config.go                # Caddy JSON config helpers (upstream, matcher)
│   │
│   ├── api/
│   │   ├── server.go                # Gin HTTP server setup, middleware registration
│   │   ├── middleware/
│   │   │   └── auth.go              # Bearer token auth middleware
│   │   └── handlers/
│   │       ├── sandbox.go           # Create/Get/List/Start/Stop/Destroy/Resize handlers
│   │       ├── health.go            # GET /health
│   │       └── proxy.go             # Toolbox proxy (forward to container daemon)
│   │
│   ├── sshgateway/
│   │   ├── gateway.go               # SSH server: authenticate by sandbox ID, proxy to container
│   │   └── config.go                # SSH host key generation/loading
│   │
│   ├── daemon/
│   │   └── embed.go                 # Embed Daytona toolbox daemon binary (daemon-amd64)
│   │
│   ├── idlemonitor/
│   │   └── monitor.go               # Track last activity per sandbox, auto-stop on idle
│   │
│   └── sync/
│       └── reconciler.go            # On startup: reconcile SQLite state with Docker reality
│
├── sdk/
│   └── go/
│       ├── internal/
│       │   └── apiclient/client.go  # Internal HTTP transport for the structured SDK
│       └── pkg/
│           ├── microvm/client.go    # Public SDK entrypoint: NewClient()/NewClientWithConfig()
│           └── types/
│               ├── config.go        # MicroVMConfig
│               └── types.go         # Sandbox, CreateSandboxOptions, ResizeSandboxOptions, ExecResult
│
├── scripts/
│   ├── install.sh                   # Main install script (Docker + Caddy + sandboxd)
│   └── uninstall.sh                 # Teardown script
│
├── packaging/
│   ├── sandboxd.service             # systemd unit file
│   ├── Caddyfile.template           # Caddy base config template
│   └── .env.template                # Environment variable template
│
├── go.mod
├── go.sum
└── Makefile                         # build, lint, test, install targets
```

---

## Component Details

### 1. `cmd/sandboxd/main.go`

Startup sequence (mirrors Daytona runner's startup order):

```
1. Load Config (env vars / .env file)
2. Open SQLite store
3. Initialize Docker client
4. Initialize netrules manager (iptables)
5. Embed and write daemon binary to temp dir
6. Start Docker event monitor
7. Run reconciler (sync SQLite ↔ Docker state)
8. Start idle monitor (if IdleTimeoutMin > 0)
9. Start SSH gateway (port 2220)
10. Start HTTP API server (port 8080)
11. Wait for SIGTERM/SIGINT → graceful shutdown
```

**Key env vars consumed:**

| Variable | Default | Purpose |
|---|---|---|
| `SB_PAT_TOKEN` | (required) | Bearer token for API auth |
| `SB_API_PORT` | `8080` | HTTP API port |
| `SB_DOMAIN` | `""` | Base domain (e.g. `sandbox.aerol.ai`). Empty = IP mode |
| `SB_CADDY_ADMIN_URL` | `http://localhost:2019` | Caddy admin endpoint |
| `SB_SSH_PORT` | `2220` | SSH gateway port |
| `SB_DB_PATH` | `/var/lib/sandboxd/state.db` | SQLite path |
| `SB_IDLE_TIMEOUT_MIN` | `0` (disabled) | Auto-stop idle sandboxes after N minutes |
| `SB_RESOURCE_LIMITS_DISABLED` | `false` | Disable cgroup limits (for dev) |

---

### 2. `internal/store/store.go`

SQLite schema:

```sql
CREATE TABLE sandboxes (
    id              TEXT PRIMARY KEY,
    image           TEXT NOT NULL,
    status          TEXT NOT NULL,  -- creating|started|stopped|destroyed|error
    public_url      TEXT,
    container_ip    TEXT,
    cpu_quota       INTEGER,
    memory_quota_mb INTEGER,
    disk_quota_gb   INTEGER,
    os_user         TEXT DEFAULT 'root',
    env_json        TEXT,           -- JSON-encoded map[string]string
    labels_json     TEXT,           -- JSON-encoded map[string]string
    network_blocked INTEGER DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

Store interface:

```go
type Store interface {
    Create(ctx, *Sandbox) error
    Get(ctx, id string) (*Sandbox, error)
    List(ctx) ([]*Sandbox, error)
    UpdateStatus(ctx, id, status string) error
    UpdateContainerIP(ctx, id, ip string) error
    Delete(ctx, id string) error
}
```

---

### 3. `pkg/docker/` — Sandbox Lifecycle

Adapted directly from `daytona/apps/runner/pkg/docker/` with these changes:
- Remove dependency on `github.com/daytonaio/daytona/libs/api-client-go` (no job polling needed).
- Remove `BackupInfoCache`, `SnapshotErrorCache`, `poller`, `healthcheck` — not needed.
- Remove `daemon.WriteStaticBinary` for computer-use plugin — optional, add only toolbox daemon.
- Keep: `create.go`, `start.go`, `stop.go`, `destroy.go`, `resize.go`, `state.go`, `monitor.go`, `image_pull.go`, `netrules/manager.go`.

**CreateSandbox flow (adapted):**

```
1. Pull Docker image (with optional registry auth)
2. Write toolbox daemon binary into container via bind mount
3. Create Docker container
  - Entrypoint: ["/tmp/.sandboxd/daemon", "--port", "41100"]
  - Env: SB_TOOLBOX_PORT, SB_TOOLBOX_TOKEN
  - Labels: sandbox-library managed
  - Resource limits: CPU shares, memory limit, disk quota
4. Derive sandbox ID from the Docker short ID (first 12 chars of the created container ID)
5. Start container
6. Wait for toolbox daemon health (GET /health on container IP:41100)
7. Call caddy.AddRoute(sandboxID, containerIP, 41100, domain)
8. Persist sandbox ID + full container ID mapping to SQLite
9. Return sandbox ID + public URL
```

**Container toolbox port:** `41100` (Daytona daemon port, configurable).

---

### 4. `pkg/caddy/` — Dynamic HTTPS Routing

Uses Caddy's [Admin API](https://caddyserver.com/docs/api) (`POST /config/apps/http/servers/sandbox/routes`).

**Route added per sandbox (domain mode):**

```json
{
  "match": [{"host": ["<sandbox-id>.sandbox.aerol.ai"]}],
  "handle": [{
    "handler": "reverse_proxy",
    "upstreams": [{"dial": "<container-ip>:41100"}]
  }]
}
```

**Port exposure (`ExposePort`):**

```json
{
  "match": [{"host": ["<sandbox-id>-<port>.sandbox.aerol.ai"]}],
  "handle": [{
    "handler": "reverse_proxy",
    "upstreams": [{"dial": "<container-ip>:<port>"}]
  }]
}
```

**IP mode (no domain):**

```json
{
  "match": [{"path": ["/<sandbox-id>/*"]}],
  "handle": [{
    "handler": "reverse_proxy",
    "upstreams": [{"dial": "<container-ip>:41100"}]
  }]
}
```

In IP mode, the mounted toolbox daemon strips the `/<sandbox-id>` prefix itself.

**TLS:** Caddy auto-manages Let's Encrypt certs for `*.sandbox.aerol.ai` when a wildcard DNS is configured. For IP mode, no TLS (HTTP only).

---

### 5. `pkg/api/` — REST API

**Base URL:** `http(s)://<server>/v1`

**Auth:** `Authorization: Bearer <SB_PAT_TOKEN>`

**Endpoints:**

| Method | Path | Handler | Description |
|---|---|---|---|
| `GET` | `/health` | `handlers.Health` | Service health check |
| `POST` | `/v1/sandboxes` | `handlers.Create` | Create + start sandbox |
| `GET` | `/v1/sandboxes` | `handlers.List` | List all sandboxes |
| `GET` | `/v1/sandboxes/:id` | `handlers.Get` | Get sandbox info |
| `POST` | `/v1/sandboxes/:id/start` | `handlers.Start` | Start a stopped sandbox |
| `POST` | `/v1/sandboxes/:id/stop` | `handlers.Stop` | Stop a running sandbox |
| `DELETE` | `/v1/sandboxes/:id` | `handlers.Destroy` | Destroy sandbox |
| `POST` | `/v1/sandboxes/:id/resize` | `handlers.Resize` | Update resource limits |
| `POST` | `/v1/sandboxes/:id/ports/:port` | `handlers.ExposePort` | Expose container port |
| `DELETE` | `/v1/sandboxes/:id/ports/:port` | `handlers.UnexposePort` | Remove port route |
| `ANY` | `/v1/sandboxes/:id/toolbox/*path` | `handlers.Proxy` | Proxy to toolbox daemon |

**Create request body:**

```json
{
  "image": "ubuntu:22.04",
  "cpu": 2,
  "memory_mb": 2048,
  "disk_gb": 10,
  "env": {"KEY": "VALUE"},
  "os_user": "root",
  "network_block_all": false,
  "registry": {
    "server": "ghcr.io",
    "username": "user",
    "password": "token"
  }
}
```

**Create response:**

```json
{
  "id": "3f7a1bc2-...",
  "status": "started",
  "public_url": "https://3f7a1bc2.sandbox.aerol.ai",
  "created_at": "2026-05-07T10:00:00Z"
}
```

---

### 6. `pkg/sshgateway/gateway.go`

Adapted from `daytona/apps/runner/pkg/sshgateway/service.go`:
- SSH server listens on `SB_SSH_PORT` (default 2220).
- Auth: username = `<sandbox-id>`, authenticate using `SB_SSH_PUBLIC_KEY`.
- On connection: inspect Docker container IP, proxy SSH session to `container:22` (or toolbox SSH port `41101`).

---

### 7. `sdk/go/` — Go SDK

```go
import (
  "os"

  microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
  "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

client, err := microvm.NewClientWithConfig(&types.MicroVMConfig{
  PATToken: os.Getenv("SB_PAT_TOKEN"),
  APIUrl:   "http://localhost:8080",
})

// Create
sb, err := client.Create(ctx, types.CreateSandboxOptions{
    Image:    "python:3.12",
    CPU:      2,
    MemoryMB: 4096,
    Env:      map[string]string{"PYTHONPATH": "/workspace"},
})

// Exec (proxied through toolbox daemon)
result, err := sb.ExecCommand(ctx, "python3 -c 'print(42)'")

// Files
err = sb.UploadFile(ctx, "/workspace/script.py", data)
data, err := sb.DownloadFile(ctx, "/workspace/output.json")

// Expose port
url, err := sb.ExposePort(ctx, 3000)

// Lifecycle
err = sb.Stop(ctx)
err = sb.Start(ctx)
err = sb.Destroy(ctx)
```

---

### 8. `scripts/install.sh`

```bash
#!/bin/bash
# Usage: curl -sSL https://get.aerol.ai | bash -s -- --domain sandbox.aerol.ai --pat-token mytoken

# 1. Detect OS (Ubuntu/Debian/RHEL)
# 2. Install Docker (if absent)
# 3. Install Caddy (if absent) — systemd service
# 4. Write /etc/caddy/Caddyfile with wildcard matcher + admin API enabled
# 5. Download sandboxd binary from GitHub releases (or build from source)
# 6. Write /etc/sandboxd/sandboxd.env with SB_DOMAIN, SB_PAT_TOKEN, etc.
# 7. Write /etc/systemd/system/sandboxd.service
# 8. systemctl daemon-reload && systemctl enable --now sandboxd caddy
# 9. Print summary: API URL, SSH endpoint, public URL pattern
```

`Caddyfile.template`:

```caddyfile
{
    admin localhost:2019
    email admin@{DOMAIN}
}

*.{DOMAIN} {
    tls {
        dns {DNS_PROVIDER} {DNS_API_TOKEN}
    }
    # Routes are managed dynamically via Admin API
    # Caddy serves as a catch-all; specific routes added by sandboxd
    respond "Sandbox not found" 404
}
```

For IP mode (no domain), Caddy runs on port 80 with path-based routing:

```caddyfile
{
    admin localhost:2019
}

:{HTTP_PORT} {
    # All routes managed dynamically
    respond "Sandbox not found" 404
}
```

---

### 9. `pkg/sync/reconciler.go`

On `sandboxd` startup:

```
For each sandbox in SQLite:
  - Inspect Docker: does container exist?
    - Yes, running → update status=started, refresh container IP, re-register Caddy route
    - Yes, stopped → update status=stopped
    - No → update status=destroyed, delete Caddy route
For each Docker container labeled "sandbox-library":
  - If not in SQLite → create record (orphan recovery)
```

---

### 10. `packaging/sandboxd.service`

```ini
[Unit]
Description=sandbox-library daemon
After=docker.service caddy.service
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=/etc/sandboxd/sandboxd.env
ExecStart=/usr/local/bin/sandboxd
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Go Module

```
module github.com/aerol-ai/microvm

go 1.22
```

**Key dependencies:**

| Package | Use |
|---|---|
| `github.com/docker/docker` | Docker SDK |
| `github.com/gin-gonic/gin` | HTTP API framework |
| `github.com/mattn/go-sqlite3` | SQLite state store |
| Docker container short ID | Sandbox ID generation |
| `github.com/coreos/go-iptables` | Network isolation rules |
| `golang.org/x/crypto/ssh` | SSH gateway |
| `github.com/google/go-containerregistry` | Image pulling with auth |
| `github.com/kelseyhightower/envconfig` | Env var config loading |
| `github.com/go-playground/validator/v10` | Config validation |

---

## Ports Summary

| Port | Service | Notes |
|---|---|---|
| `80` | Caddy (HTTP) | IP mode or HTTP redirect |
| `443` | Caddy (HTTPS) | Domain mode with TLS |
| `2019` | Caddy Admin API | Internal only (localhost) |
| `2220` | SSH gateway | SSH into sandboxes |
| `8080` | sandboxd REST API | Authenticated API |
| `41100` | Toolbox daemon | Per-container (not exposed externally) |

---

## Build & Release

```makefile
build:
    go build -ldflags "-X internal/version.Version=$(shell git describe --tags)" \
        -o bin/sandboxd ./cmd/sandboxd

test:
    go test ./...

lint:
    golangci-lint run

release:
    goreleaser release
```

Binary is a single static Go binary. Distributed via GitHub Releases.
