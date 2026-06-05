&nbsp;

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/aerol-ai/microvm/raw/main/docs/public/aerol-logo.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/aerol-ai/microvm/raw/main/docs/public/aerol-logo.svg">
    <img alt="AerolVM logo" src="https://github.com/aerol-ai/microvm/raw/main/docs/public/aerol-logo.svg" width="45%">
  </picture>
</div>

<h3 align="center">
  Run Untrusted Code Safely.<br/>
  Self-Hosted Sandbox Infrastructure for AI Agents and Ephemeral Workloads.
</h3>

<p align="center">
  <a href="https://microvm.aerol.ai">Documentation</a> ·
  <a href="https://microvm.aerol.ai/getting-started">Quick Start</a> ·
  <a href="https://github.com/aerol-ai/microvm/issues/new?labels=bug&template=bug_report.md">Report Bug</a> ·
  <a href="https://github.com/aerol-ai/microvm/issues/new?labels=enhancement&template=feature_request.md">Request Feature</a>
</p>

<p align="center">
  <a href="https://github.com/aerol-ai/microvm/actions/workflows/test.yml"><img src="https://github.com/aerol-ai/microvm/actions/workflows/test.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="https://codecov.io/gh/aerol-ai/microvm"><img src="https://codecov.io/gh/aerol-ai/microvm/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/aerol-ai/microvm/actions/workflows/release.yml"><img src="https://github.com/aerol-ai/microvm/actions/workflows/release.yml/badge.svg?event=release" alt="Release"></a>
  <a href="https://github.com/aerol-ai/microvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

&nbsp;

AerolVM is open-source, self-hosted sandbox infrastructure for running isolated code environments on your own Linux host. Each sandbox is a fully isolated compute unit with its own filesystem, network namespace, and allocated vCPU, RAM, and disk - spinning up in **under 60ms** and supporting Docker, gVisor, and Firecracker runtimes. Built for AI agent pipelines and ephemeral CI, it ships as a single Go binary backed by Caddy for TLS routing and SQLite for state, with no external dependencies and a one-line installer.

## Features

AerolVM provides a complete surface for building sandbox-backed products and agent workflows.

| Sandboxes | Execution | Networking & Ports | Storage & Secrets | Platform & Cluster |
| :--- | :--- | :--- | :--- | :--- |
| [Lifecycle (create / start / stop / destroy)](https://microvm.aerol.ai/sandboxes) | [Streaming exec & PTY](https://microvm.aerol.ai/exec-streaming) | [HTTP preview URLs](https://microvm.aerol.ai/preview) | [External storage (S3, NFS, SSHFS, rclone)](https://microvm.aerol.ai/external-storage) | [Raft-coordinated cluster](https://microvm.aerol.ai/cluster-setup) |
| [Environment & resource limits](https://microvm.aerol.ai/environment) | [Persistent PTY sessions w/ replay](https://microvm.aerol.ai/sessions) | [TCP port exposure](https://microvm.aerol.ai/tcp-ports) | [Encrypted sandbox secrets](https://microvm.aerol.ai/environment) | [HA failover & durability](https://microvm.aerol.ai/durability) |
| [Snapshots (stop-start persistence)](https://microvm.aerol.ai/snapshots) | [SSH access per sandbox](https://microvm.aerol.ai/ssh-access) | [TLS + SNI port routing](https://microvm.aerol.ai/tcp-vs-tls-ports) | [Custom domains](https://microvm.aerol.ai/custom-domains) | [Cluster ingress topology](https://microvm.aerol.ai/cluster-ingress) |
| [Multi-runtime (Docker / gVisor / Firecracker)](https://microvm.aerol.ai/sandboxes) | [File system operations](https://microvm.aerol.ai/file-system) | [Per-sandbox egress control](https://microvm.aerol.ai/network-isolation) | [Sandbox tags & tenant scoping](https://microvm.aerol.ai/sandbox-tags) | [Reconciler & self-healing](https://microvm.aerol.ai/reconcile) |
| [GPU sandboxes](https://microvm.aerol.ai/gpu-sandboxes) | [Port allowlist](https://microvm.aerol.ai/port-allowlist) | [Per-sandbox network quotas](https://microvm.aerol.ai/network-usage) | [Dashboard](https://microvm.aerol.ai/dashboard) | [Operational runbooks](https://microvm.aerol.ai/operational-runbooks) |

## Why AerolVM

AerolVM beats the two most common alternatives on the axes that matter most for AI workloads: **isolation**, **cost**, and **operational simplicity**.

| | AerolVM | e2b | Daytona |
| :--- | :--- | :--- | :--- |
| **Self-hosted** | ✅ Single binary, one-line install | ✗ Cloud only | ✅ Complex multi-component setup |
| **Runs locally** | ✅ `--local` flag, no DNS needed | ✗ | ✗ |
| **Sandbox startup** | < 90ms | ~200ms | < 90ms |
| **Runtime isolation** | ✅ Docker, gVisor (user-space kernel), Firecracker (microVM) | Firecracker (microVM) | Docker only |
| **Sandbox lifetime** | Unlimited | 1 day | Unlimited |
| **Serveless Sandbox(based on Lambda Arch)** | ✅ | ✗ | ✗ |
| **TCP + TLS port routing** | ✅ | ✗ | ✗ |
| **Per-sandbox egress control** | ✅ | ✗ | ✗ |
| **External storage** | ✅ S3 / NFS / SSHFS / rclone | ✗ | ✗ |
| **GPU support** | ✅ | ✗ | ✗ |
| **HA cluster mode** | ✅ Raft + SWIM gossip | Managed (opaque) | ✗ |
| **Drop-in SDK compat** | ✅ `/daytona` and `/e2b` facades | ✗ | ✗ |
| **Price (100 × 2vCPU/4GB sandboxes/mo)** | ~$4,000 on your infra | ~$12,000 | ~$12,000 |
| **SDK languages** | TS, Python, Go, Rust, Java | TS, Python | TS, Python, Ruby, Go, Java |
| **Open source** | ✅ MIT | ✗ | ✅ AGPL |

[See the full comparison →](https://microvm.aerol.ai/comparison)

### vs e2b

e2b is the fastest managed path if you want zero infrastructure, but it means your code runs on someone else's hardware with no self-hosting option, per-sandbox-hour billing that compounds fast at scale, a hard 1-day sandbox lifetime cap, and no kernel-level isolation for untrusted LLM-generated code. AerolVM covers the same AI execution use case on infrastructure you own, with gVisor isolation and predictable fixed-cost pricing.

> **Already on the e2b SDK?** AerolVM's `/e2b` API facade means your existing code keeps working - just point `E2B_API_URL` at your AerolVM host.

### vs Daytona

Daytona targets long-lived developer workspaces, not high-frequency ephemeral agent workloads. It requires multi-component infrastructure that is genuinely difficult to self-host and has no kernel-level isolation, no per-sandbox egress control, and no port allowlist. AerolVM is a single binary you install in 60 seconds.

> **Already on the Daytona SDK?** AerolVM's `/daytona` API facade lets you swap the backend without touching your SDK code - just update `DAYTONA_API_URL`.

## Architecture

AerolVM is a single Go binary (`sandboxd`) wired to three components:

- **Caddy** - handles wildcard TLS via DNS-01, L7 HTTP routing (`<sandbox-id>.<domain>`), and L4 TCP SNI routing (`<sandbox-id>-<port>.<domain>`). The daemon talks to the Caddy admin API; no config files are reloaded at runtime.
- **Docker / gVisor / Firecracker** - the container runtimes. gVisor runs as an OCI-compatible runtime (`runsc`) so the same Docker API creates a kernel-isolated container with one extra flag.
- **SQLite (WAL mode, single-writer)** - stores sandbox state, the TCP host-port pool, exposed-port intents, and sealed secrets. Single-writer means no contention; WAL mode means reads never block writes.

For multi-host deployments, `sandboxd` nodes form a cluster using **Raft** (FSM-replicated placement state) and **SWIM gossip** (membership + capacity heartbeats). Nodes take `server`, `worker`, or `ingress` roles. The Raft voter count stays fixed at 3 or 5 regardless of how many workers you add - the same topology Kubernetes uses for control-plane vs. data-plane scaling. See [Cluster Setup](https://microvm.aerol.ai/cluster-setup).

```
┌─────────────────────────────────────────────────────┐
│                    sandboxd                         │
│                                                     │
│  ┌──────────┐   ┌──────────┐   ┌─────────────────┐  │
│  │  HTTP    │   │ Service  │   │    SQLite store │  │
│  │  API v1  │──▶│  layer   │──▶│  (WAL, 1-writer)│  │
│  └──────────┘   └────┬─────┘   └─────────────────┘  │
│                      │                              │
│          ┌───────────┼───────────┐                  │
│          ▼           ▼           ▼                  │
│       Docker      Caddy      SSH gateway            │
│    gVisor/FC    admin API    (Ed25519)              │
└─────────────────────────────────────────────────────┘
```

## Runtimes

| Runtime | Status | Use Case |
| :--- | :--- | :--- |
| Docker (`runc`) | ✅ Available | Default. Lowest overhead, broadest image compatibility. |
| gVisor (`runsc`) | ✅ Available | User-space kernel isolation for untrusted LLM-generated code. Install with `--with-gvisor`. |
| Firecracker | ✅ Available | MicroVM isolation - dedicated kernel per sandbox for maximum security. |

## SDKs

AerolVM ships first-party SDKs for five languages. Install the one that matches your stack:

```bash
# TypeScript / Node.js
npm install @aerol-ai/aerolvm-sdk

# Python
pip install aerolvm

# Go
go get github.com/aerol-ai/microvm/sdk/go

# Rust
cargo add aerolvm

# Java (Maven)
# <dependency><groupId>ai.aerol</groupId><artifactId>aerolvm-sdk</artifactId></dependency>
```

### Quick Start

<details open>
<summary><strong>TypeScript</strong></summary>

```ts
import { MicroVM } from '@aerol-ai/aerolvm-sdk'

const client = new MicroVM({
  apiUrl: process.env.SB_API_URL,
  patToken: process.env.SB_PAT_TOKEN,
})

const sandbox = await client.create({ image: 'ubuntu:22.04' })

// Run a command and stream output
const stream = await sandbox.execStream('python3 -c "print(\'hello\')"')
stream.on('data', chunk => process.stdout.write(chunk))

// Expose a port and get a public URL
const url = await sandbox.exposePort(3000)
console.log(url) // https://<sandbox-id>-3000.sandbox.example.com

await sandbox.destroy()
```

</details>

<details>
<summary><strong>Python</strong></summary>

```python
from aerolvm import MicroVM
import os

client = MicroVM(
    api_url=os.environ["SB_API_URL"],
    pat_token=os.environ["SB_PAT_TOKEN"],
)

sandbox = client.create(image="ubuntu:22.04")

result = sandbox.exec("python3 -c \"print('hello')\"")
print(result.stdout)

url = sandbox.expose_port(3000)
print(url)  # https://<sandbox-id>-3000.sandbox.example.com

sandbox.destroy()
```

</details>

<details>
<summary><strong>Go</strong></summary>

```go
package main

import (
    "context"
    "fmt"
    "os"

    microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
    sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func main() {
    client := microvm.New(microvm.Options{
        APIURL:   os.Getenv("SB_API_URL"),
        PATToken: os.Getenv("SB_PAT_TOKEN"),
    })

    ctx := context.Background()
    sandbox, _ := client.Create(ctx, sdktypes.CreateSandboxOptions{
        Image: "ubuntu:22.04",
    })

    result, _ := sandbox.Exec(ctx, "echo hello")
    fmt.Println(result.Stdout)

    sandbox.Destroy(ctx)
}
```

</details>

Full examples for Rust and Java are in the [SDK Setup docs](https://microvm.aerol.ai/sdk-setup).

### Drop-in SDK Compatibility

If you are already running the e2b or Daytona SDK, AerolVM has API facades that accept their wire format unchanged:

| Existing SDK | AerolVM facade endpoint | Migration |
| :--- | :--- | :--- |
| `e2b` Python / TypeScript | `/e2b/...` | Set `E2B_API_URL=https://your-aerolvm-host` |
| `daytona` Python / TypeScript | `/daytona/...` | Set `DAYTONA_API_URL=https://your-aerolvm-host` |

[Using the e2b SDK →](https://microvm.aerol.ai/using-e2b-sdk) · [Using the Daytona SDK →](https://microvm.aerol.ai/using-daytona-sdk)

## Installation

See [Server Setup](https://microvm.aerol.ai/getting-started) for all installation paths: local development, single-node production with wildcard TLS, and multi-node cluster deployment.

## Use Cases

| Use Case | Description |
| :--- | :--- |
| [AI Code Execution](https://microvm.aerol.ai/use-cases/coding-agents) | Run LLM-generated code safely in kernel-isolated environments. Handle untrusted Python, JS, and shell from agent workflows without risking the host. |
| [Ephemeral CI / Build Agents](https://microvm.aerol.ai/use-cases) | Spin up a fresh environment per job, run tests, collect artifacts, destroy. No persistent state, no environment drift. |
| [Customer-Facing Products](https://microvm.aerol.ai/use-cases/customer-facing-product-experiences) | Ship interactive code runners, coding interview sandboxes, and per-user compute environments backed by AerolVM's isolation and port exposure. |
| [Data Processing Pipelines](https://microvm.aerol.ai/use-cases) | Attach S3 or NFS storage, run transforms in parallel across sandboxes, extract results - with per-sandbox network quotas to prevent runaway egress. |

## Documentation

| Guide | Description |
| :--- | :--- |
| [Quick Start](https://microvm.aerol.ai/quick-start) | Spin up a sandbox and run a command in under five minutes. |
| [Server Setup](https://microvm.aerol.ai/getting-started) | Install and configure AerolVM on a Linux host. |
| [SDK Setup](https://microvm.aerol.ai/sdk-setup) | Connect an SDK to your AerolVM server. |
| [Sandboxes](https://microvm.aerol.ai/sandboxes) | Lifecycle states, runtimes, resource limits, and configuration. |
| [Sessions](https://microvm.aerol.ai/sessions) | Persistent PTY sessions that survive reconnects with output replay. |
| [Snapshots](https://microvm.aerol.ai/snapshots) | Stop a sandbox, snapshot its state, restart it later exactly where it left off. |
| [Cluster Setup](https://microvm.aerol.ai/cluster-setup) | Multi-node deployment with Raft placement and SWIM gossip. |
| [Comparison](https://microvm.aerol.ai/comparison) | AerolVM vs e2b vs Daytona - full feature and cost analysis. |

## Contributing

AerolVM is open source under the [MIT License](LICENSE). Contributions are welcome - open an issue first for non-trivial changes so we can align on the approach before you invest time in an implementation.

```bash
make fmt      # format Go code
make test     # run tests
make build    # build sandboxd + toolboxd into bin/
```

## License

[MIT](LICENSE) · © Aerol AI, Inc.
