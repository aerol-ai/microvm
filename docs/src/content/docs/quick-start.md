---
title: Quick Start
---

**AerolVM** is open-source infrastructure for running isolated code environments. Each sandbox is a fully isolated compute unit with its own filesystem, network stack, and allocated vCPU, RAM, and disk with a support of Docker, GVisor, Kata and Wasm.

The idea is to provide a seamless, secure sandbox experience that can start in under 50ms to 1s.

Sandboxes are the core component of the [Aerol.ai](https://aerol.ai) platform, spinning up in under 90ms from code to execution and running any code in Python, TypeScript, and JavaScript. Built on OCI/Docker compatibility, massive parallelization, and unlimited persistence, sandboxes deliver consistent, predictable environments for agent workflows.

Agents and developers interact with sandboxes programmatically using the AerolVM SDKs, API, and CLI. Operations span sandbox lifecycle management, filesystem operations, process and code execution, and runtime configuration. Our stateful environment snapshots enable persistent agent operations across sessions, making AerolVM the ideal foundation for AI agent architectures.

## Runtimes

AerolVM supports multiple container runtimes, giving you a choice between security and compatibility:

| Runtime | Status | Use Case |
|---|---|---|
| Docker | ✅ | Fast startup, broad image compatibility, standard workloads |
| GVisor | ✅ | Kernel-level isolation without a full VM - ideal for untrusted code |
| Kata Containers | 🗓 | [Planned] Full VM isolation with hardware virtualization |
| WebAssembly | 🗓 | [Planned] Ultra-lightweight, portable workloads |

Today, sandboxes run on Docker. GVisor, Kata, and WebAssembly support are on the roadmap.

## Use Cases

- **AI code execution** - run LLM-generated code safely in isolated environments
- **CI / ephemeral build agents** - spin up a fresh environment per job, destroy when done
- **Interactive developer environments** - persistent workspaces with SSH, port previews, and file sync
- **Data processing pipelines** - attach cloud storage, run transforms, and extract results

## How AerolVM Compares

| | AerolVM | e2b | Daytona |
|---|---|---|---|
| **Hosting** | Self-hosted on your infra | Cloud (managed, no self-host) | Self-hosted |
| **Open source** | ✅ | ✗ | ✅ |
| **Primary use case** | AI agents + ephemeral CI | AI agent code execution | Developer workspaces |
| **Sandbox startup** | <90ms | ~1s | Seconds (persistent VMs) |
| **Runtime isolation** | Docker, gVisor (kernel-level) | Docker | Docker |
| **Persistent stop/start** | ✅ | ✗ | ✅ |
| **External storage** | S3, NFS, SSHFS, rclone | ✗ | ✗ |
| **SSH access** | ✅ | ✗ | ✅ |
| **Per-sandbox egress control** | ✅ | ✗ | ✗ |
| **SDK languages** | TS, Python, Go, Rust, Java | TS, Python | TS, Python |
| **Pricing** | Your infrastructure cost | Per sandbox-hour | Your infrastructure cost |

**e2b** is a managed cloud service optimized for AI agent sandboxes. It requires no infrastructure but offers no self-hosting, no kernel-level isolation, and no control over where code runs. AerolVM covers the same AI execution use case while running entirely on your own host, with gVisor isolation for untrusted workloads and no per-sandbox billing.

**Daytona** targets persistent developer workspaces with IDE and git integration - it is not designed for ephemeral, high-frequency sandbox creation. AerolVM prioritizes sub-second lifecycle operations, agent-friendly SDKs, and isolation runtimes over workspace ergonomics.

## Next Steps

- [Server Setup](/getting-started) - self-host AerolVM on your own infrastructure
- [Create Sandbox](/sandboxes) - lifecycle states, parameters, and configuration options
- [Environment](/environment) - image selection, env vars, and resource limits
- [Streaming Exec](/exec-streaming) - stream stdout/stderr live and use interactive PTY sessions
- [Sessions](/sessions) - persistent terminal sessions that survive reconnects
