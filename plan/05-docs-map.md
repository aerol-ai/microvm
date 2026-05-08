# Docs Map: Daytona Structure → sandbox-library

Mapping Daytona's documentation sidebar to our sandbox-library docs.
Legend: ✅ exists | 🔨 create | ❌ skip (not implemented)

## INTRODUCTION

| Daytona Page | Our File | Status |
|---|---|---|
| Quick Start | `quick-start.md` | 🔨 create |
| Architecture | `architecture.md` | ✅ exists |
| Getting Started | `getting-started.md` | ✅ exists |
| Sandboxes | `sandboxes.md` | 🔨 create |

## SANDBOX

| Daytona Page | Our File | Status |
|---|---|---|
| Environment | `environment.md` | 🔨 create |
| Snapshots | — | ❌ not implemented |
| Declarative Builder | — | ❌ not implemented |
| Volumes | `external-storage.md` | ✅ exists (covered) |
| Regions | — | ❌ not implemented |

## AGENT TOOLS (our: TOOLBOX)

| Daytona Page | Our File | Status |
|---|---|---|
| File System | `file-system.md` | 🔨 create |
| Git Operations | — | ❌ no dedicated impl (use exec) |
| Language Server Protocol | — | ❌ not implemented |
| Process & Code Execution | `exec-streaming.md` | ✅ exists |
| Pseudo Terminal (PTY) | `exec-streaming.md` | ✅ exists (covered) |
| Log Streaming | `exec-streaming.md` | ✅ exists (covered) |
| Sessions | `sessions.md` | 🔨 create |
| MCP Server | — | ❌ not implemented |
| Computer Use | — | ❌ not implemented |

## HUMAN TOOLS (our: ACCESS)

| Daytona Page | Our File | Status |
|---|---|---|
| Web Terminal | — | ❌ no standalone UI |
| SSH Access | `ssh-access.md` | 🔨 create |
| VNC Access | — | ❌ not implemented |
| VPN Connections | — | ❌ not implemented |
| Preview | `preview.md` | 🔨 create |
| Custom Preview Proxy | — | ❌ not implemented |

## SDK REFERENCE

| Daytona Page | Our File | Status |
|---|---|---|
| SDK Overview | `sdk-clients.md` | ✅ exists |
| TypeScript SDK | `typescript-sdk.md` | ✅ exists |
| Python SDK | `python-sdk.md` | ✅ exists |
| Go SDK | `go-sdk.md` | ✅ exists |
| Java SDK | `java-sdk.md` | 🔨 create |
| Rust SDK | `rust-sdk.md` | ✅ exists |

## FEATURES

| Daytona Page | Our File | Status |
|---|---|---|
| Streaming Exec | `exec-streaming.md` | ✅ exists |
| External Storage | `external-storage.md` | ✅ exists |
| Network Isolation | `network-isolation.md` | ✅ exists |
| Port Allowlist | `port-allowlist.md` | ✅ exists |

## Files to Create

1. `quick-start.md` — 5-minute guide using an SDK to spin up and run a command
2. `sandboxes.md` — Sandbox concept, lifecycle states, create/start/stop/destroy
3. `environment.md` — Docker image selection, env vars, resource sizing, idle lifecycle
4. `file-system.md` — Upload and download files via toolboxd
5. `sessions.md` — Persistent PTY terminal sessions, attach, replay buffer
6. `ssh-access.md` — SSH gateway: key provisioning, connection strings, port forwarding
7. `preview.md` — Expose ports and access services via public Caddy subdomains
8. `java-sdk.md` — Java SDK: install, lifecycle, exec streaming, sessions
