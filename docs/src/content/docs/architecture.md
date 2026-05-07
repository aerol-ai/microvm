---
title: Architecture
description: How the host daemon, in-container toolbox, Docker runtime, and public routing work together.
---

## Control Plane and Data Plane

`sandbox-library` follows a runner-style split:

- `sandboxd` runs on the host and acts as the control plane.
- `toolboxd` is injected into each sandbox container and provides the workload-facing process and file APIs.

The repository intentionally avoids depending on external Daytona runtime assets. Both binaries are built from this codebase and shipped together.

## sandboxd Responsibilities

- Create and reconcile Docker containers.
- Persist sandbox metadata and exposed ports in SQLite.
- Configure public ingress through Caddy.
- Proxy authenticated toolbox requests.
- Mount and supervise external storage.
- Apply optional network egress blocking.

## toolboxd Responsibilities

- Provide in-container health and version endpoints.
- Execute commands and stream process output.
- Handle file upload and download requests.
- Proxy local container ports behind an allowlist.

## Supporting Systems

- Docker provides the workload runtime.
- Caddy terminates TLS and routes public traffic to `sandboxd` or exposed container ports.
- SQLite holds sandbox state, credentials metadata, and port exposure data.

## Operational Shape

On startup, `sandboxd` reconciles state from disk with the current Docker runtime. That allows the daemon to restore known sandboxes, re-establish mounts, and re-push port allowlists after a restart.

For advanced behaviors, continue with:

- [Streaming Exec](/exec-streaming)
- [External Storage](/external-storage)
- [Network Isolation](/network-isolation)
- [Port Allowlist](/port-allowlist)