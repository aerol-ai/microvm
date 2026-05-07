# Missing Implementation: sandbox-library vs. Full Runner-Parity Plan

This document records the implementation gap between:

1. The original intended architecture described in `02-implementation-plan.md`
2. Daytona runner capabilities in `daytona/apps/runner`
3. The current `sandbox-library` repository implementation

The current repository is a narrower MVP focused on single-node sandbox lifecycle management plus public routing. It is not yet a full Daytona-runner-derived sandbox platform.

---

## Current State Summary

The current `sandbox-library` implementation includes:

- A host daemon (`sandboxd`)
- A lightweight in-container toolbox binary (`toolboxd`)
- Docker-backed sandbox lifecycle operations
- SQLite-backed state persistence
- Caddy Admin API route management
- REST API for sandbox control
- A small Go SDK
- Install and uninstall scripts

The current implementation is enough for a basic single-node sandbox host, but it does not yet match the original plan or the Daytona runner feature surface.

---

## Missing Areas at a Glance

The missing implementation falls into eight major groups:

1. Runner-parity Docker subsystems
2. SSH gateway and interactive access
3. Snapshot, backup, and image lifecycle
4. Volume management and persistent workspace handling
5. Advanced network controls and enforcement
6. Rich toolbox/session features
7. Recovery, monitoring, and production hardening
8. API maturity, observability, and packaging completeness

---

## 1. Runner-Parity Docker Subsystems

### Missing

- Split Docker lifecycle files such as `create.go`, `start.go`, `stop.go`, `destroy.go`, `resize.go`, `state.go`, `monitor.go`, `image_pull.go`
- Explicit daemon startup logic comparable to Daytona runner's daemon handling
- Docker event monitoring for container state drift
- Recovery helpers for crashed or half-created sandboxes
- Volume cleanup and orphan cleanup routines
- Container exec helpers beyond the simplified toolbox exec path

### Why it matters

The current implementation places most host-side sandbox orchestration into a single file, [pkg/docker/client.go](pkg/docker/client.go). That is sufficient for core operations, but it does not provide the richer lifecycle handling and operational resilience that exists in Daytona runner.

### Required work

- Split `pkg/docker/client.go` into dedicated lifecycle files
- Add Docker event subscription and reconciliation hooks
- Add explicit recovery paths for failed create/start/stop flows
- Add cleanup logic for orphaned sandboxes and resources

---

## 2. SSH Gateway and Interactive Access

### Missing

- SSH gateway service comparable to `daytona/apps/runner/pkg/sshgateway`
- SSH host key handling and authentication configuration
- Sandbox-to-SSH routing model
- Public SSH entrypoint and sandbox-targeted SSH forwarding

### Why it matters

The original use cases explicitly included SSH access into running sandboxes. That use case is currently not implemented in `sandbox-library`.

### Required work

- Add `pkg/sshgateway/gateway.go`
- Add `pkg/sshgateway/config.go`
- Wire SSH startup into `cmd/sandboxd/main.go`
- Define sandbox authentication strategy for SSH sessions
- Expose SSH access through the install and environment templates

---

## 3. Snapshot, Backup, and Image Lifecycle

### Missing

- Snapshot creation and snapshot restore
- Image push and image export flows
- Backup metadata tracking
- Backup and snapshot state transitions
- Registry-manifest helpers and image-state introspection
- Storage-backed backup flows

### Why it matters

Daytona runner contains a substantial amount of snapshot and backup logic. The current implementation supports only basic `docker pull` during sandbox creation. It does not support reusable sandbox state capture or restoration.

### Required work

- Add snapshot lifecycle APIs and types
- Add storage abstraction for snapshot artifacts
- Implement commit/export/push/pull workflows
- Persist snapshot and backup metadata
- Extend SDK support for snapshot and backup operations

---

## 4. Volume Management and Persistent Workspace Handling

### Missing

- Volume DTOs and storage-aware mount definitions
- Volume mount path binding helpers
- Volume lifecycle management
- FUSE or equivalent mount re-establishment logic
- Persistent workspace handling across sandbox restarts

### Why it matters

The current implementation assumes a simple container lifecycle. Daytona runner supports more advanced workspace and volume behavior. Without this, user workspace persistence and external storage integration remain limited.

### Required work

- Add volume models and request types
- Add Docker bind/mount assembly helpers
- Add restart-time mount validation and reattachment
- Add cleanup logic for orphaned volumes or mounts

---

## 5. Advanced Network Controls and Enforcement

### Missing

- Network allowlist rules
- Egress limiting / rate limiting
- Rule assignment and unassignment helpers
- Better chain management and persistent rule handling
- Richer security policy controls from the original plan

### Current state

The current implementation includes only a simplified block-all-egress capability in [pkg/docker/netrules/manager.go](pkg/docker/netrules/manager.go).

### Why it matters

The original plan included support for Daytona-style `netrules` behavior, including more precise outbound controls. The MVP does not yet provide that parity.

### Required work

- Split netrules into assignment, delete, set, limiter, and utility components
- Add allowlist support in API and persistence models
- Add egress rate limiting support
- Add startup recovery for previously applied rules

---

## 6. Rich Toolbox and Session Features

### Missing

- Full Daytona daemon/session architecture
- Long-running command sessions
- Command log streaming
- Terminal sessions
- Session state tracking
- Recording support and terminal dashboard support
- Broader toolbox endpoints beyond basic health, exec, file upload/download, and local proxying

### Current state

The current [cmd/toolboxd/main.go](cmd/toolboxd/main.go) is intentionally minimal. It is not a feature-complete replacement for Daytona's daemon and session stack.

### Why it matters

The original runner supports richer interactive workflows. The current toolbox is adequate for a basic control-plane sandbox, but not for the broader Daytona-style developer or agent experience.

### Required work

- Add session model and session lifecycle endpoints
- Add log streaming endpoints
- Add interactive shell/session support
- Add terminal multiplexing support
- Add authentication and initialization parity where needed

---

## 7. Recovery, Monitoring, and Production Hardening

### Missing

- Docker monitor and lifecycle event consumer
- Regular sandbox sync service
- Better startup reconciliation for edge cases
- Container recovery flows after host or daemon restarts
- Orphan detection and repair
- Resource cleanup workers
- Explicit health check subsystems for dependencies and internal components

### Current state

There is a basic reconcile path in [internal/service/service.go](internal/service/service.go), but it is much narrower than Daytona runner's recovery and monitoring behavior.

### Why it matters

Production reliability depends on more than CRUD APIs. Long-running bare-metal hosts need continuous cleanup, drift handling, and health enforcement.

### Required work

- Add Docker event consumer
- Add recurring drift detection
- Add cleanup workers for dead containers, routes, and stale state
- Add richer dependency and subsystem health reporting
- Add integration tests for restart and recovery scenarios

---

## 8. API Maturity, Observability, and Packaging Completeness

### Missing API pieces

- Dedicated middleware package for auth and recoverable errors
- Request validation layer
- DTO layer and clearer API contract boundaries
- Swagger/OpenAPI generation
- Snapshot and backup endpoints
- Stream and session endpoints

### Missing observability pieces

- Metrics collection
- Structured operational counters
- Production-grade health and service info endpoints
- Telemetry and tracing hooks if desired

### Missing packaging pieces

- Debian packaging parity
- Release automation comparable to the planned production release flow
- More complete install options for DNS providers and TLS strategies
- Expanded environment template coverage

### Why it matters

The current API and packaging are functional, but they are still MVP-grade. A full runner-derived service should expose a stronger contract, better documentation, and better production-operability surfaces.

### Required work

- Split API server into controllers, middleware, DTOs, and validators
- Generate OpenAPI docs from handlers or spec-first definitions
- Add metrics and better health reporting
- Improve install tooling for production Caddy/TLS setups
- Add formal release packaging and distribution paths

---

## Original Use Cases Not Fully Satisfied Yet

The following use cases from `01-use-cases.md` are only partially implemented or not implemented:

- UC-04 — Execute commands inside a sandbox
  Current state: basic execution exists, but not full Daytona-style sessions, logs, and interactive control.

- UC-07 — SSH into a running sandbox
  Current state: not implemented.

- UC-10 — Set resource limits
  Current state: basic CPU and memory update exists; broader runtime and storage parity is incomplete.

- UC-12 — Use a custom Docker image
  Current state: basic authenticated pull exists; broader registry and image lifecycle support is incomplete.

- UC-15 — Network isolation
  Current state: only block-all-egress is implemented; allowlists and rate limiting are missing.

- UC-17 — Health check and observability
  Current state: basic health exists; detailed observability and metrics are missing.

- UC-19 — Sandbox auto-stop on idle
  Current state: basic idle stop exists, but activity tracking is still narrow.

- UC-20 — State survives restart
  Current state: basic reconciliation exists, but richer recovery and drift correction are missing.

---

## Missing Repository Layout from the Original Plan

The original plan expected a structure closer to:

- `pkg/docker/create.go`
- `pkg/docker/start.go`
- `pkg/docker/stop.go`
- `pkg/docker/destroy.go`
- `pkg/docker/resize.go`
- `pkg/docker/state.go`
- `pkg/docker/monitor.go`
- `pkg/docker/image_pull.go`
- `pkg/sshgateway/gateway.go`
- `pkg/sshgateway/config.go`
- `pkg/idlemonitor/monitor.go`
- `pkg/sync/reconciler.go`
- `pkg/api/middleware/auth.go`
- `pkg/api/handlers/*.go`
- `pkg/daemon/embed.go`
- `internal/store/migrations/*`

The current repository intentionally compresses many of these concerns into fewer files and does not yet contain all of the originally planned packages.

---

## Recommended Next Implementation Phases

### Phase 1 — Structural Alignment

- Split current consolidated files into the planned package layout
- Restore handler, middleware, DTO, and docker-lifecycle separation
- Add migration files and make the store layout closer to the original plan

### Phase 2 — Access and Interactive Features

- Implement SSH gateway
- Implement richer toolbox session handling
- Add command logs and streaming endpoints

### Phase 3 — Storage and Snapshot Features

- Implement snapshot and backup models
- Implement storage client abstraction
- Add backup and restore APIs

### Phase 4 — Reliability and Security

- Add Docker monitor and recovery loops
- Add full netrules support
- Add cleanup workers and stronger reconcile behavior

### Phase 5 — Production Maturity

- Add metrics and observability
- Add OpenAPI docs and validation
- Improve packaging and release automation
- Add end-to-end Linux integration tests

---

## Acceptance Standard for Full Parity

`sandbox-library` should be considered close to the originally intended implementation only when all of the following are true:

- Sandbox lifecycle code is split into dedicated subsystems rather than one condensed MVP layer
- SSH access is implemented
- Snapshot and backup flows are implemented
- Volume and storage lifecycle support is present
- Advanced network control parity exists
- Session and streaming features are present
- Recovery and monitoring loops run continuously
- API documentation, validation, and observability are production-grade

Until then, the current repository should be treated as an MVP implementation, not a full Daytona runner parity implementation.