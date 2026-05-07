# Coverage Analysis: Use Cases vs. Implementation Plan

This document maps every use case from `01-use-cases.md` to the implementation plan in `02-implementation-plan.md`, identifies any gaps, and flags open questions.

---

## Coverage Matrix

| UC | Title | Covered By | Status | Notes |
|---|---|---|---|---|
| UC-01 | Install on bare metal | `scripts/install.sh`, `packaging/sandboxd.service`, `packaging/Caddyfile.template` | ✅ Full | Script handles Docker + Caddy + sandboxd setup |
| UC-02 | Create sandbox via REST | `pkg/api/handlers/sandbox.go` → `POST /v1/sandboxes`, `pkg/docker/create.go`, `pkg/caddy/routes.go` | ✅ Full | Full create → docker → caddy pipeline |
| UC-03 | Create sandbox via Go SDK | `sdk/go/client.go`, `sdk/go/sandbox.go` | ✅ Full | SDK wraps REST API |
| UC-04 | Execute commands in sandbox | `pkg/api/handlers/proxy.go` → `ANY /v1/sandboxes/:id/toolbox/*`, `sdk/go/sandbox.go Exec()` | ✅ Full | Proxied to Daytona toolbox daemon inside container |
| UC-05 | Upload/download files | `sdk/go/files.go`, proxied through toolbox daemon file endpoints | ✅ Full | Toolbox daemon already handles file ops |
| UC-06 | Expose specific port publicly | `pkg/api/handlers/sandbox.go ExposePort`, `pkg/caddy/routes.go`, `sdk/go/ports.go` | ✅ Full | Caddy route per port per sandbox |
| UC-07 | SSH into sandbox | `pkg/sshgateway/gateway.go` on port 2220 | ✅ Full | Proxies to toolbox daemon SSH port inside container |
| UC-08 | Stop and restart sandbox | `handlers/sandbox.go Start/Stop`, `pkg/docker/start.go`, `pkg/docker/stop.go` | ✅ Full | State persisted in SQLite, Caddy route preserved |
| UC-09 | Destroy sandbox | `handlers/sandbox.go Destroy`, `pkg/docker/destroy.go`, `pkg/caddy/routes.go RemoveRoute` | ✅ Full | Container removed + Caddy route removed + DB deleted |
| UC-10 | Resource limits | `pkg/docker/create.go` (cgroup config), `pkg/docker/resize.go`, `handlers/sandbox.go Resize` | ✅ Full | CPU shares + memory limit + disk quota via Docker |
| UC-11 | Environment variables | `pkg/docker/create.go` (container config env), `store/store.go env_json` | ✅ Full | Passed at create time, stored in SQLite |
| UC-12 | Custom Docker image + registry auth | `pkg/docker/image_pull.go`, `pkg/api/handlers/sandbox.go` (registry field) | ✅ Full | Auth credentials accepted in create request |
| UC-13 | Many concurrent sandboxes | Docker manages containers; `store/store.go` with per-row locking; Caddy handles routing | ✅ Full | Concurrency handled by Docker + SQLite WAL mode |
| UC-14 | List and inspect sandboxes | `GET /v1/sandboxes`, `GET /v1/sandboxes/:id`, `sdk/go/sandbox.go List/Get` | ✅ Full | Returns status, URL, resource usage |
| UC-15 | Network isolation | `pkg/docker/netrules/manager.go` (iptables), `network_block_all` field in create body | ✅ Full | Same iptables logic as Daytona runner |
| UC-16 | IP mode (no domain) | `cmd/sandboxd/main.go` detects empty `SB_DOMAIN`, Caddy uses path-based routing | ✅ Full | Path-based routing `/<sandbox-id>/` on port 80 |
| UC-17 | Health check + observability | `pkg/api/handlers/health.go GET /health`, checks Docker ping + Caddy reachability | ✅ Full | Returns sandbox count, Docker status, Caddy status |
| UC-18 | Automatic TLS via Let's Encrypt | Caddy handles this natively; `packaging/Caddyfile.template` configures ACME | ✅ Full | Zero code needed — Caddy owns cert lifecycle |
| UC-19 | Sandbox auto-stop on idle | `pkg/idlemonitor/monitor.go`, configured via `SB_IDLE_TIMEOUT_MIN` | ✅ Full | Background goroutine checks activity timestamps |
| UC-20 | State survives restart | `internal/store/store.go` (SQLite) + `pkg/sync/reconciler.go` on startup | ✅ Full | Reconciler re-syncs Docker ↔ DB + re-registers Caddy routes |

**All 20 use cases are covered.**

---

## Gap Analysis

### Gap 1 — Daytona Toolbox Daemon Binary

**Issue:** The plan embeds `daemon-amd64` (Daytona's toolbox daemon) as a static binary. This binary provides exec, file, SSH, terminal, and LSP services inside containers. The Daytona runner embeds it from a Go `embed.go` file that points to a pre-compiled binary.

**Risk:** This binary is Daytona's proprietary code (AGPL-3.0). Using it in sandbox-library is fine for self-hosted use, but redistribution in a closed product requires compliance with AGPL.

**Resolution options:**
- A. Embed the daemon binary directly (same as Daytona runner) and document the AGPL requirement.
- B. Replace with a minimal open-source toolbox daemon written from scratch (only exec + file + SSH).
- **Recommended:** Option A for speed; build Option B later as a clean-room component.

---

### Gap 2 — Wildcard TLS Certificate (DNS-01 Challenge)

**Issue:** Caddy needs a wildcard cert (`*.sandbox.aerol.ai`) which requires a DNS-01 ACME challenge. This means the install script must ask the user for their DNS provider API credentials (Cloudflare, Route53, etc.) and install the appropriate Caddy DNS plugin.

**Implementation needed:**
- `scripts/install.sh` must download the correct Caddy build with the DNS plugin (e.g., `xcaddy build --with github.com/caddy-dns/cloudflare`).
- Add `SB_DNS_PROVIDER` and `SB_DNS_API_TOKEN` to `packaging/.env.template`.
- Add provider-specific instructions to install script output.

**Alternative:** Use Caddy's HTTP-01 challenge per-subdomain (works only if each subdomain resolves to the server). This requires Caddy to dynamically provision a cert per new sandbox ID, which Caddy can do with its `on_demand` TLS feature. This avoids DNS provider complexity.

**Recommended:** Use `on_demand` TLS for simplicity:
```caddyfile
{
    on_demand_tls {
        ask http://localhost:8080/v1/tls-check
    }
}
```
sandboxd responds to `/v1/tls-check?domain=<sandbox-id>.sandbox.aerol.ai` with 200 if the sandbox exists.

---

### Gap 3 — Container → Toolbox Port Discovery

**Issue:** The plan assumes the toolbox daemon always listens on port `41100`. The Daytona daemon actually uses port `41100` for HTTP and `41101` for SSH by default, but these could conflict if multiple daemons run on the same host (they don't — they're inside separate containers with their own network namespace, so there's no conflict).

**Resolution:** No change needed. Container network isolation means port `41100` inside container A doesn't conflict with port `41100` inside container B.

---

### Gap 4 — Idle Monitor Activity Source

**Issue:** The idle monitor (`pkg/idlemonitor/monitor.go`) needs to know when a sandbox was last "active." Activity signals needed:
- API requests proxied through toolbox
- SSH connections
- Manual `Start` calls

**Implementation needed:** Add an activity timestamp update whenever a proxy request or SSH connection is routed to a sandbox. The idle monitor reads this timestamp from an in-memory map (or SQLite `last_active_at` column) and stops sandboxes that haven't been touched in `SB_IDLE_TIMEOUT_MIN`.

---

### Gap 5 — SDK Language Coverage

**Issue:** The plan includes only a Go SDK. Many AI frameworks (LangChain, LlamaIndex) are Python-based; some platforms use TypeScript/Node.

**Status:** Not covered in the initial plan.

**Recommendation:** After the Go SDK is stable, auto-generate Python and TypeScript SDKs from the OpenAPI spec (swaggo generates it for the Gin API). Add this as a follow-up milestone.

---

### Gap 6 — Multi-Server (Runner Pool) Support

**Issue:** The current plan runs one `sandboxd` per bare-metal server. There's no federation — an SDK client talks to one server. Daytona's full architecture supports multiple runners.

**Status:** Out of scope for v1.

**Recommendation:** Design the API such that a future "coordinator" service could route to multiple `sandboxd` instances. The API surface is already compatible (each server is independently addressable).

---

## Assumptions

1. **Linux only** — The server must run Linux (for Docker + iptables). macOS/Windows are not supported as hosts.
2. **amd64 only** — The embedded Daytona daemon binary is `daemon-amd64`. ARM64 support requires a separate binary or runtime compilation.
3. **Docker required** — Must be installed before `sandboxd` starts. The install script handles this.
4. **Caddy co-located** — Caddy runs on the same server. The Admin API is accessed via `localhost:2019`.
5. **Toolbox daemon** — The Daytona daemon binary (`daemon-amd64`) is embedded in the `sandboxd` binary. It is extracted to a temp directory on startup and bind-mounted into each container.

---

## Implementation Milestones

### Milestone 1 — Core (MVP)
- `cmd/sandboxd/main.go` wiring
- `internal/config`, `internal/store`
- `pkg/docker/` (create, start, stop, destroy, state)
- `pkg/caddy/` (add route, remove route)
- `pkg/api/` (create, get, list, start, stop, destroy handlers)
- `scripts/install.sh` (basic)
- `sdk/go/` (Create, Get, List, Start, Stop, Destroy)

### Milestone 2 — Full Feature Set
- `pkg/docker/resize.go`
- `pkg/docker/image_pull.go` (registry auth)
- `pkg/docker/netrules/` (network isolation)
- `pkg/sshgateway/` (SSH access)
- Port exposure endpoints + Caddy routes
- `pkg/idlemonitor/` (auto-stop)
- `pkg/sync/reconciler.go` (state recovery)
- `sdk/go/` (Exec, UploadFile, DownloadFile, ExposePort)

### Milestone 3 — Production Readiness
- `on_demand` TLS (Gap 2 fix)
- `GET /health` endpoint with all checks
- Prometheus metrics endpoint
- `scripts/install.sh` production-grade (DNS provider support, uninstall)
- OpenAPI spec generation
- Goreleaser binary publishing
- Python SDK (auto-generated from OpenAPI)

---

## Risk Summary

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| AGPL compliance for Daytona daemon | Medium | High | Document license; plan clean-room replacement |
| Wildcard TLS complexity | High | Medium | Use Caddy `on_demand` TLS (HTTP-01 per subdomain) |
| iptables rules on non-root | Medium | Medium | Run `sandboxd` as root or with `CAP_NET_ADMIN` |
| SQLite WAL contention | Low | Low | Use WAL mode; single-writer design |
| Container network IP changes | Low | High | Reconciler refreshes IPs on restart; Docker monitor handles events |
