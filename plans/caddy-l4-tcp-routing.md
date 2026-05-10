# Caddy L4 TCP Routing for Sandbox Ports

## Objective

Today `exposePort()` only publishes routes into Caddy's HTTP server, so a generated URL like `https://<sandbox-id>-5432.<domain>` cannot speak the Postgres wire protocol. This plan adds **Layer 4 TCP routing** to AerolVM so a sandbox can publish a *native* `tcp://...` (or `postgresql://...`, `redis://...`, `mongodb://...`) endpoint backed by `github.com/mholt/caddy-l4`.

The same rails are reused to publish raw TCP and TLS-multiplexed TCP, with a persistent host-port pool in `[35000, 45000]` for the raw path and a single shared listener port for the SNI-multiplexed path.

Two reconciliation surfaces are extended so caddy-l4 servers and the DB never drift:
1. The existing `POST /v1/admin/reconcile` API (extended).
2. The existing periodic + event-driven sweep (extended).

---

## Use cases unlocked

The whole purpose of this work is to turn the sandbox into a generic, customer-facing protocol host. Ten use cases this enables:

1. **Per-tenant Postgres** — what the `spawn-postgres.mdx` doc currently says is *not possible*. Ship a `postgresql://user:pass@<public>:<host-port>/appdb` DSN that works with `psql`, Prisma, SQLAlchemy, pgAdmin.
2. **Per-tenant Redis** — `redis://<public>:<host-port>` reachable from `redis-cli`, BullMQ, ioredis.
3. **Per-tenant MySQL / MariaDB** — JDBC / mysql2 clients connect natively for ephemeral test data.
4. **Per-tenant MongoDB** — `mongodb://<public>:<host-port>` for sandboxed product demos and per-customer data.
5. **MQTT broker per IoT demo** — TCP/TLS, native paho/mosquitto clients.
6. **Embedded Kafka (KRaft)** — single-broker streaming sandbox, native kafka-clients.
7. **Game server hosting** — Minecraft / Valheim / dedicated game servers (TCP, optionally UDP later).
8. **gRPC backends** — vLLM, LangGraph, custom gRPC services exposed natively.
9. **SSH bastion / Git server** — port 22 forwarded as a public TCP endpoint distinct from the sandboxd SSH gateway.
10. **TLS-only services with SNI multiplexing** — multiple TLS-shaped backends share `:443` and route by SNI (e.g. `<sandbox>-pg.<domain>` for Postgres-over-TLS, no host-port pool entry needed).

---

## Architecture

### Two protocol modes

Both modes share `caddy-l4`'s admin API surface. The sandbox SDK picks a mode per call:

| Mode | Listener | URL shape | When |
|---|---|---|---|
| `tcp` (raw) | One `:hostport` per exposure, allocated from `[35000, 45000]` | `tcp://<public>:<hostport>` | Postgres, Redis, MySQL, raw protocols |
| `tls` (SNI-mux) | Shared `:443` layer4 listener, `tls.matchers.sni` per route | `tls://<id>-<port>.<domain>:443` | TLS-wrapped TCP that already speaks SNI |
| `http` (existing) | Caddy HTTP server | `https://<id>-<port>.<domain>` | unchanged |

`http` is still the default — backwards compatible with everything in the docs today.

### Host-port allocator (raw TCP path)

The user's request: prefer **random-first** for low p95, fall back to **scan-first** when a collision happens.

```
allocate():
    for attempt in 0..16:
        candidate = randInt(35000, 45000)
        if INSERT OR IGNORE INTO exposed_ports (... host_port=candidate ...) succeeded:
            try caddy.UpsertL4Server(candidate, upstream)
            if ok: return candidate
            else:  delete the just-inserted row, continue
    # Exhausted random retries; fall back to deterministic scan.
    return scanForFreeHostPort(35000, 45000)
```

The DB has a `UNIQUE(host_port)` constraint, so two concurrent allocators race to `INSERT` and only one wins per port — no in-process lock needed. SQLite's single writer keeps this trivial.

### caddy-l4 admin shape

caddy-l4 lives under `/config/apps/layer4/servers/<server-id>`. Each server has `listen` + `routes`. Two server flavors:

```jsonc
// raw TCP — one server per allocated host port
"layer4": {
  "servers": {
    "tcp-port-37412": {
      "listen": [":37412"],
      "routes": [{
        "@id": "sandbox-sb-abc-port-5432-tcp",
        "handle": [{ "handler": "proxy", "upstreams": [{ "dial": ["172.17.0.5:5432"] }] }]
      }]
    },
    // TLS multiplexer — shared :443, routes by SNI
    "tls-mux": {
      "listen": [":443"],
      "routes": [
        {
          "@id": "sandbox-sb-abc-port-5432-tls",
          "match": [{ "tls": { "sni": ["sb-abc-5432.sandbox.example.com"] } }],
          "handle": [{ "handler": "proxy", "upstreams": [{ "dial": ["172.17.0.5:5432"] }] }]
        }
      ]
    }
  }
}
```

The `tls-mux` server is created once at install time; raw-TCP servers are created on demand and torn down on unexpose / destroy.

> **Important conflict**: Caddy's HTTPS listener (current Caddyfile) already binds `:443`. Caddy-l4 can take over `:443` and forward HTTPS to Caddy's HTTP app via `tls.handlers.http_server` or `proxy` to `127.0.0.1:444` — but a clean way is to move the HTTPS listener to a non-`443` internal port and front it with the same `layer4` server (terminate non-matching SNI on the HTTP app). This is the **most disruptive piece of the plan** and is called out as an open question.

### Reconciliation guarantees

| Direction | Today | After this change |
|---|---|---|
| DB row missing → caddy route still present | HTTP routes are GC'd by `Reconcile` walking `s.store.List` | Extended to GC both `apps/http` and `apps/layer4` routes, plus release host-port allocations |
| Container missing → DB row stays | Marks destroyed, removes routes | Same, but also tears down layer4 servers and releases host ports |
| caddy route present but no DB row (zombie route) | **Not handled today** | New: `Reconcile` walks caddy's `apps/http` and `apps/layer4` configs, deletes any route/server with our `@id` prefix that doesn't match a known sandbox/exposure |
| Container present but DB row missing (orphan container) | Removed | Same |
| Host port leaked (DB has port but caddy l4 server gone) | n/a | Re-upsert on reconcile |

---

## Files to modify / create

### 1. `scripts/install.sh`

- Always include `github.com/mholt/caddy-l4` in the Caddy build, regardless of `--dns-provider`. Today the script only swaps the apt-installed `caddy` binary when `--dns-provider` is set; that path must run unconditionally now.
  - Refactor `install_caddy_dns_plugin` into `install_custom_caddy(plugins...)` that accepts a list. Always passes `caddy-l4`; conditionally appends `caddy-dns/<provider>`.
  - Caddy's official build server already supports multiple `&p=` params: `?os=linux&arch=amd64&p=github.com/mholt/caddy-l4&p=github.com/caddy-dns/cloudflare`.
  - Extend the post-build verification: `list-modules` must include `layer4` and `layer4.handlers.proxy`.
- `write_environment` adds three new env vars to `/etc/sandboxd/sandboxd.env`:
  ```
  SB_L4_PORT_RANGE_START=35000
  SB_L4_PORT_RANGE_END=45000
  SB_L4_TLS_LISTEN=:443
  ```
- `write_caddyfile` is updated to:
  - Move the existing `https://$DOMAIN` and `https://*.$DOMAIN` blocks to listen on an internal address (e.g. `:444`) bound to localhost.
  - Add a `layer4` global app stub with one persistent `tls-mux` server on `:443` whose default route forwards non-matching SNI to `127.0.0.1:444` (so HTTPS still works).
  - Open question: simpler alternative is to keep the HTTP/HTTPS sites untouched and let caddy-l4 use a *different* port for SNI multiplexing (e.g. `:8443`). Less disruptive but a less clean URL surface.
- Print an L4 line in the final summary:
  ```
  TCP port range: 35000-45000  (configure firewall accordingly)
  TLS multiplex: :443 (shared with HTTPS via SNI)
  ```

### 2. `internal/config/config.go`

- New fields on `Config`:
  - `L4PortRangeStart int` (default 35000, env `SB_L4_PORT_RANGE_START`)
  - `L4PortRangeEnd int` (default 45000, env `SB_L4_PORT_RANGE_END`)
  - `L4TLSListen string` (default `:443`, env `SB_L4_TLS_LISTEN`)
- Validate: end > start, both within `[1024, 65535]`.

### 3. `pkg/models/types.go`

- Extend `ExposedPort`:
  ```go
  type ExposedPort struct {
      SandboxID  string    `json:"sandbox_id"`
      Port       int       `json:"port"`
      Protocol   string    `json:"protocol"`              // "http" | "tcp" | "tls"
      HostPort   int       `json:"host_port,omitempty"`   // raw TCP only
      PublicURL  string    `json:"public_url"`
      CreatedAt  time.Time `json:"created_at"`
  }
  ```
- New request type for the SDK's TCP variant:
  ```go
  type ExposePortRequest struct {
      Protocol string `json:"protocol,omitempty"` // default "http"
  }
  ```

### 4. `internal/store/store.go`

- Migration appended to `migrations`:
  ```sql
  ALTER TABLE exposed_ports ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http';
  ALTER TABLE exposed_ports ADD COLUMN host_port INTEGER NOT NULL DEFAULT 0;
  CREATE UNIQUE INDEX IF NOT EXISTS idx_exposed_ports_host_port
      ON exposed_ports(host_port) WHERE host_port > 0;
  ```
- `UpsertPort` / `loadPorts` / `DeletePort` updated to read/write `protocol` and `host_port`.
- New `ListAllExposedPorts(ctx)` for reconcile to walk every exposure across all sandboxes in one query (avoids N+1 on reconcile).
- New `TryReserveHostPort(ctx, sandboxID, containerPort, hostPort)` — single `INSERT ... ON CONFLICT DO NOTHING`; returns whether reservation took.

### 5. `pkg/caddy/client.go`

Add a separate set of helpers for layer4. Same per-`@id` upsert pattern as today's HTTP code so it stays O(1):

```go
func (c *Client) UpsertTCPRoute(ctx context.Context, id, containerIP string, port, hostPort int) error
func (c *Client) DeleteTCPRoute(ctx context.Context, id string, hostPort int) error
func (c *Client) UpsertTLSSNIRoute(ctx context.Context, id, host, containerIP string, port int) error
func (c *Client) DeleteTLSSNIRoute(ctx context.Context, id string) error
func (c *Client) ListLayer4RouteIDs(ctx context.Context) ([]string, error)  // for reconcile zombie GC
func (c *Client) ListHTTPRouteIDs(ctx context.Context) ([]string, error)    // for reconcile zombie GC
```

- `tls-mux` SNI routes patch via `PATCH /id/<routeID>` exactly like HTTP routes.
- Raw TCP servers can't be PATCHed (the listen address is part of the server config); use `PUT /config/apps/layer4/servers/tcp-port-<hostPort>` to create, `DELETE /config/apps/layer4/servers/tcp-port-<hostPort>` to drop.
- Route `@id` conventions:
  - HTTP port: `sandbox-<id>-port-<port>` (existing)
  - TCP server id: `tcp-port-<hostPort>`
  - TCP route id: `sandbox-<id>-port-<port>-tcp`
  - TLS-SNI route id: `sandbox-<id>-port-<port>-tls`

### 6. `internal/service/service.go`

- New allocator helper: `allocateHostPort(ctx, sandboxID, containerPort) (int, error)` — random-first, then scan-fallback as in the architecture section above.
- `ExposePort(ctx, id, port, protocol)` gains the protocol parameter:
  - `http` → unchanged (calls `caddy.UpsertPortRoute`).
  - `tls` → `caddy.UpsertTLSSNIRoute(... s.cfg.Domain ...)`. Returns `tls://<id>-<port>.<domain>:443`.
  - `tcp` → allocate host port, `caddy.UpsertTCPRoute(...)`, write `host_port` in DB. Returns `tcp://<publicHost>:<hostPort>`.
- `UnexposePort` looks up the row, dispatches to the right delete helper, and clears the host-port reservation.
- `Reconcile` extended (see below).
- `StartSandbox` re-upserts every protocol's caddy entry on startup.
- `StopSandbox` and `DestroySandbox` tear down all three flavors.

### 7. `internal/service/events.go`

- `markSandboxStopped` and `handleStartEvent` extended to walk `ExposedPorts` and dispatch to `UpsertTCPRoute` / `UpsertTLSSNIRoute` / `UpsertPortRoute` based on `Protocol`. Same teardown shape on stop.

### 8. `internal/service/reconcile.go` *(new file, splitting `Reconcile` out of service.go since it grows)*

- Move the existing `Reconcile`, `StartReconcileLoop`, and the embedded helpers into a new file. Pure refactor; behavior preserved.
- Extend `Reconcile`:
  1. Walk `caddy.ListHTTPRouteIDs` and `caddy.ListLayer4RouteIDs`. For every route ID matching `sandbox-...` or server matching `tcp-port-...` that has no corresponding DB row, delete it. **(zombie caddy route GC — fixes the gap in today's reconcile)**
  2. For every DB exposure missing its caddy entry (e.g. caddy was wiped), re-upsert.
  3. For every host port in DB whose caddy `tcp-port-<host>` server is missing, re-create.
  4. The existing orphan-container and destroyed-sandbox passes stay unchanged.

### 9. `pkg/api/server.go`

- `POST /v1/sandboxes/{id}/ports/{port}` body now optionally accepts `{"protocol":"tcp"|"tls"|"http"}`. Default `http`. Response shape gains `protocol` and (for TCP) `host_port`.
- `POST /v1/admin/reconcile` itself is unchanged — the work is all on the service side.

### 10. SDK surface

All five SDK languages get a new optional argument or parallel method. Convention:

- `sandbox.exposePort(port)` — unchanged, default `http`.
- `sandbox.exposeTCPPort(port)` — new, returns `{ url, host, port }` (URL plus parsed host/port for convenience).
- `sandbox.exposeTLSPort(port)` — new, returns `{ url, host, port }`.

Files:
- `sdk/typescript/src/internal/client.ts`
- `sdk/python/aerolvm/_internal/client.py` *(check exact path during impl)*
- `sdk/go/pkg/microvm/client.go`
- `sdk/go/internal/apiclient/client.go`
- `sdk/rust/...`
- `sdk/java/src/main/java/ai/aerol/microvm/Sandbox.java`
- `sdk/java/src/main/java/ai/aerol/microvm/MicroVMClient.java`

### 11. Docs

Per `CLAUDE.md`: every new top-level feature gets its own `.mdx` registered in `docs/src/content/config.ts`. Examples must use all five SDK languages with `<Tabs syncKey="lang">`.

- `docs/src/content/docs/tcp-ports.mdx` — new top-level page covering `exposeTCPPort` / `exposeTLSPort`. Walks through Postgres, Redis, MySQL examples.
- `docs/src/content/config.ts` — sidebar entry.
- `docs/src/content/docs/use-cases/customer-facing-product-experiences/spawn-postgres.mdx` — rewrite the "Important network limitation" + "Can a user access Postgres on the generated URL?" sections; switch the script to `exposeTCPPort(5432)` returning a real `postgresql://...` DSN.
- `docs/src/content/docs/reconcile.mdx` — add a section on zombie route GC.

### 12. Tests

- `pkg/caddy/client_test.go` — extend `fakeCaddy` to model `apps/layer4/servers/<id>` and SNI route shape; add cases for `UpsertTCPRoute`, `DeleteTCPRoute`, `UpsertTLSSNIRoute`, `ListLayer4RouteIDs`.
- `internal/store/store_test.go` — round-trip `protocol` and `host_port`; verify the unique index rejects duplicate host ports.
- `internal/service/lifecycle_test.go` — extend with TCP exposure paths.
- New `internal/service/reconcile_zombie_test.go` — drive a fake caddy with extra routes/servers that have no DB row, run `Reconcile`, assert they are removed.
- `pkg/api/server_test.go` — exercise `POST /v1/sandboxes/{id}/ports/{port}` with `protocol=tcp` end-to-end with a fake caddy + service.

---

## Phasing

Suggested order so each phase is independently testable:

1. **Phase 1 — caddy-l4 install path.** Modify `scripts/install.sh` to always include caddy-l4; verify `list-modules` on a fresh VM. No code changes elsewhere.
2. **Phase 2 — schema + models.** Add `protocol` and `host_port` columns + `ExposedPort` field. No behavior change yet.
3. **Phase 3 — caddy client helpers.** New `UpsertTCPRoute` / `UpsertTLSSNIRoute` plus tests against the fake caddy.
4. **Phase 4 — service-side allocator + ExposePort dispatch.** API gains `protocol` field; SDK TS first, others follow.
5. **Phase 5 — reconcile extension.** Zombie route + L4 server GC.
6. **Phase 6 — docs + remaining SDKs.** Update `spawn-postgres.mdx`; add `tcp-ports.mdx`.

Each phase is a separate PR; phases 1–3 can ship dark behind no public API.

---

## Open questions

1. **`:443` ownership.** caddy-l4's TLS-SNI multiplexer wants `:443`, but the existing Caddyfile already binds `:443` for HTTPS. Three options:
   - (a) Move HTTPS to an internal port (e.g. `127.0.0.1:444`) and have a layer4 server on `:443` route by SNI to either an internal HTTPS upstream or a TCP backend. Cleanest URL surface; biggest install.sh diff.
   - (b) Keep HTTPS on `:443`; put the SNI multiplexer on `:8443`. Easy, but URLs become `tls://host:8443` which is awkward.
   - (c) Drop the `tls` mode entirely from this round; ship only the raw-TCP host-port pool. Smaller blast radius.
   - **Recommend (a)** because (b) leaks the port number into every URL and (c) loses half the value.
2. **Firewall guidance.** The host needs `[35000, 45000]` open. install.sh on a VPS doesn't manage firewalls today (no `ufw` calls). Document the requirement; do not auto-open. Confirm.
3. **Host port range and per-tenant fairness.** 10,000 ports / sandbox theoretically allows ~10k concurrent TCP exposures. No per-sandbox cap today. Add `SB_L4_MAX_PORTS_PER_SANDBOX` (default e.g. 8) before this ships? Otherwise a buggy SDK loop could exhaust the pool.
4. **UDP.** Game servers and DNS need UDP. caddy-l4 supports it; out of scope for this round but the schema (`protocol` column) leaves room. Confirm scope = TCP-only.
5. **TLS termination.** TLS mode multiplexes by SNI but does **not** terminate TLS — the upstream must speak TLS itself (Postgres in TLS mode can; raw Redis cannot). The SDK URL must clearly say "this is encrypted end-to-end, server cert lives inside the sandbox." Should we instead offer a `tls-terminate` mode where Caddy holds the cert and proxies plaintext into the container? That doubles the design surface — recommend deferring.
6. **Reconcile API contract.** Is it acceptable to change `POST /v1/admin/reconcile` to *also* delete zombie caddy routes (no body change, semantics broaden), or should we add a query param like `?gc_caddy=true` to keep behavior bisectable for operators? Recommend broadening — the new behavior is strictly safer.
7. **Public host vs domain mode.** When `--domain` is unset (IP mode), TCP works (URL = `tcp://<public-host>:<hostport>`) but TLS-SNI mode does not (no DNS names). Should `exposeTLSPort` return an error in IP mode, or fall back to TCP silently? Recommend explicit error.

---

## Out of scope

- UDP support.
- Per-sandbox host-port quotas (called out in OQ #3).
- TLS termination at Caddy (called out in OQ #5).
- Connection-rate limiting on TCP listeners.
- Per-route metrics for L4 traffic (caddy-l4 has its own metrics surface; wiring it into `/health` is a separate piece of work).
