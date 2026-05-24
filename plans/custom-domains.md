# Custom Domains for Sandboxes

## Status

Draft — ready for `/plan-eng-review`. No code written yet.

## Objective

Let an operator (or end user via SDK) attach an **arbitrary public hostname** to a
single running sandbox, in addition to the default `<id>.$DOMAIN`
URL. Two shapes must work:

1. **Subdomain alias** — `api.acme.com` → sandbox `sb-abc`.
2. **Apex / root domain** — `acme.com` → sandbox `sb-abc`.

Both forms get HTTPS automatically via per-host ACME issuance (HTTP-01 by
default, DNS-01 optional later). The wildcard `*.$DOMAIN` cert that the
deployment already holds is **not** used for custom hostnames — they get
their own certs in Caddy's existing cert manager.

Scope of v1: HTTP / HTTPS only (the existing `protocol="http"` sandbox-root
path and `protocol="http"` port exposures). Raw TCP and TLS-SNI port
exposures (`protocol="tcp"`, `protocol="tls"`) are **out of scope** — see
"Non-goals" below.

---

## What works today, and the precise gap

`pkg/caddy/client.go` composes URLs deterministically from the sandbox ID
plus `SB_DOMAIN`:

| Surface | Function | Composed value |
|---|---|---|
| Sandbox root (toolbox) | `SandboxPublicURL` (`client.go:106`) | `https://<id>.$DOMAIN` |
| HTTP port exposure | `PortPublicURL` (`client.go:113`) | `https://<id>-<port>.$DOMAIN` |
| Caddy host match (root) | `UpsertSandboxRoute` (`client.go:163`) | `host: <id>.$DOMAIN` |
| Caddy host match (port) | `UpsertPortRoute` (`client.go:212`) | `host: <id>-<port>.$DOMAIN` |

The cert source is a single wildcard for `*.$DOMAIN` issued via DNS-01 at
install time (`pkg/caddy/client.go:813`). There is no on-demand TLS policy
and no `ask` endpoint. Caddy's HTTP server is bound to `:80` / `:443` (or
`127.0.0.1:8443` behind caddy-l4 in domain mode) but the apex / `:80` HTTP-01
challenge path is not exercised for anything other than the wildcard renewal.

The store has **no column** for additional hostnames. `CreateSandboxRequest`
(`pkg/models/types.go:351`) has no field for them. So the four real gaps are:

1. **Persistence.** Per-sandbox custom-hostname rows with global uniqueness.
2. **Caddy host matcher.** Extend the existing routes so each one also
   matches the custom hostnames.
3. **TLS issuance.** Add an on-demand TLS policy whose `ask` endpoint the
   daemon hosts.
4. **Lifecycle + cluster-mode glue.** Routes must be torn down on
   stop/destroy and re-installed by `Reconcile`; in cluster mode the
   ingress nodes (not just the owner) need the route.

---

## Non-goals (v1)

- **Custom domain on raw `tcp://` or `tls://` ports.** Both modes rely on
  the shared caddy-l4 setup. The L4 TLS mux currently terminates with the
  `*.$DOMAIN` wildcard manager and routes by SNI to a sandbox-derived host
  (`pkg/caddy/client.go:822`). Doing custom domains there means
  per-exposure cert provisioning inside caddy-l4 (no on-demand-TLS handler
  exists for layer4), which is a larger workstream. Reject
  `protocol="tcp"` and `protocol="tls"` cleanly when custom domains are
  set; revisit in a follow-up plan.
- **Per-port custom domain.** v1 attaches the custom hostname to the
  sandbox root (`<id>.$DOMAIN` semantics — proxies to toolbox port).
  Per-port custom hostnames (`api.acme.com` → container:8080) come
  later; the route shape supports it but the SDK and store schema
  stay scoped to root for v1.
- **Apex DNS records the user can't create.** We don't host DNS. Users
  must CNAME (or `ALIAS`/`ANAME` for apex) to the cluster's ingress host.
  Plan only handles the AerolVM side of that contract.
- **Wildcard custom domains.** `*.acme.com` not in v1.
- **IP / path-mode deployments (no `SB_DOMAIN`).** Custom domains require
  domain mode. In IP mode the API returns 412 Precondition Failed.

---

## User experience

```ts
// SDK
const sb = await microvm.sandboxes.create({
  image: "node:20",
  custom_domains: ["api.acme.com", "acme.com"],  // optional
});

// Later — attach more, or detach
await sb.customDomains.add("staging.acme.com");
await sb.customDomains.remove("acme.com");

// What you get back
sb.customDomains;           // ["api.acme.com", "acme.com"]
sb.publicUrl;               // "https://sb-abc.aerol.cloud" (unchanged)
sb.customDomainUrls;        // ["https://api.acme.com", "https://acme.com"]
```

Operator-side, the only requirement is that the operator has pre-pointed
`api.acme.com` (and `acme.com`) at the cluster's ingress host **before**
calling add — otherwise the first HTTPS hit will return a 502 until ACME
HTTP-01 succeeds. We don't pre-validate DNS; the `ask` endpoint just
gates which hosts Caddy is allowed to attempt issuance for.

---

## Architecture

### 1. Store schema

New table — one row per (sandbox, hostname). Global uniqueness on
hostname (a hostname maps to exactly one sandbox at a time).

```sql
CREATE TABLE sandbox_custom_domains (
    hostname    TEXT PRIMARY KEY,                  -- lowercased, no trailing dot
    sandbox_id  TEXT NOT NULL,
    created_at  DATETIME NOT NULL,
    FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
);
CREATE INDEX idx_sandbox_custom_domains_sandbox_id
    ON sandbox_custom_domains(sandbox_id);
```

The PK on `hostname` is the global uniqueness enforcement — the same
pattern the L4 host-port partial unique index uses for collision-safe
allocation (`internal/store/store.go:312`). On `ON CONFLICT` the API
returns 409, never silently steals the hostname.

`store.go` additions:

- `AddCustomDomain(ctx, sandboxID, hostname) error` — single `INSERT ... ON
  CONFLICT DO NOTHING`; returns `models.ErrConflict` when the hostname is
  already taken by another sandbox.
- `RemoveCustomDomain(ctx, sandboxID, hostname) error` — `DELETE WHERE
  hostname = ? AND sandbox_id = ?`. Mismatched sandbox returns
  `models.ErrNotFound`.
- `ListCustomDomains(ctx, sandboxID) ([]string, error)`.
- `ListAllCustomDomains(ctx) ([]CustomDomainRow, error)` — reconcile uses
  this to GC stale Caddy host matchers and to answer the `ask` endpoint.
- `ResolveCustomDomain(ctx, hostname) (sandboxID string, error)` — hot path
  for the `ask` endpoint. **Must be O(1)** — PK lookup, no scan.

Attach to bulk read in `attachPortsBulk` style (`store.go:678`): a
sibling `attachCustomDomainsBulk` does one query and groups by
`sandbox_id`, called from `loadSandboxesByIDs`.

### 2. Models

```go
// pkg/models/types.go
type CreateSandboxRequest struct {
    // ... existing fields
    CustomDomains []string `json:"custom_domains,omitempty"`
}

type Sandbox struct {
    // ... existing fields
    CustomDomains []string `json:"custom_domains,omitempty"`
}

type AddCustomDomainRequest struct {
    Hostname string `json:"hostname"`
}
```

Validation in `pkg/models` (called from both the v1 handler and
`Service.CreateSandbox`):

- Lowercase.
- Strip trailing dot.
- Each label ≤ 63 chars, total ≤ 253, RFC 1035 label charset.
- **Reject anything under `$DOMAIN`** — the wildcard already covers
  `*.$DOMAIN`. Catching this here keeps the matcher unambiguous and
  prevents a user from stealing `<some-other-id>.$DOMAIN`.
- **Reject IP literals.**
- **Reject `localhost` and `.local`.**
- Per-sandbox cap (e.g. 25) and per-request cap (e.g. 5 on create) to
  bound the matcher fan-out and ACME burst.

### 3. v1 routes

```
POST   /v1/sandboxes/{id}/custom-domains   {"hostname": "api.acme.com"}
DELETE /v1/sandboxes/{id}/custom-domains/{hostname}
GET    /v1/sandboxes/{id}/custom-domains   → ["api.acme.com", ...]
```

`GET /v1/sandboxes/{id}` (and List) include `custom_domains` in the
response.

Wire under the existing pattern (`pkg/api/v1/routes.go:89`). Follow
`/touch-create-sandbox` because `CreateSandboxRequest` gains a field
that flows through the create path.

### 4. Caddy: extend the host matcher

`UpsertSandboxRoute` today writes:

```jsonc
"match": [{"host": ["<id>.$DOMAIN"]}]
```

Extend to:

```jsonc
"match": [{"host": ["<id>.$DOMAIN", "api.acme.com", "acme.com"]}]
```

Function signature gains a `customHostnames []string` parameter (and the
peer-route variant for IP mode is a no-op since custom domains require
domain mode):

```go
func (c *Client) UpsertSandboxRoute(
    ctx context.Context,
    id, containerIP string,
    toolboxPort int,
    customHostnames []string,
) error
```

Caddy's `host` matcher is an OR-list, so one PATCH replaces the entire
matcher in place — exactly the same idempotent shape as today. No new
route, no new server, no listener change.

**Lazy bootstrap rule.** The first time a sandbox gets a custom domain
added the route already exists (sandbox is started → route was installed
at start). We just re-PATCH with the new matcher set. Idempotent.

### 5. TLS: on-demand issuance

In domain-mode today the HTTPS site reuses the wildcard cert manager. For
custom hostnames we add an on-demand TLS policy that calls back into
sandboxd to check whether the hostname is allowed.

Caddy's on-demand config (added to the existing `apps/tls/automation`
section in `pkg/caddy/client.go`'s install-time config push):

```jsonc
{
  "apps": {
    "tls": {
      "automation": {
        "policies": [
          { /* existing wildcard via DNS-01 — unchanged */ },
          {
            "on_demand": true,
            "issuers": [
              { "module": "acme" }
            ]
          }
        ],
        "on_demand": {
          "rate_limit": { "interval": "1m", "burst": 5 },
          "ask": "http://127.0.0.1:<api-port>/internal/tls-ask"
        }
      }
    }
  }
}
```

The on-demand policy is **last** in the policies list so Caddy first
matches the wildcard for `*.$DOMAIN`, then falls through to on-demand for
everything else. Hosts unknown to sandboxd are rejected by `ask`,
which means Caddy never attempts ACME for them — that is the abuse
defense.

The `ask` endpoint (loopback-only, never exposed publicly):

```go
// internal/ingress/tls_ask.go (new file)
// GET /internal/tls-ask?domain=<host>
//
// 200 → Caddy may issue a cert for this host.
// 4xx → Caddy refuses to attempt issuance.
//
// Hot path. Single PK lookup; no logs on the success path.
func (h *Handler) TLSAsk(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("domain")
    if host == "" {
        http.Error(w, "missing domain", http.StatusBadRequest)
        return
    }
    host = strings.ToLower(strings.TrimSuffix(host, "."))
    // Allow our own wildcard children (defense in depth — wildcard policy
    // should match first, but if Caddy ever falls through, we still say yes).
    if strings.HasSuffix(host, "."+h.cfg.Domain) || host == h.cfg.Domain {
        w.WriteHeader(http.StatusOK)
        return
    }
    if _, err := h.store.ResolveCustomDomain(r.Context(), host); err != nil {
        if errors.Is(err, models.ErrNotFound) {
            http.Error(w, "unknown host", http.StatusForbidden)
            return
        }
        http.Error(w, "lookup failed", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

Listen address: `internal/config.Config.InternalIngressAddr` (already
loopback-only — same address the wake proxy binds to). Add an
`/internal/tls-ask` route on that listener; **must not** be on the public
API listener.

### 6. HTTP-01 challenge path

For HTTP-01 to work, port 80 has to reach Caddy. In domain mode Caddy
already binds `:80` for ACME redirects and challenge responses; the
existing route on `:80` is fine. The only thing this plan changes there
is: Caddy now responds to ACME challenges for the custom hostnames too,
which is automatic once the on-demand policy is active.

**Cluster mode caveat.** ACME HTTP-01 challenges arrive on whichever
ingress node DNS resolves to. That node must own the route (or proxy to
the owner) **and** Caddy on that node must hold the on-demand policy. We
need every ingress node to install the on-demand policy at startup (same
config push as today). Routes for a non-owned sandbox use
`UpsertSandboxRouteToPeer` (`pkg/caddy/client.go:175`) — extend it the
same way: matcher takes the custom hostnames too, upstream stays the
peer.

In the unlucky case where the challenge arrives at node A and Caddy's
on-demand kicks off there, but the issued cert is needed on node B too:
each node issues independently the first time it sees the host (rate-
limited per the on-demand config). Acceptable for v1; a shared cert
storage (S3 / Raft / file replication) is a future optimization.

### 7. Service layer

`internal/service/custom_domains.go` (new):

```go
func (s *Service) AddCustomDomain(ctx, sandboxID, hostname) error
func (s *Service) RemoveCustomDomain(ctx, sandboxID, hostname) error
func (s *Service) reinstallCustomDomainRoutes(ctx, sandbox) error  // used by reconcile, start
```

`AddCustomDomain` ordering — store first, caddy second:

1. Validate.
2. `store.AddCustomDomain` (atomic conflict on the PK).
3. Re-PATCH the existing sandbox route with the union of hostnames.
4. On (3) failure, **delete** the row we just inserted and bubble the
   error. (Same rollback shape as `expose_port`'s failure paths —
   `pr-review.md` §4.)

`RemoveCustomDomain` ordering — caddy first, store second, with
reconcile as the safety net:

1. Re-PATCH the route with the hostname removed.
2. `store.RemoveCustomDomain`.
3. If (2) fails after (1), log; reconcile will re-converge.

`CreateSandbox` integration:

- After the sandbox is started and its base route is installed, attach
  each `req.CustomDomains` entry via `AddCustomDomain`. On any single
  failure the create call rolls back the sandbox (same cleanup the existing
  failure-path test asserts — `/touch-create-sandbox`). PR description
  must call out the boot-path latency impact.

`StartSandbox`, `RecreateSandbox`, `Reconcile`: re-install routes including
custom hostnames (read from `ListCustomDomains` and pass to
`UpsertSandboxRoute`). Same wakeup behavior as `upsertExposedPortRoute`
(`service.go:1275`).

`StopSandbox` / `DestroySandbox`: existing route deletion already handles
this (route is keyed by sandbox ID; deleting it removes all host
matchers).

### 8. Reconcile

`Reconcile` already walks sandboxes and reasserts their routes. With this
plan it also:

1. Pulls `ListAllCustomDomains` and passes the per-sandbox slice into
   the matcher re-install.
2. **Zombie GC pass**: lists current Caddy `apps/http` routes (existing
   `ListHTTPRouteIDs` — `pkg/caddy/client.go`); any custom host matcher
   on a route whose sandbox is gone gets pruned. Today this is handled
   by deleting the whole route on sandbox destroy; we keep that and add
   a defensive scan in case of partial-write races.
3. Re-PATCH any sandbox route whose Caddy matcher set diverges from the
   DB set (e.g. caddy was wiped, or a node took over and didn't have
   the matcher).

### 9. Cluster mode

`internal/cluster/` carries no per-sandbox routing state — that lives
in the owner's local store. Custom domains follow the same shape:

- **DB rows live on the owner.** `sandbox_custom_domains` is part of
  the owner's SQLite. Failover replication (`recovery_replication.go`)
  must include the new table — every place we currently replicate
  `exposed_ports` for a sandbox, we replicate `sandbox_custom_domains`
  alongside it.
- **Ingress nodes need the matcher.** Today the ingress path for a non-
  owned sandbox is `UpsertSandboxRouteToPeer` (`client.go:175`). That
  function must learn the custom hostnames too. The owner pushes them
  via the existing route-publish gossip path; ingress nodes apply.
- **`ask` endpoint is per-node.** Each node's `ResolveCustomDomain` only
  knows about sandboxes whose state it has — i.e. the owner and any
  ingress node that has been told about the route. For v1 we accept
  that the first request after a custom domain is added might hit a
  cold ingress node that returns 403 to Caddy on the `ask`. The owner
  push to ingress nodes happens on the same code path as the existing
  per-port route push, so the window is small. If this is unacceptable
  we add a cluster-wide hostname → sandbox lookup that any node can
  serve (e.g. via the placement FSM); call this an open question for
  the eng review.

PR call-outs required (`CLAUDE.md` cluster hard-rule):

- Replication tests: a custom domain set on the owner before failover
  appears on the new owner.
- Single-node regression: `EnableCluster=false` still works (the
  `cluster.Noop` already returns nil; we just need to not call
  cluster-specific paths in single-node).
- Replay safety: re-applying an `AddCustomDomain` event after recovery
  is a no-op (the `INSERT OR IGNORE` semantics already give us this).

---

## Files to modify / create

| File | Change |
|---|---|
| `internal/store/store.go` | Add `sandbox_custom_domains` table + index, plus the 5 CRUD methods listed in §1. Bulk attach in `attachPortsBulk`-style. |
| `internal/store/store_test.go` | New tests: PK conflict returns ErrConflict; ResolveCustomDomain is O(1); reconcile-style list across sandboxes. **Required by hard-rule for store changes.** |
| `pkg/models/types.go` | `CreateSandboxRequest.CustomDomains`, `Sandbox.CustomDomains`, `AddCustomDomainRequest`. Validation helper `ValidCustomDomain(host, baseDomain)`. |
| `pkg/models/types_test.go` | Validation: case-folding, trailing dot, baseDomain rejection, IP/localhost rejection. |
| `pkg/api/v1/routes.go` | Three new routes (POST/DELETE/GET). |
| `pkg/api/v1/handlers.go` | Thin decode → service → encode for the three handlers. |
| `pkg/api/v1/dto.go` (or wherever DTOs live) | Wire types. |
| `internal/service/custom_domains.go` *(new)* | `AddCustomDomain`, `RemoveCustomDomain`, `reinstallCustomDomainRoutes`. |
| `internal/service/service.go` | `CreateSandbox` consumes `req.CustomDomains` after route install. `StartSandbox`/`RecreateSandbox` pass custom hostnames into `UpsertSandboxRoute`. |
| `internal/service/reconcile.go` (or service.go if not yet split) | Apply custom hostnames in the re-install pass; zombie matcher GC. |
| `internal/ingress/tls_ask.go` *(new)* | The `ask` handler. Bound to `InternalIngressAddr`. |
| `cmd/sandboxd/main.go` | Wire the new internal route on the existing internal listener. |
| `pkg/caddy/client.go` | `UpsertSandboxRoute` and `UpsertSandboxRouteToPeer` take `customHostnames []string`. Install-time config push adds the on-demand TLS policy. |
| `pkg/caddy/client_test.go` | New: matcher PATCH includes custom hostnames; on-demand policy is present after install push; rate-limit shape matches. |
| `internal/cluster/recovery_replication.go` | Replicate the new table. |
| `internal/cluster/*_test.go` | Failover regression: custom domains survive owner change. |
| `internal/config/config.go` | Read `SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX` (default 25), `SB_TLS_ON_DEMAND_BURST` (default 5), `SB_TLS_ON_DEMAND_INTERVAL` (default `1m`). |
| `sdk/typescript/src/Sandbox.ts` and the other 4 SDKs | `sandbox.customDomains` add/remove/list, `customDomains: string[]` on the create request. Use `/add-sdk-method` to keep lockstep. |
| `docs/src/content/docs/custom-domains.mdx` *(new)* | Hard rule: 5-language tabs, no curl. Includes DNS setup steps (CNAME to ingress host) and the `ask` flow at a high level. |
| `docs/src/content.config.ts` | Register the new page in the sidebar. |

---

## Tests

Required (per `CLAUDE.md` hard rules and `pr-review.md`):

- `internal/store/store_test.go`
  - `AddCustomDomain` returns ErrConflict on PK collision.
  - `RemoveCustomDomain` is no-op + ErrNotFound on mismatched sandbox.
  - `ResolveCustomDomain` returns ErrNotFound for unknown hosts (no panic).
  - Cascade: deleting the sandbox row removes its custom domains.
- `pkg/caddy/client_test.go`
  - `UpsertSandboxRoute` writes `host: [...]` with the union of base
    name and custom hostnames; passing the same set twice is byte-
    identical (idempotent PATCH).
  - Install config push contains exactly one on-demand policy with
    `ask` pointing at the loopback address.
- `internal/service/custom_domains_test.go`
  - Add → Caddy failure → store row deleted.
  - Remove → Caddy success → store row deleted.
  - Add over the per-sandbox cap → 4xx with stable error.
- `internal/ingress/tls_ask_test.go`
  - Known host → 200, unknown → 403, malformed → 400, base-domain child
    → 200.
- `internal/cluster/recovery_replication_test.go`
  - Sandbox has 2 custom domains, owner dies, new owner answers
    `ask` for both.
- `layer4_bootstrap_test.go` — unchanged, but cross-link: custom
  domains must not interact with the L4 latch (TCP/TLS exposures
  are explicitly rejected when custom_domains is set; the test
  asserts the error path).

---

## Rollout

1. Land schema, store CRUD, model validation, tests. No external surface
   yet. (Safe to ship — the table is read-only at this point.)
2. Land the `ask` handler + on-demand TLS policy in the install-time
   config push. Verify with a manual ACME issuance against a staging
   domain.
3. Land the v1 routes and service layer behind a config gate
   `SB_ENABLE_CUSTOM_DOMAINS` (default false). API returns 412 when off.
4. Land the SDK methods in lockstep (`/add-sdk-method`).
5. Land the docs page (`/add-docs-page`).
6. Flip the gate default to true once the staging cluster has run with
   it for a week without incident.

The gate is a rollout switch, not a per-sandbox toggle — matches the
`EnableServerless` pattern in `internal/config/config.go:131`.

---

## Risks & open questions

1. **Apex domain ACME challenge.** HTTP-01 on the apex requires the
   user to point an A / `ALIAS` / `ANAME` record at the ingress host.
   Cloud DNS providers that don't support `ALIAS` (e.g. Route53 for
   non-AWS targets, raw bind) will be limited to subdomains. Document
   clearly; consider supporting per-domain DNS-01 in v2 to sidestep.
2. **Cold ingress node returning 403 on `ask`.** Stated above. The
   cleanest fix is a cluster-wide lookup via the placement FSM, but it
   adds Raft load. Eng review should decide: accept the small window,
   or add the FSM lookup.
3. **ACME rate limits.** Let's Encrypt has per-domain and per-account
   limits. A misconfigured user could ask for 100 custom domains and
   burn issuance budget. Per-sandbox cap + on-demand `rate_limit` give
   us two layers; consider also a daemon-wide budget counter for v2.
4. **Cert revocation on remove.** When a user removes a custom domain
   we delete the matcher; Caddy keeps the cert in storage until expiry.
   That's fine for correctness (the host no longer routes) but bloats
   `data_dir`. A background sweep that prunes cached certs for unknown
   hosts is a follow-up.
5. **Cluster-wide hostname uniqueness.** The store PK is per-owner. If
   sandbox A on node N1 and sandbox B on node N2 both claim
   `api.acme.com`, both inserts succeed locally. Today no global lock
   exists. Either route this through Raft (placement FSM gains a
   hostname→sandbox map) or accept that the second one to hit ingress
   wins. Open question.
6. **Wildcard custom domain via DNS-01.** Out of scope; flagged for
   the v2 plan.

---

## Out of scope, follow-up plans

- `plans/custom-domains-l4.md` — custom hostnames on `protocol="tcp"`
  and `protocol="tls"` port exposures. Needs per-exposure cert
  provisioning in caddy-l4.
- `plans/custom-domains-per-port.md` — `api.acme.com` → container:8080
  rather than the sandbox root.
- `plans/custom-domains-dns01.md` — per-host DNS-01 issuance so
  wildcard custom domains and apex domains without `ALIAS` support
  can work.
