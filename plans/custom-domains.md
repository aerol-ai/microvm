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
    status      TEXT NOT NULL DEFAULT 'pending_dns',
    last_error  TEXT,
    created_at  DATETIME NOT NULL,
    updated_at  DATETIME NOT NULL,
    FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
);
CREATE INDEX idx_sandbox_custom_domains_sandbox_id
    ON sandbox_custom_domains(sandbox_id);
```

The `status` column is the per-domain state machine surfaced through the API
(OV4A) — see §2.

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

// CustomDomainStatus is the per-domain lifecycle state surfaced through
// API + SDK (OV4A). Drives UX: clients render "DNS not pointed yet" vs
// "issuing cert" vs "ready" without polling Caddy.
type CustomDomainStatus string

const (
    CustomDomainPendingDNS CustomDomainStatus = "pending_dns" // row exists, no cert seen
    CustomDomainIssuing    CustomDomainStatus = "issuing"     // ACME flow started (first ask hit)
    CustomDomainReady      CustomDomainStatus = "ready"       // cert in storage
    CustomDomainFailed     CustomDomainStatus = "failed"      // ACME gave up; LastError set
)

type CustomDomain struct {
    Hostname  string             `json:"hostname"`
    Status    CustomDomainStatus `json:"status"`
    LastError string             `json:"last_error,omitempty"`
    CreatedAt time.Time          `json:"created_at"`
    UpdatedAt time.Time          `json:"updated_at"`
}

type CreateSandboxRequest struct {
    // ... existing fields
    CustomDomains []string `json:"custom_domains,omitempty"` // bare hostnames on create
}

type Sandbox struct {
    // ... existing fields
    CustomDomains []CustomDomain `json:"custom_domains,omitempty"` // full status on read
}

type AddCustomDomainRequest struct {
    Hostname string `json:"hostname"`
}
```

State machine (driven by service layer, not by the SDK caller):

```
            AddCustomDomain
                  │
                  ▼
            pending_dns ──── ask hit ────▶ issuing
                  │                           │
                  │                           │ cert in storage
                  ▼                           ▼
              (delete)                      ready
                                              │
                                              │ cert renew fails
                                              ▼
                                            failed ──── ask hit ────▶ issuing
```

The `pending_dns → issuing` transition happens inside `TLSAsk` (§5) the
first time Caddy asks about the hostname. `issuing → ready` happens when
the next `ask` hit confirms the cert exists in storage (cheap stat via
certmagic). `* → failed` is observability-only for v1: we surface a Caddy
ACME failure log line as `last_error`; no automatic retry beyond Caddy's
own backoff.

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

**Shared cert storage is already wired (A4-doc).** When deployed via
`scripts/install.sh --caddy-storage-s3`, `packaging/Caddyfile.template`
injects a `storage s3 { ... }` directive that points Caddy at S3 via the
certmagic-s3 plugin. The plugin handles distributed locking so two nodes
issuing the same custom hostname simultaneously coordinate through S3
rather than racing Let's Encrypt twice. The new on-demand policy below
inherits that storage automatically — no new code, just a docs cross-link
to `setup/multi-node-cert-sharing.md`. The doc must be updated to mention
that custom-hostname certs now share the same S3 bucket as the wildcard.

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

The `ask` endpoint lives as a sibling file in the wake-proxy package
(A5A — `pkg/api/ingressproxy/tls_ask.go`), not in a new `internal/ingress/`
package. It registers on the existing `InternalIngressAddr` listener
(loopback-only, bound in `cmd/sandboxd/main.go:397`):

```go
// pkg/api/ingressproxy/tls_ask.go (new file, sibling of routes.go)
//
// GET /internal/tls-ask?domain=<host>
//
// 200 → Caddy may issue a cert for this host.
// 4xx → Caddy refuses to attempt issuance.
//
// Hot path. Cluster-wide hostname lookup hits the local Raft FSM (A2A);
// no SQLite touch. Negative results are LRU-cached for 60s (C1A) so an
// SNI flood from a scanner can't burn CPU.
func (h *TLSAskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    host := strings.ToLower(strings.TrimSuffix(r.URL.Query().Get("domain"), "."))
    if host == "" {
        http.Error(w, "missing domain", http.StatusBadRequest)
        return
    }
    // Defense in depth — wildcard policy should match first.
    if host == h.cfg.Domain || strings.HasSuffix(host, "."+h.cfg.Domain) {
        w.WriteHeader(http.StatusOK)
        return
    }
    if h.negCache.has(host) {
        http.Error(w, "unknown host", http.StatusForbidden)
        return
    }
    sandboxID, ok := h.fsm.ResolveCustomDomain(host) // local Raft FSM lookup
    if !ok {
        h.negCache.add(host) // 60s TTL, cap 10k entries
        http.Error(w, "unknown host", http.StatusForbidden)
        return
    }
    h.acmeBudget.RecordAttempt(sandboxID) // see §5b
    h.status.MarkIssuing(host)            // pending_dns → issuing
    w.WriteHeader(http.StatusOK)
}
```

The handler reads from the cluster FSM (`internal/cluster/fsm.go`'s
hostname → sandbox map — see §10), not from the local SQLite store. In
single-node mode the in-process FSM still serves the same lookup
(`cluster.Noop` exposes a degenerate hostname map backed by the store).
Negative cache entries are evicted whenever `AddCustomDomain` succeeds for
that hostname (so a legitimate add doesn't have to wait 60s).

### 5b. ACME budget (OV5A)

Let's Encrypt enforces a per-account `new-orders` limit (currently 300 /
3hr). A misconfigured user with 100 custom domains can blow that for the
whole cluster. v1 ships a daemon-wide token bucket:

```go
// internal/service/acme_budget.go
//
// One bucket per Caddy ACME account. Refills at the LE published rate.
// On every TLSAsk that would trigger issuance (status != ready), Reserve
// returns false if we're at >=80% of the burst capacity, and ask returns
// 429 to Caddy. 80% leaves headroom for the cert renewals already in
// flight.
type ACMEBudget struct { ... }

func (b *ACMEBudget) Reserve(sandboxID string) (ok bool)
```

The 80% threshold is configurable via `SB_ACME_DAEMON_BUDGET_FRACTION`
(default `0.8`). Budget exhaustion is logged with `sandbox_id` so the
operator can see which tenant burned the quota. Cluster-mode: each node
maintains its own bucket; we deliberately do **not** synchronise via
Raft (one bucket per ingress node is fine — LE limits are per-account,
not per-IP, and serial issuance across nodes is rare given the s3
distributed lock).

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

**Fan-out ceiling (P1A).** Reconcile walks all sandboxes; each
custom-domain matcher write is O(1) in Caddy. At 10k sandboxes × 25
custom domains the bounded matcher-string size is ~25k hostnames
per cluster, well under Caddy's host-matcher scaling. We do not
paginate reconcile in v1; if cluster size ever crosses 50k sandboxes
we revisit. (Documented assumption, not a code gate.)

### 9. Cluster mode

Custom-domain routing piggybacks on the **delta-driven ingress
convergence** mechanism in `internal/service/ingress_delta.go` (A1A) —
the same path that already keeps non-owner ingress nodes in sync for
per-port routes. We do **not** make direct `UpsertSandboxRouteToPeer`
calls from `AddCustomDomain`.

Flow:

1. **Owner applies the change locally.** `AddCustomDomain` validates,
   inserts the SQLite row, and submits an `ApplyAddCustomDomain` Raft
   command (§10). The command writes the hostname → sandbox mapping into
   the FSM and bumps the sandbox's `ingress_version`.
2. **Ingress delta loop notices.** `ingress_delta.go` watches the FSM
   for `ingress_version` changes on sandboxes whose routes this node
   serves. On bump it computes the delta between
   `cluster.SandboxRouteSpec.CustomHostnames` (now the union from the
   FSM) and Caddy's currently-installed matcher set, and PATCHes
   `UpsertSandboxRouteToPeer` once with the full set.
3. **`cluster.ForwardHTTP` is unchanged.** Cross-node HTTP forwarding
   keys off `sandbox_id`, not hostname; once Caddy on the ingress node
   matches the custom hostname, the existing reverse-proxy path
   transparently reaches the owner.
4. **Failover.** `recovery_replication.go` already replicates
   per-sandbox state to the failover replicas. Extend the replicated
   blob with `custom_domains: []{hostname, status, last_error}` so the
   new owner has the SQLite rows on takeover. The FSM hostname map is
   already replicated by Raft itself.

PR call-outs required (`CLAUDE.md` cluster hard-rule):

- **Replication test**: sandbox with two custom domains, kill the
  owner, assert new owner answers `TLSAsk` for both hostnames and
  Caddy still serves them.
- **FSM replay test**: re-applying `ApplyAddCustomDomain` after Raft
  snapshot restore is a no-op (idempotent on hostname PK in the map).
- **Single-node regression**: `EnableCluster=false` uses a degenerate
  `Noop` FSM that resolves hostnames from the local store; no Raft
  commands submitted; same `TLSAsk` and route-install code paths.
- **Cluster ingress on a non-owner node**: SNI for the custom hostname
  arrives at node Z which is not the owner; FSM lookup resolves it;
  Caddy matches the route; `cluster.ForwardHTTP` reaches the owner.

### 10. FSM hostname uniqueness (A2A + OV7A)

`internal/cluster/fsm.go` gains a hostname → sandbox map and two new
Raft commands:

```go
// internal/cluster/fsm.go
type FSMState struct {
    // ... existing
    CustomDomains map[string]string // hostname → sandboxID (lowercase)
}

type ApplyAddCustomDomain struct {
    Hostname  string
    SandboxID string
    NodeID    string // owner node, for audit
}

type ApplyRemoveCustomDomain struct {
    Hostname  string
    SandboxID string // must match; cross-sandbox removal rejected
}
```

`ApplyAddCustomDomain` is the **uniqueness gate**. On replay:

- If `CustomDomains[hostname]` is unset → insert, bump
  `sandboxes[id].IngressVersion`, return ok.
- If it points to the same `SandboxID` → no-op (replay-safe), return ok.
- Otherwise → return `models.ErrConflict`. The owner's `AddCustomDomain`
  reverses the SQLite insert and returns 409 to the caller. This is the
  cluster-wide collision-safe allocation guarantee — the same shape as
  the `host_port` partial-unique-index pattern (`store.go:312`) but at
  the Raft layer because SQLite-PK uniqueness is per-node.

**Lifecycle tied to placement (OV7A).** Hostname entries are owned by
the sandbox placement, not by the SQLite row. Wherever a placement is
removed from the FSM (sandbox destroy, owner-drained-and-not-recovered,
cluster shrink), the same Raft command path releases every hostname in
`CustomDomains` whose `sandboxID` matches. There is no
"orphan hostname" path — if the placement is gone the hostname is gone
in the same Raft log entry. The matching `ApplyRemoveSandbox` (or
whichever existing command tears placement down) is extended with the
hostname-release sweep.

Snapshot/restore: the hostname map serializes alongside the rest of
`FSMState`. No new snapshot path; piggybacks on the existing one.

`cluster.Noop` (single-node) implements the same interface against a
local store-backed map; in single-node mode SQLite PK uniqueness is the
backing guarantee. The single-node path is the regression test target.

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
| `pkg/api/ingressproxy/tls_ask.go` *(new)* | The `ask` handler + LRU negative cache. Sibling of `routes.go` on the existing `InternalIngressAddr` listener (A5A). |
| `pkg/api/ingressproxy/routes.go` | Register `/internal/tls-ask` on the ingress mux. |
| `pkg/caddy/client.go` | `UpsertSandboxRoute` and `UpsertSandboxRouteToPeer` take `customHostnames []string`. Install-time config push adds the on-demand TLS policy (after the wildcard policy). |
| `pkg/caddy/client_test.go` | New: matcher PATCH includes custom hostnames; on-demand policy is present after install push; rate-limit shape matches. |
| `internal/cluster/fsm.go` | Hostname → sandbox map; `ApplyAddCustomDomain` / `ApplyRemoveCustomDomain` Raft commands; hostname-release sweep in placement-teardown command (OV7A). |
| `internal/cluster/fsm_test.go` | Conflict, replay safety, placement-teardown release, snapshot/restore. |
| `internal/cluster/noop.go` | Degenerate hostname-map shim backed by the local store (single-node mode). |
| `internal/cluster/recovery_replication.go` | Replicate the new table alongside `exposed_ports`. |
| `internal/service/ingress_delta.go` | Extend the spec carried per sandbox to include `CustomHostnames`; bump `ingress_version` on add/remove. |
| `internal/service/ingress_delta_test.go` | Delta-driven matcher propagation to ingress nodes. |
| `internal/service/acme_budget.go` *(new)* | Daemon-wide ACME token bucket (OV5A). 80%-of-LE-account-limit gate. |
| `internal/observability/metrics.go` | `acme_lock_held_seconds` gauge, `acme_lock_acquire_duration_seconds` histogram, `ask_requests_total{result}` counter (F3/F4). |
| `setup/prometheus/alerts/sandboxd.yml` | Alert on `acme_lock_held_seconds > 300`; alert on `rate(ask_requests_total[2m]) == 0 while up == 1`. |
| `setup/multi-node-cert-sharing.md` | Cross-link from §5: explicitly mention custom-hostname certs ride the same S3 bucket as the wildcard (A4-doc). |
| `internal/config/config.go` | `SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX` (default 25), `SB_TLS_ON_DEMAND_BURST` (default 5), `SB_TLS_ON_DEMAND_INTERVAL` (default `1m`), `SB_ENABLE_CUSTOM_DOMAINS` (gate, default false), `SB_ACME_DAEMON_BUDGET_FRACTION` (default 0.8). |
| `sdk/typescript/src/Sandbox.ts` and the other 4 SDKs | `sandbox.customDomains` add/remove/list, `customDomains: string[]` on the create request. Use `/add-sdk-method` to keep lockstep. |
| `docs/src/content/docs/custom-domains.mdx` *(new)* | Hard rule: 5-language tabs, no curl. Includes DNS setup steps (CNAME to ingress host) and the `ask` flow at a high level. |
| `docs/src/content.config.ts` | Register the new page in the sidebar. |

---

## Tests

Required (per `CLAUDE.md` hard rules and `pr-review.md`):

**Store** — `internal/store/store_test.go`
  - `AddCustomDomain` returns `ErrConflict` on hostname PK collision
    across sandboxes.
  - `AddCustomDomain` is idempotent for same `(sandbox, hostname)`.
  - `RemoveCustomDomain` returns `ErrNotFound` on mismatched sandbox.
  - `ResolveCustomDomain` returns `ErrNotFound` for unknown hosts.
  - Cascade: deleting the sandbox row removes its custom domains.
  - `attachCustomDomainsBulk` correctly groups by `sandbox_id` across
    a mixed-result query.
  - Status transitions: `MarkIssuing`, `MarkReady`, `MarkFailed` are
    idempotent and update `updated_at`.

**Models / validation** — `pkg/models/types_test.go`
  - Case-folding (`API.ACME.COM` → `api.acme.com`).
  - Trailing dot stripped.
  - Base-domain rejection (`<id>.$DOMAIN`, `$DOMAIN` itself).
  - IP literal rejection (v4 + v6).
  - `localhost`, `*.local` rejected.
  - Boundary: 63-char label accepted, 64-char rejected; 253-char total
    accepted, 254 rejected.
  - Per-request cap (5 on create) → validation error.

**Caddy** — `pkg/caddy/client_test.go`
  - `UpsertSandboxRoute` writes `host: [...]` with the union of base
    name and custom hostnames; passing the same set twice is byte-
    identical (idempotent PATCH).
  - `UpsertSandboxRouteToPeer` (cluster ingress path) includes the
    custom-hostname set in its matcher.
  - Install config push contains exactly one on-demand policy with
    `ask` URL pointing at `InternalIngressAddr/internal/tls-ask`,
    `rate_limit.interval=1m`, `rate_limit.burst=5`.

**Service** — `internal/service/custom_domains_test.go`
  - Add → store insert OK → Caddy PATCH fails → store row rolled back.
  - Remove → Caddy PATCH OK → store delete; reconcile recovers if step 2
    fails.
  - Add over per-sandbox cap → stable error with cap name.
  - **IRON RULE regression**: `protocol="tcp"` exposure + `custom_domains`
    → rejected with explicit error (not silently accepted, not panic).
  - **IRON RULE regression**: `protocol="tls"` exposure + `custom_domains`
    → same.
  - IP-mode deployment (`SB_DOMAIN=""`) + `custom_domains` →
    412 Precondition Failed.
  - `EnableCustomDomains=false` + `custom_domains` → 412.

**ask handler** — `pkg/api/ingressproxy/tls_ask_test.go`
  - Known host → 200; unknown → 403; malformed (empty / IP) → 400;
    base-domain child → 200.
  - Negative cache: 1000 successive lookups for an unknown host hit FSM
    once, return 403 from cache subsequently; entries expire after 60s.
  - `AddCustomDomain` evicts the host from negative cache (verified by
    immediate ask returning 200 without 60s wait).
  - ACME budget exhaustion → 429 with `Retry-After` header.

**FSM** — `internal/cluster/fsm_test.go`
  - `ApplyAddCustomDomain` rejects cross-sandbox hostname conflict.
  - `ApplyAddCustomDomain` is replay-safe for same `(host, sandbox)`.
  - Removing a sandbox releases all its hostnames in the same Raft
    command.
  - Snapshot + restore round-trips the hostname map intact.

**Cluster ingress** — `internal/service/ingress_delta_test.go`
  - Adding a custom domain bumps `ingress_version`; ingress nodes
    pick up the new matcher within one delta cycle.
  - SNI request for a custom hostname arrives at a non-owner node →
    matched by Caddy → forwarded via `cluster.ForwardHTTP` to owner.

**Failover** — `internal/cluster/recovery_replication_test.go`
  - Sandbox has 2 custom domains; owner dies; new owner answers
    `TLSAsk` 200 for both; Caddy still serves them via shared S3 cert
    storage (no re-issuance triggered).

**API contract** — `pkg/api/v1/handlers_test.go`
  - `GET /v1/sandboxes/{id}` includes `custom_domains` with per-domain
    `status` field.
  - `POST /v1/sandboxes/{id}/custom-domains` idempotent for same host.
  - `DELETE` returns 404 for unknown host, 204 for known.

**E2E ACME** (T1A) — `internal/service/custom_domains_e2e_test.go`
  - Stand up Pebble (LE staging stand-in) + localstack S3 + sandboxd.
  - Add a custom domain with `/etc/hosts` override pointing at ingress.
  - Hit `https://<host>/` → first request triggers issuance via Pebble,
    second request serves cached cert from S3.
  - Kill ingress node, bring up a second one against the same S3 — cert
    reused, no second Pebble issuance.

**Layer4 cross-link** — `layer4_bootstrap_test.go` unchanged; the
IRON RULE regression above is the assertion that custom domains do not
interact with the L4 latch.

---

## 11. Workload assumptions (OV1A)

Designing for these workloads — scope decisions become wrong if reality
drifts far from them:

- **Long-lived sandboxes with stable hostnames.** Median sandbox lifetime
  measured in days, custom hostname attached at create time and rarely
  changed. We are **not** optimising for the "thousands of ephemeral
  one-off hostnames per hour" case — that would warrant a different
  cert-cache strategy (and is what TODO `Custom domains — cert blob GC
  after removal` is for at scale, see `TODOS.md`).
- **Bounded fan-out per sandbox.** Per-sandbox cap of 25 is intentional;
  it lets us keep the host matcher as a single in-place PATCH and avoid
  paginating reconcile.
- **Operator-controlled DNS.** Users own the DNS record they point at the
  cluster. We do not validate DNS pre-issuance; the `ask` endpoint is
  the only gate. Misconfigured users get a 502 until they fix DNS, not
  a silent failure.
- **Multi-tenant cluster.** A misbehaving tenant burning ACME budget
  must not starve other tenants. This is the OV5A motivation.
- **Read-heavy `ask` path.** Caddy can hammer `ask` during SNI bursts
  (scanners, mistuned clients). We size the negative cache for that.

If any of these stop holding (e.g. we want hostname-per-port, or we
expect 100k churning hostnames/day), revisit before extending v1.

## 12. Observability

Two failure modes from the eng review require monitoring before ship,
not just tests:

- **F3 — S3 lock held by a dead node during ACME.** certmagic-s3 takes
  a distributed lock on the cert key for the duration of the ACME flow.
  If a node dies mid-issuance the lock falls off via TTL; in pathological
  cases (network partition that masks the death) it can stick.
  Instrument: `acme_lock_acquire_duration_seconds` histogram +
  `acme_lock_held_seconds` per-active-lock gauge in `expvar`;
  Prometheus alert at >5m held.
- **F4 — `ask` loopback listener crashes mid-process.** If
  `ingressproxy.Server` exits but the rest of sandboxd keeps running,
  every new HTTPS connection will fail TLS until the next restart and
  Caddy's on-demand cache is cold. Instrument: `ask_requests_total{result}`
  counter + a Prometheus alert on the absence of any successful `ask`
  for >2m while the process is up.

Implementation lives next to existing metrics in
`internal/observability/`. Prometheus rules go in
`setup/prometheus/alerts/` alongside existing alerts. Both metrics + rules
ship in the v1 PR — not a follow-up.

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
2. **Cert revocation on remove.** When a user removes a custom domain
   we delete the matcher; Caddy keeps the cert in storage until expiry.
   Correctness intact, bloat only. Background sweep deferred to a
   follow-up — see `TODOS.md`.
3. **Wildcard custom domain via DNS-01.** Out of scope; flagged for
   the v2 plan.

**Closed during eng review** (decisions captured in GSTACK REVIEW REPORT below):

- Cluster-wide hostname uniqueness → resolved via FSM (A2A, §10).
- Cold ingress node returning 403 on `ask` → collapsed into FSM
  lookup (A3A).
- ACME budget burn by a misconfigured tenant → promoted to v1 scope
  via daemon-wide token bucket (OV5A, §5b).

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

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | not run |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | not run |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | issues_open (PLAN) | 13 issues, 2 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | not run (no UI scope) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | not run |

**Outside Voice:** Codex unavailable (binary broken); fell back to Claude subagent. Surfaced 7 findings, 4 promoted to cross-model tension decisions (OV1A, OV4A, OV5A, OV7A).

**CROSS-MODEL:** Outside voice agreed with all original architectural decisions (A1A, A2A, A3A, A4-resolve, A5A). Disagreed on TODO-3 — outside voice argued daemon-wide ACME budget enforcement is a v1 multi-tenant blocker, not a TODO. User accepted (OV5A); TODO-3 promoted to v1 scope.

**UNRESOLVED:** 0 decisions left open.

**Decisions locked (apply during implementation):**

| ID | Decision |
|---|---|
| A1A | Rewrite §9 around `internal/service/ingress_delta.go` (delta-driven cluster ingress convergence) instead of direct `UpsertSandboxRouteToPeer` calls |
| A2A | Cluster-wide hostname uniqueness enforced via placement FSM (Raft); `AddCustomDomain` becomes a Raft command, hostname→sandbox map in FSM state |
| A3A | `ask` endpoint reads from local FSM state (collapsed into A2A); no separate cold-cache lookup mechanism |
| A4-doc | certmagic-s3 shared cert storage already handles multi-node issuance via distributed lock — add §5 note + docs cross-link to `setup/multi-node-cert-sharing.md`; no new code |
| A5A | `ask` handler colocates with wake-proxy code on `InternalIngressAddr` (no new `internal/ingress/` package) |
| C1A | Add bounded LRU negative cache to `ask` handler (60s TTL, cap 10k, evict on successful `AddCustomDomain`) |
| T1A | Required v1 E2E test using Pebble + localstack S3 + `/etc/hosts` override to verify full ACME flow |
| P1A | Document expected reconcile fan-out ceiling; do not paginate in v1 |
| OV1A | Add "Workload assumptions" section to plan: who uses this, what sandbox lifetime model it assumes |
| OV4A | API + SDK gain per-domain status field: `{hostname, status: pending_dns\|issuing\|ready\|failed, error?}` |
| OV5A | Daemon-wide ACME issuance token bucket lands in v1 (not v2 TODO); refuse at 80% of LE account limit with 429 |
| OV7A | Hostname FSM entries are lifetime-bound to sandbox FSM placement; same Raft command that removes a sandbox releases its hostnames |
| TODO-1A | Cert blob GC after removal → `TODOS.md` (deferred) |
| TODO-3A | (Superseded by OV5A — promoted to v1) |

**Plan revisions required before code:**

1. Rewrite §9 cluster section around `ingress_delta.go` and `cluster.ForwardHTTP` (A1A).
2. Add §10 "FSM hostname uniqueness" subsection (A2A + OV7A).
3. Update §5 to cross-reference `setup/multi-node-cert-sharing.md` and note certmagic-s3 behavior (A4-doc).
4. Change §5 handler path from `internal/ingress/tls_ask.go` to a sibling file in the wake-proxy package (A5A).
5. Add §5b "ACME budget" subsection (OV5A).
6. Add §11 "Workload assumptions" section (OV1A).
7. Expand §2 Models with per-domain status field + state machine (OV4A).
8. Update §10 "Tests" — add regression tests (tcp/tls + custom_domains rejection, FSM, ingress_delta, negative cache, validation completeness, API contract, E2E ACME).
9. Move TODO-3 (daemon-wide ACME budget) out of "Risks & open questions" #3 into the v1 work breakdown.
10. Add a one-line capacity note in §8 (P1A reconcile fan-out ceiling).
11. Append "Critical observability" (Failure modes #3, #4) — expvar metrics + Prometheus alerts for `ask` call rate and certmagic-s3 lock duration — to v1 scope.

**Failure-mode critical gaps (must close before ship, not just before merge):** 2
- F3 — S3 lock held by dead node during ACME (no monitoring) → addressed by observability addition above
- F4 — `ask` loopback listener crashes mid-process (no monitoring) → addressed by observability addition above

**VERDICT:** ENG REVIEW COMPLETE (issues open). 13 plan revisions required before implementation starts. No second blocker found. CEO review and design review not applicable (backend/infra change with no UI surface). Re-run `/plan-eng-review` after the plan is updated to confirm closure, then run `/ship` when implementation lands.

