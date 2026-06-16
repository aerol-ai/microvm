# Plan: `maskRequestHost` — Caddy ingress Host-header rewrite

Status: **DRAFT — awaiting review**
Owner: server + 5 SDKs + docs
Stacks on: nothing (egress + `allowPublicTraffic` already merged to `main`)

---

## 1. Problem statement

E2B exposes a per-sandbox network option `network.maskRequestHost`. When a port
is exposed, ingress reaches the user's app through our reverse proxy at a public
hostname like `<port>-<sandboxid>.<domain>`. By default Caddy forwards the
incoming `Host` header **unchanged**, so the app inside the sandbox sees
`Host: <port>-<sandboxid>.<domain>`.

That breaks every framework that does **host-header allow-listing**:

- Vite (`server.allowedHosts`) → *"Blocked request. This host is not allowed."*
- webpack-dev-server (`allowedHosts`)
- Next.js dev server, Create-React-App dev server
- Django (`ALLOWED_HOSTS`), Rails host authorization, Flask/Werkzeug

`maskRequestHost: "<value>"` tells the proxy to **rewrite the `Host` header to
`<value>`** before forwarding to the upstream service, so the framework accepts
the request. The public URL is unchanged; only the header the container sees
changes.

Today the E2B facade hard-rejects it:
`pkg/api/e2b/handlers.go:579` → `notImplemented("network.maskRequestHost is not implemented yet")`.

This plan makes it a real, persisted, reconcile-safe per-sandbox setting and
wires it across all five SDKs + docs.

---

## 2. Design decisions

### 2.1 What it is, mechanically
A Caddy `reverse_proxy` handler supports
`handle[].headers.request.set.Host = ["<value>"]`. When `maskRequestHost` is
non-empty we add that block to the **per-port HTTP route**; when empty we emit
**byte-for-byte the current JSON** (critical — the existing non-serverless
route-shape regression test asserts exact JSON).

### 2.2 Scope: which routes get the rewrite
`maskRequestHost` applies to **per-port HTTP exposures only** — the
`<port>-<id>.<domain>` subdomain routes that serve the user's web app:

| Route method | Path | Gets Host rewrite? | Why |
|---|---|---|---|
| `UpsertPortRoute` | direct, non-serverless | **Yes** | serves user app |
| `UpsertPortRouteWithRetry` | serverless warm-bypass | **Yes** | serves user app |
| `UpsertPortRouteWithDial` | WASM host-mediated | **Yes** | serves user app |
| `UpsertWakeHTTPPortRoute` | serverless wake-aware | **No** (proxy enforces) | Caddy route unchanged; the loopback ingress proxy sets Host from the row — §2.4 |
| `UpsertSandboxRoute` | toolbox `/<id>/` root | **No** | platform agent expects its own Host |
| `/<id>/proxy/<port>/` path | toolbox-mediated | **No** (N/A) | path proxy runs *inside* toolbox, not a Caddy route |
| `UpsertTCPRoute` / TLS / SNI | raw L4 | **No** (N/A) | no HTTP `Host` header in raw TCP/TLS passthrough |
| `*ToPeer` (cluster forward) | cross-node | **deferred** (see 2.5) | the owning node applies the rewrite |

**Decision:** mask applies to the four per-port HTTP route shapes. The main
toolbox route, TCP, and TLS routes ignore it. TCP/TLS exposures with a mask set
are accepted but the mask is silently inert (documented), because the field is
sandbox-scoped, not port-scoped, and a sandbox can mix protocols.

### 2.3 Threading the value without signature churn
The per-port HTTP methods currently have fixed signatures that many tests assert
against. To avoid breaking them, introduce an **options struct + a private route
builder**, keep the existing public methods as zero-option wrappers:

```go
// pkg/caddy/client.go
type HTTPRouteOptions struct {
    // MaskRequestHost, when non-empty, rewrites the upstream Host header.
    // Empty => no headers block emitted (JSON identical to pre-feature).
    MaskRequestHost string
}

// private builder used by every per-port HTTP route shape
func reverseProxyHandle(dial string, opts HTTPRouteOptions) map[string]any
```

Add `opts HTTPRouteOptions` to the four methods (or `*WithOptions` variants).
**Decision: add the param directly** (simpler call graph; the methods are
internal-ish and only ~6 call sites). Existing callers pass
`HTTPRouteOptions{}` → identical JSON. Wrappers like `UpsertPortRoute` keep
their current public signature and pass `{}`; a new
`UpsertPortRouteWithOptions` carries the mask. (Final variant naming settled in
build; the plan's contract is: empty opts == today's bytes.)

### 2.4 Serverless wake path — RESOLVED (Option A)
**Audited (`pkg/api/ingressproxy/handlers.go:227`).** The wake route is a
two-handler Caddy chain (`rewrite` URI → `reverse_proxy` to the loopback
`InternalIngressAddr`). The internal ingress proxy then **deliberately
overrides** Host: `pr.Out.Host = target.Host` (the container IP:port). So a
Caddy-level `header_up Host` on the wake route would be **clobbered** — a wake
route rewrite alone does NOT work.

This also surfaced a pre-existing asymmetry the feature must reconcile:

| Path | Host the container sees **today** (no mask) |
|---|---|
| Direct route (non-serverless / serverless warm-bypass) | `<port>-<id>.<domain>` (Caddy passes inbound Host through) |
| Wake route (serverless, cold) | `<containerIP>:<port>` (proxy forces `target.Host`) |

**Solution: enforce the mask at the proxy from the resolved sandbox config — no
Caddy change on the wake route.** `WakeAwarePortTarget` (`service.go:2941`)
already loads the full sandbox row, so the mask is one field away at zero extra
I/O. Carry it on the resolver result and apply it where Host is set:

- `PortEndpoint{ URL string }` → add `MaskRequestHost string`, populated in
  `WakeAwarePortTarget` from `sandbox.MaskRequestHost` (covers Docker **and**
  WASM upstreams in one place).
- `handlers.go:227` becomes:
  ```go
  if endpoint.MaskRequestHost != "" {
      pr.Out.Host = endpoint.MaskRequestHost
  } else {
      pr.Out.Host = target.Host // today's behavior, byte-for-byte
  }
  ```

**Two enforcement points, one source of truth (the sandbox row):** Caddy
`header_up Host` for the direct route (§3.3), the ingress proxy for the wake
route. When the mask is empty, **both paths keep today's exact bytes** — no
behavior change for existing sandboxes. As a bonus, a set mask also fixes the
warm↔cold Host inconsistency above. Mask is create-only (§2.7), so the value
baked into the Caddy direct route can't drift from what the proxy reads.

Options B (Caddy sets Host + proxy preserves inbound — needs a sentinel to tell
"mask" from "default public host", regression-prone), C (always-mask default —
changes the direct path's default Host), and D (route all ingress through the
proxy — kills the direct-route latency win) were considered and rejected. See
the build discussion in this plan's history. (UC-13, UC-15, UC-22.)

### 2.5 Cluster / peer-forward path
`UpsertPortRouteToPeer` / `UpsertSandboxRouteToPeer` install SNI/path-forward
routes pointing at the **owning node**. The owning node holds the sandbox row
(incl. `MaskRequestHost`) and applies the real rewrite when it installs its own
per-port route. The forwarding node must therefore **not** also rewrite (double
rewrite). **Decision:** peer routes ignore the mask; the owner enforces it.
Add a single-node-vs-cluster note to the PR. (UC-14.)

### 2.6 Validation
- Trim whitespace. Empty after trim => feature off (pass-through).
- Reject control chars / CR-LF (header-injection guard) — must be a valid HTTP
  host token. Reuse/extend existing host validation (custom-domain hostname
  validation in `internal/service/custom_domains.go` is the reference). (UC-08, UC-09.)
- Max length cap (e.g. 253, the DNS name max) to bound the column. (UC-10.)
- A bare value like `localhost`, `example.com`, or `host:8080` is allowed
  (E2B treats it as an opaque Host string). Port suffix permitted. (UC-07.)

### 2.7 Default & semantics
- Type: `string`. Empty = pass-through (today's behavior). Non-empty =
  `header_up Host <value>`.
- Store default: empty string `''`.
- E2B-faithful: the value is forwarded verbatim as the `Host` header.

---

## 3. Files to modify

### 3.1 Server — wire types
- **`pkg/models/types.go`**
  - `CreateSandboxRequest`: add `MaskRequestHost string \`json:"mask_request_host,omitempty"\``.
  - `Sandbox`: add `MaskRequestHost string \`json:"mask_request_host,omitempty"\``.
  - Rationale comment in the dense house style (WHY: framework host-checks).

### 3.2 Server — store column
- **`internal/store/store.go`**
  - `CREATE TABLE sandboxes`: `mask_request_host TEXT NOT NULL DEFAULT ''`.
  - Idempotent `ALTER TABLE sandboxes ADD COLUMN mask_request_host TEXT NOT NULL DEFAULT '';` in the migration list.
  - Add `mask_request_host` to the **6 shared column-list lines** (Create INSERT,
    Upsert INSERT, Get/List/ListByOwner/ListByRuntime SELECTs).
  - Upsert `UPDATE SET mask_request_host = excluded.mask_request_host`.
  - Add VALUES placeholder (53 → 54).
  - `scanSandbox`: add `&maskRequestHost` scan target in column order; assign to
    `sandbox.MaskRequestHost`.
- **`internal/store/store_test.go`**
  - `TestMaskRequestHostColumnRoundTrip` (create → get → assert value).
  - Extend `sqlRowStub` with the new column value (mirrors the egress fix).
  - Extend the e2b sealed-meta round-trip stub blob (already references
    `mask_request_host` at `store_test.go:602`).

### 3.3 Server — Caddy route builder
- **`pkg/caddy/client.go`**
  - Add `HTTPRouteOptions{ MaskRequestHost string }`.
  - Add private `reverseProxyHandle(dial string, opts HTTPRouteOptions) map[string]any`
    that emits the `headers.request.set.Host` block **only** when
    `opts.MaskRequestHost != ""`.
  - Refactor `UpsertPortRoute`, `UpsertPortRouteWithDial`,
    `UpsertPortRouteWithRetry` to build their handle via `reverseProxyHandle`,
    threading an `opts`. **`UpsertWakeHTTPPortRoute` is NOT changed** — the wake
    route's Host is enforced in the ingress proxy, not Caddy (§2.4 Option A).
  - Keep zero-option behavior byte-for-byte identical.
- **`pkg/caddy/client_test.go`**
  - `TestPortRouteEmitsHostRewriteWhenMaskSet` (JSON contains `headers.request.set.Host`).
  - `TestPortRouteNoHeaderBlockWhenMaskEmpty` (JSON identical to current — guards regression).
  - Mask variants for WithDial / WithRetry / Wake shapes.

### 3.4 Server — service layer (the chokepoint)
- **`internal/service/public_traffic.go`** (or a new `mask_request_host.go` in
  the same package, mirroring how egress got its own seam)
  - Thread `sandbox.MaskRequestHost` into `upsertExposedPortRoute` →
    `applyHTTPPortRoute` so each per-port HTTP shape passes
    `HTTPRouteOptions{MaskRequestHost: sandbox.MaskRequestHost}`.
  - `installWasmHTTPPortRoute` likewise (WASM dial route).
- **`internal/service/service.go`**
  - `CreateSandbox` struct mapping: `MaskRequestHost: req.MaskRequestHost`
    (after validation).
  - `validateMaskRequestHost(string) error` (trim, CR-LF/control-char reject,
    length cap). Call from the create path.
  - The rollback `Destroy` literal and reconcile/start paths already route
    through `upsertExposedPortRoute`, so the mask reapplies automatically on
    reconcile, start, and docker start events — **verify, don't duplicate**.
  - WASM/Firecracker: no special rejection needed (Host rewrite is a Caddy-edge
    concern, runtime-agnostic). WASM already uses `UpsertPortRouteWithDial`.
  - **`WakeAwarePortTarget` (`service.go:2941`)**: populate the new
    `PortEndpoint.MaskRequestHost` from the already-loaded sandbox row (both the
    Docker upstream branch and the `wasmHTTPUpstreamURL` branch). Zero extra I/O.
  - **`PortEndpoint` struct (`service.go:2933`)**: add `MaskRequestHost string`.
- **`internal/service/service_test.go`** / new test file
  - `TestExposedPortRouteCarriesMaskRequestHost` (assert the route the service
    asks Caddy to install carries the Host rewrite).
  - `TestMaskRequestHostReappliedOnReconcile`.
  - `TestInvalidMaskRequestHostRejectedAtCreate`.
  - `TestWakeAwarePortTargetCarriesMaskRequestHost` (endpoint carries the row's mask).

### 3.4b Server — internal ingress proxy (serverless wake path)
- **`pkg/api/ingressproxy/handlers.go`**
  - In the `httpWake` Rewrite closure (line ~227), set `pr.Out.Host` from
    `endpoint.MaskRequestHost` when non-empty, else keep `target.Host`
    (today's behavior, byte-for-byte). See §2.4.
- **`pkg/api/ingressproxy/handlers_test.go`**
  - `TestHttpWakeAppliesMaskRequestHost` (fake resolver returns an endpoint with
    a mask → assert the upstream request's Host equals the mask).
  - `TestHttpWakeKeepsTargetHostWhenNoMask` (regression: unset → `target.Host`).
- **`PortResolver` fakes** in `pkg/api/ingressproxy/*_test.go`: the fake already
  returns `service.PortEndpoint`; setting the new field is additive (no
  signature change), so existing fakes compile unchanged and only the new tests
  populate it.

### 3.5 Server — E2B facade
- **`pkg/api/e2b/handlers.go`**
  - **Delete** the `notImplemented` at line ~579.
  - Pass `maskRequestHost` into `serviceReq.MaskRequestHost` and
    `wasmReq.MaskRequestHost` (the value is already extracted at line ~567 and
    carried in `sandboxMeta`).
- **`pkg/api/e2b/handlers_additional_test.go`**
  - Remove the `networkMaskRequestHost` case from `TestE2BCreateSandboxNotImplemented`.
- **`pkg/api/e2b/handlers_test.go`**
  - `TestCreateSandboxAcceptsMaskRequestHost` (201 + value plumbed).
  - `TestCreateSandboxRejectsInvalidMaskRequestHost` (400 on CR-LF/control char).
- **`pkg/api/e2b/meta.go`** — already carries `MaskRequestHost` end-to-end; no
  change expected. Verify the sealed-blob round-trip still includes it.

### 3.6 SDKs (5, lockstep)
- **TypeScript** — `sdk/typescript/src/types.ts`: `maskRequestHost?: string`.
  `sdk/typescript/src/internal/client.ts`: `mask_request_host: options.maskRequestHost`.
  `client.test.ts`: serialization test.
- **Python** — `sdk/python/microvm/types.py`: `maskRequestHost: str`.
  `client.py`: `_first_of(options, "maskRequestHost", "mask_request_host")`.
  `tests/test_client.py`: serialization test.
- **Go** — `sdk/go/pkg/types/types.go`: `CreateSandboxOptions = models.CreateSandboxRequest`
  alias inherits the field **free** (confirm the alias still holds); add an
  explicit field only if the SDK defines its own struct. Add a transport test.
- **Rust** — `sdk/rust/src/types.rs`: `mask_request_host: Option<String>`
  (`#[serde(rename = "mask_request_host", skip_serializing_if = "Option::is_none")]`).
  `lib.rs`: add to `minimal_create_options` + serialization test.
- **Java** — `sdk/java/.../model/CreateOptions.java`: `@JsonProperty("mask_request_host")`
  field + setter. `MicroVMClient.java`: copy line. `MicroVMClientTest.java`: test.

### 3.7 Docs
- **`docs/src/content/docs/network-isolation.mdx`** — new section
  **"Masking the Request Host"** with the Vite/webpack motivation and a
  five-language `<Tabs syncKey="lang">` create example. Update the **Limitations**
  list (remove "no host masking" if implied; note TCP/TLS exposures ignore it).
  No sidebar change (existing page).

---

## 4. Use cases (verification matrix)

| # | Use case | Expected behavior | Covered by |
|---|---|---|---|
| UC-01 | Create sandbox with `maskRequestHost: "localhost"`, expose HTTP port | Caddy port route emits `headers.request.set.Host = ["localhost"]`; app's host-check passes | caddy + service test |
| UC-02 | Create sandbox **without** mask, expose HTTP port | Route JSON identical to pre-feature (no headers block) | caddy regression test |
| UC-03 | Vite dev server with `allowedHosts` strict, mask set to a value Vite allows | request not blocked (manual/integration) | docs + integration note |
| UC-04 | Mask value persisted, daemon restarts, reconcile reapplies route | reconciled route still carries the Host rewrite | service reconcile test |
| UC-05 | `StartSandbox` after stop re-publishes exposures | mask reapplied on every per-port route | service start test |
| UC-06 | Docker `start` event republishes routes | mask reapplied (events.go path → `syncExposedPortRoute`) | events path (shared helper) |
| UC-07 | Mask with port suffix `"app.internal:8080"` | accepted verbatim as Host | validation test |
| UC-08 | Mask containing CR/LF (`"a\r\nX-Injected: 1"`) | rejected 400 at create (header-injection guard) | validation test |
| UC-09 | Mask containing control chars / spaces | rejected 400 | validation test |
| UC-10 | Mask longer than 253 chars | rejected 400 | validation test |
| UC-11 | Empty / whitespace-only mask | treated as off; pass-through; no headers block | service + caddy test |
| UC-12 | Mask + serverless warm-bypass route (`UpsertPortRouteWithRetry`) | Host rewrite present alongside `load_balancing.try_duration` | caddy test |
| UC-13 | Mask + serverless **wake** route (cold start) | ingress proxy sets `pr.Out.Host = mask` from `PortEndpoint.MaskRequestHost` (NOT a Caddy rewrite — §2.4 Option A) | ingressproxy handler test |
| UC-13b | Serverless sandbox, **no** mask, wake vs. warm-bypass | both keep today's bytes (wake → `target.Host`; direct-bypass → passthrough); no regression | ingressproxy + caddy regression tests |
| UC-14 | Mask in **cluster** mode, sandbox owned by another node | forwarding node does **not** double-rewrite; owner applies it | cluster reasoning + peer-route test |
| UC-15 | Mask + WASM runtime HTTP exposure (`UpsertPortRouteWithDial`) | Host rewrite present on the dial route | wasm_ports test |
| UC-16 | Mask + **TCP** exposure | mask inert (no Host in raw TCP); exposure still works | service test + docs note |
| UC-17 | Mask + **TLS** exposure | mask inert (SNI passthrough); exposure still works | service test + docs note |
| UC-18 | Mask + `allowPublicTraffic:false` | expose rejected (existing gate) before mask matters; no route created | existing gate test |
| UC-19 | Mask + `networkBlockAll:true` | egress blocked, ingress route still carries mask (independent axes) | service test |
| UC-20 | Mask round-trips through store (create → Get/List) | value returned on read APIs | store round-trip test |
| UC-21 | Mask round-trips through E2B sealed metadata blob | `mask_request_host` preserved on resume/inspect | e2b meta test (existing stub) |
| UC-22 | Unexpose then re-expose a port with mask set | re-exposed route carries mask again | service expose test |
| UC-23 | E2B `network.maskRequestHost` create request | 201 (was 501); value plumbed to service | e2b handler test |
| UC-24 | All 5 SDKs serialize `maskRequestHost` → `mask_request_host` | wire JSON carries snake_case key | per-SDK serialization tests |
| UC-25 | Mask updated after create | **N/A — create-only.** No update-network API exists (only `UpdateLifecycle`/`UpdateTags`/`SetNetworkLimits`). Mask is fixed at create. | n/a (documented) |
| UC-26 | Multiple ports exposed on one sandbox, mask set | every per-port HTTP route carries the same Host rewrite | service multi-port test |

(26 use cases; ≥20 satisfied.)

---

## 5. pr-review.md axes (pre-filled)

1. **Idempotency.** Route upserts are already idempotent (`upsertRoute` is
   create-or-replace by `@id`). Mask adds a deterministic field to the same
   route body → re-applying converges. No new pool/port allocation. ✅
2. **Boot-path latency.** `CreateSandbox` gains one string validation + one
   struct-field copy. No new I/O, no new caddy call on the boot path beyond the
   exposures that already happen. First-call case unchanged. ✅
3. **Lazy bootstrap.** N/A — no new daemon-start work; no latch.
4. **Failure-path consistency.** Mask is a property of the route body, not a
   separate write. No new multi-step write, no new rollback rule. A failed route
   install rolls back exactly as today (the exposure rollback already covers it). ✅
5. **TCP host-port pool & L4.** Untouched — mask is HTTP-only; TCP/TLS routes
   ignore it. No change to `TryReserveHostPort`, `allocateHostPort`, the
   `host_port` index, or `EnsureLayer4`. ✅
6. **Cluster mode.** Owner applies the rewrite; forwarding node does not (no
   double-rewrite). No FSM/placement/recovery change. No-op when
   `EnableCluster` is false. Single-node path unchanged. ✅
- **Store schema.** One new `TEXT NOT NULL DEFAULT ''` column + idempotent
  ALTER; backward compatible (old rows default to pass-through). ✅
- **Coverage.** New caddy builder, service helper, validation, store column,
  and e2b handler branch each get tests; target keeps pkg ≥85%.

---

## 6. Build & verification commands

```
make fmt
go build ./...
go test ./pkg/caddy/... ./internal/store/... ./internal/service/... ./pkg/api/e2b/... ./pkg/api/ingressproxy/...
go test -count=1 -coverprofile=coverage.out ./cmd/... ./internal/... ./pkg/...
go tool cover -func=coverage.out | grep -E "caddy|store|service|e2b|ingressproxy"
(cd sdk/typescript && npm ci && npm run build && npm test)
(cd sdk/python && python -m unittest discover -s tests -v)
(cd sdk/go && go test ./...)
make docs-build
# rust/java: CI only (no local cargo/mvn) — mirror existing field shape exactly
```

---

## 7. Open questions for review

1. **Route variant naming** — add `opts` param to existing methods vs.
   `*WithOptions` variants? (Plan assumes whichever keeps existing test JSON
   byte-identical; leaning toward an `opts` param + zero-value default.)
2. ~~**Wake-path Host propagation (UC-13)**~~ — **RESOLVED (Option A, §2.4).**
   Audited `pkg/api/ingressproxy/handlers.go:227` (`pr.Out.Host = target.Host`):
   a Caddy wake-route rewrite would be clobbered. Solution: carry the mask on
   `PortEndpoint` (the row is already loaded in `WakeAwarePortTarget`) and apply
   it in the proxy. No Caddy change on the wake route; unset mask keeps today's
   bytes on both paths. No documented limitation needed — masking works on every
   HTTP route shape.
3. ~~**Update path (UC-25)**~~ — **RESOLVED: create-only.** No
   mutate-network-after-create API exists. UC-25 is N/A.
4. **Should the main `/<id>/` toolbox route ever honor mask?** Plan says no
   (platform agent). Confirm no E2B client relies on masking the root route.

### Verified-against-code (this plan is grounded, not speculative)
- Go SDK inherits the field free: `sdk/go/pkg/types/types.go:5`
  `type CreateSandboxOptions = models.CreateSandboxRequest`. ✅
- E2B `meta.go` already carries `MaskRequestHost` through the sealed blob
  (`pkg/api/e2b/meta.go:76,92,114,169,284,301`); only the handler reject +
  service plumbing are missing. ✅
- Service route chokepoints exist and are shared by reconcile/start/events/
  serverless: `upsertExposedPortRoute` (`service.go:2676`) →
  `applyHTTPPortRoute` (`service.go:2745`); `syncExposedPortRoute`
  (`public_traffic.go:63`). Threading the mask here covers UC-04/05/06/22
  without touching each call site. ✅
- Store column pattern is the same one egress/`allow_public_traffic` just used
  (`store.go:71,73,624,629,737,894,924,926,1027`). ✅
- Wake path audited: `pkg/api/ingressproxy/handlers.go:227` forces
  `pr.Out.Host = target.Host`; `WakeAwarePortTarget` (`service.go:2941`) already
  loads the sandbox row, so `PortEndpoint.MaskRequestHost` is free to populate.
  `PortResolver` fakes return the struct by value → additive field, no fake
  churn. ✅
```
