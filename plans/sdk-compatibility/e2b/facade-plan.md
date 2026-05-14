# E2B Python SDK Compatibility Plan

## Objective

Make AerolVM consumable by the unmodified E2B Python SDK without changing AerolVM's native SDKs or `/v1` API.

This plan replaces the earlier placeholder E2B discovery section in `plans/daytona-e2b-compatibility-facades.md` with a concrete target based on the local E2B SDK checkout.

## Current Status

- Control-plane MVP under `/e2b` is implemented.
- Runtime MVP under `/e2b/runtime` is implemented and proxies into toolboxd's internal `/envd` compatibility surface.
- Create idempotency is implemented with a persisted request-fingerprint table and bounded replay window.
- A real Python smoke harness against `e2b==2.21.0` is implemented and passes against the local SDK checkout.

## Constraints

- Do not modify `sdk/python` in this repository.
- Do not change `/v1` request or response behavior.
- Keep compatibility logic in facade packages and toolbox compatibility handlers, not in `internal/service` business logic.
- Document setup later in:
  - `docs/src/content/docs/sdk-setup.md`
  - `docs/src/content/docs/getting-started.md`

## Implementation Guardrails

These are not optional polish items. They are design constraints from the repo's API review rules and need to be satisfied by the implementation plan from the first patch onward.

### Idempotency is a hard requirement

All `/e2b` sandbox APIs must be safe under retries and concurrent duplicate calls.

That means the implementation must define explicit retry behavior for:

- `POST /e2b/sandboxes`
- `POST /e2b/sandboxes/{id}/connect`
- `POST /e2b/sandboxes/{id}/pause`
- `POST /e2b/sandboxes/{id}/timeout`
- `POST /e2b/sandboxes/{id}/snapshots`
- `DELETE /e2b/templates/{id}`

The implemented create strategy uses a canonical request fingerprint persisted in `e2b_create_requests`.

The fingerprint is built from the normalized create semantics, not the raw JSON body text. It covers the effective template ID, timeout and lifecycle settings, metadata, env vars, secure mode, and supported network fields. This keeps semantically identical retries stable even when JSON field order differs.

The replay behavior is intentionally bounded so legitimate duplicate launches are still allowed:

- first identical request claims the fingerprint and writes a pending row with a 2 minute lock TTL
- concurrent identical requests wait up to 30 seconds for that pending create to finish instead of launching a duplicate sandbox
- once the create succeeds, the row moves to `ready` and replays the same sandbox for a 10 second replay window
- after the replay window expires, the same request is allowed to create a new sandbox again
- if native sandbox creation or metadata persistence fails, the reservation is deleted and any newly created sandbox is rolled back

Minimum expected behavior:

- repeated `connect` must not double-start a sandbox or shorten a longer timeout already in force
- repeated `pause` against an already-paused sandbox should be a success no-op
- repeated snapshot create for the same effective snapshot identity should return the existing snapshot or fail with a clear conflict, never create ambiguous duplicates

### Protect the create path

Sandbox creation latency is a protected path in this repo.

Phase-one `/e2b/sandboxes` work is allowed to add:

- one bounded template-alias lookup
- one bounded metadata read or write sequence
- normal native `CreateSandbox` work already performed by AerolVM

Phase one should not add:

- external catalog lookups
- wildcard-host bootstrap
- Caddy bootstrap
- runtime proxy warm-up
- any best-effort daemon recovery loop on the create request path

If any future E2B feature needs best-effort daemon-start bootstrap, mirror the `EnsureLayer4Ready` shape from `internal/service`: atomic fast-path latch plus single-flight mutex, with retries only on the first API path that actually needs the feature.

### Define rollback ownership on partial failure

The plan needs explicit cleanup rules anywhere the facade touches both native resources and compatibility metadata.

Required rules:

- if native sandbox creation succeeds and the `e2b_sandboxes` metadata write fails, destroy the newly created sandbox before returning an error so retries do not leak live sandboxes
- if native snapshot creation succeeds and the facade fails while recording E2B-facing metadata, pick and document one behavior before implementation: either roll back the native snapshot immediately or preserve it and make the next identical request reuse it deterministically
- when later ingress work touches both Caddy and persisted state, use explicit "did I create this?" ownership tracking; do not rely on reconcile as the primary cleanup path

### Deployment touch points are part of the plan

Adding `/e2b` is not only a Go router change.

When the facade lands, update both API allowlists:

- `packaging/Caddyfile.template`
- `scripts/install.sh`

Both need `/e2b` and `/e2b/*`, the same way `/daytona` was wired.

## Inputs Reviewed

### Upstream SDK target

- Local SDK path: `/Users/sumansaurabh/Documents/startup-3/opensource-repos/E2B/packages/python-sdk`
- Package: `e2b`
- Version: `2.21.0`
- Primary initial contract: sync Python SDK
- Secondary validation target: async Python SDK, because it uses the same wire contract

### AerolVM implementation areas reviewed

- `pkg/api/server.go`
- `pkg/api/daytona/*`
- `internal/service/service.go`
- `internal/store/store.go`
- `cmd/toolboxd/*`
- `pkg/models/*`
- `docs/src/content/docs/sdk-setup.md`
- `docs/src/content/docs/getting-started.md`

## Confirmed E2B Contract

### Control-plane API

The Python SDK uses an HTTP control plane rooted at `ConnectionConfig.api_url`.

Important route families exercised by the SDK:

| Route family | Purpose | Current importance |
|---|---|---|
| `POST /sandboxes` | create sandbox from `templateID` | Required for MVP |
| `GET /sandboxes` | list sandboxes | Required for MVP |
| `GET /sandboxes/{id}` | get sandbox info | Required for MVP |
| `DELETE /sandboxes/{id}` | kill sandbox | Required for MVP |
| `POST /sandboxes/{id}/connect` | reconnect and optionally extend timeout | Required for MVP |
| `POST /sandboxes/{id}/pause` | pause sandbox | Required for MVP |
| `POST /sandboxes/{id}/timeout` | update timeout | Required for MVP |
| `POST /sandboxes/{id}/snapshots` | create snapshot | Required for MVP |
| `GET /snapshots` | list snapshots | Required for MVP |
| `DELETE /templates/{id}` | delete snapshot by template id | Required for MVP because `delete_snapshot()` uses this path |
| `GET /sandboxes/{id}/metrics` | sandbox metrics | Later |
| `GET /sandboxes/{id}/logs`, `GET /v2/sandboxes/{id}/logs` | sandbox logs | Later |
| `/templates`, `/v2/templates`, `/v3/templates`, `/tags`, `/volumes` | template, build, tag, and volume APIs | Explicitly out of MVP |

### Sandbox runtime API

The SDK does not stop at the control plane. After create or connect it talks to a sandbox-side API using:

- HTTP endpoints such as `GET /files`, `POST /files`, `GET /health`
- Connect-RPC style endpoints such as:
  - `/process.Process/List`
  - `/process.Process/Connect`
  - `/process.Process/Start`
  - `/process.Process/Update`
  - `/process.Process/SendInput`
  - `/process.Process/SendSignal`
  - `/process.Process/CloseStdin`
  - `/filesystem.Filesystem/Stat`
  - `/filesystem.Filesystem/MakeDir`
  - `/filesystem.Filesystem/Move`
  - `/filesystem.Filesystem/ListDir`
  - `/filesystem.Filesystem/Remove`
  - watcher routes under `/filesystem.Filesystem/...`

This means `/e2b` cannot be a control-plane-only adapter. It also needs a runtime facade that makes toolboxd look enough like E2B envd.

### Auth and per-sandbox headers

The SDK uses different auth shapes on the two planes:

| Surface | Upstream auth shape | Notes for AerolVM |
|---|---|---|
| Control plane | `X-API-KEY: <token>` | Reuse AerolVM PAT token, but accept the E2B header name on `/e2b` routes. |
| Sandbox runtime | `X-Access-Token`, `E2b-Sandbox-Id`, `E2b-Sandbox-Port` | Emitted by the SDK after `create()` and `connect()`. The facade must accept these and route to the right toolbox target. Phase-one recommendation: surface AerolVM's existing per-sandbox toolbox token as `envdAccessToken`, validate `X-Access-Token` against it at `/e2b/runtime`, then forward the native bearer token to toolboxd. |
| User impersonation on envd calls | `Authorization: Basic <base64(user:)>` | Used for file and process operations with an explicit user. |
| Public traffic gating | `e2b-traffic-access-token` | Needed later for `allow_public_traffic=false`. AerolVM does not have this today. |

### Runtime token mapping

The current AerolVM runtime path already stores a per-sandbox toolbox token and injects it when proxying to toolboxd. The E2B facade should reuse that instead of introducing a second runtime secret store.

Recommended phase-one mapping:

- on create and connect responses, emit the sandbox's toolbox token as E2B `envdAccessToken` when the facade is operating in secure runtime mode
- on `GET /e2b/sandboxes` and `GET /e2b/sandboxes/{id}`, shape the same token into the E2B response fields where the SDK expects it
- at `/e2b/runtime`, compare incoming `X-Access-Token` with the sandbox's stored toolbox token
- when proxying to toolboxd, continue forwarding `Authorization: Bearer <toolbox token>` exactly as the native toolbox proxy already does

This keeps the runtime credential story aligned with the existing daemon and avoids adding extra secret persistence for phase one.

### Base URL and path-prefix viability

The generated E2B client issues absolute-looking request paths such as `/sandboxes`, but the current `httpx` behavior still resolves them correctly against a base URL with a path segment.

That means this works as an initial setup target:

```text
E2B_API_URL=https://sandbox.example.com/e2b
```

and requests resolve under:

```text
/e2b/sandboxes
```

So the user's requested `/e2b` path family is viable.

## Key AerolVM Findings

### Good overlap already exists

The current AerolVM server already gives the facade most of the core substrate it needs:

- create, get, list, start, stop, destroy sandboxes
- per-sandbox lifecycle timers
- native sandbox snapshots
- toolbox target resolution
- public HTTP port exposure
- persistent store-backed compatibility metadata pattern via `/daytona`

### The runtime split is the main architectural constraint

`cmd/toolboxd` already supports command execution, sessions, upload, download, and Daytona-oriented file and git helpers, but it does not currently expose the E2B envd contract.

That means the E2B work needs:

1. top-level control-plane handlers in `pkg/api/e2b`
2. runtime-side compatibility handlers in `cmd/toolboxd`
3. a routing layer that proxies E2B runtime requests to the correct sandbox toolbox endpoint

### Some E2B features are true gaps today

The current repo does not have first-class support for:

- traffic access tokens for public ingress
- `mask_request_host` host rewrite semantics
- automatic resume on inbound public traffic when `auto_resume=true`
- per-destination network allow and deny lists
- E2B template catalog, template builds, tags, or volumes
- sandbox metrics and logs in E2B's shapes

Those must be phased explicitly instead of being approximated silently.

## Recommended Architecture

### Route ownership

Add a new facade package and register it from `pkg/api/server.go`:

```text
pkg/api/
  e2b/
    routes.go
    handlers.go
    dto.go
    translate.go
    runtime_proxy.go
```

The route family should be rooted at `/e2b`.

### Runtime gateway for phase one

Do not make initial compatibility depend on wildcard hostnames.

Instead, support a fixed runtime gateway under the same facade family, for example:

```text
/e2b/runtime
/e2b/runtime/{path...}
```

The setup then becomes:

```text
E2B_API_URL=https://sandbox.example.com/e2b
E2B_SANDBOX_URL=https://sandbox.example.com/e2b/runtime
E2B_API_KEY=<same PAT token>
```

This is the cleanest way to satisfy the user's request for a path-based `/e2b` endpoint while avoiding immediate wildcard host-routing work.

The runtime proxy should:

- read `E2b-Sandbox-Id`
- resolve the sandbox's toolbox target through `Service.ToolboxTarget(...)`
- forward the request path and body to toolboxd
- preserve E2B runtime headers that toolboxd needs, especially `X-Access-Token`, `E2b-Sandbox-Id`, `E2b-Sandbox-Port`, and `Authorization`

The implemented gateway rewrites `/e2b/runtime/...` into toolboxd's internal `/envd/...` namespace. This keeps the E2B envd contract separate from Daytona's existing `/files` and `/process` semantics.

The implemented header flow is:

- validate `X-Access-Token` against the sandbox's stored toolbox token when the sandbox is secure
- preserve inbound `Authorization: Basic ...` as `X-E2B-User-Authorization` for toolbox-side user impersonation compatibility
- inject `Authorization: Bearer <toolbox token>` on the hop from the public gateway to toolboxd

### Metadata storage

Follow the Daytona pattern instead of stuffing compatibility-only fields into the native sandbox model.

Add a new metadata model and store table, for example:

```text
pkg/models/e2b.go
internal/store: e2b_sandboxes table + helpers
```

Persist fields that AerolVM either does not model natively or models differently, including:

- requested `template_id`
- resolved template alias returned to the SDK, when one exists
- metadata map
- lifecycle mode: `on_timeout` and `auto_resume`
- requested timeout seconds
- secure mode
- allow-public-traffic intent
- requested network allow and deny lists
- requested host mask
- any E2B-facing alias values needed for stable response shaping

### Keep `internal/service` product-agnostic

The service layer should continue dealing in AerolVM primitives only:

- create sandbox
- start or stop sandbox
- update lifecycle
- create or remove snapshot
- expose port
- resolve toolbox target

All E2B naming, status, auth, timeout, and template semantics should stay in the facade layer or toolbox compatibility layer.

## Translation Rules

### State mapping

Map native AerolVM state to E2B state like this:

| AerolVM | E2B |
|---|---|
| `started` | `running` |
| `stopped` | `paused` |

Destroyed sandboxes should remain 404 on read and `False` on `delete_snapshot()`-style boolean methods where the SDK expects that behavior.

### Timeout and pause semantics

E2B timeout is not AerolVM's native wire shape, but it maps cleanly onto lifecycle timers.

Recommended translation:

- `lifecycle.on_timeout = "kill"` -> native `DestroyAtAge = timeout`
- `lifecycle.on_timeout = "pause"` -> native `StopAtAge = timeout`
- `POST /e2b/sandboxes/{id}/timeout` updates the same lifecycle field according to stored E2B timeout mode
- `POST /e2b/sandboxes/{id}/connect` must only extend the deadline when the new timeout is longer than the existing one, matching the upstream SDK contract

### Template resolution

E2B creates sandboxes from `templateID`, not from an image name.

We need an explicit resolver instead of guessing:

1. If `templateID` matches a native AerolVM snapshot created through the E2B facade, create from that snapshot image.
2. Otherwise resolve the template through a facade-owned alias map.
3. If no mapping exists, return a clear 4xx error.

The minimum viable mapping should include `base`, because `Sandbox.create()` defaults to it in the Python SDK.

Recommended config shape:

```text
SB_E2B_TEMPLATE_MAP_JSON={"base":"ubuntu:22.04"}
```

That keeps template aliasing explicit and out of native AerolVM APIs.

The control-plane response shaping also needs to preserve E2B's template-facing fields accurately:

- `templateID` should reflect the E2B-facing template identifier the caller used or the facade resolved
- optional `alias` in list and get responses is template alias information, not a sandbox-specific name
- metadata must round-trip through create, list, and get because the SDK supports metadata filters on list calls

### Snapshot identifier mapping

E2B uses the returned `snapshot_id` string as the stable external identifier for both recreate and delete flows.

That means the facade should treat the E2B snapshot identifier as first-class metadata, not as an incidental formatting detail.

Recommended rule:

- persist the exact E2B-facing `snapshot_id` string for each snapshot created through the facade
- when the caller supplied a snapshot name, preserve an E2B-style named identifier such as `namespace/name:tag`
- when the caller did not supply a name, persist a generated fallback identifier that is still stable for later `DELETE /e2b/templates/{id}` resolution
- resolve deletes by E2B `snapshot_id` first, with native snapshot-name lookup only as an internal fallback

This matches the upstream SDK, where `delete_snapshot()` deletes by the same template-style identifier previously returned from `create_snapshot()`.

### Public host and ingress note

The SDK's `get_host(port)` builds `port-sandboxid.domain`, while AerolVM's current public port URLs are documented as `sandboxid-port.domain`.

For phase one, avoid depending on this by requiring `E2B_SANDBOX_URL=/e2b/runtime` for SDK runtime operations.

Full `get_host()` compatibility should be a later phase that adds E2B-specific host generation and Caddy routing.

## Phased Delivery

### Phase 1: Control-plane MVP

Implement these under `/e2b`:

| Route | Status | Mapping |
|---|---|---|
| `POST /e2b/sandboxes` | Implemented | create sandbox via template resolver + metadata persistence + persisted idempotent replay |
| `GET /e2b/sandboxes` | Implemented | native list + E2B response shaping + metadata filter support |
| `GET /e2b/sandboxes/{id}` | Implemented | native get + E2B response shaping |
| `DELETE /e2b/sandboxes/{id}` | Implemented | native destroy |
| `POST /e2b/sandboxes/{id}/connect` | Implemented | native start or no-op + timeout extension |
| `POST /e2b/sandboxes/{id}/pause` | Implemented | native stop |
| `POST /e2b/sandboxes/{id}/timeout` | Implemented | lifecycle update |
| `POST /e2b/sandboxes/{id}/snapshots` | Implemented | native snapshot create |
| `GET /e2b/snapshots` | Implemented | native snapshot list, with optional facade filter shaping |
| `DELETE /e2b/templates/{id}` | Implemented | native snapshot delete by id or mapped name |

The goal of phase one is to make create, connect, pause, timeout, kill, and snapshot workflows usable from the Python SDK.

### Phase 2: Runtime MVP via `/e2b/runtime`

Add E2B envd compatibility to toolboxd and proxy it through the top-level API.

Recommended runtime scope:

| Capability | Status | Notes |
|---|---|---|
| `GET /health` | Implemented | simple sandbox liveness |
| `GET /files`, `POST /files` | Implemented | read and write file contents |
| `filesystem.Stat` | Implemented | map to file info helper |
| `filesystem.MakeDir` | Implemented | add directory creation |
| `filesystem.Move` | Implemented | reuse move helper |
| `filesystem.ListDir` | Implemented | list entries with mode, owner, size, timestamps |
| `filesystem.Remove` | Implemented | add remove helper |
| `process.List` | Implemented | list running process handles |
| `process.Start` | Implemented | run command or PTY |
| `process.Connect` | Implemented | reconnect to running process |
| `process.Update` | Implemented | PTY resize |
| `process.SendInput` | Implemented | stdin and PTY input |
| `process.SendSignal` | Implemented | signal process |
| `process.CloseStdin` | Implemented | EOF stdin without killing process |

Implementation note:

- The implemented runtime surface uses manual Connect JSON encoding and decoding instead of adding a new Connect dependency.
- The internal toolbox namespace is `/envd`, not `/files` or `/process`, to avoid collisions with Daytona compatibility routes.
- Under the hood, process operations reuse the existing session machinery instead of inventing a third process model.
- Watcher APIs remain explicit 501 responses in this phase.

### Phase 3: Ingress compatibility

These features matter for E2B host URLs and browser-facing flows, but they should not block the first SDK-compatible control-plane and runtime pass:

- `allow_public_traffic=false` and `e2b-traffic-access-token`
- `mask_request_host`
- automatic resume on inbound HTTP traffic when `auto_resume=true`
- `sandbox.get_host(port)` and `sandbox_domain` behavior that matches E2B's `port-sandboxid.domain` scheme

This phase likely touches:

- Caddy route generation
- public URL builders
- maybe installation templates and allowlists, the same way Daytona path exposure needed explicit Caddy updates

### Regression gates for later phases

If E2B ingress compatibility ends up changing any of the fragile networking paths already called out in `pr-review.md`, the implementation must add the same regression coverage required elsewhere in the repo.

Specifically:

- any change to host-port allocation semantics requires store regression coverage in `internal/store/store_test.go`
- any change to L4 bootstrap or readiness latching requires regression coverage in `internal/service/layer4_bootstrap_test.go`
- any PR that adds work to native sandbox boot through the E2B facade must explicitly call out the latency impact in the PR description

### Phase 4: Explicitly unsupported or later-surface APIs

Return clear 501 or 4xx responses for these until we choose to build them:

- `GET /sandboxes/{id}/metrics`
- `GET /sandboxes/{id}/logs`
- `GET /v2/sandboxes/{id}/logs`
- template catalog and template build APIs
- tag APIs
- volume APIs
- per-destination `allow_out` and `deny_out` semantics
- filesystem watchers

Do not fake these as successful with incomplete semantics.

## Open Design Questions

These should be resolved before implementation starts, or answered in the first implementation PR description.

1. For named snapshots, do we preserve the user-supplied snapshot name directly as the native snapshot name, or store a separate facade alias while keeping native snapshot names collision-free?
2. When phase-three ingress work starts, do we want to preserve `secure=false` as a fully tokenless runtime mode, or should later browser-facing flows still issue a traffic-scoped token for consistency?

## Testing Plan

### Go facade tests

Add `pkg/api/e2b` handler tests for:

- auth translation from `X-API-KEY`
- create and connect translation
- timeout extension rules
- state mapping `started <-> running`, `stopped <-> paused`
- snapshot creation and delete mapping
- metadata persistence and restart-safe reads

Use the same style as the Daytona harness:

- real service
- temp SQLite store
- real mounts manager
- no external Caddy admin dependency

### Toolbox compatibility tests

Add `cmd/toolboxd` tests for:

- `/files` read and write behavior with E2B headers
- filesystem RPC handlers
- process RPC handlers for command mode and PTY mode
- `close stdin` versus process termination
- resize and reconnect behavior

### Python contract harness

Add a focused smoke harness that runs against the real upstream Python SDK `e2b==2.21.0`.

Implemented harness shape:

- `scripts/e2b_sdk_smoke.py` exercises create, runtime health, file read and write, file list, commands, pause, reconnect, snapshot create, snapshot list, snapshot delete, and sandbox delete
- `pkg/api/e2b/contract_test.go` builds a temporary `toolboxd`, starts an in-process `/e2b` API server, creates a temporary Python virtualenv, installs either `SB_E2B_PYTHON_SDK_PATH` or `SB_E2B_PYTHON_SDK_SPEC` into it, and runs the smoke script
- the smoke test is opt-in via `SB_E2B_PYTHON_SMOKE=1` so normal `go test ./...` stays fast and hermetic

Do not try to run the entire upstream test suite first. Start with a pinned subset that matches our delivery phases:

#### Phase 1 subset

- create
- connect
- pause
- kill
- timeout
- snapshot create, list, delete, recreate from snapshot

#### Phase 2 subset

- commands run, connect, stdin, kill
- files read, write, list, mkdir, move, remove
- PTY create, connect, resize, input

#### Phase 3 subset

- host access
- allow public traffic token behavior
- host masking
- auto-resume on public request

## Docs Plan

After implementation, update the requested docs pages as follows.

### `docs/src/content/docs/sdk-setup.md`

Add an E2B compatibility section that shows:

```bash
export E2B_API_URL=https://sandbox.example.com/e2b
export E2B_SANDBOX_URL=https://sandbox.example.com/e2b/runtime
export E2B_API_KEY=<your-pat-token>
```

and make clear that this is a compatibility facade, not the native AerolVM Python SDK.

### `docs/src/content/docs/getting-started.md`

Add a short server-side compatibility note covering:

- `/e2b` control-plane availability
- PAT token reuse as `E2B_API_KEY`
- the need for `E2B_SANDBOX_URL` in the first rollout
- domain-mode host compatibility as a later enhancement if we add full E2B public host semantics

If the docs section grows beyond a short setup note, split it into a dedicated page later.

## Recommended Implementation Order

1. Scaffold `pkg/api/e2b` and register `/e2b` from `pkg/api/server.go`.
2. Add E2B metadata model and store helpers.
3. Implement the control-plane MVP routes and snapshot delete alias.
4. Add `E2B_API_URL=/e2b` response shaping and timeout translation tests.
5. Add `/e2b/runtime` proxy routing through `Service.ToolboxTarget(...)`.
6. Implement toolboxd E2B file and process compatibility handlers.
7. Run a pinned Python smoke harness for create, connect, commands, files, PTY, and snapshots.
8. Decide whether to tackle ingress compatibility next or hold it for a second pass.
9. Update `sdk-setup.md` and `getting-started.md` after the first working path is stable.

## Recommendation

Build `/e2b` in two deliberate layers:

1. a control-plane facade plus fixed runtime gateway under `/e2b`
2. full public-host and traffic-token compatibility only after the SDK's core command, file, PTY, and snapshot flows work

That approach satisfies the user's requested path-based setup, avoids premature wildcard-host routing work, and reuses the proven Daytona facade architecture without forcing E2B terminology into the native AerolVM API.