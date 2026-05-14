# Daytona and E2B Compatibility Facade Plan

Note: the E2B portion of this document is now historical context. The active E2B implementation plan lives in `plans/sdk-compatibility/e2b/facade-plan.md`.

## Objective

Make AerolVM consumable by external sandbox SDKs without changing AerolVM's own SDKs, starting with Daytona and then E2B.

The concrete target is:

1. Expose a `/daytona` endpoint surface that accepts Daytona-style requests and maps them onto AerolVM's existing control-plane and toolbox capabilities.
2. Expose a parallel `/e2b` compatibility surface using the same facade architecture.
3. Keep AerolVM's native API and SDKs unchanged. In particular, do not modify `sdk/go` to look like Daytona.
4. Document the setup from the server side, primarily in `docs/src/content/docs/getting-started.md` and `docs/src/content/docs/sdk-setup.md`.

## Non-goals

- Do not change `/v1` behavior to impersonate Daytona or E2B.
- Do not rename AerolVM models to external product terminology internally.
- Do not promise full Daytona or E2B parity on day one when the underlying capability does not exist.
- Do not add server-side behavior only to satisfy an external SDK unless the behavior is also a sensible AerolVM primitive.

## Current Code Structure

These are the key code paths the compatibility work should build on.

### Top-level HTTP router

- `pkg/api/server.go` is the only place that wires top-level route families.
- Today it mounts `/health` and `/v1/...`.
- This is the correct insertion point for new top-level facades such as `/daytona/...` and `/e2b/...`.

### Versioned AerolVM API

- `pkg/api/v1/routes.go` and `pkg/api/v1/handlers.go` are intentionally thin.
- They decode AerolVM wire DTOs, call `internal/service`, and encode responses.
- `pkg/api/v1/proxy.go` already contains the reverse-proxy pattern for per-sandbox toolbox routing.

### Core server capabilities already present

`internal/service/service.go` already gives us a strong substrate for a compatibility layer:

- sandbox create, get, list, start, stop, destroy, resize
- lifecycle timers
- encrypted mount persistence
- toolbox target discovery per sandbox
- HTTP/TCP/TLS port exposure
- idempotent port exposure behavior already called out in `pr-review.md`

This is important because it means the compatibility work should mostly be translation and selective augmentation, not a second orchestration stack.

### Current toolbox surface

`cmd/toolboxd/main.go` currently exposes a narrower toolbox API than Daytona expects. AerolVM toolbox support today includes:

- `POST /process/execute`
- `GET /process/exec/stream`
- `POST /files/upload`
- `GET /files/download`
- `/sessions/...`

This is a major planning constraint. Daytona's sandbox object is not just a control-plane client; it also constructs a Daytona toolbox client and expects a richer file/process surface.

### Docs entry points requested by the user

- `docs/src/content/docs/getting-started.md`
- `docs/src/content/docs/sdk-setup.md`

Those are the right places for setup guidance, but if compatibility mode grows beyond a short setup section we should consider a dedicated docs page later to stay aligned with the repo's docs conventions.

## Daytona SDK Contract: What It Actually Needs

The local Daytona Go SDK at `/Users/sumansaurabh/Documents/startup-3/opensource-repos/daytona/libs/sdk-go` is configurable via `DAYTONA_API_URL` or `DaytonaConfig.APIUrl`, so AerolVM can be targeted without changing Daytona's SDK.

From the code reviewed, the Daytona SDK expects two separate surfaces:

1. A Daytona-shaped control plane under the configured base URL.
2. A Daytona-shaped toolbox base URL returned in sandbox responses, which the SDK then uses for process, file system, PTY, git, code interpreter, and related sandbox operations.

### Strong overlap with AerolVM today

These Daytona concepts map well to existing AerolVM primitives:

- create sandbox from an image string
- get sandbox
- list sandboxes
- start sandbox
- stop sandbox
- delete sandbox
- resize sandbox
- execute a command in the sandbox
- upload and download files
- session-style process continuity
- per-port public URL exposure
- network block-all and allowlist at create time

### Partial overlap that needs translation logic

These can likely be supported, but only with explicit mapping rules:

- Daytona `AutoStopInterval` -> AerolVM lifecycle idle-stop
- Daytona `AutoDeleteInterval` -> AerolVM lifecycle idle-destroy
- Daytona preview link -> AerolVM `ExposePort(..., "http")` with an adapter-shaped response
- Daytona toolbox URL -> AerolVM proxy URL that points at a Daytona-specific toolbox facade

### Capability gaps that are not solved by a path rewrite

These are real gaps and should be called out up front:

- sandbox names are not first-class in AerolVM's current public model
- sandbox labels are not a first-class persisted API concept
- Daytona target/region does not exist in AerolVM
- Daytona snapshot APIs do not exist in AerolVM
- Daytona image-build and build-log flows do not exist in AerolVM's current create path
- Daytona volume lifecycle APIs do not exist; AerolVM has external mounts instead
- Daytona archive APIs do not exist in AerolVM
- Daytona dynamic network-update APIs do not exist as a public AerolVM surface today
- Daytona toolbox filesystem APIs are much richer than AerolVM's current upload/download-only toolbox implementation
- Daytona toolbox services like Git, LSP, computer-use, and code interpreter are not current AerolVM toolbox features

## Key Architectural Conclusion

`/daytona` cannot be implemented as a naive reverse proxy to `/v1`.

The control-plane shapes differ, and the Daytona SDK also expects a Daytona toolbox API. The correct design is a facade layer with explicit request/response translation and selective proxying.

The same logic applies to `/e2b`.

## Proposed Package Layout

Add two new top-level API packages and one shared compatibility helper area.

```text
pkg/api/
  daytona/
    routes.go
    handlers.go
    dto.go
    toolbox_proxy.go
    translate.go
  e2b/
    routes.go
    handlers.go
    dto.go
    toolbox_proxy.go
    translate.go
internal/compat/
  lifecycle.go
  errors.go
  urls.go
```

### Design rules

- `pkg/api/daytona` owns Daytona wire contracts.
- `pkg/api/e2b` owns E2B wire contracts.
- `internal/service` stays external-product agnostic.
- Shared translation helpers must stay generic. If a helper starts embedding Daytona-only or E2B-only semantics, keep it inside that facade package instead.

## Router Plan

Update `pkg/api/server.go` to register:

- `/daytona/...`
- `/e2b/...`

This mirrors the existing route-family pattern used for `/v1` and keeps the compatibility surfaces isolated from AerolVM's native API.

## Daytona Facade Plan

### Phase 0: Pin the supported Daytona contract

Before implementing handlers, capture the exact HTTP contract we want to support from the current Daytona SDK version.

Scope this to the subset that provides real value immediately:

- image-based sandbox lifecycle
- resize
- command execution
- file upload/download
- sessions or PTY continuity where feasible
- preview links

Anything outside that subset should be intentionally marked unsupported instead of being silently approximated.

### Phase 1: Control-plane facade

Implement Daytona control-plane endpoints under `/daytona` that translate into AerolVM service calls.

Initial support target:

- create sandbox from image string
- get sandbox
- list sandboxes
- start sandbox
- stop sandbox
- delete sandbox
- resize sandbox

Translation rules:

- image string -> `models.CreateSandboxRequest.Image`
- env vars -> `Env`
- user -> map to `OSUser` when valid, otherwise reject explicitly
- resource CPU/memory/disk -> AerolVM resource fields
- network block-all / allowlist -> existing AerolVM create fields
- auto-stop interval -> lifecycle stop-if-idle
- auto-delete interval -> lifecycle destroy-if-idle

Unsupported create inputs should fail clearly, for example:

- snapshot-based create
- custom build info / Dockerfile build
- target region
- public/private semantics if Daytona requires behavior AerolVM does not have
- labels if we do not introduce them as a true AerolVM capability
- Daytona volumes during initial rollout

### Phase 2: Daytona response shaping

Every Daytona sandbox response needs to look like a Daytona sandbox, not an AerolVM sandbox.

That means synthesizing or mapping fields such as:

- `id`
- `name`
- `state`
- `target`
- `autoArchiveInterval`
- `autoDeleteInterval`
- `networkBlockAll`
- `networkAllowList`
- `toolboxProxyUrl`

Important choices:

- If AerolVM does not truly support a field, prefer an empty or omitted value plus explicit documentation over a misleading fake value.
- `toolboxProxyUrl` should point at a Daytona facade path, not directly at `/v1/sandboxes/{id}/toolbox`.

Recommended shape:

- return `toolboxProxyUrl` as something like `/daytona/toolbox`
- let the Daytona SDK append `/{sandboxId}` exactly as it already does

### Phase 3: Daytona toolbox facade

This is the critical piece that makes the Daytona SDK actually usable after sandbox creation.

Implement `/daytona/toolbox/{sandboxId}/...` as a compatibility facade that does one of three things per endpoint:

1. direct proxy to an existing AerolVM toolbox endpoint
2. path and body translation around an existing AerolVM toolbox endpoint
3. explicit `501 Not Implemented` when AerolVM has no equivalent capability

Initial Daytona toolbox support target:

- process execution
- streaming process output if the Daytona SDK path can be mapped cleanly
- single-file upload
- single-file download
- session-style process continuity where semantics match closely enough

Expected follow-up work on `toolboxd` for better Daytona compatibility:

- folder creation
- file listing and metadata
- file delete and move
- bulk upload/download aliases
- any PTY-specific endpoints the Daytona SDK actually exercises

This work should be treated as AerolVM toolbox expansion, not as Daytona-only hacks, when the feature is generally useful.

### Phase 4: Preview and port compatibility

Map Daytona preview-style access onto AerolVM port exposure.

Recommended initial behavior:

- Daytona preview URL request -> call AerolVM `ExposePort(..., "http")`
- return the public URL
- return an empty token if AerolVM keeps the route public

Do not implement signed preview semantics unless we add a real signed-preview concept server-side.

### Phase 5: Explicitly unsupported Daytona features

Return clear unsupported responses for the first iteration of:

- snapshots
- build logs
- archive
- volumes API
- labels replacement
- dynamic network-update APIs
- Git service
- LSP service
- computer-use service
- code interpreter service

The goal is a dependable subset, not a broad but misleading surface.

## E2B Facade Plan

There is no local E2B SDK or repo checked out alongside Daytona in `opensource-repos`, so `/e2b` should be planned as a second facade on the same architecture, but with an explicit discovery step first.

### Phase 0: Contract discovery

Before implementing `/e2b`, pin:

- which E2B SDK version we are targeting
- which language SDKs matter first
- which exact control-plane and runtime APIs must work

Do not start coding `/e2b` from memory.

### Phase 1: Reuse the same facade pattern

After contract discovery:

- add `pkg/api/e2b`
- register it from `pkg/api/server.go`
- reuse the same generic helper patterns used by `/daytona`
- add an E2B-specific toolbox/runtime facade only where the wire contract differs

### Expected likely overlap

Based on AerolVM's current capabilities, E2B compatibility is most likely feasible first around:

- sandbox lifecycle
- command execution
- file upload/download
- port exposure and browser previews
- network restriction

### Expected likely gaps

These should be assumed unknown until we inspect the actual E2B SDK we intend to support:

- template semantics
- env initialization behavior
- filesystem APIs beyond upload/download
- browser or desktop-specific APIs
- code interpreter semantics

## Why the Daytona and E2B work should share one architecture

Both integrations are adapter problems around the same AerolVM substrate.

Shared concerns:

- auth translation
- error translation
- lifecycle interval conversion
- URL shaping for control-plane and toolbox paths
- unsupported-feature handling
- contract-test scaffolding

If we do `/daytona` first in a way that hardcodes one-off assumptions into `internal/service`, `/e2b` will be slower and messier. If we build proper facades now, `/e2b` becomes an incremental adapter rather than a second rewrite.

## Testing Plan

### Control-plane adapter tests

Add focused tests for each facade package that verify:

- request translation into `internal/service`
- response shaping back into Daytona/E2B wire formats
- unsupported fields fail clearly
- auth behavior is consistent with the external SDK's expectations

### Toolbox facade tests

Add tests that prove the adapter routes either:

- proxy correctly to existing toolbox endpoints, or
- translate correctly, or
- return `501` with a stable error body

### End-to-end compatibility tests

For Daytona first:

- point a real or fixture-based Daytona client at AerolVM `/daytona`
- create sandbox from image string
- execute a command
- upload and download a file
- stop and delete the sandbox

This should be the acceptance gate for the first implementation.

### Guardrails from `pr-review.md`

The compatibility work touches `pkg/api`, and likely `internal/service` and `cmd/toolboxd`, so explicitly preserve:

- idempotency on repeated requests
- no accidental added work in the AerolVM create hot path unless called out
- no `/v1` wire behavior drift
- clean failure-path rollback rules when facades create side effects such as exposing ports

## Documentation Plan

The user specifically wants docs updates centered on:

- `docs/src/content/docs/getting-started.md`
- `docs/src/content/docs/sdk-setup.md`

Recommended changes after implementation:

### `getting-started.md`

Add a short compatibility section that explains:

- AerolVM can expose Daytona- and E2B-compatible facades
- the Daytona base URL should point at `/daytona`
- the E2B base URL should point at `/e2b`
- compatibility mode is server-side and does not require AerolVM SDK changes

### `sdk-setup.md`

Add a compatibility section that explains:

- native AerolVM SDKs remain the primary API
- Daytona and E2B SDKs can target AerolVM through compatibility endpoints
- which features are supported in the current compatibility subset
- which features remain unsupported

Important docs note:

- if the compatibility setup grows beyond a short section, promote it to a dedicated docs page instead of bloating setup pages.

## Recommended Implementation Order

1. Freeze the Daytona support subset and exact route inventory.
2. Scaffold `pkg/api/daytona` and register `/daytona` in `pkg/api/server.go`.
3. Implement Daytona control-plane lifecycle subset.
4. Implement Daytona toolbox facade for process plus basic file transfer.
5. Add contract-style end-to-end tests using the Daytona SDK.
6. Document Daytona setup in the requested docs files.
7. Inspect the target E2B SDK and freeze its support subset.
8. Scaffold `pkg/api/e2b` and implement the same pattern.

## Open Questions To Resolve Before Coding

1. Which Daytona SDK version do we want to pin as the compatibility target?
2. Do we want to support only API-key auth initially and explicitly reject Daytona JWT org flows?
3. Should sandbox `name` be introduced as a first-class AerolVM field, or omitted from the compatibility subset initially?
4. Should preview URLs in compatibility mode always be public, or do we want to add a true signed-preview feature first?
5. For E2B, which SDK and language should define the first supported contract?
6. Do we want the first delivery to be a narrow but working Daytona subset, or do we want to delay until richer filesystem coverage is added to `toolboxd`?

## Recommendation

Implement Daytona first, but only as a well-defined subset with a real toolbox facade. Do not start with E2B in parallel until the shared facade scaffolding exists and the E2B target SDK is pinned.

That sequence gives us the fastest path to a credible compatibility story while keeping AerolVM's native API clean.