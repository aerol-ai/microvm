# Facade convergence: one service path for every API surface

Status: investigation done 2026-10-12; fixes in progress as a PR stack.

## Why

AerolVM has one business layer (`internal/service`) and four HTTP surfaces:
`/v1`, and the compatibility facades `/daytona`, `/e2b` and `/runloop`. The rule
(CLAUDE.md, "Service layer is version-agnostic") is that a facade only
translates its wire format and calls the service. Every security check,
lifecycle rule, idempotency rule and error mapping lives in one place, so the
four surfaces cannot disagree.

That rule has eroded. Each facade grew its own copy of things the service
should own: image builds, snapshot resolution, cluster forwarding, error
mapping, create retries, toolbox calls. The copies drifted, and some of the
drift is a security hole. This plan lists every finding from a read-only audit
of the four surfaces, ranks it, and assigns it to a PR.

## How the audit was done

Four read-only passes over `pkg/api/{v1,daytona,e2b,runloop}`,
`pkg/api/{apihttp,clustercreate,clusterlist}`, `internal/service` and
`cmd/toolboxd`, one per area: images and snapshots; sandbox create and
lifecycle; exec, sessions and files; auth, errors and facade state. Each
finding names its code by searchable function name. **Verified** means the
claim was re-checked by reading the code (or a failing test); **unverified**
means it is inferred and must be confirmed by a test before or while fixing.

Every fix below follows the same shape: put the rule in `internal/service`
(or one shared `pkg/api` helper for HTTP plumbing), delete the facade copies,
and add a test that runs the same input through every surface.

## Findings

Severity: **S** security, **B** broken behaviour, **D** drift or duplication.
Surfaces: v1, dt (daytona), e2b, rl (runloop).

### Security

| ID | Finding | Surfaces | Status | PR |
|---|---|---|---|---|
| S1 | **Builds read any local image.** `buildImageLocked` builds with no `pull`, so dockerd resolves `FROM`, `COPY --from` and `RUN --mount=from=` against images already on the node. Nothing authorizes those references. A tenant can `FROM` another tenant's snapshot image (`docker.SnapshotImageTag` is a hash of the snapshot's name, and names are global and confirmable through a name conflict), another tenant's built image, or an older snapshot committed under its name, and start the result. | v1 `buildImage`, v1 `resolveSnapshotImage`, dt `resolveBuildInfo` | verified (no `pull`, no parsing) | A |
| S2 | **Built images have no owner.** `docker.BuildTagFor` hashes only the Dockerfile and context hashes. Built tags have no snapshot row, so `resolveSnapshotChain` treats `aerolvm-build/<hash>` as an ordinary image and any tenant who knows (or reproduces) the Dockerfile can start another tenant's build. The build cache also returns one tenant's build to another without rebuilding, so anything a build fetched at build time (a mutable `FROM` tag, `RUN curl` against an internal host) leaks. | v1, dt (direct tag, `snapshot` fallback in `createImage`, register-then-create) | verified | A |
| S3 | **Snapshot delete removes images it only points at.** `DeleteSnapshot` removes `snapshot.Image` whenever no other snapshot row holds it. A registered snapshot points at someone else's image (`python:3.12`, another tenant's build), so deleting it removes that image from the node unless a container is using it. | dt, e2b, rl delete | verified | #672 fixup |
| S4 | **Build rollback deletes a shared tag.** dt `createSandbox`, dt `createSnapshotFromImage` and v1 `registerSnapshot` call `RemoveImage(freshlyBuiltTag)` when the next step fails. Another tenant may have been handed the same tag from the cache in between. | v1, dt | verified (code path) | A |
| S5 | **WASM host file APIs follow guest symlinks.** `toolhost.resolveHostPath` checks paths as text only; `handleDownload`, `handleListFiles` and `atomicWriteFile` then open through symlinks on the host. If the guest can create a relative symlink (wazero `dirFS.Symlink`), it reads or writes host files. | all (WASM runtime) | path check verified; exploit unverified | C |
| S6 | **`/e2b/runtime` has no platform auth and compares tokens unsafely.** Mounted without `d.Auth`; the only credential is `X-Access-Token == sandbox.ToolboxToken` with `!=` (not constant time), and a `secure=false` sandbox needs none. Unscoped 404 vs 401 answers reveal which sandbox ids exist. | e2b | verified | B |
| S7 | **`/v1/sandboxes/{id}/toolbox/{path...}` reaches toolboxd's admin endpoint.** It forwards any path with the toolbox token, including `POST /admin/allowed-ports`, which gates the public `/{id}/proxy/{port}` route in path mode. A tenant can open ports without `ExposePort` until the next sync. | v1 | verified (route exists, passthrough is generic) | B |
| S8 | **Metrics endpoints accept tenant tokens.** `/debug/vars` and `/v1/metrics` use `requireAuth`, which accepts validated user tokens, so on managed builds any tenant reads fleet-wide counters. | v1 | verified | B |
| S9 | **A user token with an empty owner fails open.** `authenticateUserToken` accepts an identity whose `OwnerRef` is empty; the service then scopes the caller to owner `""`, which matches every operator-created sandbox. | all | verified | B |
| S10 | **Single-node trusts cluster control headers.** `clusterControlHeaderGuard` only checks `X-Cluster-*` when cluster mode is on, so in single-node `Prepare` honours a caller-supplied create target and id. A caller chooses its sandbox id, and a 409 reveals another tenant's id exists. | v1, dt, e2b | guard verified; id effect unverified | B |
| S11 | **Daytona reads guest output with no size limit.** `sendToolboxJSON` and `readToolboxHTTPError` read toolbox responses unbounded, and `bulkUpload` parses multipart with no `MaxBytesReader`. A guest printing gigabytes, or a large upload, exhausts the daemon's memory or temp disk for every tenant on the node. Runloop caps these (64 MiB, 4 KiB, 256 MiB); the service's WASM round trip buffers whole responses. | dt (+ service WASM path) | verified | G |
| S12 | **Toolbox calls reach a stopped sandbox's stale address.** `ToolboxTarget` only checks that `ContainerIP` is set; stop clears it only for Firecracker, so Docker and containerd calls dial a stale IP carrying the sandbox's token. | all except rl exec | code path verified; IP reuse unverified | G |

### Broken behaviour

| ID | Finding | Surfaces | Status | PR |
|---|---|---|---|---|
| B1 | **`/runloop` is unreachable through the stock Caddy config.** The `@api` matchers in `scripts/install.sh` and `packaging/Caddyfile.template` list `/v1 /daytona /e2b /mcp` only. | rl | verified | #641 fixup |
| B2 | **Daytona and E2B creates forward an empty body.** Both read the body with `apihttp.DecodeJSON` before `clustercreate.Prepare`, which forwards the same request to a remote target; v1 and Runloop restore the body first. A create placed on another node arrives empty. | dt, e2b | code path verified; needs a forwarding test | F |
| B3 | **v1's copy of the create path skips platform volumes.** `createSandboxOnSelectedNode` duplicates `clustercreate.CreateOnSelectedNode` without `ResolvePlatformVolumesForReplication`, so a failover recreate mounts by name in the operator scope. | v1 | unverified | F |
| B4 | **Daytona places the sandbox using a different request than it creates.** `clusterPlacementRequest` skips WASM translation, volumes and egress, so a Daytona WASM sandbox can land on a node without WASM. | dt | unverified | F |
| B5 | **`/e2b/runtime` is not forwarded to the owner node.** It reads the sandbox from the local store, so on an N-node cluster about (N−1)/N of E2B exec and file calls 404. | e2b | verified (no wrapper) | E |
| B6 | **Snapshot-by-id calls are not routed to the snapshot's node** on `/daytona/snapshots/{id}` and `DELETE /e2b/templates/{id}`; `GetSnapshot` reads only the local store. Runloop routes them. | dt, e2b | unverified | I |
| B7 | **`RoundTripToolbox` does not dispatch isolate sandboxes**, unlike `ServeToolboxReverseProxy`; Daytona exec/files and all Runloop calls on isolate fail with 502. | dt, rl | unverified | G |
| B8 | **Daytona proxies toolbox routes nothing implements** (`process/pty`, `DELETE files`, `files/folder`, `files/replace`, `files/permissions`, `lsp/*`); toolboxd and the WASM host 404. | dt | unverified | G |
| B9 | **E2B cluster lists drop `X-API-KEY` callers' remote sandboxes.** The peer fan-out forwards only `Authorization`. | e2b | unverified | J |
| B10 | **Daytona's unpaginated list stops at 100 in cluster mode**; the cursor is only in a header the SDK ignores. | dt | unverified | J |
| B11 | **Facade state and tag edits are lost on failover.** `sandbox_compat_state` is node-local; `UpdateTags` does not `replicateSpecPatch`. | dt, e2b, rl | unverified | J |
| B12 | **`clustercreate` writes some errors in the v1 shape on every surface** (`ErrArtifactNodeUnavailable`, no egress gateway), and Runloop loses `x-should-retry:false`. | e2b, rl | unverified | D |
| B13 | **A create slower than 5 s may fail promote.** `OverlapCreateAndPromote` starts its commit timeout before the create. | all | unverified | F |

### Drift and duplication

| ID | Finding | Surfaces | PR |
|---|---|---|---|
| D1 | **Three error mappers disagree.** `apihttp.WriteStoreAwareError` vs hand copies in e2b and runloop: admission denied 403 vs 400, admission/engine/cluster-finalization unavailable 503 vs 400 (clients stop retrying), create timeout 504 vs 400, seal/promote 500 vs 400; Daytona's `writeToolboxError` turns manual-stop and wake-circuit errors into 502. E2B hard-codes Retry-After values. | all | D |
| D2 | **Four copies of `clusterForwardWrap`** (plus `runloop.forwardToNode`, `clustercreate.routeExistingPlacement`): lookup errors 500 vs 503, duplicate loop guards, plain-text vs JSON errors, name resolution only on Daytona. | all | E |
| D3 | **Image builds are implemented three times** (v1 `buildImage`, v1 `resolveSnapshotImage`, dt `resolveBuildInfo`, two `ImageBuilder` interfaces, two single-line-`FROM` helpers) with different shortcuts, node binding and error codes. | v1, dt | A |
| D4 | **Create retries are handled four ways**: e2b derives the id from the body (identical concurrent creates share one sandbox), rl uses x-request-id plus an in-memory flight, v1 and dt have none. | all | F |
| D5 | **Slow creates are cancelled differently**: rl detaches, others cancel on client disconnect; e2b cleans its reservation with the request context. | all | F |
| D6 | **Delete twice**: 404 on v1/dt/e2b, 200 from rl's node-local, in-memory tombstones. | all | H |
| D7 | **Lifecycle rules live in facades** (e2b connect/pause, rl suspend/resume state checks; read-modify-write of `Lifecycle` in dt and e2b). | all | H |
| D8 | **Snapshot reference resolution differs**: dt resolves one hop itself and falls back to `ImageID`; e2b and rl pass names to the service. Snapshot + alias writes are copied (e2b, rl) and not atomic. | dt, e2b, rl | I |
| D9 | **Snapshot lists**: dt and e2b load the whole table and page in memory; rl pages in the store. v1 has no snapshot get/list/delete. Delete-missing is 200 on rl, 404 elsewhere. | all | I |
| D10 | **Toolbox helpers are copied**: multipart upload pipes, home-dir lookup, toolbox error readers; two service helpers dispatch runtimes differently. | dt, rl | G |
| D11 | **Facades read config from the environment** (`SB_DAYTONA_DEFAULT_IMAGE` per request, `SB_E2B_TEMPLATE_MAP_JSON`, `SB_E2B_CLIENT_ID`, the Runloop blueprint map) instead of `internal/config`; which images a tenant may start differs per facade. | dt, e2b, rl | J |
| D12 | **List fan-out is copied** (e2b and dt `listFacadeClusterItems`), with different partial-coverage policies (200 + header vs 503) and page caps (none on e2b). | dt, e2b, rl | J |
| D13 | **Owner checks rely on callers**: `request_idempotency` has no owner column; compat-state helpers don't check owners; rl re-implements visibility for its in-memory state. | all | H |
| D14 | **Runloop's execution ledger lives in the facade** (~1,700 lines): durable exec records, recovery watchers, output tails. Other surfaces have no exec dedupe. | rl | later |
| D15 | **Too many store reads per toolbox call** (5+ on dt, 3 on rl exec). | dt, rl | G |

## PR stack

Every PR is stacked; nothing merges until the stack is green (one task per
PR). Fixes to code that is still under review go to that PR.

| PR | Scope | Findings |
|---|---|---|
| #641 fixup | Caddy routes `/runloop` | B1 |
| #672 fixup | Snapshot delete removes only the snapshot's own committed image | S3 |
| A | `Service.BuildImage`: one build path for v1 and Daytona; owner-scoped built tags; every base-image reference authorized as the caller; rollback through the pending-image GC; typed errors | S1, S2, S4, D3 |
| B | Edge auth: `/e2b/runtime` constant-time token and scoped lookup; deny toolboxd `/admin/*` through the v1 passthrough; operator-only metrics; reject empty owners; ignore cluster control headers in single-node | S6–S10 |
| C | WASM host files confined with `os.Root` | S5 |
| D | One error table (`apihttp`), used by every facade writer and by `clustercreate` | D1, B12 |
| E | One cluster forward wrapper; `/e2b/runtime` forwarded by its header id | D2, B5 |
| F | One create path: body handling inside `Prepare`, v1 on `CreateOnSelectedNode`, Daytona places the translated request, create idempotency and detachment in the service | B2–B4, B13, D4, D5 |
| G | Toolbox access in the service: bounded round trips, isolate dispatch, not-running refusal, shared upload/home-dir/exec helpers, 501 for unimplemented Daytona routes | S11, S12, B7, B8, D10, D15 |
| H | Lifecycle and delete in the service: state rules, lifecycle patches under the sandbox lock, durable delete idempotency, owner checks inside shared state helpers | D6, D7, D13 |
| I | Snapshot catalogue: one reference resolver, atomic snapshot + alias, store-paged lists everywhere, home-node routing for snapshot ids, v1 get/list/delete | B6, D8, D9 |
| J | Facade config in `internal/config`, one list fan-out and partial policy, replicated facade state and tags | B9–B11, D11, D12 |
| later | Move the Runloop execution ledger into the service | D14 |

## Test that keeps the surfaces together

Each PR adds cases to a cross-surface table test: the same request (a create,
a snapshot reference, an error from the service, a forwarded call) through
`/v1`, `/daytona`, `/e2b` and `/runloop`, asserting the same outcome. A
facade that grows its own rule fails it.
