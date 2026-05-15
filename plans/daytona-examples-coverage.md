# Daytona examples coverage audit

Audit of `aerovm-examples/daytona-examples` against the daytona facade in
`pkg/api/daytona`. One row per example, with the SDK surface it touches,
whether it should run today, and what (if anything) is still missing.

Done in this pass:

- `POST /process/code-run` whitelisted (`sandbox.process.codeRun`).
- `process/session/*`, `process/interpreter/*`, `process/pty/*` switched to
  `httputil.ReverseProxy` so WebSocket upgrades (logs, interpreter execute,
  PTY connect) survive the proxy.
- `process/pty` (bare) added — covers `listPtySessions` + `createPty`.
- `DELETE /files`, `POST /files/folder`, `POST /files/replace`,
  `POST /files/permissions` whitelisted.
- `/lsp/*` whitelisted as a prefix.
- `/work-dir` accepted as alias for `/workdir` (SDK `InfoApi.getWorkDir`).
- **`POST /daytona/snapshots`** — snapshot-from-image (the
  `declarative-image` + `region` blocker). Two paths supported:
  - `imageName`: pre-built registry image, registered as-is.
  - `buildInfo.dockerfileContent`: Dockerfile run through the existing
    `resolveBuildInfo` → `Builder.BuildImage` pipeline. Single-line `FROM`
    short-circuits to the bare image without a build.
- **Snapshot name → image lookup** wired into `createImage`. The Daytona
  SDK passes a snapshot *name* on sandbox create; the facade now resolves
  that name through the snapshot store and uses the row's image as the
  runtime image. Unknown names still fall through as direct image refs
  for backwards compat (the `create-vm` example pattern).
- `SandboxSnapshot` model extended with `Entrypoint`, `RegionID`, `CPU`,
  `GPU`, `MemoryMB`, `DiskGB` — surfaced back through `toSnapshotResponse`
  so SDK polls see the resources/region the caller asked for.
- `service.RegisterSnapshot` added — persists an image-backed snapshot
  row, idempotent on (name + image), conflicts on different image under
  same name.

## Per-example status

| Example | Should run now? | What it exercises | Notes |
|---|---|---|---|
| `auto-archive` | ✅ | `daytona.create`, `setAutoArchiveInterval`, `delete` | All routes exist. |
| `auto-delete` | ✅ | `daytona.create`, `setAutoDeleteInterval` | All routes exist. |
| `charts` | ✅ | `daytona.create` w/ image, `process.codeRun`, chart artifacts | Needs `code-run` fix (now in). Charts are returned in-band on the `codeRun` response — no separate route. |
| `create-vm` | ✅ | `daytona.create({snapshot})`, `executeCommand` | Snapshot must already exist on the registry. |
| `declarative-image` | ⚠️ (partial) | `daytona.snapshot.create({image, resources})` with `Image.debianSlim(...).pipInstall(...)` | `POST /daytona/snapshots` now exists. `imageName` and `buildInfo.dockerfileContent` paths work end-to-end. The example also uses `Image.addLocalFile(...)` which uploads context blobs via the Daytona object-storage API + sends `buildInfo.contextHashes` — that uploader endpoint and the daemon-side context resolver are still missing (see big-feature notes below). |
| `exec-command` | ✅ | `codeRun`, `executeCommand`, sessions (sync + async logs), `codeInterpreter` | All small fixes in. CodeInterpreter requires a running toolbox daemon that implements `/process/interpreter/*` — proxy layer is now correct. |
| `file-operations` | ✅ | `fs.listFiles`, `createFolder`, `uploadFiles`, `searchFiles`, `replaceInFiles`, `downloadFiles`, `downloadFile`, `uploadFileStream`, `downloadFileStream` | Whitelisted folder + replace this pass. |
| `git-lsp` | ✅ | `git.clone`, `fs.findFiles`, `createLspServer`, `lsp.start/didOpen/documentSymbols/didClose/completions`, `fs.replaceInFiles` | `/lsp/*` prefix added. |
| `lifecycle` | ✅ | full lifecycle: create / labels / stop / start / get / exec / list / delete | All routes exist. |
| `network-settings` | ✅ | `daytona.create({networkBlockAll})`, `daytona.create({networkAllowList})` | Both fields already accepted by `createSandbox` DTO. |
| `pagination/sandbox` | ✅ | `daytona.list(labels, page, limit)` | `/sandbox/paginated` exists. |
| `pagination/snapshot` | ✅ | `daytona.snapshot.list(page, limit)` | `GET /snapshots` exists. |
| `pty` | ✅ | `createPty`, `sendInput`, `resizePtySession`, `kill`, `wait` (WS) | `process/pty/*` is now WS-capable; bare `process/pty` whitelisted. |
| `region` | ✅ (single-region) | `daytona.snapshot.create({regionId})` and `daytona.create({snapshot})` against the regional snapshot | `regionId` is now persisted on the snapshot row and echoed back in the response (`regionIds: [...]`). The daemon does not yet route requests across regions, so the example creates and lists snapshots in both regions but a real multi-region deployment would still need region-aware backend routing. |
| `volumes` | ❌ | `daytona.volume.get('name', create=true)`, `daytona.create({volumes:[{volumeId, mountPath, subpath}]})` | **Big feature gap**: volume management is intentionally rejected by the facade (`handlers.go:786`). Needs: `GET/POST/DELETE /daytona/volumes`, `GET /daytona/volumes/by-name/{name}`, plus `Volumes` wiring in `createSandbox` translation and mount-binding through `service.CreateSandbox`. |

## Big-feature gaps (deferred)

These require backend work beyond a route whitelist and are tracked here
rather than implemented in-pass.

### 1. Volume management

Affects: `volumes`.

Surface needed on the facade:
- `GET /daytona/volumes` — list (paginated).
- `POST /daytona/volumes` — create.
- `GET /daytona/volumes/{id}` — get by id.
- `GET /daytona/volumes/by-name/{name}` — get by name (the SDK uses this in
  `daytona.volume.get('name', true)` with create-if-missing semantics).
- `DELETE /daytona/volumes/{id}`.

Backend needed:
- A `volumes` table in `internal/store` (or reuse an existing one if mounts
  already track them).
- Wiring `Volumes` in `createSandboxRequest` → `models.CreateSandboxRequest`
  → `service.CreateSandbox` → `mounts.Manager` binds. The translation today
  short-circuits at `handlers.go:786` with `"volumes are not supported"`.
- Subpath support inside the mount manager (the SDK passes a `subpath`
  field per-volume binding for multi-tenant isolation).

### 2. Build snapshot from Image — partially done

Affects: `declarative-image`, `region`.

**Done:**
- `POST /daytona/snapshots` handler — `imageName` and
  `buildInfo.dockerfileContent` both supported.
- Snapshot store extended with entrypoint / regionId / cpu / gpu /
  memoryMB / diskGB.
- Snapshot name → image lookup in `createImage` so
  `daytona.create({snapshot: name})` correctly resolves.
- Synchronous build, return `state=active` so SDK poll loop exits on the
  first read (no build-logs-url endpoint needed for the no-onLogs case).

**Still missing:**
- **`contextHashes` resolver.** Required by `Image.addLocalFile(...)` (used
  by the `declarative-image` example). The SDK uploads context blobs to
  Daytona's `objectStorageApi` and sends the hashes in `buildInfo`. We need:
  - An object-storage facade endpoint the SDK can upload to (today returns
    "not configured" — see `Daytona.js` `processImageContext`).
  - A daemon-side resolver that fetches blobs by hash, assembles a build
    context tar, and hands it to `Builder.BuildImage` (gated behind
    `SB_IMAGE_BUILD_CONTEXT_ENABLED`; the resolver itself returns "not yet
    implemented" today).
- **`GET /snapshots/{id}/build-logs-url`** — only needed when the SDK
  caller passes `onLogs: console.log` and the build runs asynchronously.
  With the current synchronous-build approach + `state=active` on first
  return, the SDK never enters its log-streaming branch.
- **Multi-region routing.** `regionId` is persisted and echoed, but the
  daemon doesn't yet route create/list operations across regions.

### 3. ComputerUse / `/computeruse/*`

Not exercised by any example in the audit. Skip for now; if a future
example needs it, mirror the `/lsp/*` prefix approach.

## How to re-verify

```sh
cd sandbox-library
go test ./pkg/api/daytona/ -count=1
```

`TestToolboxProxyForwardedRoutes` is a table-driven test where each row is
tagged with the example that would break if the route regresses — failure
output points directly at the affected example.
