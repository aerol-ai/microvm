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

## Per-example status

| Example | Should run now? | What it exercises | Notes |
|---|---|---|---|
| `auto-archive` | ✅ | `daytona.create`, `setAutoArchiveInterval`, `delete` | All routes exist. |
| `auto-delete` | ✅ | `daytona.create`, `setAutoDeleteInterval` | All routes exist. |
| `charts` | ✅ | `daytona.create` w/ image, `process.codeRun`, chart artifacts | Needs `code-run` fix (now in). Charts are returned in-band on the `codeRun` response — no separate route. |
| `create-vm` | ✅ | `daytona.create({snapshot})`, `executeCommand` | Snapshot must already exist on the registry. |
| `declarative-image` | ⚠️ | `daytona.snapshot.create({image, resources})` with `Image.debianSlim(...).pipInstall(...)` | **Big feature gap**: `POST /daytona/snapshots` is not routed. Facade has GET/DELETE for snapshots and `POST /sandbox/{id}/snapshot` (snapshot-of-running-sandbox), but no build-snapshot-from-Image path. |
| `exec-command` | ✅ | `codeRun`, `executeCommand`, sessions (sync + async logs), `codeInterpreter` | All small fixes in. CodeInterpreter requires a running toolbox daemon that implements `/process/interpreter/*` — proxy layer is now correct. |
| `file-operations` | ✅ | `fs.listFiles`, `createFolder`, `uploadFiles`, `searchFiles`, `replaceInFiles`, `downloadFiles`, `downloadFile`, `uploadFileStream`, `downloadFileStream` | Whitelisted folder + replace this pass. |
| `git-lsp` | ✅ | `git.clone`, `fs.findFiles`, `createLspServer`, `lsp.start/didOpen/documentSymbols/didClose/completions`, `fs.replaceInFiles` | `/lsp/*` prefix added. |
| `lifecycle` | ✅ | full lifecycle: create / labels / stop / start / get / exec / list / delete | All routes exist. |
| `network-settings` | ✅ | `daytona.create({networkBlockAll})`, `daytona.create({networkAllowList})` | Both fields already accepted by `createSandbox` DTO. |
| `pagination/sandbox` | ✅ | `daytona.list(labels, page, limit)` | `/sandbox/paginated` exists. |
| `pagination/snapshot` | ✅ | `daytona.snapshot.list(page, limit)` | `GET /snapshots` exists. |
| `pty` | ✅ | `createPty`, `sendInput`, `resizePtySession`, `kill`, `wait` (WS) | `process/pty/*` is now WS-capable; bare `process/pty` whitelisted. |
| `region` | ⚠️ | `daytona.snapshot.create({regionId})` and `daytona.create({snapshot})` against the regional snapshot | Inherits the `declarative-image` gap. Once `POST /daytona/snapshots` exists, `regionId` needs to be persisted on the snapshot row. |
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

### 2. Build snapshot from Image

Affects: `declarative-image`, `region`.

The Daytona SDK `snapshot.create({ name, image, resources, regionId })`
posts to `POST /snapshots` with either an `imageName` (pre-built image) or
a `buildInfo` payload (dockerfile content + context hashes the SDK uploaded
to S3 separately). The facade currently only knows how to snapshot a
running sandbox (`POST /sandbox/{id}/snapshot`).

To make `declarative-image` runnable end-to-end we need:
- `POST /daytona/snapshots` handler.
- For `imageName`: pull-or-tag-and-register flow — should reuse the same
  image-build infrastructure the create-sandbox path uses
  (`Deps.Builder.BuildImage` / `RefreshTag`).
- For `buildInfo`: dockerfile build that pulls context blobs by hash from
  the configured object store (`Daytona`'s `objectStorageApi`). This is
  the harder half — needs object-store integration on the server.
- `GET /snapshots/{id}/build-logs-url` — the SDK polls this when
  `onLogs` is set to stream build progress. Could be backed by Docker's
  build-log stream.
- `regionId` persistence on the snapshot row.

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
