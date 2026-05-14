# E2B SDK Method Map

This file maps the supported E2B SDK methods to the AerolVM handler or toolboxd path they now hit.

## Control-plane methods

| E2B SDK method | External path | AerolVM entry point | Notes |
|---|---|---|---|
| `Sandbox.create(...)` | `POST /e2b/sandboxes` | `pkg/api/e2b/handlers.go:createSandbox` | Creates a sandbox, persists E2B metadata, and returns runtime token info. |
| `Sandbox.list(...)` | `GET /e2b/sandboxes` or `GET /e2b/v2/sandboxes` | `pkg/api/e2b/handlers.go:listSandboxes` | Supports state and metadata filtering on the shaped E2B response. |
| `Sandbox.connect(...)` | `POST /e2b/sandboxes/{id}/connect` | `pkg/api/e2b/handlers.go:connectSandbox` | Starts a stopped sandbox if needed and only extends timeouts forward. |
| `sandbox.pause()` | `POST /e2b/sandboxes/{id}/pause` | `pkg/api/e2b/handlers.go:pauseSandbox` | No-op success if the sandbox is already paused. |
| `sandbox.kill()` | `DELETE /e2b/sandboxes/{id}` | `pkg/api/e2b/handlers.go:deleteSandbox` | Destroys the sandbox. |
| timeout update methods | `POST /e2b/sandboxes/{id}/timeout` | `pkg/api/e2b/handlers.go:updateTimeout` | Updates lifecycle timeout semantics. |
| `sandbox.create_snapshot(...)` | `POST /e2b/sandboxes/{id}/snapshots` | `pkg/api/e2b/handlers.go:createSnapshot` | Persists a stable E2B-facing snapshot ID. |
| `sandbox.list_snapshots(...)` | `GET /e2b/snapshots` | `pkg/api/e2b/handlers.go:listSnapshots` | Lists snapshot metadata in the E2B response shape. |
| `Sandbox.delete_snapshot(snapshot_id)` | `DELETE /e2b/templates/{id}` | `pkg/api/e2b/handlers.go:deleteSnapshot` | Deletes by the same stable external snapshot ID returned at create time. |

## Runtime file methods

All runtime methods first pass through the public runtime gateway:

- `pkg/api/e2b/runtime_proxy.go:runtimeProxy`

That proxy rewrites `/e2b/runtime/...` to `/envd/...` inside toolboxd.

| E2B SDK method | Public runtime path | Toolboxd path after rewrite | Toolboxd handler |
|---|---|---|---|
| `sandbox.files.read(path)` | `GET /e2b/runtime/files?path=...` | `GET /envd/files?path=...` | `cmd/toolboxd/envd.go:handleEnvdFileRead` |
| `sandbox.files.write(path, content)` | `POST /e2b/runtime/files?path=...` | `POST /envd/files?path=...` | `cmd/toolboxd/envd.go:handleEnvdFileWrite` |
| `sandbox.files.list(path, depth=...)` | `POST /e2b/runtime/filesystem.Filesystem/ListDir` | `POST /envd/filesystem.Filesystem/ListDir` | `cmd/toolboxd/envd.go:handleEnvdFilesystemListDir` |
| directory stat calls | `POST /e2b/runtime/filesystem.Filesystem/Stat` | `POST /envd/filesystem.Filesystem/Stat` | `cmd/toolboxd/envd.go:handleEnvdFilesystemStat` |
| directory creation calls | `POST /e2b/runtime/filesystem.Filesystem/MakeDir` | `POST /envd/filesystem.Filesystem/MakeDir` | `cmd/toolboxd/envd.go:handleEnvdFilesystemMakeDir` |
| move or rename calls | `POST /e2b/runtime/filesystem.Filesystem/Move` | `POST /envd/filesystem.Filesystem/Move` | `cmd/toolboxd/envd.go:handleEnvdFilesystemMove` |
| remove calls | `POST /e2b/runtime/filesystem.Filesystem/Remove` | `POST /envd/filesystem.Filesystem/Remove` | `cmd/toolboxd/envd.go:handleEnvdFilesystemRemove` |

## Runtime process methods

| E2B SDK method | Public runtime path | Toolboxd path after rewrite | Toolboxd handler |
|---|---|---|---|
| `sandbox.commands.run(...)` | `POST /e2b/runtime/process.Process/Start` | `POST /envd/process.Process/Start` | `cmd/toolboxd/envd.go:handleEnvdProcessStart` |
| process reconnect flows | `POST /e2b/runtime/process.Process/Connect` | `POST /envd/process.Process/Connect` | `cmd/toolboxd/envd.go:handleEnvdProcessConnect` |
| process listing | `POST /e2b/runtime/process.Process/List` | `POST /envd/process.Process/List` | `cmd/toolboxd/envd.go:handleEnvdProcessList` |
| PTY resize | `POST /e2b/runtime/process.Process/Update` | `POST /envd/process.Process/Update` | `cmd/toolboxd/envd.go:handleEnvdProcessUpdate` |
| stdin or PTY input | `POST /e2b/runtime/process.Process/SendInput` | `POST /envd/process.Process/SendInput` | `cmd/toolboxd/envd.go:handleEnvdProcessSendInput` |
| signal delivery | `POST /e2b/runtime/process.Process/SendSignal` | `POST /envd/process.Process/SendSignal` | `cmd/toolboxd/envd.go:handleEnvdProcessSendSignal` |
| stdin close without killing process | `POST /e2b/runtime/process.Process/CloseStdin` | `POST /envd/process.Process/CloseStdin` | `cmd/toolboxd/envd.go:handleEnvdProcessCloseStdin` |

## Runtime health

| E2B operation | Public runtime path | Toolboxd path after rewrite | Toolboxd handler |
|---|---|---|---|
| runtime health check | `GET /e2b/runtime/health` | `GET /envd/health` | `cmd/toolboxd/envd.go:handleEnvdHealth` |

## Unsupported runtime watcher APIs

These paths currently exist only to return explicit `501 Not Implemented` responses:

- `POST /e2b/runtime/filesystem.Filesystem/WatchDir`
- `POST /e2b/runtime/filesystem.Filesystem/CreateWatcher`
- `POST /e2b/runtime/filesystem.Filesystem/GetWatcherEvents`
- `POST /e2b/runtime/filesystem.Filesystem/RemoveWatcher`

After rewrite, toolboxd handles those under `/envd/...` and returns a clear not-implemented error instead of silently pretending support.

## One important nuance: `sandbox.is_running()`

`sandbox.is_running()` is usually a client-side convenience check against the current sandbox object's state, not a dedicated AerolVM endpoint of its own.

In practice, the state it inspects comes from prior control-plane responses such as:

- `Sandbox.create(...)`
- `Sandbox.connect(...)`
- sandbox fetch or list operations

So it is useful to think of it as reading the latest known E2B-shaped sandbox state rather than issuing its own runtime call.