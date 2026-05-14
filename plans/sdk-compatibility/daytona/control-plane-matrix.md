# Daytona Control-plane Matrix

These tables describe the current `/daytona` control-plane compatibility surface implemented by AerolVM.

## Route-level support

| Daytona route or capability | Status | AerolVM mapping | Notes |
|---|---|---|---|
| `POST /daytona/sandbox` | Partial | Maps onto native sandbox create | Image-based create is supported. Some Daytona create fields are unsupported or metadata-only. |
| `GET /daytona/sandbox` | Supported | Maps onto native sandbox list | Includes Daytona-shaped response translation. |
| `GET /daytona/sandbox/paginated` | Supported | Maps onto native sandbox list with facade pagination | Pagination is handled in the facade layer. |
| `GET /daytona/sandbox/{idOrName}` | Supported | Maps onto native sandbox get plus stored Daytona name resolution | Name lookup survives restarts via persistent store metadata. |
| `DELETE /daytona/sandbox/{idOrName}` | Supported | Maps onto native sandbox destroy | Supports lookup by Daytona name or AerolVM sandbox ID. |
| `POST /daytona/sandbox/{idOrName}/start` | Supported | Maps onto native sandbox start | Native lifecycle operation. |
| `POST /daytona/sandbox/{idOrName}/stop` | Supported | Maps onto native sandbox stop | Native lifecycle operation. |
| `POST /daytona/sandbox/{idOrName}/snapshot` | Partial | Calls native snapshot create, returns a Daytona-shaped sandbox response | Create-from-sandbox works for generated and high-level Daytona clients, but broader Daytona snapshot catalog APIs are still missing. |
| `POST /daytona/sandbox/{idOrName}/resize` | Supported | Maps onto native sandbox resize | Native resource resize operation. |
| `GET /daytona/sandbox/{id}/toolbox-proxy-url` | Supported | Returns AerolVM Daytona toolbox facade base | Used by Daytona SDKs to reach toolbox routes. |
| `GET /daytona/sandbox/{idOrName}/ports/{port}/preview-url` | Supported | Calls native port exposure | Returns Daytona-shaped preview URL response. |
| `PUT /daytona/sandbox/{idOrName}/labels` | Supported | Stored in persistent Daytona metadata | Labels are compatibility metadata, not a native AerolVM first-class resource. |
| `POST /daytona/sandbox/{idOrName}/autostop/{interval}` | Supported | Maps onto native idle-stop lifecycle | Operationally enforced by AerolVM lifecycle logic. |
| `POST /daytona/sandbox/{idOrName}/autodelete/{interval}` | Supported | Maps onto native idle-destroy lifecycle | Operationally enforced by AerolVM lifecycle logic. |
| `POST /daytona/sandbox/{idOrName}/autoarchive/{interval}` | Partial | Stored in persistent Daytona metadata only | AerolVM does not implement real archive behavior today. |

## Create-field support

| Daytona create field | Status | Current behavior |
|---|---|---|
| `name` | Supported | Persisted in store-backed Daytona metadata and resolved after restart. |
| `env` | Supported | Mapped onto native sandbox environment variables. |
| `labels` | Supported | Persisted in store-backed Daytona metadata. |
| `cpu` | Supported | Mapped onto native sandbox CPU request. |
| `memory` | Supported | Mapped onto native sandbox memory request. |
| `disk` | Supported | Mapped onto native sandbox disk request. |
| `user` | Partial | Mapped to native `OSUser` when provided. |
| `autoStopInterval` | Supported | Mapped to AerolVM idle-stop lifecycle. |
| `autoDeleteInterval` | Supported | Mapped to AerolVM idle-destroy lifecycle. |
| `autoArchiveInterval` | Partial | Stored as metadata only. No archive runtime behavior exists. |
| `snapshot` | Partial | Accepted as an image fallback/input alias. Together with the snapshot-create route, local snapshot image refs can be reused for later creates, but full Daytona snapshot management semantics do not exist. |
| `target` | Partial | Stored as metadata only. No AerolVM scheduling or region semantics exist. |
| `public=true` or omitted | Supported | Facade assumes public sandbox routing. |
| `public=false` | Partial | Accepted for compatibility, but AerolVM still treats the sandbox as public in the current Daytona facade. |
| `networkBlockAll` | Supported | Mapped onto native egress-block setting. |
| `networkAllowList` | Unsupported | Non-empty values are explicitly rejected on create. |
| `gpu` | Unsupported | Positive GPU requests are explicitly rejected in the Daytona facade. |
| `volumes` | Unsupported | Daytona volume lifecycle is not mapped. |
| `buildInfo` | Partial | The facade accepts the simple Daytona Go SDK shape `dockerfileContent: "FROM <image>"` and translates it to a native AerolVM image. Richer Dockerfile build semantics remain unsupported. |

## Known control-plane gaps

| Daytona area | Status | Gap |
|---|---|---|
| Snapshot lifecycle APIs | Partial | Create-from-sandbox now exists, but there is still no Daytona snapshot list/get/delete/activate management surface. |
| Build/image pipeline APIs | Unsupported | AerolVM create is image-based; no Daytona-style build flow is exposed. |
| Archive lifecycle | Unsupported beyond metadata | `autoarchive` is stored, but real archive behavior is not implemented. |
| Dynamic network allowlist management | Unsupported | No separate Daytona-shaped update API is exposed. |
| Target or region scheduling | Unsupported beyond metadata | `target` is stored only for compatibility display. |
| Daytona volume lifecycle | Unsupported | AerolVM has external mounts, but not Daytona volume APIs. |