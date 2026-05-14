---
name: add-daytona-route
description: Add a Daytona-SDK-compatible route under /daytona/... by translating Daytona's wire shape to internal/service calls. Keeps version branching out of internal/. Use when the user asks to "support this in the Daytona facade", "add a /daytona route", "make Daytona SDK work with X", or wants to extend Daytona compatibility coverage. Proactively suggest when adding a feature that has a corresponding Daytona SDK call.
---

# Add a Daytona compatibility route

The Daytona facade lives at `pkg/api/daytona/` and translates Daytona's wire shape to `pkg/models` + `service.Service` calls.

**No version-specific branching in `internal/`.** If you find yourself wanting `if facade == "daytona"` inside `internal/service`, stop — that translation belongs in the facade.

## File layout

```
pkg/api/daytona/
  routes.go             Route table.
  handlers.go           Wire decode → service call → wire encode.
  dto.go                Daytona-shaped request/response types.
  meta.go               Daytona-specific metadata helpers.
  toolbox.go            Toolbox-proxy paths (/daytona/toolbox/{id}/...).
  contract_test.go      Wire-level contract tests.
  contract_harness_test.go
  routes_test.go
  handlers_test.go
  toolbox_test.go
```

## Steps

1. **Route.** Add to `pkg/api/daytona/routes.go`. Follow the existing pattern:
   ```go
   mux.Handle("POST "+PathPrefix+"/sandbox/{idOrName}/myop", d.Auth(http.HandlerFunc(h.myOp)))
   ```
   The `PathPrefix` constant is `/daytona`. Use `{idOrName}` (not `{id}`) where Daytona's API accepts either form — the existing handlers resolve names via `Store.ResolveDaytonaSandboxID`.
2. **Handler.** Add to `pkg/api/daytona/handlers.go`. Translate the Daytona DTO into a `pkg/models.*` shape, then call `service.*`.
3. **DTO.** If the Daytona wire shape differs from `pkg/models`, add a translation type in `pkg/api/daytona/dto.go`. Don't pollute `pkg/models` with Daytona-shaped fields.
4. **Daytona-specific metadata** (labels, name aliases, autostop/autodelete intervals) goes through `Service.UpsertDaytonaMetadata` / `Store.UpsertDaytonaMetadata`. Business logic lives in `internal/service/daytona.go`.
5. **Update the support table** in `plans/sdk-compatibility/daytona/control-plane-matrix.md` or `toolbox-matrix.md`. Move rows from "Unsupported" to "Supported" / "Partial".
6. **Contract test.** Add to `pkg/api/daytona/contract_test.go` — these check the wire shape matches what the Daytona SDK expects.

## Hard rules (same as `/v1`)

- **Idempotency** is required (`pr-review.md` §1). Retries must be safe under the Daytona SDK's retry policy too — Daytona clients can be more aggressive than native ones.
- **Sandbox-boot impact** must be called out in the PR if the new route triggers a create path.
- **Failure-path consistency** must be documented for any route that writes to both caddy and the store.

## Where Daytona behaves differently from `/v1`

- Identifiers can be sandbox ID *or* user-supplied name → use `{idOrName}` and resolve via the store helper.
- Labels and metadata are first-class on Daytona but live in a separate metadata table on the AerolVM side.
- `/daytona/toolbox/{id}/...` is a thin proxy to the in-sandbox toolbox; see `toolbox.go`.
