---
name: add-v1-endpoint
description: Add a new route under /v1/... to the AerolVM HTTP server. Walks through DTOs, handler, route registration, service-layer call, tests, and the idempotency check. Use when the user asks to "add a v1 endpoint", "add an API route", "add a new HTTP handler", or describes a new sandbox/admin operation that needs to be exposed over /v1. Proactively suggest when the user proposes a server feature without saying which version it belongs in — and remind them v1 is soft-frozen.
---

# Add a `/v1` endpoint

**Hard constraint:** `/v1` is **soft-frozen** (see `pr-review.md` §6).

- Adding a brand-new route → fine.
- Changing an existing v1 response body, status code, header, or path → **not fine**. Put it in `pkg/api/v2/` instead.
- No `if version == "v1"` branching in `internal/`. The service layer is version-agnostic.

## Steps

1. **DTOs.** Add request + response types to `pkg/api/v1/dto.go` if they're version-shaped. If they match `pkg/models/*`, reuse those directly — don't duplicate.
2. **Handler.** Add a method on `*handlers` in `pkg/api/v1/handlers.go`. Keep it thin:
   ```go
   func (h *handlers) myThing(w http.ResponseWriter, r *http.Request) {
       var req models.MyRequest
       if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
           apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
           return
       }
       resp, err := h.deps.Service.MyThing(r.Context(), req)
       if err != nil {
           apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
           return
       }
       apihttp.WriteJSON(w, http.StatusOK, resp)
   }
   ```
   - Use `apihttp.WriteStoreAwareError` so `models.ErrNotFound` / capacity errors map to the right status.
3. **Route.** Register in `pkg/api/v1/routes.go` with the method baked into the pattern and `d.Auth(...)`:
   ```go
   mux.Handle("POST "+PathPrefix+"/my/route", d.Auth(http.HandlerFunc(h.myThing)))
   ```
4. **Service method.** Add the business logic on `*service.Service` (in `internal/service/`, topical file).
5. **Tests.** Add a handler-level test in `pkg/api/v1/routes_test.go` AND a service test in `internal/service/*_test.go`.

## Before opening the PR

Answer these in your head (and fill in the PR template):

- **Idempotency** (`pr-review.md` §1): what happens if this exact request is retried 5× concurrently with the same inputs? Retrying must not leak resources or return "already exists".
- **Sandbox boot impact** (`pr-review.md` §2): does this add ANY work to `CreateSandbox` or anything it transitively calls? If yes, call it out explicitly — even "only on the first call" counts.
- **Failure-path consistency** (`pr-review.md` §4): if the handler writes to both caddy and the store, what cleans up on partial failure?
