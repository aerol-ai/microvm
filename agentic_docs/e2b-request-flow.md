# Request Flow: `Sandbox.create()` to `sandbox.commands.run()`

This walkthrough describes the concrete path the real E2B Python SDK now takes through AerolVM.

## 1. SDK bootstrap

The Python SDK is configured with:

- `E2B_API_URL=https://.../e2b`
- `E2B_SANDBOX_URL=https://.../e2b/runtime`
- `E2B_API_KEY=<pat>`

That split is important.

- `/e2b` is the control plane.
- `/e2b/runtime` is the runtime gateway.

## 2. `Sandbox.create(...)`

When the SDK calls `Sandbox.create(...)`, it sends a control-plane request to:

- `POST /e2b/sandboxes`

with:

- `X-API-KEY: <pat>`
- the E2B create JSON body containing fields such as `templateID`, `timeout`, `metadata`, `envs`, and `secure`

Inside AerolVM, the request enters `pkg/api/e2b/handlers.go:createSandbox`.

That handler does five important things before returning:

1. Translates the E2B body into native `models.CreateSandboxRequest` plus E2B-only metadata.
2. Computes a canonical request fingerprint for safe retry handling.
3. Claims a persisted create reservation so concurrent retries do not launch duplicate sandboxes.
4. Calls native `Service.CreateSandbox(...)`.
5. Persists E2B metadata and completes the create reservation.

The response is then shaped like E2B, including:

- `sandboxID`
- `envdAccessToken`
- `envdVersion`
- the template and lifecycle fields the SDK expects

## 3. Why the create response matters

The SDK does not stop at create.

It immediately uses the returned sandbox identity and runtime token to talk to the sandbox runtime. That is why returning `envdAccessToken` and a stable `sandboxID` was required for real compatibility.

## 4. Runtime calls switch to `/e2b/runtime`

When the SDK later performs runtime work such as file I/O, command execution, or health checks, it targets:

- `GET /e2b/runtime/health`
- `GET /e2b/runtime/files`
- `POST /e2b/runtime/files`
- `POST /e2b/runtime/process.Process/Start`
- `POST /e2b/runtime/filesystem.Filesystem/ListDir`

Those requests carry runtime-scoped headers such as:

- `E2b-Sandbox-Id`
- `X-Access-Token`
- optional `Authorization: Basic ...` when the SDK wants user impersonation semantics

## 5. Runtime gateway behavior

Every runtime request first enters `pkg/api/e2b/runtime_proxy.go:runtimeProxy`.

That proxy is responsible for the compatibility bridge between the public E2B-shaped surface and the native toolboxd surface.

It does the following:

1. Reads `E2b-Sandbox-Id`.
2. Loads the sandbox and its stored E2B metadata.
3. Validates `X-Access-Token` against the sandbox's stored toolbox token when the sandbox is secure.
4. Resolves the sandbox's toolbox endpoint with `Service.ToolboxTarget(...)`.
5. Rewrites `/e2b/runtime/...` to `/envd/...`.
6. Preserves inbound Basic auth as `X-E2B-User-Authorization`.
7. Injects native `Authorization: Bearer <toolbox token>` when forwarding to toolboxd.

That translation is the reason the public E2B runtime API can stay E2B-shaped while toolboxd remains protected by its existing bearer-token model.

## 6. Why `/envd` exists inside toolboxd

The E2B SDK expects envd-style runtime endpoints.

Toolboxd already had Daytona-oriented `/files` and `/process` behavior, so adding a separate internal namespace avoided collisions and made the compatibility layer explicit.

Inside toolboxd, `cmd/toolboxd/main.go:normalizeSandboxPath` preserves `/envd/...` instead of collapsing it into older route families.

Then `cmd/toolboxd/envd.go:handleEnvdRoute` dispatches the request to the matching envd-compatible handler.

## 7. `sandbox.commands.run(...)`

When the SDK runs a command, it eventually reaches:

- `POST /e2b/runtime/process.Process/Start`

The public runtime proxy rewrites that to:

- `POST /envd/process.Process/Start`

Toolboxd handles that in `cmd/toolboxd/envd.go:handleEnvdProcessStart`.

That handler:

1. Decodes the Connect JSON request body.
2. Translates the E2B process config into a native toolboxd session request.
3. Creates a process session through the existing `sessions.Manager`.
4. Registers the session in the envd compatibility index by PID or tag.
5. Streams process events back as Connect JSON envelopes.

The stream includes:

- a start event with the PID
- stdout or stderr data events
- a final end event with exit information

The SDK reads that event stream and turns it into the command result object returned by `sandbox.commands.run()`.

## 8. Example end-to-end trace

For the smoke harness path:

1. `Sandbox.create(template="base", timeout=120, metadata=..., envs=..., secure=True)`
2. `POST /e2b/sandboxes`
3. `createSandbox` translates, dedupes, creates, persists metadata, returns `sandboxID` and `envdAccessToken`
4. `sandbox.commands.run("printf $E2B_SMOKE", envs={...})`
5. `POST /e2b/runtime/process.Process/Start`
6. `runtimeProxy` validates headers and rewrites to `/envd/process.Process/Start`
7. toolboxd `handleEnvdProcessStart` creates a session and streams output
8. SDK reads the stream and returns `stdout == "smoke"`

## 9. Why this split was necessary

Without the control plane, the SDK could not create, reconnect, pause, snapshot, or delete sandboxes.

Without the runtime gateway and `/envd` compatibility surface, the SDK could create a sandbox but would immediately fail on:

- `sandbox.files.read(...)`
- `sandbox.files.write(...)`
- `sandbox.files.list(...)`
- `sandbox.commands.run(...)`
- PTY and reconnect flows

Real E2B compatibility required both planes.