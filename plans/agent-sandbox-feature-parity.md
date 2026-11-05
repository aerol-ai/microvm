# agent-sandbox feature parity plan

**Status:** Decisions closed 2026-11-05 (section 11) · **Date:** 2026-11-05 · **Branch:** `plans/agent-sandbox-feature-parity` (from `main` at `e33b6e16`)

**In one line:** build the useful features of
[kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
that do not need Kubernetes, fix three bugs we found on our side while
comparing, and park the Kubernetes-only features for the later "run AerolVM on
Kubernetes" effort.

---

## 1. Why this plan

agent-sandbox is the Kubernetes SIG Apps project for AI agent sandboxes. It
installs on any cluster with Helm, and each sandbox is a Kubernetes pod. We
studied it in depth: its code, docs, roadmap and open issues, plus a live test
on a local cluster.

What it has and we don't falls into two groups:

1. **Things it gets for free because a sandbox is a pod.** Install with
   Helm or GitOps, any pod setting, a cloud identity per pod (IRSA), Kueue
   quotas, KEDA autoscaling, policy tools like OPA Gatekeeper. We can only get
   these by running AerolVM on Kubernetes. That is a separate effort, designed
   in `plans/kubernetes-full-architecture.md` on branch
   `plans/kubernetes-ceo-review` (PR #522). Section 6 lists them so that effort
   starts from a complete list.
2. **Product features that have nothing to do with Kubernetes.** File
   watching, a full file API in the SDKs, output limits on commands, an async
   Python client, framework adapters, restart on failure, warm-pool controls
   and more. We can build these now, on today's architecture. Section 5 lists
   every one with a decision.

The goal of this document is to **close on group 2**: agree on what we build,
in what order, and what we skip.

## 2. How we checked

- **agent-sandbox:** commit `4d39311` on `main` (2026-11-04). That is release
  v1.0.9 plus 46 later commits. All agent-sandbox paths below are relative to
  [that commit](https://github.com/kubernetes-sigs/agent-sandbox/tree/4d39311ba9d89001d79ff1217ed330c7ea3761ec).
  "main-only" means the feature landed after v1.0.9 and is not in a release
  yet.
- **AerolVM:** `main` at `e33b6e16`.
- **What we read:** sandboxd (the in-sandbox agent), sandbox-router, the
  controllers and API types, the Python, Go and TypeScript clients, the 6
  integration packages, about 80 examples, the docs, the roadmap and the 120
  open issues.
- **Live test** (kind cluster on a laptop, v1.0.9, 2026-11-04):
  - Taking a sandbox from a warm pool: **0.04–0.05 s**. Making one with the
    pool empty: **5.5 s**.
  - A streaming command through sandboxd ran for 6.5 minutes without trouble.
  - A buffered command through the router failed at **30 s**, because the
    router's `--response-header-timeout` defaults to 30 s.
  - Closing the stream killed the process. There is no way to reconnect.
- **"Missing" in the AerolVM column** means we searched the code and docs and
  found nothing. Appendix A lists the searches. A feature can still exist
  under a name we did not search for.

## 3. Fix first: AerolVM bugs found while comparing

We confirmed these by reading the code, not by running them. Step one of each
fix is to reproduce the bug in a test.

| ID | Bug | Evidence | Fix | Size |
|---|---|---|---|---|
| **B1** | **Daytona SDK file calls hit routes that do not exist.** Delete file, create folder, replace in files and set permissions return 404. So do the LSP calls. | `pkg/api/daytona/toolbox.go:92-99` forwards `DELETE /files`, `POST /files/folder`, `/files/replace` and `/files/permissions`. `lsp/*` is forwarded at `:116-120`. toolboxd has no handler for any of them (`cmd/toolboxd/main.go:503-527`), and its default case returns `404 not found`. The facade tests pass because they use a fake toolbox (`pkg/api/daytona/toolbox_proxy_test.go:113-115`). No live test or doc covers these calls. | Add the four handlers to toolboxd, reusing the envd `Remove`, `MakeDir` and `Move` code (`cmd/toolboxd/envd.go`). For `lsp/*`, either build it or return a clear 501. Add toolboxd tests and a live use case. | S |
| **B2** | **The `exec` timeout does not end the call.** If a command leaves a background child holding stdout, the call stays open past `timeout_seconds`. | `cmd/toolboxd/main.go:699-729` uses `exec.CommandContext` with no process group and no `WaitDelay`, and reads all output before it waits. `startTracked` (`cmd/toolboxd/child_table.go:135`) sets no `Setpgid`. On timeout Go kills only the shell. The docs half-admit it: "Background jobs make `exec` wait" (`docs/src/content/docs/exec-streaming.mdx:540`). | Start the command in its own process group. On timeout, kill the whole group. Set `cmd.WaitDelay` so draining output has an upper bound. Return `timed_out: true`. Ship with E1. | S |
| **B3** | **The docs promise E2B "watch a folder", but it returns 501.** | `docs/src/content/docs/using-e2b-sdk.mdx:99` says it works. `cmd/toolboxd/envd.go:383-390` answers all four watcher calls with 501. | Fix the doc now. F6 builds the real watcher. | S |

## 4. Decision summary

**Decisions:**
- **Build N:** build it in phase N (section 9).
- **Later:** worth doing, but not in this plan.
- **K8s:** park for the Kubernetes effort (section 6).
- **No:** don't build, with the reason given.

**Sizes:** S = up to 2 days, M = up to 1 week, L = more.

| ID | Feature | Size | Decision |
|---|---|---|---|
| B1 | Daytona file routes that 404 | S | **Build 0** |
| B2 | `exec` timeout that does not end the call | S | **Build 0** |
| B3 | E2B watch docs vs 501 | S | **Build 0** |
| F1 | File verbs in all 5 SDKs: list, info, delete, mkdir, move, copy | M | **Build 1** |
| F2 | Write options: append, create-only, file mode, atomic write | S | **Build 1** |
| F3 | Upload a folder as a tar and unpack it | S–M | **Build 1** |
| F4 | Download with Range and HEAD, streaming in every SDK, client size cap | S | **Build 1** |
| F5 | File watcher | M | **Build 1** |
| E1 | Server-side output caps, `truncated` and `timed_out` flags, operator limits | S–M | **Build 1** |
| E2 | Run a command as a list (no shell) in `exec` and `execStream` | S | **Build 1** |
| E3 | Report the signal that killed a command (and exit code 128+n) | S | **Build 1** |
| E4 | Close stdin from the SDKs | S | **Build 1** |
| E5 | Kill the whole process tree on gVisor (`/proc` scan fallback) | S | **Later** (check first) |
| E6 | Graceful toolboxd shutdown: `/health` returns 503, then SIGTERM, then SIGKILL | S | **Later** |
| E7 | In-sandbox metadata endpoint (env vars with secrets hidden) | S | **Later** |
| S1 | Async Python client | M | **Build 2** |
| S2 | Auto-cleanup: `with`, `await using`, `Close()`, AutoCloseable | S | **Build 2** |
| S3 | Typed errors in Python and TypeScript | S | **Build 2** |
| S4 | `get_or_create` by name in the SDKs | S | **Build 2** |
| S5 | Delete many sandboxes by tag | S | **Build 2** |
| S6 | Per-call timeouts in Python and TypeScript | S | **Build 2** |
| S7 | Custom CA, client certificate and extra headers in Python | S | **Build 2** |
| S8 | OpenTelemetry spans in the SDKs | M | **Later** |
| S9 | Latency as the client sees it | S | **Later** |
| L1 | Restart on failure, with backoff | S–M | **Build 2** |
| L2 | Why a sandbox stopped: status reasons | S–M | **Build 2** |
| L3 | Lifecycle event feed per sandbox | S | **Build 2** |
| L4 | Server-wide default destroy timer | S | **Build 2** |
| L5 | Destroy N seconds after the main program exits | S | **Build 2** |
| L6 | Destroy at a fixed clock time | S | **Build 2** |
| L7 | Keep a short record after destroy | S | **Later** |
| L8 | Stop that keeps memory (checkpoint/restore) | L | **Later** |
| I1 | Retry the dial to the in-sandbox agent | S | **Build 2** |
| I2 | gRPC (h2c) on HTTP port routes | S–M | **Later** |
| I3 | gRPC-Web and CORS for browser clients | M | **Later** |
| I4 | Body size cap on non-upload requests | S | **Later** |
| O1 | Lifecycle metrics, plus warm/cold and template labels | S | **Build 2** |
| O2 | `pprof` behind admin auth | S | **Build 2** |
| O3 | Publish a create-throughput benchmark | S | **Build 2** |
| T1 | Sandbox templates: named create defaults | M | **Build 3** |
| T2 | Template policies for env and volumes | S | **Build 3** |
| T3 | Operator create-policy file | S–M | **Build 3** |
| T4 | One flag to block private networks by default | S | **Build 3** |
| W1 | Warm-pool API: per-image depth and status | M | **Build 3** |
| W2 | Pool depth that follows demand, down to zero | S–M | **Build 3** |
| W3 | Rolling replace when a pool's image changes | S | **Build 3** |
| W4 | Set env when a warm sandbox is handed out, so env doesn't force a cold start | M | **Later** |
| V1 | `delete_with_sandbox` and size cap for platform volumes | S | **Build 3** |
| V2 | Attach storage when a warm sandbox is handed out | M | **Later** |
| D1 | A cloud identity per sandbox (OIDC token for AWS, Azure and GCP) | M–L | **Build 4** |
| A1 | Signed per-sandbox scoped tokens | M | **Build 4** |
| A2 | Share a port behind a sign-in (token, then cookie) | M | **Build 4** |
| A3 | Pass trace context into toolboxd | S | **Build 4** |
| P1 | Node labels and placement rules (zone, instance type) | M | **Build 4** |
| P2 | Per-team quotas | M | **Build 4** |
| P3 | Swap for density | S | **Later** |
| P4 | One URL in front of a group of sandboxes | M | **Later** |
| G1 | OpenAI Agents SDK provider | M | **Build 5** |
| G2 | LangChain DeepAgents backend | S | **Build 5** |
| G3 | OpenHands workspace | M | **Later** |
| G4 | Gymnasium environment for RL | S | **Build 5** |
| G5 | NeMo Gym (check whether the Daytona facade works first) | S | **Build 5** |
| G6 | Harbor / Terminal-Bench adapter | M | **Later** |
| G7 | RL batch runner | L | **Later** |
| G8 | Computer-use and browser template (desktop, Chrome DevTools, Playwright) | M | **Build 5** |
| G9 | Recipes for more coding-agent CLIs | S each | **Build 5** |
| G10 | VS Code (code-server) template | S | **Build 5** |
| G11 | Agent Client Protocol example | S | **Later** |
| G12 | Host an MCP server inside a sandbox | S–M | **Build 5** |
| G13 | WebMCP bridge | M | **No** for now |
| G14 | Token revoked when the program that used it exits | M | **Later** |
| R1 | Kata Containers runtime | L | **K8s** |
| R2 | Windows guest | L | **No** |
| R3 | Hyperlight and urunc runtimes | L | **No** |
| R4 | GPU with gVisor (`nvproxy`) | M | **Later** |

## 5. Feature catalogue

Each table answers four questions:
1. What does agent-sandbox have, and where?
2. What does AerolVM have today?
3. What exactly would we build?
4. What did we decide?

### 5.1 Files (F)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| F1 | **File verbs in the SDKs.** List a folder (with a depth limit), get info or check a file exists, delete (optionally recursive), make a folder, move (with an overwrite guard and a fallback when moving across filesystems), copy (recursive, keeping modes and links). Return 409 if a path is the wrong kind (file vs folder). | sandboxd `packages/sandboxd/pkg/server/filesystem.go`: list `:348-426`, recursive `:325-344` (#2101), delete `:899-970`, mkdir `:533-587` (#2097), move `:985-1105` and copy `:1122-1240` (#2118). Clients: Python `files/filesystem.py`; TS `files.ts:52-62` (#2140); Go `files.go:634-655` (#2156). Mostly main-only. | Our docs say: "There is no SDK call to list a folder" (`docs/src/content/docs/file-system.mdx:212`). The SDKs have only `upload_file` and `download_file`. The server half exists: toolboxd `/files`, `/files/info`, `/files/move`, `/files/search`, `/files/find` (`cmd/toolboxd/main.go:503-527`) and envd `ListDir`, `Stat`, `MakeDir`, `Move`, `Remove`. Only the Daytona and E2B facades use them. | Add `/v1/sandboxes/{id}/files/...` routes for list (`depth`, entry cap, never follow symlinks), info, delete (`recursive`), mkdir (`parents`, `mode`), move (`overwrite`) and copy. Add matching methods to all 5 SDKs, plus docs. Also expose search and find, which we already have. | M | **Build 1** |
| F2 | **Write options:** append, create only if missing (412 if it exists, safe under races), file mode, atomic write (temp file then rename). | `filesystem.go:428-530`, `:626-660` (#2112), `:706-740`; TS `types.ts:237-264` (#2151) | Upload creates parent folders. It is not atomic, has no mode (files land as root, `rw-r--r--`), has no append and no create-only (`cmd/toolboxd/main.go:924-932`). | Add `append`, `create_only`, `mode` and atomic replace to the upload route and the SDKs. | S | **Build 1** |
| F3 | **Upload a folder as a tar.** gzip detected, caps on entry count and size, hard links and escaping paths rejected. | `filesystem.go:755-897` (#2130, main-only) | The docs tell users to upload a tar and run `tar` through exec (`file-system.mdx:191-197`). | Add `extract=true` on upload, with the same caps, and `upload_dir(local, remote)` in the SDKs. | S–M | **Build 1** |
| F4 | **Download options:** Range and HEAD, streaming read and write in every SDK, a size cap on the client. | `filesystem.go:255-309` (`ServeContent`); Python `read_to`; TS `rest.ts:752,833`; Go `ReadTo`/`WriteReader`; Python `models.py:364` max download size | Downloads stream with Content-Length, but there is no Range and no HEAD (`cmd/toolboxd/main.go:794-832`). Only the Go SDK streams (`sdk/go/pkg/microvm/client.go:673-681`). No client cap. | Use `http.ServeContent` in toolboxd. Add streaming read and write plus `max_bytes` to the Python, TypeScript, Rust and Java SDKs. | S | **Build 1** |
| F5 | **File watcher.** A live stream of create, write, remove, rename and chmod events. Optional recursive mode that also watches new subfolders. Events batched every 250 ms, limit on watches at once, overflow reported. | `packages/sandboxd/spec/watcher/v1/watcher.proto:26-100`; `pkg/server/watcher.go:37-250`; Python `watcher/file_watcher.py:62`; Go `sandbox.go:759`. In v1.0.9. | **Missing.** All four envd watcher calls return 501 (`cmd/toolboxd/envd.go:383-390`). | An inotify watcher in toolboxd, streamed over WebSocket on `/v1/sandboxes/{id}/files/watch`. Wire the E2B `WatchDir` calls to it (fixes B3). `watch(path, recursive, on_event)` in all 5 SDKs. Firecracker and gVisor need a test of their own. WASM and isolate return a clear "not supported". | M | **Build 1** |
| — | Paths confined to a root folder | `packages/sandboxd/pkg/pathutil/sandbox.go:40-105` | Not done on purpose: the VM or container is the security boundary, and absolute paths are allowed. | Nothing | — | **No** |

### 5.2 Running commands (E)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| E1 | **Output limits.** Separate byte caps for stdout and stderr: keep the start, drain the rest, return `truncated` flags. A time limit separate from the request deadline, a `timed_out` reason, elapsed time. The operator sets default and maximum limits. | `ExecuteWithLimits` in `packages/sandboxd/spec/process/v1/process.proto:37-39,109-135`; `pkg/server/process.go:347-519`; operator policy `pkg/server/execution_policy.go:28-102` (#2117, main-only) | `timeout_seconds` (default 5 min) and `duration_ms` exist (`cmd/toolboxd/main.go:682-685`). There is no byte cap: `exec` holds all output in memory. Only the MCP/CLI client trims output (`internal/agenttools/exec.go:19-75`). | Add `max_stdout_bytes`, `max_stderr_bytes`, and `truncated` and `timed_out` in `ExecResult`. Add server settings for the default and maximum. Ship with B2. | S–M | **Build 1** |
| E2 | **Command as a list,** with no shell in between. | `process.proto:67-71` | `exec` and `execStream` always run through a shell (`cmd/toolboxd/main.go:699`; `exec_stream.go:128`). Sessions and envd already take a list. | Optional `argv` field next to `command`. | S | **Build 1** |
| E3 | **Which signal killed it.** Exit code 128+n when a signal ends the command. | `process.go:845-853` | Streams and sessions report `-1` plus the signal name. The buffered `ExecResult` has no signal field (`pkg/models/types.go:1406-1411`). | Add a `signal` field to `ExecResult`. Keep `exit_code` unchanged for compatibility, and document how it maps to 128+n. | S | **Build 1** |
| E4 | **Close stdin** (send end-of-input). | TS `commands.ts:250,283` | toolboxd supports it (`exec_stream.go:299-323`), but no SDK exposes it. | `close_stdin()` on stream handles in all 5 SDKs. | S | **Build 1** |
| E5 | **Kill the whole tree on gVisor,** by scanning `/proc` for children. | `process.go:743-825` (#1379) | On disconnect, toolboxd SIGKILLs the process group (`exec_stream.go:199-206`). Not checked whether that reaches grandchildren under gVisor. | Test first. Add the `/proc` scan only if the test fails. | S | **Later** |
| E6 | **Graceful shutdown.** `/health` returns 503, children get SIGTERM, then SIGKILL after 2 s. | `packages/sandboxd/cmd/sandboxd/main.go:246-256` | The signal is forwarded and shutdown takes 10 s (`cmd/toolboxd/main.go:380-393`). `/health` never returns 503. | Return 503 while draining. | S | **Later** |
| E7 | **Metadata endpoint.** Env vars with a chosen prefix; names with TOKEN, SECRET or KEY hidden. | `pkg/server/metadata.go:30-69` | Missing | Small, but low value. | S | **Later** |

### 5.3 SDK experience (S)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| S1 | **Async Python client** | `async_sandbox_client.py:110` (`[async]` extra) | Missing. The Python SDK is sync only. | `AsyncMicroVM` built on `httpx` or `aiohttp`, with the same methods as the sync client. Share the request-building code so the two can't drift. | M | **Build 2** |
| S2 | **Auto-cleanup.** A `with` block, `async with`, delete-on-exit, TypeScript `asyncDispose`. | Python `sandbox_client.py:61,114,212`; TS `sandbox-client.ts:1203,1290`; Go `client.go:310` | Missing | Python `with`/`async with`, TypeScript `await using`, a Go helper, Java `AutoCloseable`, Rust guard. Opt-in delete-on-exit. | S | **Build 2** |
| S3 | **Typed errors** | Python `exceptions.py:18-82` (11 classes); TS `exceptions.ts:29-183` | Go has `ErrNotFound` and `ErrConflict`. Python and TypeScript have one HTTP error type carrying the status. | `NotFoundError`, `ConflictError`, `CapacityError` (503), `TimeoutError`, `AuthError`. Subclasses of today's error type, so existing code keeps working. | S | **Build 2** |
| S4 | **Get or create by name** | `claim_adoption.py:43` | Names are unique and `get_by_name` exists, but users write the recipe themselves (`sandboxes.mdx:194-245`). Only the CLI/MCP has it (`internal/agenttools/create.go:81`). | `get_or_create(name, ...)` in all 5 SDKs, reusing the CLI logic. | S | **Build 2** |
| S5 | **Delete many at once** | Python `delete_all` | List and paging only | `destroy_all(tags=...)` that lists by tag and deletes, idempotently. | S | **Build 2** |
| S6 | **Per-call timeouts** | `timeout=` on every Python method | Go uses `ctx`. TypeScript has one client-wide `AbortSignal`. Python has none. | A per-call `timeout` in Python and a per-call `signal` in TypeScript. | S | **Build 2** |
| S7 | **Custom CA, client certificate and extra headers** | Python `models.py:223-228` | Go and TypeScript accept a custom HTTP client. Python calls `urlopen` with no hook (`client.py:1439`). | `ca_file`, `client_cert`, `headers` options in Python. Banks behind TLS-inspecting proxies need this. | S | **Build 2** |
| S8 | **OpenTelemetry spans in the SDKs** | Python `trace_manager.py`; TS `types.ts:29`; Go `options.go:307` | The server traces; the SDKs don't. | Optional spans plus `traceparent` sent from the SDKs. | M | **Later** |
| S9 | **Latency as the client sees it** | Python `metrics.py`; `examples/webhook-inject-timestamp` | Server-Timing headers only | The SDK sends its send time and the server records it. | S | **Later** |

### 5.4 Lifecycle (L)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| L1 | **Restart on failure,** with backoff from 5 s to 5 min, reset after 10 minutes of running fine. | `failedPodPolicy: Recreate`, `api/v1beta1/sandbox_types.go:258-332`; `controllers/sandbox_controller.go:2460-2581` | **Missing.** A crash marks the sandbox `stopped` (`internal/service/events.go`, `markSandboxStopped`). Only serverless wake starts it again. | `lifecycle.restartOnFailure` with the same backoff, in the die-event path. Off by default. It must not fight the idle-stop timer or a user's stop. | S–M | **Build 2** |
| L2 | **Why it stopped.** Status reasons such as idle, out of memory, disk limit, expired, program exited, crashed. | Ready, PodScheduled and Finished conditions with reasons, `sandbox_types.go:41-175` | One status value (`pkg/models/types.go:26-39`) plus `last_error`. No reason code. | A `status_reason` field (plus `exit_code` for an exit), set on every stop path, in all 5 SDKs. | S–M | **Build 2** |
| L3 | **Lifecycle event feed.** Created, ready, stopped (with reason), restarted, expired, deleted. | Kubernetes events: `controllers/sandbox_controller.go:78-80,1084-1099` | The audit log has system callers for lifecycle, wake, failover and reconcile (`internal/service/audit_caller.go:18-33`), readable at `GET /v1/sandboxes/{id}/audit`. Not checked that it covers every automatic stop or delete. | Check audit coverage of every automatic stop and delete. Then add a filtered "lifecycle events" view, or document the audit query. | S | **Build 2** |
| L4 | **Server-wide default destroy timer,** so a crashed client can't leak sandboxes forever. agent-sandbox has the opposite problem (#2051). | None | `SB_IDLE_TIMEOUT_MIN` sets a default idle **stop** (`lifecycle.mdx:151`). There is no default destroy. | `SB_DEFAULT_DESTROY_IF_IDLE_FOR` and `SB_MAX_AGE`, applied when a create sets nothing. | S | **Build 2** |
| L5 | **Destroy after the program exits.** | `ttlSecondsAfterFinished`, `extensions/api/v1beta1/sandboxclaim_types.go:72-77` | An exit just becomes `stopped`. Cleanup waits for `destroyIfIdleFor`. | `lifecycle.destroyAfterExitFor`. | S | **Build 2** |
| L6 | **Destroy at a fixed clock time.** | `shutdownTime`, `sandbox_types.go:368-400` | Durations only: `destroyAtAge` and `stopAtAge` (`pkg/models/types.go:362-366`). | Accept an RFC 3339 `destroyAt` and convert it to an age. | S | **Build 2** |
| L7 | **Keep a short record after destroy,** with the reason. | `shutdownPolicy: Retain`, `sandbox_types.go:386-400` | A destroy deletes the row. Only the audit log keeps a trace. | Optional, time-limited records of destroyed sandboxes. | S | **Later** |
| L8 | **Stop that keeps memory.** The sandbox resumes with its programs still running. Also makes "golden" warm pools possible (L8 + W1). | GKE Pod Snapshots only, including GPU: `site/content/docs/sandbox/snapshots`; `examples/podsnapshot-golden-warmpool`; `examples/gpu-l4-snapshot-sandbox` (#2147) | Snapshots save files, not memory (`images-and-snapshots.mdx`, "What a snapshot keeps"). WASM passivation keeps memory. The Firecracker template has a memory snapshot only at boot. | `runsc checkpoint/restore` for gVisor, and Firecracker snapshot/load on stop and start. Big; needs its own plan. | L | **Later** |

**AerolVM is already ahead here.** We have idle stop and destroy driven by
real activity, plus wake on traffic. agent-sandbox has only fixed deadlines.
Idle cleanup and scale-to-zero are still "Planned" on its roadmap.

### 5.5 Ingress and proxy (I)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| I1 | **Retry the dial** to the in-sandbox agent (3 tries, 200 to 800 ms). | `sandbox-router/proxy/retry.go:44-140` | No retry in the toolbox proxy (we do have wake on request, `internal/service/toolbox_proxy.go:62`). | Retry connection-refused errors only, never a request that was already sent. | S | **Build 2** |
| I2 | **gRPC on HTTP routes** (h2c to the sandbox). | `sandbox-router/proxy/grpc.go:33-303` | Only through TCP/TLS ports (`tcp-ports.mdx:8`). | h2c upstream in Caddy for ports marked as gRPC. | S–M | **Later** |
| I3 | **gRPC-Web and CORS** for browser clients. | `sandbox-router/proxy/grpcweb.go:106-394` (#2143, main-only) | Missing | Only if a customer asks. | M | **Later** |
| I4 | **Request body cap** on non-upload routes. | `--max-request-body-bytes` | Upload cap only (`cmd/toolboxd/main.go:755`) | A server setting. | S | **Later** |

Not copied: the router's 30 s response-header timeout and 180 s total timeout.
That is the timeout that killed buffered commands in our live test.

### 5.6 Templates and policy (T)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| T1 | **Sandbox templates.** A named set of create defaults: image, runtime, size, lifecycle, egress profile, env, volumes. | `SandboxTemplate`, `extensions/api/v1beta1/sandboxtemplate_types.go:99-160` | Snapshots carry image, user and size hints. Firecracker templates are disk images only. Egress profiles are named policies. Nothing bundles all the create defaults. | `/v1/sandbox-templates` and `create(template="name", ...)`, where explicit fields win. Stored in the cluster FSM so every server sees them. In all 5 SDKs. | M | **Build 3** |
| T2 | **Template policies:** whether a caller may set or override env vars, and whether they may add volumes. | `envVarsInjectionPolicy` and `volumeClaimTemplatesPolicy`, `sandboxtemplate_types.go:33-80,136-158` | Missing. Any caller can set any env var. | `env_policy: disallowed\|allowed\|overrides` and `volumes_policy` on templates. Lets a bank lock one approved template. | S | **Build 3** |
| T3 | **Operator create-policy file.** Allowed registries and images, allowed runtimes, maximum size, non-root required, GPU allowed. | Admission policies: `examples/policy/*`, secure-sandbox-vap docs | Only `SB_HOST_RUNTIMES`. Hardening is built in, but an operator can't limit images, runtimes or sizes. | `SB_CREATE_POLICY_FILE` checked at create, the same way the egress operator file works, with a clear 403 reason. | S–M | **Build 3** |
| T4 | **Block private networks by default.** | The default NetworkPolicy blocks RFC 1918, 169.254/16, fc00::/7 and fe80::/10 (`extensions/controllers/sandboxtemplate_controller.go:192-256`). | With no policy set, container, gVisor and Firecracker sandboxes can reach private addresses (`engineering-network-defenses.mdx`, "Default posture"). Metadata addresses are always blocked. Operators can already add blocked ranges in the operator file. | One flag, `SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT`. Decide later whether to make it the default. | S | **Build 3** |

### 5.7 Warm pools (W)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| W1 | **Warm pools as an API object.** Depth per image or template, with status (ready, target). | `SandboxWarmPool`, `extensions/api/v1beta1/sandboxwarmpool_types.go:40-124` | Pools are set per server by env vars, one depth for every image (`SB_DOCKER_POOL_*`, `internal/config/config.go:2091-2096`). Status shows only in `/v1/capacity`. No pool route. | `/v1/warm-pools` with per-image or per-template depth, stored in the cluster FSM, with status per server and in total. Admin only. | M | **Build 3** |
| W2 | **Depth that follows demand,** down to zero. | KEDA and HPA examples: `examples/keda-scale-to-zero`, `examples/hpa-swp-scaling` | Targets are added on misses and dropped after an idle time (`internal/pool/dockerpool/pool.go:121,137`), but the depth doesn't follow demand. | Depth set from a moving average of recent hits and misses, between a minimum and maximum. | S–M | **Build 3** |
| W3 | **Rolling replace when the image changes.** | `updateStrategy` OnReplenish/Recreate, `sandboxwarmpool_types.go:62-89` | Warm slots with an outdated image are pruned (`pool.go:255`). | Expose it on the pool API: replace now, or replace as used. | S | **Build 3** |
| W4 | **Env does not force a cold start.** Set env when the warm sandbox is handed out. | agent-sandbox can't do this either: env forces a cold start (`sandboxclaim_types.go`, `env` comment). | Env, mounts, volumes, a non-root user and more force a cold start (`pkg/docker/docker_pool.go:86-115`). | Hand env to toolboxd at adopt time, so commands see it. It is not process env for PID 1. Touches the boot path (`/touch-create-sandbox`). | M | **Later** |

### 5.8 Storage (V)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| V1 | **A volume that goes with its sandbox,** with a size cap. | `volumeClaimTemplates`: a disk per sandbox, kept while suspended, deleted with the sandbox (`api/v1beta1/sandbox_types.go:296-309`) | The sandbox's own disk survives a stop. Platform volumes are never deleted with a sandbox and have no size cap (`platform-volumes.mdx:115-166`). | `delete_with_sandbox: true` and `max_bytes` on platform volumes. | S | **Build 3** |
| V2 | **Attach storage when a warm sandbox is handed out.** | `examples/latebind-storage-gke-sandbox`; roadmap "Storage Customization at Claim Time" is Planned. | Mounts force a cold start. | Not checked whether this is feasible. | M | **Later** |

### 5.9 Identity, access and placement (D, A, P)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| D1 | **A cloud identity per sandbox.** Code inside gets short-lived AWS, Azure or GCP credentials for its own role, with no stored secret. **The most important item for banks.** | Through Kubernetes: a service account per pod, plus IRSA or Workload Identity (`examples/sandbox-ksa`, `examples/irsa-simulation-localstack`). "Identity at claim time" is still Planned on its roadmap. | Missing. A per-sandbox toolbox token exists, and egress can inject credentials (`pkg/models/types.go:695-700`), but nothing gives a sandbox its own cloud identity. | AerolVM acts as an OIDC issuer. Each sandbox gets a short-lived signed token (subject = team and sandbox, optional role tag) as a file that is refreshed before it expires. The customer's IAM trusts our issuer and maps it to a role, through `AssumeRoleWithWebIdentity`, Azure federated credentials or GCP Workload Identity Federation. This is how IRSA works. Needs its own design doc and a security review. | M–L | **Build 4** |
| A1 | **Signed per-sandbox scoped tokens.** A token you can hand to a browser or an end user. It works only for one sandbox, port, path and method, expires, and can be checked without a database call. | v1 HMAC and v2 Ed25519, bound to the sandbox and the request: `sandbox-router/authz/scopedtoken.go:115,240-331`, `scopedtoken_v2.go:56` | Personal access tokens carry role, team and expiry (`pkg/models/tokens.go`), but nothing scoped to one sandbox or path. | Ed25519 tokens with key IDs and rotation, issued by `/v1/sandboxes/{id}/tokens`, checked at ingress and the toolbox proxy. | M | **Build 4** |
| A2 | **Share a port behind a sign-in.** `?token=` sets an HttpOnly cookie for that sandbox, then a 302 strips the token from the URL. | `sandbox-router/proxy/browsersession.go:33-80` (#1446) | A public URL is either open to anyone (`public-urls.mdx:10`) or not exposed. The Daytona preview token is `""` (`pkg/api/daytona/handlers.go:723-727`). | A `visibility: token` option on expose, using A1 tokens, in Caddy or the ingress proxy. | M | **Build 4** |
| A3 | **Trace context into the sandbox agent.** | The router forwards W3C trace context (`sandbox-router/observability/tracing.go`) | API spans exist (`pkg/api/middleware.go:70-73`). None reach toolboxd. | Forward `traceparent`, and add simple toolboxd spans. | S | **Build 4** |
| P1 | **Placement rules.** Run this sandbox in zone X, on instance type Y, on nodes with label Z. | Full pod scheduling: nodeSelector, affinity, tolerations | Placement filters on runtime, GPU, capacity and artifact affinity (`internal/cluster/placement.go:95-160,365`). No node labels and no zones. | Node labels in gossip, plus a `placement` field on create (labels and zone). Cluster code: needs regression tests and a cluster-correctness call-out. | M | **Build 4** |
| P2 | **Per-team quotas.** Maximum sandboxes, CPU and memory per team. Optional queue. | Kueue example (`examples/kueue-agent-sandbox`) | Admission per server only, with 503 and Retry-After (`pkg/capacity/capacity.go:50-75`). The control-plane admission hook is a no-op in open source (`pkg/controlplane/controlplane.go:26`). | Quotas per team, stored in the FSM, checked at create, with a clear 429. A queue is out of scope. | M | **Build 4** |
| P3 | **Swap for density.** | `examples/gke-swap` | Swap equals the memory limit, so it is off (`pkg/docker/client.go:691`). | An opt-in setting. | S | **Later** |
| P4 | **One URL for a group of sandboxes.** | `examples/claimed-sandbox-service` | Missing | Load balancing across sandboxes with a tag. | M | **Later** |

### 5.10 Observability (O)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| O1 | **Lifecycle metrics:** expired, finished, stop and start counters; warm vs cold and template labels on create latency. | 14 metrics, `internal/metrics/metrics.go:87-306` | Create latency, per-stage latency, wake, OOM, disk-limit and pool metrics, plus 72 alert rules and 12 Grafana dashboards. The counters and labels named here are missing. | Add the counters and labels, plus a dashboard panel. | S | **Build 2** |
| O2 | **`pprof`** | `cmd/agent-sandbox-controller/main.go:107-122` | Missing (no `net/http/pprof`) | Admin-only, off by default. | S | **Build 2** |
| O3 | **A published throughput benchmark** (creates per second at p50, p90 and p99). | `docs/performance-tuning.md:42,168-173`: about 300 claims/s at p90 ≤ 200 ms; 45/s sustained at p50 92 ms | We have latency numbers but no published creates-per-second figure. | A repeatable load test plus a docs page. | S | **Build 2** |

### 5.11 Integrations and use cases (G)

None of their integration packages are on PyPI; users install them from git
(`clients/integrations/README.md`).

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| G1 | **OpenAI Agents SDK provider** (theirs is marked "Prototype"). | `clients/integrations/openai/` | Missing | An `aerolvm-openai-agents` package. It saves and restores the workspace with our snapshots. | M | **Build 5** |
| G2 | **LangChain DeepAgents backend** | `clients/integrations/deepagents/` (execute, upload, download) | Missing | A small adapter package. | S | **Build 5** |
| G3 | **OpenHands workspace** | `clients/integrations/openhands/` | Missing | Adapter. | M | **Later** |
| G4 | **Gymnasium environment for RL.** A fresh sandbox per episode, shell commands as actions, pluggable reward. | `clients/integrations/gymnasium/` | Missing | An `aerolvm-gymnasium` package. Our fast creates and snapshots fit RL well. | S | **Build 5** |
| G5 | **NVIDIA NeMo Gym** | `clients/integrations/nemo-gym/` | Missing. NeMo Gym ships a Daytona provider, so our `/daytona` facade may already work. | Test the Daytona path first. Write a provider only if it fails. | S | **Build 5** |
| G6 | **Harbor / Terminal-Bench** | `examples/harbor-terminal-bench` (#2126; the package it refers to is missing at `4d39311`) | Missing | Adapter. | M | **Later** |
| G7 | **RL batch runner.** One sandbox per task, many clusters. | `examples/agent-sandbox-rl` | Missing | — | L | **Later** |
| G8 | **Computer use and browser automation.** A desktop image (Xvfb, VNC, Chrome with DevTools on 9222, Playwright), plus an `agent(query)` helper. | Python `extensions/computer_use.py:22`; `examples/{gemini-cu-sandbox,chrome-sandbox,playwright-sandbox,aio-sandbox}`; docs `runtime-templates/computer-use` | Closest is a tutorial where a person drives Chromium over noVNC (`use-cases/customer-facing-product-experiences/secure-burner-browser.mdx`). No DevTools or Playwright guide. | A ready-made image (a template, once T1 lands) and a docs page with five-language examples. | M | **Build 5** |
| G9 | **More coding-agent recipes:** OpenCode, Aider, Gemini CLI, Codex CLI and others. | `examples/{opencode,aider,pi-code-agent,hermes-agent,openclaw-*}` | Five coding-agent docs centred on Claude Code (e.g. `use-cases/coding-agents/large-scale-refactor-migration-agent.mdx`). | One recipe page per agent, using sessions so long runs survive a disconnect. | S each | **Build 5** |
| G10 | **VS Code in the browser** (code-server) | `examples/vscode-sandbox` | Missing | Template plus docs. A2 makes it private to one user. | S | **Build 5** |
| G11 | **Agent Client Protocol example** | `examples/agentclientprotocol` | Missing. The building blocks exist (exec stream with stdin). | Example. | S | **Later** |
| G12 | **Host an MCP server inside a sandbox** | `examples/mcp-server-sandbox`, `n8n-mcp` | Missing as a doc. The E2B `mcp` create option returns 501 (`using-e2b-sdk.mdx:116`). | A docs recipe, and support for the E2B `mcp` option. | S–M | **Build 5** |
| G13 | **WebMCP bridge** | `examples/webmcp-bridge-sandbox` | Missing | Too early; the WebMCP proposal is not settled. | M | **No** for now |
| G14 | **Token revoked when its program exits** | `examples/containarium-execution-scoped-token` | Egress inject rules already keep real keys out of the sandbox (`secret-env-architecture.mdx`). | Revisit after A1 and D1. | M | **Later** |

**Already covered** (no work needed):
- **Headless Claude Code:** five coding-agent docs.
- **JupyterLab:** `use-cases/data-processing-ml/headless-jupyter-notebook.mdx`.
- **One long-lived sandbox per user that sleeps when idle:** `one-click-user-sandbox.mdx` plus `stopIfIdleFor` and `serverless`.
- **E2B envd inside the sandbox:** built into toolboxd.
- **MCP server for the platform:** ours has OAuth, toolsets and read-only mode. Theirs "does not have built-in authentication".

### 5.12 Runtimes (R)

| ID | Feature | agent-sandbox | AerolVM today | Decision |
|---|---|---|---|---|
| R1 | Kata Containers (QEMU, Cloud Hypervisor, Firecracker) | Any RuntimeClass; `examples/kata-*` | `"kata"` is reserved and rejected at create (`pkg/models/types.go:82`). | **K8s**. In a Kubernetes mode we get it through RuntimeClass. |
| R2 | Windows guest (QEMU in a pod, needs `/dev/kvm`) | `examples/windows-sandbox` | Missing | **No.** It needs KVM on the node, which standard EKS and AKS instances don't offer. |
| R3 | Hyperlight, urunc | `examples/hyperlight-sandbox` (#2119), `examples/urunc-sandbox` | Missing | **No.** Niche. Our Firecracker, WASM and V8 isolate runtimes cover these needs. |
| R4 | GPU with gVisor | GKE Sandbox with an L4 GPU (`examples/gpu-l4-snapshot-sandbox`) | GPU is Docker only. GPU with gVisor fails at create (`gpu-sandboxes.mdx`). | **Later.** Try `runsc --nvproxy` in a spike. |

## 6. Deferred to the Kubernetes effort (K)

These only make sense when a sandbox is a Kubernetes pod. They are recorded
here so the Kubernetes design starts from a complete list. They are not part
of this plan.

| Feature | agent-sandbox evidence |
|---|---|
| Install as Kubernetes resources, with Helm, OLM, kustomize and GitOps | `helm/`, `olm/`, `k8s/` |
| Any pod setting: sidecars, init containers, security context | `podTemplate`, `api/v1beta1/sandbox_types.go:292` |
| A Kubernetes service account per sandbox, plus IRSA or Workload Identity. Our non-Kubernetes version is D1. | `examples/sandbox-ksa`, `examples/irsa-simulation-localstack` |
| RuntimeClass (Kata, gVisor, Hyperlight, urunc) | `examples/kata-*`, `examples/urunc-sandbox` |
| Kueue admission and API Priority and Fairness | `examples/kueue-agent-sandbox`, `examples/apf-insulation` |
| PodDisruptionBudgets | `examples/manual-pdb` |
| Cluster-autoscaler eviction hints on warm pods | `extensions/controllers/sandboxwarmpool_controller.go:59,1196` |
| Managed NetworkPolicy, Cilium and Network Policy API egress | `examples/demo-cilium-egress`, `examples/network-policy-api-sandbox` |
| TokenReview auth at the router | `sandbox-router/authz/tokenreview.go:121-257` |
| Claim objects, conditions and events, read with kubectl | `extensions/api/v1beta1/sandboxclaim_types.go` |
| Namespace-scoped RBAC (#1440, open) | `helm/templates/rbac.generated.yaml` |
| KEDA and HPA on warm pools. Our non-Kubernetes version is W2. | `examples/keda-scale-to-zero`, `examples/hpa-swp-scaling` |
| GKE Pod Snapshots. Our non-Kubernetes version is L8. | `site/content/docs/sandbox/snapshots` |
| Multi-cluster fleet | `examples/multi-cluster-fleet` |
| CRD versioning and upgrades | `docs/api-migration-guide.md` |
| Pod-IP routing cache in the router | `sandbox-router/cache/cache.go` |

## 7. Things we will not copy

| agent-sandbox behaviour | Why not |
|---|---|
| Fixed-deadline expiry only | Ours follows real activity. Section 5.4 adds the fixed-deadline options as well. |
| A command is killed when its stream closes, and you can't reconnect (#2061) | Our sessions survive a disconnect, with attach and replay. |
| The router strips the `Authorization` header, so in-sandbox auth can't be used through it (#2102) | Our proxy swaps in the sandbox's own token (`internal/service/toolbox_proxy.go:105-121`). |
| No default expiry, so claims leak when a client crashes (#2051) | L4 adds a server-wide default. |
| A 30 s response-header timeout on the router | It breaks long buffered commands. We keep a dead-peer timeout instead. |
| Paths confined to a root folder | The VM or container is our boundary. Agents need absolute paths. |
| Default router auth "AllowAll" | We fail closed. |

## 8. What AerolVM already has that agent-sandbox lacks

Keep these, don't regress them, and use them in comparisons:

- **Sessions** that survive a disconnect, with several clients attached at once, replay and recordings.
- **Idle stop and destroy** driven by real activity, and **wake on traffic** (serverless).
- **Egress controls:** domain allow lists, learn mode, live policy changes, named profiles, byte quotas, credential injection, and metadata addresses always blocked.
- **Tamper-evident audit log** with an S3 witness, **key custody**, **SSO and roles**, team-scoped tokens.
- **Public URLs**, custom domains, TCP/TLS ports and SSH.
- **Snapshots on any cloud** and any runtime, not only GKE.
- **Failover** to another server, using the replicated spec and sealed secrets.
- **Five runtimes** (Docker, containerd, gVisor, Firecracker, WASM) plus V8 isolates.
- **Five published SDKs** (their TypeScript client is `"private": true`), a **CLI**, and an **MCP server** with OAuth.
- **Drop-in Daytona, E2B and Runloop facades.**
- **A dashboard.** Theirs is "Planned".
- **72 alert rules and 12 dashboards.** They have one alert.
- **A process reaper** in the in-sandbox agent. Theirs leaves zombies (#1980).

## 9. Phases

Each phase is a stack of pull requests, one per feature. Nothing in a stack
merges until the whole stack is done and green. SDK releases move by patch
version only (0.8.1 → 0.8.2).

| Phase | Theme | Items | Why this order |
|---|---|---|---|
| **0** | Fix what's broken | B1, B2, B3 | Small and already broken for users. |
| **1** | Files and commands | F1–F5, E1–E4 | The most visible gap. The server half mostly exists already. B2 and E1 share code. |
| **2** | SDK and lifecycle quick wins | S1–S7, L1–L6, I1, O1–O3 | Many small items with a big effect on day-to-day use. L4 also closes the "leaked sandbox" class of problem. |
| **3** | Templates, pools, policy, storage | T1–T4, W1–W3, V1 | Lets a bank lock down one approved template. T1 comes first, since T2, W1 and G8 build on it. |
| **4** | Identity, access, placement | D1, A1–A3, P1, P2 | The bank asks: per-sandbox cloud identity, private shared URLs, zones, quotas. D1 and P1 need their own design docs and reviews. |
| **5** | Integrations and use cases | G1, G2, G4, G5, G8, G9, G10, G12 | Adoption work. It builds on the file API, templates and tokens from earlier phases. |

Phases 0–2 are mostly independent within a phase and can run in parallel
worktrees.

## 10. Rules every PR in this plan follows

- **New `/v1` route:** use `/add-v1-endpoint`. Every route must be idempotent under retries and concurrent duplicate calls (`pr-review.md`).
- **New SDK method:** use `/add-sdk-method`, so all 5 SDKs change together, with a docs example in five-language tabs.
- **New docs page:** use `/add-docs-page`. No raw HTTP or `curl` examples.
- **Anything on the create path** (W4, T1, T3, P1, P2, D1): use `/touch-create-sandbox`, and state the boot-latency impact in the PR, including the first call.
- **Cluster code** (T1, W1, P1, P2 store state in the FSM or change placement): regression tests next to the changed file, plus a cluster-correctness call-out. Single-node mode must keep working.
- **Coverage:** every touched Go package stays at or above about 85% (`/maintain-coverage`).
- **Live behaviour** that mocks can't prove (F5 on Firecracker and gVisor, L1, D1) gets an integration use case.

## 11. Decisions (closed 2026-11-05)

These were the open choices before Phase 1. All eight were closed on
2026-11-05 with the recommended answer. If one changes later, update this
table and note the date.

| # | Question | Decision |
|---|---|---|
| Q1 | Is the phase order right? | Yes: bugs, then files and commands, then SDK and lifecycle, then templates, then identity, then integrations. |
| Q2 | D1 (cloud identity per sandbox): which cloud first? | AWS (`AssumeRoleWithWebIdentity`), because that's the bank target. Azure next. |
| Q3 | A2 (port behind a sign-in): a per-port option, or the default for new ports? | A per-port option, `visibility: public\|token`. Public stays the default for now. |
| Q4 | T4 (block private networks): only a flag, or the new default? | Ship the flag. Decide on the default in a later release, with a changelog note. |
| Q5 | L1 (restart on failure): on or off by default? | Off. Opt in per sandbox. |
| Q6 | Which framework adapters matter to customers? | G1 (OpenAI Agents) and G4 (Gymnasium) first. Ask customers before G3, G6 and G7. |
| Q7 | Where do adapter packages live? | In this repo under `integrations/`, published to PyPI and npm. Unlike agent-sandbox, which doesn't publish them. |
| Q8 | F5 (file watcher) on WASM and V8 isolates? | Not supported. Return a clear error. |

## 12. Definition of done

- Every **Build** item is merged, with tests, docs, and 5-SDK support where it applies.
- B1–B3 each have a test that failed before the fix.
- The comparison page (`aerolvm-vs-daytona-vs-e2b.mdx`, or a new one) gains an agent-sandbox column.
- This plan is updated with the outcome of each phase and with every decision changed along the way.

---

## Appendix A: searches behind "Missing"

All searches were run against AerolVM `main` at `e33b6e16`, across `cmd/`,
`internal/`, `pkg/`, `sdk/` and `docs/src/content/docs/`, case-insensitive
unless noted.

| Feature | Search terms | Hits |
|---|---|---|
| File watcher | `WatchDir`, `fsnotify`, `inotify`, `watch_dir` | `cmd/toolboxd/envd.go` only (returns 501) |
| Async Python | `AsyncSandbox`, `async def`, `asyncio` in `sdk/python` | none |
| Framework adapters | `langchain`, `langgraph`, `deepagents`, `openai-agents`, `SandboxAgent`, `crewai`, `gymnasium`, `gym.Env`, `nemo`, `openhands`, `harbor`, `terminal-bench`, `swe-bench` | none |
| Auto-cleanup | `__enter__`, `AutoCloseable`, `impl Drop`, `asyncDispose`, `atexit` in `sdk/` | one Java test |
| Client tracing | `opentelemetry`, `traceparent` in `sdk/` | none |
| Output caps | `truncat`, `OutputLimit`, `MaxOutput`, `stdout_limit`, `LimitReader` in `cmd/toolboxd`, `pkg/models` | client-side only (`internal/agenttools`) |
| Append / create-only | `O_APPEND`, `"append"`, `If-None-Match` in `cmd/toolboxd` | none |
| Restart on failure | `RestartPolicy`, `restart_policy`, `unless-stopped`, `on-failure`, `crash.?loop`, `backoff` in `pkg/docker`, `internal/runtime`, `internal/service`, `pkg/models` | none |
| Placement rules | `NodeSelector`, `PlacementConstraint`, `MemberLabels`, `zone` in `internal/cluster` | none |
| Cloud identity | `AssumeRole`, `role_arn`, `web identity`, `SPIFFE`, `IRSA`, `workload identity` | only KMS and S3-mount credentials, not per-sandbox identity |
| Templates (bundled create defaults) | `blueprint`, `SandboxPreset`, `SandboxProfile` | only the Runloop facade's image map |
| `pprof` | `net/http/pprof` | none |
| Browser automation docs | `9222`, `devtools protocol`, `cdp`, `puppeteer`, `playwright` | none |

## Appendix B: sources

- agent-sandbox code at [`4d39311`](https://github.com/kubernetes-sigs/agent-sandbox/tree/4d39311ba9d89001d79ff1217ed330c7ea3761ec), release [v1.0.9](https://github.com/kubernetes-sigs/agent-sandbox/releases/tag/v1.0.9), [`roadmap.md`](https://github.com/kubernetes-sigs/agent-sandbox/blob/4d39311ba9d89001d79ff1217ed330c7ea3761ec/roadmap.md).
- agent-sandbox issues read in full:
  - [#2061](https://github.com/kubernetes-sigs/agent-sandbox/issues/2061): processes die with the stream.
  - [#1889](https://github.com/kubernetes-sigs/agent-sandbox/issues/1889): SDK access through the router.
  - [#2102](https://github.com/kubernetes-sigs/agent-sandbox/issues/2102): router strips Authorization.
  - [#1440](https://github.com/kubernetes-sigs/agent-sandbox/issues/1440): cluster-wide RBAC.
  - [#2051](https://github.com/kubernetes-sigs/agent-sandbox/issues/2051): leaked claims.
  - [#1980](https://github.com/kubernetes-sigs/agent-sandbox/issues/1980): zombie processes.
  - [#2152](https://github.com/kubernetes-sigs/agent-sandbox/issues/2152): v1 token lifetime.
  - [#818](https://github.com/kubernetes-sigs/agent-sandbox/issues/818): L7 egress.
  - [#643](https://github.com/kubernetes-sigs/agent-sandbox/issues/643): per-sandbox network policy.
- Related AerolVM plans on branch `plans/kubernetes-ceo-review` (PR #522): `plans/kubernetes-explained.md`, `plans/kubernetes-full-architecture.md`, `plans/kubernetes-cockroachdb-parallels.md`.
