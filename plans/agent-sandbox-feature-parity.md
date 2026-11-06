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
| **B1** | **Daytona SDK file calls hit routes that do not exist.** Delete file, create folder, replace in files and set permissions return 404. So do the LSP calls. | `pkg/api/daytona/toolbox.go:92-99` forwards `DELETE /files`, `POST /files/folder`, `/files/replace` and `/files/permissions`. `lsp/*` is forwarded at `:116-120`. toolboxd has no handler for any of them (`cmd/toolboxd/main.go:503-527`), and its default case returns `404 not found`. The facade tests pass because they use a fake toolbox (`pkg/api/daytona/toolbox_proxy_test.go:113-115`). The docs already list these calls as "Not supported (HTTP 404)" (`using-daytona-sdk.mdx:102`); no live test covers them. | Add the four handlers to toolboxd, reusing the envd `Remove`, `MakeDir` and `Move` code (`cmd/toolboxd/envd.go`). Change `using-daytona-sdk.mdx:102` from "Not supported (HTTP 404)" to "Works (not on WASM sandboxes)", and have the WASM toolhost answer those routes and `process/pty` with a clear 501 instead of its default 404 (`internal/runtime/wasm/toolhost/host.go:56-120`). For `lsp/*`, toolboxd itself returns a clear 501 ("language servers are not supported"), and `using-daytona-sdk.mdx:104` changes from "HTTP 404" to "HTTP 501" (CEO review R5). Until E8 lands, toolboxd also returns 501 for `process/pty` and `process/pty/*`, and `using-daytona-sdk.mdx:103` says "HTTP 501" (CEO review R7). Add toolboxd tests and a live use case. Also add an offline inventory test: every path the Daytona, Runloop and E2B envd facades forward to toolboxd must be answered by the real toolboxd mux, not its default 404 (CEO review X2). For the prefixes the facades forward whole (Daytona `git/` and `lsp/`, `pkg/api/daytona/toolbox.go:113-120`; E2B `/envd/*`, `pkg/api/e2b/runtime_proxy.go:57`), the test lists each concrete subpath the Daytona and E2B SDKs call. It covers toolboxd only; WASM sandboxes are served by the host-side toolhost (`internal/runtime/wasm/toolhost/`), which has its own tests. | S |
| **B2** | **The `exec` timeout does not end the call.** If a command leaves a background child holding stdout, the call stays open past `timeout_seconds`. | `cmd/toolboxd/main.go:699-736` uses `exec.CommandContext` with no process group and no `WaitDelay`, and reads all output before it waits. `startTracked` (`cmd/toolboxd/child_table.go:135`) sets no `Setpgid`. On timeout Go kills only the shell. The docs half-admit it: "Background jobs make `exec` wait" (`docs/src/content/docs/exec-streaming.mdx:540`). | Start the command in its own process group, and on timeout kill the whole group (the `execStream` pattern, `exec_stream.go:135,205`). Return shortly after the command itself ends: after a 1 s grace for trailing output (only when a background job still holds the output), send the result, and keep draining (and discarding) any pipe a background job still holds, so the job keeps running and is not killed by a closed pipe. Mechanism: toolboxd creates the pipes itself (`os.Pipe()`, the write ends set as `cmd.Stdout`/`cmd.Stderr`), so `cmd.Wait` inside `trackedChild.wait` (`child_table.go:75-78`) cannot close toolboxd's read ends; toolboxd closes its own copies of the write ends right after start, or the drainers never see EOF; the drainers run detached from the request, with a hard limit of 256 per sandbox (about 512 file descriptors): past it, a new background job's output is closed after the 1 s grace instead of getting a drainer, so that job may stop on its next write; the count and an "at cap" flag are reported in toolboxd's `/health` JSON with a warning log (toolboxd has no metrics endpoint), and a test runs cap+1 background jobs (eng review ER3); `cmd.Cancel` kills `-pgid`, because `CommandContext` alone kills only the shell. Rewrite "Background jobs make `exec` wait" (`exec-streaming.mdx:540`). Tests: `sleep 600 &` returns at once; a timeout with a background child returns `timed_out`; a background write paused across the 1 s grace boundary is kept before the reply and discarded after it, never corrupting it (one "responded" flag under one mutex); all also run on gVisor (UC-335 history). (CEO review R1.) The change applies to every caller of this handler: AerolVM `exec`, Daytona `executeCommand` (`pkg/api/daytona/toolbox.go:353`) and Runloop one-shot commands (`pkg/api/runloop/toolbox.go:209`); the Daytona and Runloop docs say so, and a Daytona contract case runs `sleep 600 &`. Kept unchanged, with existing tests green: exit status (reaper race, gVisor ESRCH), the pushed sandbox env, the image PATH, the missing-workdir error, the 5-minute default and full output when no background job holds it (eng review ER2). Return `timed_out: true`: B2 adds it to `ExecResult` (`pkg/models/types.go:1406`) and to all 5 SDKs' exec result types. B2 ships in Phase 0 (Q1); E1 in Phase 1 adds its caps and `truncated` on top of B2's `timed_out`. | S |
| **B3** | **The docs promise E2B "watch a folder", but it returns 501.** | `docs/src/content/docs/using-e2b-sdk.mdx:99` says it works. `cmd/toolboxd/envd.go:383-390` answers all four watcher calls with 501. | Fix the doc now: watching works only on gVisor and Firecracker sandboxes, once F5 lands (CEO review R8). F5 builds the real watcher. | S |

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
| O4 | Count toolbox calls by feature, result and API (CEO review R10) | S | **Build 0** |
| F1 | File verbs in all 5 SDKs: list, info, delete, mkdir, move, copy | M | **Build 1** |
| F2 | Write options: append, create-only, file mode, atomic write | S | **Build 1** |
| F3 | Upload a folder as a tar and unpack it | S–M | **Build 1** |
| F4 | Download with Range and HEAD, streaming in every SDK, client size cap | S | **Build 1** |
| F5 | File watcher | M | **Build 1** |
| E1 | Server-side output caps, `truncated` flag, operator limits (`timed_out` comes from B2) | S–M | **Build 1** |
| E2 | Run a command as a list (no shell) in `exec` and `execStream` | S | **Build 1** |
| E3 | Report the signal that killed a command (and exit code 128+n) | S | **Build 1** |
| E4 | Close stdin from the SDKs (already shipped; PTY docs note only) | S | **Build 1** |
| E5 | Kill the whole process tree on gVisor (`/proc` scan fallback) | S | **Later** (check first) |
| E6 | Graceful toolboxd shutdown: `/health` returns 503, then SIGTERM, then SIGKILL | S | **Later** |
| E7 | In-sandbox metadata endpoint (env vars with secrets hidden) | S | **Later** |
| E8 | Daytona SDK terminals (`process.createPty`) on toolboxd's existing terminal support | M | **Build 1** |
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
| O1 | Lifecycle metrics, plus a warm/cold label | S | **Build 2** |
| O2 | `pprof` behind admin auth | S | **Build 2** |
| O3 | Publish a create-throughput benchmark | S | **Build 2** |
| M1 | "Moving from agent-sandbox" docs page (CEO review X5) | S | **Build 2** |
| T1 | Sandbox templates: named create defaults | M | **No** (cut, CEO review D10) |
| T2 | Template policies for env and volumes | S | **No** (cut with T1, CEO review D11) |
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
| G8 | Computer-use and browser image (desktop, Chrome DevTools, Playwright) | M | **Build 5** |
| G9 | Recipes for more coding-agent CLIs | S each | **Build 5** |
| G10 | VS Code (code-server) image | S | **Build 5** |
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
| F1 | **File verbs in the SDKs.** List a folder (with a depth limit), get info or check a file exists, delete (optionally recursive), make a folder, move (with an overwrite guard and a fallback when moving across filesystems), copy (recursive, keeping modes and links). Return 409 if a path is the wrong kind (file vs folder). Errors map to specific statuses: ENOENT 404, EACCES/EPERM 403, ENOSPC 507 "sandbox disk is full" (today a bare 500), EXDEV handled by the move fallback (CEO review Section 2). | sandboxd `packages/sandboxd/pkg/server/filesystem.go`: list `:348-426`, recursive `:325-344` (#2101), delete `:899-970`, mkdir `:533-587` (#2097), move `:985-1105` and copy `:1122-1240` (#2118). Clients: Python `files/filesystem.py`; TS `files.ts:52-62` (#2140); Go `files.go:634-655` (#2156). Mostly main-only. | Our docs say: "There is no SDK call to list a folder" (`docs/src/content/docs/file-system.mdx:212`). The SDKs have only `upload_file` and `download_file`. Part of the server half exists: toolboxd `/files`, `/files/info`, `/files/move`, `/files/search`, `/files/find` (`cmd/toolboxd/main.go:503-527`) and envd `ListDir`, `Stat`, `MakeDir`, `Move`, `Remove`. Only the Daytona and E2B facades use them. Copy, the list depth limit, the entry cap and the 409 for the wrong kind of path are new toolboxd code. | Add toolboxd handlers for list (`depth`, entry cap, never follow symlinks), info, delete (`recursive`), mkdir (`parents`, `mode`), move (`overwrite`) and copy. One handler set, shared with the Daytona facade (B1 adds delete and mkdir); the new options are optional fields Daytona never sends, and their defaults keep today's Daytona behaviour (move overwrites, `daytona_files_git.go:171`; no entry cap), so the SDKs send `overwrite=false` and an entry cap explicitly. The file work itself (move, mkdir, delete, list, stat) lives in one shared core with an options struct, called by these REST handlers and by E2B's envd handlers alike; each keeps its own wire format and error shape, and envd keeps "move creates the parent folder" as an option (eng review ER1). Info gains a 64-bit `size_bytes` field, because the shared handler's size is 32-bit (`daytona_files_git.go:511`); Daytona's field stays as it is. On WASM and V8 isolate sandboxes, F1, F2, F3 and F4 return a clear 501 beyond the plain upload, download and list the WASM toolhost already serves, as Q8 does for F5. That includes the toolhost upload refusing the F2 options (`append`, `create_only`, `mode`, atomic) and F3's `extract`, which it would otherwise ignore and answer 201 (`internal/runtime/wasm/toolhost/files.go:16-56`), with a test. The SDKs call them through the existing `/v1/sandboxes/{id}/toolbox/files/...` pass-through, so there are no new sandboxd routes (CEO review R2). Add matching methods to all 5 SDKs, plus docs. Also expose search and find, which we already have. | M | **Build 1** |
| F2 | **Write options:** append, create only if missing (412 if it exists, safe under races), file mode, atomic write (temp file then rename). | `filesystem.go:428-530`, `:626-660` (#2112), `:706-740`; TS `types.ts:237-264` (#2151) | Upload creates parent folders. It is not atomic, has no mode (files land as root, `rw-r--r--`), has no append and no create-only (`cmd/toolboxd/main.go:924-932`). | Add `append`, `create_only`, `mode` and atomic replace to the upload route and the SDKs. Conflicting options (for example `append` with `create_only` or atomic) return 400 naming both; `create_only` uses `O_EXCL`, or `link(2)` / `RENAME_NOREPLACE` when atomic, so it is safe under races; a test sends two `create_only` uploads at once and expects exactly one 2xx and one 412 (CEO review Sections 2 and 4). | S | **Build 1** |
| F3 | **Upload a folder as a tar.** gzip detected, caps on entry count and size, hard links and escaping paths rejected. | `filesystem.go:755-897` (#2130, main-only) | The docs tell users to upload a tar and run `tar` through exec (`file-system.mdx:191-197`). | Add `extract=true` on upload, with the same caps, and `upload_dir(local, remote)` in the SDKs. Give `aerolvm cp` a `-r` flag: upload a folder through `extract=true`, download one through `tar` over exec, unpacked safely: the CLI rejects absolute paths, "..", symlinks and hard links that point outside the target, and device files, caps entries and total size, writes only under the target folder, and is tested with a hostile archive (CEO review R9). Both F3's unpack in toolboxd and the CLI's unpack write through Go's `os.Root` (Go 1.26, `go.mod:3`), because checks on entry names alone miss two-step symlink chains; the hostile-archive test includes such a chain (eng review). Every file, and every mode change, is written to a fresh temp file in the target folder and renamed into place, never truncated in place, so a pre-existing hard link inside the target (for example pnpm's `node_modules`) cannot carry a write to a file outside it; this reuses the WASM toolhost's `atomicWriteFile` pattern (`internal/runtime/wasm/toolhost/files.go:145`), and the test includes a pre-existing hard link (eng outside voice #1). It replaces the tar hint at `cmd/aerolvm/files.go:107-108`. Ships with tests and a `cli.mdx` line. On an image with no `tar`, and on WASM and V8 isolate sandboxes, `cp -r` fails with an error that names the cause (CEO review X4). | S–M | **Build 1** |
| F4 | **Download options:** Range and HEAD, streaming read and write in every SDK, a size cap on the client. | `filesystem.go:255-309` (`ServeContent`); Python `read_to`; TS `rest.ts:752,833`; Go `ReadTo`/`WriteReader`; Python `models.py:364` max download size | Downloads stream with Content-Length, but there is no Range and no HEAD (`cmd/toolboxd/main.go:794-832`). Only the Go SDK streams (`sdk/go/pkg/microvm/client.go:673-681`). No client cap. | Use `http.ServeContent` in toolboxd. Add streaming read and write plus `max_bytes` to the Python, TypeScript, Rust and Java SDKs. | S | **Build 1** |
| F5 | **File watcher.** A live stream of create, write, remove, rename and chmod events. Optional recursive mode that also watches new subfolders. Events batched every 250 ms, limit on watches at once, overflow reported. | `packages/sandboxd/spec/watcher/v1/watcher.proto:26-100`; `pkg/server/watcher.go:37-250`; Python `watcher/file_watcher.py:62`; Go `sandbox.go:759`. In v1.0.9. | **Missing.** All four envd watcher calls return 501 (`cmd/toolboxd/envd.go:383-390`). | An inotify watcher in toolboxd, streamed over WebSocket on toolboxd `/files/watch`, reached through `/v1/sandboxes/{id}/toolbox/files/watch` (CEO review R2). Wire the E2B `WatchDir` calls to it (fixes B3). `watch(path, recursive, on_event)` in all 5 SDKs. Firecracker and gVisor need a test of their own. WASM and isolate return a clear "not supported". Docker and containerd sandboxes also return a clear 501 ("file watching needs a gVisor or Firecracker sandbox"): root there shares the host's inotify limit (kernel default 128 instances per user, never raised by our installers), so one tenant could break watching for others (CEO review R8). The E2B `WatchDir` calls answer the same way. | M | **Build 1** |
| — | Paths confined to a root folder | `packages/sandboxd/pkg/pathutil/sandbox.go:40-105` | Not done on purpose: the VM or container is the security boundary, and absolute paths are allowed. | Nothing | — | **No** |

### 5.2 Running commands (E)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| E1 | **Output limits.** Separate byte caps for stdout and stderr: keep the start, drain the rest, return `truncated` flags. A time limit separate from the request deadline, a `timed_out` reason, elapsed time. The operator sets default and maximum limits. | `ExecuteWithLimits` in `packages/sandboxd/spec/process/v1/process.proto:37-39,109-135`; `pkg/server/process.go:347-519`; operator policy `pkg/server/execution_policy.go:28-102` (#2117, main-only) | `timeout_seconds` (default 5 min) and `duration_ms` exist (`cmd/toolboxd/main.go:682-685`). There is no byte cap: `exec` holds all output in memory. Only the MCP/CLI client trims output (`internal/agenttools/exec.go:19-75`). | Add `max_stdout_bytes`, `max_stderr_bytes`, and `truncated` in `ExecResult` (`timed_out` comes from B2). Add server settings for the default and maximum (how they reach toolboxd is pending row ER5). toolboxd lists these limits on `/version` next to the file options, and an SDK that sends a cap to an older toolboxd fails closed with the same "re-create / restart the sandbox" error, covered by a mixed-version test (eng review ER4). | S–M | **Build 1** |
| E2 | **Command as a list,** with no shell in between. | `process.proto:67-71` | `exec` and `execStream` always run through a shell (`cmd/toolboxd/main.go:699`; `exec_stream.go:128`). Sessions and envd already take a list. | Optional `argv` field next to `command`. An `argv` command must find the same programs as a shell command on the same route, including what the login profile adds (conda, nix, sdkman from `/etc/profile.d`, `cmd/toolboxd/loginshell/loginshell.go:9-11`). So when the image has a shell, run it as `<shell> -lc '<PATH restore>; exec "$@"' sh argv...` (login shell for `exec`, plain `-c` for `execStream`): the arguments skip shell parsing, and PATH matches. When the image has no shell, exec `argv[0]` directly, resolved against the image PATH (`AEROLVM_IMAGE_PATH`), because Go's `exec.Command` would otherwise search toolboxd's own PATH. A missing program gives exit code 127 and a "not found" stderr line, like a shell (CEO review Section 2). | S | **Build 1** |
| E3 | **Which signal killed it.** Exit code 128+n when a signal ends the command. | `process.go:845-853` | Streams and sessions report `-1` plus the signal name. The buffered `ExecResult` has no signal field (`pkg/models/types.go:1406-1411`). | Add a `signal` field to `ExecResult`. Keep `exit_code` unchanged for compatibility, and document how it maps to 128+n. | S | **Build 1** |
| E4 | **Close stdin** (send end-of-input). | TS `commands.ts:250,283` | toolboxd supports it (`exec_stream.go:299-323`), and all 5 SDKs already expose it as `close` (`exec-streaming.mdx:304`). | Already shipped: all 5 SDKs expose `close`/`Close` on stream handles, documented at `exec-streaming.mdx:304` (corrected by the eng outside voice). Remaining work: document that on a PTY stream `close` is a no-op (`cmd/toolboxd/exec_stream.go:365`), so callers send Ctrl-D instead. | S | **Build 1** (docs only) |
| E5 | **Kill the whole tree on gVisor,** by scanning `/proc` for children. | `process.go:743-825` (#1379) | On disconnect, toolboxd SIGKILLs the process group (`exec_stream.go:199-206`). Not checked whether that reaches grandchildren under gVisor. | Test first. Add the `/proc` scan only if the test fails. | S | **Later** |
| E6 | **Graceful shutdown.** `/health` returns 503, children get SIGTERM, then SIGKILL after 2 s. | `packages/sandboxd/cmd/sandboxd/main.go:246-256` | The signal is forwarded and shutdown takes 10 s (`cmd/toolboxd/main.go:380-393`). `/health` never returns 503. | Return 503 while draining. | S | **Later** |
| E7 | **Metadata endpoint.** Env vars with a chosen prefix; names with TOKEN, SECRET or KEY hidden. | `pkg/server/metadata.go:30-69` | Missing | Small, but low value. | S | **Later** |
| E8 | **Daytona SDK terminals** (CEO review R7). | — (a Daytona compatibility gap, found by the X2 test) | The Daytona facade forwards `process/pty` and `process/pty/*` (`pkg/api/daytona/toolbox.go:86`), but toolboxd has no such route, so `process.createPty` and related calls fail; the docs say "Not supported (HTTP 404)" (`using-daytona-sdk.mdx:103`). AerolVM already ships terminals through the TTY exec stream (`cmd/toolboxd/exec_stream.go`, `creack/pty`). | toolboxd routes for Daytona's PTY calls (create, list, connect over WebSocket, resize, kill), built on toolboxd's existing sessions, which already give a terminal an id, survive a disconnect, resize, take signals and allow reattach (`cmd/toolboxd/sessions_handler.go:24`). The TTY exec stream alone does not fit: it kills the process group when its socket drops (`exec_stream.go:199-206`) and keeps no list by id. Daytona's create, list, info, resize, kill and connect map onto session create, list, get, resize, signal/delete and attach. Sessions today have no count limit and keep an exited session's replay buffer (`cmd/toolboxd/sessions/manager.go:345-356,412`), so E8 adds a per-sandbox limit on Daytona terminals (429 when reached) and frees a finished terminal's buffer after a short retention, keeping its exit status; existing sessions are unchanged; tested with N+1 terminals and a memory check (CEO review R11). Change `using-daytona-sdk.mdx:103` to "Works", noting "not on WASM". The X2 test then expects these routes to answer. Add a live use case with the Daytona SDK. | M | **Build 1** |

### 5.3 SDK experience (S)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| S1 | **Async Python client** | `async_sandbox_client.py:110` (`[async]` extra) | Missing. The Python SDK is sync only. | `AsyncMicroVM` built on `httpx` or `aiohttp`, with the same methods as the sync client. Share the request-building code so the two can't drift. | M | **Build 2** |
| S2 | **Auto-cleanup.** A `with` block, `async with`, delete-on-exit, TypeScript `asyncDispose`. | Python `sandbox_client.py:61,114,212`; TS `sandbox-client.ts:1203,1290`; Go `client.go:310` | Missing | Python `with`/`async with`, TypeScript `await using`, a Go helper, Java `AutoCloseable`, Rust guard. Opt-in delete-on-exit. | S | **Build 2** |
| S3 | **Typed errors** | Python `exceptions.py:18-82` (11 classes); TS `exceptions.ts:29-183` | Go has `ErrNotFound` and `ErrConflict`. Python and TypeScript have one HTTP error type carrying the status. | `NotFoundError`, `ConflictError`, `CapacityError` (503), `TimeoutError`, `AuthError`. Subclasses of today's error type, so existing code keeps working. | S | **Build 2** |
| S4 | **Get or create by name** | `claim_adoption.py:43` | Names are unique and `get_by_name` exists, but users write the recipe themselves (`sandboxes.mdx:194-245`). Only the CLI/MCP has it (`internal/agenttools/create.go:81`). | `get_or_create(name, ...)` in all 5 SDKs, reusing the CLI logic: create by name, and a caller that loses a race reads the winner (CEO review R4). | S | **Build 2** |
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
| L5 | **Destroy after the program exits.** | `ttlSecondsAfterFinished`, `extensions/api/v1beta1/sandboxclaim_types.go:72-77` | When the main program exits, toolboxd (PID 1) logs it and keeps serving (`cmd/toolboxd/main.go:408-414`), so the sandbox does not stop and nothing records the exit; cleanup waits for `destroyIfIdleFor` (corrected by the outside review). | `lifecycle.destroyAfterExitFor`. | S | **Build 2** |
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
| T1 | **Sandbox templates.** A named set of create defaults: image, runtime, size, lifecycle, egress profile, env, volumes. | `SandboxTemplate`, `extensions/api/v1beta1/sandboxtemplate_types.go:99-160` | Snapshots carry image, user and size hints. Firecracker templates are disk images only. Egress profiles are named policies. Nothing bundles all the create defaults. | `/v1/sandbox-templates` and `create(template="name", ...)`, where explicit fields win. Stored in the cluster FSM so every server sees them. In all 5 SDKs. | M | **No.** Cut by the founder on 2026-11-05 (CEO review D10): "after thorough review, i do not want this feature at all". |
| T2 | **Template policies:** whether a caller may set or override env vars, and whether they may add volumes. | `envVarsInjectionPolicy` and `volumeClaimTemplatesPolicy`, `sandboxtemplate_types.go:33-80,136-158` | Missing. Any caller can set any env var. | `env_policy: disallowed\|allowed\|overrides` and `volumes_policy` on templates. Lets a bank lock one approved template. | S | **No.** Cut with T1 on 2026-11-05 (CEO review D11): its rules had no template to attach to. |
| T3 | **Operator create-policy file.** Allowed registries and images, allowed runtimes, maximum size, non-root required, GPU allowed. | Admission policies: `examples/policy/*`, secure-sandbox-vap docs | Only `SB_HOST_RUNTIMES`. Hardening is built in, but an operator can't limit images, runtimes or sizes. | `SB_CREATE_POLICY_FILE` checked at create, the same way the egress operator file works, with a clear 403 reason. | S–M | **Build 3** |
| T4 | **Block private networks by default.** | The default NetworkPolicy blocks RFC 1918, 169.254/16, fc00::/7 and fe80::/10 (`extensions/controllers/sandboxtemplate_controller.go:192-256`). | With no policy set, container, gVisor and Firecracker sandboxes can reach private addresses (`engineering-network-defenses.mdx`, "Default posture"). Metadata addresses are always blocked. Operators can already add blocked ranges in the operator file. | One flag, `SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT`. Decide later whether to make it the default. | S | **Build 3** |

### 5.7 Warm pools (W)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| W1 | **Warm pools as an API object.** Depth per image, with status (ready, target). | `SandboxWarmPool`, `extensions/api/v1beta1/sandboxwarmpool_types.go:40-124` | Pools are set per server by env vars, one depth for every image (`SB_DOCKER_POOL_*`, `internal/config/config.go:2091-2096`). Status shows only in `/v1/capacity`. No pool route. | `/v1/warm-pools` with per-image depth, stored like named egress profiles: a store table on every node (`internal/store/egress_profiles.go`), replicated through the cluster FSM when cluster mode is on (`internal/cluster/fsm_egress_profiles.go`), so single-node mode works with no FSM. Status per server and in total. Admin only. | M | **Build 3** |
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
| D1 | **A cloud identity per sandbox.** Code inside gets short-lived AWS, Azure or GCP credentials for its own role, with no stored secret. **The most important item for banks.** | Through Kubernetes: a service account per pod, plus IRSA or Workload Identity (`examples/sandbox-ksa`, `examples/irsa-simulation-localstack`). "Identity at claim time" is still Planned on its roadmap. | Missing. A per-sandbox toolbox token exists, and egress can inject credentials (`pkg/models/types.go:695-700`), but nothing gives a sandbox its own cloud identity. | AerolVM acts as an OIDC issuer. Each sandbox gets a short-lived signed token (subject = team and sandbox, optional role tag) as a file that is refreshed before it expires. The customer's IAM trusts our issuer and maps it to a role, through `AssumeRoleWithWebIdentity`, Azure federated credentials or GCP Workload Identity Federation. This is how IRSA works. Needs its own design doc and a security review: `plans/sandbox-cloud-identity.md` (2026-11-06). | M–L | **Build 4** |
| A1 | **Signed per-sandbox scoped tokens.** A token you can hand to a browser or an end user. It works only for one sandbox, port, path and method, expires, and can be checked without a database call. | v1 HMAC and v2 Ed25519, bound to the sandbox and the request: `sandbox-router/authz/scopedtoken.go:115,240-331`, `scopedtoken_v2.go:56` | Personal access tokens carry role, team and expiry (`pkg/models/tokens.go`), but nothing scoped to one sandbox or path. | Ed25519 tokens with key IDs and rotation, issued by `/v1/sandboxes/{id}/tokens`, checked at ingress and the toolbox proxy. | M | **Build 4** |
| A2 | **Share a port behind a sign-in.** `?token=` sets an HttpOnly cookie for that sandbox, then a 302 strips the token from the URL. | `sandbox-router/proxy/browsersession.go:33-80` (#1446) | A public URL is either open to anyone (`public-urls.mdx:10`) or not exposed. The Daytona preview token is `""` (`pkg/api/daytona/handlers.go:723-727`). | A `visibility: token` option on expose, using A1 tokens, in Caddy or the ingress proxy. | M | **Build 4** |
| A3 | **Trace context into the sandbox agent.** | The router forwards W3C trace context (`sandbox-router/observability/tracing.go`) | API spans exist (`pkg/api/middleware.go:70-73`). None reach toolboxd. | Forward `traceparent`, and add simple toolboxd spans. | S | **Build 4** |
| P1 | **Placement rules.** Run this sandbox in zone X, on instance type Y, on nodes with label Z. | Full pod scheduling: nodeSelector, affinity, tolerations | Placement filters on runtime, GPU, capacity and artifact affinity (`internal/cluster/placement.go:95-160,365`). No node labels and no zones. | Node labels, plus a `placement` field on create (labels and zone). Cluster code: needs regression tests and a cluster-correctness call-out. Design: `plans/placement-rules.md` (2026-11-06); labels ride the capacity heartbeat, not gossip, because gossip metadata is capped at 512 bytes. | M | **Build 4** |
| P2 | **Per-team quotas.** Maximum sandboxes, CPU and memory per team. Optional queue. | Kueue example (`examples/kueue-agent-sandbox`) | Admission per server only (`pkg/capacity/capacity.go`, `Admitter`), with 503 and Retry-After (`pkg/api/apihttp/admission.go:37`). The control-plane admission hook is a no-op in open source (`pkg/controlplane/controlplane.go:332`). | Quotas per team, stored like named egress profiles (store table, plus the cluster FSM when cluster mode is on), checked at create and again at resize, restart and recreate (resize today re-admits against host capacity only, `internal/service/service.go:4556`), with atomic admission under concurrent requests and a clear 429. A queue is out of scope. | M | **Build 4** |
| P3 | **Swap for density.** | `examples/gke-swap` | Swap equals the memory limit, so it is off (`pkg/docker/client.go:691`). | An opt-in setting. | S | **Later** |
| P4 | **One URL for a group of sandboxes.** | `examples/claimed-sandbox-service` | Missing | Load balancing across sandboxes with a tag. | M | **Later** |

### 5.10 Observability (O)

| ID | Feature | agent-sandbox | AerolVM today | What we build | Size | Decision |
|---|---|---|---|---|---|---|
| O1 | **Lifecycle metrics:** expired, finished, stop and start counters; a warm vs cold label on create latency. | 14 metrics, `internal/metrics/metrics.go:87-306` | Create latency, per-stage latency, wake, OOM, disk-limit and pool metrics, plus 72 alert rules and 12 Grafana dashboards. The counters and labels named here are missing. | Add the counters and labels, plus a dashboard panel. | S | **Build 2** |
| O2 | **`pprof`** | `cmd/agent-sandbox-controller/main.go:107-122` | Missing (no `net/http/pprof`) | Admin-only, off by default. | S | **Build 2** |
| O3 | **A published throughput benchmark** (creates per second at p50, p90 and p99). | `docs/performance-tuning.md:42,168-173`: about 300 claims/s at p90 ≤ 200 ms; 45/s sustained at p50 92 ms | We have latency numbers but no published creates-per-second figure. | A repeatable load test plus a docs page. | S | **Build 2** |
| O4 | **Toolbox call counts** (CEO review R10). | — | toolboxd has no metrics; sandboxd's only toolbox metric is `aerolvm_toolbox_calls_ended_total` (`internal/service/toolbox_calls.go:71`), calls ended by a stop. | sandboxd counts toolbox-proxied responses by route class (files, watch, exec, exec_stream, sessions, pty, lsp, other), status class (2xx, 4xx, 501, 5xx) and API surface (v1, daytona, e2b, runloop): about 128 series, no per-sandbox labels, exported through the expvar-to-Prometheus path, plus one Grafana panel. Ships in Phase 0 so the 501s from B1, R5 and R7 are counted from the first release. It counts at all three proxy points: the shared toolbox proxy (v1 and Daytona), E2B's own proxy (`pkg/api/e2b/runtime_proxy.go:90`) and Runloop's `RoundTripToolbox` calls (`pkg/api/runloop/toolbox.go:78`); a WebSocket upgrade counts once, at the upgrade, as a success (status class 101→2xx, as the middleware records it, `pkg/api/middleware.go:167`) (eng outside voice #5). | S | **Build 0** |

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
| G8 | **Computer use and browser automation.** A desktop image (Xvfb, VNC, Chrome with DevTools on 9222, Playwright), plus an `agent(query)` helper. | Python `extensions/computer_use.py:22`; `examples/{gemini-cu-sandbox,chrome-sandbox,playwright-sandbox,aio-sandbox}`; docs `runtime-templates/computer-use` | Closest is a tutorial where a person drives Chromium over noVNC (`use-cases/customer-facing-product-experiences/secure-burner-browser.mdx`). No DevTools or Playwright guide. | A ready-made image and a docs page with five-language examples. | M | **Build 5** |
| G9 | **More coding-agent recipes:** OpenCode, Aider, Gemini CLI, Codex CLI and others. | `examples/{opencode,aider,pi-code-agent,hermes-agent,openclaw-*}` | Five coding-agent docs centred on Claude Code (e.g. `use-cases/coding-agents/large-scale-refactor-migration-agent.mdx`). | One recipe page per agent, using sessions so long runs survive a disconnect. | S each | **Build 5** |
| G10 | **VS Code in the browser** (code-server) | `examples/vscode-sandbox` | Missing | A ready-made image plus docs. A2 makes it private to one user. | S | **Build 5** |
| G11 | **Agent Client Protocol example** | `examples/agentclientprotocol` | Missing. The building blocks exist (exec stream with stdin). | Example. | S | **Later** |
| G12 | **Host an MCP server inside a sandbox** | `examples/mcp-server-sandbox`, `n8n-mcp` | Missing as a doc. The E2B `mcp` create option returns 501 (`using-e2b-sdk.mdx:116`). | A docs recipe, and support for the E2B `mcp` option. | S–M | **Build 5** |
| G13 | **WebMCP bridge** | `examples/webmcp-bridge-sandbox` | Missing | Too early; the WebMCP proposal is not settled. | M | **No** for now |
| G14 | **Token revoked when its program exits** | `examples/containarium-execution-scoped-token` | Egress inject rules already keep real keys out of the sandbox (`secret-env-architecture.mdx`). | Revisit after A1 and D1. | M | **Later** |
| M1 | **"Moving from agent-sandbox" page** (CEO review X5) | Their Python, Go and TypeScript clients | Missing. §12 adds a comparison column only. | A new `.mdx` page, written after Phase 1 lands: each agent-sandbox client call next to the matching AerolVM SDK call (their create-from-`SandboxTemplate` call maps to `create` with an image and create options, since AerolVM has no templates), in five `syncKey="lang"` tabs, registered in `docs/src/content.config.ts`. | S | **Build 2** |

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
| **0** | Fix what's broken | B1, B2, B3, O4 | Small and already broken for users. |
| **1** | Files and commands | F1–F5, E1–E4, E8 | The most visible gap. The server half mostly exists already. B2 and E1 share code. |
| **2** | SDK and lifecycle quick wins | S1–S7, L1–L6, I1, O1–O3, M1 | Many small items with a big effect on day-to-day use. L4 also closes the "leaked sandbox" class of problem. |
| **3** | Pools, policy, storage | T3, T4, W1–W3, V1 | Lets an operator limit what callers may create. (T1 and T2 were cut on 2026-11-05, CEO review D10 and D11.) |
| **4** | Identity, access, placement | D1, A1–A3, P1, P2 | The bank asks: per-sandbox cloud identity, private shared URLs, zones, quotas. D1 and P1 need their own design docs and reviews. |
| **5** | Integrations and use cases | G1, G2, G4, G5, G8, G9, G10, G12 | Adoption work. It builds on the file API and tokens from earlier phases. |

Phases 0–2 are mostly independent within a phase and can run in parallel
worktrees.

## 10. Rules every PR in this plan follows

- **New `/v1` route:** use `/add-v1-endpoint`. Every route must be idempotent under retries and concurrent duplicate calls (`pr-review.md`).
- **New SDK method:** use `/add-sdk-method`, so all 5 SDKs change together, with a docs example in five-language tabs.
- **Older toolboxd (spec review round 3):** a sandbox can run a toolboxd built before these changes (a Firecracker template keeps its build's toolboxd, `internal/runtime/firecracker/guest_env.go:106-114`; a running Docker sandbox keeps its bind-mounted binary), and it silently ignores unknown options, so `overwrite=false` would overwrite and `create_only` would replace. toolboxd lists the file options it supports on `/version`; the SDKs check before sending a safety option and fail closed with a "re-create the template / restart the sandbox" error, the same way `guest_env.go:114` already does. A toolboxd test checks that every option the file handlers accept is listed on `/version`, so the list cannot drift (eng review). The same rule covers E1's output caps (eng review ER4).
- **Retries (CEO review R4):** file calls use the SDKs' two existing retry tiers (`sdk/python/microvm/client.py:95-105`) plus one new rule for delete and mkdir on a retry. Safe calls (list, info, download, plain or atomic write) retry on 421/429/502/503/504. Delete and mkdir (with or without parents) are in the safe tier. For delete, and for mkdir without parents, a retry that finds the work already done (404, folder exists) counts as success; the first attempt still reports it. mkdir with parents already succeeds when the folder exists. Move, copy, append and create_only retry only on 429/503, like `exec`, and a lost reply surfaces as an error. Each verb's docs say which tier it is in. Bodies that are streamed (Go `UploadFileStream`, F3 folder upload, F4 streaming writes) are sent once and never retried, because they can't be re-sent. The Go SDK's buffered `UploadFile` gains retries (today it is sent once, `sdk/go/internal/apiclient/client.go:845-875`). F1 and F2 PRs cite R4 (D12) as the approved exception to `pr-review.md` §1 for move, copy, append and `create_only`.
- **New docs page:** use `/add-docs-page`. No raw HTTP or `curl` examples.
- **Anything on the create path** (W4, T3, T4, L4, L6, P1, P2, D1): use `/touch-create-sandbox`, and state the boot-latency impact in the PR, including the first call.
- **Cluster code** (W1, P1, P2 store state in the FSM or change placement): regression tests next to the changed file, plus a cluster-correctness call-out. Single-node mode must keep working.
- **Coverage:** every touched Go package stays at or above about 85% (`/maintain-coverage`).
- **Live behaviour** that mocks can't prove (B2 on gVisor, F5 on Firecracker and gVisor, E8 through the Daytona SDK, L1, D1) gets an integration use case. `make test` stays offline.

## 11. Decisions (closed 2026-11-05)

These were the open choices before Phase 1. All eight were closed on
2026-11-05 with the recommended answer. If one changes later, update this
table and note the date.

| # | Question | Decision |
|---|---|---|
| Q1 | Is the phase order right? | Yes: bugs, then files and commands, then SDK and lifecycle, then pools and policy (was "templates"; changed 2026-11-05 when T1 and T2 were cut), then identity, then integrations. |
| Q2 | D1 (cloud identity per sandbox): which cloud first? | AWS (`AssumeRoleWithWebIdentity`), because that's the bank target. Azure next. |
| Q3 | A2 (port behind a sign-in): a per-port option, or the default for new ports? | A per-port option, `visibility: public\|token`. Public stays the default for now. |
| Q4 | T4 (block private networks): only a flag, or the new default? | Ship the flag. Decide on the default in a later release, with a changelog note. |
| Q5 | L1 (restart on failure): on or off by default? | Off. Opt in per sandbox. |
| Q6 | Which framework adapters matter to customers? | G1 (OpenAI Agents) and G4 (Gymnasium) first. Ask customers before G3, G6 and G7. |
| Q7 | Where do adapter packages live? | In this repo under `integrations/`, published to PyPI and npm. Unlike agent-sandbox, which doesn't publish them. |
| Q8 | F5 (file watcher) on WASM and V8 isolates? | Not supported. Return a clear error. |

Change, 2026-11-05 (CEO review D10, D11): T1 (sandbox templates) and T2 (template policies) were cut. Q1's order stands; Phase 3 is now pools, policy and storage.

## 12. Definition of done

- Every **Build** item is merged, with tests, docs, and 5-SDK support where it applies.
- B1 and B2 each have a test that failed before the fix. B3 is a docs fix.
- The comparison page (`aerolvm-vs-daytona-vs-e2b.mdx`, or a new one) gains an agent-sandbox column, and the "Moving from agent-sandbox" page (M1) is live.
- The facade route inventory test (X2) runs in `make test`.
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

---

## CEO review working notes (2026-11-05)

`/plan-ceo-review`, mode **SELECTIVE EXPANSION** (founder answer D1,
2026-11-05; the review recommended SCOPE REDUCTION). Q1–Q8 in section 11
stay closed. Code checked against `main` at `e33b6e16` (unchanged since the
plan was written).

### Step 0 findings

- **B1, B2, B3 confirmed in code.** B1: `pkg/api/daytona/toolbox.go:92-99`
  forwards four file routes that toolboxd never registers, so they hit the
  default 404 at `cmd/toolboxd/main.go:552`. B2: `cmd/toolboxd/main.go:699`
  has no process group, and `:724-734` reads both pipes to the end before
  `child.wait()`. B3: `using-e2b-sdk.mdx:99` vs `cmd/toolboxd/envd.go:383-390`.
- **B2's fix as written is not enough (resolved: R1, D8).** Go applies `WaitDelay` only
  inside `cmd.Wait`, and toolboxd reads to EOF before it waits
  (`main.go:724-736`). The fix also needs a group kill on timeout and a
  bounded close of the read ends. `execStream` already has the group kill
  (`exec_stream.go:135,205`).
- **F1 may not need new `/v1/.../files` routes (resolved: R2, D9).** The SDKs already
  reach toolboxd through `/v1/sandboxes/{id}/toolbox/{path...}`
  (`pkg/api/v1/routes.go:210-211`, `sdk/python/microvm/client.py:1258`).
- **"Template" already has two meanings (resolved: T1 and T2 cut, D10 and D11).** Firecracker rootfs
  templates (`/v1/templates`, `routes.go:181-187`; `template_id`,
  `pkg/models/types.go:742`; `create_template()` in the SDKs) and E2B's
  template = snapshot. T1 would add a third.
- **D1 is "the most important item for banks" but sits in Phase 4** (moving its design earlier, X3, was declined in D5).
- **Line refs (fixed in spec review round 1):** the no-op admitter is `pkg/controlplane/controlplane.go:332`,
  not `:26`; `pkg/capacity/capacity.go:50-75` is config, not the 503 path.
- **Not re-verified:** kind live-test timings, agent-sandbox's 300 claims/s,
  L3 audit coverage of every automatic stop or delete.
- **Outside view:** GKE ships agent-sandbox as a preview (March 2026) and a
  third-party operator implements its API, so its API is becoming a
  standard. Shaping W1/L2 to match it would keep the later Kubernetes facade a
  translator, like `/daytona` and `/e2b` (offered as X1; declined in D3).

```
REALITY: premise-table finding 29 of 31 code claims hold; 2 wrong line refs; unverified=3 pkg/controlplane/controlplane.go:332
REALITY: already-done pass origin/main is still e33b6e16 cmd/toolboxd/main.go:699
REALITY: surface-check finding F1 routes duplicate the toolbox proxy; "template" name taken pkg/api/v1/routes.go:181
REALITY: binding-decisions finding K8s decision (own controller reconciles agents.x-k8s.io CRDs) not reflected in T1/W1/L2 plans/agent-sandbox-feature-parity.md:238
REALITY: numbers finding 72 alert rules and 12 dashboards [measured]; sizes [estimated]; kind timings [re-measure before gate] plans/agent-sandbox-feature-parity.md:50
REALITY: deferred-asks pass no linked issue plans/agent-sandbox-feature-parity.md:1
REALITY: pr-count finding whole-phase stacks held until green; Phase 2 holds 17 PRs (18 with M1) plans/agent-sandbox-feature-parity.md:375
PLAN_REALITY: phase=ceo rows=7/7 missing=none unverified=3 verdict=complete
```

### Decision ledger

| ID and owner | Contract and evidence | Current | Proposed | Status | Exact approval and scope |
|---|---|---|---|---|---|
| X1 (T1, W1, L2, L5, L6 owners) | K8s plan decision 2026-09-30: own controller reconciles `agents.x-k8s.io` CRDs; "no facade-specific tables" rule | T1/W1/L2/L5/L6 shapes designed on AerolVM's own terms | — | declined | D3 answer 2026-11-05: "Skip" (review recommended Add). Scope: no mapping table, no golden translation test. |
| X2 (Phase 0, B1) | B1 root cause: facade tests use a fake toolbox (`pkg/api/daytona/toolbox_proxy_test.go:26-35`) | Inventory test: every path the Daytona, Runloop and E2B envd facades forward is answered by the real toolboxd mux, in `make test`, shipped in B1's PR | — | approved | D4 answer 2026-11-05: "Add to this plan's scope (recommended)". Scope: the offline inventory test plus the small refactor that makes forwarded paths listable; nothing else in B1 changes. |
| X3 (D1) | Plan: D1 "most important item for banks", "needs its own design doc and a security review" (§5.9, §9) | Design and code both in Phase 4 | — | declined | D5 answer 2026-11-05: "Skip" (review recommended Add). Scope: D1 design, review and code stay together in Phase 4. |
| X4 (F3, CLI) | `aerolvm cp` exists (`cmd/aerolvm/files.go:28`), one file at a time; folders refused with a tar hint (`:107-108`) | `aerolvm cp -r` both directions in F3's PR, plus a `cli.mdx` line | — | approved | D6 answer 2026-11-05: "Add to this plan's scope (recommended)". Scope: `-r` on `aerolvm cp` (upload via F3's extract, download via tar through exec), its tests and one docs line; no other CLI verbs. |
| X5 (docs) | §12 adds an agent-sandbox column to the comparison page | "Moving from agent-sandbox" page (M1), Phase 2, five `syncKey="lang"` tabs | — | approved | D7 answer 2026-11-05: "Add to this plan's scope" (review recommended Defer). Scope: one new docs page written after Phase 1, registered in the sidebar; no SDK or server change. |
| R1 (B2, toolboxd exec) | Spec review: `WaitDelay` cannot help when reads finish before `Wait` (`main.go:724-736`); docs say "Background jobs make `exec` wait" (`exec-streaming.mdx:540`) | `exec` returns shortly after the command ends; background jobs keep running, later output dropped; timeout kills the group; docs line rewritten; tests incl. gVisor | — | approved | D8 answer 2026-11-05: "Return when the command ends (recommended)". Scope: B2 only (toolboxd buffered exec, its docs line, its tests). |
| R2 (F1, F5 server surface) | Spec review: SDKs already call toolboxd through `/v1/sandboxes/{id}/toolbox/{path...}` (`routes.go:210-211`) with `sandbox.exec` and cluster forwarding | SDKs use `/toolbox/files/...` and `/toolbox/files/watch`; one toolboxd handler set shared with Daytona; no new sandboxd routes | — | approved | D9 answer 2026-11-05: "Toolbox pass-through, one handler set (recommended)". Scope: F1 and F5 server surface only. |
| R3 (T1) | "Template" already means a Firecracker rootfs (`/v1/templates`, `template_id` at `pkg/models/types.go:742`) and an E2B snapshot | T1 cut from the plan; W1 per image only; O1, G8, G10 drop "template" | — | approved | D10 answer 2026-11-05 (typed): "after thorough review, i do not want this feature at all". Scope: T1 removed; mechanical follow-ons in W1, O1, G8, G10, section 9, section 10. T2 is R6. |
| R6 (T2) | T2's env and volume policies attach to a T1 template (section 5.6) | T2 cut; T3 unchanged | — | approved | D11 answer 2026-11-05: "Cut T2 too (recommended)". Scope: T2 removed; no env or volume rules added to T3. |
| R7 (B1/X2 `process/pty`) | Spec review round 2: Daytona forwards `process/pty` (`pkg/api/daytona/toolbox.go:86`); toolboxd has no such route, so X2 fails on day one; docs say "Not supported (HTTP 404)" (`using-daytona-sdk.mdx:103`) | New item E8 (Phase 1, size M): Daytona terminals on toolboxd's TTY exec stream; B1 returns 501 for `process/pty` until E8 lands | — | approved | D14 answer 2026-11-06: "Build Daytona terminals" (review recommended a clear 501). Scope: E8 as described in section 5.2, its docs line, X2 expectations and a live use case; B1's interim 501. |
| R8 (F5 watcher, host inotify) | Section 1: Docker/containerd sandboxes run as host root (no user namespaces in `pkg/docker/client.go` or `internal/runtime/containerd`); kernel default `fs.inotify.max_user_instances` = 128 per user (inotify(7)); nothing in `scripts/`, `setup/`, `Ansible/`, `Terraform/` raises it | F5 on gVisor and Firecracker only; Docker and containerd return a clear 501; B3 docs say so | — | approved | D16 answer 2026-11-06: "Offer F5 only on gVisor and Firecracker" (review recommended A, cap + raise host limits). Completeness 7/10, logged as an accepted shortcut. |
| P1 (F3 partial extract) | Section 2: a failure mid-archive leaves earlier entries on disk | Unstated | Rollback rule (keep partial like `tar -x`, or all-or-nothing via a temp dir) | approved (owner F3, 2026-11-06): keep what was written, like `tar -x`; an all-or-nothing temp folder cannot be renamed over a folder that already holds files without losing them | a mid-archive failure returns an error naming the failing entry and the count written, with a test |
| R9 (X4 download direction) | Section 3: `aerolvm cp -r box:/dir ./dir` unpacks a tar built inside an untrusted sandbox onto the user's machine | Tar over exec, every entry checked (no absolute, "..", escaping links, devices; caps; hostile-archive test) | — | approved | D17 answer 2026-11-06: "Unpack the tar, but check every entry (recommended)". Scope: X4 download direction only. |
| R10 (observability) | Section 8: toolboxd has no metrics; sandboxd's only toolbox metric is `aerolvm_toolbox_calls_ended_total` (`internal/service/toolbox_calls.go:71`), calls ended by a stop | New item O4 in Phase 0: counter by route class x status class x surface, one Grafana panel | — | approved | D18 answer 2026-11-06: "Count every call by feature and result (recommended)". Scope: O4 as described in section 5.10. |
| P2 (L5 exit signal) | Outside review #1: toolboxd keeps serving after the main program exits (`cmd/toolboxd/main.go:408-414`) | L5 assumes an exit stops the sandbox | How toolboxd reports main-program completion to sandboxd | approved (owner L5, 2026-11-06): toolboxd's reaper already sees the main program exit (`cmd/toolboxd/main.go`, `startReaper`); it shows the state, exit code or signal and time on `/health`, and sandboxd's existing one-minute lifecycle sweep reads it only for started sandboxes that set `destroyAfterExitFor`, with bounded concurrency and a short timeout. sandboxd stores the exit time and code, so a daemon restart keeps the timer; L2's "program exited" reason and `exit_code` come from the same record. Runtime independent for every toolboxd runtime; WASM and isolate refuse the option at create | — required verification: a test where the main program exits and `destroyAfterExitFor` fires; L2's "program exited" reason uses the same signal |
| P3 (V1 size cap) | Outside review #4: platform volumes are S3/NFS mounts (`pkg/volumes/volumes.go:209`); guest writes bypass the toolbox | V1 promises `max_bytes` | Per-backend enforcement, or drop `max_bytes` | approved (owner V1, 2026-11-06): drop `max_bytes`. Platform volumes are S3 or NFS mounts (`pkg/volumes/volumes.go`, `Backend.Kind`) that the guest writes directly, so AerolVM cannot refuse a write past a cap; a cap it cannot enforce is worse than none. V1 ships `delete_with_sandbox` only, and the docs say how to cap size on the backend (NFS server quotas; S3 bucket-level limits) | — required verification before V1 starts: a write past the cap fails on every supported backend, or the field is removed |
| P4 (L1 on Firecracker) | Outside review #5: die events are wired only for Docker/containerd (`pkg/daemon/container_engine_wiring.go:30`) | L1 hooks the die-event path | Runtime-independent exit transition, or restrict L1 to Docker/containerd | approved (owner L1, 2026-11-06): restrict L1 to Docker and containerd (gVisor included), whose die events reach `markSandboxStopped`; Firecracker, WASM and isolate refuse `restartOnFailure` at create with a clear 400. Firecracker support needs a VMM-exit event source that also covers adopted VMMs (`internal/runtime/firecracker/vmm_adopt.go`); it is a later item | — required verification: L1's test matrix lists each runtime as supported (with a crash test) or refused at create |
| R11 (E8 limits) | Outside review #6: no session count gate; exited sessions keep their replay buffer; the sweeper deletes recordings only (`cmd/toolboxd/sessions/manager.go:345-356,412`) | E8 limits Daytona terminals per sandbox (429) and frees a finished terminal's buffer after a short retention; existing sessions unchanged | — | approved | D19 answer 2026-11-06: "Apply this change (recommended)". Scope: E8-created terminals only. |
| R4 (F1, F2, S4 retry) | CLAUDE.md hard rule 1; SDK retry tiers (`sdk/python/microvm/client.py:95-105`); exec ledger (`internal/service/exec_ledger.go`) | Two retry tiers as for exec; rule in section 10; S4 race noted | — | approved | D12 answer 2026-11-05: "Two retry tiers, like exec (recommended)". Scope: SDK retry classification and docs for F1/F2 verbs, S4 race; no ledger. |
| R5 (B1 `lsp/*`) | Plan B1: "either build it or return a clear 501"; docs already say "Not supported (HTTP 404)" (`using-daytona-sdk.mdx:104`) | Clear 501 for every `lsp/*` call; X2 expects 501; docs say 501 | — | approved | D13 answer 2026-11-05: "Return a clear 501 (recommended)". Scope: B1's `lsp/*` handling and one docs line; no LSP feature. |

### Answered: X1 (D3, 2026-11-05)

Founder answer: **Skip**. T1, W1, L2, L5 and L6 are designed on AerolVM's own terms; no agent-sandbox mapping table or translation test. Recorded under NOT in scope.

### Answered: X2 (D4, 2026-11-05)

Founder answer: **Add**. B1's PR also ships an offline inventory test: every path the Daytona, Runloop and E2B envd facades forward to toolboxd must be answered by the real toolboxd mux, not its default 404.

### Answered: X3 (D5, 2026-11-05)

Founder answer: **Skip**. D1's design doc, security review and code stay together in Phase 4, as written. Recorded under NOT in scope.

### Answered: X4 (D6, 2026-11-05)

Founder answer: **Add**. F3's PR also gives `aerolvm cp` a `-r` flag: upload a folder through F3's tar extract, download one through tar over exec, with tests and a `cli.mdx` line.

### Answered: X5 (D7, 2026-11-05)

Founder answer: **Add** (review recommended Defer). New item M1: a "Moving from agent-sandbox" docs page in Phase 2, written after Phase 1 lands.

### Accepted scope (from the cherry-pick)

- **X2 → B1:** offline facade route inventory test, in B1's PR.
- **X4 → F3:** `aerolvm cp -r`, in F3's PR.
- **X5 → M1:** "Moving from agent-sandbox" docs page, Phase 2.

### NOT in scope

| Item | Why |
|---|---|
| X1: shape T1/W1/L2/L5/L6 to match agent-sandbox's API | Founder chose Skip (D3). AerolVM's shapes are its own; the Kubernetes effort will map them. |
| X3: write D1's design doc during Phases 0–1 | Founder chose Skip (D5). D1 design, review and code stay together in Phase 4. |
| Deferring Phases 2–5 | Founder chose SELECTIVE EXPANSION over SCOPE REDUCTION (D1). All six phases stay. |

### Spec review round 1 (2026-11-05)

Independent reviewer: score 6/10, FAIL. 12 issues: Completeness 4, Consistency 3, Clarity 3, Feasibility 2; Scope PASS.

Fixed without a new decision (facts, approved scope, repo rules, or Q1):
- B3 pointed at "F6"; the watcher is F5.
- B2 said "Ship with E1" but sits in Phase 0; Q1 puts bugs first, so B2 ships alone with `timed_out` and E1 builds on it.
- P2 line refs: `controlplane.go:332`; 503 is `apihttp/admission.go:37`.
- F1 overstated "the server half exists".
- F3 lacked X4's tests, `cli.mdx` line and the no-`tar` / WASM / isolate error.
- E2 did not say which PATH an `argv` command sees.
- Section 10's create-path list missed T2, T4, L4 and L6.
- X2 needed concrete subpaths under `git/` and `lsp/`.

Needs a founder decision: R1–R5 below.

### Answered: R1 (D8, 2026-11-05)

Founder answer: **A, return when the command ends**. B2's row in section 3 now carries the approved behaviour.

### Answered: R2 (D9, 2026-11-05)

Founder answer: **A, toolbox pass-through, one handler set**. F1 and F5 in section 5.1 now say so.

### Answered: R3 (D10, 2026-11-05)

Founder answer (typed): **"after thorough review, i do not want this feature at all."** T1 is cut. Follow-on edits with no new choice: W1 depth is per image only; O1 drops its "template" label; G8 and G10 ship as ready-made images; Phase 3 renamed; T1 removed from section 10's lists; a dated change note added under section 11. T2 depends on T1, so it is R6.

### Answered: R6 (D11, 2026-11-05)

Founder answer: **A, cut T2 too**. T3 stays as written.

### Answered: R4 (D12, 2026-11-05)

Founder answer: **A, two retry tiers like exec**. Rule added to section 10; S4 notes the race.

### Answered: R5 (D13, 2026-11-05)

Founder answer: **A, return a clear 501**. B1's row now says so.

### Spec review round 1: outcome

All 12 issues are closed, by the direct fixes listed above and by founder decisions R1–R6 (the "template" naming issue closed when T1 and T2 were cut).

### Spec review round 2 (2026-11-05)

Independent reviewer: score 6/10, FAIL. 17 new issues (none repeated from round 1); Scope PASS.

Fixed without a new decision (facts, approved answers R1–R6, Q8, repo rules, or physical limits):
- B1: the docs already listed the four calls as unsupported (`using-daytona-sdk.mdx:102`); B1 now changes that line to "Works". toolboxd itself returns R5's 501.
- X2: names the E2B `/envd/*` subpaths and states it does not cover the WASM toolhost.
- B2: the mechanism that makes R1 work (toolboxd-owned pipes, detached drainers with a gauge, `cmd.Cancel` kills `-pgid`), a 1 s grace, and `timed_out` in all 5 SDKs in Phase 0.
- E1 no longer also adds `timed_out`.
- E2 names the env for each route.
- F1: shared-handler defaults keep Daytona's behaviour; a 64-bit `size_bytes` on info; WASM and isolate get a clear 501 for F1, F2 and F4, as Q8 does for F5.
- Section 10 retry rule: names the new delete/mkdir rule, exempts streamed bodies, adds Go `UploadFile` retries, and makes F1/F2 PRs cite R4 as the approved exception to `pr-review.md` §1.
- Section 12: B3 is a docs fix.
- M1 maps the create-from-template call.
- Q1 row updated for the T1/T2 cut.
- Count and line-ref fixes.

Needs a founder decision: R7 below.

### Answered: R7 (D14, 2026-11-06)

Founder answer: **B, build Daytona terminals** (review recommended a clear 501). New item E8 in Phase 1 (section 5.2). B1 returns 501 for `process/pty` until E8 lands.

### Spec review round 3 (final, 2026-11-06)

Independent reviewer: score 7/10, FAIL. 10 issues; Scope PASS. This was the third and last reviewer launch, so the fixes below were checked against the plan text by the review itself, not by a fourth reviewer.

Fixed without a new decision (prime directive "no silent failures", Q8, approved answers R1, R4, R7, repo rules, or wrong facts in an earlier fix-up):
1. Older toolboxd silently ignores new safety options → toolboxd advertises supported options on `/version`; SDKs fail closed (section 10).
2. F3 `extract` and F2 options on WASM would be ignored with a 201 → toolhost refuses them with 501, with a test (section 5.1, F1).
3. Daytona docs "Works" while WASM still 404s → "not on WASM", and the toolhost answers those routes with 501 (B1, E8).
4. E2's round-2 PATH claim was wrong → argv runs as `<shell> -lc '...; exec "$@"' sh argv...`, or direct exec on the image PATH when there is no shell (E2).
5. Summary table still gave E1 `timed_out` → fixed (section 4).
6. R4's mkdir rule named the wrong case → both mkdir forms in the safe tier (section 10).
7. B2's gVisor tests had no home → in section 10's live list.
8. W1 and P2 had no single-node storage → store table plus FSM, like egress profiles (W1, P2).
9. E8 could not work on the TTY exec stream → built on toolboxd sessions, which already have ids, reattach, resize and signals (E8).
10. Go's `exec.Command` searches toolboxd's PATH → covered by fix 4.

issues verified: 10 of 10 (applied edits read back against the plan text; not a fourth review).


### Document approval (D15, 2026-11-06)

Founder answer: **"Approve and continue (recommended)"**. Accepts this plan version and the CEO summary, including two mechanism changes from spec review round 3: E8 on toolboxd sessions (not the TTY exec stream) and E2's `sh -lc 'exec "$@"'` wrapper.

### Build sequence (0I)

```
  HOUR 1 (foundations)   toolboxd is PID 1 with its own reaper: every exec child goes through
                         startTracked (child_table.go). SDK calls reach toolboxd only through
                         /v1/sandboxes/{id}/toolbox/ (sandbox.exec + cluster forwarding).
                         WASM files are a separate host-side toolhost. Five SDKs, two retry tiers.
  HOUR 2-3 (core logic)  B2: drainer lifetime vs the reaper and cmd.Wait. E8: Daytona's PTY wire
                         shape vs the session API. F1: one handler set, Daytona defaults kept.
                         R4: which tier each verb is in, in all 5 SDKs.
  HOUR 4-5 (integration) Firecracker templates and running Docker sandboxes keep an old toolboxd,
                         so new options must fail closed via /version. gVisor's ESRCH reap path
                         (UC-335). TestDaytonaSDKContracts gates any Daytona change. X2 needs
                         lsp/* and process/pty answering 501 on day one.
  HOUR 6+ (polish/tests) Live use cases: B2 on gVisor, F5 on Firecracker and gVisor, E8 through
                         the Daytona SDK. cmd/toolboxd stays at ~85% coverage. Five-tab docs.
```

Feasibility blockers: none. Pending scope choices: none.

Effort [estimated]: Phase 0, human ~1 week / CC ~3 hours. Phase 1 (F1–F5, E1–E4, E8, X4), human ~5 weeks / CC ~2 days. Whole plan (Phases 0–5), human ~5 months / CC ~3–4 weeks.

### Section 1: Architecture Review (2026-11-06)

Findings: 1 CRITICAL (R8, decision below); 2 corrections applied to B2 (drainer count via `/health`, since toolboxd has no metrics; close the parent's write ends after start); R2's Daytona-derived file format noted for Section 10; P2 owner must prove an O(1) quota check with no store write on the create path.

### Answered: R8 (D16, 2026-11-06)

Founder answer: **B, F5 only on gVisor and Firecracker**. Docker and containerd return a clear 501. Ceiling: no file watching on the default runtime (containerd). Upgrade when: containerd customers ask for watch, or user namespaces / per-host inotify tuning land. Logged with `gstack-decision-log`.

### Section 2: Error & Rescue Map (2026-11-06)

Registry for Phases 0–1 is in this section's chat record and the Error & Rescue Registry below. Three gaps fixed as routine (ENOSPC 507, option conflicts 400, argv not found 127); one implementation choice left pending with an owner (P1: F3 partial-extract rollback rule). Phases 2–5 owners must prove: L1 never fights idle stop or a user stop; L2 sets a reason on every stop path; L4 never destroys a sandbox with its own timers; I1 retries only connection-refused.

### Section 3: Security & Threat Model (2026-11-06)

One HIGH-impact unmitigated threat: X4's download direction unpacks an untrusted tar on the user's machine (R9 below). Mitigated: F3 in-sandbox extract, WASM host-side ops (501), F5 cross-tenant (R8), B2 drainers (pids limit). Phase 4 owners must prove: A2 uses a host-only `__Host-` cookie (Secure, HttpOnly, SameSite=Lax, no Domain) so a sandbox page cannot plant cookies for other sandboxes; D1 and A1 keys get their own design and security review.

### Answered: R9 (D17, 2026-11-06)

Founder answer: **A, unpack the tar but check every entry**. F3's X4 text now carries the checks and the hostile-archive test.

### Sections 4–7 (2026-11-06)

- **Section 4:** B2's reply buffer is guarded by one "responded" flag under one mutex; both completion orders checked; grace-boundary test added to B2. F2 `create_only` race named (O_EXCL / RENAME_NOREPLACE) with a two-writer test. Edge cases (retry, huge folders, dropped watch, two clients on one terminal) covered by R4, the entry cap, watcher cleanup and existing session behaviour.
- **Section 5:** F1 owner moves the shared handlers out of `daytona_files_git.go` into `files.go`; split upload option checks from write steps (over 5 branches); one argv helper for `exec` and `execStream`; one retry-tier table per SDK.
- **Section 6:** test diagram in the chat record; every row is inside approved scope. 2am test: B2 live on gVisor plus X2. Injected clocks for the grace window and watcher batching.
- **Section 7:** no new store writes in Phases 0–2; B2 adds up to 1 s only when a background job holds the output; item owners pick F1's entry cap and E1's default caps, each with a test at the cap; P2 owner proves an O(1) quota check.

### Answered: R10 (D18, 2026-11-06)

Founder answer: **A, count every call by feature and result**. New item O4 in Phase 0 (section 5.10).

### Section 8: Observability (2026-11-06)

One WARNING, resolved by R10 (O4). Already covered: B2 drainer count in `/health`, F5 overflow events, existing disk-limit alerts behind 507s. Gap noted for Phase 4: no request id reaches toolboxd until A3.

### Section 9: Deployment & Rollout (2026-11-06)

- Store columns (corrected by the outside review): lifecycle settings are explicit columns (`internal/store/store.go:109-112`), so L1 (restart policy and backoff state), L2 (`status_reason`, `exit_code`) and L5 (`destroy_after_exit`, exit time) add columns through `/add-store-column`, and their deadlines and backoff must survive a daemon restart. L4 and L6 reuse existing columns. W1 and P2 (Phases 3–4) add store tables and FSM commands: their owners must prove a mixed-version cluster handles the new command safely (an old node must not crash or diverge), with regression tests next to the FSM file (CLAUDE.md cluster rule).
- toolboxd skew: SDKs fail closed via `/version`. Docs for each new file feature say it needs a sandbox created on or after the release (running Docker/containerd sandboxes keep their bind-mounted toolboxd; Firecracker templates need a rebuild).
- WARNING: R1 changes `exec` behaviour with no per-request opt-out. Rollback is a release rollback, and only new sandboxes get the old behaviour.
- Order: server release first, then the SDK patch release (safe either way, because the SDKs check `/version`); docs merge after the SDK release.
- Phase 1's stack (F1–F5, E1–E4, E8; X4 inside F3) is about 11 PRs held until all are green, per the stacked-PR rule: expect rebase work.
- Post-deploy: X2 in CI; live use cases (B2 on gVisor, F5 on gVisor and Firecracker, E8 through the Daytona SDK); the O4 panel shows 2xx for files and exec; first hour, watch the 5xx rate per route class.

### Section 10: Long-Term Trajectory (2026-11-06)

- Reversibility 3/5. Debt: R2 keeps a Daytona-derived request format in AerolVM's own file API; R1 changes `exec` semantics users will build on; R8 makes file watching differ by runtime; these review notes make the plan long.
- Retrospective: X2 was the load-bearing pick (it found the terminal gap that became E8, and the WASM docs gap). X1 stopped mattering once T1 and T2 were cut. X3's absence keeps the bank's top ask (D1) behind Phase 4's design cycle.
- Platform: one toolboxd handler set for every facade, `/version` option listing, and O4's counter form a reusable kit for future facade parity.

### Section 11: Design & UX

SKIPPED (no UI scope): docs pages and a CLI flag only.

### Outside voice: Codex (2026-11-06)

Completed (provider codex, model gpt-6-astra per the probe). 6 findings, all checked against the code:
- #1 L5 exit signal — true (`cmd/toolboxd/main.go:408-414`). L5's "AerolVM today" corrected; mechanism pending as P2.
- #2 store columns — true (`internal/store/store.go:109-112`); my Section 9 line "no store migrations in Phases 0–2" was wrong and is corrected (L1, L2, L5 add columns through `/add-store-column`).
- #3 P2 bypass by resize — true (`internal/service/service.go:4556`); P2 now checks quota at create, resize, restart and recreate.
- #4 V1 `max_bytes` has no enforcement — plausible (mount specs only, `pkg/volumes/volumes.go:209`); pending as P3.
- #5 L1 misses Firecracker — true (`pkg/daemon/container_engine_wiring.go:30`); pending as P4.
- #6 E8 limits — true; my round-3 claim that sessions have a cap and idle cleanup was wrong and is removed; decision R11 below.

### Answered: R11 (D19, 2026-11-06)

Founder answer: **A, apply this change**. E8's row in section 5.2 now carries the limit, the buffer cleanup and the test.

### TODO choices

No TODO proposals remain: no scope item was deferred (D3–D7), and the four pending rows (P1–P4) stay as owner decisions in this plan, not TODOs.

### Approval readiness

Approval readiness: PASS — X1 (D3 "Skip", declined), X2 (D4 "Add"), X3 (D5 "Skip", declined), X4 (D6 "Add"), X5/M1 (D7 "Add"), R1 (D8), R2 (D9), R3/T1 cut (D10, typed), R6/T2 cut (D11), R4 (D12), R5 (D13), R7/E8 (D14), document approval (D15), R8 (D16), R9 (D17), R10/O4 (D18), R11 (D19). Mode: D1. Corrections applied without a new choice are listed under spec review rounds 1–3, Sections 1–8 and the outside voice; each cites the fact, rule or prior answer behind it. Pending, non-blocking, with owners: P1 (F3), P2 (L5), P3 (V1), P4 (L1).

### Review facts

- Mode: SELECTIVE EXPANSION. Status: issues_open (4 pending owner decisions, 0 critical gaps).
- Scope: 5 cherry-picks proposed, 3 accepted (X2, X4, X5→M1), 2 skipped (X1, X3), 0 deferred. Review decisions added E8 (R7) and O4 (R10) and cut T1 (D10) and T2 (D11).
- Outside voice: Codex completed, 6 findings: 3 resolved (#2, #3 corrected; #6 decided as R11), 3 pending as P2–P4.

### NOT in scope

| Item | Answer | Why |
|---|---|---|
| X1: match agent-sandbox's API shapes | D3 Skip | AerolVM designs its own shapes; the Kubernetes effort maps later. |
| X3: D1 design during Phases 0–1 | D5 Skip | D1 design, review and code stay together in Phase 4. |
| T1: sandbox templates | D10 (typed) | "after thorough review, i do not want this feature at all." |
| T2: template env and volume policies | D11 Cut | No template to attach to; T3 unchanged. |
| F5 on Docker and containerd | D16 B | Host root's inotify budget is shared across tenants; clear 501 instead (accepted shortcut, 7/10). |
| Deferring Phases 2–5 | D1 | Founder kept all six phases (SELECTIVE EXPANSION over SCOPE REDUCTION). |

Deferred to TODOS.md: none. The original plan's **Later**, **No** and **K8s** rows (sections 4–6) are unchanged.

### What already exists (and whether the plan reuses it)

| Existing code | Reused by |
|---|---|
| `/v1/sandboxes/{id}/toolbox/{path...}` pass-through (`pkg/api/v1/routes.go:210-211`) | F1, F5 (R2) |
| toolboxd Daytona file handlers and envd `Remove`/`MakeDir`/`Move` | B1, F1 (one handler set) |
| `execStream` process-group kill (`exec_stream.go:135,205`) | B2 |
| toolboxd sessions: ids, reattach, resize, signals (`sessions_handler.go:24`) | E8 |
| `agenttools.GetOrCreate` (`internal/agenttools/create.go:81`) | S4 |
| SDK retry tiers (`sdk/python/microvm/client.py:95-105`) | R4 |
| `guest_env.go` fail-closed on an old toolboxd (`:106-114`) | `/version` option check |
| Egress profiles: store table + FSM (`internal/store/egress_profiles.go`, `internal/cluster/fsm_egress_profiles.go`) | W1, P2 |
| Audit system callers (`internal/service/audit_caller.go:23-33`) | L3 |
| expvar-to-Prometheus path (`pkg/api/prometheus.go`) | O4 |
| Exec ledger (`internal/service/exec_ledger.go`) | Not reused (R4 chose retry tiers) |

### Dream state delta

```
  TODAY                          AFTER PHASES 0-1                  12-MONTH IDEAL (Step 0C)
  B1 404s, exec hangs, no SDK -> file API in 5 SDKs, exec that  -> complete SDKs, per-sandbox cloud
  file API, docs promise 501s    returns, Daytona terminals,       identity, locked-down creates, drop-in
                                 honest 501s, a call counter,      for Daytona/E2B/Runloop and
                                 watch on gVisor/Firecracker       agent-sandbox's API
```

Still short of the ideal after this plan: no agent-sandbox API alignment (X1 declined), no templates (T1/T2 cut), no file watching on the default runtime (R8), and the bank's top ask (D1) waits for Phase 4.

### Error & Rescue Registry (Phases 0–1)

| Codepath | Failure | Rescue | User sees |
|---|---|---|---|
| toolboxd file verbs | ENOENT | 404 with path | not found |
| toolboxd file verbs | EEXIST (create_only / move guard) | 412 / 409 | conflict |
| toolboxd file verbs | ENOTEMPTY, ENOTDIR, EISDIR | 409 "wrong kind of path" | conflict |
| toolboxd file verbs | EACCES, EPERM | 403 with path | forbidden |
| upload, copy | ENOSPC | 507 "sandbox disk is full" | clear |
| upload | conflicting options | 400 naming both | clear |
| upload extract (F3) | escaping entry, hard link, cap | 400 / 413 naming the entry | clear |
| upload extract (F3) | mid-archive failure | error names entry and count written (rollback rule P1) | clear |
| download (F4) | bad range | 416 | clear |
| watch (F5) | Docker/containerd, WASM, isolate | 501 | clear |
| watch (F5) | queue overflow | overflow event | client re-lists |
| exec (B2) | timeout, background child | kill `-pgid`, `timed_out` | flag |
| exec (E2) | `argv[0]` missing | exit 127 + stderr | like a shell |
| Daytona PTY (E8) | over the terminal limit | 429 | clear |
| SDK | older toolboxd lacks an option | fail closed, "re-create / restart" | clear |
| `aerolvm cp -r` | hostile archive | entry rejected, nothing written outside target | clear |

Phases 2–5, capability rows (owner must prove): L1 restart never fights idle stop or a user stop, and covers each supported runtime (P4); L2 sets a reason on every stop path; L4 never destroys a sandbox with its own timers; L5 fires from a real exit signal (P2); I1 retries only connection-refused; V1 enforces its cap per backend or drops it (P3); P2 admits quota at create, resize, restart and recreate; W1/P2 FSM commands are safe in a mixed-version cluster; A2 uses a host-only `__Host-` cookie.

### Failure Modes Registry

```
  CODEPATH                 | FAILURE MODE                  | RESCUED? | TEST? | USER SEES?        | LOGGED?
  -------------------------|-------------------------------|----------|-------|-------------------|--------
  toolboxd file verbs      | ENOENT/EEXIST/ENOTDIR/EACCES  | Y        | Y     | specific 4xx      | Y
  upload/copy              | ENOSPC                        | Y (507)  | Y     | clear             | Y
  upload                   | conflicting options           | Y (400)  | Y     | clear             | Y
  upload create_only       | concurrent writers            | Y O_EXCL | Y     | one 412           | Y
  extract (F3)             | escaping entry / cap          | Y        | Y     | 400/413           | Y
  extract (F3)             | mid-archive failure           | partial  | Y     | error + count     | Y   (rollback rule P1)
  download (F4)            | bad range                     | Y (416)  | Y     | clear             | n/a
  watch (F5)               | shared-kernel runtime         | Y (501)  | Y     | clear             | Y
  watch (F5)               | overflow                      | Y        | Y     | overflow event    | Y
  exec (B2)                | background child holds output | Y        | Y+gV  | prompt reply      | /health count
  exec (B2)                | timeout                       | Y        | Y+gV  | timed_out         | Y
  exec (E2)                | argv[0] missing               | Y (127)  | Y     | like a shell      | Y
  Daytona PTY (E8)         | terminal limit                | Y (429)  | Y     | clear             | Y
  Daytona PTY (E8)         | finished terminal memory      | Y freed  | Y     | none              | Y
  SDK option check         | older toolboxd                | Y        | Y     | fail closed       | client
  aerolvm cp -r            | hostile archive               | Y        | Y     | entry rejected    | client
  X2 inventory             | forwarded route missing       | Y (CI)   | Y     | n/a               | CI
  O4 counter               | render failure                | existing | Y     | panel gap         | Y
  L1 (capability)          | Firecracker exit unseen       | unknown  | owner | owner proves (P4) | —
  L5 (capability)          | no exit signal                | unknown  | owner | owner proves (P2) | —
  V1 (capability)          | cap not enforceable           | unknown  | owner | owner proves (P3) | —
  P2 (capability)          | quota bypass via resize       | planned  | owner | 429               | —
  W1/P2 FSM (capability)   | mixed-version cluster         | unknown  | owner | owner proves      | —
  A2 (capability)          | cookie tossing                | planned  | owner | owner proves      | —
```

CRITICAL GAPS (RESCUED=N and TEST=N and USER SEES=Silent): 0.

### Scope Expansion Decisions

Full record: `/Users/sumansaurabh/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-11-05-agent-sandbox-feature-parity.md`.
- Accepted: X2 (facade route inventory test), X4 (`aerolvm cp -r`), X5 (M1 docs page).
- Deferred: none.
- Skipped: X1 (agent-sandbox API shapes), X3 (D1 design early).

### Diagrams

Produced in this review: system architecture (Section 1), data flow with shadow paths (Section 4), state machines for B2, F5 and E8 (Section 1), error flow (Error & Rescue Registry above), deployment sequence and rollback flowchart (below).

```
 Deployment sequence
 sandboxd release (ships toolboxd) ─► new sandboxes get new toolboxd ─► SDK patch release
        │                                 (running Docker/containerd keep old;   (SDKs check /version,
        │                                  Firecracker templates need a rebuild)   so order is safe)
        └─► X2 in CI · live UCs (B2 gVisor, F5 gVisor/FC, E8 Daytona SDK) ─► docs merge ─► watch O4 panel
```

```
 Rollback flowchart
 problem after release ─► which part?
   ├─ toolboxd behaviour (B2, F1-F5, E8) ─► roll back the sandboxd release ─► new sandboxes get old toolboxd
   │                                         └─ running sandboxes keep the new one until recreated
   ├─ SDK method ─► publish the previous patch version; old toolboxd paths fail closed anyway
   ├─ O4 counter ─► roll back sandboxd; the counter is additive, no data to migrate
   └─ docs ─► revert the docs PR
```

### Stale Diagram Audit

No ASCII diagrams exist in the files this plan touches (`cmd/toolboxd/*`, `pkg/api/daytona/toolbox.go`, `pkg/api/e2b/runtime_proxy.go`, `internal/service/toolbox_proxy.go`, `internal/runtime/wasm/toolhost/host.go`, `cmd/aerolvm/files.go`, and the five docs pages). Stale diagrams found: 0.

### Completion Summary

```
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SELECTIVE EXPANSION                         |
  | System Audit         | main = e33b6e16; B1-B3 real; 29/31 claims   |
  |                      | hold; docs already listed B1 as unsupported;|
  |                      | toolboxd has no metrics; no userns, no      |
  |                      | inotify tuning on hosts                     |
  | Step 0               | SELECTIVE (D1); 3/5 picks; T1+T2 cut;       |
  |                      | 3 spec reviews (6, 6, 7)                    |
  | Section 1  (Arch)    | 3 issues found (1 critical -> R8)           |
  | Section 2  (Errors)  | 16 error paths mapped, 4 GAPS (3 fixed,     |
  |                      | 1 pending P1)                               |
  | Section 3  (Security)| 2 issues found, 1 High (R9)                 |
  | Section 4  (Data/UX) | 6 edge cases mapped, 0 unhandled            |
  | Section 5  (Quality) | 4 issues found                              |
  | Section 6  (Tests)   | Diagram produced, 0 gaps                    |
  | Section 7  (Perf)    | 0 issues found (3 owner notes)              |
  | Section 8  (Observ)  | 1 gaps found (-> O4)                        |
  | Section 9  (Deploy)  | 4 risks flagged                             |
  | Section 10 (Future)  | Reversibility: 3/5, debt items: 4           |
  | Section 11 (Design)  | SKIPPED (no UI scope)                       |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (6 items)                           |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| 16 rows, 0 CRITICAL GAPS                    |
  | Failure modes        | 24 total, 0 CRITICAL GAPS                   |
  | TODOS.md updates     | 0 items proposed                            |
  | Scope proposals      | 5 proposed, 3 accepted (EXP + SEL)          |
  | CEO plan             | written                                     |
  | Outside voice        | codex, completed (6 findings)               |
  | Lake Score           | 0/1 recommendations chose complete option   |
  | Diagrams produced    | 6 (architecture, data flow, state machines, |
  |                      | error flow, deployment, rollback)           |
  | Stale diagrams found | 0                                           |
  | Unresolved decisions | 4 (listed below)                            |
  | Reality rows         | 7/7 rows (PLAN_REALITY), 3 unverified       |
  +====================================================================+
```

### Unresolved Decisions

- P1 (owner F3): settled 2026-11-06 — keep partial like `tar -x`, and the error names the failing entry and the count written.
- P2 (owner L5): settled 2026-11-06 — toolboxd `/health` shows the main program's exit; the lifecycle sweep reads it for sandboxes that opted in, and sandboxd stores it.
- P3 (owner V1): settled 2026-11-06 — drop `max_bytes`; V1 ships `delete_with_sandbox`; docs explain backend-side caps.
- P4 (owner L1): settled 2026-11-06 — L1 on Docker and containerd (incl. gVisor) only; other runtimes refuse it at create; Firecracker later.

## Implementation Tasks

Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship.
Effort assumes bug fix with regression ~20x and features ~30x (human ÷ CC).

- [ ] **T1 (P1, human: ~1 day / CC: ~30min)** — toolboxd — Add B1's four file handlers; return 501 for `lsp/*` and `process/pty`; make the WASM toolhost answer them with 501
  - Surfaced by: Step 0 (B1), R5, R7, spec review round 3 #3
  - Files: `cmd/toolboxd/main.go`, `cmd/toolboxd/daytona_files_git.go`, `internal/runtime/wasm/toolhost/host.go`, `docs/src/content/docs/using-daytona-sdk.mdx`
  - Verify: `go test ./cmd/toolboxd/... ./internal/runtime/wasm/...` (each test failed before the fix)
- [ ] **T2 (P1, human: ~1 day / CC: ~20min)** — facades — Facade route inventory test (X2)
  - Surfaced by: Step 0G X2; spec review round 2 (E2B `/envd/*`, WASM exclusion)
  - Files: `pkg/api/daytona/toolbox.go`, `pkg/api/e2b/runtime_proxy.go`, `pkg/api/runloop/toolbox.go`, new test next to them
  - Verify: `make test`
- [ ] **T3 (P1, human: ~2 days / CC: ~45min)** — toolboxd exec — Rework buffered exec per R1 (own pipes, close write ends, detached drainers, `cmd.Cancel` kills `-pgid`, 1 s grace, `timed_out` in `ExecResult` and 5 SDKs, `/health` drainer count, docs line)
  - Surfaced by: Step 0 (B2), R1, spec reviews 2–3, Sections 1 and 4
  - Files: `cmd/toolboxd/main.go`, `cmd/toolboxd/child_table.go`, `pkg/models/types.go`, `sdk/*`, `docs/src/content/docs/exec-streaming.mdx`, `integration-tests/suite/`
  - Verify: `go test -run Exec ./cmd/toolboxd/...`; live use case on gVisor
- [ ] **T4 (P1, human: ~1 day / CC: ~20min)** — sandboxd — O4 toolbox call counter and Grafana panel
  - Surfaced by: Section 8, R10
  - Files: `internal/service/toolbox_proxy.go`, `setup/grafana/`
  - Verify: unit test on the counter; series visible on `/metrics`
- [ ] **T5 (P1, human: ~1h / CC: ~5min)** — docs — B3: E2B watch is not supported yet, and later only on gVisor/Firecracker
  - Surfaced by: Step 0 (B3), R8
  - Files: `docs/src/content/docs/using-e2b-sdk.mdx`
  - Verify: docs build
- [ ] **T6 (P2, human: ~1 week / CC: ~3h)** — toolboxd + SDKs — F1 verbs on one shared handler set (moved to `files.go`), Daytona defaults kept, `size_bytes`, error mapping, WASM/isolate 501
  - Surfaced by: R2, Sections 2 and 5, spec review round 2
  - Files: `cmd/toolboxd/`, `sdk/*`, `docs/src/content/docs/file-system.mdx`
  - Verify: toolboxd unit tests + each SDK's tests
- [ ] **T7 (P2, human: ~2 days / CC: ~40min)** — toolboxd — F2 options with conflict 400 and the two-writer `create_only` race test
  - Surfaced by: Sections 2 and 4
  - Files: `cmd/toolboxd/main.go`
  - Verify: `go test -run Upload ./cmd/toolboxd/...`
- [ ] **T8 (P2, human: ~3 days / CC: ~1h)** — toolboxd + CLI — F3 extract and `aerolvm cp -r` with safe unpack both ways; hostile-archive tests (P1 rollback rule decided first)
  - Surfaced by: X4, R9, Section 3
  - Files: `cmd/toolboxd/`, `cmd/aerolvm/files.go`, `docs/src/content/docs/cli.mdx`
  - Verify: `go test ./cmd/aerolvm/... ./cmd/toolboxd/...`
- [ ] **T9 (P2, human: ~1 week / CC: ~2h)** — toolboxd — F5 watcher on gVisor/Firecracker, 501 elsewhere, E2B `WatchDir`
  - Surfaced by: R8
  - Files: `cmd/toolboxd/`, `cmd/toolboxd/envd.go`, `sdk/*`
  - Verify: unit tests with an injected clock; live use cases on gVisor and Firecracker
- [ ] **T10 (P2, human: ~1 day / CC: ~20min)** — toolboxd — E2 `argv` through the shell wrapper, direct exec without a shell, exit 127
  - Surfaced by: spec review round 3 #4, Section 2
  - Files: `cmd/toolboxd/main.go`, `cmd/toolboxd/exec_stream.go`
  - Verify: test that a `/etc/profile.d` tool is found by `argv`
- [ ] **T11 (P2, human: ~1 week / CC: ~2h)** — toolboxd — E8 Daytona terminals on sessions, with the per-sandbox limit and buffer cleanup
  - Surfaced by: R7, R11, outside voice #6
  - Files: `cmd/toolboxd/sessions/`, `cmd/toolboxd/sessions_handler.go`, `pkg/api/daytona/toolbox.go`, `docs/src/content/docs/using-daytona-sdk.mdx`
  - Verify: `TestDaytonaSDKContracts`; N+1 terminals test; live use case with the Daytona SDK
- [ ] **T12 (P2, human: ~3 days / CC: ~1h)** — SDKs — `/version` option check (fail closed), R4 retry tiers, Go `UploadFile` retries, streamed bodies never retried
  - Surfaced by: R4, spec review rounds 2–3
  - Files: `cmd/toolboxd/main.go` (`/version`), `sdk/*`
  - Verify: each SDK's tests
- [ ] **T13 (P3, human: ~2h / CC: ~15min)** — Phases 2–4 owners — Settle P2–P4 before L1, L5 and V1 start; add P2's resize check, A2's `__Host-` cookie, W1/P2 mixed-version FSM tests, store columns via `/add-store-column`
  - Surfaced by: outside voice #1–#5, Sections 3 and 9
  - Files: to be determined
  - Verify: each owner's PR description cites the settled row

## Eng review working notes (2026-11-06)

Target: this file, reviewed by `/plan-eng-review` right after the CEO review. Depth: implementation-ready for Phases 0–1; Phases 2–5 stay capability-level, and each needs its own eng review before it is built (their open rows P1–P4 and D1/P1 design docs settle there).

### Scope record

feature answers: none proposed (scope was settled in the CEO review); structure: B "Original arrangement" (eng D1, 2026-11-06); accepted scope: the plan as approved at CEO D15 plus CEO D16–D19, unchanged; pending remedies: ER1 (shared file-operation core, Section 2), ER2 (B2 regression contract, Section 3).

Scope Challenge result: scope accepted as-is.

### Reality rows (eng)

```
REALITY: premise-table finding new claims hold: x/sys go.mod:136, creack/pty go.mod:8, gorilla/websocket go.mod:12, go 1.26.10 go.mod:3 (os.Root available), envd vs Daytona move differ, /process/execute shared by Daytona, Runloop and Go SDK; unverified=3 cmd/toolboxd/envd.go:938
REALITY: already-done pass origin/main still e33b6e16; no commits on named paths cmd/toolboxd/main.go:699
REALITY: surface-check pass sessions routes, /version and the toolbox pass-through all exist cmd/toolboxd/sessions_handler.go:24
REALITY: binding-decisions finding decision log said E8 on the TTY exec stream; superseded per D15 (sessions) plans/agent-sandbox-feature-parity.md:192
REALITY: numbers finding Phase 0-1 about 45 changed files and 5 new components [estimated]; effort table [estimated]; kind timings [re-measure before gate] plans/agent-sandbox-feature-parity.md:383
REALITY: deferred-asks pass no linked issue plans/agent-sandbox-feature-parity.md:1
REALITY: pr-count finding no ship-policy.json; Phase 0 is 4 PRs (B1, B2, B3, O4), Phase 1 about 11, each stack held until all green plans/agent-sandbox-feature-parity.md:385
PLAN_REALITY: phase=eng rows=7/7 missing=none unverified=3 verdict=complete
```

### Scope Challenge findings

1. [INFORMATIONAL] (confidence: 9/10) decision log — the E8 entry still said "TTY exec stream"; superseded to sessions per CEO D15 (factual repair). Disposition: fixed.
2. [INFORMATIONAL] (confidence: 8/10) `go.mod:136` — F5 can use `golang.org/x/sys/unix` inotify, already a dependency, instead of adding fsnotify; recursion is manual (watch new subfolders, rescan on `IN_Q_OVERFLOW`, expect watches to vanish when folders are deleted). Disposition: guidance for F5's owner; no plan change.
3. [INFORMATIONAL] (confidence: 8/10) F3 / X4 — name checks miss two-step symlink chains; `os.Root` is the mechanism for R9's "writes only under the target". Disposition: carried forward as required proof of R9 (F3 text updated).
4. [INFORMATIONAL] (confidence: 7/10) `TODOS.md:186-200` — WebSocket streams drop during Caddy reloads (UC-266); F5 and E8 inherit it. Disposition: noted under failure modes; existing TODO.

### Section 1: Architecture

- Design-twice (E8): shape A (plan) adds Daytona terminal routes in toolboxd that call the session manager in-process; shape B has the Daytona facade translate to toolboxd `/sessions`, rewriting WebSocket frames. Pick A: the mapping sits next to the session state it owns, behind a small surface; B leaks the session wire format into the facade and adds frame rewriting on a cluster-forwarded path.
- Red flag #6 (two ways to do one task): envd and the Daytona/native handlers implement move, mkdir, remove and list separately (`cmd/toolboxd/envd.go:888-995`, `cmd/toolboxd/daytona_files_git.go:123-176`), and already differ (envd move creates the parent folder, `envd.go:938`; Daytona move does not, `daytona_files_git.go:171`). Decision ER1 (Section 2).
- Red flag #8 (hand-synced list): `/version`'s option list vs the handlers' options. Disposition: consistency test, carried forward as required proof of the approved fail-closed rule (section 10 text updated).
- Production failure per new path: F5 and E8 WebSockets drop on Caddy reload (UC-266, existing TODO); a sandbox restart ends drainers, watchers and terminals (expected; clients reconnect).
- Security: unchanged from the CEO review (sections 3 and R9).

### Section 2: Code Quality

1. [INFORMATIONAL] (confidence: 9/10) `cmd/toolboxd/envd.go:922-950` and `cmd/toolboxd/daytona_files_git.go:160-176` — two implementations of the same file operations, with different behaviour, about to gain F1's options (overwrite guard, EXDEV fallback, recursive delete, 409/507 mapping). Without a shared core, E2B's envd calls miss those fixes and the two paths drift. Decision ER1 below.

Shared-code rubric for ER1: callers `handleEnvdFilesystemMove` (`envd.go:922`), `handleEnvdFilesystemMakeDir` (`:888`), `handleEnvdFilesystemRemove` (`:976`), `handleEnvdFilesystemListDir` (`:954`), `handleDaytonaMoveFile` (`daytona_files_git.go:160`), `handleDaytonaListFiles` (`:137`), `handleDaytonaFileInfo` (`:123`), plus B1's new delete and folder handlers (proposed). Helper: plain functions in `cmd/toolboxd` (move, mkdir, remove, list, stat) with an options struct; each handler keeps its own wire parsing and error envelope (`writeEnvdFilesystemError`, `writeFilesystemError`); envd keeps "move creates the parent folder" as an option. Lines [estimated]: about 60 removed, about 120 added (net +60), plus about 150 test lines. Blast radius: one bug reaches E2B, Daytona and native callers, covered by table-driven core tests, envd tests and `TestDaytonaSDKContracts`.

### Eng decision ledger

#### ER1: shared file-operation core
Finding: Section 2 #1, INFORMATIONAL, confidence 9/10, `cmd/toolboxd/envd.go:922-950` / `cmd/toolboxd/daytona_files_git.go:160-176`, reviewer: native eng review
Plan baseline: F1 "one handler set, shared with the Daytona facade" (CEO R2, D9); envd not mentioned
Runtime evidence: envd move creates the parent folder (`envd.go:938`); Daytona move does not (`daytona_files_git.go:171`); separate error writers
Comparison grid:

```text
Commitment                                    | Approval              | Current             | A (shared core)          | B (keep two)           | C (defer)
F1 verbs, one REST handler set (Daytona+SDK)  | CEO R2, D9            | approved            | unchanged                | unchanged              | unchanged
envd file ops (E2B) call a shared core        | pending               | separate code       | yes, in F1               | no                     | TODO after Phase 1
envd keeps "move creates the parent folder"   | existing behaviour    | yes                 | yes (option)             | yes                    | yes
EXDEV fallback, 507, overwrite guard on E2B   | pending               | no                  | yes                      | no                     | later
Core table-driven tests + existing envd tests | pending               | n/a                 | yes                      | n/a                    | later
  + TestDaytonaSDKContracts                    |                       |                     |                          |                        |
```

Question D3:
D3 — ER1: Should E2B's file calls (envd) and the REST file handlers share one core for move, mkdir, delete and list? Project: plans/agent-sandbox-feature-parity (PR #923), Phase 1 item F1. ELI10: toolboxd has two separate copies of the same file actions: one for E2B's SDK (envd) and one for the Daytona and AerolVM REST calls. They already behave a little differently: E2B's move creates the target folder, Daytona's doesn't. F1 is about to add safety options and better errors (overwrite guard, cross-disk move, "disk full" 507). With two copies, only the REST side gets them, and the copies drift further. Option A moves the actual file work into one shared set of functions; each API keeps its own request format and error shape. Stakes: without it, E2B users get a weaker, different version of the same file actions, and every later fix must be made twice. Recommendation: A, because one implementation of each file action is what keeps three APIs consistent, for about two days of work. Completeness: A=9/10, B=6/10, C=6/10. Net: a small refactor now versus two drifting copies of the file code.
Header: ER1 core
Options:
A) Share one core in F1 (recommended)
Move move/mkdir/delete/list/stat into shared functions with an options struct; envd and REST handlers keep their wire formats and error shapes; envd keeps "move creates the parent folder" as an option; table-driven core tests plus envd tests and TestDaytonaSDKContracts. Effort S (human: ~2 days / CC: ~40 min), risk low, ~+60 net lines. ✅ E2B, Daytona and SDK callers get the same safety options and errors. ✅ Each later file fix is made once, not twice. ❌ A core bug reaches all three APIs at once (covered by the shared tests).
B) Keep two copies
F1's options and fixes go into the REST handlers only; envd stays as it is. Effort S (zero extra implementation work), risk medium. ✅ No change to E2B's code path in Phase 1. ✅ Smallest F1 diff. ❌ E2B lacks the overwrite guard, cross-disk move and 507, and the copies keep drifting.
C) Defer to a TODO
Ship F1 on the REST side; record merging envd onto a shared core as a TODO after Phase 1. Effort S (zero implementation work now), risk medium. ✅ Phase 1 stays as planned. ✅ The merge can follow once F1's options settle. ❌ E2B users get the weaker version until someone picks the TODO up.

State: approved
Actual answer: A) Share one core in F1 (recommended) — eng D3, 2026-11-06
Accepted scope: in F1, move/mkdir/delete/list/stat become shared functions with an options struct; envd and REST handlers keep their wire formats and error writers; envd keeps "move creates the parent folder" as an option; table-driven core tests plus existing envd tests and TestDaytonaSDKContracts. F1's text in section 5.1 updated.
History: none

### Section 3: Test review

Framework: Go `go test` / `make test` (offline), per-SDK test commands in CLAUDE.md, live use cases under `integration-tests/` (integration tag). Existing buffered-exec coverage: exit code + stderr (`cmd/toolboxd/coverage_boost5_test.go:159`), pushed env (`sandbox_env_test.go:161`), image PATH (`loginshell_exec_test.go:22`), reaper race and gVisor ESRCH (`child_table` tests), happy path (`coverage_boost2_test.go`). No exec-behaviour tests for the Daytona (`pkg/api/daytona/toolbox.go:353`) or Runloop (`pkg/api/runloop/toolbox.go:209`) callers of the same handler.

Coverage diagram: 7 of 27 planned paths already tested (26%); 20 gaps, 4 needing live use cases. Every gap is required proof of an approved item (B1, B2/R1, ER1, X2, X4/R9, E8/R11, F5/R8, O4/R10, R4), except ER2 below (regression rule).

#### ER2: B2 regression contract
Finding: Section 3, CRITICAL (regression rule), confidence 9/10, `cmd/toolboxd/main.go:699-736` shared by `pkg/api/daytona/toolbox.go:353` and `pkg/api/runloop/toolbox.go:209`, reviewer: native eng review
Plan baseline: CEO R1 (D8): "`exec` returns shortly after the command itself ends; background jobs keep running"; scope "B2 only (toolboxd buffered exec, its docs line, its tests)"; facade callers not named
Runtime evidence: Daytona `executeCommand` and Runloop one-shot (10 s timeout) call the same `/process/execute` handler; existing tests cover exit codes, env, PATH, reaper race and ESRCH, not facade behaviour
Comparison grid:

```text
Commitment                                    | Approval        | Current                | A (all callers)          | B (exec only)
Preserve: exit status (reaper race, gVisor    | pending (rule)  | tested                 | kept, tests stay green   | kept, tests stay green
  ESRCH), pushed env, image PATH, missing-    |                 |                        |                          |
  workdir error, 5-min default, full output   |                 |                        |                          |
  when no background job                      |                 |                        |                          |
AerolVM exec: return when the command ends    | CEO R1, D8      | approved               | yes                      | yes
Daytona executeCommand: same new behaviour    | pending         | waits for bg jobs      | yes                      | no, keeps waiting (now
                                              |                 |                        |                          |   ends at the timeout)
Runloop one-shot: same new behaviour          | pending         | waits for bg jobs      | yes                      | no, keeps waiting
Internal "wait for background" flag           | pending         | none                   | none                     | yes, set by facades
New tests: `sleep 600 &` returns; timeout +   | R1 (required)   | none                   | yes, plus a Daytona      | yes, plus a Daytona
  bg child -> timed_out; grace edge; gVisor   |                 |                        |   contract case          |   case that still waits
```

Question D4:
D4 — ER2: Should B2's new "return when the command ends" behaviour also apply to Daytona and Runloop users? Project: plans/agent-sandbox-feature-parity (PR #923), Phase 0 item B2. ELI10: B2 changes toolboxd's command runner so a command that starts a background job returns right away instead of waiting. That same runner also serves Daytona's `executeCommand` and Runloop's one-shot commands, so they change too unless we say otherwise. Either way, everything else stays the same and stays tested: exit codes, env, PATH, error messages, the 5-minute default and full output for normal commands. Option A gives every caller the new behaviour. Option B keeps Daytona and Runloop waiting for background jobs as today (but the call now ends at the timeout), using an internal flag. Stakes: under A, a Daytona or Runloop script that relied on waiting for background output returns early; under B, the same command behaves differently depending on which SDK runs it. Recommendation: A, because one behaviour is simpler to test and explain, and Daytona and Runloop users suffer the same hang today. Note: options differ in kind, not coverage — no completeness score. Net: one consistent behaviour versus keeping the facades exactly as they are.
Header: ER2 exec
Options:
A) All callers get it (recommended)
AerolVM exec, Daytona executeCommand and Runloop one-shot all return when the command ends; preserve list kept with existing tests green; new tests incl. a Daytona contract case with `sleep 600 &` and gVisor live runs; the Daytona and Runloop docs note it (E2B's envd commands use a different path and are unchanged). Effort S (human: ~1 day / CC: ~20 min), risk medium. ✅ One behaviour and one test set for every API. ✅ Daytona and Runloop agents stop hanging on `cmd &` too. ❌ A facade script that waited for background output now returns early.
B) AerolVM exec only
Facades set an internal "wait for background" flag and keep today's wait, now bounded by the timeout's group kill; same preserve list and tests, plus a Daytona case that still waits. Effort S (human: ~1 day / CC: ~30 min), risk low. ✅ Daytona and Runloop behave exactly as before, except the call now always ends. ✅ No surprise for facade users. ❌ Two behaviours behind one handler, and an extra flag to keep tested.

State: approved
Actual answer: A) All callers get it (recommended) — eng D4, 2026-11-06
Accepted scope: B2's new behaviour applies to AerolVM exec, Daytona executeCommand and Runloop one-shot; preserve list kept with existing tests green (exit status incl. reaper race and gVisor ESRCH, pushed env, image PATH, missing-workdir error, 5-minute default, full output without background jobs); new tests incl. a Daytona contract case with `sleep 600 &` and gVisor live runs; Daytona and Runloop docs note it. B2's text in section 3 updated.
History: none

### Section 4: Performance

1. [INFORMATIONAL] (confidence: 7/10) `cmd/toolboxd/daytona_files_git.go:143` — `entries, err := os.ReadDir(targetPath)`: the Daytona list reads a whole folder into memory with no cap, and F1 keeps that default for Daytona callers (CEO R2); the SDKs send an entry cap. Scale: about 100 bytes per entry [estimated], so a folder of a million entries costs ~100 MB in toolboxd. Disposition: existing behaviour, noted; no change.
2. [INFORMATIONAL] (confidence: 7/10) B2 — the 1 s grace applies only when a background job holds the output; detached drainers are bounded by the sandbox's pids limit (gVisor cap, commit db42fd37). Disposition: noted.
3. [INFORMATIONAL] (confidence: 6/10) O4 — one expvar map increment per proxied toolbox request, about 128 series, no per-sandbox labels. Disposition: noted.
4. [INFORMATIONAL] (confidence: 6/10) E8 — retained memory is bounded by the terminal limit times the replay buffer size (R11). Disposition: noted.
No store writes are added in Phases 0–2 (CEO R4); no queries in loops; F3/F4 stream.

### Outside voice: Codex (eng, 2026-11-06)

Completed (provider codex, model gpt-6-astra per the probe). 6 findings, all checked against the code:
1. High — X4/F3 `os.Root` does not stop a write through a pre-existing hard link (`internal/runtime/wasm/toolhost/files.go:145` has the safe pattern). True. Disposition: required for R9's "writes only under the target"; F3 text updated (temp file + rename, hard-link test).
2. High — B2's drainer bound relies on the pids limit, which gVisor applies best-effort (`cmd/toolboxd/gvisor_pids.go:16-21`). True. Disposition: decision ER3 below.
3. High — an older toolboxd silently ignores E1's caps (`cmd/toolboxd/main.go:673`, permissive decode). True. Disposition: decision ER4.
4. Medium — E1's operator settings have no delivery path into toolboxd (`cmd/toolboxd/main.go:37-42`: pushed env reaches children, not toolboxd). True. Disposition: pending ER5 (owner E1).
5. Medium — O4 misses E2B's proxy and Runloop's `RoundTripToolbox`, and has no class for 101 upgrades. True. Disposition: required for R10; O4 text updated.
6. Medium — E4 is already shipped in all 5 SDKs; PTY `close` is a no-op. True. Disposition: factual correction; E4 reduced to a PTY docs note.

#### ER5: how E1's operator defaults and maximums reach toolboxd
Finding: eng outside voice #4, Medium, confidence 8/10, `cmd/toolboxd/main.go:37-42`, reviewer: codex
Plan baseline: E1 "Add server settings for the default and maximum" (section 5.2)
Runtime evidence: Docker sets the guest env at create (`pkg/docker/client.go:479`); Firecracker pushes env to children, not toolboxd's own settings
State: approved (owner E1, 2026-11-06, at the start of Phase 1)
Actual answer: sandboxd fills in the operator's default and clamps to the operator's maximum in the exec request before it forwards it, on every path that reaches toolboxd's buffered exec (v1, the toolbox pass-through, Daytona, Runloop). The rule lives in sandboxd, so it holds on every runtime, after warm-pool adoption, on Firecracker templates and on already-running agents. No `/version` round trip on the exec path: an older agent ignores a default sandboxd adds, which is today's behaviour, and a cap the caller asked for is still refused by the SDK under ER4. toolboxd keeps its own hard ceiling as a last line.
Accepted scope: the above, with a test per path that the default is filled in and a larger request is clamped
History: none

#### ER3: explicit budget for B2's detached drainers
Finding: eng outside voice #2, High, confidence 8/10, `cmd/toolboxd/gvisor_pids.go:16-21`, reviewer: codex
Plan baseline: CEO R1 (D8) and B2 text: drainers "bounded by the sandbox's pids limit", count in `/health`, warning above 64
Runtime evidence: gVisor's pids cap is best-effort (a failure is logged, not fatal); each detached drainer holds a goroutine and two file descriptors in toolboxd, so enough of them can use up toolboxd's own file limit and stop it serving the sandbox
Comparison grid:

```text
Commitment                                   | Approval        | Current (B2 text)      | A (apply)                 | B (keep)        | C (investigate)        | D (defer)
exec returns when the command ends; bg jobs  | CEO R1, ER2     | approved               | unchanged                 | unchanged       | unchanged              | unchanged
  keep running (under the cap)               |                 |                        |                           |                 |                        |
Hard cap on detached drainers per sandbox    | pending         | none (pids limit)      | 256 drainers (~512 fds)   | none            | after measuring        | none now
At the cap: close the output after the grace | pending         | n/a                    | yes; the job may stop on  | n/a             | n/a                    | n/a
  instead of detaching a new drainer         |                 |                        |   its next write          |                 |                        |
Warning log + /health shows "at cap"         | pending         | warn above 64          | yes                       | warn above 64   | warn above 64          | warn above 64
Test: cap+1 background jobs                  | pending         | none                   | yes                       | none            | none                   | none
```

Question D5:
D5 — ER3: Should toolboxd put a hard limit on the background-job readers B2 leaves running? Project: plans/agent-sandbox-feature-parity (PR #923), Phase 0 item B2. ELI10: With B2, when a command leaves a background job running, toolboxd keeps a small reader alive to soak up that job's output, so the job isn't killed. Each reader holds two file handles in toolboxd. The plan says the sandbox's process limit keeps their number down, but on gVisor that limit is best-effort, and toolboxd has its own file-handle limit. An agent that starts many background jobs could use up toolboxd's handles, and then toolboxd stops answering for that sandbox. Option A sets a hard limit (256 readers); past it, a new background job's output is closed after the 1 s grace instead, the way Buildkite and GitLab Runner do it, so that job may stop the next time it prints. Stakes: without a limit, one busy sandbox can break its own toolbox (file calls, exec, terminals) until restart. Recommendation: A, because a fixed budget keeps toolboxd alive, and 256 background jobs per sandbox is far beyond normal use. Completeness: A=9/10, B=5/10, C=6/10, D=5/10. Net: a hard limit with a clear fallback versus trusting a limit that may not be there.
Header: ER3 cap
Options:
A) Apply this change (recommended)
toolboxd allows at most 256 detached readers per sandbox; past that, a new background job's output is closed after the 1 s grace (it may stop on its next write); a warning log and `/health` show "at cap"; tested with cap+1 background jobs. Effort S (human: ~half a day / CC: ~15 min), risk low. ✅ toolboxd can never run out of file handles because of B2. ✅ Normal agents never get near 256, so they see no change. ❌ The 257th still-printing background job may stop when it next writes.
B) Keep this row's current value
Rely on the sandbox's process limit and the warning above 64, as written. Effort S (zero extra implementation work), risk medium. ✅ No limit to explain or tune. ✅ Every background job keeps running. ❌ On gVisor, where the process limit is best-effort, toolboxd can run out of file handles.
C) Investigate before choosing
Measure toolboxd's file limit and real background-job counts on each runtime, then pick a number. Effort S (human: ~half a day / CC: ~15 min), risk medium. ✅ The limit comes from real numbers. ✅ May show a different number fits better. ❌ B2's design stays open until the measurement is done.
D) Defer this proposed change only
Ship B2 as written; leave the limit unresolved for later. Effort S (zero implementation work now), risk medium. ✅ B2 lands without extra work. ✅ A limit can be added later without breaking callers. ❌ The file-handle exhaustion risk ships with B2.

State: approved
Actual answer: A) Apply this change (recommended) — eng D5, 2026-11-06
Accepted scope: hard limit of 256 detached drainers per sandbox; past it, a new background job's output is closed after the 1 s grace; warning log and `/health` "at cap"; test with cap+1 background jobs. B2 text updated.
History: none

#### ER4: protect E1's caps against an older toolboxd
Finding: eng outside voice #3, High, confidence 8/10, `cmd/toolboxd/main.go:673` (`json.NewDecoder(r.Body).Decode(&req)` accepts unknown fields), reviewer: codex
Plan baseline: section 10 "Older toolboxd": toolboxd lists the file options it supports on `/version`; SDKs fail closed before sending a file safety option (approved at CEO D15)
Runtime evidence: an older toolboxd ignores `max_stdout_bytes`/`max_stderr_bytes` and returns all output, so an SDK that asked for a cap can still receive unbounded output
Comparison grid:

```text
Commitment                                    | Approval      | Current           | A (apply)                  | B (keep)          | C (investigate)        | D (defer)
/version lists file options; SDKs fail closed | CEO D15       | approved          | unchanged                  | unchanged         | unchanged              | unchanged
/version also lists E1's exec limits          | pending       | no                | yes                        | no                | after checking options | no
SDK sending a cap to an older toolboxd        | pending       | cap ignored       | fails closed: "re-create / | cap ignored       | unchanged              | cap ignored
                                              |               |                   |   restart the sandbox"     |                   |                        |
Mixed-version test (new SDK, old toolboxd)    | pending       | none              | yes                        | none              | none                   | none
```

Question D6:
D6 — ER4: When a new SDK asks an older sandbox agent to cap command output, should the SDK refuse instead of getting unlimited output? Project: plans/agent-sandbox-feature-parity (PR #923), Phase 1 item E1. ELI10: E1 lets a caller say "give me at most N bytes of output". A sandbox started before E1 runs an older toolboxd that silently ignores that request and sends everything, so a caller expecting a small reply can get gigabytes. We already decided that for file safety options, toolboxd lists what it supports on `/version` and the SDK refuses rather than send an option an older agent would ignore. Option A applies the same rule to E1's output caps. Stakes: without it, asking for a cap gives no protection on older sandboxes, and the caller only finds out when memory runs out. Recommendation: A, because it is the same rule we already use for file options, so one mechanism and one error message cover both. Completeness: A=9/10, B=4/10, C=6/10, D=4/10. Net: one consistent fail-closed rule versus a cap that silently does nothing on older sandboxes.
Header: ER4 caps
Options:
A) Apply this change (recommended)
toolboxd lists E1's exec limits on `/version` next to the file options; an SDK that sends a cap to an older toolboxd fails closed with the same "re-create / restart the sandbox" error; a mixed-version test covers it. Effort S (human: ~1 day / CC: ~20 min), risk low, reuses the `/version` option check. ✅ A requested cap is either enforced or refused, never silently ignored. ✅ Same mechanism and error as the file options. ❌ Callers on older sandboxes must restart or re-create them to use caps.
B) Keep this row's current value
`/version` lists file options only; an older toolboxd ignores E1's caps. Effort S (zero extra implementation work), risk high. ✅ No extra check in the SDKs. ✅ Exec on an older sandbox always runs. ❌ A caller that asked for a cap can still receive unbounded output.
C) Investigate before choosing
Check whether a client-side byte limit in each SDK could replace the refusal, then choose. Effort S (human: ~half a day / CC: ~15 min), risk medium. ✅ May find a fallback that works on older sandboxes without an error. ✅ Keeps both paths open. ❌ E1's compatibility story stays open until the check is done.
D) Defer this proposed change only
Ship E1 without the check; leave this row unresolved. Effort S (zero implementation work now), risk high. ✅ E1 lands without extra work. ✅ The check can be added later. ❌ Caps silently do nothing on older sandboxes until then.

State: approved
Actual answer: A) Apply this change (recommended) — eng D6, 2026-11-06
Accepted scope: `/version` lists E1's exec limits; an SDK sending a cap to an older toolboxd fails closed with the "re-create / restart the sandbox" error; mixed-version test. E1 text and section 10 updated.
History: none

### Final planning decisions

TODOS.md: no proposals (ER5 stays a pending owner decision in this plan, not a TODO).

Approval readiness: PASS — ER1 (eng D3 "Share one core in F1"), ER2 (eng D4 "All callers get it"), ER3 (eng D5 "Apply this change"), ER4 (eng D6 "Apply this change"); structure (eng D1, "Original arrangement", scope selector only). Carried forward as required proof of earlier approvals, not new remedies: `os.Root` + temp-file-and-rename extraction with hard-link and two-step symlink tests (CEO R9, D17); `/version` option consistency test (fail-closed rule, CEO D15); O4 at three proxy points with 101 counted once (CEO R10, D18). Factual correction: E4 already shipped. Pending: ER5 (owner E1).

### NOT in scope (eng)

- Phases 2–5 at implementation depth: each phase gets its own eng review before it is built (P1–P4, D1 and P1 design docs).
- A new file-watching dependency: F5 uses `golang.org/x/sys` (already in `go.mod`), not fsnotify.
- A smaller file arrangement: declined at eng D1 ("Original arrangement").
- Retiring tests: none.

### What already exists (eng)

| Existing code | Reuse in this plan |
|---|---|
| WASM toolhost `atomicWriteFile` through `os.Root` (`internal/runtime/wasm/toolhost/files.go:145`) | F3 and X4 extraction write pattern |
| envd file handlers (`cmd/toolboxd/envd.go:888-995`) and Daytona handlers (`daytona_files_git.go:123-176`) | Become callers of the ER1 shared core |
| `golang.org/x/sys` (`go.mod:136`), `creack/pty` (`go.mod:8`), `gorilla/websocket` (`go.mod:12`) | F5 inotify, E8 terminals, watch stream |
| Existing exec tests: exit code (`coverage_boost5_test.go:159`), pushed env (`sandbox_env_test.go:161`), image PATH (`loginshell_exec_test.go:22`), reaper/ESRCH (`child_table` tests) | ER2's preserve list stays green |
| Middleware 101 classification (`pkg/api/middleware.go:167`) | O4 status classes |
| `TestDaytonaSDKContracts` (`pkg/api/daytona/contract_test.go:960`) | ER1, ER2 and E8 contract cases |

### Diagrams (eng)

```
 ER1 shared file core
   REST handlers (native SDKs + Daytona) ─┐            ┌─ writeFilesystemError (REST shape)
   envd handlers (E2B)                    ├─► core: move/mkdir/remove/list/stat(opts) ─┤
   B1 delete/folder/replace/chmod ────────┘   opts: CreateParents, Overwrite, Recursive, └─ writeEnvdFilesystemError (envd shape)
                                                    Depth, EntryCap, Mode     errno -> 409/403/404/507
```

```
 B2 exec with the drainer budget (ER3)
  START ─► shell exits ─► output still held? ─no─► RESPOND
                               │yes
                               ▼
                         grace 1 s ─► RESPOND ─► drainers < 256? ─yes─► detach drainer ─► EOF ─► free slot
                                                       │no
                                                       └─► close output (job may stop on next write); /health "at cap"
  timeout ─► kill -pgid ─► RESPOND(timed_out) ─► same drainer path
```

```
 O4 instrumentation points
  v1 /toolbox/* and Daytona ─► shared toolbox proxy ──┐
  E2B /envd/*               ─► E2B reverse proxy ─────┼─► counter{route class, status class, surface}
  Runloop                   ─► RoundTripToolbox ──────┘     101 upgrade counted once as success
```

### Failure modes (eng)

| New path | Realistic failure | Test / handling | User sees |
|---|---|---|---|
| ER1 shared core | a core bug reaches E2B, Daytona and SDK at once | table-driven core tests + envd tests + `TestDaytonaSDKContracts` | specific 4xx/507 |
| B2 drainers | an agent starts hundreds of background jobs | ER3 cap, cap+1 test | prompt reply; `/health` "at cap" |
| B2 facades | a Daytona script expected to wait for background output | ER2 contract case, docs note | returns early (documented) |
| E1 caps | SDK asks an older toolboxd to cap output | ER4 fail closed, mixed-version test | clear "re-create / restart" error |
| E1 settings | operator default never reaches toolboxd | pending ER5 verification | unknown until ER5 settles |
| X4/F3 extract | target already holds a hard link to an outside file | temp file + rename, hard-link test | outside file untouched |
| O4 | an uninstrumented proxy path | three instrumentation points, per-path test | complete counts |
| F5, E8 WebSockets | drop during a Caddy reload (UC-266) | existing TODO | client reconnects |

Critical gaps (no test, no handling, silent): 0.

### Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| B1 + 501s (lsp, pty) | `cmd/toolboxd`, `internal/runtime/wasm/toolhost`, docs | — |
| X2 inventory test | `pkg/api/daytona`, `pkg/api/e2b`, `pkg/api/runloop` | B1 |
| B2 exec + ER2/ER3 | `cmd/toolboxd`, `pkg/models`, `sdk/*`, docs, `integration-tests` | — |
| B3 docs | docs | — |
| O4 counter | `internal/service`, `pkg/api/e2b`, `pkg/api/runloop`, `setup/grafana` | — |
| F1 + ER1 core | `cmd/toolboxd`, `sdk/*`, docs | B1 |
| F2, F3 + X4 | `cmd/toolboxd`, `cmd/aerolvm`, `sdk/*` | F1 |
| F4 | `cmd/toolboxd`, `sdk/*` | F1 |
| F5 | `cmd/toolboxd`, `sdk/*` | F1 |
| E1–E3 + ER4 | `cmd/toolboxd`, `pkg/models`, `sdk/*` | B2, ER5 settled |
| E8 | `cmd/toolboxd` (sessions), `pkg/api/daytona`, docs | B1 |

Parallel lanes: Lane A: B1 → X2 → F1 → F2/F3 → F4 → F5 (`cmd/toolboxd` files). Lane B: B2 → E1–E3 (`cmd/toolboxd` exec). Lane C: O4 (`internal/service`, proxies). Lane D: B3 docs. Lane E: E8 (sessions) after B1.
Execution order: launch A + B + C + D together; E after B1 lands in its stack.
Conflict flags: lanes A, B and E all edit `cmd/toolboxd/main.go` (route switch vs exec handler) and every lane touching SDKs edits the same 5 SDK clients; sequence those edits or rebase often, since stacks merge only when all are green.

### Unresolved decisions (eng)

- ER5 (owner E1): settled 2026-11-06 — sandboxd fills in and clamps the limits before forwarding (see the ER5 row).

### Completion summary (eng)

- Step 0: Scope Challenge — scope accepted as-is
- Reality rows: 7/7 applicable rows emitted (`PLAN_REALITY phase=eng rows=7/7 verdict=complete`), 3 unverified premises
- Architecture Review: 3 issues found
- Code Quality Review: 1 issue found
- Test Review: diagram produced, 20 gaps identified
- Performance Review: 4 issues found
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 0 items proposed to user
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 1 in this review
- Outside voice: codex, completed (6 findings)
- Parallelization: 5 lanes, 4 parallel / 1 sequential (Lane E after B1)
- Lake Score: N/A (no answered question offered a 10/10 option)

## Implementation Tasks (eng review)

Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship.
Effort assumes refactor ~20x, tests ~50x, features ~30x (human ÷ CC).

- [ ] **ET1 (P1, human: ~2 days / CC: ~40min)** — toolboxd — Shared file-operation core for envd and REST handlers (ER1)
  - Surfaced by: Section 2 #1 — `cmd/toolboxd/envd.go:922-950` vs `daytona_files_git.go:160-176`
  - Files: `cmd/toolboxd/envd.go`, `cmd/toolboxd/daytona_files_git.go`
  - Verify: `go test ./cmd/toolboxd/...` and `go test -run TestDaytonaSDKContracts ./pkg/api/daytona/...`
- [ ] **ET2 (P1, human: ~1 day / CC: ~20min)** — toolboxd exec — B2 regression contract for all callers (ER2)
  - Surfaced by: Section 3 regression rule — `pkg/api/daytona/toolbox.go:353`, `pkg/api/runloop/toolbox.go:209`
  - Files: `pkg/api/daytona/contract_test.go`, `pkg/api/runloop/`, `docs/src/content/docs/using-daytona-sdk.mdx`
  - Verify: existing exec tests stay green; new Daytona `sleep 600 &` case passes
- [ ] **ET3 (P1, human: ~half day / CC: ~15min)** — toolboxd exec — 256-drainer cap, `/health` "at cap", cap+1 test (ER3)
  - Surfaced by: eng outside voice #2 — `cmd/toolboxd/gvisor_pids.go:16-21`
  - Files: `cmd/toolboxd/main.go`
  - Verify: `go test -run Drainer ./cmd/toolboxd/...`
- [ ] **ET4 (P1, human: ~1 day / CC: ~20min)** — sandboxd — O4 at three proxy points, 101 counted once
  - Surfaced by: eng outside voice #5 — `pkg/api/e2b/runtime_proxy.go:90`, `pkg/api/runloop/toolbox.go:78`
  - Files: `internal/service/toolbox_proxy.go`, `pkg/api/e2b/runtime_proxy.go`, `pkg/api/runloop/toolbox.go`
  - Verify: per-path counter tests
- [ ] **ET5 (P2, human: ~1 day / CC: ~30min)** — toolboxd + CLI — Extraction through `os.Root` with temp-file-and-rename; hard-link and two-step symlink tests
  - Surfaced by: Scope Challenge #3, eng outside voice #1 — `internal/runtime/wasm/toolhost/files.go:145`
  - Files: `cmd/toolboxd/`, `cmd/aerolvm/files.go`
  - Verify: `go test ./cmd/aerolvm/... ./cmd/toolboxd/...`
- [ ] **ET6 (P2, human: ~1 day / CC: ~20min)** — toolboxd + SDKs — `/version` lists exec limits; SDKs fail closed; mixed-version tests (ER4)
  - Surfaced by: eng outside voice #3 — `cmd/toolboxd/main.go:673`
  - Files: `cmd/toolboxd/main.go`, `sdk/*`
  - Verify: each SDK's tests
- [ ] **ET7 (P2, human: ~2h / CC: ~10min)** — toolboxd — `/version` option consistency test
  - Surfaced by: Section 1 red flag #8 — `cmd/toolboxd/main.go:448`
  - Files: `cmd/toolboxd/`
  - Verify: `go test ./cmd/toolboxd/...`
- [ ] **ET8 (P2, human: ~30min / CC: ~5min)** — docs — PTY `close` is a no-op; send Ctrl-D (E4)
  - Surfaced by: eng outside voice #6 — `cmd/toolboxd/exec_stream.go:365`
  - Files: `docs/src/content/docs/exec-streaming.mdx`
  - Verify: docs build
- [ ] **ET9 (P3, human: ~2h / CC: ~15min)** — E1 owner — Settle ER5 before coding E1
  - Surfaced by: eng outside voice #4 — `cmd/toolboxd/main.go:37-42`
  - Files: to be determined
  - Verify: E1's PR cites the settled ER5 row

## Build notes (2026-11-06)

What changed from the plan text while building, and why. Each PR cites
its row here.

**Phase 0 (B1, B2, B3, O4)** passed live on `cluster-3-mixed-gvisor`
(UC-369 to UC-372). B1 also changed one older test that expected 500 for
"already exists"; the plan's error mapping makes it 409.

**Phase 1 foundation.** toolboxd lists its request options on `/version` as
features (`cmd/toolboxd/features.go`), and a test parses the handlers so an
option cannot ship unlisted (ET7). The five SDKs check the list before
sending an option an older agent would drop (ER4).

**Phase 1 deviations:**
- F1: `size_bytes` (and `path`, `symlink_target`) come only with
  `extended=true`. Daytona's Go client decodes file info with
  `DisallowUnknownFields`, so a new field on the shared reply would break
  every Daytona file call.
- F1/F2/F3: one `/version` feature per plan item (`files.verbs`,
  `files.write_options`, `files.extract`), because two verbs share the
  `overwrite` option and the drift test allows each option in one feature.
- F1: error codes `file_not_found` and `folder_exists` let a retried delete
  or mkdir tell "already done" from an agent without the route (R4).
- F3: owner decision P1 applied (keep partial, name the entry and count).
  `internal/safetar` is the one unpacker for toolboxd and `aerolvm cp -r`.
- F5: the SDK method is `watch_files` (`WatchFiles`, `watchFiles`), not
  `watch`, which reads as ambiguous on a sandbox object. toolboxd tells
  gVisor (uname version) and Firecracker (kernel command line) apart from
  a shared kernel itself, so `CreateSandbox` is untouched; unknown means 501.
  Limits: 16 watches per sandbox, 8,192 folders per watch, 16,384 per
  sandbox, 4,096 events per batch. Every SDK gives up after 60 s if the
  watch never starts.
- E1: per-stream `stdout_truncated` and `stderr_truncated` instead of one
  `truncated`, because the caps are per stream. toolboxd's own ceiling is
  64 MiB per stream (what Daytona and Runloop already decode). ER5 applied:
  `SB_EXEC_OUTPUT_DEFAULT_BYTES` and `SB_EXEC_OUTPUT_MAX_BYTES`, filled in
  and clamped by sandboxd at both toolbox chokepoints.
- E2: `argv[0]` may not start with "-" (a shell's `exec` would read it as
  an option).
- E3: buffered exec reports `signal` as "SIGKILL"; streams and sessions keep
  their existing "killed" wording, because changing it would break their
  wire format.
- E8: 32 Daytona terminals per sandbox; a finished terminal frees its
  buffer after 30 s and keeps its exit code. Isolate sandboxes answer 501
  for terminals and sessions (they used to fall through to the fetch
  handler).

**Phase 2 lifecycle (L1–L6, O1, O2) deviations and decisions:**
- L2: a fixed set of reasons (`user_stop`, `idle`, `max_age`,
  `out_of_memory`, `disk_limit`, `crashed`, `reconcile`, `program_exited`,
  `failover`, `restarted`). The store writes a reason only with the status
  change that caused it, so Docker's "stop" event after "die" cannot
  overwrite the true reason. An exit with code 0 nobody asked for reads as
  `program_exited`; a non-zero one as `crashed`.
- L1: the backoff state is stored, so a daemon restart neither loses a due
  restart (the sweep picks it up within a minute) nor resets a crash loop
  to full speed. A sandbox reconcile finds stopped is not restarted (its
  exit is unknown). A stop cancels a pending restart after it writes the
  stopped row, and the timer re-checks the reason under the per-sandbox
  lock; a residual window needs two writes to interleave in well under a
  millisecond.
- L4: the defaults are written into a new sandbox's lifecycle at create,
  not applied by the sweep (owner agreed): they show on GET, and turning
  them on never deletes older sandboxes. Unit tests only, since setting them
  on a shared live scenario would change every other use case.
- L5: toolboxd `/health` gains `main_program`; the exit time is clamped so
  a guest clock that is behind can only make a delete late.
- L6: `destroyAt` becomes `destroyAtAge` before the spec is recorded, so the
  replicated spec carries only an age; at most 30 days ahead.
- L3: new records `runtime.exited`, `runtime.removed`,
  `reconcile.found_stopped`, `failover.recreated`, `fleet.suspend`,
  `fleet.delete`; the audit filter accepts `caller=system:*`.
- O1: no alert (a crash-loop threshold depends on the workload); one
  dashboard panel instead.

**Phase 3 policy and storage (T3, T4, V1) decisions:**
- T3: YAML file, reloaded like the egress operator file (10 s poll or
  SIGHUP, a bad edit keeps the last good file); a set
  `SB_CREATE_POLICY_FILE` with no file behind it is a boot error and every
  create gets 503 until fixed (fail closed). Size limits apply to the size a
  sandbox really gets, defaults included. `require_non_root` is checked
  against the image's `USER` before the container exists (numeric non-0
  only, the Kubernetes rule), and sends Docker and gVisor creates down the
  cold path.
- T4: the flag is a default, not a floor: a sandbox with its own policy
  keeps exactly its own; the operator file's `deny_cidrs` stays the floor.
  The node's DNS resolver in a blocked range gets a `/32` allow entry.
- V1: `delete_with_sandbox` belongs to the volume (409 on a conflicting
  reference); deletion goes through the reclaim ledger, so a failed backend
  delete is retried by the sweep, never lost. Also fixed: the SQLite volume
  record delete now refuses in one statement while any attachment holds it
  (a count then a delete could drop another sandbox's attachment).
- Rust SDK: `PlatformVolumeMount` (and other structs across the phases)
  gained public fields; code that builds them without
  `..Default::default()` needs that added. Release notes must say so.

**Fixes found by the Phase 1 live run (cluster-3-mixed-gvisor, 23/24 parity
use cases passed, 2 skipped for FC and WASM):**
- UC-387: killing a Daytona terminal whose shell had started a job under job
  control (`sleep 300 &`) never ended the session: the job sits in its own
  process group, survives the kill of the shell's group, and keeps the
  terminal open, so the output pump never saw end-of-file. The kill now
  sends SIGHUP, waits the grace, then kills every process holding the
  terminal's `/dev/pts/N` open (found through `/proc/*/fd`, while the
  master is still open so the number cannot be reused), then hangs up.
  Matching on `tty_nr` does not work: the kernel drops the controlling
  terminal of the whole session when its leader exits.
- `TestExecStreamDropKillsProcessGroup/pipes` fails on macOS about one run
  in five (the orphaned background child is reaped late by launchd). It
  passed 40 of 40 on Linux, where CI and toolboxd run; left as is.

**Phase 2 access (A1–A3):**
- A1: a sandbox token is signed, works for one sandbox, can be narrowed
  to a path prefix and methods, lasts 24 h by default (30 days at most),
  and is checked with no database call. A retry after a lost answer only
  makes a second short-lived token.
- A2: `visibility: "token"` sets a `__Host-aerolvm-token` cookie. A gated
  port is left off toolboxd's `/proxy/<port>` list and a custom domain
  cannot point at it. An older client's retry never opens a gated port:
  only an explicit `public` or `token` changes the setting. In a cluster,
  token ports wait until every server supports them (`TokenPortGate`).
- A3: W3C trace context reaches toolboxd and is logged there; no spans and
  no new dependency in toolboxd.

**Warm pools (W1–W3):** entries live in the Raft FSM (ops 33/34) behind
the rolling-upgrade gate, 32 entries at most, so any server answers a read
without a fan-out. W2: an entry gives `min_depth` and `max_depth`, and each
server follows its own creates (an average under 0.1 per interval counts
as no demand). W3: `on_image_change` is `replace_now` (default) or
`replace_as_used`.

**FSM numbering.** The lanes picked ops versions on their own; the stack
renumbered them at integration: 6 token ports, 7 warm pools, 8 identity,
9 team quotas (`fsmOpsVersion = 9`). Some commit messages written before
that still say "version 6" for warm pools; the code and PR bodies use the
numbers above.

**Identity (D1)** follows `plans/sandbox-cloud-identity.md`. Only a node
that signs opens the signing key. The first token took 875 ms on the live
run, so minting stays off the create path (D1.8).

**Ops (I1, O3):** I1 dials toolboxd again only on "connection refused",
three times, 200, 400 and 800 ms apart, before any byte of the request is
sent, at both toolbox chokepoints and in E2B's proxy. It adds no time when
the first dial works, and none to `CreateSandbox`. O3 is
`cmd/aerolvm-bench` and `performance-benchmark.mdx`.

**Placement and quotas (P1, P2)** follow `plans/placement-rules.md`; team
quotas are FSM ops 38/39.

**Recipes (G12, G8, G10, G9):** E2B's own API starts nothing for `mcp`;
the E2B SDK runs E2B's `mcp-gateway` in the sandbox after the create and
reaches it on port 50005. The facade now accepts `mcp` and exposes 50005
(rolled back with the create if the expose fails). What AerolVM cannot do
answers 501 by name: E2B's `mcp-gateway` template, unless an operator maps
it, and WASM sandboxes. The computer-use and code-server images live
under `images/` and are not pushed anywhere.

**SDK (S1–S7):** the typed errors subclass each SDK's existing HTTP error,
so old `except`/`catch` code keeps working. `AsyncMicroVM` uses `httpx`
from the optional `[async]` extra; the sync client gained no dependency.
A follow-up gave the identity and quota calls a per-call timeout, a
TypeScript signal and an async form.

**Integrations (G1, G2, G4, G5):** Python packages under `integrations/`,
not published, with offline tests against a shared fake that must match
every `MicroVM` signature. G5 tested NeMo Gym's Daytona provider first and
found three facade bugs. All three are now fixed: create answers 200
(Daytona's API does; the Python SDK reads a body only from a 200), the
sandbox always carries `kvm`, and each bulk-download part, error parts
too, is named by the full requested path. NeMo Gym's Daytona provider now
works with Daytona Python SDK 0.179.0 and 0.230.0. The `aerolvm` provider
stays, for AerolVM's own create options.

**Fixes found by the cluster-3-mixed and cluster-3-mixed-docker live
runs:**
- Caddy's `@api` matcher did not forward `/.well-known/openid-configuration`
  and `/.well-known/jwks.json`. A test now checks every public route
  against both Caddyfiles.
- A create that a cluster forwards skipped the operator create policy (T3).
  `CheckCreatePolicy` now runs in `clustercreate.Prepare`.
- `delete_with_sandbox` (V1) could find the volume still attached on a
  lagging replica; the delete is retried in the background on "in use",
  250 ms doubling to 8 s (about 16 s in all).
- UC-389 and UC-424 test fixes. UC-427 (containerd) and UC-422 (warm-pool
  demand) gained diagnostics.

**Fixes found in the final local verification:**
- The integration-tagged suite stopped compiling at G2 (a second
  `apiStatus` helper); renamed in G2.
- The integration fake lacked S6's per-call `timeout`; fixed in G1's copy
  and in G2's shared copy, so each package passes at its own commit.
- `TestWatcherBadFileRefusedThenFixed` (T3) raced the 5 ms poll by writing
  the file in place; it now writes a temp file and renames it.

**M1** is `docs/src/content/docs/moving-from-agent-sandbox.mdx`.

**Fixes found by the final live runs (2026-11-06, all five scenarios).**
Several are older than this stack; the parity use cases were the first to
reach them.
- WASM and isolate sandboxes answered 401 to every authenticated
  `/v1/.../toolbox/` call: the pass-through handed their in-process host
  the caller's PAT, not the sandbox's toolbox token (UC-379; same code on
  main). Fixed as the container path does it.
- A cluster image build forwarded to another node failed after about 30 s:
  it used the shared peer client's limit, while a build answers only when
  done (UC-464/465; older than the stack). The forward now gets
  `2 × SB_IMAGE_BUILD_TIMEOUT + 1 min`.
- An Idempotency-Key create whose client hung up mid-create left its
  container, and the retry got 409 "sandbox already exists" (UC-450). Two
  fixes: containerd's create undo now runs on a context that ignores the
  client's cancel (as Docker's did), and a keyed create that still meets a
  leftover (a hang-up inside Docker's `/containers/create` or containerd's
  `NewContainer`) removes it under the create lease and creates again.
  Docker's 409 name conflict now reads as `ErrSandboxContainerExists`.
  Proven live: 10 of 10 UC-450 runs on the Docker engine removed a real
  leftover and passed.
- OpenCode and Codex CLI wait for their input to end, and a session keeps
  it open, so both recipes hung (UC-467). Their commands end with
  `< /dev/null` now.
- Test fixes: UC-457 retries a create from a snapshot through the cluster's
  registry push window (as UC-260 does); UC-454 holds the refusal for 30 s
  and allows 20 s, since the runner's network added 8 s on its own;
  `aerolvm-bench` gained `-template`, because a Firecracker create without
  one rebuilds its disk and pulls the image every time (Docker Hub's pull
  limit stopped the first run).

**O3 numbers** are in `performance-benchmark.mdx`, from the tool run on a
node in us-east-1. Firecracker from a template: 36.5 creates/s at 4
workers, p50 67 ms, p99 93 ms, on one c5.metal. Docker and gVisor were
measured again on fixed-performance servers (3 × c6i.2xlarge, PR #981),
because the first run on burstable t3.medium servers was CPU-credit bound:
gVisor 19.4/s at 4 workers (p50 171 ms); Docker 8.9/s (p50 303 ms), and
the warm pool cuts p50 at 1 worker from 191 ms to 38 ms. The page has a
"where the time goes" table from each create's Server-Timing header.

**Live coverage.** Across the final runs every one of the 82 parity use
cases (UC-369 to UC-467) passed in at least one scenario: cluster-3-mixed,
cluster-3-mixed-docker, cluster-3-mixed-gvisor, single-node-fc and
single-node-wasm.

**Review guides (2026-11-06).** Writing each PR's step-by-step review
guide (pr-review.md §A) meant reading every diff again, and that found
more bugs. Each was fixed in the commit that made it (a fixup, so the PR
that adds the code also has the fix), with a test that fails without it:
- Security: a `safetar` link that only leads out of the folder once later
  entries are in is now removed and the archive refused (F3); two expose
  calls on one port can no longer interleave and leave a "token" row on the
  open route, and the warm cache can no longer keep "not gated" after a
  gate change (A2); a sandbox token is held to its own sandbox in the
  service, not only to its owner (A1); the toolbox proxies no longer pass
  the caller's `baggage` header into the sandbox (A3).
- Correctness: a file copy keeps setuid/setgid (F1); Java's download cap
  keeps the bytes under the limit (F4); a stop fails, instead of being
  undone later, when it cannot cancel a pending restart (L1); a guest clock
  that is behind no longer makes `destroyAfterExitFor` early, and the
  probes get their own 10 s of the sweep (L5); a refused `destroyAt` no
  longer holds a cluster create's name for 120 s, and the forwarded body
  carries the age (L6); an env-pinned warm-pool key no longer keeps a
  frozen image ID (W3); the identity role cache is capped (D1).
- Tests and words: `TestIdentityRefresher`, the V1 best-effort test, the
  F2 atomic-failure test; the O1 metric row, stale comments and five
  commit messages (fv and op numbers, O3's table).
- Fixes that touch code later commits rewrote are commits on a 59th PR,
  #982 (`fix/parity-review-findings`), on top of the benchmark PR #981: the SDK
  "retry found its work done" rule now counts only after a lost reply
  (it fired after 429/503 too, so deleting a missing path reported
  success); get_or_create deletes on exit only what it created; `import
  microvm` no longer loads httpx; a Daytona text replace keeps owner,
  mode and symlink; the E2B mcp create skips the port probe; smaller
  items.
- Still open, written in the PR bodies: a `destroyAt` lifecycle update
  sent during a rolling upgrade (lifecycle.mdx says to finish the upgrade
  first); the Rust SDK does not return a port's visibility (a field would
  break matches); the TypeScript SDK on main still prints the token in
  `JSON.stringify(sandbox)` (fixed in the stack; main needs a backport).

**Owner decisions settled at build time:** P1 (F3), P2 (L5), P3 (V1),
P4 (L1), ER5 (E1); see their rows. D1 and P1 have design docs:
`plans/sandbox-cloud-identity.md`, `plans/placement-rules.md`.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | ISSUES OPEN | 5 proposals, 3 accepted, 0 deferred |
| Outside Review | Codex (outside voice of `/plan-ceo-review` and `/plan-eng-review`) | Independent 2nd opinion | 2 | completed | 12 findings; 8 resolved; 4 unresolved (P2–P4, ER5) |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | ISSUES OPEN | 28 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex (model gpt-6-astra per the probe), plan-review phase, completed twice: after the CEO review (6 findings: 3 resolved, 3 left as P2–P4) and after the eng review (6 findings: 5 resolved by corrections or decisions ER3/ER4, 1 left as ER5).
- **CROSS-MODEL:** the native eng review (Claude Opus 5.5) and Codex found complementary issues with no overlap and no disagreement on any decision. Native: duplicated envd/REST file code (ER1), B2's reach into Daytona and Runloop (ER2), `/version` drift. Codex: hard links through `os.Root`, the drainer bound (ER3), E1 caps on older agents (ER4), E1 settings delivery (ER5), O4's missing proxy paths, E4 already shipped.
- **VERDICT:** no review is CLEAR. CEO and Eng reviews are ISSUES OPEN: all Phase 0–1 findings are decided or mapped to tasks, with 1 pending eng decision (ER5) and 4 pending CEO owner rows (P1–P4). eng review required.

**UNRESOLVED DECISIONS:**
- ER5 (owner E1): how E1's operator default and maximum reach toolboxd on every runtime, warm-pool adoption, Firecracker templates and running agents.
- + 4 unresolved from prior reviews
